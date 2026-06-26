//! Reroute action templates — the ONLY way a reroute can happen. No free-text
//! execution. Each template carries a provider type, mode, a typed parameter
//! schema, a safety level, a plan (the commands to run), a verification method,
//! and an optional rollback template.
//!
//! This module loads templates, validates caller parameters against the schema,
//! and renders the exact command list — substituting ONLY type-checked values
//! (ip / cidr / asn), which makes CLI injection impossible (validated params
//! contain no whitespace or newlines, so they cannot smuggle extra commands).
//!
//! device_cli plan/verification JSON shapes (see migration 20260613000600):
//!   plan_json:         {"transport":"ios_ssh","config_mode":true,"apply":["<cmd {param}>"]}
//!   verification_json: {"method":"ios_show","command":"<show {param}>","expect":<substr>,"reject":<substr>}
//! A cidr param `X` also exposes `{X_net}` and `{X_mask}` to the renderer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};
use sqlx::types::Json as SqlxJson;
use sqlx::MySqlPool;

/// A full reroute template loaded from the DB.
#[derive(Debug, Clone)]
pub struct Template {
    pub id: u64,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub provider_type: String,
    pub mode: String,
    pub automatic_allowed: bool,
    pub parameter_schema: Value,
    pub plan: Value,
    pub verification: Value,
    pub rollback_template_id: Option<u64>,
    /// The IPv6 counterpart of an IPv4 host-route template (e.g. null_route_prefix
    /// -> null_route_prefix_v6). The auto-target resolver swaps to it when the
    /// resolved victim is an IPv6 address. NULL for templates without a v6 form.
    pub v6_sibling_template_id: Option<u64>,
    pub enabled: bool,
}

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: u64,
    name: String,
    display_name: Option<String>,
    description: Option<String>,
    provider_type: String,
    mode: String,
    automatic_allowed: bool,
    parameter_schema_json: Option<SqlxJson<Value>>,
    plan_json: Option<SqlxJson<Value>>,
    verification_json: Option<SqlxJson<Value>>,
    rollback_template_id: Option<u64>,
    v6_sibling_template_id: Option<u64>,
    enabled: bool,
}

const COLS: &str = "id, name, display_name, description, provider_type, mode, \
     automatic_allowed, parameter_schema_json, plan_json, \
     verification_json, rollback_template_id, v6_sibling_template_id, enabled";

impl From<TemplateRow> for Template {
    fn from(r: TemplateRow) -> Self {
        Template {
            id: r.id,
            name: r.name,
            display_name: r.display_name,
            description: r.description,
            provider_type: r.provider_type,
            mode: r.mode,
            automatic_allowed: r.automatic_allowed,
            parameter_schema: r.parameter_schema_json.map(|j| j.0).unwrap_or(Value::Null),
            plan: r.plan_json.map(|j| j.0).unwrap_or(Value::Null),
            verification: r.verification_json.map(|j| j.0).unwrap_or(Value::Null),
            rollback_template_id: r.rollback_template_id,
            v6_sibling_template_id: r.v6_sibling_template_id,
            enabled: r.enabled,
        }
    }
}

/// Load one template by id.
pub async fn load(pool: &MySqlPool, id: u64) -> Result<Template> {
    let row = sqlx::query_as::<_, TemplateRow>(&format!(
        "SELECT {COLS} FROM reroute_templates WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("loading reroute template")?
    .ok_or_else(|| anyhow!("reroute template {id} not found"))?;
    Ok(row.into())
}

/// Load every template (for the catalog page).
pub async fn load_all(pool: &MySqlPool) -> Result<Vec<Template>> {
    let rows = sqlx::query_as::<_, TemplateRow>(&format!(
        "SELECT {COLS} FROM reroute_templates ORDER BY provider_type, name"
    ))
    .fetch_all(pool)
    .await
    .context("loading reroute templates")?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// The concrete, ready-to-run plan for a device_cli template + parameters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RenderedPlan {
    pub template_id: u64,
    pub template_name: String,
    pub config_mode: bool,
    /// Full command sequence in order (incl. `configure terminal` / `end`).
    pub commands: Vec<String>,
    pub verify: Option<VerifyStep>,
}

/// A post-action verification read (a `show` command + substring expectations).
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyStep {
    pub command: String,
    /// Substring that MUST appear in the output for success.
    pub expect: Option<String>,
    /// Substring that must NOT appear for success.
    pub reject: Option<String>,
}

/// Validate `params` against `schema` and expand derived values. Returns a flat
/// name -> string substitution map (a `cidr` param `X` also yields `X_net` /
/// `X_mask`). Errors are user-facing and never leak internals.
pub fn validate_and_expand(schema: &Value, params: &Value) -> Result<Map<String, Value>> {
    let schema_obj = schema
        .as_object()
        .ok_or_else(|| anyhow!("this template has no parameter schema"))?;
    let empty = Map::new();
    let params_obj = params.as_object().unwrap_or(&empty);

    let mut subst: Map<String, Value> = Map::new();
    for (name, spec) in schema_obj {
        let ty = spec.get("type").and_then(Value::as_str).unwrap_or("string");
        let required = spec
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Optional schema default, used when the caller omits the param.
        let default = spec.get("default").and_then(|d| match d {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        });

        let provided = match params_obj.get(name) {
            Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
            Some(Value::Number(n)) => n.to_string(),
            _ => match default {
                Some(d) => d,
                None if required => bail!("missing required parameter '{name}'"),
                None => continue,
            },
        };

        match ty {
            "ip" => {
                let ip: Ipv4Addr = provided
                    .parse()
                    .map_err(|_| anyhow!("parameter '{name}' must be an IPv4 address"))?;
                subst.insert(name.clone(), Value::String(ip.to_string()));
            }
            "asn" => {
                let asn: u32 = provided
                    .parse()
                    .map_err(|_| anyhow!("parameter '{name}' must be an AS number"))?;
                if asn == 0 {
                    bail!("parameter '{name}' must be a non-zero AS number");
                }
                subst.insert(name.clone(), Value::String(asn.to_string()));
            }
            "int" => {
                let n: u32 = provided
                    .parse()
                    .map_err(|_| anyhow!("parameter '{name}' must be a non-negative integer"))?;
                subst.insert(name.clone(), Value::String(n.to_string()));
            }
            "cidr" => {
                // Address family is pinned per-param ("v4" default, "v6" opt-in) so
                // a value of the wrong family is rejected rather than mis-rendered.
                let family = spec.get("family").and_then(Value::as_str).unwrap_or("v4");
                // Optional blast-radius bound: the prefix must be /min_len or more
                // specific (e.g. 8 for v4, 29 for v6). Auto-detected hosts (/32,/128)
                // always pass; a too-broad manual prefix is refused.
                let min_len = spec.get("min_len").and_then(Value::as_u64).map(|n| n as u32);
                if family == "v6" {
                    let (net, len, norm) =
                        parse_cidr_v6(&provided).map_err(|e| anyhow!("parameter '{name}': {e}"))?;
                    enforce_min_len(name, len, min_len)?;
                    subst.insert(name.clone(), Value::String(norm));
                    subst.insert(format!("{name}_net"), Value::String(net));
                    subst.insert(format!("{name}_len"), Value::String(len.to_string()));
                } else {
                    let (net, mask, len, norm) =
                        parse_cidr_v4(&provided).map_err(|e| anyhow!("parameter '{name}': {e}"))?;
                    enforce_min_len(name, len, min_len)?;
                    subst.insert(name.clone(), Value::String(norm));
                    subst.insert(format!("{name}_net"), Value::String(net));
                    subst.insert(format!("{name}_mask"), Value::String(mask));
                    subst.insert(format!("{name}_len"), Value::String(len.to_string()));
                }
            }
            _ => {
                // Restricted string: no whitespace (prevents CLI injection).
                if provided.chars().any(char::is_whitespace) {
                    bail!("parameter '{name}' must not contain whitespace");
                }
                // Optional closed set (e.g. a BGP direction in|out).
                if let Some(allowed) = spec.get("enum").and_then(Value::as_array) {
                    if !allowed.iter().any(|v| v.as_str() == Some(provided.as_str())) {
                        let list: Vec<&str> = allowed.iter().filter_map(Value::as_str).collect();
                        bail!("parameter '{name}' must be one of: {}", list.join(", "));
                    }
                }
                subst.insert(name.clone(), Value::String(provided));
            }
        }
    }

    // Containment pass: a `subprefix_of` param must sit within its parent CIDR
    // (the AWS-SG-style "any subnet of, including the whole prefix" rule).
    for (name, spec) in schema_obj {
        let Some(parent) = spec.get("subprefix_of").and_then(Value::as_str) else {
            continue;
        };
        if let (Some(child), Some(par)) = (
            subst.get(name).and_then(Value::as_str),
            subst.get(parent).and_then(Value::as_str),
        ) {
            if !cidr_contains(par, child)? {
                bail!("parameter '{name}' ({child}) must be within {parent} ({par})");
            }
        }
    }
    Ok(subst)
}

/// True if `child` CIDR is equal to or more-specific than (contained in) `parent`.
/// Cross-family pairs (v4 vs v6) are never contained.
fn cidr_contains(parent: &str, child: &str) -> Result<bool> {
    let (pnet, plen) = parse_cidr_any(parent)?;
    let (cnet, clen) = parse_cidr_any(child)?;
    if clen < plen || pnet.is_ipv4() != cnet.is_ipv4() {
        return Ok(false); // child must be same family and equal/more-specific
    }
    Ok(network_of(cnet, plen) == network_of(pnet, plen))
}

/// True if host `ip` falls within `cidr` (same family). Best-effort: an
/// unparseable cidr or a family mismatch is simply "not contained". Used by the
/// flow auto-target resolver to keep a derived host inside our announced space.
pub fn cidr_contains_host(cidr: &str, ip: IpAddr) -> bool {
    match parse_cidr_any(cidr) {
        Ok((net, len)) if net.is_ipv4() == ip.is_ipv4() => {
            network_of(ip, len) == network_of(net, len)
        }
        _ => false,
    }
}

/// Mask an address down to its `len`-bit network (family-aware).
fn network_of(ip: IpAddr, len: u32) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX.checked_shl(32 - len.min(32)).unwrap_or(0)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX.checked_shl(128 - len.min(128)).unwrap_or(0)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

/// Parse "addr/len" (v4 or v6) -> (network address, prefix length).
fn parse_cidr_any(s: &str) -> Result<(IpAddr, u32)> {
    let (ip_s, len_s) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR '{s}'"))?;
    let ip: IpAddr = ip_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid IP in '{s}'"))?;
    let len: u32 = len_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid prefix length in '{s}'"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len > max {
        bail!("prefix length out of range in '{s}'");
    }
    Ok((network_of(ip, len), len))
}

/// Render a device_cli template into its exact command list + verification.
pub fn render(t: &Template, params: &Value) -> Result<RenderedPlan> {
    if t.provider_type != "device_cli" {
        bail!("preview is only supported for device_cli templates");
    }
    let subst = validate_and_expand(&t.parameter_schema, params)?;

    let plan = t
        .plan
        .as_object()
        .ok_or_else(|| anyhow!("template has no plan"))?;
    let config_mode = plan
        .get("config_mode")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let apply = plan
        .get("apply")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("template plan has no apply commands"))?;

    // Optional exec commands that run AFTER the config block closes (privileged
    // EXEC, e.g. `clear ip bgp <peer> soft out`). They are never wrapped in
    // `configure terminal` / `end`.
    let exec_after = plan
        .get("exec_after")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut commands = Vec::with_capacity(apply.len() + exec_after.len() + 2);
    if config_mode {
        commands.push("configure terminal".to_string());
    }
    for c in apply {
        let raw = c
            .as_str()
            .ok_or_else(|| anyhow!("plan command is not a string"))?;
        commands.push(substitute(raw, &subst)?);
    }
    if config_mode {
        commands.push("end".to_string());
    }
    for c in &exec_after {
        let raw = c
            .as_str()
            .ok_or_else(|| anyhow!("plan exec_after command is not a string"))?;
        commands.push(substitute(raw, &subst)?);
    }

    // expect/reject may reference template params (e.g. `{prefix_net}`); substitute
    // them too. A static substring (no braces) passes through unchanged.
    let verify = match t.verification.as_object() {
        Some(v) => match v.get("command").and_then(Value::as_str) {
            Some(cmd) => Some(VerifyStep {
                command: substitute(cmd, &subst)?,
                expect: subst_opt(v.get("expect"), &subst)?,
                reject: subst_opt(v.get("reject"), &subst)?,
            }),
            None => None,
        },
        None => None,
    };

    Ok(RenderedPlan {
        template_id: t.id,
        template_name: t.name.clone(),
        config_mode,
        commands,
        verify,
    })
}

/// Replace `{name}` tokens; error if any placeholder is unresolved (so a command
/// is never sent with a missing parameter).
fn substitute(template: &str, subst: &Map<String, Value>) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unbalanced '{{' in template command"))?;
        let key = &after[..end];
        let val = subst
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("unresolved parameter '{{{key}}}'"))?;
        out.push_str(val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Substitute `{name}` tokens in an optional verification substring (expect /
/// reject). `None` (no such key / not a string) passes through as `None`.
fn subst_opt(v: Option<&Value>, subst: &Map<String, Value>) -> Result<Option<String>> {
    match v.and_then(Value::as_str) {
        Some(s) => Ok(Some(substitute(s, subst)?)),
        None => Ok(None),
    }
}

/// Parse `a.b.c.d/len` -> (network, netmask, len, normalized `net/len`). IPv4.
fn parse_cidr_v4(s: &str) -> Result<(String, String, u32, String)> {
    let (ip_s, len_s) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("expected CIDR a.b.c.d/len"))?;
    let ip: Ipv4Addr = ip_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid IPv4 address"))?;
    let len: u32 = len_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid prefix length"))?;
    if len > 32 {
        bail!("prefix length must be 0..32");
    }
    let mask: u32 = if len == 0 {
        0
    } else {
        u32::MAX.checked_shl(32 - len).unwrap_or(0)
    };
    let net = u32::from(ip) & mask;
    Ok((
        Ipv4Addr::from(net).to_string(),
        Ipv4Addr::from(mask).to_string(),
        len,
        format!("{}/{len}", Ipv4Addr::from(net)),
    ))
}

/// Refuse a prefix broader than `min_len` (the blast-radius bound). `None` = no
/// bound. A more-specific prefix (larger len, e.g. a /32 host) always passes.
fn enforce_min_len(name: &str, len: u32, min_len: Option<u32>) -> Result<()> {
    if let Some(min) = min_len {
        if len < min {
            bail!("parameter '{name}' must be /{min} or more specific (got /{len})");
        }
    }
    Ok(())
}

/// Parse `addr/len` -> (network address, len, normalized `net/len`). IPv6.
/// IPv6 routes use prefix/len form (no dotted mask), so only `net` + `len`.
fn parse_cidr_v6(s: &str) -> Result<(String, u32, String)> {
    let (ip_s, len_s) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("expected CIDR addr/len"))?;
    let ip: Ipv6Addr = ip_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid IPv6 address"))?;
    let len: u32 = len_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid prefix length"))?;
    if len > 128 {
        bail!("prefix length must be 0..128");
    }
    let mask: u128 = if len == 0 {
        0
    } else {
        u128::MAX.checked_shl(128 - len).unwrap_or(0)
    };
    let net_addr = Ipv6Addr::from(u128::from(ip) & mask);
    Ok((net_addr.to_string(), len, format!("{net_addr}/{len}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cidr_expands_to_net_and_mask() {
        let (net, mask, len, norm) = parse_cidr_v4("192.0.2.130/24").unwrap();
        assert_eq!(net, "192.0.2.0");
        assert_eq!(mask, "255.255.255.0");
        assert_eq!(len, 24);
        assert_eq!(norm, "192.0.2.0/24");
    }

    #[test]
    fn v6_cidr_param_renders_host_route() {
        // A family:"v6" cidr param yields {prefix} (normalized) + {prefix_net}; the
        // IPv6 null-route template uses prefix/len form (no dotted mask).
        let t = tmpl(
            json!({"prefix": {"type": "cidr", "family": "v6", "required": true}}),
            json!({
                "transport": "ios_ssh", "config_mode": true,
                "apply": ["ipv6 route {prefix} Null0"],
            }),
            json!({"command": "show ipv6 route {prefix_net}", "expect": "Null0"}),
        );
        let rp = render(&t, &json!({"prefix": "2001:db8::5/128"})).unwrap();
        assert_eq!(
            rp.commands,
            vec!["configure terminal", "ipv6 route 2001:db8::5/128 Null0", "end"]
        );
        assert_eq!(rp.verify.unwrap().command, "show ipv6 route 2001:db8::5");
        // A v4 value in a v6-pinned param is rejected (not mis-rendered).
        assert!(render(&t, &json!({"prefix": "192.0.2.1/32"})).is_err());
    }

    #[test]
    fn host_containment_is_family_aware() {
        use std::net::IpAddr;
        let v4: IpAddr = "203.0.113.45".parse().unwrap();
        let v6: IpAddr = "2001:db8::dead".parse().unwrap();
        // host inside / outside an announced v4 prefix
        assert!(cidr_contains_host("203.0.113.0/24", v4));
        assert!(!cidr_contains_host("198.51.100.0/24", v4));
        // v6 host inside its prefix; cross-family never matches
        assert!(cidr_contains_host("2001:db8::/32", v6));
        assert!(!cidr_contains_host("203.0.113.0/24", v6));
        assert!(!cidr_contains_host("2001:db8::/32", v4));
        // a /32 announced host contains itself
        assert!(cidr_contains_host("203.0.113.45/32", v4));
    }

    #[test]
    fn enum_param_restricts_values() {
        // A BGP direction param accepts only its closed set.
        let schema = json!({"direction": {"type": "string", "required": true, "enum": ["in", "out"]}});
        assert!(validate_and_expand(&schema, &json!({"direction": "out"})).is_ok());
        assert!(validate_and_expand(&schema, &json!({"direction": "in"})).is_ok());
        assert!(validate_and_expand(&schema, &json!({"direction": "both"})).is_err());
    }

    #[test]
    fn min_len_bounds_manual_prefix() {
        // v4: min_len 8 -> /8..32 allowed, /7 refused; an auto host /32 always ok.
        let v4 = json!({"prefix": {"type": "cidr", "required": true, "min_len": 8}});
        assert!(validate_and_expand(&v4, &json!({"prefix": "203.0.113.5/32"})).is_ok());
        assert!(validate_and_expand(&v4, &json!({"prefix": "10.0.0.0/8"})).is_ok());
        assert!(validate_and_expand(&v4, &json!({"prefix": "10.0.0.0/7"})).is_err());
        // v6: min_len 29 -> /29..128 allowed, /28 refused; an auto host /128 ok.
        let v6 = json!({"prefix": {"type": "cidr", "family": "v6", "required": true, "min_len": 29}});
        assert!(validate_and_expand(&v6, &json!({"prefix": "2001:db8::1/128"})).is_ok());
        assert!(validate_and_expand(&v6, &json!({"prefix": "2001:db8::/29"})).is_ok());
        assert!(validate_and_expand(&v6, &json!({"prefix": "2001:db8::/28"})).is_err());
    }

    #[test]
    fn substitute_rejects_unresolved() {
        let m = Map::new();
        assert!(substitute("router bgp {local_asn}", &m).is_err());
    }

    #[test]
    fn subprefix_must_be_within_parent() {
        let schema = json!({
            "parent": {"type": "cidr", "required": true, "source": "announced_prefix"},
            "target": {"type": "cidr", "required": true, "subprefix_of": "parent"},
        });
        // more-specific within the parent, and equal to the parent, are allowed.
        assert!(validate_and_expand(
            &schema,
            &json!({"parent": "192.0.2.0/24", "target": "192.0.2.128/25"})
        )
        .is_ok());
        assert!(validate_and_expand(
            &schema,
            &json!({"parent": "192.0.2.0/24", "target": "192.0.2.0/24"})
        )
        .is_ok());
        // a different block, or a less-specific block, are rejected.
        assert!(validate_and_expand(
            &schema,
            &json!({"parent": "192.0.2.0/24", "target": "198.51.100.0/24"})
        )
        .is_err());
        assert!(validate_and_expand(
            &schema,
            &json!({"parent": "192.0.2.0/24", "target": "192.0.0.0/16"})
        )
        .is_err());
    }

    fn tmpl(schema: Value, plan: Value, verification: Value) -> Template {
        Template {
            id: 1,
            name: "t".into(),
            display_name: None,
            description: None,
            provider_type: "device_cli".into(),
            mode: "ios_ssh".into(),
            automatic_allowed: false,
            parameter_schema: schema,
            plan,
            verification,
            rollback_template_id: None,
            v6_sibling_template_id: None,
            enabled: true,
        }
    }

    #[test]
    fn exec_after_runs_after_config_block() {
        let t = tmpl(
            json!({
                "neighbor_ip": {"type": "ip", "required": true},
                "prefix": {"type": "cidr", "required": true},
                "prefix_list_name": {"type": "string", "required": true},
            }),
            json!({
                "transport": "ios_ssh", "config_mode": true,
                "apply": ["ip prefix-list {prefix_list_name} permit {prefix}"],
                "exec_after": ["clear ip bgp {neighbor_ip} soft out"],
            }),
            json!({"command": "show ip bgp neighbors {neighbor_ip} advertised-routes", "expect": "{prefix_net}"}),
        );
        let rp = render(
            &t,
            &json!({"neighbor_ip": "10.0.0.1", "prefix": "192.0.2.0/24", "prefix_list_name": "PL-UPSTREAM-A"}),
        )
        .unwrap();
        assert_eq!(
            rp.commands,
            vec![
                "configure terminal",
                "ip prefix-list PL-UPSTREAM-A permit 192.0.2.0/24",
                "end",
                "clear ip bgp 10.0.0.1 soft out",
            ]
        );
        // expect substring is substituted to the prefix network.
        assert_eq!(rp.verify.unwrap().expect.as_deref(), Some("192.0.2.0"));
    }

    #[test]
    fn mss_default_and_verify_substitution() {
        let t = tmpl(
            json!({
                "interface": {"type": "string", "required": true, "source": "interface_name"},
                "mss": {"type": "int", "required": true, "default": "1436"},
            }),
            json!({
                "transport": "ios_ssh", "config_mode": true,
                "apply": ["interface {interface}", "ip tcp adjust-mss {mss}"],
            }),
            json!({"command": "show running-config interface {interface}", "expect": "ip tcp adjust-mss {mss}"}),
        );
        // mss omitted -> uses the schema default 1436.
        let rp = render(&t, &json!({"interface": "GigabitEthernet0/0"})).unwrap();
        assert_eq!(
            rp.commands,
            vec![
                "configure terminal",
                "interface GigabitEthernet0/0",
                "ip tcp adjust-mss 1436",
                "end",
            ]
        );
        assert_eq!(
            rp.verify.unwrap().expect.as_deref(),
            Some("ip tcp adjust-mss 1436")
        );
    }

    #[test]
    fn ip_param_rejects_injection() {
        let schema = json!({"neighbor_ip": {"type": "ip", "required": true}});
        // A would-be injection is not a valid IPv4 -> rejected.
        let bad = json!({"neighbor_ip": "10.0.0.1\n no router bgp 1"});
        assert!(validate_and_expand(&schema, &bad).is_err());
        let good = json!({"neighbor_ip": "10.0.0.1"});
        assert!(validate_and_expand(&schema, &good).is_ok());
    }
}
