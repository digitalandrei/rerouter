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

use std::net::Ipv4Addr;

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
    enabled: bool,
}

const COLS: &str = "id, name, display_name, description, provider_type, mode, \
     automatic_allowed, parameter_schema_json, plan_json, \
     verification_json, rollback_template_id, enabled";

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
                let (net, mask, norm) =
                    parse_cidr_v4(&provided).map_err(|e| anyhow!("parameter '{name}': {e}"))?;
                subst.insert(name.clone(), Value::String(norm));
                subst.insert(format!("{name}_net"), Value::String(net));
                subst.insert(format!("{name}_mask"), Value::String(mask));
            }
            _ => {
                // Restricted string: no whitespace (prevents CLI injection).
                if provided.chars().any(char::is_whitespace) {
                    bail!("parameter '{name}' must not contain whitespace");
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
fn cidr_contains(parent: &str, child: &str) -> Result<bool> {
    let (pnet, plen) = parse_cidr_parts(parent)?;
    let (cnet, clen) = parse_cidr_parts(child)?;
    if clen < plen {
        return Ok(false); // child must be equal or longer (more specific)
    }
    let pmask: u32 = if plen == 0 {
        0
    } else {
        u32::MAX.checked_shl(32 - plen).unwrap_or(0)
    };
    Ok((cnet & pmask) == (pnet & pmask))
}

/// Parse "a.b.c.d/len" -> (u32 network bits, prefix length).
fn parse_cidr_parts(s: &str) -> Result<(u32, u32)> {
    let (ip, len) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR '{s}'"))?;
    let ip: Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid IPv4 in '{s}'"))?;
    let len: u32 = len
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid prefix length in '{s}'"))?;
    if len > 32 {
        bail!("prefix length out of range in '{s}'");
    }
    Ok((u32::from(ip), len))
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

    let mut commands = Vec::with_capacity(apply.len() + 2);
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

    let verify = match t.verification.as_object() {
        Some(v) => match v.get("command").and_then(Value::as_str) {
            Some(cmd) => Some(VerifyStep {
                command: substitute(cmd, &subst)?,
                expect: v.get("expect").and_then(Value::as_str).map(str::to_string),
                reject: v.get("reject").and_then(Value::as_str).map(str::to_string),
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

/// Parse `a.b.c.d/len` -> (network, netmask, normalized `net/len`). IPv4 only.
fn parse_cidr_v4(s: &str) -> Result<(String, String, String)> {
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
        format!("{}/{len}", Ipv4Addr::from(net)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cidr_expands_to_net_and_mask() {
        let (net, mask, norm) = parse_cidr_v4("192.0.2.130/24").unwrap();
        assert_eq!(net, "192.0.2.0");
        assert_eq!(mask, "255.255.255.0");
        assert_eq!(norm, "192.0.2.0/24");
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
