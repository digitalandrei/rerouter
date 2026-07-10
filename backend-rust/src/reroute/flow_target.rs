//! Flow auto-target resolution: derive the host to null-route from flow telemetry
//! at fire/apply time, instead of a hard-coded prefix.
//!
//! For a flow rule (interface + direction + protocol + port selector — e.g. TCP
//! dport 443) the resolver finds the heaviest destination IP in the matching flows
//! over a recent window and forms a /32 (IPv4) or /128 (IPv6) host route — BUT only
//! if that host sits inside one of the null-route device's announced prefixes
//! (`device_bgp_networks`). We never black-hole an address outside our own space.
//!
//! LOW flow-sampling confidence is surfaced (not hidden): the detection engine
//! blocks AUTOMATIC execution on it (doctrine), while a manual apply may proceed
//! with the operator's eyes on the resolved IP. The resolved host is always
//! rendered into the would-run plan before anything runs.

use std::fmt;
use std::net::IpAddr;

use serde_json::{Map, Value};
use sqlx::MySqlPool;

use crate::reroute::templates::{self, Template};

/// The marker stored in `rule_actions.auto_target` for "null-route the attacked
/// destination host derived from this flow rule".
pub const FLOW_DST_HOST: &str = "flow_dst_host";

/// How far back to look for the current victim. The flood is live, so a short
/// window reflects "who is being hit right now" without dragging in stale targets.
const WINDOW_MINUTES: i64 = 5;
/// How many top destinations to consider before giving up on in-prefix containment.
const CANDIDATE_LIMIT: i64 = 10;

/// The flow selector an auto-target action resolves against (taken from the rule).
pub struct FlowSelector {
    pub interface_id: Option<u64>,
    pub direction: Option<String>,
    pub protocol: Option<u16>,
    pub port: Option<u16>,
    pub port_kind: Option<String>,
}

/// A resolved auto-target host.
pub struct ResolvedTarget {
    /// Host route, e.g. "203.0.113.45/32" or "2001:db8::5/128".
    pub cidr: String,
    pub is_v6: bool,
    pub est_bytes: u64,
    pub est_pkts: u64,
    pub low_confidence: bool,
}

/// Why resolution did not yield a usable, in-prefix host.
#[derive(Debug, PartialEq, Eq)]
pub enum TargetError {
    NotFlowRule,
    UnknownInterface,
    NoOwnedPrefixes,
    NoFlows,
    NoInPrefixTarget,
    Db,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::NotFlowRule => {
                write!(f, "auto-target needs a flow rule (no flow selector on this rule)")
            }
            TargetError::UnknownInterface => write!(f, "rule interface not found"),
            TargetError::NoOwnedPrefixes => write!(
                f,
                "device has no announced prefixes discovered — run prefix discovery before using auto-target"
            ),
            TargetError::NoFlows => write!(
                f,
                "no matching flows in the last {WINDOW_MINUTES} min to identify a target host"
            ),
            TargetError::NoInPrefixTarget => write!(
                f,
                "no attacked destination falls within the device's announced prefixes"
            ),
            TargetError::Db => write!(f, "database error resolving the target host"),
        }
    }
}

/// Resolve the top in-prefix destination host for a flow selector.
/// `null_route_device_id` is the device the route will be installed on; its
/// announced prefixes bound the target (we only black-hole our own space).
pub async fn resolve_flow_dst_host(
    pool: &MySqlPool,
    sel: &FlowSelector,
    null_route_device_id: u64,
) -> Result<ResolvedTarget, TargetError> {
    let direction = sel.direction.as_deref().ok_or(TargetError::NotFlowRule)?;
    let interface_id = sel.interface_id.ok_or(TargetError::NotFlowRule)?;

    // The flow source device + ifIndex for the rule's monitored interface (flows
    // are bucketed by ifIndex, which is always present unlike interface_id).
    let (flow_device_id, if_index): (u64, u32) =
        sqlx::query_as("SELECT device_id, if_index FROM device_interfaces WHERE id = ?")
            .bind(interface_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| TargetError::Db)?
            .ok_or(TargetError::UnknownInterface)?;

    // Announced prefixes that bound the target, on the null-route device.
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT prefix FROM device_bgp_networks WHERE device_id = ? \
           AND last_discovered_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? HOUR)",
    )
    .bind(null_route_device_id)
    .bind(templates::ROUTING_INVENTORY_MAX_AGE_HOURS)
    .fetch_all(pool)
    .await
    .map_err(|_| TargetError::Db)?;
    if owned.is_empty() {
        return Err(TargetError::NoOwnedPrefixes);
    }

    // Top candidate destinations matching the selector over the window. port_col is
    // whitelisted (never raw input), matching the flows read API's pattern.
    let mut sql = String::from(
        "SELECT dst_addr, \
         CAST(SUM(bytes * effective_sampling_rate) AS UNSIGNED) AS est_bytes, \
         CAST(SUM(pkts  * effective_sampling_rate) AS UNSIGNED) AS est_pkts, \
         CAST(MAX(sampling_confidence = 'low') AS UNSIGNED) AS low_conf \
         FROM flow_talker_buckets \
         WHERE device_id = ? AND if_index = ? AND direction = ? \
           AND bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)",
    );
    if sel.protocol.is_some() {
        sql.push_str(" AND protocol = ?");
    }
    let port_col = match sel.port_kind.as_deref() {
        Some("src") => "src_port",
        _ => "dst_port",
    };
    if sel.port.is_some() {
        sql.push_str(" AND ");
        sql.push_str(port_col);
        sql.push_str(" = ?");
    }
    sql.push_str(" GROUP BY dst_addr ORDER BY est_bytes DESC LIMIT ");
    sql.push_str(&CANDIDATE_LIMIT.to_string());

    let mut q = sqlx::query_as::<_, (String, u64, u64, u64)>(&sql)
        .bind(flow_device_id)
        .bind(if_index)
        .bind(direction)
        .bind(WINDOW_MINUTES);
    if let Some(p) = sel.protocol {
        q = q.bind(p);
    }
    if let Some(p) = sel.port {
        q = q.bind(p);
    }
    let rows = q.fetch_all(pool).await.map_err(|_| TargetError::Db)?;
    if rows.is_empty() {
        return Err(TargetError::NoFlows);
    }

    // Pick the heaviest destination that is inside our announced space.
    for (dst, est_bytes, est_pkts, low_conf) in rows {
        let Ok(ip) = dst.parse::<IpAddr>() else {
            continue;
        };
        if owned.iter().any(|p| templates::cidr_contains_host(p, ip)) {
            let is_v6 = ip.is_ipv6();
            return Ok(ResolvedTarget {
                cidr: format!("{ip}/{}", if is_v6 { 128 } else { 32 }),
                is_v6,
                est_bytes,
                est_pkts,
                low_confidence: low_conf != 0,
            });
        }
    }
    Err(TargetError::NoInPrefixTarget)
}

/// Auto-target metadata attached to a prepared action (for the plan / alert).
pub struct AutoTargetInfo {
    pub cidr: String,
    pub low_confidence: bool,
    pub note: String,
}

/// A rule action made ready to run: the (possibly family-swapped) template + the
/// concrete params, plus any auto-target metadata. Or a reason it was skipped.
// The Ready variant carries a `Template` by value (as `ActionRequest` does); this
// is a short-lived per-action value, so boxing to equalize variants buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum PreparedAction {
    Ready {
        template: Template,
        params: Value,
        auto_target: Option<AutoTargetInfo>,
    },
    Skip {
        reason: String,
    },
}

/// Build a ready-to-run action from a stored `rule_action`. A static action just
/// loads its template. An auto-target action resolves the flow destination host,
/// swaps to the IPv6 sibling template when the victim is IPv6, and merges the
/// resolved host into the params (keeping other params such as the RTBH tag).
pub async fn prepare_action(
    pool: &MySqlPool,
    sel: &FlowSelector,
    template_id: u64,
    null_route_device_id: u64,
    params: Value,
    auto_target: Option<&str>,
) -> PreparedAction {
    let base = match templates::load(pool, template_id).await {
        Ok(t) => t,
        Err(_) => {
            return PreparedAction::Skip {
                reason: "template not found".into(),
            }
        }
    };

    if auto_target != Some(FLOW_DST_HOST) {
        return PreparedAction::Ready {
            template: base,
            params,
            auto_target: None,
        };
    }

    let resolved = match resolve_flow_dst_host(pool, sel, null_route_device_id).await {
        Ok(r) => r,
        Err(e) => {
            return PreparedAction::Skip {
                reason: format!("auto-target: {e}"),
            }
        }
    };

    // Family-appropriate template: swap to the IPv6 sibling for an IPv6 victim.
    let template = if resolved.is_v6 {
        match base.v6_sibling_template_id {
            Some(sib) => match templates::load(pool, sib).await {
                Ok(t) => t,
                Err(_) => {
                    return PreparedAction::Skip {
                        reason: "auto-target: IPv6 sibling template is missing".into(),
                    }
                }
            },
            None => {
                return PreparedAction::Skip {
                    reason: format!(
                        "auto-target: victim {} is IPv6 but '{}' has no IPv6 variant",
                        resolved.cidr, base.name
                    ),
                }
            }
        }
    } else {
        base
    };

    let mut obj: Map<String, Value> = params.as_object().cloned().unwrap_or_default();
    obj.insert("prefix".into(), Value::String(resolved.cidr.clone()));

    let note = format!(
        "auto-target {} (~{} bytes, ~{} pkts in {WINDOW_MINUTES} min{})",
        resolved.cidr,
        resolved.est_bytes,
        resolved.est_pkts,
        if resolved.low_confidence {
            ", LOW sampling confidence"
        } else {
            ""
        },
    );
    PreparedAction::Ready {
        template,
        params: Value::Object(obj),
        auto_target: Some(AutoTargetInfo {
            cidr: resolved.cidr,
            low_confidence: resolved.low_confidence,
            note,
        }),
    }
}
