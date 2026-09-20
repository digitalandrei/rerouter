//! Durable, versioned device-action plans.
//!
//! A prepared plan is the boundary between read-only inspection and a router
//! mutation.  It records the exact state observed, the exact commands to send,
//! the state that must be proved afterwards, and the compare-before-restore
//! inverse.  Callers persist the complete value before any command is sent.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::MySqlPool;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PREPARED_DEVICE_ACTION_SCHEMA_VERSION: u16 = 1;
pub const PREPARED_TEMPLATE_NAMES: &[&str] = &[
    "null_route_prefix",
    "null_route_withdraw",
    "null_route_prefix_v6",
    "null_route_withdraw_v6",
    "blackhole_prefix",
    "blackhole_withdraw",
    "blackhole_prefix_v6",
    "blackhole_withdraw_v6",
    "bgp_session_enable",
    "bgp_session_disable",
    "bgp_advertise_add",
    "bgp_advertise_remove",
    "bgp_route_map_set",
    "bgp_route_map_unset",
    "bgp_export_policy_set",
    "iface_tcp_adjust_mss",
    "iface_tcp_adjust_mss_remove",
    "iface_shutdown",
    "iface_no_shutdown",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTransportIdentity {
    pub host: String,
    pub port: u16,
    pub pinned_host_fingerprint: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    #[default]
    Routing,
    ConfigurationOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedEffect {
    Change,
    AlreadySatisfied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedSafetyEffect {
    Additive,
    Neutral,
    Destructive,
    Mixed,
    Noop,
    Unproven,
}

pub fn prepared_safety_effect(action: &PreparedDeviceAction) -> Result<PreparedSafetyEffect> {
    if action.effect == PreparedEffect::AlreadySatisfied {
        return Ok(PreparedSafetyEffect::Noop);
    }
    if action.template_name != "bgp_export_policy_set" {
        return Ok(PreparedSafetyEffect::Unproven);
    }
    let kind = action
        .canonical_params
        .get("policy_kind")
        .and_then(Value::as_str);
    let route_map_safe = |states: &[DeviceStateSnapshot]| -> bool {
        states
            .iter()
            .find_map(|state| match state {
                DeviceStateSnapshot::ExportPolicyAttachment {
                    route_map,
                    route_maps,
                    ..
                } => Some(match route_map {
                    None => true,
                    Some(name) => route_maps
                        .iter()
                        .find(|m| m.name == *name)
                        .is_some_and(|map| {
                            !map.clauses.is_empty()
                                && map.clauses.iter().all(|clause| {
                                    clause.action == crate::reroute::policy::PermitDeny::Permit
                                        && clause.matches.is_empty()
                                        && clause.sets.iter().all(|term| {
                                            term.value.starts_with("as-path prepend ")
                                                || term.value.starts_with("metric ")
                                                || term.value.starts_with("local-preference ")
                                        })
                                })
                        }),
                }),
                _ => None,
            })
            .unwrap_or(false)
    };
    let extract=|states:&[DeviceStateSnapshot]|->Result<(Option<String>,Vec<crate::reroute::policy::NamedPrefixList>)>{states.iter().find_map(|state|match state{DeviceStateSnapshot::ExportPolicyAttachment{prefix_list,prefix_lists,..}=>Some((prefix_list.clone(),prefix_lists.clone())),_=>None}).ok_or_else(||anyhow::anyhow!("export policy safety evidence is incomplete"))};
    if kind == Some("route_map") {
        let extract_map = |states: &[DeviceStateSnapshot]| -> Result<(
            Option<String>,
            Vec<crate::reroute::policy::NamedRouteMap>,
        )> {
            states
                .iter()
                .find_map(|state| match state {
                    DeviceStateSnapshot::ExportPolicyAttachment {
                        route_map,
                        route_maps,
                        ..
                    } => Some((route_map.clone(), route_maps.clone())),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("export policy safety evidence is incomplete"))
        };
        let safe = |name: Option<String>, maps: Vec<crate::reroute::policy::NamedRouteMap>| {
            let Some(name) = name else { return true };
            maps.iter().find(|m| m.name == name).is_some_and(|map| {
                !map.clauses.is_empty()
                    && map.clauses.iter().all(|clause| {
                        clause.action == crate::reroute::policy::PermitDeny::Permit
                            && clause.matches.is_empty()
                            && clause.sets.iter().all(|term| {
                                term.value.starts_with("as-path prepend ")
                                    || term.value.starts_with("metric ")
                                    || term.value.starts_with("local-preference ")
                            })
                    })
            })
        };
        let before = extract_map(&action.before).is_ok_and(|(name, maps)| safe(name, maps));
        let after = extract_map(&action.after).is_ok_and(|(name, maps)| safe(name, maps));
        return Ok(if before && after {
            PreparedSafetyEffect::Neutral
        } else {
            PreparedSafetyEffect::Unproven
        });
    }
    if kind != Some("prefix_list") {
        return Ok(PreparedSafetyEffect::Unproven);
    }
    if !route_map_safe(&action.before) || !route_map_safe(&action.after) {
        return Ok(PreparedSafetyEffect::Unproven);
    }
    let (before_name, before_lists) = match extract(&action.before) {
        Ok(v) => v,
        Err(_) => return Ok(PreparedSafetyEffect::Unproven),
    };
    let (after_name, after_lists) = match extract(&action.after) {
        Ok(v) => v,
        Err(_) => return Ok(PreparedSafetyEffect::Unproven),
    };
    let permitted = |name: Option<String>,
                     lists: Vec<crate::reroute::policy::NamedPrefixList>|
     -> Result<std::collections::BTreeSet<String>> {
        let Some(name) = name else {
            bail!("absence of an outbound prefix-list is unrestricted")
        };
        let list = lists
            .into_iter()
            .find(|list| list.name == name)
            .ok_or_else(|| anyhow::anyhow!("selected prefix-list definition missing"))?;
        exact_permitted_prefixes_from_list(&list)
    };
    let before = match permitted(before_name, before_lists) {
        Ok(v) => v,
        Err(_) => return Ok(PreparedSafetyEffect::Unproven),
    };
    let after = match permitted(after_name, after_lists) {
        Ok(v) => v,
        Err(_) => return Ok(PreparedSafetyEffect::Unproven),
    };
    Ok(if before == after {
        PreparedSafetyEffect::Noop
    } else if before.is_subset(&after) {
        PreparedSafetyEffect::Additive
    } else if after.is_subset(&before) {
        PreparedSafetyEffect::Destructive
    } else {
        PreparedSafetyEffect::Mixed
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCertainty {
    ProvenNoEffect,
    UnknownEffect,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreparedExecutionError {
    pub certainty: EffectCertainty,
    pub reason: String,
}

impl std::fmt::Display for PreparedExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for PreparedExecutionError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixListSnapshotEntry {
    pub sequence: u32,
    pub permit: bool,
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ge: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub le: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixListConsumer {
    /// A stable, operator-readable kind such as `neighbor_out`, `neighbor_in`,
    /// `peer_group_out`, `route_map`, or `redistribution`.
    pub kind: String,
    pub owner: String,
    pub direction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceStateSnapshot {
    PrefixList {
        name: String,
        entries: Vec<PrefixListSnapshotEntry>,
        consumers: Vec<PrefixListConsumer>,
    },
    Ipv4StaticRoute {
        prefix: String,
        next_hop: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<u32>,
        present: bool,
    },
    Ipv6StaticRoute {
        prefix: String,
        next_hop: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<u32>,
        present: bool,
    },
    RouteResolution {
        prefix: String,
        next_hop: String,
        present: bool,
    },
    BgpAdvertisement {
        neighbor: String,
        prefix: String,
        present: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        community: Option<String>,
    },
    BgpRoute {
        prefix: String,
        present: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        community: Option<String>,
    },
    NeighborShutdown {
        local_asn: u32,
        neighbor: String,
        shutdown: bool,
    },
    BgpNeighborState {
        neighbor: String,
        administratively_shutdown: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<String>,
    },
    RouteMapAssignment {
        local_asn: u32,
        neighbor: String,
        direction: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address_family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route_map: Option<String>,
    },
    ExportPolicyAttachment {
        local_asn: u32,
        neighbor: String,
        address_family: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix_list: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route_map: Option<String>,
        prefix_lists: Vec<crate::reroute::policy::NamedPrefixList>,
        route_maps: Vec<crate::reroute::policy::NamedRouteMap>,
        /// Policy definitions whose exact contents authorize this attachment.
        /// `None` means a legacy snapshot and retains the historical full-catalog
        /// comparison. New snapshots list only the current/restore objects; an
        /// empty list deliberately means this policy kind has no owned definition, so
        /// unrelated policy additions cannot strand a valid inverse.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_prefix_lists: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_route_maps: Option<Vec<String>>,
    },
    InterfaceAdmin {
        interface: String,
        shutdown: bool,
    },
    InterfaceOperational {
        interface: String,
        administratively_down: bool,
    },
    InterfaceMss {
        interface: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mss: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedInverse {
    #[serde(default)]
    pub verification_mode: VerificationMode,
    /// The state that must still be current before an inverse may run.  A
    /// mismatch means somebody else changed the router and the inverse refuses.
    pub expected_current: Vec<DeviceStateSnapshot>,
    pub restore: Vec<DeviceStateSnapshot>,
    pub commands: Vec<String>,
    pub verify: Vec<DeviceStateSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrepareInput {
    pub device_id: u64,
    pub template_id: u64,
    pub template_name: String,
    pub canonical_params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreparedDeviceAction {
    pub schema_version: u16,
    pub device_id: u64,
    pub template_id: u64,
    pub template_name: String,
    pub canonical_params: Value,
    #[serde(default)]
    pub verification_mode: VerificationMode,
    pub commands: Vec<String>,
    pub before: Vec<DeviceStateSnapshot>,
    pub after: Vec<DeviceStateSnapshot>,
    pub verify: Vec<DeviceStateSnapshot>,
    pub effect: PreparedEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inverse: Option<PreparedInverse>,
    pub prepared_at: DateTime<Utc>,
}

impl PreparedDeviceAction {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PREPARED_DEVICE_ACTION_SCHEMA_VERSION {
            bail!(
                "unsupported prepared action schema version {}",
                self.schema_version
            );
        }
        if self.device_id == 0 || self.template_id == 0 || self.template_name.trim().is_empty() {
            bail!("prepared action identity is incomplete");
        }
        match self.effect {
            PreparedEffect::Change
                if self.commands.is_empty()
                    || self.before.is_empty()
                    || self.after.is_empty()
                    || self.verify.is_empty() =>
            {
                bail!("a changing prepared action needs commands and non-empty before/after/verification evidence")
            }
            PreparedEffect::AlreadySatisfied
                if !self.commands.is_empty()
                    || self.inverse.is_some()
                    || self.before.is_empty()
                    || self.after.is_empty()
                    || self.verify.is_empty() =>
            {
                bail!("an already-satisfied action must own no commands/inverse and must carry explicit before/after/verification evidence")
            }
            _ => {}
        }
        if let Some(inverse) = &self.inverse {
            if inverse.verification_mode != self.verification_mode {
                bail!("prepared inverse verification scope differs from its action");
            }
            if inverse.commands.is_empty()
                || inverse.expected_current.is_empty()
                || inverse.restore.is_empty()
                || inverse.verify.is_empty()
            {
                bail!("a prepared inverse needs commands plus non-empty compare/restore/verification state");
            }
        }
        Ok(())
    }

    /// Compare the authority-bearing contents of preview and runtime
    /// preparation. Observation timestamps are evidence metadata and do not alter
    /// the command/state contract.
    pub fn equivalent_for_execution(&self, runtime: &Self) -> bool {
        self.schema_version == runtime.schema_version
            && self.device_id == runtime.device_id
            && self.template_id == runtime.template_id
            && self.template_name == runtime.template_name
            && self.canonical_params == runtime.canonical_params
            && self.verification_mode == runtime.verification_mode
            && self.commands == runtime.commands
            && self.before == runtime.before
            && self.after == runtime.after
            && self.verify == runtime.verify
            && self.effect == runtime.effect
            && self.inverse == runtime.inverse
    }
}

/// Exact configuration-line verification. IOS indentation is ignored, but the
/// command tokens and their order must match completely; a covering route,
/// different tag, or same-address/different-length prefix cannot satisfy it.
pub fn has_exact_config_line(output: &str, expected: &str) -> bool {
    let expected = expected.split_whitespace().collect::<Vec<_>>();
    output
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>() == expected)
}

/// Find an exact NLRI token in structured BGP output. Status glyphs and columns
/// may vary between IOS releases, so every whitespace-delimited token is tested,
/// but only a canonical address/length equality counts.
pub fn has_exact_cidr(output: &str, expected: &str) -> bool {
    let Some(expected) = normalize_cidr(expected) else {
        return false;
    };
    output.lines().any(|line| {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("BGP routing table entry for ") {
            let candidate = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches([',', '(', ')']);
            return normalize_cidr(candidate).as_deref() == Some(expected.as_str());
        }
        let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
        let candidate = match tokens.as_slice() {
            [first, ..] if normalize_cidr(first).is_some() => *first,
            [status, cidr, ..] if bgp_status_token(status) => *cidr,
            [status_a, status_b, cidr, ..]
                if bgp_status_token(status_a) && bgp_status_token(status_b) =>
            {
                *cidr
            }
            _ => return false,
        };
        normalize_cidr(candidate).as_deref() == Some(expected.as_str())
    })
}

fn bgp_status_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| {
            matches!(
                c,
                '*' | '>'
                    | '<'
                    | 's'
                    | 'd'
                    | 'h'
                    | 'r'
                    | 'S'
                    | 'f'
                    | 'x'
                    | 'a'
                    | 'c'
                    | 'm'
                    | 'b'
                    | 'i'
            )
        })
}

/// Verify an exact BGP NLRI plus the exact intended community token. This is
/// suitable for output of `show ip bgp <exact-prefix>`; callers must not feed a
/// multi-prefix table because community lines are associated by command scope.
pub fn has_exact_bgp_route(output: &str, prefix: &str, community: Option<&str>) -> bool {
    let lines = output.lines().collect::<Vec<_>>();
    lines.iter().enumerate().any(|(start, line)| {
        if !bgp_line_has_exact_prefix(line, prefix) {
            return false;
        }
        let end = lines[start + 1..]
            .iter()
            .position(|candidate| bgp_line_prefix(candidate).is_some())
            .map(|offset| start + 1 + offset)
            .unwrap_or(lines.len());
        community.is_none_or(|wanted| {
            lines[start..end].iter().any(|block_line| {
                block_line
                    .split_whitespace()
                    .any(|token| token.trim_matches([',', '(', ')']) == wanted)
            })
        })
    })
}

pub fn has_exact_route_resolution(output: &str, prefix: &str, next_hop: &str) -> bool {
    let Some(expected) = normalize_cidr(prefix) else {
        return false;
    };
    let lines = output.lines().collect::<Vec<_>>();
    lines.iter().enumerate().any(|(start, line)| {
        let exact = line
            .trim()
            .strip_prefix("Routing entry for ")
            .and_then(|rest| rest.split_whitespace().next())
            .map(|candidate| candidate.trim_matches([',', '(', ')']))
            .and_then(normalize_cidr)
            .as_deref()
            == Some(expected.as_str());
        if !exact {
            return false;
        }
        let end = lines[start + 1..]
            .iter()
            .position(|candidate| candidate.trim().starts_with("Routing entry for "))
            .map(|offset| start + 1 + offset)
            .unwrap_or(lines.len());
        lines[start..end].iter().any(|block_line| {
            block_line
                .split_whitespace()
                .any(|token| token.trim_matches([',', '*', '(', ')']) == next_hop)
        })
    })
}

fn bgp_line_prefix(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("BGP routing table entry for ") {
        return rest
            .split_whitespace()
            .next()
            .map(|token| token.trim_matches([',', '(', ')']))
            .and_then(normalize_cidr);
    }
    let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    let candidate = match tokens.as_slice() {
        [first, ..] if normalize_cidr(first).is_some() => *first,
        [status, cidr, ..] if bgp_status_token(status) => *cidr,
        [status_a, status_b, cidr, ..]
            if bgp_status_token(status_a) && bgp_status_token(status_b) =>
        {
            *cidr
        }
        _ => return None,
    };
    normalize_cidr(candidate)
}

fn bgp_line_has_exact_prefix(line: &str, prefix: &str) -> bool {
    bgp_line_prefix(line).as_deref() == normalize_cidr(prefix).as_deref()
}

pub(crate) fn complete_advertisement_table(output: &str) -> bool {
    let lines = output.lines().collect::<Vec<_>>();
    let Some(header) = lines.iter().position(|line| {
        line.to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["network", "next"])
    }) else {
        return false;
    };
    let Some((footer, declared)) =
        lines
            .iter()
            .enumerate()
            .skip(header + 1)
            .find_map(|(i, line)| {
                let lower = line.trim().to_ascii_lowercase();
                lower
                    .strip_prefix("total number of prefixes ")
                    .and_then(|count| count.trim().parse::<usize>().ok())
                    .map(|count| (i, count))
            })
    else {
        return false;
    };
    let rows = &lines[header + 1..footer];
    rows.iter()
        .all(|line| line.trim().is_empty() || bgp_line_prefix(line).is_some())
        && rows
            .iter()
            .filter(|line| bgp_line_prefix(line).is_some())
            .count()
            == declared
        && lines[footer + 1..]
            .iter()
            .all(|line| line.trim().is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceVerdict {
    Matched,
    ProvenMismatch,
    Unproven,
}

fn evidence_matches(verdict: EvidenceVerdict, subject: &str) -> Result<bool> {
    match verdict {
        EvidenceVerdict::Matched => Ok(true),
        EvidenceVerdict::ProvenMismatch => Ok(false),
        EvidenceVerdict::Unproven => {
            bail!("{subject} response did not prove either presence or absence")
        }
    }
}

fn explicit_absence(output: &str) -> bool {
    output.lines().any(|line| {
        matches!(
            line.trim().to_ascii_lowercase().as_str(),
            "% network not in table"
                | "network not in table"
                | "% route not found"
                | "route not found"
                | "% no matching route"
                | "no matching route"
        )
    })
}

fn bgp_evidence(
    output: &str,
    prefix: &str,
    community: Option<&str>,
    advertisement: bool,
    expected_present: bool,
) -> EvidenceVerdict {
    if output.trim().is_empty() {
        return EvidenceVerdict::Unproven;
    }
    let exact_prefix = has_exact_cidr(output, prefix);
    let exact_value = has_exact_bgp_route(output, prefix, community);
    if exact_prefix {
        return if expected_present && exact_value {
            EvidenceVerdict::Matched
        } else {
            EvidenceVerdict::ProvenMismatch
        };
    }
    let advertisement_table = advertisement && complete_advertisement_table(output);
    let exact_detail_absent = !advertisement && explicit_absence(output);
    if advertisement_table || exact_detail_absent {
        if expected_present {
            EvidenceVerdict::ProvenMismatch
        } else {
            EvidenceVerdict::Matched
        }
    } else {
        EvidenceVerdict::Unproven
    }
}

fn route_resolution_evidence(
    output: &str,
    prefix: &str,
    next_hop: &str,
    expected_present: bool,
) -> EvidenceVerdict {
    let exact_prefix = has_exact_route_resolution(output, prefix, next_hop)
        || output.lines().any(|line| {
            line.trim()
                .strip_prefix("Routing entry for ")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(normalize_cidr)
                .as_deref()
                == normalize_cidr(prefix).as_deref()
        });
    if exact_prefix {
        let exact_value = has_exact_route_resolution(output, prefix, next_hop);
        if expected_present && exact_value {
            EvidenceVerdict::Matched
        } else {
            EvidenceVerdict::ProvenMismatch
        }
    } else if explicit_absence(output) {
        if expected_present {
            EvidenceVerdict::ProvenMismatch
        } else {
            EvidenceVerdict::Matched
        }
    } else {
        EvidenceVerdict::Unproven
    }
}

fn validate_interface_stanza(output: &str, interface: &str) -> Result<()> {
    let headers = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("interface "))
        .collect::<Vec<_>>();
    if headers.len() != 1 || headers[0] != interface {
        bail!("interface configuration response was not exactly the requested {interface} stanza");
    }
    Ok(())
}

/// Prepare the sequenced one-peer prefix-list action entirely from read-only
/// snapshots. The caller obtains these reads again under the native IOS lock at
/// execution time and compares the resulting value with the authorized preview.
pub fn prepare_prefix_list_action(
    input: &PrepareInput,
    template: &super::templates::Template,
    bgp_config: &str,
    route_map_config: &str,
    full_config: &str,
    neighbor_output: &str,
    prefix_list_output: &str,
) -> Result<PreparedDeviceAction> {
    use super::prefix_list::{self, SequencePlan};

    if !matches!(
        template.name.as_str(),
        "bgp_advertise_add" | "bgp_advertise_remove"
    ) {
        bail!("template '{}' is not a prefix-list action", template.name);
    }
    if input.device_id == 0
        || input.template_id != template.id
        || input.template_name != template.name
    {
        bail!("prepare input does not match the selected template");
    }
    let subst =
        super::templates::validate_and_expand(&template.parameter_schema, &input.canonical_params)?;
    let get = |name: &str| -> Result<String> {
        subst
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("missing canonical parameter '{name}'"))
    };
    let peer = get("neighbor_ip")?;
    let list = get("prefix_list_name")?;
    let prefix = get("prefix")?;
    let parsed_neighbor = parse_bgp_neighbor_state(neighbor_output, &peer)?;
    if parsed_neighbor.administratively_shutdown
        || parsed_neighbor.state.as_deref() != Some("Established")
    {
        bail!("BGP neighbor {peer} is not Established; refusing per-peer advertisement mutation");
    }
    let established_neighbor = DeviceStateSnapshot::BgpNeighborState {
        neighbor: peer.clone(),
        administratively_shutdown: false,
        state: Some("Established".into()),
    };
    let consumers = crate::ssh::ensure_exclusive_prefix_list_consumer(
        bgp_config,
        route_map_config,
        full_config,
        &list,
        &peer,
    )?;
    let entries =
        prefix_list::parse_prefix_list(prefix_list_output, &list).map_err(anyhow::Error::msg)?;
    let before_entries = entries
        .iter()
        .map(prefix_entry_snapshot)
        .collect::<Vec<_>>();
    let before_list = DeviceStateSnapshot::PrefixList {
        name: list.clone(),
        entries: before_entries.clone(),
        consumers: consumers.clone(),
    };

    let adding = template.name == "bgp_advertise_add";
    let decision = if adding {
        prefix_list::plan_add(prefix_list_output, &list, &prefix)
    } else {
        prefix_list::plan_remove(prefix_list_output, &list, &prefix)
    };
    let advertisement = DeviceStateSnapshot::BgpAdvertisement {
        neighbor: peer.clone(),
        prefix: prefix.clone(),
        present: adding,
        community: None,
    };
    match decision {
        SequencePlan::Refuse(reason) => bail!(reason),
        SequencePlan::AlreadySatisfied { .. } => {
            let action = PreparedDeviceAction {
                schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
                device_id: input.device_id,
                template_id: input.template_id,
                template_name: input.template_name.clone(),
                canonical_params: input.canonical_params.clone(),
                verification_mode: VerificationMode::Routing,
                commands: Vec::new(),
                before: vec![before_list.clone(), established_neighbor.clone()],
                after: vec![
                    before_list,
                    advertisement.clone(),
                    established_neighbor.clone(),
                ],
                verify: vec![advertisement, established_neighbor],
                effect: PreparedEffect::AlreadySatisfied,
                inverse: None,
                prepared_at: Utc::now(),
            };
            action.validate()?;
            Ok(action)
        }
        SequencePlan::Use(sequence) => {
            let (rendered, params) = super::templates::render_with_sequence(
                template,
                &input.canonical_params,
                sequence,
            )?;
            let mut after_entries = before_entries;
            if adding {
                let (network, length) = prefix
                    .split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("invalid canonical prefix"))?;
                after_entries.push(PrefixListSnapshotEntry {
                    sequence,
                    permit: true,
                    prefix: format!("{network}/{length}"),
                    ge: None,
                    le: None,
                });
                after_entries.sort_by_key(|entry| entry.sequence);
            } else {
                after_entries.retain(|entry| entry.sequence != sequence);
            }
            let after_list = DeviceStateSnapshot::PrefixList {
                name: list.clone(),
                entries: after_entries,
                consumers,
            };
            let inverse_config = if adding {
                format!("no ip prefix-list {list} seq {sequence} permit {prefix}")
            } else {
                format!("ip prefix-list {list} seq {sequence} permit {prefix}")
            };
            let inverse_advertisement = DeviceStateSnapshot::BgpAdvertisement {
                neighbor: peer.clone(),
                prefix: prefix.clone(),
                present: !adding,
                community: None,
            };
            let inverse = PreparedInverse {
                verification_mode: VerificationMode::Routing,
                expected_current: vec![
                    after_list.clone(),
                    advertisement.clone(),
                    established_neighbor.clone(),
                ],
                restore: vec![
                    before_list.clone(),
                    inverse_advertisement.clone(),
                    established_neighbor.clone(),
                ],
                commands: vec![
                    "configure terminal".into(),
                    inverse_config,
                    "end".into(),
                    format!("clear ip bgp {peer} soft out"),
                ],
                verify: vec![
                    before_list.clone(),
                    inverse_advertisement,
                    established_neighbor.clone(),
                ],
            };
            let action = PreparedDeviceAction {
                schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
                device_id: input.device_id,
                template_id: input.template_id,
                template_name: input.template_name.clone(),
                canonical_params: params,
                verification_mode: VerificationMode::Routing,
                commands: rendered.commands,
                before: vec![before_list, established_neighbor.clone()],
                after: vec![
                    after_list.clone(),
                    advertisement.clone(),
                    established_neighbor.clone(),
                ],
                verify: vec![after_list, advertisement, established_neighbor],
                effect: PreparedEffect::Change,
                inverse: Some(inverse),
                prepared_at: Utc::now(),
            };
            action.validate()?;
            Ok(action)
        }
    }
}

fn prefix_entry_snapshot(entry: &super::prefix_list::PrefixListEntry) -> PrefixListSnapshotEntry {
    PrefixListSnapshotEntry {
        sequence: entry.sequence,
        permit: entry.permit,
        prefix: format!("{}/{}", entry.network, entry.length),
        ge: entry.ge,
        le: entry.le,
    }
}

/// Compare live locked-session reads with typed expected state. Every read stays
/// inside the native IOS configuration lock through `do show`; malformed or
/// unsupported state is an error, never a successful comparison.
pub async fn verify_current(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    device_id: u64,
    expected: &[DeviceStateSnapshot],
) -> Result<bool> {
    for state in expected {
        let matches = match state {
            DeviceStateSnapshot::PrefixList {
                name,
                entries,
                consumers,
            } => {
                let output = locked
                    .read(device_id, &format!("show ip prefix-list {name}"))
                    .await?;
                let actual = super::prefix_list::parse_prefix_list(&output.output, name)
                    .map_err(anyhow::Error::msg)?
                    .iter()
                    .map(prefix_entry_snapshot)
                    .collect::<Vec<_>>();
                let bgp = locked
                    .read(device_id, "show running-config | section ^router bgp")
                    .await?;
                let route_maps = locked
                    .read(device_id, "show running-config | section ^route-map")
                    .await?;
                let full_config = locked.read(device_id, "show running-config").await?;
                let actual_consumers = crate::ssh::prefix_list_consumers(
                    &bgp.output,
                    &route_maps.output,
                    &full_config.output,
                    name,
                );
                actual == *entries && actual_consumers == *consumers
            }
            DeviceStateSnapshot::Ipv4StaticRoute { present, .. } => {
                let command = static_config_read_command(state)?;
                let output = locked.read(device_id, &command).await?;
                evidence_matches(
                    static_expected_evidence(&output.output, state, *present)?,
                    "IPv4 static-route",
                )?
            }
            DeviceStateSnapshot::Ipv6StaticRoute { present, .. } => {
                let command = static_config_read_command(state)?;
                let output = locked.read(device_id, &command).await?;
                evidence_matches(
                    static_expected_evidence(&output.output, state, *present)?,
                    "IPv6 static-route",
                )?
            }
            DeviceStateSnapshot::BgpAdvertisement {
                neighbor,
                prefix,
                present,
                community,
            } => {
                let output = locked
                    .read(
                        device_id,
                        &format!("show ip bgp neighbors {neighbor} advertised-routes"),
                    )
                    .await?;
                evidence_matches(
                    bgp_evidence(&output.output, prefix, community.as_deref(), true, *present),
                    "BGP advertisement",
                )?
            }
            DeviceStateSnapshot::RouteResolution {
                prefix,
                next_hop,
                present,
            } => {
                let normalized = normalize_cidr(prefix)
                    .ok_or_else(|| anyhow::anyhow!("invalid route prefix {prefix:?}"))?;
                let (network, _) = normalized
                    .split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("invalid route prefix {prefix:?}"))?;
                let command = if normalized.contains(':') {
                    format!("show ipv6 route {normalized}")
                } else {
                    format!("show ip route {network}")
                };
                let output = locked.read(device_id, &command).await?;
                evidence_matches(
                    route_resolution_evidence(&output.output, &normalized, next_hop, *present),
                    "route-resolution",
                )?
            }
            DeviceStateSnapshot::BgpRoute {
                prefix,
                present,
                community,
            } => {
                let command = if prefix.contains(':') {
                    format!("show bgp ipv6 unicast {prefix}")
                } else {
                    format!("show ip bgp {prefix}")
                };
                let output = locked.read(device_id, &command).await?;
                evidence_matches(
                    bgp_evidence(
                        &output.output,
                        prefix,
                        community.as_deref(),
                        false,
                        *present,
                    ),
                    "BGP route",
                )?
            }
            DeviceStateSnapshot::NeighborShutdown {
                local_asn,
                neighbor,
                shutdown,
            } => {
                let output = locked
                    .read(device_id, "show running-config | section ^router bgp")
                    .await?;
                let router_line = format!("router bgp {local_asn}");
                let has_router = output.output.lines().any(|line| line.trim() == router_line);
                let line = format!("neighbor {neighbor} shutdown");
                has_router && (has_exact_config_line(&output.output, &line) == *shutdown)
            }
            DeviceStateSnapshot::BgpNeighborState {
                neighbor,
                administratively_shutdown,
                state,
            } => {
                let output = locked
                    .read(device_id, &format!("show ip bgp neighbors {neighbor}"))
                    .await?;
                let actual = parse_bgp_neighbor_state(&output.output, neighbor)?;
                actual.administratively_shutdown == *administratively_shutdown
                    && state
                        .as_ref()
                        .map(|expected| actual.state.as_deref() == Some(expected.as_str()))
                        .unwrap_or(true)
            }
            DeviceStateSnapshot::RouteMapAssignment {
                local_asn,
                neighbor,
                direction,
                address_family,
                route_map,
            } => {
                let output = locked
                    .read(device_id, "show running-config | section ^router bgp")
                    .await?;
                let has_router = output
                    .output
                    .lines()
                    .any(|line| line.trim() == format!("router bgp {local_asn}"));
                let actual = address_family
                    .as_deref()
                    .map(|family| {
                        parse_route_map_assignment_scoped(
                            &output.output,
                            neighbor,
                            direction,
                            family,
                        )
                    })
                    .transpose()?;
                has_router && actual.flatten() == *route_map && address_family.is_some()
            }
            DeviceStateSnapshot::ExportPolicyAttachment {
                local_asn,
                neighbor,
                address_family,
                prefix_list,
                route_map,
                prefix_lists,
                route_maps,
                required_prefix_lists,
                required_route_maps,
            } => {
                let bgp = locked
                    .read(device_id, "show running-config | section ^router bgp")
                    .await?;
                let rm = locked
                    .read(device_id, "show running-config | section ^route-map")
                    .await?;
                let pl = locked
                    .read(device_id, "show running-config | section ^ip prefix-list")
                    .await?;
                let inventory = crate::reroute::policy::parse_inventory(
                    device_id,
                    &bgp.output,
                    &rm.output,
                    &pl.output,
                    Utc::now(),
                );
                let direct = inventory
                    .peer_bindings
                    .iter()
                    .filter(|b| {
                        b.neighbor_ip == *neighbor
                            && b.local_asn == *local_asn
                            && b.address_family == *address_family
                            && b.direction == "out"
                            && b.scope == crate::reroute::policy::BindingScope::Direct
                    })
                    .collect::<Vec<_>>();
                let actual_prefix = direct
                    .iter()
                    .find(|b| b.policy_kind == crate::reroute::policy::PolicyKind::PrefixList)
                    .map(|b| b.policy_name.clone());
                let actual_map = direct
                    .iter()
                    .find(|b| b.policy_kind == crate::reroute::policy::PolicyKind::RouteMap)
                    .map(|b| b.policy_name.clone());
                let (actual_lists, actual_maps) = policy_definitions_without_references(
                    inventory.prefix_lists,
                    inventory.route_maps,
                );
                let required_lists_match = if let Some(required) = required_prefix_lists {
                    required.iter().all(|name| {
                        let expected = prefix_lists.iter().find(|item| item.name == *name);
                        expected.is_some()
                            && actual_lists.iter().find(|item| item.name == *name) == expected
                    })
                } else {
                    actual_lists == *prefix_lists
                };
                let required_maps_match = if let Some(required) = required_route_maps {
                    required.iter().all(|name| {
                        let expected = route_maps.iter().find(|item| item.name == *name);
                        expected.is_some()
                            && actual_maps.iter().find(|item| item.name == *name) == expected
                    })
                } else {
                    actual_maps == *route_maps
                };
                inventory.blockers.is_empty()
                    && actual_prefix == *prefix_list
                    && actual_map == *route_map
                    && required_lists_match
                    && required_maps_match
            }
            DeviceStateSnapshot::InterfaceAdmin {
                interface,
                shutdown,
            } => {
                let output = locked
                    .read(
                        device_id,
                        &format!("show running-config interface {interface}"),
                    )
                    .await?;
                validate_interface_stanza(&output.output, interface)?;
                has_exact_config_line(&output.output, "shutdown") == *shutdown
            }
            DeviceStateSnapshot::InterfaceOperational {
                interface,
                administratively_down,
            } => {
                let output = locked
                    .read(device_id, &format!("show interfaces {interface}"))
                    .await?;
                let proves_interface = output
                    .output
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{interface} is ")));
                proves_interface
                    && (output
                        .output
                        .to_ascii_lowercase()
                        .contains("administratively down")
                        == *administratively_down)
            }
            DeviceStateSnapshot::InterfaceMss { interface, mss } => {
                let output = locked
                    .read(
                        device_id,
                        &format!("show running-config interface {interface}"),
                    )
                    .await?;
                validate_interface_stanza(&output.output, interface)?;
                let actual = output.output.lines().find_map(|line| {
                    let tokens = line.split_whitespace().collect::<Vec<_>>();
                    match tokens.as_slice() {
                        ["ip", "tcp", "adjust-mss", value] => value.parse::<u32>().ok(),
                        _ => None,
                    }
                });
                actual == *mss
            }
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Preview-time exact snapshot verification over ordinary read-only SSH
/// sessions. Runtime repeats the same typed checks through `verify_current`
/// while native configuration locks are retained.
pub async fn verify_snapshots_read_only(
    pool: &MySqlPool,
    device_id: u64,
    expected: &[DeviceStateSnapshot],
) -> Result<bool> {
    let mut port = ReadOnlySnapshotPort::new(pool.clone());
    verify_current(&mut port, device_id, expected).await
}

/// Preview an ordered inverse set without requiring future sibling state to
/// exist yet. The same projection is repeated under exclusive locks at apply.
pub async fn verify_sequence_read_only(
    pool: &MySqlPool,
    actions: &[PreparedDeviceAction],
) -> Result<bool> {
    let mut port = ReadOnlySnapshotPort::new(pool.clone());
    verify_prepared_sequence(&mut port, actions).await
}

/// Reconcile an ordered inverse preview. If an action's owned after-state is
/// present it remains a Change. If its restore-state is already present, it is
/// converted to a verified no-op that still closes the original ownership link.
/// Any third state is a conflict and refuses the whole preview.
pub async fn prepare_inverse_sequence_read_only(
    pool: &MySqlPool,
    actions: &mut [PreparedDeviceAction],
) -> Result<()> {
    let mut port = ReadOnlySnapshotPort::new(pool.clone());
    reconcile_inverse_sequence(&mut port, actions).await
}

struct ReaderSnapshotPort<'a, R> {
    reader: &'a R,
}
impl<R: PreparationReader> crate::ssh::LockedDeviceSetPort for ReaderSnapshotPort<'_, R> {
    fn device_ids(&self) -> Vec<u64> {
        vec![]
    }
    fn read<'a>(
        &'a mut self,
        device_id: u64,
        command: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<crate::ssh::CommandResult>> {
        Box::pin(async move {
            Ok(crate::ssh::CommandResult {
                command: command.into(),
                output: self.reader.read_one(device_id, command).await?,
            })
        })
    }
    fn execute<'a>(
        &'a mut self,
        _: u64,
        _: &'a [String],
    ) -> crate::ssh::BoxFuture<'a, Result<crate::ssh::SshOutcome>> {
        Box::pin(async { bail!("read-only preparation port cannot execute") })
    }
    fn unlock_all(self: Box<Self>) -> crate::ssh::BoxFuture<'static, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

pub async fn prepare_inverse_sequence_read_only_with_reader<R: PreparationReader>(
    reader: &R,
    actions: &mut [PreparedDeviceAction],
) -> Result<()> {
    reconcile_inverse_sequence(&mut ReaderSnapshotPort { reader }, actions).await
}

pub async fn reconcile_inverse_sequence(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    actions: &mut [PreparedDeviceAction],
) -> Result<()> {
    let mut projected: HashMap<String, DeviceStateSnapshot> = HashMap::new();
    for action in actions {
        action.validate()?;
        if action.effect == PreparedEffect::AlreadySatisfied {
            if !states_match_with_projection(locked, action.device_id, &action.verify, &projected)
                .await?
            {
                bail!("prepared inverse no-op is no longer in its verified restore state");
            }
        } else if states_match_with_projection(locked, action.device_id, &action.before, &projected)
            .await?
        {
            // Normal inverse: current state is still owned by the original.
        } else if states_match_with_projection(locked, action.device_id, &action.after, &projected)
            .await?
            && states_match_with_projection(locked, action.device_id, &action.verify, &projected)
                .await?
        {
            action.commands.clear();
            action.before = action.after.clone();
            action.effect = PreparedEffect::AlreadySatisfied;
            action.inverse = None;
            action.prepared_at = Utc::now();
            action.validate()?;
        } else {
            bail!(
                "router state matches neither the action-owned state nor the authorized restore state"
            );
        }
        for state in action.after.iter().chain(action.verify.iter()) {
            if let Some(key) = state_key(action.device_id, state) {
                projected.insert(key, state.clone());
            }
        }
    }
    Ok(())
}

async fn states_match_with_projection(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    device_id: u64,
    states: &[DeviceStateSnapshot],
    projected: &HashMap<String, DeviceStateSnapshot>,
) -> Result<bool> {
    if states.is_empty() {
        return Ok(false);
    }
    for state in states {
        if let Some(key) = state_key(device_id, state) {
            if let Some(projected_state) = projected.get(&key) {
                if projected_state != state {
                    return Ok(false);
                }
                continue;
            }
        }
        if !verify_current(locked, device_id, std::slice::from_ref(state)).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

struct ReadOnlySnapshotPort {
    pool: MySqlPool,
    cache: BTreeMap<(u64, String), crate::ssh::CommandResult>,
}

impl ReadOnlySnapshotPort {
    fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            cache: BTreeMap::new(),
        }
    }
}

impl crate::ssh::LockedDeviceSetPort for ReadOnlySnapshotPort {
    fn device_ids(&self) -> Vec<u64> {
        Vec::new()
    }

    fn read<'a>(
        &'a mut self,
        device_id: u64,
        command: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<crate::ssh::CommandResult>> {
        Box::pin(async move {
            let key = (device_id, command.to_string());
            if let Some(result) = self.cache.get(&key) {
                return Ok(result.clone());
            }
            let outcome =
                crate::ssh::run_commands(&self.pool, device_id, &[command.to_string()]).await?;
            let result = outcome
                .results
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("device returned no result for {command:?}"))?;
            self.cache.insert(key, result.clone());
            Ok(result)
        })
    }

    fn execute<'a>(
        &'a mut self,
        _device_id: u64,
        _commands: &'a [String],
    ) -> crate::ssh::BoxFuture<'a, Result<crate::ssh::SshOutcome>> {
        Box::pin(async {
            Err(anyhow::anyhow!(
                "read-only snapshot verifier refuses command execution"
            ))
        })
    }

    fn unlock_all(self: Box<Self>) -> crate::ssh::BoxFuture<'static, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Validate an ordered preview against live state while all device locks are
/// held. The first occurrence of each state key is read from IOS; later actions
/// compare their `before` to the projected `after` of earlier siblings instead
/// of incorrectly expecting that future state to exist before the first write.
pub async fn verify_prepared_sequence(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    actions: &[PreparedDeviceAction],
) -> Result<bool> {
    let mut projected: HashMap<String, DeviceStateSnapshot> = HashMap::new();
    for action in actions {
        action.validate()?;
        for before in &action.before {
            if let Some(key) = state_key(action.device_id, before) {
                if let Some(prior_after) = projected.get(&key) {
                    if prior_after != before {
                        return Ok(false);
                    }
                } else if !verify_current(locked, action.device_id, std::slice::from_ref(before))
                    .await?
                {
                    return Ok(false);
                }
            } else if !verify_current(locked, action.device_id, std::slice::from_ref(before))
                .await?
            {
                return Ok(false);
            }
        }
        for after in &action.after {
            if let Some(key) = state_key(action.device_id, after) {
                projected.insert(key, after.clone());
            }
        }
    }
    Ok(true)
}

/// Prove the final projected state of an ordered bundle while every native
/// device lock is still retained. The last `after`/`verify` expectation for each
/// resource wins. Call this before a destructive sibling and once again before
/// releasing the bundle lock set, so an earlier additive dependency that flaps
/// after its own verification cannot license a withdrawal.
pub async fn verify_projected_after(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    actions: &[PreparedDeviceAction],
) -> Result<bool> {
    let mut final_states: HashMap<String, (u64, DeviceStateSnapshot)> = HashMap::new();
    for action in actions {
        action.validate()?;
        for state in action.after.iter().chain(action.verify.iter()) {
            let key = state_key(action.device_id, state).ok_or_else(|| {
                anyhow::anyhow!("prepared final-state evidence has no projection key: {state:?}")
            })?;
            final_states.insert(key, (action.device_id, state.clone()));
        }
    }
    let mut by_device: BTreeMap<u64, Vec<DeviceStateSnapshot>> = BTreeMap::new();
    for (_, (device_id, state)) in final_states {
        by_device.entry(device_id).or_default().push(state);
    }
    for (device_id, states) in by_device {
        if !verify_current(locked, device_id, &states).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn verify_transport_identities(
    locked: &dyn crate::ssh::LockedDeviceSetPort,
    expected: &std::collections::BTreeMap<u64, DeviceTransportIdentity>,
) -> Result<bool> {
    if locked.device_ids() != expected.keys().copied().collect::<Vec<_>>() {
        return Ok(false);
    }
    for (device_id, expected_identity) in expected {
        if locked.transport_identity(*device_id)? != *expected_identity {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn execute_prepared(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    action: &PreparedDeviceAction,
) -> Result<crate::ssh::SshOutcome> {
    action.validate()?;
    if !verify_current(locked, action.device_id, &action.before).await? {
        return Err(PreparedExecutionError {
            certainty: EffectCertainty::ProvenNoEffect,
            reason: "router state changed after preparation; no command was sent".into(),
        }
        .into());
    }
    if action.effect == PreparedEffect::AlreadySatisfied {
        if !verify_with_retry(locked, action.device_id, &action.verify).await? {
            return Err(PreparedExecutionError {
                certainty: EffectCertainty::ProvenNoEffect,
                reason: "already-satisfied state did not pass exact verification".into(),
            }
            .into());
        }
        return Ok(crate::ssh::SshOutcome {
            results: Vec::new(),
            fingerprint: "retained-locked-session".into(),
            pinned_now: false,
        });
    }
    let outcome = locked.execute(action.device_id, &action.commands).await?;
    if !verify_with_retry(locked, action.device_id, &action.verify).await? {
        return Err(PreparedExecutionError {
            certainty: EffectCertainty::UnknownEffect,
            reason: "commands ran but exact prepared after-state was not proved".into(),
        }
        .into());
    }
    Ok(outcome)
}

pub async fn execute_inverse(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    device_id: u64,
    inverse: &PreparedInverse,
) -> Result<crate::ssh::SshOutcome> {
    if !verify_current(locked, device_id, &inverse.expected_current).await? {
        return Err(PreparedExecutionError {
            certainty: EffectCertainty::ProvenNoEffect,
            reason: "router state no longer matches the action-owned after-state; inverse refused"
                .into(),
        }
        .into());
    }
    let outcome = locked.execute(device_id, &inverse.commands).await?;
    if !verify_with_retry(locked, device_id, &inverse.verify).await? {
        return Err(PreparedExecutionError {
            certainty: EffectCertainty::UnknownEffect,
            reason: "inverse commands ran but the exact restore state was not proved".into(),
        }
        .into());
    }
    Ok(outcome)
}

async fn verify_with_retry(
    locked: &mut dyn crate::ssh::LockedDeviceSetPort,
    device_id: u64,
    expected: &[DeviceStateSnapshot],
) -> Result<bool> {
    // IOS BGP/policy state can converge after the config prompt returns. Keep all
    // native locks while polling for at most 30 seconds; malformed, rejected, or
    // incomplete reads still return Err immediately and become uncertain.
    const ATTEMPTS: usize = 16;
    for attempt in 0..ATTEMPTS {
        if verify_current(locked, device_id, expected).await? {
            return Ok(true);
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    Ok(false)
}

fn ipv4_network_mask(prefix: &str) -> Result<(String, String)> {
    let normalized = normalize_cidr(prefix)
        .ok_or_else(|| anyhow::anyhow!("invalid IPv4 route prefix {prefix:?}"))?;
    let (network, length) = normalized
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid IPv4 route prefix {prefix:?}"))?;
    if network.contains(':') {
        bail!("expected an IPv4 route prefix, got {prefix}");
    }
    let length: u32 = length.parse()?;
    let mask = if length == 0 {
        0
    } else {
        u32::MAX << (32 - length)
    };
    Ok((network.to_string(), Ipv4Addr::from(mask).to_string()))
}

/// Prepare an ordered action list without acquiring configuration locks or
/// sending writes. Later actions on the same prefix-list see the projected
/// after-state of earlier actions, matching ordered bundle semantics.
pub trait PreparationReader: Send + Sync {
    fn read_one<'a>(
        &'a self,
        device_id: u64,
        command: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<String>>;
    fn read_many<'a>(
        &'a self,
        device_id: u64,
        commands: &'a [String],
    ) -> crate::ssh::BoxFuture<'a, Result<Vec<String>>>;
}

struct RusshPreparationReader<'a> {
    pool: &'a MySqlPool,
}
impl PreparationReader for RusshPreparationReader<'_> {
    fn read_one<'a>(
        &'a self,
        device_id: u64,
        command: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<String>> {
        Box::pin(async move { read_one(self.pool, device_id, command).await })
    }
    fn read_many<'a>(
        &'a self,
        device_id: u64,
        commands: &'a [String],
    ) -> crate::ssh::BoxFuture<'a, Result<Vec<String>>> {
        Box::pin(async move { read_many(self.pool, device_id, commands).await })
    }
}

pub async fn prepare_actions_read_only(
    pool: &MySqlPool,
    inputs: &[PrepareInput],
) -> Result<Vec<PreparedDeviceAction>> {
    prepare_actions_read_only_with_reader(pool, inputs, &RusshPreparationReader { pool }).await
}

pub async fn prepare_actions_read_only_for_mode(
    pool: &MySqlPool,
    inputs: &[PrepareInput],
    verification_mode: VerificationMode,
) -> Result<Vec<PreparedDeviceAction>> {
    prepare_actions_read_only_with_reader_for_mode(
        pool,
        inputs,
        &RusshPreparationReader { pool },
        verification_mode,
    )
    .await
}

pub async fn prepare_actions_read_only_with_reader<R: PreparationReader>(
    pool: &MySqlPool,
    inputs: &[PrepareInput],
    reader: &R,
) -> Result<Vec<PreparedDeviceAction>> {
    prepare_actions_read_only_with_reader_for_mode(pool, inputs, reader, VerificationMode::Routing)
        .await
}

pub async fn prepare_actions_read_only_with_reader_for_mode<R: PreparationReader>(
    pool: &MySqlPool,
    inputs: &[PrepareInput],
    reader: &R,
    verification_mode: VerificationMode,
) -> Result<Vec<PreparedDeviceAction>> {
    let mut prepared = Vec::with_capacity(inputs.len());
    let mut projected_prefix_lists: HashMap<(u64, String), String> = HashMap::new();
    let mut projected_states: HashMap<String, DeviceStateSnapshot> = HashMap::new();
    for input in inputs {
        let template = super::templates::load(pool, input.template_id).await?;
        if template.name != input.template_name {
            bail!(
                "template identity changed during preparation (expected {}, loaded {})",
                input.template_name,
                template.name
            );
        }
        if !PREPARED_TEMPLATE_NAMES.contains(&template.name.as_str()) {
            bail!(
                "template '{}' is not in the prepared-action catalog",
                template.name
            );
        }
        match template.name.as_str() {
            "bgp_advertise_add" | "bgp_advertise_remove" => {
                let subst = super::templates::validate_and_expand(
                    &template.parameter_schema,
                    &input.canonical_params,
                )?;
                let list = subst
                    .get("prefix_list_name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("prefix-list action has no list"))?
                    .to_string();
                let neighbor = subst
                    .get("neighbor_ip")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("prefix-list action has no neighbor"))?
                    .to_string();
                let neighbor_probe = DeviceStateSnapshot::BgpNeighborState {
                    neighbor: neighbor.clone(),
                    administratively_shutdown: false,
                    state: Some("Established".into()),
                };
                let projected_neighbor = projected_states
                    .get(&state_key(input.device_id, &neighbor_probe).unwrap())
                    .cloned();
                let key = (input.device_id, list.clone());
                let projected_list = projected_prefix_lists.get(&key).cloned();
                let mut commands = vec![
                    "show running-config | section ^router bgp".to_string(),
                    "show running-config | section ^route-map".to_string(),
                    "show running-config".to_string(),
                ];
                if projected_neighbor.is_none() {
                    commands.push(format!("show ip bgp neighbors {neighbor}"));
                }
                if projected_list.is_none() {
                    commands.push(format!("show ip prefix-list {list}"));
                }
                let reads = reader.read_many(input.device_id, &commands).await?;
                let mut read_index = 3;
                let neighbor_output = match projected_neighbor {
                    Some(DeviceStateSnapshot::BgpNeighborState {
                        administratively_shutdown: false,
                        state: Some(state),
                        ..
                    }) if state == "Established" => {
                        format!("BGP neighbor is {neighbor}, remote AS 0\n BGP state = Established")
                    }
                    Some(_) => bail!(
                        "an earlier action does not project BGP neighbor {neighbor} to Established"
                    ),
                    None => {
                        let output = reads[read_index].clone();
                        read_index += 1;
                        output
                    }
                };
                let list_output = projected_list.unwrap_or_else(|| reads[read_index].clone());
                let mut action = prepare_prefix_list_action(
                    input,
                    &template,
                    &reads[0],
                    &reads[1],
                    &reads[2],
                    &neighbor_output,
                    &list_output,
                )?;
                action.verification_mode = verification_mode;
                if let Some(inverse) = &mut action.inverse {
                    inverse.verification_mode = verification_mode;
                }
                if let Some(DeviceStateSnapshot::PrefixList { entries, .. }) = action.after.first()
                {
                    projected_prefix_lists.insert(key, render_prefix_list_snapshot(&list, entries));
                }
                for state in &action.after {
                    if let Some(key) = state_key(input.device_id, state) {
                        projected_states.insert(key, state.clone());
                    }
                }
                prepared.push(action);
            }
            _ => {
                let mut action = prepare_catalog_action(
                    pool,
                    input,
                    &template,
                    &projected_states,
                    reader,
                    verification_mode,
                )
                .await?;
                action.verification_mode = verification_mode;
                if let Some(inverse) = &mut action.inverse {
                    inverse.verification_mode = verification_mode;
                }
                for state in &action.after {
                    if let Some(key) = state_key(input.device_id, state) {
                        projected_states.insert(key, state.clone());
                    }
                }
                prepared.push(action);
            }
        }
    }
    Ok(prepared)
}

async fn prepare_catalog_action(
    pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
    verification_mode: VerificationMode,
) -> Result<PreparedDeviceAction> {
    let subst =
        super::templates::validate_and_expand(&template.parameter_schema, &input.canonical_params)?;
    match template.name.as_str() {
        "null_route_prefix" | "null_route_withdraw" | "blackhole_prefix"
        | "blackhole_withdraw" | "null_route_prefix_v6" | "null_route_withdraw_v6"
        | "blackhole_prefix_v6" | "blackhole_withdraw_v6" => {
            prepare_static_route(pool, input, template, &subst, projected,reader).await
        }
        "bgp_session_enable" | "bgp_session_disable" => {
            prepare_neighbor_shutdown(pool, input, template, &subst, projected,reader).await
        }
        "bgp_route_map_set" | "bgp_route_map_unset" => {
            prepare_route_map(pool, input, template, &subst, projected,reader).await
        }
        "bgp_export_policy_set" => {
            prepare_export_policy(pool, input, template, &subst, projected,reader,verification_mode).await
        }
        "iface_tcp_adjust_mss" | "iface_tcp_adjust_mss_remove" => {
            prepare_interface_mss(pool, input, template, &subst, projected,reader).await
        }
        "iface_shutdown" | "iface_no_shutdown" => {
            prepare_interface_admin(pool, input, template, &subst, projected,reader).await
        }
        other => bail!(
            "template '{other}' has no structured read-only preparation implementation; enforced execution is unavailable"
        ),
    }
}

async fn prepare_export_policy(
    _pool: &MySqlPool,
    input: &PrepareInput,
    _template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
    verification_mode: VerificationMode,
) -> Result<PreparedDeviceAction> {
    use crate::reroute::policy::{BindingScope, PolicyKind};
    let neighbor = subst_string(subst, "neighbor_ip")?;
    let kind = match subst_string(subst, "policy_kind")?.as_str() {
        "prefix_list" => PolicyKind::PrefixList,
        "route_map" => PolicyKind::RouteMap,
        other => bail!("unsupported export policy kind '{other}'"),
    };
    let desired_name = subst_string(subst, "policy_name")?;
    let projected_state = projected.iter().find_map(|(key, state)| {
        (key.starts_with(&format!("{}:export_policy:{neighbor}:", input.device_id)))
            .then_some(state.clone())
    });
    let mut before = if let Some(state) = projected_state {
        state
    } else {
        let reads = reader
            .read_many(
                input.device_id,
                &[
                    "show running-config | section ^router bgp".into(),
                    "show running-config | section ^route-map".into(),
                    "show running-config | section ^ip prefix-list".into(),
                ],
            )
            .await?;
        let inventory = crate::reroute::policy::parse_inventory(
            input.device_id,
            &reads[0],
            &reads[1],
            &reads[2],
            Utc::now(),
        );
        if !inventory.blockers.is_empty() {
            bail!(
                "routing-policy inventory is incomplete: {}",
                inventory.blockers.join(", ")
            );
        }
        let (local_asn, family) = prove_neighbor_context(&reads[0], &neighbor)?;
        let matching = inventory
            .peer_bindings
            .iter()
            .filter(|b| {
                b.neighbor_ip == neighbor && b.address_family == family && b.direction == "out"
            })
            .collect::<Vec<_>>();
        if matching.iter().any(|b| b.scope != BindingScope::Direct) {
            bail!("peer {neighbor} export policy is inherited or ambiguous; direct attachment required");
        }
        if matching
            .iter()
            .filter(|b| b.policy_kind == PolicyKind::PrefixList)
            .count()
            > 1
            || matching
                .iter()
                .filter(|b| b.policy_kind == PolicyKind::RouteMap)
                .count()
                > 1
        {
            bail!("peer {neighbor} has ambiguous duplicate direct outbound policy bindings");
        }
        let prefix_list = matching
            .iter()
            .find(|b| b.policy_kind == PolicyKind::PrefixList)
            .map(|b| b.policy_name.clone());
        let route_map = matching
            .iter()
            .find(|b| b.policy_kind == PolicyKind::RouteMap)
            .map(|b| b.policy_name.clone());
        let (prefix_lists, route_maps) =
            policy_definitions_without_references(inventory.prefix_lists, inventory.route_maps);
        DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn,
            neighbor: neighbor.clone(),
            address_family: family,
            prefix_list,
            route_map,
            prefix_lists,
            route_maps,
            required_prefix_lists: None,
            required_route_maps: None,
        }
    };
    let (local_asn, family, current_prefix, current_map, prefix_lists, route_maps) = match &before {
        DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn,
            address_family,
            prefix_list,
            route_map,
            prefix_lists,
            route_maps,
            ..
        } => (
            *local_asn,
            address_family.clone(),
            prefix_list.clone(),
            route_map.clone(),
            prefix_lists.clone(),
            route_maps.clone(),
        ),
        _ => bail!("projected export-policy state has the wrong type"),
    };
    let exists = match kind {
        PolicyKind::PrefixList => prefix_lists.iter().any(|p| p.name == desired_name),
        PolicyKind::RouteMap => route_maps.iter().any(|p| p.name == desired_name),
    };
    if !exists {
        bail!("selected export policy '{desired_name}' was not present in the complete snapshot");
    }
    let (desired_prefix, desired_map, current_name) = match kind {
        PolicyKind::PrefixList => (
            Some(desired_name.clone()),
            current_map.clone(),
            current_prefix.clone(),
        ),
        PolicyKind::RouteMap => (
            current_prefix.clone(),
            Some(desired_name.clone()),
            current_map.clone(),
        ),
    };
    let mut required_prefix_lists = [current_prefix.as_ref(), desired_prefix.as_ref()]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    required_prefix_lists.sort();
    required_prefix_lists.dedup();
    let mut required_route_maps = [current_map.as_ref(), desired_map.as_ref()]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    required_route_maps.sort();
    required_route_maps.dedup();
    if let DeviceStateSnapshot::ExportPolicyAttachment {
        required_prefix_lists: before_required_lists,
        required_route_maps: before_required_maps,
        ..
    } = &mut before
    {
        *before_required_lists = Some(required_prefix_lists.clone());
        *before_required_maps = Some(required_route_maps.clone());
    }
    let after = DeviceStateSnapshot::ExportPolicyAttachment {
        local_asn,
        neighbor: neighbor.clone(),
        address_family: family.clone(),
        prefix_list: desired_prefix,
        route_map: desired_map,
        prefix_lists: prefix_lists.clone(),
        route_maps: route_maps.clone(),
        required_prefix_lists: Some(required_prefix_lists),
        required_route_maps: Some(required_route_maps),
    };
    let effect = if before == after {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let noun = match kind {
        PolicyKind::PrefixList => "prefix-list",
        PolicyKind::RouteMap => "route-map",
    };
    let attach = format!("neighbor {neighbor} {noun} {desired_name} out");
    let restore = match current_name {
        Some(ref name) => format!("neighbor {neighbor} {noun} {name} out"),
        None => format!("no neighbor {neighbor} {noun} {desired_name} out"),
    };
    let mut desired_verify = vec![after.clone()];
    let mut restore_verify = vec![before.clone()];
    if verification_mode == VerificationMode::Routing && kind == PolicyKind::PrefixList {
        let desired = exact_permitted_prefixes(&desired_name, &prefix_lists)?;
        let prior = current_name
            .as_deref()
            .map(|name| exact_permitted_prefixes(name, &prefix_lists))
            .transpose()?
            .unwrap_or_default();
        for prefix in desired.union(&prior) {
            desired_verify.push(DeviceStateSnapshot::BgpAdvertisement {
                neighbor: neighbor.clone(),
                prefix: prefix.clone(),
                present: desired.contains(prefix),
                community: None,
            });
            restore_verify.push(DeviceStateSnapshot::BgpAdvertisement {
                neighbor: neighbor.clone(),
                prefix: prefix.clone(),
                present: prior.contains(prefix),
                community: None,
            });
        }
    } else if verification_mode == VerificationMode::Routing {
        if let Some(prefix_list) = current_prefix.as_deref() {
            // Attribute-only route-map replacement must preserve reachability
            // selected by the complementary prefix-list. Bind that actual routing
            // proof into both apply and restore verification.
            for prefix in exact_permitted_prefixes(prefix_list, &prefix_lists)? {
                let proof = DeviceStateSnapshot::BgpAdvertisement {
                    neighbor: neighbor.clone(),
                    prefix,
                    present: true,
                    community: None,
                };
                desired_verify.push(proof.clone());
                restore_verify.push(proof);
            }
        }
    }
    finish_prepared(
        input,
        effect,
        export_attachment_commands(local_asn, &family, &neighbor, attach),
        vec![before.clone()],
        desired_verify.clone(),
        desired_verify.clone(),
        Some(PreparedInverse {
            verification_mode,
            expected_current: desired_verify,
            restore: restore_verify.clone(),
            commands: export_attachment_commands(local_asn, &family, &neighbor, restore),
            verify: restore_verify,
        }),
    )
}

fn exact_permitted_prefixes(
    name: &str,
    lists: &[crate::reroute::policy::NamedPrefixList],
) -> Result<std::collections::BTreeSet<String>> {
    let list = lists
        .iter()
        .find(|list| list.name == name)
        .ok_or_else(|| anyhow::anyhow!("prefix-list {name} definition missing"))?;
    exact_permitted_prefixes_from_list(list)
}

fn exact_permitted_prefixes_from_list(
    list: &crate::reroute::policy::NamedPrefixList,
) -> Result<std::collections::BTreeSet<String>> {
    use crate::reroute::policy::PermitDeny;
    let mut entries = list.entries.iter().collect::<Vec<_>>();
    entries.sort_by_key(|e| e.sequence);
    if entries
        .iter()
        .any(|e| e.action == PermitDeny::Permit && (e.ge.is_some() || e.le.is_some()))
    {
        bail!("prefix-list {} has ranged permit semantics", list.name)
    }
    let candidates = entries
        .iter()
        .filter(|e| e.action == PermitDeny::Permit)
        .map(|e| e.prefix.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut allowed = std::collections::BTreeSet::new();
    for candidate in candidates {
        let child_len = candidate
            .rsplit_once('/')
            .and_then(|(_, n)| n.parse::<u8>().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid candidate prefix"))?;
        let decision = entries
            .iter()
            .find(|entry| {
                let base_len = entry
                    .prefix
                    .rsplit_once('/')
                    .and_then(|(_, n)| n.parse::<u8>().ok())
                    .unwrap_or(255);
                let min = entry.ge.unwrap_or(base_len);
                let max = entry
                    .le
                    .unwrap_or(if entry.ge.is_some() { 32 } else { base_len });
                child_len >= min
                    && child_len <= max
                    && super::templates::cidr_contains(&entry.prefix, &candidate).unwrap_or(false)
            })
            .map(|entry| entry.action);
        if decision == Some(PermitDeny::Permit) {
            allowed.insert(candidate);
        }
    }
    Ok(allowed)
}

fn export_attachment_commands(
    local_asn: u32,
    family: &str,
    neighbor: &str,
    line: String,
) -> Vec<String> {
    let mut commands = vec![
        "configure terminal".into(),
        format!("router bgp {local_asn}"),
    ];
    if family == "ipv4" {
        commands.push("address-family ipv4".into())
    }
    commands.push(line);
    if family == "ipv4" {
        commands.push("exit-address-family".into())
    }
    commands.extend(["end".into(), format!("clear ip bgp {neighbor} soft out")]);
    commands
}

fn prove_neighbor_context(config: &str, neighbor: &str) -> Result<(u32, String)> {
    let local_asn = config
        .lines()
        .find_map(|line| line.trim().strip_prefix("router bgp ")?.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("local BGP ASN is unproven"))?;
    let mut family = "default_ipv4";
    let mut found = std::collections::BTreeSet::new();
    let mut global_declared = false;
    for line in config.lines() {
        let s = line.trim();
        if let Some(v) = s.strip_prefix("address-family ") {
            family = if v == "ipv4" || v == "ipv4 unicast" {
                "ipv4"
            } else {
                "unsupported"
            };
            continue;
        }
        if s == "exit-address-family" {
            family = "default_ipv4";
            continue;
        }
        if let Some(rest) = s.strip_prefix(&format!("neighbor {neighbor} ")) {
            if family == "default_ipv4" {
                global_declared = true;
            } else if rest == "activate"
                || rest.starts_with("prefix-list ")
                || rest.starts_with("route-map ")
            {
                found.insert(family.to_string());
            }
        }
    }
    if found.is_empty() && global_declared {
        found.insert("default_ipv4".into());
    }
    if found.len() != 1 {
        bail!("peer {neighbor} was not proven in exactly one supported IPv4 configuration scope")
    }
    let family = found.into_iter().next().unwrap();
    if family == "unsupported" {
        bail!("peer {neighbor} is in an unsupported address family")
    }
    Ok((local_asn, family))
}

fn policy_definitions_without_references(
    mut lists: Vec<crate::reroute::policy::NamedPrefixList>,
    mut maps: Vec<crate::reroute::policy::NamedRouteMap>,
) -> (
    Vec<crate::reroute::policy::NamedPrefixList>,
    Vec<crate::reroute::policy::NamedRouteMap>,
) {
    for list in &mut lists {
        list.referenced_by.clear()
    }
    for map in &mut maps {
        map.references.clear()
    }
    (lists, maps)
}

fn subst_string(subst: &serde_json::Map<String, Value>, name: &str) -> Result<String> {
    subst
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("missing canonical parameter '{name}'"))
}

async fn prepare_static_route(
    pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
) -> Result<PreparedDeviceAction> {
    let prefix = subst_string(subst, "prefix")?;
    let v6 = prefix.contains(':');
    let tagged = template.name.starts_with("blackhole_");
    let desired_present = template.name.contains("_prefix");
    let tag = if tagged {
        Some(subst_string(subst, "tag")?.parse::<u32>()?)
    } else {
        None
    };
    let desired = if v6 {
        DeviceStateSnapshot::Ipv6StaticRoute {
            prefix: prefix.clone(),
            next_hop: "Null0".into(),
            tag,
            present: desired_present,
        }
    } else {
        DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: prefix.clone(),
            next_hop: "Null0".into(),
            tag,
            present: desired_present,
        }
    };
    let key = state_key(input.device_id, &desired).expect("static route has key");
    let projected_before = projected.get(&key);
    let before = match projected_before {
        Some(state) => state.clone(),
        None => read_static_route(reader, input.device_id, &desired).await?,
    };
    let currently_present = static_present(&before)?;
    if desired_present
        && !currently_present
        && projected.values().any(|state| {
            same_static_prefix(state, &desired)
                && static_present(state).unwrap_or(false)
                && static_config_line(state).ok() != static_config_line(&desired).ok()
        })
    {
        bail!("an earlier action projects a different same-prefix static route; refusing an ambiguous combined plan");
    }
    if desired_present && !currently_present && projected_before.is_none() {
        // Refuse a same-prefix static with different next-hop/tag. Adding a
        // second path or replacing an operator-owned route is outside the plan.
        ensure_no_conflicting_static(reader, input.device_id, &desired).await?;
    }
    let effect = if currently_present == desired_present {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let after = desired;
    let desired_resolution = DeviceStateSnapshot::RouteResolution {
        prefix: prefix.clone(),
        next_hop: "Null0".into(),
        present: desired_present,
    };
    let resolution_key =
        state_key(input.device_id, &desired_resolution).expect("route resolution has key");
    let before_resolution = match projected.get(&resolution_key) {
        Some(state) => state.clone(),
        None => read_route_resolution(reader, input.device_id, &prefix, "Null0").await?,
    };
    let mut before_states = vec![before.clone(), before_resolution.clone()];
    let mut after_states = vec![after.clone(), desired_resolution.clone()];
    let mut verify = vec![after.clone(), desired_resolution];
    let mut inverse_verify = vec![before.clone(), before_resolution];
    if tagged {
        let community: Option<String> = sqlx::query_scalar(
            "SELECT community FROM rtbh_communities WHERE tag = ? ORDER BY id LIMIT 1",
        )
        .bind(tag.unwrap_or_default())
        .fetch_optional(pool)
        .await?;
        let community = community.ok_or_else(|| {
            anyhow::anyhow!(
                "RTBH tag {} has no configured community",
                tag.unwrap_or_default()
            )
        })?;
        let bgp_probe = DeviceStateSnapshot::BgpRoute {
            prefix: prefix.clone(),
            present: false,
            community: None,
        };
        let bgp_key = state_key(input.device_id, &bgp_probe).expect("BGP route has key");
        let before_bgp = match projected.get(&bgp_key) {
            Some(state) => state.clone(),
            None => {
                let bgp_command = if v6 {
                    format!("show bgp ipv6 unicast {prefix}")
                } else {
                    format!("show ip bgp {prefix}")
                };
                let bgp_output = reader.read_one(input.device_id, &bgp_command).await?;
                let exact = bgp_evidence(&bgp_output, &prefix, Some(&community), false, true);
                if exact == EvidenceVerdict::Unproven {
                    bail!("BGP route preparation response was unproven");
                }
                let bgp_present = exact == EvidenceVerdict::Matched;
                if !bgp_present && has_exact_cidr(&bgp_output, &prefix) {
                    bail!("the existing exact BGP route does not carry the catalogued RTBH community; refusing an unclassifiable restore state");
                }
                DeviceStateSnapshot::BgpRoute {
                    prefix: prefix.clone(),
                    present: bgp_present,
                    community: bgp_present.then_some(community.clone()),
                }
            }
        };
        let after_bgp = DeviceStateSnapshot::BgpRoute {
            prefix: prefix.clone(),
            present: desired_present,
            community: desired_present.then_some(community.clone()),
        };
        before_states.push(before_bgp.clone());
        after_states.push(after_bgp.clone());
        verify.push(after_bgp);
        inverse_verify.push(before_bgp);
    }
    let rendered = super::templates::render(template, &input.canonical_params)?;
    let inverse_commands = static_route_commands(&after, currently_present)?;
    finish_prepared(
        input,
        effect,
        rendered.commands,
        before_states,
        after_states.clone(),
        verify,
        inverse_commands.map(|commands| PreparedInverse {
            verification_mode: VerificationMode::Routing,
            expected_current: after_states,
            restore: inverse_verify.clone(),
            commands,
            verify: inverse_verify,
        }),
    )
}

async fn read_static_route(
    reader: &impl PreparationReader,
    device_id: u64,
    desired: &DeviceStateSnapshot,
) -> Result<DeviceStateSnapshot> {
    let mut absent = desired.clone();
    set_static_present(&mut absent, false)?;
    let command = static_config_read_command(desired)?;
    let output = reader.read_one(device_id, &command).await?;
    let present_evidence = static_expected_evidence(&output, desired, true)?;
    let absent_evidence = static_expected_evidence(&output, desired, false)?;
    if present_evidence == EvidenceVerdict::Unproven || absent_evidence == EvidenceVerdict::Unproven
    {
        bail!("static-route preparation response was unproven");
    }
    if present_evidence == EvidenceVerdict::Matched {
        let mut present = desired.clone();
        set_static_present(&mut present, true)?;
        Ok(present)
    } else if absent_evidence == EvidenceVerdict::Matched {
        Ok(absent)
    } else {
        bail!("same-prefix static route has different attributes; restore state is unclassifiable")
    }
}

async fn read_route_resolution(
    reader: &impl PreparationReader,
    device_id: u64,
    prefix: &str,
    next_hop: &str,
) -> Result<DeviceStateSnapshot> {
    let normalized =
        normalize_cidr(prefix).ok_or_else(|| anyhow::anyhow!("invalid route prefix {prefix:?}"))?;
    let (network, _) = normalized
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid route prefix {prefix:?}"))?;
    let command = if normalized.contains(':') {
        format!("show ipv6 route {normalized}")
    } else {
        format!("show ip route {network}")
    };
    let output = reader.read_one(device_id, &command).await?;
    let evidence = route_resolution_evidence(&output, &normalized, next_hop, true);
    if evidence == EvidenceVerdict::Unproven {
        bail!("route-resolution preparation response was unproven");
    }
    Ok(DeviceStateSnapshot::RouteResolution {
        prefix: normalized.clone(),
        next_hop: next_hop.to_string(),
        present: evidence == EvidenceVerdict::Matched,
    })
}

async fn ensure_no_conflicting_static(
    reader: &impl PreparationReader,
    device_id: u64,
    desired: &DeviceStateSnapshot,
) -> Result<()> {
    let prefix = match desired {
        DeviceStateSnapshot::Ipv4StaticRoute { prefix, .. } => {
            let (network, mask) = ipv4_network_mask(prefix)?;
            format!("ip route {network} {mask}")
        }
        DeviceStateSnapshot::Ipv6StaticRoute { prefix, .. } => {
            format!(
                "ipv6 route {}",
                normalize_cidr(prefix).ok_or_else(|| anyhow::anyhow!("invalid prefix"))?
            )
        }
        _ => bail!("not a static route snapshot"),
    };
    let output = reader
        .read_one(
            device_id,
            &format!("show running-config | include ^{prefix} "),
        )
        .await?;
    if output.lines().any(|line| !line.trim().is_empty()) {
        bail!("a different same-prefix static route already exists; refusing to change operator-owned routing state");
    }
    Ok(())
}

fn static_present(state: &DeviceStateSnapshot) -> Result<bool> {
    match state {
        DeviceStateSnapshot::Ipv4StaticRoute { present, .. }
        | DeviceStateSnapshot::Ipv6StaticRoute { present, .. } => Ok(*present),
        _ => bail!("not a static route snapshot"),
    }
}

fn set_static_present(state: &mut DeviceStateSnapshot, value: bool) -> Result<()> {
    match state {
        DeviceStateSnapshot::Ipv4StaticRoute { present, .. }
        | DeviceStateSnapshot::Ipv6StaticRoute { present, .. } => {
            *present = value;
            Ok(())
        }
        _ => bail!("not a static route snapshot"),
    }
}

fn same_static_prefix(a: &DeviceStateSnapshot, b: &DeviceStateSnapshot) -> bool {
    match (a, b) {
        (
            DeviceStateSnapshot::Ipv4StaticRoute { prefix: a, .. },
            DeviceStateSnapshot::Ipv4StaticRoute { prefix: b, .. },
        )
        | (
            DeviceStateSnapshot::Ipv6StaticRoute { prefix: a, .. },
            DeviceStateSnapshot::Ipv6StaticRoute { prefix: b, .. },
        ) => normalize_cidr(a) == normalize_cidr(b),
        _ => false,
    }
}

pub(crate) fn static_config_line(state: &DeviceStateSnapshot) -> Result<String> {
    match state {
        DeviceStateSnapshot::Ipv4StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => {
            let (network, mask) = ipv4_network_mask(prefix)?;
            Ok(match tag {
                Some(tag) => format!("ip route {network} {mask} {next_hop} tag {tag}"),
                None => format!("ip route {network} {mask} {next_hop}"),
            })
        }
        DeviceStateSnapshot::Ipv6StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => {
            let prefix = normalize_cidr(prefix).ok_or_else(|| anyhow::anyhow!("invalid prefix"))?;
            Ok(match tag {
                Some(tag) => format!("ipv6 route {prefix} {next_hop} tag {tag}"),
                None => format!("ipv6 route {prefix} {next_hop}"),
            })
        }
        _ => bail!("not a static route snapshot"),
    }
}

fn static_config_read_command(state: &DeviceStateSnapshot) -> Result<String> {
    match state {
        DeviceStateSnapshot::Ipv4StaticRoute { .. } => Ok(format!(
            "show running-config | include ^{}$",
            static_config_line(state)?
        )),
        DeviceStateSnapshot::Ipv6StaticRoute { .. } => {
            // IOS may choose a different equivalent IPv6 text compression. Read
            // the bounded command family and compare the prefix semantically.
            Ok("show running-config | include ^ipv6 route".into())
        }
        _ => bail!("not a static route snapshot"),
    }
}

fn static_snapshot_matches(output: &str, expected: &DeviceStateSnapshot) -> Result<bool> {
    match expected {
        DeviceStateSnapshot::Ipv4StaticRoute { .. } => {
            let expected_line = static_config_line(expected)?;
            Ok(has_exact_config_line(output, &expected_line))
        }
        DeviceStateSnapshot::Ipv6StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => {
            let expected_prefix = normalize_cidr(prefix)
                .ok_or_else(|| anyhow::anyhow!("invalid IPv6 route prefix {prefix:?}"))?;
            if !expected_prefix.contains(':') {
                bail!("expected an IPv6 route prefix, got {prefix}");
            }
            for line in output.lines() {
                let tokens = line.split_whitespace().collect::<Vec<_>>();
                let (candidate, hop, candidate_tag) = match tokens.as_slice() {
                    ["ipv6", "route", candidate, hop] => (*candidate, *hop, None),
                    ["ipv6", "route", candidate, hop, "tag", tag] => {
                        (*candidate, *hop, tag.parse::<u32>().ok())
                    }
                    _ => continue,
                };
                if normalize_cidr(candidate).as_deref() == Some(expected_prefix.as_str())
                    && hop == next_hop
                    && candidate_tag == *tag
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => bail!("not a static route snapshot"),
    }
}

fn static_config_evidence(output: &str, expected: &DeviceStateSnapshot) -> Result<EvidenceVerdict> {
    // A completed empty `show running-config | include ...` body proves that
    // the filtered configuration object is absent.
    if output.trim().is_empty() {
        return Ok(EvidenceVerdict::ProvenMismatch);
    }
    let valid = match expected {
        // This command contains the complete expected line inside an anchored
        // IOS include expression. A different otherwise-valid route means the
        // response is not from the requested filter and proves nothing.
        DeviceStateSnapshot::Ipv4StaticRoute { .. } => {
            let expected_line = static_config_line(expected)?;
            output
                .lines()
                .all(|line| has_exact_config_line(line, &expected_line))
        }
        DeviceStateSnapshot::Ipv6StaticRoute { .. } => output.lines().all(|line| {
            let t = line.split_whitespace().collect::<Vec<_>>();
            matches!(t.as_slice(), ["ipv6", "route", prefix, hop]
                if normalize_cidr(prefix).is_some_and(|p| p.contains(':')) && (*hop == "Null0" || hop.parse::<std::net::IpAddr>().is_ok()))
                || matches!(t.as_slice(), ["ipv6", "route", prefix, hop, "tag", tag]
                if normalize_cidr(prefix).is_some_and(|p| p.contains(':')) && (*hop == "Null0" || hop.parse::<std::net::IpAddr>().is_ok()) && tag.parse::<u32>().is_ok())
        }),
        _ => false,
    };
    if !valid {
        return Ok(EvidenceVerdict::Unproven);
    }
    Ok(if static_snapshot_matches(output, expected)? {
        EvidenceVerdict::Matched
    } else {
        EvidenceVerdict::ProvenMismatch
    })
}

fn static_expected_evidence(
    output: &str,
    expected: &DeviceStateSnapshot,
    expected_present: bool,
) -> Result<EvidenceVerdict> {
    let parsed = static_config_evidence(output, expected)?;
    if parsed == EvidenceVerdict::Unproven {
        return Ok(parsed);
    }
    let exact = parsed == EvidenceVerdict::Matched;
    let wanted_prefix = match expected {
        DeviceStateSnapshot::Ipv4StaticRoute { prefix, .. }
        | DeviceStateSnapshot::Ipv6StaticRoute { prefix, .. } => normalize_cidr(prefix),
        _ => None,
    }
    .ok_or_else(|| anyhow::anyhow!("invalid static route prefix"))?;
    let same_prefix = output.lines().any(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        match (expected, tokens.as_slice()) {
            (
                DeviceStateSnapshot::Ipv4StaticRoute { prefix, .. },
                ["ip", "route", network, mask, ..],
            ) => ipv4_network_mask(prefix)
                .is_ok_and(|wanted| wanted.0 == *network && wanted.1 == *mask),
            (DeviceStateSnapshot::Ipv6StaticRoute { .. }, ["ipv6", "route", candidate, ..]) => {
                normalize_cidr(candidate).as_deref() == Some(wanted_prefix.as_str())
            }
            _ => false,
        }
    }) || exact;
    Ok(if expected_present {
        if exact {
            EvidenceVerdict::Matched
        } else {
            EvidenceVerdict::ProvenMismatch
        }
    } else if same_prefix {
        EvidenceVerdict::ProvenMismatch
    } else {
        EvidenceVerdict::Matched
    })
}

fn static_route_commands(
    state: &DeviceStateSnapshot,
    present: bool,
) -> Result<Option<Vec<String>>> {
    if static_present(state)? == present {
        return Ok(None);
    }
    let line = static_config_line(state)?;
    let command = if present { line } else { format!("no {line}") };
    Ok(Some(vec![
        "configure terminal".into(),
        command,
        "end".into(),
    ]))
}

async fn prepare_neighbor_shutdown(
    _pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
) -> Result<PreparedDeviceAction> {
    let neighbor = subst_string(subst, "neighbor_ip")?;
    let local_asn = subst_string(subst, "local_asn")?.parse::<u32>()?;
    let desired_shutdown = template.name == "bgp_session_disable";
    let desired = DeviceStateSnapshot::NeighborShutdown {
        local_asn,
        neighbor: neighbor.clone(),
        shutdown: desired_shutdown,
    };
    let key = state_key(input.device_id, &desired).unwrap();
    let before = match projected.get(&key) {
        Some(state) => state.clone(),
        None => {
            let output = reader
                .read_one(input.device_id, "show running-config | section ^router bgp")
                .await?;
            let router_line = format!("router bgp {local_asn}");
            let peer_prefix = format!("neighbor {neighbor} ");
            if !output.lines().any(|line| line.trim() == router_line)
                || !output
                    .lines()
                    .any(|line| line.trim_start().starts_with(&peer_prefix))
            {
                bail!("fresh running-config did not prove BGP neighbor {neighbor} under AS {local_asn}");
            }
            DeviceStateSnapshot::NeighborShutdown {
                local_asn,
                neighbor: neighbor.clone(),
                shutdown: has_exact_config_line(&output, &format!("neighbor {neighbor} shutdown")),
            }
        }
    };
    let current = match &before {
        DeviceStateSnapshot::NeighborShutdown { shutdown, .. } => *shutdown,
        _ => bail!("projected BGP neighbor state has the wrong type"),
    };
    let operational_probe = DeviceStateSnapshot::BgpNeighborState {
        neighbor: neighbor.clone(),
        administratively_shutdown: current,
        state: None,
    };
    let operational_key = state_key(input.device_id, &operational_probe).unwrap();
    let before_operational = match projected.get(&operational_key) {
        Some(state) => state.clone(),
        None => {
            let output = reader
                .read_one(
                    input.device_id,
                    &format!("show ip bgp neighbors {neighbor}"),
                )
                .await?;
            let parsed = parse_bgp_neighbor_state(&output, &neighbor)?;
            DeviceStateSnapshot::BgpNeighborState {
                neighbor: neighbor.clone(),
                administratively_shutdown: parsed.administratively_shutdown,
                state: parsed.state,
            }
        }
    };
    let desired_operational = DeviceStateSnapshot::BgpNeighborState {
        neighbor: neighbor.clone(),
        administratively_shutdown: desired_shutdown,
        state: Some(
            if desired_shutdown {
                "Idle"
            } else {
                "Established"
            }
            .into(),
        ),
    };
    let effect = if current == desired_shutdown {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let commands = super::templates::render(template, &input.canonical_params)?.commands;
    let inverse_command = if current {
        format!("neighbor {neighbor} shutdown")
    } else {
        format!("no neighbor {neighbor} shutdown")
    };
    finish_prepared(
        input,
        effect,
        commands,
        vec![before.clone(), before_operational.clone()],
        vec![desired.clone(), desired_operational.clone()],
        vec![desired.clone(), desired_operational.clone()],
        Some(PreparedInverse {
            verification_mode: VerificationMode::Routing,
            expected_current: vec![desired, desired_operational],
            restore: vec![before.clone(), before_operational.clone()],
            commands: vec![
                "configure terminal".into(),
                format!("router bgp {local_asn}"),
                inverse_command,
                "end".into(),
            ],
            verify: vec![before, before_operational],
        }),
    )
}

async fn prepare_route_map(
    _pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
) -> Result<PreparedDeviceAction> {
    let neighbor = subst_string(subst, "neighbor_ip")?;
    let local_asn = subst_string(subst, "local_asn")?.parse::<u32>()?;
    let direction = subst_string(subst, "direction")?;
    let requested = subst_string(subst, "route_map")?;
    let output = reader
        .read_one(input.device_id, "show running-config | section ^router bgp")
        .await?;
    let (proved_asn, family) = prove_neighbor_context(&output, &neighbor)?;
    anyhow::ensure!(
        proved_asn == local_asn,
        "requested ASN differs from fresh BGP scope"
    );
    let desired_map = (template.name == "bgp_route_map_set").then_some(requested.clone());
    let desired = DeviceStateSnapshot::RouteMapAssignment {
        local_asn,
        neighbor: neighbor.clone(),
        direction: direction.clone(),
        address_family: Some(family.clone()),
        route_map: desired_map.clone(),
    };
    let key = state_key(input.device_id, &desired).unwrap();
    let before = match projected.get(&key) {
        Some(state) => state.clone(),
        None => DeviceStateSnapshot::RouteMapAssignment {
            local_asn,
            neighbor: neighbor.clone(),
            direction: direction.clone(),
            address_family: Some(family.clone()),
            route_map: parse_route_map_assignment_scoped(&output, &neighbor, &direction, &family)?,
        },
    };
    let current = match &before {
        DeviceStateSnapshot::RouteMapAssignment {
            address_family: Some(scope),
            route_map,
            ..
        } if scope == &family => route_map.clone(),
        _ => bail!("route-map scope evidence is incomplete"),
    };
    if template.name == "bgp_route_map_unset" && current.as_deref().is_some_and(|m| m != requested)
    {
        bail!("peer currently uses a different route-map")
    }
    let effect = if current == desired_map {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let apply = match &desired_map {
        Some(map) => format!("neighbor {neighbor} route-map {map} {direction}"),
        None => format!("no neighbor {neighbor} route-map {requested} {direction}"),
    };
    let restore = match &current {
        Some(map) => format!("neighbor {neighbor} route-map {map} {direction}"),
        None => format!("no neighbor {neighbor} route-map {requested} {direction}"),
    };
    finish_prepared(
        input,
        effect,
        scoped_route_map_commands(local_asn, &family, &neighbor, &direction, apply),
        vec![before.clone()],
        vec![desired.clone()],
        vec![desired.clone()],
        Some(PreparedInverse {
            verification_mode: VerificationMode::Routing,
            expected_current: vec![desired],
            restore: vec![before.clone()],
            commands: scoped_route_map_commands(local_asn, &family, &neighbor, &direction, restore),
            verify: vec![before],
        }),
    )
}

fn scoped_route_map_commands(
    local_asn: u32,
    family: &str,
    neighbor: &str,
    direction: &str,
    line: String,
) -> Vec<String> {
    let mut out = vec![
        "configure terminal".into(),
        format!("router bgp {local_asn}"),
    ];
    if family != "default_ipv4" {
        out.push(format!("address-family {family}"));
    }
    out.push(line);
    if family != "default_ipv4" {
        out.push("exit-address-family".into());
    }
    out.push("end".into());
    out.push(format!("clear ip bgp {neighbor} soft {direction}"));
    out
}

fn parse_route_map_assignment_scoped(
    output: &str,
    neighbor: &str,
    direction: &str,
    wanted: &str,
) -> Result<Option<String>> {
    let mut family = "default_ipv4";
    let mut found = Vec::new();
    for line in output.lines() {
        let s = line.trim();
        if let Some(v) = s.strip_prefix("address-family ") {
            family = if v == "ipv4" || v == "ipv4 unicast" {
                "ipv4"
            } else {
                "unsupported"
            };
            continue;
        }
        if s == "exit-address-family" {
            family = "default_ipv4";
            continue;
        }
        let t = s.split_whitespace().collect::<Vec<_>>();
        if let ["neighbor", peer, "route-map", map, dir] = t.as_slice() {
            if *peer == neighbor && *dir == direction && family == wanted {
                found.push((*map).to_string());
            }
        }
    }
    if found.len() > 1 {
        bail!("multiple route-map assignments in proved scope")
    }
    Ok(found.pop())
}

struct ParsedBgpNeighborState {
    administratively_shutdown: bool,
    state: Option<String>,
}

fn parse_bgp_neighbor_state(output: &str, neighbor: &str) -> Result<ParsedBgpNeighborState> {
    let header = format!("BGP neighbor is {neighbor}");
    if !output
        .lines()
        .any(|line| line.trim_start().starts_with(&header))
    {
        bail!("BGP neighbor output did not identify {neighbor}");
    }
    let state = output.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("BGP state = ")?;
        rest.split(|c: char| c == ',' || c == '(' || c.is_whitespace())
            .find(|part| !part.is_empty())
            .map(str::to_string)
    });
    if state.is_none() {
        bail!("BGP neighbor output did not contain a state for {neighbor}");
    }
    Ok(ParsedBgpNeighborState {
        administratively_shutdown: output
            .to_ascii_lowercase()
            .contains("administratively shut"),
        state,
    })
}

async fn prepare_interface_mss(
    _pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
) -> Result<PreparedDeviceAction> {
    let interface = subst_string(subst, "interface")?;
    let desired_mss = if template.name == "iface_tcp_adjust_mss" {
        Some(subst_string(subst, "mss")?.parse::<u32>()?)
    } else {
        None
    };
    let desired = DeviceStateSnapshot::InterfaceMss {
        interface: interface.clone(),
        mss: desired_mss,
    };
    let key = state_key(input.device_id, &desired).unwrap();
    let before = match projected.get(&key) {
        Some(state) => state.clone(),
        None => {
            let output = reader
                .read_one(
                    input.device_id,
                    &format!("show running-config interface {interface}"),
                )
                .await?;
            validate_interface_stanza(&output, &interface)?;
            let mss = output.lines().find_map(|line| {
                let tokens = line.split_whitespace().collect::<Vec<_>>();
                match tokens.as_slice() {
                    ["ip", "tcp", "adjust-mss", value] => value.parse::<u32>().ok(),
                    _ => None,
                }
            });
            DeviceStateSnapshot::InterfaceMss {
                interface: interface.clone(),
                mss,
            }
        }
    };
    let current = match &before {
        DeviceStateSnapshot::InterfaceMss { mss, .. } => *mss,
        _ => bail!("projected interface MSS state has the wrong type"),
    };
    let effect = if current == desired_mss {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let inverse_cmd = current
        .map(|mss| format!("ip tcp adjust-mss {mss}"))
        .unwrap_or_else(|| "no ip tcp adjust-mss".into());
    finish_prepared(
        input,
        effect,
        super::templates::render(template, &input.canonical_params)?.commands,
        vec![before.clone()],
        vec![desired.clone()],
        vec![desired.clone()],
        Some(PreparedInverse {
            verification_mode: VerificationMode::Routing,
            expected_current: vec![desired],
            restore: vec![before.clone()],
            commands: vec![
                "configure terminal".into(),
                format!("interface {interface}"),
                inverse_cmd,
                "end".into(),
            ],
            verify: vec![before],
        }),
    )
}

async fn prepare_interface_admin(
    _pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
    reader: &impl PreparationReader,
) -> Result<PreparedDeviceAction> {
    let interface = subst_string(subst, "interface")?;
    let desired_shutdown = template.name == "iface_shutdown";
    let desired = DeviceStateSnapshot::InterfaceAdmin {
        interface: interface.clone(),
        shutdown: desired_shutdown,
    };
    let key = state_key(input.device_id, &desired).unwrap();
    let before = match projected.get(&key) {
        Some(state) => state.clone(),
        None => {
            let output = reader
                .read_one(
                    input.device_id,
                    &format!("show running-config interface {interface}"),
                )
                .await?;
            validate_interface_stanza(&output, &interface)?;
            DeviceStateSnapshot::InterfaceAdmin {
                interface: interface.clone(),
                shutdown: has_exact_config_line(&output, "shutdown"),
            }
        }
    };
    let current = match &before {
        DeviceStateSnapshot::InterfaceAdmin { shutdown, .. } => *shutdown,
        _ => bail!("projected interface admin state has the wrong type"),
    };
    let operational_probe = DeviceStateSnapshot::InterfaceOperational {
        interface: interface.clone(),
        administratively_down: current,
    };
    let operational_key = state_key(input.device_id, &operational_probe).unwrap();
    let before_operational = match projected.get(&operational_key) {
        Some(state) => state.clone(),
        None => {
            let output = reader
                .read_one(input.device_id, &format!("show interfaces {interface}"))
                .await?;
            if !output
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{interface} is ")))
            {
                bail!("interface operational read did not prove interface {interface}");
            }
            DeviceStateSnapshot::InterfaceOperational {
                interface: interface.clone(),
                administratively_down: output
                    .to_ascii_lowercase()
                    .contains("administratively down"),
            }
        }
    };
    let before_admin_down = match &before_operational {
        DeviceStateSnapshot::InterfaceOperational {
            administratively_down,
            ..
        } => *administratively_down,
        _ => bail!("projected interface operational state has the wrong type"),
    };
    if before_admin_down != current {
        bail!(
            "interface config and operational admin state disagree; refusing an unstable snapshot"
        );
    }
    let desired_operational = DeviceStateSnapshot::InterfaceOperational {
        interface: interface.clone(),
        administratively_down: desired_shutdown,
    };
    let effect = if current == desired_shutdown {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let inverse_cmd = if current { "shutdown" } else { "no shutdown" };
    finish_prepared(
        input,
        effect,
        super::templates::render(template, &input.canonical_params)?.commands,
        vec![before.clone(), before_operational.clone()],
        vec![desired.clone(), desired_operational.clone()],
        vec![desired.clone(), desired_operational.clone()],
        Some(PreparedInverse {
            verification_mode: VerificationMode::Routing,
            expected_current: vec![desired, desired_operational],
            restore: vec![before.clone(), before_operational.clone()],
            commands: vec![
                "configure terminal".into(),
                format!("interface {interface}"),
                inverse_cmd.into(),
                "end".into(),
            ],
            verify: vec![before, before_operational],
        }),
    )
}

fn finish_prepared(
    input: &PrepareInput,
    effect: PreparedEffect,
    commands: Vec<String>,
    before: Vec<DeviceStateSnapshot>,
    after: Vec<DeviceStateSnapshot>,
    verify: Vec<DeviceStateSnapshot>,
    inverse: Option<PreparedInverse>,
) -> Result<PreparedDeviceAction> {
    let verification_mode = inverse
        .as_ref()
        .map(|prepared| prepared.verification_mode)
        .unwrap_or(VerificationMode::Routing);
    let action = PreparedDeviceAction {
        schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
        device_id: input.device_id,
        template_id: input.template_id,
        template_name: input.template_name.clone(),
        canonical_params: input.canonical_params.clone(),
        verification_mode,
        commands: if effect == PreparedEffect::Change {
            commands
        } else {
            Vec::new()
        },
        before,
        after,
        verify,
        effect,
        inverse: (effect == PreparedEffect::Change)
            .then_some(inverse)
            .flatten(),
        prepared_at: Utc::now(),
    };
    action.validate()?;
    Ok(action)
}

fn state_key(device_id: u64, state: &DeviceStateSnapshot) -> Option<String> {
    let suffix = match state {
        DeviceStateSnapshot::PrefixList { name, .. } => format!("prefix_list:{name}"),
        DeviceStateSnapshot::Ipv4StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => format!("v4_route:{prefix}:{next_hop}:{tag:?}"),
        DeviceStateSnapshot::Ipv6StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => format!("v6_route:{prefix}:{next_hop}:{tag:?}"),
        DeviceStateSnapshot::RouteResolution {
            prefix, next_hop, ..
        } => format!("route_resolution:{prefix}:{next_hop}"),
        DeviceStateSnapshot::NeighborShutdown { neighbor, .. } => format!("neighbor:{neighbor}"),
        DeviceStateSnapshot::BgpNeighborState { neighbor, .. } => {
            format!("neighbor_operational:{neighbor}")
        }
        DeviceStateSnapshot::RouteMapAssignment {
            neighbor,
            direction,
            address_family,
            ..
        } => format!("route_map:{neighbor}:{direction}:{address_family:?}"),
        DeviceStateSnapshot::ExportPolicyAttachment {
            neighbor,
            address_family,
            ..
        } => {
            format!("export_policy:{neighbor}:{address_family}")
        }
        DeviceStateSnapshot::InterfaceAdmin { interface, .. } => {
            format!("interface_admin:{interface}")
        }
        DeviceStateSnapshot::InterfaceOperational { interface, .. } => {
            format!("interface_operational:{interface}")
        }
        DeviceStateSnapshot::InterfaceMss { interface, .. } => {
            format!("interface_mss:{interface}")
        }
        DeviceStateSnapshot::BgpRoute { prefix, .. } => format!("bgp_route:{prefix}"),
        DeviceStateSnapshot::BgpAdvertisement {
            neighbor, prefix, ..
        } => format!("bgp_advertisement:{neighbor}:{prefix}"),
    };
    Some(format!("{device_id}:{suffix}"))
}

async fn read_one(pool: &MySqlPool, device_id: u64, command: &str) -> Result<String> {
    let outcome = crate::ssh::run_commands(pool, device_id, &[command.to_string()]).await?;
    outcome
        .results
        .first()
        .map(|result| result.output.clone())
        .ok_or_else(|| anyhow::anyhow!("device returned no result for {command:?}"))
}

async fn read_many(pool: &MySqlPool, device_id: u64, commands: &[String]) -> Result<Vec<String>> {
    let outcome = crate::ssh::run_commands(pool, device_id, commands).await?;
    if outcome.results.len() != commands.len() {
        bail!(
            "device returned {} results for {} read commands",
            outcome.results.len(),
            commands.len()
        );
    }
    Ok(outcome
        .results
        .into_iter()
        .map(|result| result.output)
        .collect())
}

fn render_prefix_list_snapshot(name: &str, entries: &[PrefixListSnapshotEntry]) -> String {
    let noun = if entries.len() == 1 {
        "entry"
    } else {
        "entries"
    };
    let mut output = format!("ip prefix-list {name}: {} {noun}", entries.len());
    for entry in entries {
        output.push_str(&format!(
            "\nseq {} {} {}",
            entry.sequence,
            if entry.permit { "permit" } else { "deny" },
            entry.prefix
        ));
        if let Some(ge) = entry.ge {
            output.push_str(&format!(" ge {ge}"));
        }
        if let Some(le) = entry.le {
            output.push_str(&format!(" le {le}"));
        }
    }
    output
}

pub(crate) fn normalize_cidr(value: &str) -> Option<String> {
    let (addr, len) = value.split_once('/')?;
    let ip: IpAddr = addr.parse().ok()?;
    let len: u32 = len.parse().ok()?;
    match ip {
        IpAddr::V4(ip) if len <= 32 => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            Some(format!("{}/{}", Ipv4Addr::from(u32::from(ip) & mask), len))
        }
        IpAddr::V6(ip) if len <= 128 => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            Some(format!("{}/{}", Ipv6Addr::from(u128::from(ip) & mask), len))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FakeLocked {
        outputs: BTreeMap<String, String>,
    }

    impl crate::ssh::LockedDeviceSetPort for FakeLocked {
        fn device_ids(&self) -> Vec<u64> {
            vec![1]
        }

        fn transport_identity(&self, device_id: u64) -> Result<DeviceTransportIdentity> {
            if device_id != 1 {
                bail!("unknown fake device");
            }
            Ok(DeviceTransportIdentity {
                host: "edge.example.test".into(),
                port: 22,
                pinned_host_fingerprint: "SHA256:fixture".into(),
            })
        }

        fn read<'a>(
            &'a mut self,
            _device_id: u64,
            command: &'a str,
        ) -> crate::ssh::BoxFuture<'a, Result<crate::ssh::CommandResult>> {
            Box::pin(async move {
                let output = self
                    .outputs
                    .get(command)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("unexpected fake read {command:?}"))?;
                Ok(crate::ssh::CommandResult {
                    command: command.into(),
                    output,
                })
            })
        }

        fn execute<'a>(
            &'a mut self,
            _device_id: u64,
            _commands: &'a [String],
        ) -> crate::ssh::BoxFuture<'a, Result<crate::ssh::SshOutcome>> {
            Box::pin(async { anyhow::bail!("verification fake refuses writes") })
        }

        fn unlock_all(self: Box<Self>) -> crate::ssh::BoxFuture<'static, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn base(effect: PreparedEffect) -> PreparedDeviceAction {
        PreparedDeviceAction {
            schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
            device_id: 1,
            template_id: 2,
            template_name: "example".into(),
            canonical_params: serde_json::json!({}),
            verification_mode: VerificationMode::Routing,
            commands: Vec::new(),
            before: Vec::new(),
            after: Vec::new(),
            verify: Vec::new(),
            effect,
            inverse: None,
            prepared_at: Utc::now(),
        }
    }

    #[test]
    fn noop_can_never_claim_an_inverse() {
        let mut plan = base(PreparedEffect::AlreadySatisfied);
        plan.inverse = Some(PreparedInverse {
            verification_mode: VerificationMode::Routing,
            expected_current: Vec::new(),
            restore: Vec::new(),
            commands: vec!["no shutdown".into()],
            verify: Vec::new(),
        });
        assert!(plan.validate().is_err());
    }

    #[test]
    fn verification_mode_is_strict_backward_compatible_and_execution_bound() {
        let legacy = serde_json::json!({
            "schema_version": 1,
            "device_id": 1,
            "template_id": 2,
            "template_name": "example",
            "canonical_params": {},
            "commands": [],
            "before": [],
            "after": [],
            "verify": [],
            "effect": "already_satisfied",
            "prepared_at": Utc::now()
        });
        let decoded: PreparedDeviceAction = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(decoded.verification_mode, VerificationMode::Routing);

        let mut configuration_only = decoded.clone();
        configuration_only.verification_mode = VerificationMode::ConfigurationOnly;
        assert!(!decoded.equivalent_for_execution(&configuration_only));

        let mut unknown = legacy;
        unknown["verification_mode"] = serde_json::json!("configish");
        assert!(serde_json::from_value::<PreparedDeviceAction>(unknown).is_err());
    }

    #[test]
    fn change_and_noop_require_meaningful_evidence() {
        let mut change = base(PreparedEffect::Change);
        change.commands = vec!["configure terminal".into(), "end".into()];
        assert!(change.validate().is_err());
        assert!(base(PreparedEffect::AlreadySatisfied).validate().is_err());
    }

    #[test]
    fn prepared_catalog_covers_the_nineteen_seeded_action_types_once() {
        let unique = PREPARED_TEMPLATE_NAMES
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(PREPARED_TEMPLATE_NAMES.len(), 19);
        assert_eq!(unique.len(), 19);
        for required in [
            "iface_tcp_adjust_mss",
            "bgp_route_map_set",
            "bgp_advertise_add",
            "blackhole_prefix_v6",
        ] {
            assert!(unique.contains(required));
        }
    }

    #[test]
    fn serde_round_trip_keeps_the_versioned_contract() {
        let plan = base(PreparedEffect::AlreadySatisfied);
        let encoded = serde_json::to_value(&plan).unwrap();
        assert_eq!(encoded["schema_version"], 1);
        let decoded: PreparedDeviceAction = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, plan);
    }

    #[test]
    fn execution_equivalence_ignores_only_observation_time() {
        let preview = base(PreparedEffect::AlreadySatisfied);
        let mut runtime = preview.clone();
        runtime.prepared_at += chrono::Duration::seconds(1);
        assert!(preview.equivalent_for_execution(&runtime));
        runtime.device_id += 1;
        assert!(!preview.equivalent_for_execution(&runtime));
    }

    #[test]
    fn transport_identity_binds_host_port_and_pinned_key() {
        let fake = FakeLocked {
            outputs: BTreeMap::new(),
        };
        let mut expected = BTreeMap::from([(
            1,
            DeviceTransportIdentity {
                host: "edge.example.test".into(),
                port: 22,
                pinned_host_fingerprint: "SHA256:fixture".into(),
            },
        )]);
        assert!(verify_transport_identities(&fake, &expected).unwrap());
        expected.get_mut(&1).unwrap().port = 2222;
        assert!(!verify_transport_identities(&fake, &expected).unwrap());
    }

    #[test]
    fn exact_verification_rejects_wrong_prefix_length_and_tag() {
        let bgp = "*> 10.0.0.0/25 192.0.2.1 0 65000 i";
        assert!(!has_exact_cidr(bgp, "10.0.0.0/24"));
        assert!(has_exact_cidr(bgp, "10.0.0.0/25"));
        assert!(!has_exact_cidr(
            "diagnostic text mentions 10.0.0.0/24 but contains no NLRI row",
            "10.0.0.0/24"
        ));
        assert!(has_exact_cidr(
            "BGP routing table entry for 10.0.0.0/24, version 9",
            "10.0.0.0/24"
        ));

        let config = " ip route 10.0.0.0 255.255.255.0 Null0 tag 777";
        assert!(!has_exact_config_line(
            config,
            "ip route 10.0.0.0 255.255.255.0 Null0 tag 666"
        ));
        assert!(has_exact_config_line(
            config,
            "ip route 10.0.0.0 255.255.255.0 Null0 tag 777"
        ));
        assert!(!has_exact_route_resolution(
            "diagnostic mentions 10.0.0.0/24 via Null0",
            "10.0.0.0/24",
            "Null0"
        ));
        assert!(!has_exact_route_resolution(
            "Routing entry for 10.0.0.0/25\n * directly connected, via Null0",
            "10.0.0.0/24",
            "Null0"
        ));
    }

    #[test]
    fn exact_bgp_verification_requires_the_intended_community() {
        let output = "BGP routing table entry for 203.0.113.0/24\nCommunity: 65000:666 no-export";
        assert!(has_exact_bgp_route(
            output,
            "203.0.113.0/24",
            Some("65000:666")
        ));
        assert!(!has_exact_bgp_route(
            output,
            "203.0.113.0/24",
            Some("65000:999")
        ));
    }

    #[test]
    fn evidence_distinguishes_absence_from_an_unproven_empty_response() {
        let route = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.0/24".into(),
            next_hop: "Null0".into(),
            tag: Some(666),
            present: false,
        };
        assert_eq!(
            static_config_evidence("", &route).unwrap(),
            EvidenceVerdict::ProvenMismatch
        );
        assert_eq!(
            bgp_evidence("", "203.0.113.0/24", None, true, false),
            EvidenceVerdict::Unproven
        );
        assert_eq!(
            route_resolution_evidence("", "203.0.113.0/24", "Null0", false),
            EvidenceVerdict::Unproven
        );
        assert_eq!(
            bgp_evidence(
                "Network Next Hop\nTotal number of prefixes 0",
                "203.0.113.0/24",
                None,
                true,
                false
            ),
            EvidenceVerdict::Matched
        );
    }

    #[tokio::test]
    async fn empty_interface_config_is_unproven_not_an_absence_proof() {
        let mut fake = FakeLocked {
            outputs: BTreeMap::from([(
                "show running-config interface GigabitEthernet0/0".into(),
                String::new(),
            )]),
        };
        let state = DeviceStateSnapshot::InterfaceMss {
            interface: "GigabitEthernet0/0".into(),
            mss: None,
        };
        assert!(verify_current(&mut fake, 1, &[state]).await.is_err());
    }

    #[tokio::test]
    async fn expected_absence_rejects_conflicting_or_foreign_evidence() {
        let state = DeviceStateSnapshot::BgpAdvertisement {
            neighbor: "192.0.2.2".into(),
            prefix: "203.0.113.0/24".into(),
            present: false,
            community: Some("65000:666".into()),
        };
        let mut fake = FakeLocked { outputs: BTreeMap::from([("show ip bgp neighbors 192.0.2.2 advertised-routes".into(), "Network Next Hop Metric LocPrf Weight Path\n*> 203.0.113.0/24 0.0.0.0 0 32768 i\nCommunity: 65000:999".into())]) };
        assert!(!verify_current(&mut fake, 1, &[state]).await.unwrap());

        let state = DeviceStateSnapshot::RouteResolution {
            prefix: "203.0.113.0/24".into(),
            next_hop: "Null0".into(),
            present: false,
        };
        let mut fake = FakeLocked {
            outputs: BTreeMap::from([(
                "show ip route 203.0.113.0".into(),
                "Routing entry for 203.0.113.0/24\n * 192.0.2.1".into(),
            )]),
        };
        assert!(!verify_current(&mut fake, 1, &[state]).await.unwrap());

        let state = DeviceStateSnapshot::BgpRoute {
            prefix: "203.0.113.0/24".into(),
            present: false,
            community: None,
        };
        let mut fake = FakeLocked {
            outputs: BTreeMap::from([(
                "show ip bgp 203.0.113.0/24".into(),
                "BGP routing table entry for 203.0.114.0/24".into(),
            )]),
        };
        assert!(verify_current(&mut fake, 1, &[state]).await.is_err());

        let state = DeviceStateSnapshot::InterfaceMss {
            interface: "GigabitEthernet0/0".into(),
            mss: None,
        };
        let mut fake = FakeLocked { outputs: BTreeMap::from([("show running-config interface GigabitEthernet0/0".into(), "interface GigabitEthernet0/0\ninterface GigabitEthernet0/1\n ip tcp adjust-mss 1400".into())]) };
        assert!(verify_current(&mut fake, 1, &[state]).await.is_err());
    }

    #[tokio::test]
    async fn exact_filtered_ipv4_absence_rejects_a_foreign_route_response() {
        let state = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.0/24".into(),
            next_hop: "Null0".into(),
            tag: Some(666),
            present: false,
        };
        let command = static_config_read_command(&state).unwrap();
        let mut fake = FakeLocked {
            outputs: BTreeMap::from([(
                command,
                "ip route 198.51.100.0 255.255.255.0 Null0 tag 666".into(),
            )]),
        };
        assert!(verify_current(&mut fake, 1, &[state]).await.is_err());
    }

    #[tokio::test]
    async fn broad_ipv6_route_read_can_prove_one_prefix_absent_among_foreign_routes() {
        let state = DeviceStateSnapshot::Ipv6StaticRoute {
            prefix: "2001:db8:1::/48".into(),
            next_hop: "Null0".into(),
            tag: Some(666),
            present: false,
        };
        let mut fake = FakeLocked {
            outputs: BTreeMap::from([(
                "show running-config | include ^ipv6 route".into(),
                "ipv6 route 2001:db8:2::/48 Null0 tag 666".into(),
            )]),
        };
        assert!(verify_current(&mut fake, 1, &[state]).await.unwrap());
    }

    #[tokio::test]
    async fn advertisement_absence_requires_a_complete_consistent_table() {
        let state = DeviceStateSnapshot::BgpAdvertisement {
            neighbor: "192.0.2.2".into(),
            prefix: "203.0.113.0/24".into(),
            present: false,
            community: None,
        };
        let command = "show ip bgp neighbors 192.0.2.2 advertised-routes".to_string();
        for incomplete in [
            "Network Next Hop Metric LocPrf Weight Path\n*> 198.51.100.0/24 0.0.0.0 0 32768 i",
            "Network Next Hop Metric LocPrf Weight Path\n*> 198.51.100.0/24 0.0.0.0 0 32768 i\nmalformed row\nTotal number of prefixes 1",
            "Network Next Hop Metric LocPrf Weight Path\n*> 198.51.100.0/24 0.0.0.0 0 32768 i\nTotal number of prefixes 2",
        ] {
            let mut fake = FakeLocked {
                outputs: BTreeMap::from([(command.clone(), incomplete.into())]),
            };
            assert!(verify_current(&mut fake, 1, std::slice::from_ref(&state))
                .await
                .is_err());
        }
        let mut complete = FakeLocked {
            outputs: BTreeMap::from([(
                command,
                "Network Next Hop Metric LocPrf Weight Path\n*> 198.51.100.0/24 0.0.0.0 0 32768 i\nTotal number of prefixes 1".into(),
            )]),
        };
        assert!(verify_current(&mut complete, 1, &[state]).await.unwrap());
    }

    #[tokio::test]
    async fn route_attributes_are_bound_to_the_exact_route_block() {
        let bgp = DeviceStateSnapshot::BgpRoute {
            prefix: "203.0.113.0/24".into(),
            present: true,
            community: Some("65000:666".into()),
        };
        let mut fake = FakeLocked { outputs: BTreeMap::from([(
            "show ip bgp 203.0.113.0/24".into(),
            "BGP routing table entry for 203.0.113.0/24\n Community: 65000:999\nBGP routing table entry for 198.51.100.0/24\n Community: 65000:666".into(),
        )]) };
        assert!(!verify_current(&mut fake, 1, &[bgp]).await.unwrap());

        let route = DeviceStateSnapshot::RouteResolution {
            prefix: "203.0.113.0/24".into(),
            next_hop: "Null0".into(),
            present: true,
        };
        let mut fake = FakeLocked { outputs: BTreeMap::from([(
            "show ip route 203.0.113.0".into(),
            "Routing entry for 203.0.113.0/24\n * 192.0.2.1\nRouting entry for 198.51.100.0/24\n * directly connected, via Null0".into(),
        )]) };
        assert!(!verify_current(&mut fake, 1, &[route]).await.unwrap());
    }

    #[tokio::test]
    async fn typed_verifier_covers_every_catalog_family_and_rejects_near_matches() {
        let bgp_config = "router bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n neighbor 192.0.2.1 shutdown\n neighbor 192.0.2.1 route-map EXPORT out\n neighbor 192.0.2.2 remote-as 65002\n neighbor 192.0.2.2 prefix-list EDGE out";
        let interface_config = "interface GigabitEthernet0/0\n shutdown\n ip tcp adjust-mss 1436";
        let mut outputs = BTreeMap::new();
        outputs.insert(
            "show ip prefix-list EDGE".into(),
            "ip prefix-list EDGE: 2 entries\nseq 5 permit 203.0.113.0/24\nseq 10 deny 0.0.0.0/0 le 32".into(),
        );
        outputs.insert(
            "show running-config | section ^router bgp".into(),
            bgp_config.into(),
        );
        outputs.insert(
            "show running-config | section ^route-map".into(),
            String::new(),
        );
        outputs.insert("show running-config".into(), bgp_config.into());
        outputs.insert(
            "show running-config | include ^ip route 203.0.113.0 255.255.255.0 Null0 tag 666$"
                .into(),
            "ip route 203.0.113.0 255.255.255.0 Null0 tag 666".into(),
        );
        outputs.insert(
            "show running-config | include ^ip route 203.0.113.0 255.255.255.0 Null0 tag 777$"
                .into(),
            String::new(),
        );
        outputs.insert(
            "show running-config | include ^ipv6 route".into(),
            "ipv6 route 2001:0db8:0:0::/48 Null0".into(),
        );
        outputs.insert(
            "show ip route 203.0.113.0".into(),
            "Routing entry for 203.0.113.0/24\n * directly connected, via Null0".into(),
        );
        outputs.insert(
            "show ip bgp neighbors 192.0.2.2 advertised-routes".into(),
            "Network Next Hop Metric LocPrf Weight Path\n*> 203.0.113.0/24 0.0.0.0 0 32768 i\nTotal number of prefixes 1"
                .into(),
        );
        outputs.insert(
            "show ip bgp 203.0.113.0/24".into(),
            "BGP routing table entry for 203.0.113.0/24\nCommunity: 65000:666".into(),
        );
        outputs.insert(
            "show ip bgp neighbors 192.0.2.1".into(),
            "BGP neighbor is 192.0.2.1\n BGP state = Idle (Administratively shut)".into(),
        );
        outputs.insert(
            "show ip bgp neighbors 192.0.2.2".into(),
            "BGP neighbor is 192.0.2.2\n BGP state = Established, up for 00:10:00".into(),
        );
        outputs.insert(
            "show running-config interface GigabitEthernet0/0".into(),
            interface_config.into(),
        );
        outputs.insert(
            "show interfaces GigabitEthernet0/0".into(),
            "GigabitEthernet0/0 is administratively down, line protocol is down".into(),
        );
        let mut fake = FakeLocked { outputs };
        let expected = vec![
            DeviceStateSnapshot::PrefixList {
                name: "EDGE".into(),
                entries: vec![
                    PrefixListSnapshotEntry {
                        sequence: 5,
                        permit: true,
                        prefix: "203.0.113.0/24".into(),
                        ge: None,
                        le: None,
                    },
                    PrefixListSnapshotEntry {
                        sequence: 10,
                        permit: false,
                        prefix: "0.0.0.0/0".into(),
                        ge: None,
                        le: Some(32),
                    },
                ],
                consumers: vec![PrefixListConsumer {
                    kind: "neighbor".into(),
                    owner: "192.0.2.2".into(),
                    direction: "out".into(),
                }],
            },
            DeviceStateSnapshot::Ipv4StaticRoute {
                prefix: "203.0.113.0/24".into(),
                next_hop: "Null0".into(),
                tag: Some(666),
                present: true,
            },
            DeviceStateSnapshot::Ipv6StaticRoute {
                prefix: "2001:db8::/48".into(),
                next_hop: "Null0".into(),
                tag: None,
                present: true,
            },
            DeviceStateSnapshot::RouteResolution {
                prefix: "203.0.113.0/24".into(),
                next_hop: "Null0".into(),
                present: true,
            },
            DeviceStateSnapshot::BgpAdvertisement {
                neighbor: "192.0.2.2".into(),
                prefix: "203.0.113.0/24".into(),
                present: true,
                community: None,
            },
            DeviceStateSnapshot::BgpRoute {
                prefix: "203.0.113.0/24".into(),
                present: true,
                community: Some("65000:666".into()),
            },
            DeviceStateSnapshot::NeighborShutdown {
                local_asn: 65000,
                neighbor: "192.0.2.1".into(),
                shutdown: true,
            },
            DeviceStateSnapshot::BgpNeighborState {
                neighbor: "192.0.2.1".into(),
                administratively_shutdown: true,
                state: Some("Idle".into()),
            },
            DeviceStateSnapshot::BgpNeighborState {
                neighbor: "192.0.2.2".into(),
                administratively_shutdown: false,
                state: Some("Established".into()),
            },
            DeviceStateSnapshot::RouteMapAssignment {
                local_asn: 65000,
                neighbor: "192.0.2.1".into(),
                direction: "out".into(),
                address_family: Some("default_ipv4".into()),
                route_map: Some("EXPORT".into()),
            },
            DeviceStateSnapshot::InterfaceAdmin {
                interface: "GigabitEthernet0/0".into(),
                shutdown: true,
            },
            DeviceStateSnapshot::InterfaceOperational {
                interface: "GigabitEthernet0/0".into(),
                administratively_down: true,
            },
            DeviceStateSnapshot::InterfaceMss {
                interface: "GigabitEthernet0/0".into(),
                mss: Some(1436),
            },
        ];
        assert!(verify_current(&mut fake, 1, &expected).await.unwrap());
        let legacy_scopeless = DeviceStateSnapshot::RouteMapAssignment {
            local_asn: 65000,
            neighbor: "192.0.2.1".into(),
            direction: "out".into(),
            address_family: None,
            route_map: Some("EXPORT".into()),
        };
        assert!(!verify_current(&mut fake, 1, &[legacy_scopeless])
            .await
            .unwrap());

        let wrong_tag = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.0/24".into(),
            next_hop: "Null0".into(),
            tag: Some(777),
            present: true,
        };
        assert!(!verify_current(&mut fake, 1, &[wrong_tag]).await.unwrap());
        let wrong_length = DeviceStateSnapshot::BgpAdvertisement {
            neighbor: "192.0.2.2".into(),
            prefix: "203.0.113.0/25".into(),
            present: true,
            community: None,
        };
        assert!(!verify_current(&mut fake, 1, &[wrong_length]).await.unwrap());
    }

    #[tokio::test]
    async fn inverse_sequence_turns_already_restored_step_into_owned_noop() {
        let mut outputs = BTreeMap::new();
        outputs.insert(
            "show running-config interface GigabitEthernet0/0".into(),
            "interface GigabitEthernet0/0\n no ip redirects".into(),
        );
        outputs.insert(
            "show interfaces GigabitEthernet0/0".into(),
            "GigabitEthernet0/0 is up, line protocol is up".into(),
        );
        let mut fake = FakeLocked { outputs };
        let up = vec![
            DeviceStateSnapshot::InterfaceAdmin {
                interface: "GigabitEthernet0/0".into(),
                shutdown: false,
            },
            DeviceStateSnapshot::InterfaceOperational {
                interface: "GigabitEthernet0/0".into(),
                administratively_down: false,
            },
        ];
        let down = vec![
            DeviceStateSnapshot::InterfaceAdmin {
                interface: "GigabitEthernet0/0".into(),
                shutdown: true,
            },
            DeviceStateSnapshot::InterfaceOperational {
                interface: "GigabitEthernet0/0".into(),
                administratively_down: true,
            },
        ];
        let make = |name: &str,
                    before: Vec<DeviceStateSnapshot>,
                    after: Vec<DeviceStateSnapshot>,
                    command: &str| PreparedDeviceAction {
            schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
            device_id: 1,
            template_id: 1,
            template_name: name.into(),
            canonical_params: serde_json::json!({}),
            verification_mode: VerificationMode::Routing,
            commands: vec![
                "configure terminal".into(),
                "interface GigabitEthernet0/0".into(),
                command.into(),
                "end".into(),
            ],
            before,
            after: after.clone(),
            verify: after,
            effect: PreparedEffect::Change,
            inverse: None,
            prepared_at: Utc::now(),
        };
        let mut actions = vec![
            make(
                "inverse-no-shutdown",
                down.clone(),
                up.clone(),
                "no shutdown",
            ),
            make("inverse-shutdown", up, down, "shutdown"),
        ];
        reconcile_inverse_sequence(&mut fake, &mut actions)
            .await
            .unwrap();
        assert_eq!(actions[0].effect, PreparedEffect::AlreadySatisfied);
        assert!(actions[0].commands.is_empty());
        assert_eq!(actions[1].effect, PreparedEffect::Change);
    }

    #[tokio::test]
    async fn projected_final_proof_detects_a_replacement_peer_flap() {
        let mut outputs = BTreeMap::new();
        outputs.insert(
            "show ip bgp neighbors 192.0.2.9".into(),
            "BGP neighbor is 192.0.2.9\n BGP state = Idle".into(),
        );
        let mut fake = FakeLocked { outputs };
        let established = DeviceStateSnapshot::BgpNeighborState {
            neighbor: "192.0.2.9".into(),
            administratively_shutdown: false,
            state: Some("Established".into()),
        };
        let action = PreparedDeviceAction {
            schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
            device_id: 1,
            template_id: 1,
            template_name: "bgp_session_enable".into(),
            canonical_params: serde_json::json!({}),
            verification_mode: VerificationMode::Routing,
            commands: vec![
                "configure terminal".into(),
                "router bgp 65000".into(),
                "no neighbor 192.0.2.9 shutdown".into(),
                "end".into(),
            ],
            before: vec![DeviceStateSnapshot::BgpNeighborState {
                neighbor: "192.0.2.9".into(),
                administratively_shutdown: true,
                state: Some("Idle".into()),
            }],
            after: vec![established.clone()],
            verify: vec![established],
            effect: PreparedEffect::Change,
            inverse: None,
            prepared_at: Utc::now(),
        };
        assert!(!verify_projected_after(&mut fake, &[action]).await.unwrap());
    }

    #[tokio::test]
    async fn export_policy_proof_ignores_unrelated_definitions_but_binds_owned_policies() {
        use crate::reroute::policy::{NamedPrefixList, PermitDeny, PrefixListEntry};
        let named = |name: &str, prefix: &str| NamedPrefixList {
            name: name.into(),
            entries: vec![
                PrefixListEntry {
                    sequence: 10,
                    action: PermitDeny::Permit,
                    prefix: prefix.into(),
                    ge: None,
                    le: None,
                },
                PrefixListEntry {
                    sequence: 20,
                    action: PermitDeny::Deny,
                    prefix: "0.0.0.0/0".into(),
                    ge: None,
                    le: Some(32),
                },
            ],
            referenced_by: vec![],
        };
        let expected = DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn: 34501,
            neighbor: "192.0.2.9".into(),
            address_family: "ipv4".into(),
            prefix_list: Some("DESIRED".into()),
            route_map: None,
            prefix_lists: vec![
                named("CURRENT", "198.51.100.0/24"),
                named("DESIRED", "194.105.142.0/24"),
            ],
            route_maps: vec![],
            required_prefix_lists: Some(vec!["CURRENT".into(), "DESIRED".into()]),
            required_route_maps: Some(vec![]),
        };
        let bgp = "router bgp 34501\n address-family ipv4\n neighbor 192.0.2.9 activate\n neighbor 192.0.2.9 prefix-list DESIRED out\n exit-address-family";
        let prefix_lists = "ip prefix-list CURRENT seq 10 permit 198.51.100.0/24\nip prefix-list CURRENT seq 20 deny 0.0.0.0/0 le 32\nip prefix-list DESIRED seq 10 permit 194.105.142.0/24\nip prefix-list DESIRED seq 20 deny 0.0.0.0/0 le 32\nip prefix-list UNRELATED seq 10 permit 203.0.113.0/24\nip prefix-list UNRELATED seq 20 deny 0.0.0.0/0 le 32";
        let outputs = BTreeMap::from([
            (
                "show running-config | section ^router bgp".into(),
                bgp.into(),
            ),
            (
                "show running-config | section ^route-map".into(),
                String::new(),
            ),
            (
                "show running-config | section ^ip prefix-list".into(),
                prefix_lists.into(),
            ),
        ]);
        assert!(verify_current(
            &mut FakeLocked {
                outputs: outputs.clone(),
            },
            1,
            std::slice::from_ref(&expected)
        )
        .await
        .unwrap());

        let mut changed = outputs;
        changed.insert(
            "show running-config | section ^ip prefix-list".into(),
            prefix_lists.replace("194.105.142.0/24", "194.105.143.0/24"),
        );
        assert!(
            !verify_current(&mut FakeLocked { outputs: changed }, 1, &[expected])
                .await
                .unwrap()
        );
    }

    #[test]
    fn export_attachment_commands_keep_the_proven_scope() {
        let af = export_attachment_commands(
            34501,
            "ipv4",
            "192.0.2.1",
            "neighbor 192.0.2.1 prefix-list P out".into(),
        );
        assert_eq!(
            af,
            vec![
                "configure terminal",
                "router bgp 34501",
                "address-family ipv4",
                "neighbor 192.0.2.1 prefix-list P out",
                "exit-address-family",
                "end",
                "clear ip bgp 192.0.2.1 soft out"
            ]
        );
        let global = export_attachment_commands(
            34501,
            "default_ipv4",
            "192.0.2.1",
            "neighbor 192.0.2.1 route-map R out".into(),
        );
        assert!(!global.iter().any(|line| line.starts_with("address-family")));
        assert_eq!(global[2], "neighbor 192.0.2.1 route-map R out");
    }

    #[test]
    fn neighbor_context_is_exact_and_ambiguous_context_refuses() {
        let config="router bgp 34501\n neighbor 192.0.2.1 remote-as 64500\n address-family ipv4\n neighbor 192.0.2.10 remote-as 64501\n exit-address-family";
        assert_eq!(
            prove_neighbor_context(config, "192.0.2.1").unwrap(),
            (34501, "default_ipv4".into())
        );
        let normal="router bgp 34501\n neighbor 192.0.2.1 remote-as 64500\n address-family ipv4\n neighbor 192.0.2.1 activate\n neighbor 192.0.2.1 prefix-list pfx-to-viva out\n exit-address-family";
        assert_eq!(
            prove_neighbor_context(normal, "192.0.2.1").unwrap(),
            (34501, "ipv4".into())
        );
    }

    #[test]
    fn emdd_second_prefix_makes_replacement_additive_not_destructive() {
        use crate::reroute::policy::{NamedPrefixList, PermitDeny};
        let entry = |sequence: u32, prefix: &str| PrefixListSnapshotEntry {
            sequence,
            permit: true,
            prefix: prefix.into(),
            ge: None,
            le: None,
        };
        let named = |name: &str, entries: Vec<PrefixListSnapshotEntry>| NamedPrefixList {
            name: name.into(),
            entries: entries
                .into_iter()
                .map(|e| crate::reroute::policy::PrefixListEntry {
                    sequence: e.sequence,
                    action: PermitDeny::Permit,
                    prefix: e.prefix,
                    ge: e.ge,
                    le: e.le,
                })
                .collect(),
            referenced_by: vec![],
        };
        let lists = vec![
            named("eMA1", vec![entry(5, "194.105.142.0/24")]),
            named(
                "eMA2",
                vec![entry(5, "194.105.142.0/24"), entry(10, "194.102.117.0/24")],
            ),
        ];
        let state = |name: &str| DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn: 34501,
            neighbor: "192.0.2.1".into(),
            address_family: "ipv4".into(),
            prefix_list: Some(name.into()),
            route_map: None,
            prefix_lists: lists.clone(),
            route_maps: vec![],
            required_prefix_lists: None,
            required_route_maps: None,
        };
        let action = PreparedDeviceAction {
            schema_version: 1,
            device_id: 1,
            template_id: 1,
            template_name: "bgp_export_policy_set".into(),
            canonical_params: serde_json::json!({"policy_kind":"prefix_list"}),
            verification_mode: VerificationMode::Routing,
            commands: vec!["x".into()],
            before: vec![state("eMA1")],
            after: vec![state("eMA2")],
            verify: vec![state("eMA2")],
            effect: PreparedEffect::Change,
            inverse: None,
            prepared_at: Utc::now(),
        };
        assert_eq!(
            prepared_safety_effect(&action).unwrap(),
            PreparedSafetyEffect::Additive
        );
        let mut complemented = action.clone();
        let attribute_map = crate::reroute::policy::NamedRouteMap {
            name: "prepend-3".into(),
            references: vec![],
            clauses: vec![crate::reroute::policy::RouteMapClause {
                sequence: 10,
                action: PermitDeny::Permit,
                matches: vec![],
                sets: vec![crate::reroute::policy::PolicyTerm {
                    kind: "as-path_prepend".into(),
                    value: "as-path prepend 34501".into(),
                }],
            }],
        };
        for state in complemented
            .before
            .iter_mut()
            .chain(complemented.after.iter_mut())
        {
            if let DeviceStateSnapshot::ExportPolicyAttachment {
                route_map,
                route_maps,
                ..
            } = state
            {
                *route_map = Some("prepend-3".into());
                *route_maps = vec![attribute_map.clone()];
            }
        }
        assert_eq!(
            prepared_safety_effect(&complemented).unwrap(),
            PreparedSafetyEffect::Additive
        );
        if let DeviceStateSnapshot::ExportPolicyAttachment { route_maps, .. } =
            &mut complemented.after[0]
        {
            route_maps[0].clauses[0]
                .matches
                .push(crate::reroute::policy::PolicyTerm {
                    kind: "ip_address".into(),
                    value: "ip address 10".into(),
                });
        }
        assert_eq!(
            prepared_safety_effect(&complemented).unwrap(),
            PreparedSafetyEffect::Unproven
        );
        let reverse = PreparedDeviceAction {
            before: action.after.clone(),
            after: action.before.clone(),
            verify: action.before.clone(),
            ..action
        };
        assert_eq!(
            prepared_safety_effect(&reverse).unwrap(),
            PreparedSafetyEffect::Destructive
        );
        let mut unrestricted = reverse.clone();
        if let DeviceStateSnapshot::ExportPolicyAttachment { prefix_list, .. } =
            &mut unrestricted.before[0]
        {
            *prefix_list = None;
        }
        assert_eq!(
            prepared_safety_effect(&unrestricted).unwrap(),
            PreparedSafetyEffect::Unproven
        );
    }

    #[test]
    fn attribute_only_permit_all_route_map_is_proven_neutral() {
        use crate::reroute::policy::{NamedRouteMap, PermitDeny, PolicyTerm, RouteMapClause};
        let safe = NamedRouteMap {
            name: "PREPEND".into(),
            references: vec![],
            clauses: vec![RouteMapClause {
                sequence: 10,
                action: PermitDeny::Permit,
                matches: vec![],
                sets: vec![PolicyTerm {
                    kind: "as-path_prepend".into(),
                    value: "as-path prepend 65001 65001".into(),
                }],
            }],
        };
        let state = |name: Option<&str>| DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn: 34501,
            neighbor: "192.0.2.1".into(),
            address_family: "ipv4".into(),
            prefix_list: Some("EMDD".into()),
            route_map: name.map(Into::into),
            prefix_lists: vec![],
            route_maps: vec![safe.clone()],
            required_prefix_lists: None,
            required_route_maps: None,
        };
        let action = PreparedDeviceAction {
            schema_version: 1,
            device_id: 1,
            template_id: 1,
            template_name: "bgp_export_policy_set".into(),
            canonical_params: serde_json::json!({"policy_kind":"route_map"}),
            verification_mode: VerificationMode::Routing,
            commands: vec!["x".into()],
            before: vec![state(None)],
            after: vec![state(Some("PREPEND"))],
            verify: vec![state(Some("PREPEND"))],
            effect: PreparedEffect::Change,
            inverse: None,
            prepared_at: Utc::now(),
        };
        assert_eq!(
            prepared_safety_effect(&action).unwrap(),
            PreparedSafetyEffect::Neutral
        );
        let mut unsafe_action = action.clone();
        if let DeviceStateSnapshot::ExportPolicyAttachment { route_maps, .. } =
            &mut unsafe_action.after[0]
        {
            route_maps[0].clauses[0].matches.push(PolicyTerm {
                kind: "ip_address".into(),
                value: "ip address prefix-list FILTER".into(),
            });
        }
        assert_eq!(
            prepared_safety_effect(&unsafe_action).unwrap(),
            PreparedSafetyEffect::Unproven
        );
        let mut unsafe_before = action.clone();
        if let DeviceStateSnapshot::ExportPolicyAttachment {
            route_map,
            route_maps,
            ..
        } = &mut unsafe_before.before[0]
        {
            *route_map = Some("PREPEND".into());
            route_maps[0].clauses[0].action = PermitDeny::Deny;
        }
        assert_eq!(
            prepared_safety_effect(&unsafe_before).unwrap(),
            PreparedSafetyEffect::Unproven
        );
    }

    #[test]
    fn exact_policy_evaluator_supports_terminal_deny_and_respects_early_shadow() {
        use crate::reroute::policy::{NamedPrefixList, PermitDeny, PrefixListEntry};
        let entry = |sequence, action, prefix: &str, le| PrefixListEntry {
            sequence,
            action,
            prefix: prefix.into(),
            ge: None,
            le,
        };
        let valid = NamedPrefixList {
            name: "EMDD".into(),
            referenced_by: vec![],
            entries: vec![
                entry(5, PermitDeny::Permit, "194.105.142.0/24", None),
                entry(10, PermitDeny::Deny, "0.0.0.0/0", Some(32)),
            ],
        };
        assert_eq!(
            exact_permitted_prefixes_from_list(&valid)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["194.105.142.0/24"]
        );
        let shadowed = NamedPrefixList {
            name: "BAD".into(),
            referenced_by: vec![],
            entries: vec![
                entry(1, PermitDeny::Deny, "194.105.0.0/16", Some(24)),
                entry(5, PermitDeny::Permit, "194.105.142.0/24", None),
            ],
        };
        assert!(exact_permitted_prefixes_from_list(&shadowed)
            .unwrap()
            .is_empty());
    }
}
