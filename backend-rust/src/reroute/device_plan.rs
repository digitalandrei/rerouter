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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedEffect {
    Change,
    AlreadySatisfied,
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
        route_map: Option<String>,
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
    has_exact_cidr(output, prefix)
        && community
            .map(|wanted| {
                output
                    .split_whitespace()
                    .any(|token| token.trim_matches([',', '(', ')']) == wanted)
            })
            .unwrap_or(true)
}

pub fn has_exact_route_resolution(output: &str, prefix: &str, next_hop: &str) -> bool {
    let Some(expected) = normalize_cidr(prefix) else {
        return false;
    };
    let exact_entry = output.lines().any(|line| {
        let Some(rest) = line.trim().strip_prefix("Routing entry for ") else {
            return false;
        };
        let candidate = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches([',', '(', ')']);
        normalize_cidr(candidate).as_deref() == Some(expected.as_str())
    });
    exact_entry
        && output
            .split_whitespace()
            .any(|token| token.trim_matches([',', '*']) == next_hop)
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
                static_snapshot_matches(&output.output, state)? == *present
            }
            DeviceStateSnapshot::Ipv6StaticRoute { present, .. } => {
                let command = static_config_read_command(state)?;
                let output = locked.read(device_id, &command).await?;
                static_snapshot_matches(&output.output, state)? == *present
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
                has_exact_bgp_route(&output.output, prefix, community.as_deref()) == *present
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
                has_exact_route_resolution(&output.output, &normalized, next_hop) == *present
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
                has_exact_bgp_route(&output.output, prefix, community.as_deref()) == *present
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
                route_map,
            } => {
                let output = locked
                    .read(device_id, "show running-config | section ^router bgp")
                    .await?;
                let has_router = output
                    .output
                    .lines()
                    .any(|line| line.trim() == format!("router bgp {local_asn}"));
                let actual = parse_route_map_assignment(&output.output, neighbor, direction)?;
                has_router && actual == *route_map
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
    let mut port = ReadOnlySnapshotPort { pool: pool.clone() };
    verify_current(&mut port, device_id, expected).await
}

/// Preview an ordered inverse set without requiring future sibling state to
/// exist yet. The same projection is repeated under exclusive locks at apply.
pub async fn verify_sequence_read_only(
    pool: &MySqlPool,
    actions: &[PreparedDeviceAction],
) -> Result<bool> {
    let mut port = ReadOnlySnapshotPort { pool: pool.clone() };
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
    let mut port = ReadOnlySnapshotPort { pool: pool.clone() };
    reconcile_inverse_sequence(&mut port, actions).await
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
            let outcome =
                crate::ssh::run_commands(&self.pool, device_id, &[command.to_string()]).await?;
            outcome
                .results
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("device returned no result for {command:?}"))
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
pub async fn prepare_actions_read_only(
    pool: &MySqlPool,
    inputs: &[PrepareInput],
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
                let reads = read_many(pool, input.device_id, &commands).await?;
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
                let action = prepare_prefix_list_action(
                    input,
                    &template,
                    &reads[0],
                    &reads[1],
                    &reads[2],
                    &neighbor_output,
                    &list_output,
                )?;
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
                let action =
                    prepare_catalog_action(pool, input, &template, &projected_states).await?;
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
) -> Result<PreparedDeviceAction> {
    let subst =
        super::templates::validate_and_expand(&template.parameter_schema, &input.canonical_params)?;
    match template.name.as_str() {
        "null_route_prefix" | "null_route_withdraw" | "blackhole_prefix"
        | "blackhole_withdraw" | "null_route_prefix_v6" | "null_route_withdraw_v6"
        | "blackhole_prefix_v6" | "blackhole_withdraw_v6" => {
            prepare_static_route(pool, input, template, &subst, projected).await
        }
        "bgp_session_enable" | "bgp_session_disable" => {
            prepare_neighbor_shutdown(pool, input, template, &subst, projected).await
        }
        "bgp_route_map_set" | "bgp_route_map_unset" => {
            prepare_route_map(pool, input, template, &subst, projected).await
        }
        "iface_tcp_adjust_mss" | "iface_tcp_adjust_mss_remove" => {
            prepare_interface_mss(pool, input, template, &subst, projected).await
        }
        "iface_shutdown" | "iface_no_shutdown" => {
            prepare_interface_admin(pool, input, template, &subst, projected).await
        }
        other => bail!(
            "template '{other}' has no structured read-only preparation implementation; enforced execution is unavailable"
        ),
    }
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
        None => read_static_route(pool, input.device_id, &desired).await?,
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
        ensure_no_conflicting_static(pool, input.device_id, &desired).await?;
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
        None => read_route_resolution(pool, input.device_id, &prefix, "Null0").await?,
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
                let bgp_output = read_one(pool, input.device_id, &bgp_command).await?;
                let bgp_present = has_exact_cidr(&bgp_output, &prefix);
                if bgp_present && !has_exact_bgp_route(&bgp_output, &prefix, Some(&community)) {
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
            expected_current: after_states,
            restore: inverse_verify.clone(),
            commands,
            verify: inverse_verify,
        }),
    )
}

async fn read_static_route(
    pool: &MySqlPool,
    device_id: u64,
    desired: &DeviceStateSnapshot,
) -> Result<DeviceStateSnapshot> {
    let mut absent = desired.clone();
    set_static_present(&mut absent, false)?;
    let command = static_config_read_command(desired)?;
    let output = read_one(pool, device_id, &command).await?;
    if static_snapshot_matches(&output, desired)? {
        let mut present = desired.clone();
        set_static_present(&mut present, true)?;
        Ok(present)
    } else {
        Ok(absent)
    }
}

async fn read_route_resolution(
    pool: &MySqlPool,
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
    let output = read_one(pool, device_id, &command).await?;
    Ok(DeviceStateSnapshot::RouteResolution {
        prefix: normalized.clone(),
        next_hop: next_hop.to_string(),
        present: has_exact_route_resolution(&output, &normalized, next_hop),
    })
}

async fn ensure_no_conflicting_static(
    pool: &MySqlPool,
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
    let output = read_one(
        pool,
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

fn static_config_line(state: &DeviceStateSnapshot) -> Result<String> {
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
    pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
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
            let output = read_one(
                pool,
                input.device_id,
                "show running-config | section ^router bgp",
            )
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
            let output = read_one(
                pool,
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
    pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
) -> Result<PreparedDeviceAction> {
    let neighbor = subst_string(subst, "neighbor_ip")?;
    let local_asn = subst_string(subst, "local_asn")?.parse::<u32>()?;
    let direction = subst_string(subst, "direction")?;
    let requested = subst_string(subst, "route_map")?;
    let desired_map = (template.name == "bgp_route_map_set").then_some(requested.clone());
    let desired = DeviceStateSnapshot::RouteMapAssignment {
        local_asn,
        neighbor: neighbor.clone(),
        direction: direction.clone(),
        route_map: desired_map.clone(),
    };
    let key = state_key(input.device_id, &desired).unwrap();
    let before = match projected.get(&key) {
        Some(state) => state.clone(),
        None => {
            let output = read_one(
                pool,
                input.device_id,
                "show running-config | section ^router bgp",
            )
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
            let actual = parse_route_map_assignment(&output, &neighbor, &direction)?;
            DeviceStateSnapshot::RouteMapAssignment {
                local_asn,
                neighbor: neighbor.clone(),
                direction: direction.clone(),
                route_map: actual,
            }
        }
    };
    let current = match &before {
        DeviceStateSnapshot::RouteMapAssignment { route_map, .. } => route_map.clone(),
        _ => bail!("projected route-map state has the wrong type"),
    };
    if template.name == "bgp_route_map_unset"
        && current.as_deref().is_some_and(|map| map != requested)
    {
        bail!(
            "peer {neighbor} currently uses route-map {}; refusing to remove requested map {requested}",
            current.as_deref().unwrap_or("")
        );
    }
    let effect = if current == desired_map {
        PreparedEffect::AlreadySatisfied
    } else {
        PreparedEffect::Change
    };
    let commands = super::templates::render(template, &input.canonical_params)?.commands;
    let restore_command = match &current {
        Some(map) => format!("neighbor {neighbor} route-map {map} {direction}"),
        None => format!("no neighbor {neighbor} route-map {requested} {direction}"),
    };
    finish_prepared(
        input,
        effect,
        commands,
        vec![before.clone()],
        vec![desired.clone()],
        vec![desired.clone()],
        Some(PreparedInverse {
            expected_current: vec![desired],
            restore: vec![before.clone()],
            commands: vec![
                "configure terminal".into(),
                format!("router bgp {local_asn}"),
                restore_command,
                "end".into(),
                format!("clear ip bgp {neighbor} soft {direction}"),
            ],
            verify: vec![before],
        }),
    )
}

fn parse_route_map_assignment(
    output: &str,
    neighbor: &str,
    direction: &str,
) -> Result<Option<String>> {
    let mut matches = output.lines().filter_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        match tokens.as_slice() {
            ["neighbor", found, "route-map", map, found_direction]
                if *found == neighbor && *found_direction == direction =>
            {
                Some((*map).to_string())
            }
            _ => None,
        }
    });
    let first = matches.next();
    if matches.next().is_some() {
        bail!("neighbor {neighbor} has multiple {direction} route-map assignments");
    }
    Ok(first)
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
    pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
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
            let output = read_one(
                pool,
                input.device_id,
                &format!("show running-config interface {interface}"),
            )
            .await?;
            if !output
                .lines()
                .any(|line| line.trim() == format!("interface {interface}"))
            {
                bail!("fresh running-config did not prove interface {interface}");
            }
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
    pool: &MySqlPool,
    input: &PrepareInput,
    template: &super::templates::Template,
    subst: &serde_json::Map<String, Value>,
    projected: &HashMap<String, DeviceStateSnapshot>,
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
            let output = read_one(
                pool,
                input.device_id,
                &format!("show running-config interface {interface}"),
            )
            .await?;
            if !output
                .lines()
                .any(|line| line.trim() == format!("interface {interface}"))
            {
                bail!("fresh running-config did not prove interface {interface}");
            }
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
            let output = read_one(
                pool,
                input.device_id,
                &format!("show interfaces {interface}"),
            )
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
    let action = PreparedDeviceAction {
        schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
        device_id: input.device_id,
        template_id: input.template_id,
        template_name: input.template_name.clone(),
        canonical_params: input.canonical_params.clone(),
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
            ..
        } => format!("route_map:{neighbor}:{direction}"),
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

fn normalize_cidr(value: &str) -> Option<String> {
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
            expected_current: Vec::new(),
            restore: Vec::new(),
            commands: vec!["no shutdown".into()],
            verify: Vec::new(),
        });
        assert!(plan.validate().is_err());
    }

    #[test]
    fn change_and_noop_require_meaningful_evidence() {
        let mut change = base(PreparedEffect::Change);
        change.commands = vec!["configure terminal".into(), "end".into()];
        assert!(change.validate().is_err());
        assert!(base(PreparedEffect::AlreadySatisfied).validate().is_err());
    }

    #[test]
    fn prepared_catalog_covers_the_eighteen_seeded_action_types_once() {
        let unique = PREPARED_TEMPLATE_NAMES
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(PREPARED_TEMPLATE_NAMES.len(), 18);
        assert_eq!(unique.len(), 18);
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
            "*> 203.0.113.0/24 0.0.0.0 0 32768 i".into(),
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
}
