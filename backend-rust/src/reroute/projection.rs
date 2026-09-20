//! Whole-set, secret-free projection for prepared device actions.

use super::device_plan::{DeviceStateSnapshot, PreparedDeviceAction, PreparedEffect};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectedChange {
    pub action_index: usize,
    pub template_name: String,
    pub effect: PreparedEffect,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceProjection {
    pub device_id: u64,
    pub before_config: String,
    pub after_config: String,
    pub revert_config: String,
    pub changes: Vec<ProjectedChange>,
    pub completeness: String,
    pub blockers: Vec<String>,
    pub read_at: DateTime<Utc>,
}

struct ProjectionState {
    before: Vec<DeviceStateSnapshot>,
    after: Vec<DeviceStateSnapshot>,
    revert: Vec<DeviceStateSnapshot>,
    changes: Vec<ProjectedChange>,
    read_at: DateTime<Utc>,
}

/// Project an ordered set through one shared state. Later actions therefore see
/// earlier after-state, while revert is rendered in reverse action order.
pub fn project_action_set(
    actions: &[PreparedDeviceAction],
) -> anyhow::Result<Vec<DeviceProjection>> {
    for action in actions {
        action.validate()?;
    }
    let mut devices: BTreeMap<u64, ProjectionState> = BTreeMap::new();
    for (index, action) in actions.iter().enumerate() {
        let d = devices
            .entry(action.device_id)
            .or_insert_with(|| ProjectionState {
                before: vec![],
                after: vec![],
                revert: vec![],
                changes: vec![],
                read_at: action.prepared_at,
            });
        for state in &action.before {
            insert_first(&mut d.before, state.clone());
            insert_first(&mut d.after, state.clone());
        }
        for state in &action.after {
            upsert(&mut d.after, state.clone());
        }
        d.changes.push(ProjectedChange {
            action_index: index,
            template_name: action.template_name.clone(),
            effect: action.effect,
        });
        d.read_at = d.read_at.max(action.prepared_at);
    }
    for action in actions.iter().rev() {
        if let Some(d) = devices.get_mut(&action.device_id) {
            if let Some(inv) = &action.inverse {
                for state in &inv.restore {
                    upsert(&mut d.revert, state.clone())
                }
            } else {
                for state in &action.before {
                    upsert(&mut d.revert, state.clone())
                }
            }
        }
    }
    Ok(devices
        .into_iter()
        .map(|(device_id, state)| {
            let ProjectionState {
                before,
                after,
                revert,
                changes,
                read_at,
            } = state;
            let legacy_scope = before
                .iter()
                .chain(after.iter())
                .chain(revert.iter())
                .any(|s| {
                    matches!(
                        s,
                        DeviceStateSnapshot::RouteMapAssignment {
                            address_family: None,
                            ..
                        }
                    )
                });
            DeviceProjection {
                device_id,
                before_config: render(&before),
                after_config: render(&after),
                revert_config: render(&revert),
                changes,
                completeness: if legacy_scope {
                    "incomplete"
                } else {
                    "complete"
                }
                .into(),
                blockers: if legacy_scope {
                    vec!["legacy route-map assignment has no proven address-family scope".into()]
                } else {
                    vec![]
                },
                read_at,
            }
        })
        .collect())
}

fn upsert(states: &mut Vec<DeviceStateSnapshot>, state: DeviceStateSnapshot) {
    let k = key(&state);
    if let Some(pos) = states.iter().position(|s| key(s) == k) {
        states[pos] = state
    } else {
        states.push(state)
    }
}
fn insert_first(states: &mut Vec<DeviceStateSnapshot>, state: DeviceStateSnapshot) {
    let k = key(&state);
    if !states.iter().any(|s| key(s) == k) {
        states.push(state);
    }
}
fn key(s: &DeviceStateSnapshot) -> String {
    match s {
        DeviceStateSnapshot::PrefixList { name, .. } => format!("prefix-list:{name}"),
        DeviceStateSnapshot::Ipv4StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => format!("v4-route:{prefix}:{next_hop}:{tag:?}"),
        DeviceStateSnapshot::Ipv6StaticRoute {
            prefix,
            next_hop,
            tag,
            ..
        } => format!("v6-route:{prefix}:{next_hop}:{tag:?}"),
        DeviceStateSnapshot::RouteResolution {
            prefix, next_hop, ..
        } => format!("route-resolution:{prefix}:{next_hop}"),
        DeviceStateSnapshot::BgpAdvertisement {
            neighbor, prefix, ..
        } => format!("advertisement:{neighbor}:{prefix}"),
        DeviceStateSnapshot::BgpRoute { prefix, .. } => format!("bgp-route:{prefix}"),
        DeviceStateSnapshot::NeighborShutdown { neighbor, .. } => {
            format!("neighbor:{neighbor}:shutdown")
        }
        DeviceStateSnapshot::BgpNeighborState { neighbor, .. } => {
            format!("neighbor:{neighbor}:operational")
        }
        DeviceStateSnapshot::RouteMapAssignment {
            neighbor,
            direction,
            address_family,
            ..
        } => format!("peer:{neighbor}:{direction}:{address_family:?}"),
        DeviceStateSnapshot::ExportPolicyAttachment {
            neighbor,
            address_family,
            ..
        } => format!("export-policy:{neighbor}:{address_family}"),
        DeviceStateSnapshot::InterfaceAdmin { interface, .. } => {
            format!("interface:{interface}:admin")
        }
        DeviceStateSnapshot::InterfaceOperational { interface, .. } => {
            format!("interface:{interface}:operational")
        }
        DeviceStateSnapshot::InterfaceMss { interface, .. } => format!("interface:{interface}:mss"),
    }
}
fn render(states: &[DeviceStateSnapshot]) -> String {
    let mut sections = Vec::new();
    let mut attachments: BTreeMap<(u32, String), std::collections::BTreeSet<String>> =
        BTreeMap::new();
    let mut prefix_lists: BTreeMap<String, crate::reroute::policy::NamedPrefixList> =
        BTreeMap::new();
    let mut route_maps: BTreeMap<String, crate::reroute::policy::NamedRouteMap> = BTreeMap::new();
    for state in states {
        if let DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn,
            neighbor,
            address_family,
            prefix_list,
            route_map,
            prefix_lists: lists,
            route_maps: maps,
            ..
        } = state
        {
            let lines = attachments
                .entry((*local_asn, address_family.clone()))
                .or_default();
            if let Some(name) = prefix_list {
                lines.insert(format!("  neighbor {neighbor} prefix-list {name} out"));
            }
            if let Some(name) = route_map {
                lines.insert(format!("  neighbor {neighbor} route-map {name} out"));
            }
            for list in lists {
                prefix_lists
                    .entry(list.name.clone())
                    .or_insert_with(|| list.clone());
            }
            for map in maps {
                route_maps
                    .entry(map.name.clone())
                    .or_insert_with(|| map.clone());
            }
        } else {
            sections.push(render_state(state));
        }
    }
    for ((asn, af), lines) in attachments {
        let mut body = vec![format!("router bgp {asn}"), format!(" address-family {af}")];
        body.extend(lines);
        body.push(" exit-address-family".into());
        sections.push(body.join("\n"));
    }
    for (_, list) in prefix_lists {
        for entry in list.entries {
            sections.push(format!(
                "ip prefix-list {} seq {} {} {}{}{}",
                list.name,
                entry.sequence,
                match entry.action {
                    crate::reroute::policy::PermitDeny::Permit => "permit",
                    crate::reroute::policy::PermitDeny::Deny => "deny",
                },
                entry.prefix,
                entry.ge.map(|v| format!(" ge {v}")).unwrap_or_default(),
                entry.le.map(|v| format!(" le {v}")).unwrap_or_default()
            ));
        }
    }
    for (_, map) in route_maps {
        for clause in map.clauses {
            sections.push(format!(
                "route-map {} {} {}",
                map.name,
                match clause.action {
                    crate::reroute::policy::PermitDeny::Permit => "permit",
                    crate::reroute::policy::PermitDeny::Deny => "deny",
                },
                clause.sequence
            ));
            for term in clause.matches {
                sections.push(format!(" match {}", term.value));
            }
            for term in clause.sets {
                sections.push(format!(" set {}", term.value));
            }
        }
    }
    sections.join("\n")
}
fn render_state(s: &DeviceStateSnapshot) -> String {
    match s {
        DeviceStateSnapshot::PrefixList{name,entries,..}=>entries.iter().map(|e|format!("ip prefix-list {name} seq {} {} {}{}{}",e.sequence,if e.permit{"permit"}else{"deny"},e.prefix,e.ge.map(|v|format!(" ge {v}")).unwrap_or_default(),e.le.map(|v|format!(" le {v}")).unwrap_or_default())).collect::<Vec<_>>().join("\n"),
        DeviceStateSnapshot::RouteMapAssignment{local_asn,neighbor,direction,address_family,route_map}=>match address_family {
            Some(family)=>{let line=route_map.as_ref().map(|m|format!("neighbor {neighbor} route-map {m} {direction}")).unwrap_or_else(||format!("! neighbor {neighbor} has no {direction} route-map"));if family=="default_ipv4"{format!("router bgp {local_asn}\n {line}")}else{format!("router bgp {local_asn}\n address-family {family}\n  {line}\n exit-address-family")}},
            None=>match route_map{Some(m)=>format!("! incomplete scope: router bgp {local_asn}, neighbor {neighbor} route-map {m} {direction}"),None=>format!("! incomplete scope: router bgp {local_asn}, neighbor {neighbor} has no {direction} route-map")}
        },
        DeviceStateSnapshot::Ipv4StaticRoute{present,..}|DeviceStateSnapshot::Ipv6StaticRoute{present,..}=>{
            let line=super::device_plan::static_config_line(s).unwrap_or_else(|_|"! invalid static route evidence".into());
            if *present {line}else{format!("! absent: {line}")}
        },
        DeviceStateSnapshot::NeighborShutdown{local_asn,neighbor,shutdown}=>format!("router bgp {local_asn}\n {}neighbor {neighbor} shutdown",if *shutdown{""}else{"no "}),
        DeviceStateSnapshot::InterfaceAdmin{interface,shutdown}=>format!("interface {interface}\n {}shutdown",if *shutdown{""}else{"no "}),
        DeviceStateSnapshot::InterfaceMss{interface,mss}=>match mss{Some(v)=>format!("interface {interface}\n ip tcp adjust-mss {v}"),None=>format!("interface {interface}\n no ip tcp adjust-mss")},
        DeviceStateSnapshot::BgpAdvertisement{neighbor,prefix,present,..}=>format!("! neighbor {neighbor} {}advertises {prefix}",if *present{""}else{"does not "}),
        DeviceStateSnapshot::BgpRoute{prefix,present,..}=>format!("! BGP route {prefix} {}present",if *present{""}else{"not "}),
        DeviceStateSnapshot::RouteResolution{prefix,next_hop,present}=>format!("! route {prefix} via {next_hop} {}present",if *present{""}else{"not "}),
        DeviceStateSnapshot::BgpNeighborState{neighbor,administratively_shutdown,state}=>format!("! neighbor {neighbor}: admin_shutdown={administratively_shutdown}, state={}",state.as_deref().unwrap_or("unknown")),
        DeviceStateSnapshot::InterfaceOperational{interface,administratively_down}=>format!("! interface {interface}: administratively_down={administratively_down}"),
        DeviceStateSnapshot::ExportPolicyAttachment{local_asn,neighbor,address_family,prefix_list,route_map,prefix_lists,route_maps,..} => {
            let mut lines=vec![format!("router bgp {local_asn}"),format!(" address-family {address_family}")];
            if let Some(name)=prefix_list {lines.push(format!("  neighbor {neighbor} prefix-list {name} out"));}
            if let Some(name)=route_map {lines.push(format!("  neighbor {neighbor} route-map {name} out"));}
            lines.push(" exit-address-family".into());
            for list in prefix_lists { for entry in &list.entries {lines.push(format!("ip prefix-list {} seq {} {} {}{}{}",list.name,entry.sequence,match entry.action{crate::reroute::policy::PermitDeny::Permit=>"permit",crate::reroute::policy::PermitDeny::Deny=>"deny"},entry.prefix,entry.ge.map(|v|format!(" ge {v}")).unwrap_or_default(),entry.le.map(|v|format!(" le {v}")).unwrap_or_default()));} }
            for map in route_maps { for clause in &map.clauses {lines.push(format!("route-map {} {} {}",map.name,match clause.action{crate::reroute::policy::PermitDeny::Permit=>"permit",crate::reroute::policy::PermitDeny::Deny=>"deny"},clause.sequence));for term in &clause.matches{lines.push(format!(" match {}",term.value));}for term in &clause.sets{lines.push(format!(" set {}",term.value));}} }
            lines.join("\n")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reroute::device_plan::*;
    use serde_json::json;
    fn a(before: Option<&str>, after: &str) -> PreparedDeviceAction {
        let s = |m: Option<&str>| DeviceStateSnapshot::RouteMapAssignment {
            local_asn: 34501,
            neighbor: "1.1.1.1".into(),
            direction: "out".into(),
            address_family: None,
            route_map: m.map(Into::into),
        };
        PreparedDeviceAction {
            schema_version: 1,
            device_id: 1,
            template_id: 1,
            template_name: "bgp_export_policy_set".into(),
            canonical_params: json!({}),
            verification_mode: VerificationMode::Routing,
            commands: vec!["x".into()],
            before: vec![s(before)],
            after: vec![s(Some(after))],
            verify: vec![s(Some(after))],
            effect: PreparedEffect::Change,
            inverse: Some(PreparedInverse {
                verification_mode: VerificationMode::Routing,
                expected_current: vec![s(Some(after))],
                restore: vec![s(before)],
                commands: vec!["y".into()],
                verify: vec![s(before)],
            }),
            prepared_at: Utc::now(),
        }
    }
    #[test]
    fn sequential_projection_and_reverse() {
        let p = project_action_set(&[a(None, "A"), a(Some("A"), "B")]).unwrap();
        assert!(p[0].after_config.contains("route-map B out"));
        assert!(p[0].before_config.contains("has no out route-map"));
        assert!(p[0].revert_config.contains("has no out route-map"));
    }

    #[test]
    fn static_ipv4_uses_network_mask_and_absence_is_not_a_mutation_command() {
        let present = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            tag: None,
            present: true,
        };
        let absent = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            tag: None,
            present: false,
        };
        assert_eq!(
            render_state(&present),
            "ip route 203.0.113.9 255.255.255.255 Null0"
        );
        assert_eq!(
            render_state(&absent),
            "! absent: ip route 203.0.113.9 255.255.255.255 Null0"
        );
    }

    #[test]
    fn export_definitions_are_deduplicated_across_peers() {
        use crate::reroute::policy::{NamedPrefixList, PermitDeny, PrefixListEntry};
        let list = NamedPrefixList {
            name: "EMDD".into(),
            referenced_by: vec![],
            entries: vec![PrefixListEntry {
                sequence: 5,
                action: PermitDeny::Permit,
                prefix: "194.105.142.0/24".into(),
                ge: None,
                le: None,
            }],
        };
        let state = |peer: &str| DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn: 34501,
            neighbor: peer.into(),
            address_family: "ipv4".into(),
            prefix_list: Some("EMDD".into()),
            route_map: None,
            prefix_lists: vec![list.clone()],
            route_maps: vec![],
            required_prefix_lists: None,
            required_route_maps: None,
        };
        let rendered = render(&[state("192.0.2.1"), state("192.0.2.2")]);
        assert_eq!(rendered.matches("router bgp 34501").count(), 1);
        assert_eq!(rendered.matches("ip prefix-list EMDD seq 5").count(), 1);
        assert!(rendered.contains("neighbor 192.0.2.1 prefix-list EMDD out"));
        assert!(rendered.contains("neighbor 192.0.2.2 prefix-list EMDD out"));
    }

    #[test]
    fn mixed_peer_mss_and_static_projection_has_exact_before_after_revert() {
        let mk = |name: &str, before: Vec<DeviceStateSnapshot>, after: Vec<DeviceStateSnapshot>| {
            PreparedDeviceAction {
                schema_version: 1,
                device_id: 7,
                template_id: 1,
                template_name: name.into(),
                canonical_params: json!({}),
                verification_mode: VerificationMode::Routing,
                commands: vec!["configure terminal".into(), "x".into(), "end".into()],
                before: before.clone(),
                after: after.clone(),
                verify: after.clone(),
                effect: PreparedEffect::Change,
                inverse: Some(PreparedInverse {
                    verification_mode: VerificationMode::Routing,
                    expected_current: after,
                    restore: before.clone(),
                    commands: vec!["configure terminal".into(), "y".into(), "end".into()],
                    verify: before,
                }),
                prepared_at: Utc::now(),
            }
        };
        let route_before = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            tag: None,
            present: false,
        };
        let route_after = DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            tag: None,
            present: true,
        };
        let mss_before = DeviceStateSnapshot::InterfaceMss {
            interface: "Port-channel1".into(),
            mss: None,
        };
        let mss_after = DeviceStateSnapshot::InterfaceMss {
            interface: "Port-channel1".into(),
            mss: Some(1400),
        };
        let peer = |map: Option<&str>| DeviceStateSnapshot::ExportPolicyAttachment {
            local_asn: 34501,
            neighbor: "89.33.22.81".into(),
            address_family: "ipv4".into(),
            prefix_list: Some("pfx-to-viva".into()),
            route_map: map.map(Into::into),
            prefix_lists: vec![],
            route_maps: vec![],
            required_prefix_lists: None,
            required_route_maps: None,
        };
        let projection = project_action_set(&[
            mk("null_route_prefix", vec![route_before], vec![route_after]),
            mk("iface_tcp_adjust_mss", vec![mss_before], vec![mss_after]),
            mk(
                "bgp_export_policy_set",
                vec![peer(None)],
                vec![peer(Some("prepend-3"))],
            ),
        ])
        .unwrap()
        .remove(0);
        assert!(projection
            .before_config
            .contains("! absent: ip route 203.0.113.9 255.255.255.255 Null0"));
        assert!(projection
            .after_config
            .contains("ip route 203.0.113.9 255.255.255.255 Null0"));
        assert!(projection.after_config.contains("ip tcp adjust-mss 1400"));
        assert!(projection.after_config.contains("route-map prepend-3 out"));
        assert!(projection.revert_config.contains("! absent: ip route"));
        assert!(projection.revert_config.contains("no ip tcp adjust-mss"));
        assert!(!projection.revert_config.contains("route-map prepend-3 out"));
    }
}
