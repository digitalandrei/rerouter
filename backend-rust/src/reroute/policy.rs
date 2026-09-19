//! Bounded, typed IPv4 routing-policy inventory.
//!
//! Parsing is deliberately limited to the IOS forms Rerouter can explain and
//! safely attach. Unknown clauses remain visible as blockers; they are never
//! guessed through.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermitDeny {
    Permit,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixListEntry {
    pub sequence: u32,
    pub action: PermitDeny,
    pub prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ge: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub le: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTerm {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMapClause {
    pub sequence: u32,
    pub action: PermitDeny,
    pub matches: Vec<PolicyTerm>,
    pub sets: Vec<PolicyTerm>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedPrefixList {
    pub name: String,
    pub entries: Vec<PrefixListEntry>,
    pub referenced_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedRouteMap {
    pub name: String,
    pub clauses: Vec<RouteMapClause>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingScope {
    Direct,
    Inherited,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    PrefixList,
    RouteMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerPolicyBinding {
    pub neighbor_ip: String,
    pub local_asn: u32,
    pub address_family: String,
    pub direction: String,
    pub policy_kind: PolicyKind,
    pub policy_name: String,
    pub scope: BindingScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryCompleteness {
    Complete,
    Partial,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPolicyInventory {
    pub device_id: u64,
    pub read_at: DateTime<Utc>,
    pub completeness: InventoryCompleteness,
    pub blockers: Vec<String>,
    pub prefix_lists: Vec<NamedPrefixList>,
    pub route_maps: Vec<NamedRouteMap>,
    pub peer_bindings: Vec<PeerPolicyBinding>,
}

pub fn parse_inventory(
    device_id: u64,
    bgp: &str,
    route_maps: &str,
    prefix_lists: &str,
    read_at: DateTime<Utc>,
) -> RoutingPolicyInventory {
    let mut blockers = Vec::new();
    let mut lists: BTreeMap<String, NamedPrefixList> = BTreeMap::new();
    for line in prefix_lists.lines() {
        let t: Vec<_> = line.split_whitespace().collect();
        let Some(pos) = t
            .windows(2)
            .position(|w| w == ["prefix-list", "sequence-number"] || w[0] == "prefix-list")
        else {
            continue;
        };
        if t.get(pos) != Some(&"prefix-list") || t.get(pos + 1) == Some(&"sequence-number") {
            continue;
        }
        let Some(name) = t.get(pos + 1) else { continue };
        let rest = &t[pos + 2..];
        let (sequence, at) = if rest.first() == Some(&"seq") {
            (rest.get(1).and_then(|s| s.parse().ok()), 2)
        } else {
            (None, 0)
        };
        let Some(sequence) = sequence else {
            blockers.push(format!("prefix_list_{name}_missing_sequence"));
            continue;
        };
        let Some(action) = rest.get(at).and_then(|s| match *s {
            "permit" => Some(PermitDeny::Permit),
            "deny" => Some(PermitDeny::Deny),
            _ => None,
        }) else {
            blockers.push(format!("prefix_list_{name}_unsupported_action"));
            continue;
        };
        let Some(prefix) = rest.get(at + 1).filter(|p| valid_prefix(p)) else {
            blockers.push(format!("prefix_list_{name}_invalid_prefix"));
            continue;
        };
        let mut ge = None;
        let mut le = None;
        let mut i = at + 2;
        let mut valid = true;
        while i < rest.len() {
            match rest[i] {
                "ge" => ge = rest.get(i + 1).and_then(|v| v.parse().ok()),
                "le" => le = rest.get(i + 1).and_then(|v| v.parse().ok()),
                _ => valid = false,
            };
            i += 2;
        }
        if !valid || ge.is_some_and(|v| v > 32) || le.is_some_and(|v| v > 32) {
            blockers.push(format!("prefix_list_{name}_unsupported_qualifier"));
            continue;
        }
        lists
            .entry((*name).into())
            .or_insert_with(|| NamedPrefixList {
                name: (*name).into(),
                entries: vec![],
                referenced_by: vec![],
            })
            .entries
            .push(PrefixListEntry {
                sequence,
                action,
                prefix: (*prefix).into(),
                ge,
                le,
            });
    }
    for l in lists.values_mut() {
        l.entries.sort_by_key(|e| e.sequence);
        if l.entries.windows(2).any(|w| w[0].sequence == w[1].sequence) {
            blockers.push(format!("prefix_list_{}_duplicate_sequence", l.name));
        }
    }

    let mut maps: BTreeMap<String, NamedRouteMap> = BTreeMap::new();
    let mut active: Option<(String, usize)> = None;
    for line in route_maps.lines() {
        let t: Vec<_> = line.split_whitespace().collect();
        if let ["route-map", name, act, seq] = t.as_slice() {
            let action = match *act {
                "permit" => PermitDeny::Permit,
                "deny" => PermitDeny::Deny,
                _ => {
                    blockers.push(format!("route_map_{name}_unsupported_action"));
                    continue;
                }
            };
            let Some(sequence) = seq.parse().ok() else {
                blockers.push(format!("route_map_{name}_invalid_sequence"));
                continue;
            };
            let map = maps.entry((*name).into()).or_insert_with(|| NamedRouteMap {
                name: (*name).into(),
                clauses: vec![],
                references: vec![],
            });
            map.clauses.push(RouteMapClause {
                sequence,
                action,
                matches: vec![],
                sets: vec![],
            });
            active = Some(((*name).into(), map.clauses.len() - 1));
            continue;
        }
        let Some((name, idx)) = &active else { continue };
        let Some(clause) = maps.get_mut(name).and_then(|m| m.clauses.get_mut(*idx)) else {
            continue;
        };
        if let Some(v) = line.trim().strip_prefix("match ") {
            clause.matches.push(PolicyTerm {
                kind: v.split_whitespace().take(3).collect::<Vec<_>>().join("_"),
                value: v.into(),
            });
        } else if let Some(v) = line.trim().strip_prefix("set ") {
            clause.sets.push(PolicyTerm {
                kind: v.split_whitespace().take(2).collect::<Vec<_>>().join("_"),
                value: v.into(),
            });
        }
    }

    let (local_asn, bindings) = parse_bindings(bgp, &mut blockers);
    for b in &bindings {
        let reference = format!(
            "neighbor:{}:{}:{}",
            b.neighbor_ip, b.address_family, b.direction
        );
        match b.policy_kind {
            PolicyKind::PrefixList => {
                if let Some(p) = lists.get_mut(&b.policy_name) {
                    p.referenced_by.push(reference)
                }
            }
            PolicyKind::RouteMap => {
                if let Some(r) = maps.get_mut(&b.policy_name) {
                    r.references.push(reference)
                }
            }
        }
    }
    for b in &bindings {
        let known = match b.policy_kind {
            PolicyKind::PrefixList => lists.contains_key(&b.policy_name),
            PolicyKind::RouteMap => maps.contains_key(&b.policy_name),
        };
        if !known {
            blockers.push(format!("dangling_policy_{}", b.policy_name));
        }
    }
    if local_asn.is_none() {
        blockers.push("bgp_local_asn_unproven".into());
    }
    RoutingPolicyInventory {
        device_id,
        read_at,
        completeness: if blockers.is_empty() {
            InventoryCompleteness::Complete
        } else {
            InventoryCompleteness::Partial
        },
        blockers,
        prefix_lists: lists.into_values().collect(),
        route_maps: maps.into_values().collect(),
        peer_bindings: bindings,
    }
}

fn valid_prefix(s: &str) -> bool {
    s.split_once('/').is_some_and(|(ip, len)| {
        ip.parse::<Ipv4Addr>().is_ok() && len.parse::<u8>().is_ok_and(|n| n <= 32)
    })
}

fn parse_bindings(bgp: &str, blockers: &mut Vec<String>) -> (Option<u32>, Vec<PeerPolicyBinding>) {
    let mut asn = None;
    let mut af = "default_ipv4";
    let mut direct = Vec::new();
    let mut groups: BTreeMap<String, Vec<(PolicyKind, String)>> = BTreeMap::new();
    let mut memberships: BTreeMap<String, String> = BTreeMap::new();
    for line in bgp.lines() {
        let s = line.trim();
        if let Some(v) = s.strip_prefix("router bgp ") {
            asn = v.parse().ok();
            continue;
        }
        if let Some(v) = s.strip_prefix("address-family ") {
            af = if v == "ipv4" || v == "ipv4 unicast" {
                "ipv4"
            } else {
                "unsupported"
            };
            continue;
        }
        if s == "exit-address-family" {
            af = "default_ipv4";
            continue;
        }
        let Some(r) = s.strip_prefix("neighbor ") else {
            continue;
        };
        let t: Vec<_> = r.split_whitespace().collect();
        if let [peer, "peer-group", group] = t.as_slice() {
            if peer.parse::<Ipv4Addr>().is_ok() {
                memberships.insert((*peer).into(), (*group).into());
            }
            continue;
        }
        let Some((kind, name, dir)) = (match t.as_slice() {
            [_, "prefix-list", n, d] => Some((PolicyKind::PrefixList, *n, *d)),
            [_, "route-map", n, d] => Some((PolicyKind::RouteMap, *n, *d)),
            _ => None,
        }) else {
            continue;
        };
        if dir != "out" {
            continue;
        }
        if af == "unsupported" {
            blockers.push(format!("unsupported_address_family_for_{}", t[0]));
            continue;
        }
        if let Ok(ip) = t[0].parse::<Ipv4Addr>() {
            direct.push((ip.to_string(), kind, name.to_string(), af.to_string()))
        } else {
            groups
                .entry(t[0].into())
                .or_default()
                .push((kind, name.into()))
        }
    }
    let mut out = Vec::new();
    let Some(local) = asn else { return (None, out) };
    for (peer, kind, name, family) in direct {
        out.push(PeerPolicyBinding {
            neighbor_ip: peer,
            local_asn: local,
            address_family: family,
            direction: "out".into(),
            policy_kind: kind,
            policy_name: name,
            scope: BindingScope::Direct,
        });
    }
    for (peer, group) in memberships {
        if let Some(p) = groups.get(&group) {
            for (kind, name) in p {
                out.push(PeerPolicyBinding {
                    neighbor_ip: peer.clone(),
                    local_asn: local,
                    address_family: "ipv4".into(),
                    direction: "out".into(),
                    policy_kind: kind.clone(),
                    policy_name: name.clone(),
                    scope: if p.len() == 1 {
                        BindingScope::Inherited
                    } else {
                        BindingScope::Ambiguous
                    },
                })
            }
        }
    }
    for index in 0..out.len() {
        let count = out
            .iter()
            .filter(|other| {
                other.neighbor_ip == out[index].neighbor_ip
                    && other.address_family == out[index].address_family
                    && other.direction == out[index].direction
                    && other.policy_kind == out[index].policy_kind
            })
            .count();
        if count > 1 {
            out[index].scope = BindingScope::Ambiguous;
        }
    }
    (Some(local), out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emdd_inventory_keeps_extra_prefix_and_scope() {
        let p="ip prefix-list pfx-to-viva seq 5 permit 194.105.142.0/24\nip prefix-list pfx-to-viva seq 10 permit 194.102.117.0/24\nip prefix-list pfx-to-viva seq 20 deny 0.0.0.0/0 le 32\nip prefix-list no-export seq 5 deny 0.0.0.0/0 le 32";
        let b="router bgp 34501\n address-family ipv4\n neighbor 1.1.1.1 prefix-list pfx-to-viva out\n exit-address-family";
        let i = parse_inventory(2, b, "", p, Utc::now());
        assert_eq!(i.prefix_lists[1].entries.len(), 3);
        assert_eq!(i.peer_bindings[0].scope, BindingScope::Direct);
        assert_eq!(i.peer_bindings[0].address_family, "ipv4");
    }
    #[test]
    fn preserves_global_scope_and_refuses_duplicate_direct_binding() {
        let p="ip prefix-list A seq 5 permit 192.0.2.0/24\nip prefix-list B seq 5 deny 0.0.0.0/0 le 32";
        let b="router bgp 34501\n neighbor 1.1.1.1 remote-as 64500\n neighbor 1.1.1.1 prefix-list A out\n neighbor 1.1.1.1 prefix-list B out";
        let i = parse_inventory(1, b, "", p, Utc::now());
        assert!(i
            .peer_bindings
            .iter()
            .all(|binding| binding.address_family == "default_ipv4"));
        assert!(i
            .peer_bindings
            .iter()
            .all(|binding| binding.scope == BindingScope::Ambiguous));
    }
    #[test]
    fn sanitized_ema3_snapshot_preserves_peer_scope_and_attribute_maps() {
        let prefixes="ip prefix-list no-export seq 10 deny 0.0.0.0/0 le 32\nip prefix-list pfx-to-viva seq 5 permit 194.105.142.0/24\nip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32\nip prefix-list no-default seq 20 permit 0.0.0.0/0 ge 1 le 24";
        let bgp="router bgp 34501\n neighbor 23.45.23.197 remote-as 32787\n neighbor 89.33.22.81 remote-as 57136\n address-family ipv4\n neighbor 23.45.23.197 activate\n neighbor 23.45.23.197 prefix-list no-export out\n neighbor 89.33.22.81 activate\n neighbor 89.33.22.81 prefix-list pfx-to-viva out\n neighbor 89.33.22.81 route-map prepend-3 out\n exit-address-family";
        let maps="route-map teste-iulian permit 10\n match ip address 10\n set local-preference 201\nroute-map prepend-3 permit 100\n set as-path prepend 34501 34501 34501\nroute-map set-metric permit 10\n set metric 80";
        let inventory = parse_inventory(3, bgp, maps, prefixes, Utc::now());
        assert!(inventory.blockers.is_empty(), "{:?}", inventory.blockers);
        assert!(inventory
            .peer_bindings
            .iter()
            .all(|b| b.scope == BindingScope::Direct && b.address_family == "ipv4"));
        let prepend = inventory
            .route_maps
            .iter()
            .find(|m| m.name == "prepend-3")
            .unwrap();
        assert!(prepend.clauses[0].matches.is_empty());
        assert_eq!(
            prepend.clauses[0].sets[0].value,
            "as-path prepend 34501 34501 34501"
        );
        let filtering = inventory
            .route_maps
            .iter()
            .find(|m| m.name == "teste-iulian")
            .unwrap();
        assert!(!filtering.clauses[0].matches.is_empty());
    }
}
