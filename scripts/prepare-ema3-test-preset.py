#!/usr/bin/env python3
"""Prepare, but never apply, the reviewed EMA3-only mitigation preset."""
import argparse
import copy
import hashlib
import json
import pathlib
import sys

SOURCE_FINGERPRINT = "124b488dd8882c53bd27f8e470dd8e0f542e3abbd8a6cbd5202d0ac5e444b150"
SOURCE_ID = 1
SOURCE_REVISION = 4
SOURCE_NAME = "e-manuel-apply"
TARGET_NAME = "e-manuel-apply-ema3-test"
TARGET_DEVICE_ID = 3
TARGET_DEVICE_NAME = "eMA3"
EXPECTED_SOURCE_ACTION_IDS = [31, 33, 35, 37, 39, 42, 43, 45]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def values(snapshot, kind):
    return [copy.deepcopy(item["value"]) for item in snapshot if item.get("kind") == kind]


def prepare(snapshot):
    if fingerprint(snapshot) != SOURCE_FINGERPRINT:
        raise ValueError("input differs from the reviewed raw EMA3 snapshot")

    presets = values(snapshot, "preset")
    actions = sorted(values(snapshot, "action"), key=lambda action: action["position"])
    devices = values(snapshot, "device")
    templates = values(snapshot, "template")
    inventories = values(snapshot, "inventory")
    states = values(snapshot, "state")
    if len(presets) != 1 or (presets[0]["id"], presets[0]["name"], presets[0]["revision"], presets[0]["archived_at"]) != (SOURCE_ID, SOURCE_NAME, SOURCE_REVISION, None):
        raise ValueError("source preset identity changed")
    if len(actions) != 16 or [a["position"] for a in actions] != list(range(16)):
        raise ValueError("source action count or order changed")
    if any(a["preset_id"] != SOURCE_ID or a["enabled"] != 1 for a in actions):
        raise ValueError("source action ownership or enabled state changed")
    if {(d["id"], d["name"]) for d in devices} != {(1, "eMA2"), (2, "eMA1"), (3, "eMA3")}:
        raise ValueError("device identities changed")
    template_by_id = {template["id"]: template for template in templates}
    for template_id, name in ((12, "iface_tcp_adjust_mss"), (22, "bgp_export_policy_set")):
        if template_by_id.get(template_id) != {"id": template_id, "name": name, "enabled": 1}:
            raise ValueError(f"template {template_id} identity changed")
    if len(inventories) != 1 or inventories[0]["device_id"] != TARGET_DEVICE_ID:
        raise ValueError("EMA3 inventory identity changed")
    inventory = inventories[0]["inventory"]
    if inventories[0].get("completeness") != "complete" or inventory.get("completeness") != "complete" or inventory.get("blockers") != []:
        raise ValueError("EMA3 inventory is not complete")
    expected_lists = {
        "pfx-to-viva": [
            {"action": "permit", "prefix": "194.105.142.0/24", "sequence": 5},
            {"le": 32, "action": "deny", "prefix": "0.0.0.0/0", "sequence": 10},
        ],
        "no-export": [{"le": 32, "action": "deny", "prefix": "0.0.0.0/0", "sequence": 10}],
    }
    actual_lists = {entry["name"]: entry["entries"] for entry in inventory["prefix_lists"]}
    if any(actual_lists.get(name) != entries for name, entries in expected_lists.items()):
        raise ValueError("EMA3 target prefix-list definitions changed")
    peer_bindings = inventory["peer_bindings"]
    expected_current_policies = {
        **{ip: "no-export" for ip in ("23.45.23.197", "23.45.23.199", "23.45.23.201", "23.45.23.203", "23.45.23.205", "23.45.23.207")},
        "213.249.122.145": "pfx-to-viva",
    }
    for peer, policy in expected_current_policies.items():
        matches = [binding for binding in peer_bindings if binding.get("scope") == "direct" and binding.get("direction") == "out" and binding.get("address_family") == "ipv4" and binding.get("neighbor_ip") == peer and binding.get("policy_kind") == "prefix_list" and binding.get("policy_name") == policy]
        if len(matches) != 1:
            raise ValueError(f"EMA3 cached peer binding changed for {peer}")

    source_actions = [action for action in actions if action["device_id"] == 2 and action["device_name"] == "eMA1"]
    if [action["id"] for action in source_actions] != EXPECTED_SOURCE_ACTION_IDS:
        raise ValueError("reviewed eMA1 source action selection changed")
    target_actions = []
    for position, source in enumerate(source_actions):
        target = {
            "device_id": TARGET_DEVICE_ID,
            "reroute_template_id": source["reroute_template_id"],
            "enabled": 1,
            "params": copy.deepcopy(source["params"]),
        }
        target_actions.append(target)

    expected = [
        (22, {"neighbor_ip": ip, "policy_kind": "prefix_list", "policy_name": "pfx-to-viva"})
        for ip in ("23.45.23.197", "23.45.23.199", "23.45.23.201", "23.45.23.203", "23.45.23.205", "23.45.23.207")
    ] + [
        (12, {"mss": "1436", "interface": "Po1"}),
        (22, {"neighbor_ip": "213.249.122.145", "policy_kind": "prefix_list", "policy_name": "no-export"}),
    ]
    if [(a["reroute_template_id"], a["params"]) for a in target_actions] != expected:
        raise ValueError("derived EMA3 action semantics changed")

    body = {
        "name": TARGET_NAME,
        "description": "eMA3-only lab test clone of e-manuel-apply revision 4: advertise 194.105.142.0/24 to six Akamai peers, set Po1 MSS 1436, and apply no-export to COLT. For Idle peers, choose Configuration-only test verification; routing is not verified.",
        "created_by": None,
        "actions": target_actions,
    }
    api_body = {"name": body["name"], "description": body["description"], "actions": body["actions"]}
    report = {
        "schema": 1,
        "operation": "definition_only_insert",
        "authorization": "user-authorized EMA3-only clone",
        "source": {"id": SOURCE_ID, "name": SOURCE_NAME, "revision": SOURCE_REVISION, "action_count": 16, "fingerprint": SOURCE_FINGERPRINT},
        "target": {"name": TARGET_NAME, "device_id": TARGET_DEVICE_ID, "device_name": TARGET_DEVICE_NAME, "action_count": 8},
        "source_actions": source_actions,
        "action_derivation": [{"target_position": position, "source_action_id": source["id"]} for position, source in enumerate(source_actions)],
        "database_record": body,
        "api_body": api_body,
        "preserved_database_objects": ["source preset/actions", "rules", "router configuration", "routing inventory evidence"],
        "excluded_writes": ["execution_plans", "reroutes", "reroute_bundles", "locks", "timers", "sessions"],
    }
    return api_body, report


def sql_quote(value):
    return "'" + value.replace("'", "''") + "'"


def json_sql(value):
    return sql_quote(canonical(value))


def sql_for(body, report):
    routine = "rrt_create_ema3_test_" + SOURCE_FINGERPRINT[:12]
    source_actions = report["source_actions"]
    current_peer_policies = {
        **{ip: "no-export" for ip in ("23.45.23.197", "23.45.23.199", "23.45.23.201", "23.45.23.203", "23.45.23.205", "23.45.23.207")},
        "213.249.122.145": "pfx-to-viva",
    }
    lines = [
        "-- Definition-only insert. This does not create a plan, reroute, lock, timer, or execution authority.",
        "DELIMITER //",
        f"CREATE PROCEDURE {routine}()",
        "main: BEGIN",
        "  DECLARE new_preset_id BIGINT UNSIGNED;",
        "  DECLARE locked_revision BIGINT UNSIGNED;",
        "  DECLARE export_template_id BIGINT UNSIGNED;",
        "  DECLARE mss_template_id BIGINT UNSIGNED;",
        "  DECLARE inventory_doc JSON;",
        "  DECLARE inserted_actions INT DEFAULT 0;",
        "  DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; RESIGNAL; END;",
        "  START TRANSACTION;",
        "  SELECT revision INTO locked_revision FROM mitigation_presets WHERE id=1 AND BINARY name='e-manuel-apply' AND archived_at IS NULL FOR UPDATE;",
        "  IF locked_revision IS NULL OR locked_revision <> 4 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source preset id/revision changed'; END IF;",
        "  IF (SELECT COUNT(*) FROM mitigation_preset_actions WHERE preset_id=1) <> 16 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source preset no longer has exactly 16 actions'; END IF;",
        "  IF (SELECT COUNT(*) FROM mitigation_presets WHERE BINARY name='e-manuel-apply-ema3-test') <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='target preset name already exists; refusing overwrite'; END IF;",
        "  IF (SELECT COUNT(*) FROM devices WHERE id=3 AND BINARY name='eMA3') <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='EMA3 device identity changed'; END IF;",
        "  SELECT id INTO export_template_id FROM reroute_templates WHERE id=22 AND BINARY name='bgp_export_policy_set' AND enabled=1;",
        "  SELECT id INTO mss_template_id FROM reroute_templates WHERE id=12 AND BINARY name='iface_tcp_adjust_mss' AND enabled=1;",
        "  IF export_template_id IS NULL OR mss_template_id IS NULL THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='required enabled template identity changed'; END IF;",
        "  SELECT inventory_json INTO inventory_doc FROM routing_policy_snapshots WHERE device_id=3 AND completeness='complete' FOR UPDATE;",
        "  IF inventory_doc IS NULL OR JSON_UNQUOTE(JSON_EXTRACT(inventory_doc,'$.completeness')) <> 'complete' OR JSON_LENGTH(JSON_EXTRACT(inventory_doc,'$.blockers')) <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='EMA3 cached inventory is incomplete'; END IF;",
        "  IF (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name')) AS named_lists WHERE BINARY list_name='pfx-to-viva') <> 1 OR (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name',NESTED PATH '$.entries[*]' COLUMNS(entry_action VARCHAR(16) PATH '$.action',entry_prefix VARCHAR(64) PATH '$.prefix',entry_sequence INT PATH '$.sequence',entry_ge INT PATH '$.ge' NULL ON EMPTY,entry_le INT PATH '$.le' NULL ON EMPTY))) AS entries WHERE BINARY list_name='pfx-to-viva') <> 2 OR (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name',NESTED PATH '$.entries[*]' COLUMNS(entry_action VARCHAR(16) PATH '$.action',entry_prefix VARCHAR(64) PATH '$.prefix',entry_sequence INT PATH '$.sequence',entry_ge INT PATH '$.ge' NULL ON EMPTY,entry_le INT PATH '$.le' NULL ON EMPTY))) AS entries WHERE BINARY list_name='pfx-to-viva' AND entry_action='permit' AND entry_prefix='194.105.142.0/24' AND entry_sequence=5 AND entry_ge IS NULL AND entry_le IS NULL) <> 1 OR (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name',NESTED PATH '$.entries[*]' COLUMNS(entry_action VARCHAR(16) PATH '$.action',entry_prefix VARCHAR(64) PATH '$.prefix',entry_sequence INT PATH '$.sequence',entry_ge INT PATH '$.ge' NULL ON EMPTY,entry_le INT PATH '$.le' NULL ON EMPTY))) AS entries WHERE BINARY list_name='pfx-to-viva' AND entry_action='deny' AND entry_prefix='0.0.0.0/0' AND entry_sequence=10 AND entry_ge IS NULL AND entry_le=32) <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='EMA3 pfx-to-viva definition changed or duplicated'; END IF;",
        "  IF (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name')) AS named_lists WHERE BINARY list_name='no-export') <> 1 OR (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name',NESTED PATH '$.entries[*]' COLUMNS(entry_action VARCHAR(16) PATH '$.action',entry_prefix VARCHAR(64) PATH '$.prefix',entry_sequence INT PATH '$.sequence',entry_ge INT PATH '$.ge' NULL ON EMPTY,entry_le INT PATH '$.le' NULL ON EMPTY))) AS entries WHERE BINARY list_name='no-export') <> 1 OR (SELECT COUNT(*) FROM JSON_TABLE(inventory_doc,'$.prefix_lists[*]' COLUMNS(list_name VARCHAR(191) PATH '$.name',NESTED PATH '$.entries[*]' COLUMNS(entry_action VARCHAR(16) PATH '$.action',entry_prefix VARCHAR(64) PATH '$.prefix',entry_sequence INT PATH '$.sequence',entry_ge INT PATH '$.ge' NULL ON EMPTY,entry_le INT PATH '$.le' NULL ON EMPTY))) AS entries WHERE BINARY list_name='no-export' AND entry_action='deny' AND entry_prefix='0.0.0.0/0' AND entry_sequence=10 AND entry_ge IS NULL AND entry_le=32) <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='EMA3 no-export definition changed or duplicated'; END IF;",
    ]
    for source in source_actions:
        params = json_sql(source["params"])
        lines.append(
            f"  IF (SELECT COUNT(*) FROM mitigation_preset_actions WHERE id={source['id']} AND preset_id=1 AND device_id=2 AND position={source['position']} AND enabled=1 AND reroute_template_id={source['reroute_template_id']} AND JSON_CONTAINS(params_json,{params})=1 AND JSON_CONTAINS({params},params_json)=1) <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source action {source['id']} changed'; END IF;"
        )
    for peer, policy in current_peer_policies.items():
        lines.append(f"  IF (SELECT COUNT(*) FROM JSON_TABLE(JSON_EXTRACT(inventory_doc,'$.peer_bindings'),'$[*]' COLUMNS(scope_name VARCHAR(32) PATH '$.scope',direction_name VARCHAR(8) PATH '$.direction',address_family_name VARCHAR(16) PATH '$.address_family',neighbor_ip_name VARCHAR(45) PATH '$.neighbor_ip',policy_kind_name VARCHAR(32) PATH '$.policy_kind',policy_name_value VARCHAR(191) PATH '$.policy_name')) AS bindings WHERE scope_name='direct' AND direction_name='out' AND address_family_name='ipv4' AND neighbor_ip_name='{peer}' AND policy_kind_name='prefix_list') <> 1 OR (SELECT COUNT(*) FROM JSON_TABLE(JSON_EXTRACT(inventory_doc,'$.peer_bindings'),'$[*]' COLUMNS(scope_name VARCHAR(32) PATH '$.scope',direction_name VARCHAR(8) PATH '$.direction',address_family_name VARCHAR(16) PATH '$.address_family',neighbor_ip_name VARCHAR(45) PATH '$.neighbor_ip',policy_kind_name VARCHAR(32) PATH '$.policy_kind',policy_name_value VARCHAR(191) PATH '$.policy_name')) AS bindings WHERE scope_name='direct' AND direction_name='out' AND address_family_name='ipv4' AND neighbor_ip_name='{peer}' AND policy_kind_name='prefix_list' AND BINARY policy_name_value='{policy}') <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='EMA3 peer {peer} binding changed or duplicated'; END IF;")
    description = sql_quote(body["description"])
    lines += [
        f"  INSERT INTO mitigation_presets(name,description,revision,archived_at,created_by,updated_by) VALUES('e-manuel-apply-ema3-test',{description},1,NULL,NULL,NULL);",
        "  SET new_preset_id=LAST_INSERT_ID();",
    ]
    for position, action in enumerate(body["actions"]):
        template_var = "mss_template_id" if action["reroute_template_id"] == 12 else "export_template_id"
        lines.append(f"  INSERT INTO mitigation_preset_actions(preset_id,reroute_template_id,device_id,params_json,enabled,position) VALUES(new_preset_id,{template_var},3,{json_sql(action['params'])},1,{position});")
        lines.append("  SET inserted_actions=inserted_actions+ROW_COUNT();")
    audit_after = {"name": TARGET_NAME, "revision": 1, "created_by": None, "device_id": 3, "actions": [{**action, "position": position, "source_action_id": source["id"]} for position, (action, source) in enumerate(zip(body["actions"], source_actions))]}
    message = "User-authorized EMA3-only preset clone from source preset id 1 revision 4 with 8 actions; definition only."
    lines += [
        "  IF inserted_actions <> 8 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='target action insert count mismatch'; END IF;",
        f"  INSERT INTO audit_logs(actor_type,actor_user_id,event_type,entity_type,entity_id,message,before_json,after_json) VALUES('system',NULL,'mitigation_preset_cloned','mitigation_preset',new_preset_id,{sql_quote(message)},{json_sql({'source_preset_id': 1, 'source_revision': 4, 'source_actions': source_actions})},{json_sql(audit_after)});",
        "  COMMIT;",
        "END//",
        "DELIMITER ;",
        f"CALL {routine}();",
        f"DROP PROCEDURE {routine};",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=pathlib.Path)
    parser.add_argument("--body", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--sql", type=pathlib.Path, required=True)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text())
    body, report = prepare(snapshot)
    args.body.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.sql.write_text(sql_for(body, report))
    print(canonical({"body": str(args.body), "report": str(args.report), "sql": str(args.sql), "target": TARGET_NAME, "actions": 8}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"refused: {error}", file=sys.stderr)
        sys.exit(2)
