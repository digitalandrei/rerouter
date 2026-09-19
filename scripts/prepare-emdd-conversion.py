#!/usr/bin/env python3
"""Prepare the reviewed EMDD definition conversion without contacting production."""
import argparse, copy, hashlib, json, pathlib, sys

PREFIX = "194.105.142.0/24"
REVIEWED_FINGERPRINT = "c4f667d50197533cc668de59e8c4633e0747c087cb7731a9b15e5b941eaba161"
SNAPSHOT_KEYS = ("preset", "actions", "templates", "devices", "rule_count", "active_runs", "reroute_count", "device_locks", "migrations")

def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"))
def fingerprint(value): return hashlib.sha256(canonical(value).encode()).hexdigest()
def reviewed_fingerprint(snapshot): return fingerprint({key: snapshot[key] for key in SNAPSHOT_KEYS})

def convert(source):
    snapshot = copy.deepcopy(source)
    if reviewed_fingerprint(snapshot) != REVIEWED_FINGERPRINT:
        raise ValueError("input differs from the reviewed raw EMDD snapshot")
    preset, actions, templates = snapshot["preset"], snapshot["actions"], snapshot["templates"]
    if (preset["id"], preset["name"], preset["revision"], preset["archived_at"]) != (1, "e-manuel-apply", 3, None):
        raise ValueError("preset identity changed")
    if snapshot["migrations"] != 67 or len(templates) != 18 or snapshot["rule_count"] != 13:
        raise ValueError("source schema/catalog/rule count changed")
    if snapshot["active_runs"] or snapshot["reroute_count"] or snapshot["device_locks"]:
        raise ValueError("active history or locks present")
    if len(actions) != 16 or [a["id"] for a in actions] != list(range(31, 47)) or [a["position"] for a in actions] != list(range(16)):
        raise ValueError("action identities or positions changed")
    if any(a["enabled"] != 1 or a["preset_id"] != 1 for a in actions): raise ValueError("action enabled/owner state changed")
    if "bgp_export_policy_set" in {t["name"] for t in templates}: raise ValueError("source snapshot unexpectedly contains target template")

    before = copy.deepcopy(actions); changed=[]; blocked=[]
    for action in actions:
        if action["template_name"] == "iface_tcp_adjust_mss":
            if action["params"] != {"mss":"1436","interface":"Po1"} or action["reroute_template_id"] != 12: raise ValueError("MSS fingerprint changed")
            continue
        params=action["params"]; peer=params["neighbor_ip"]
        if params["prefix"] != PREFIX: raise ValueError("prefix scope changed")
        if action["device_name"] == "eMA1": policy = "no-export" if action["template_name"] == "bgp_advertise_remove" else "pfx-to-viva"
        elif action["device_name"] == "eMA2":
            policy = "rr-colt-without-194105142" if action["template_name"] == "bgp_advertise_remove" else "rr-194105142-only"; blocked.append(action["id"])
        else: raise ValueError("unexpected device")
        action["planned_template_name"]="bgp_export_policy_set"; action["reroute_template_id"]=None
        action["template_name"]="bgp_export_policy_set"; action["params"]={"neighbor_ip":peer,"policy_kind":"prefix_list","policy_name":policy}
        action["definition_status"]="needs_setup" if action["id"] in blocked else "ready"; changed.append(action["id"])
    if len(changed)!=14 or len(blocked)!=7: raise ValueError("reviewed conversion cardinality changed")
    result={"preset":{**preset,"revision":4},"actions":actions}
    report={"schema":2,"preset_id":1,"planned_target_template_name":"bgp_export_policy_set","resolved_target_template_id":None,
            "before_fingerprint":fingerprint(before),"after_fingerprint":fingerprint(actions),"before_actions":before,
            "preserved_description":preset["description"],"preserved_action_ids":[a["id"] for a in actions],"converted_action_ids":changed,
            "blocked_action_ids":blocked,"deletions":[],"whole_set_status":"needs_setup","reason":"seven eMA2 actions require two reviewed prefix lists"}
    return result,report

def quoted_json(value): return "'"+canonical(value).replace("'","''")+"'"
def sql_for(result,report):
    routine="rrt_emdd_convert_"+report["before_fingerprint"][:12]
    lines=["DELIMITER //",f"CREATE PROCEDURE {routine}()", "main: BEGIN",
      "DECLARE target_id BIGINT UNSIGNED; DECLARE locked_revision BIGINT UNSIGNED; DECLARE changed_rows INT DEFAULT 0;",
      "DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; RESIGNAL; END;", "START TRANSACTION;",
      "SELECT revision INTO locked_revision FROM mitigation_presets WHERE id=1 AND name='e-manuel-apply' AND archived_at IS NULL FOR UPDATE;",
      "IF locked_revision <> 3 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='preset revision changed'; END IF;",
      "SELECT id INTO target_id FROM reroute_templates WHERE name='bgp_export_policy_set' AND enabled=1;",
      "IF target_id IS NULL OR (SELECT COUNT(*) FROM reroute_templates) <> 19 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='post-migration template catalog invalid'; END IF;",
      "IF (SELECT COUNT(*) FROM mitigation_preset_actions WHERE preset_id=1) <> 16 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='action count changed'; END IF;",
      "IF (SELECT COUNT(*) FROM reroute_bundles WHERE state IN ('planned','running','compensating') OR remaining_mutations>0) <> 0 OR (SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL) <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='active run or lock present'; END IF;"]
    old={a["id"]:a for a in report["before_actions"]}
    for action in result["actions"]:
        prior=old[action["id"]]; prior_json=quoted_json(prior["params"])
        predicate=f"id={action['id']} AND preset_id=1 AND position={action['position']} AND enabled=1 AND reroute_template_id={prior['reroute_template_id']} AND JSON_CONTAINS(params_json,{prior_json}) AND JSON_CONTAINS({prior_json},params_json)"
        lines.append(f"IF (SELECT COUNT(*) FROM mitigation_preset_actions WHERE {predicate}) <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='action {action['id']} fingerprint changed'; END IF;")
        if action["id"] in report["converted_action_ids"]:
            lines.append(f"UPDATE mitigation_preset_actions SET reroute_template_id=target_id,params_json={quoted_json(action['params'])} WHERE {predicate}; SET changed_rows=changed_rows+ROW_COUNT();")
    audit={**report,"resolved_target_template_id":None}; description=result["preset"]["description"].replace("'","''")
    lines += ["IF changed_rows <> 14 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='conversion row count mismatch'; END IF;",
      f"UPDATE mitigation_presets SET revision=4 WHERE id=1 AND revision=3 AND description='{description}';",
      "IF ROW_COUNT() <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='preset CAS failed'; END IF;",
      f"INSERT INTO audit_logs(actor_type,event_type,entity_type,entity_id,message) VALUES('system','emdd_preset_converted','mitigation_preset',1,JSON_SET({quoted_json(audit)},'$.resolved_target_template_id',target_id));",
      "COMMIT;", "END//", "DELIMITER ;", f"CALL {routine}();", f"DROP PROCEDURE {routine};"]
    return "\n".join(lines)+"\n"

def main():
    p=argparse.ArgumentParser(); p.add_argument("snapshot",type=pathlib.Path); p.add_argument("--report",type=pathlib.Path,required=True); p.add_argument("--apply-output",type=pathlib.Path)
    a=p.parse_args(); source=json.loads(a.snapshot.read_text()); result,report=convert(source)
    a.report.write_text(json.dumps({"report":report,"prior":source,"converted":result},indent=2,sort_keys=True)+"\n")
    if a.apply_output: a.apply_output.write_text(sql_for(result,report))
    print(canonical({key:value for key,value in report.items() if key!="before_actions"}))
if __name__=="__main__":
    try: main()
    except (ValueError,KeyError,json.JSONDecodeError) as error: print(f"refused: {error}",file=sys.stderr); sys.exit(2)
