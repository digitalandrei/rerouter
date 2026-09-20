#!/usr/bin/env python3
"""Produce a fail-closed, dry-run cadence retuning report. Never writes state."""
import argparse, csv, datetime, io, json, os, pathlib, subprocess, sys
from urllib.parse import parse_qs, unquote, urlparse

MAX_COUNT = 2**32 - 1
FLOW_PREFIXES = ("flow_", "netflow_", "sflow_")
CAPTURE_QUERIES = {
    "devices": "SELECT id,poll_interval_seconds FROM devices ORDER BY id",
    "interfaces": "SELECT id,device_id FROM device_interfaces ORDER BY id",
    "rules": "SELECT r.id,r.metric,r.interface_id,r.metric_aggregation,r.consecutive_samples,r.recovery_mode,r.recovery_consecutive_samples,r.duration_seconds,r.recovery_window_seconds,r.threshold_value,r.recovery_threshold_value,COALESCE(rs.current_state,'clear') AS current_state,r.automatic_reroute_enabled,r.automatic_revert_enabled FROM rules r LEFT JOIN rule_states rs ON rs.rule_id=r.id ORDER BY r.id",
    "members": "SELECT rule_id,interface_id FROM rule_interfaces ORDER BY rule_id,interface_id",
    "settings": "SELECT `key`,`value` FROM system_settings WHERE `key` IN ('operating_mode','automatic_actions_enabled') ORDER BY `key`",
    "owned_runs": "SELECT DISTINCT COALESCE(original.rule_id,source.rule_id) AS rule_id FROM reroutes original LEFT JOIN reroute_bundles source ON source.id=original.bundle_id WHERE COALESCE(original.rule_id,source.rule_id) IS NOT NULL AND original.rollback_of_reroute_id IS NULL AND ((original.state IN ('planned','pending','running','verifying','uncertain') OR original.mutation_effect IN ('pending','unknown') OR (original.mutation_effect='changed' AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop')))) OR source.recovery_claim_token IS NOT NULL OR source.lifecycle_state IN ('recovery_scheduled','recovery_claimed','recovery_running','recovery_blocked')) ORDER BY rule_id",
}

def _require_int(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value

def _scaled(old, old_cadence, new_cadence):
    if old == 0:
        return 0
    product = old * old_cadence
    value = (product + new_cadence - 1) // new_cadence
    if value > MAX_COUNT:
        raise ValueError("scaled sample count overflows u32")
    return value

def _index(snapshot):
    required = {"devices", "interfaces", "rules", "settings", "owned_run_rule_ids", "metrics_rollup_seconds", "captured_at"}
    missing = required - snapshot.keys()
    if missing:
        raise ValueError(f"snapshot missing fields: {sorted(missing)}")
    devices = {}
    for row in snapshot["devices"]:
        did = _require_int(row.get("id"), "device.id", 1)
        if did in devices: raise ValueError(f"duplicate device {did}")
        devices[did] = _require_int(row.get("poll_interval_seconds"), "poll interval", 5)
    interfaces = {}
    for row in snapshot["interfaces"]:
        iid = _require_int(row.get("id"), "interface.id", 1)
        did = _require_int(row.get("device_id"), "interface.device_id", 1)
        if iid in interfaces or did not in devices: raise ValueError(f"invalid interface {iid}")
        interfaces[iid] = did
    return devices, interfaces

def plan(snapshot, candidates):
    devices, interfaces = _index(snapshot)
    if not isinstance(snapshot["captured_at"],str) or not snapshot["captured_at"].strip(): raise ValueError("captured_at missing")
    rollup = _require_int(snapshot["metrics_rollup_seconds"], "metrics_rollup_seconds", 1)
    requested = {}
    for did, new in candidates.items():
        did, new = _require_int(did, "candidate device", 1), _require_int(new, "candidate interval", 5)
        if did not in devices: raise ValueError(f"candidate device {did} is missing")
        if new >= devices[did]: raise ValueError(f"device {did} candidate must be faster than {devices[did]}")
        requested[did] = new
    settings = snapshot["settings"]
    blockers = []
    if settings.get("operating_mode") != "observe": blockers.append("operating_mode must be observe")
    if settings.get("automatic_actions_enabled") not in (False, 0, "0", "false"):
        blockers.append("automatic action master switch must be off")
    owned_rows = snapshot.get("owned_run_rule_ids", [])
    if not isinstance(owned_rows, list): raise ValueError("owned_run_rule_ids must be a list")
    owned = set()
    for value in owned_rows:
        rid = _require_int(value, "owned run rule id", 1)
        if rid in owned: raise ValueError(f"duplicate owned run rule id {rid}")
        owned.add(rid)
    table, rule_requests = [], []
    seen_rules=set()
    for rule in sorted(snapshot["rules"], key=lambda r: r.get("id", 0)):
        rid = _require_int(rule.get("id"), "rule.id", 1)
        if rid in seen_rules: raise ValueError(f"duplicate rule {rid}")
        seen_rules.add(rid)
        metric = rule.get("metric")
        if not isinstance(metric, str) or not metric: raise ValueError(f"rule {rid} metric missing")
        required={"metric_aggregation","consecutive_samples","recovery_mode","recovery_consecutive_samples","duration_seconds","recovery_window_seconds","threshold_value","recovery_threshold_value","current_state","automatic_reroute_enabled","automatic_revert_enabled"}
        missing=required-rule.keys()
        if missing: raise ValueError(f"rule {rid} missing fields: {sorted(missing)}")
        _require_int(rule["duration_seconds"],f"rule {rid} duration_seconds")
        if rule["recovery_window_seconds"] is not None: _require_int(rule["recovery_window_seconds"],f"rule {rid} recovery_window_seconds")
        if isinstance(rule["threshold_value"],bool) or not isinstance(rule["threshold_value"],(int,float)): raise ValueError(f"rule {rid} threshold invalid")
        if rule["recovery_threshold_value"] is not None and (isinstance(rule["recovery_threshold_value"],bool) or not isinstance(rule["recovery_threshold_value"],(int,float))): raise ValueError(f"rule {rid} recovery threshold invalid")
        aggregation = rule.get("metric_aggregation", "single")
        if aggregation not in ("single","sum"): raise ValueError(f"rule {rid} aggregation is unsupported")
        raw_members = rule.get("member_interface_ids")
        if aggregation == "sum":
            if not isinstance(raw_members, list) or not raw_members: raise ValueError(f"aggregate rule {rid} requires explicit members")
            members = raw_members
        else:
            members = raw_members or ([rule["interface_id"]] if rule.get("interface_id") else [])
        if not members: raise ValueError(f"rule {rid} has no interface membership")
        if len(set(members)) != len(members): raise ValueError(f"rule {rid} has duplicate members")
        member_devices = []
        for iid in members:
            if iid not in interfaces: raise ValueError(f"rule {rid} member interface {iid} missing")
            member_devices.append(interfaces[iid])
        affected = any(d in requested for d in member_devices)
        old_cadence = max([devices[d] for d in member_devices] + ([rollup] if aggregation == "sum" else []))
        new_cadence = max([requested.get(d, devices[d]) for d in member_devices] + ([rollup] if aggregation == "sum" else []))
        old_fire = _require_int(rule.get("consecutive_samples", 0), f"rule {rid} consecutive_samples")
        stored_recovery = rule.get("recovery_consecutive_samples")
        recovery_mode=rule["recovery_mode"]
        if recovery_mode not in ("auto","threshold","manual"): raise ValueError(f"rule {rid} recovery_mode invalid")
        recovery_active = recovery_mode != "manual"
        old_recovery = old_fire if stored_recovery is None else _require_int(stored_recovery, f"rule {rid} recovery_consecutive_samples")
        flow = metric.startswith(FLOW_PREFIXES)
        new_fire = old_fire if flow or not affected else _scaled(old_fire, old_cadence, new_cadence)
        resolved_new_recovery = old_recovery if flow or not affected or not recovery_active else _scaled(old_recovery, old_cadence, new_cadence)
        new_recovery = stored_recovery if not recovery_active else (None if stored_recovery is None else resolved_new_recovery)
        recovery_threshold = rule.get("recovery_threshold_value")
        resolved_recovery = rule.get("threshold_value") if recovery_threshold is None else recovery_threshold
        if affected:
            if rule.get("current_state") != "clear": blockers.append(f"rule {rid} must be clear")
            if rid in owned or rule.get("owned_run_active"): blockers.append(f"rule {rid} has owned active work")
            if rule.get("automatic_reroute_enabled") not in (False, 0, None) or rule.get("automatic_revert_enabled") not in (False,0,None): blockers.append(f"rule {rid} automatic execution must be disarmed")
        fire_sample_before = old_fire * old_cadence
        fire_sample_after = new_fire * new_cadence
        recovery_sample_before = old_recovery * old_cadence
        recovery_sample_after = resolved_new_recovery * new_cadence
        fire_lower_before = max(rule["duration_seconds"], max(0, old_fire - 1) * old_cadence)
        fire_lower_after = max(rule["duration_seconds"], max(0, new_fire - 1) * new_cadence)
        if flow:
            recovery_duration = rule["recovery_window_seconds"] if recovery_mode == "threshold" and rule["recovery_window_seconds"] is not None else rule["duration_seconds"]
            recovery_lower_before = recovery_lower_after = recovery_duration
        else:
            # SNMP recovery is count-driven; the engine treats zero as one.
            recovery_lower_before = max(0, max(1, old_recovery) - 1) * old_cadence
            recovery_lower_after = max(0, max(1, resolved_new_recovery) - 1) * new_cadence
        row = {
            "rule_id": rid, "metric": metric, "aggregation": aggregation,
            "member_interface_ids": members, "old_cadence_seconds": old_cadence,
            "new_cadence_seconds": new_cadence, "before_consecutive_samples": old_fire,
            "after_consecutive_samples": new_fire, "before_recovery_consecutive_samples": stored_recovery,
            "after_recovery_consecutive_samples": new_recovery,"resolved_recovery_samples_before":old_recovery,
            "resolved_recovery_samples_after":resolved_new_recovery,
            "nominal_fire_sample_budget_before": fire_sample_before,
            "nominal_fire_sample_budget_after": fire_sample_after,
            "nominal_recovery_sample_budget_before": recovery_sample_before,
            "nominal_recovery_sample_budget_after": recovery_sample_after,
            "estimated_fire_lower_bound_before": fire_lower_before,
            "estimated_fire_lower_bound_after": fire_lower_after,
            "estimated_recovery_lower_bound_before": recovery_lower_before,
            "estimated_recovery_lower_bound_after": recovery_lower_after,
            "duration_seconds": rule.get("duration_seconds"),
            "recovery_mode": recovery_mode,
            "recovery_window_seconds": rule.get("recovery_window_seconds"),
            "threshold_value": rule.get("threshold_value"),
            "recovery_threshold_value": recovery_threshold,
            "resolved_recovery_threshold_value": resolved_recovery,
            "changed": new_fire != old_fire or new_recovery != stored_recovery,
        }
        table.append(row)
        if row["changed"]:
            body={"consecutive_samples":new_fire}
            if stored_recovery is not None: body["recovery_consecutive_samples"]=new_recovery
            rule_requests.append({"method":"PUT","path":f"/api/rules/{rid}","body":body})
    unknown_owned = owned - seen_rules
    if unknown_owned: raise ValueError(f"owned run rule ids missing from rules: {sorted(unknown_owned)}")
    device_requests = [{"method":"PUT","path":f"/api/devices/{did}","body":{"poll_interval_seconds":requested[did]}} for did in sorted(requested)]
    rollback_rules=[]
    for request in reversed(rule_requests):
        row=next(x for x in table if x["rule_id"]==int(request["path"].split('/')[-1]))
        body={"consecutive_samples":row["before_consecutive_samples"]}
        if row["before_recovery_consecutive_samples"] is not None: body["recovery_consecutive_samples"]=row["before_recovery_consecutive_samples"]
        rollback_rules.append({**request,"body":body})
    rollback_devices = [{"method":"PUT","path":f"/api/devices/{did}","body":{"poll_interval_seconds":devices[did]}} for did in sorted(requested, reverse=True)]
    return {"schema":1,"dry_run":True,"captured_at":snapshot["captured_at"],"before_after":table,
            "blockers":sorted(set(blockers)),"apply_requests":[] if blockers else rule_requests + device_requests,
            "rollback_requests":[] if blockers else rollback_devices + rollback_rules,"automatic_rearm_requests":[]}

def default_query_runner(url, query):
    parsed = urlparse(url)
    database=unquote(parsed.path.strip('/'))
    username=unquote(parsed.username or "")
    if parsed.scheme not in ("mysql", "mariadb") or not parsed.hostname or not database:
        raise ValueError("URL file must contain one mysql:// or mariadb:// URL")
    if username.lower() == "root" or not (database == "rerouter" or database.startswith("rerouter_test_")):
        raise ValueError("capture is restricted to a non-root Rerouter database account")
    env = os.environ.copy(); env.pop("DATABASE_URL",None); env["MYSQL_PWD"] = unquote(parsed.password or "")
    cmd = ["mysql", "--no-defaults", "--batch", "--raw"]
    socket = parse_qs(parsed.query).get("socket", [None])[0]
    if socket: cmd += ["--socket", unquote(socket)]
    else: cmd += ["-h", parsed.hostname, "-P", str(parsed.port or 3306)]
    cmd += ["-u", username, database, "-e", query]
    result = subprocess.run(cmd, text=True, capture_output=True, env=env, check=True)
    return list(csv.DictReader(io.StringIO(result.stdout), delimiter="\t"))

def capture_readonly(url_file, metrics_rollup_seconds, runner=default_query_runner):
    url = pathlib.Path(url_file).read_text().strip()
    captured = {}
    for name, query in CAPTURE_QUERIES.items():
        if not query.lstrip().upper().startswith("SELECT "): raise AssertionError("non-read-only capture query")
        captured[name] = runner(url, query)
    def nullable(value): return None if value in (None,"","NULL") else value
    members = {}
    for row in captured["members"]: members.setdefault(int(row["rule_id"]), []).append(int(row["interface_id"]))
    owned = [int(row["rule_id"]) for row in captured["owned_runs"]]
    settings = {row["key"]: row["value"] for row in captured["settings"]}
    rules=[]
    for row in captured["rules"]:
        rid=int(row["id"]); rules.append({
            "id":rid,"metric":row["metric"],"interface_id":int(nullable(row.get("interface_id"))) if nullable(row.get("interface_id")) is not None else None,
            "metric_aggregation":row.get("metric_aggregation") or ("sum" if rid in members else "single"),
            "member_interface_ids":members.get(rid,[]),"consecutive_samples":int(row["consecutive_samples"]),
            "recovery_mode":row["recovery_mode"],"recovery_consecutive_samples":None if nullable(row.get("recovery_consecutive_samples")) is None else int(row["recovery_consecutive_samples"]),"duration_seconds":int(row["duration_seconds"]),
            "recovery_window_seconds":None if nullable(row.get("recovery_window_seconds")) is None else int(row["recovery_window_seconds"]),"threshold_value":float(row["threshold_value"]),
            "recovery_threshold_value":None if nullable(row.get("recovery_threshold_value")) is None else float(row["recovery_threshold_value"]),
            "current_state":row["current_state"],"automatic_reroute_enabled":row["automatic_reroute_enabled"] in ("1",1,True),
            "automatic_revert_enabled":row["automatic_revert_enabled"] in ("1",1,True),"owned_run_active":rid in owned})
    return {"captured_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "devices":[{"id":int(r["id"]),"poll_interval_seconds":int(r["poll_interval_seconds"])} for r in captured["devices"]],
            "interfaces":[{"id":int(r["id"]),"device_id":int(r["device_id"])} for r in captured["interfaces"]],
            "rules":rules,"settings":settings,"owned_run_rule_ids":owned,
            "metrics_rollup_seconds":_require_int(metrics_rollup_seconds,"metrics rollup",1)}

def parse_candidates(items):
    result={}
    for item in items:
        if item.count("=") != 1: raise ValueError(f"invalid candidate {item!r}")
        key,value=item.split("=",1); did=int(key); seconds=int(value)
        if did in result: raise ValueError(f"duplicate candidate device {did}")
        result[did]=seconds
    return result

def main():
    p=argparse.ArgumentParser(); p.add_argument("snapshot", nargs="?", type=pathlib.Path)
    p.add_argument("--poll-interval", action="append", default=[], metavar="DEVICE=SECONDS")
    p.add_argument("--output", type=pathlib.Path); p.add_argument("--db-url-file", type=pathlib.Path)
    p.add_argument("--metrics-rollup-seconds", type=int)
    args=p.parse_args()
    if args.db_url_file:
        if args.metrics_rollup_seconds is None: p.error("--metrics-rollup-seconds is required with --db-url-file")
        print(json.dumps(capture_readonly(args.db_url_file,args.metrics_rollup_seconds), indent=2, sort_keys=True)); return
    if not args.snapshot: p.error("snapshot is required unless --db-url-file is used")
    candidates=parse_candidates(args.poll_interval)
    report=plan(json.loads(args.snapshot.read_text()), candidates)
    text=json.dumps(report,indent=2,sort_keys=True)+"\n"
    if args.output: args.output.write_text(text)
    else: print(text,end="")
if __name__ == "__main__":
    try: main()
    except (ValueError,KeyError,json.JSONDecodeError,subprocess.SubprocessError) as error:
        print(f"refused: {error}",file=sys.stderr); sys.exit(2)
