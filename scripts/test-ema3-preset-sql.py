#!/usr/bin/env python3
"""Exercise generated EMA3 preset SQL using session-local tables only.

Requires REROUTER_TEST_DATABASE_URL for the existing dedicated test database.
It never starts a database daemon and all fixture tables are TEMPORARY.
"""
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import urllib.parse

ROOT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("ema3_prepare", ROOT / "prepare-ema3-test-preset.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
raw = json.loads((ROOT / "fixtures/ema3-preset-before.json").read_text())
body, report = M.prepare(raw)
generated = M.sql_for(body, report)


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


ddl = """CREATE TEMPORARY TABLE mitigation_presets(id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,name VARCHAR(191) NOT NULL UNIQUE,description TEXT,revision BIGINT UNSIGNED NOT NULL DEFAULT 1,archived_at DATETIME NULL,created_by BIGINT NULL,updated_by BIGINT NULL);
CREATE TEMPORARY TABLE mitigation_preset_actions(id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,preset_id BIGINT UNSIGNED NOT NULL,reroute_template_id BIGINT UNSIGNED NOT NULL,device_id BIGINT UNSIGNED NOT NULL,params_json JSON NOT NULL,enabled TINYINT NOT NULL,position INT NOT NULL,UNIQUE KEY(preset_id,position));
CREATE TEMPORARY TABLE devices(id BIGINT UNSIGNED PRIMARY KEY,name VARCHAR(191) NOT NULL);
CREATE TEMPORARY TABLE reroute_templates(id BIGINT UNSIGNED PRIMARY KEY,name VARCHAR(191) NOT NULL,enabled TINYINT NOT NULL);
CREATE TEMPORARY TABLE routing_policy_snapshots(device_id BIGINT UNSIGNED PRIMARY KEY,inventory_json JSON NOT NULL,completeness VARCHAR(16) NOT NULL);
CREATE TEMPORARY TABLE audit_logs(id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,actor_type VARCHAR(32),actor_user_id BIGINT NULL,event_type VARCHAR(64),entity_type VARCHAR(64),entity_id BIGINT,message TEXT,before_json JSON,after_json JSON);
"""
preset = next(item["value"] for item in raw if item["kind"] == "preset")
inventory = next(item["value"] for item in raw if item["kind"] == "inventory")
setup = ddl
setup += f"INSERT INTO mitigation_presets(id,name,description,revision,archived_at) VALUES(1,{quote(preset['name'])},{quote(preset['description'])},4,NULL);\n"
for device in (item["value"] for item in raw if item["kind"] == "device"):
    setup += f"INSERT INTO devices VALUES({device['id']},{quote(device['name'])});\n"
for template in (item["value"] for item in raw if item["kind"] == "template"):
    setup += f"INSERT INTO reroute_templates VALUES({template['id']},{quote(template['name'])},{template['enabled']});\n"
for action in (item["value"] for item in raw if item["kind"] == "action"):
    setup += f"INSERT INTO mitigation_preset_actions(id,preset_id,reroute_template_id,device_id,params_json,enabled,position) VALUES({action['id']},1,{action['reroute_template_id']},{action['device_id']},{quote(M.canonical(action['params']))},{action['enabled']},{action['position']});\n"
setup += f"INSERT INTO routing_policy_snapshots VALUES(3,{quote(M.canonical(inventory['inventory']))},'complete');\n"

first_checks = """SELECT IF((SELECT COUNT(*) FROM mitigation_presets WHERE BINARY name='e-manuel-apply-ema3-test')=1,'create-ok','create-fail');
SELECT IF((SELECT COUNT(*) FROM mitigation_preset_actions WHERE preset_id<>(1))=8,'actions-ok','actions-fail');
SELECT IF((SELECT COUNT(*) FROM audit_logs WHERE event_type='mitigation_preset_cloned')=1,'audit-ok','audit-fail');
"""
repeat_checks = """SELECT IF((SELECT COUNT(*) FROM mitigation_presets WHERE BINARY name='e-manuel-apply-ema3-test')=1,'repeat-ok','repeat-fail');
SELECT IF((SELECT COUNT(*) FROM mitigation_preset_actions WHERE preset_id<>(1))=8,'repeat-actions-ok','repeat-actions-fail');
"""
reset_fixture = """DELETE FROM mitigation_preset_actions WHERE preset_id<>1;
DELETE FROM mitigation_presets WHERE id<>1;
DELETE FROM audit_logs;
UPDATE routing_policy_snapshots SET inventory_json=JSON_ARRAY_APPEND(inventory_json,'$.prefix_lists[2].entries',JSON_OBJECT('action','permit','prefix','194.105.143.0/24','sequence',7)) WHERE device_id=3;
"""
drift_checks = """SELECT IF((SELECT COUNT(*) FROM mitigation_presets WHERE BINARY name='e-manuel-apply-ema3-test')=0,'drift-ok','drift-fail');
SELECT IF((SELECT COUNT(*) FROM mitigation_preset_actions WHERE preset_id<>1)=0,'drift-actions-ok','drift-actions-fail');
SELECT IF((SELECT COUNT(*) FROM audit_logs)=0,'drift-audit-ok','drift-audit-fail');
"""
ge_drift_fixture = f"""UPDATE routing_policy_snapshots SET inventory_json={quote(M.canonical(inventory['inventory']))} WHERE device_id=3;
UPDATE routing_policy_snapshots SET inventory_json=JSON_SET(inventory_json,'$.prefix_lists[2].entries[0].ge',24) WHERE device_id=3;
"""
ge_drift_checks = """SELECT IF((SELECT COUNT(*) FROM mitigation_presets WHERE BINARY name='e-manuel-apply-ema3-test')=0,'ge-drift-ok','ge-drift-fail');
SELECT IF((SELECT COUNT(*) FROM mitigation_preset_actions WHERE preset_id<>1)=0,'ge-drift-actions-ok','ge-drift-actions-fail');
SELECT IF((SELECT COUNT(*) FROM audit_logs)=0,'ge-drift-audit-ok','ge-drift-audit-fail');
"""

url = urllib.parse.urlparse(os.environ["REROUTER_TEST_DATABASE_URL"])
query = urllib.parse.parse_qs(url.query)
socket = query.get("socket", [None])[0]
database_name = urllib.parse.unquote(url.path.lstrip("/"))
account_name = urllib.parse.unquote(url.username or "")
if not re.fullmatch(r"rerouter_test(?:_[A-Za-z0-9_]+)?", database_name) or account_name.lower() in {"", "root"}:
    raise SystemExit("refusing SQL fixture: URL must name a test schema and a non-root account")
base_command = ["mysql", "--batch", "--skip-column-names", "-u", account_name, database_name]
if socket:
    base_command.extend(["--socket", socket])
environment = {**os.environ, "MYSQL_PWD": urllib.parse.unquote(url.password or "")}
preflight = subprocess.run(base_command, input="SELECT DATABASE(),CURRENT_USER(); SHOW GRANTS;\n", text=True, capture_output=True, env=environment)
grant_lines = [line.upper() for line in preflight.stdout.splitlines() if line.upper().startswith("GRANT ")]
identity_line = preflight.stdout.splitlines()[0].split("\t") if preflight.stdout.splitlines() else []
identity_ok = len(identity_line) == 2 and identity_line[0] == database_name and identity_line[1].split("@", 1)[0] == account_name
def grant_scope_allowed(line):
    if " ON *.*" in line:
        return line.startswith("GRANT USAGE ON *.*")
    scope = re.search(r" ON [`]?([^`.*]+)[`]?\.\*", line)
    return scope is None or re.fullmatch(r"REROUTER_TEST(?:_[A-Z0-9_]+)?", scope.group(1)) is not None
if preflight.returncode != 0 or not identity_ok or not all(grant_scope_allowed(line) for line in grant_lines):
    raise SystemExit("refusing SQL fixture: connection is not the expected restricted test account/schema")
command = [base_command[0], "--force", *base_command[1:]]
run = subprocess.run(command, input=setup + generated + first_checks + generated + repeat_checks + reset_fixture + generated + drift_checks + ge_drift_fixture + generated + ge_drift_checks, text=True, capture_output=True, env=environment)
expected = ["create-ok", "actions-ok", "audit-ok", "repeat-ok", "repeat-actions-ok", "drift-ok", "drift-actions-ok", "drift-audit-ok", "ge-drift-ok", "ge-drift-actions-ok", "ge-drift-audit-ok"]
if run.stdout.split() != expected:
    raise SystemExit(f"unexpected SQL assertions: {run.stdout!r}\n{run.stderr}")
if "target preset name already exists; refusing overwrite" not in run.stderr:
    raise SystemExit("repeat execution did not refuse the existing name")
if "pfx-to-viva definition changed or duplicated" not in run.stderr:
    raise SystemExit("extra prefix-list permit was not refused")
if run.stderr.count("pfx-to-viva definition changed or duplicated") < 2:
    raise SystemExit("ge-broadened prefix-list permit was not refused")
print("generated EMA3 SQL fixture execution: ok")
