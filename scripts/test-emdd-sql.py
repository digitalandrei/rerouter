#!/usr/bin/env python3
"""Execute generated conversion SQL against session-local fixture tables."""
import importlib.util,json,os,pathlib,subprocess,tempfile,urllib.parse
ROOT=pathlib.Path(__file__).parent; spec=importlib.util.spec_from_file_location("conversion",ROOT/"prepare-emdd-conversion.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
raw=json.loads((ROOT/"fixtures/emdd-app-before.json").read_text()); result,report=M.convert(raw); generated=M.sql_for(result,report)
ddl="""CREATE TEMPORARY TABLE mitigation_presets(id BIGINT PRIMARY KEY,name VARCHAR(191),revision BIGINT,archived_at DATETIME NULL,description TEXT);
CREATE TEMPORARY TABLE mitigation_preset_actions(id BIGINT PRIMARY KEY,preset_id BIGINT,reroute_template_id BIGINT,device_id BIGINT,params_json JSON,enabled TINYINT,position INT);
CREATE TEMPORARY TABLE reroute_templates(id BIGINT PRIMARY KEY,name VARCHAR(191) UNIQUE,enabled TINYINT);
CREATE TEMPORARY TABLE reroute_bundles(id BIGINT,state VARCHAR(32),remaining_mutations INT);
CREATE TEMPORARY TABLE locks(id BIGINT,cleared_at DATETIME NULL);
CREATE TEMPORARY TABLE audit_logs(actor_type VARCHAR(32),event_type VARCHAR(191),entity_type VARCHAR(64),entity_id BIGINT,message LONGTEXT);
"""
q=lambda value:"'"+str(value).replace("'","''")+"'"
setup=ddl+f"INSERT INTO mitigation_presets VALUES(1,'e-manuel-apply',3,NULL,{q(raw['preset']['description'])});\n"
for template in raw["templates"]: setup+=f"INSERT INTO reroute_templates VALUES({template['id']},{q(template['name'])},{template['enabled']});\n"
setup+="INSERT INTO reroute_templates VALUES(22,'bgp_export_policy_set',1);\n"
for a in raw["actions"]: setup+=f"INSERT INTO mitigation_preset_actions VALUES({a['id']},1,{a['reroute_template_id']},{a['device_id']},{q(M.canonical(a['params']))},{a['enabled']},{a['position']});\n"
checks="""SELECT IF((SELECT revision FROM mitigation_presets WHERE id=1)=4,'ok','fail');
SELECT IF((SELECT COUNT(*) FROM mitigation_preset_actions WHERE reroute_template_id=22)=14,'ok','fail');
SELECT IF((SELECT description FROM mitigation_presets WHERE id=1)='advertise prefix 194.105.142.0/24 to Akamai, remove prefix 194.105.142.0/24 from on-prem ISP and mss clamp to 1436.','ok','fail');
SELECT IF((SELECT COUNT(*) FROM audit_logs WHERE event_type='emdd_preset_converted')=1,'ok','fail');
"""
url=urllib.parse.urlparse(os.environ["REROUTER_TEST_DATABASE_URL"]); query=urllib.parse.parse_qs(url.query); socket=query.get("socket",[None])[0]
cmd=["mysql","--force","--batch","--skip-column-names","-u",urllib.parse.unquote(url.username or ""),urllib.parse.unquote(url.path.lstrip("/"))]
if socket: cmd.extend(["--socket",socket])
env={**os.environ,"MYSQL_PWD":urllib.parse.unquote(url.password or "")}; run=subprocess.run(cmd,input=setup+generated+generated+checks,text=True,capture_output=True,env=env)
if "preset revision changed" not in run.stderr: raise SystemExit("idempotent reapply did not refuse")
if run.stdout.split()!=["ok","ok","ok","ok"]: raise SystemExit("unexpected conversion assertions")
print("generated SQL fixture execution: ok")
