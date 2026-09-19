#!/usr/bin/env python3
"""Load/capture/verify the real schema-67 upgrade fixture through a private URL."""
import argparse,hashlib,json,os,pathlib,subprocess,urllib.parse
ROOT=pathlib.Path(__file__).parent; RAW=json.loads((ROOT/"fixtures/emdd-app-before.json").read_text())
def q(v): return "'"+str(v).replace("'","''")+"'"
class Client:
 def __init__(self,url_file):
  p=urllib.parse.urlparse(pathlib.Path(url_file).read_text().strip()); self.db=urllib.parse.unquote(p.path.lstrip('/')); self.user=urllib.parse.unquote(p.username or '')
  assert self.db.startswith('rerouter_test_') and 'test' in self.user and self.user!='root'
  assert p.hostname in ('127.0.0.1','localhost'); assert p.port in (None,13379,3306)
  exe='mysql' if p.port==13379 else 'mariadb'; self.cmd=[exe,'-h',p.hostname,'-u',self.user,'--batch','--skip-column-names']
  if p.port: self.cmd += ['-P',str(p.port)]
  socket=urllib.parse.parse_qs(p.query).get('socket',[None])[0]
  if socket: self.cmd += ['--socket',socket]
  self.cmd.append(self.db)
  self.env={**os.environ,'MYSQL_PWD':urllib.parse.unquote(p.password or '')}; self.env.pop('DATABASE_URL',None)
 def run(self,sql):
  r=subprocess.run(self.cmd,input=sql,text=True,capture_output=True,env=self.env)
  if r.returncode: raise RuntimeError(r.stderr.strip())
  return r.stdout
def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'))
def load(c):
 empty=json.loads(c.run("SELECT JSON_OBJECT('users',(SELECT COUNT(*) FROM users),'devices',(SELECT COUNT(*) FROM devices),'rules',(SELECT COUNT(*) FROM rules),'presets',(SELECT COUNT(*) FROM mitigation_presets),'actions',(SELECT COUNT(*) FROM mitigation_preset_actions),'sessions',(SELECT COUNT(*) FROM sessions));").strip())
 if any(empty.values()): raise RuntimeError(f"fixture schema is not empty: {empty}")
 sql=["START TRANSACTION;","INSERT INTO users(id,name,email,password,two_factor_confirmed_at) VALUES(1,'Upgrade fixture','upgrade-fixture@example.test','unused',UTC_TIMESTAMP());",
      "INSERT INTO role_user(role_id,user_id) SELECT id,1 FROM roles WHERE name='superadmin';",
      "INSERT INTO sessions(id,token_hash,user_id,ip_address,user_agent,totp_verified,last_activity_at,expires_at) VALUES(1,REPEAT('a',64),1,'192.0.2.100','upgrade-fixture',1,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 7 DAY);",
      "INSERT INTO devices(id,name,hostname,enabled,ssh_username,ssh_auth_method) VALUES(1,'eMA2','192.0.2.12',1,NULL,NULL),(2,'eMA1','192.0.2.11',1,NULL,NULL),(3,'eMA3','192.0.2.13',1,NULL,NULL);",
      f"INSERT INTO mitigation_presets(id,name,description,revision,created_by,updated_by) VALUES(1,'e-manuel-apply',{q(RAW['preset']['description'])},3,1,1),(2,'unrelated-preserved','must survive conversion',1,1,1);"]
 for a in RAW['actions']: sql.append(f"INSERT INTO mitigation_preset_actions(id,preset_id,reroute_template_id,device_id,params_json,enabled,position) VALUES({a['id']},1,{a['reroute_template_id']},{a['device_id']},{q(canonical(a['params']))},{a['enabled']},{a['position']});")
 ids=[1,4,5,6,7,9,10,11,12,13,14,15,16]
 for index,rid in enumerate(ids):
  recovery=('manual' if rid in (6,10) else 'threshold' if rid in (9,14) else 'auto'); threshold=1000+index*111; enabled=0 if rid==1 else 1; auto=1 if rid in (4,11) else 0; manual=1 if rid in (5,7,9) else 0
  sql.append(f"INSERT INTO rules(id,device_id,name,metric,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_threshold_value,recovery_window_seconds,recovery_consecutive_samples,severity,enabled,automatic_reroute_enabled,manual_apply_enabled,actions_revision) VALUES({rid},{1 if index%2==0 else 2},'fixture-rule-{rid}','rx_bps','>',{threshold},30,3,'{recovery}',{threshold/2 if recovery=='threshold' else 'NULL'},{60 if recovery=='threshold' else 'NULL'},{2 if recovery=='threshold' else 'NULL'},'warning',{enabled},{auto},{manual},1);")
  state='firing' if rid in (4,5,7) else 'matching' if rid==9 else 'clear'; sql.append(f"INSERT INTO rule_states(rule_id,current_state,consecutive_match_count,last_metric_value,last_evaluated_at) VALUES({rid},'{state}',{2 if state=='matching' else 3 if state=='firing' else 0},{threshold+10},UTC_TIMESTAMP());")
 sql += ["INSERT INTO audit_logs(actor_type,event_type,entity_type,message) VALUES('system','unknown_fixture_event','fixture','must survive conversion');","COMMIT;"]
 c.run('\n'.join(sql))
def snapshot(c):
 queries={
  'migrations':"SELECT version,HEX(checksum),success FROM _sqlx_migrations ORDER BY version",
  'templates':"SELECT id,name,enabled,automatic_allowed,parameter_schema_json,plan_json,verification_json,rollback_template_id FROM reroute_templates ORDER BY id",
  'rules':"SELECT r.id,r.name,r.device_id,r.interface_id,r.metric,r.metric_aggregation,r.flow_direction,r.flow_protocol,r.flow_port,r.flow_port_kind,r.operator,r.threshold_value,r.duration_seconds,r.consecutive_samples,r.recovery_mode,r.recovery_threshold_value,r.recovery_window_seconds,r.recovery_consecutive_samples,r.severity,r.enabled,r.automatic_reroute_enabled,r.manual_apply_enabled,r.reroute_template_id,r.actions_revision,rs.current_state,rs.consecutive_match_count,rs.last_metric_value FROM rules r LEFT JOIN rule_states rs ON rs.rule_id=r.id ORDER BY r.id",
  'sessions':"SELECT id,token_hash,user_id,ip_address,user_agent,totp_verified,last_activity_at,expires_at FROM sessions ORDER BY id",
  'devices':"SELECT id,name,hostname,ssh_username,ssh_auth_method,ssh_password_encrypted,ssh_private_key_encrypted FROM devices ORDER BY id",
  'presets':"SELECT id,name,description,revision,archived_at FROM mitigation_presets ORDER BY id",
  'actions':"SELECT id,preset_id,reroute_template_id,device_id,CAST(params_json AS CHAR),enabled,position FROM mitigation_preset_actions ORDER BY id",
  'counts':"SELECT (SELECT COUNT(*) FROM reroutes),(SELECT COUNT(*) FROM locks),(SELECT COUNT(*) FROM audit_logs WHERE event_type='unknown_fixture_event')"}
 return {name:c.run(query).splitlines() for name,query in queries.items()}
def main():
 p=argparse.ArgumentParser(); p.add_argument('--url-file',required=True); p.add_argument('--evidence',type=pathlib.Path,required=True); p.add_argument('command',choices=['load','capture'])
 a=p.parse_args(); c=Client(a.url_file)
 if a.command=='load': load(c)
 data=snapshot(c); a.evidence.parent.mkdir(parents=True,exist_ok=True); a.evidence.write_text(json.dumps({'database':c.db,'user':c.user,'snapshot':data,'sha256':hashlib.sha256(canonical(data).encode()).hexdigest()},indent=2,sort_keys=True)+'\n')
 print(json.dumps({'database':c.db,'rows':{k:len(v) for k,v in data.items()},'sha256':hashlib.sha256(canonical(data).encode()).hexdigest()},sort_keys=True))
if __name__=='__main__': main()
