#!/usr/bin/env python3
import importlib.util,json,pathlib,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location("retune",ROOT/"retune-sample-counts.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)

def snapshot():
 return {"captured_at":"2026-09-20T10:00:00Z","metrics_rollup_seconds":10,
  "settings":{"operating_mode":"observe","automatic_actions_enabled":False},"owned_run_rule_ids":[],
  "devices":[{"id":1,"poll_interval_seconds":30},{"id":2,"poll_interval_seconds":20}],
  "interfaces":[{"id":11,"device_id":1},{"id":22,"device_id":2}],
  "rules":[
   {"id":1,"metric":"rx_bps","interface_id":11,"metric_aggregation":"single","member_interface_ids":[],"consecutive_samples":4,"recovery_mode":"auto","recovery_consecutive_samples":2,"duration_seconds":90,"recovery_window_seconds":40,"threshold_value":100,"recovery_threshold_value":None,"current_state":"clear","automatic_reroute_enabled":False,"automatic_revert_enabled":False},
   {"id":2,"metric":"tx_bps","metric_aggregation":"sum","member_interface_ids":[11,22],"consecutive_samples":3,"recovery_mode":"threshold","recovery_consecutive_samples":1,"duration_seconds":70,"recovery_window_seconds":20,"threshold_value":200,"recovery_threshold_value":150,"current_state":"clear","automatic_reroute_enabled":False,"automatic_revert_enabled":False},
   {"id":3,"metric":"flow_bytes","interface_id":11,"metric_aggregation":"single","member_interface_ids":[],"consecutive_samples":0,"recovery_mode":"manual","recovery_consecutive_samples":0,"duration_seconds":60,"recovery_window_seconds":30,"threshold_value":9,"recovery_threshold_value":None,"current_state":"clear","automatic_reroute_enabled":False,"automatic_revert_enabled":False}]}

class RetuneTest(unittest.TestCase):
 def test_worked_single_aggregate_flow_and_order(self):
  report=M.plan(snapshot(),{1:10})
  self.assertEqual("2026-09-20T10:00:00Z",report["captured_at"])
  by={r["rule_id"]:r for r in report["before_after"]}
  self.assertEqual((4,12),(by[1]["before_consecutive_samples"],by[1]["after_consecutive_samples"]))
  self.assertGreaterEqual(by[1]["nominal_fire_sample_budget_after"],by[1]["nominal_fire_sample_budget_before"])
  self.assertEqual(90,by[1]["estimated_fire_lower_bound_before"])
  self.assertEqual(110,by[1]["estimated_fire_lower_bound_after"])
  self.assertEqual(30,by[1]["estimated_recovery_lower_bound_before"])
  self.assertEqual(50,by[1]["estimated_recovery_lower_bound_after"])
  self.assertEqual(30,by[2]["old_cadence_seconds"]); self.assertEqual(20,by[2]["new_cadence_seconds"])
  self.assertEqual(5,by[2]["after_consecutive_samples"])
  self.assertEqual(0,by[3]["after_consecutive_samples"])
  self.assertEqual(100,by[1]["resolved_recovery_threshold_value"])
  self.assertEqual(["/api/rules/1","/api/rules/2","/api/devices/1"],[r["path"] for r in report["apply_requests"]])
  self.assertTrue(all(r["method"]=="PUT" for r in report["apply_requests"]+report["rollback_requests"]))
  self.assertEqual("/api/devices/1",report["rollback_requests"][0]["path"])
  for key in ("duration_seconds","recovery_window_seconds","threshold_value","recovery_threshold_value"):
   self.assertEqual(snapshot()["rules"][0][key],by[1][key])
  data=snapshot(); data["rules"][0]["recovery_consecutive_samples"]=None
  fallback=M.plan(data,{1:10}); row=fallback["before_after"][0]
  self.assertEqual((4,12),(row["resolved_recovery_samples_before"],row["resolved_recovery_samples_after"]))
  self.assertNotIn("recovery_consecutive_samples",fallback["apply_requests"][0]["body"])
 def test_member_change_and_blockers_fail_closed(self):
  data=snapshot(); data["rules"][1]["member_interface_ids"]=[22]
  self.assertFalse(M.plan(data,{1:10})["before_after"][1]["changed"])
  data=snapshot(); data["rules"][0]["current_state"]="firing"; data["rules"][0]["automatic_reroute_enabled"]=True; data["owned_run_rule_ids"]=[1]
  report=M.plan(data,{1:10}); self.assertEqual([],report["apply_requests"]); self.assertEqual(3,len([b for b in report["blockers"] if "rule 1" in b]))
 def test_ambiguity_and_candidate_validation(self):
  data=snapshot(); data["rules"][0]["interface_id"]=999
  with self.assertRaises(ValueError): M.plan(data,{1:10})
  with self.assertRaises(ValueError): M.plan(snapshot(),{1:4})
  with self.assertRaises(ValueError): M.plan(snapshot(),{1:30})
  with self.assertRaises(ValueError): M.parse_candidates(["1=10","1=5"])
  data=snapshot(); data["owned_run_rule_ids"]=["1"]
  with self.assertRaises(ValueError): M.plan(data,{1:10})
  data=snapshot(); data["owned_run_rule_ids"]=[999]
  with self.assertRaises(ValueError): M.plan(data,{1:10})
  data=snapshot(); data["rules"][1]["member_interface_ids"]=[]; data["rules"][1]["interface_id"]=11
  with self.assertRaises(ValueError): M.plan(data,{1:10})
  self.assertEqual(M.MAX_COUNT,M._scaled(M.MAX_COUNT,M.MAX_COUNT,M.MAX_COUNT))
  owned_sql=M.CAPTURE_QUERIES["owned_runs"].upper()
  self.assertIn("ROLLBACK_OF_REROUTE_ID IS NULL",owned_sql); self.assertIn("NOT EXISTS",owned_sql)
 def test_readonly_capture_uses_only_select_and_sanitizes(self):
  rows={
   "devices":[{"id":"1","poll_interval_seconds":"30"}],"interfaces":[{"id":"11","device_id":"1"}],
   "rules":[{"id":"1","metric":"rx_bps","interface_id":"11","metric_aggregation":"single","consecutive_samples":"2","recovery_mode":"auto","recovery_consecutive_samples":"NULL","duration_seconds":"60","recovery_window_seconds":"NULL","threshold_value":"10","recovery_threshold_value":"NULL","current_state":"clear","automatic_reroute_enabled":"0","automatic_revert_enabled":"0"}],
   "members":[],"settings":[{"key":"operating_mode","value":"observe"},{"key":"automatic_actions_enabled","value":"0"}],"owned_runs":[]}
  seen=[]
  def runner(url,query):
   self.assertEqual("mysql://readonly.invalid/rerouter_test_unit",url); self.assertTrue(query.startswith("SELECT ")); seen.append(query)
   name=next(k for k,v in M.CAPTURE_QUERIES.items() if v==query); return rows[name]
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/"url"; p.write_text("mysql://readonly.invalid/rerouter_test_unit")
   out=M.capture_readonly(p,10,runner)
  self.assertEqual(len(M.CAPTURE_QUERIES),len(seen)); self.assertNotIn("url",json.dumps(out)); self.assertEqual(10,out["metrics_rollup_seconds"])
  self.assertIsNone(out["rules"][0]["recovery_consecutive_samples"])
 def test_mysql_cli_uses_no_defaults_decoded_secret_and_socket(self):
  completed=mock.Mock(stdout="id\tvalue\n1\tNULL\n")
  with mock.patch.object(M.subprocess,"run",return_value=completed) as run:
   M.default_query_runner("mysql://u%40x:p%2Fq@localhost/rerouter_test_unit?socket=%2Ftmp%2Fdb.sock","SELECT 1")
  cmd=run.call_args.args[0]; env=run.call_args.kwargs["env"]
  self.assertEqual(["mysql","--no-defaults"],cmd[:2]); self.assertIn("--socket",cmd)
  self.assertNotIn("-h",cmd); self.assertEqual("p/q",env["MYSQL_PWD"]); self.assertNotIn("p/q"," ".join(cmd))
  self.assertNotIn("DATABASE_URL",env)
  with self.assertRaises(ValueError): M.default_query_runner("mysql://root:x@localhost/rerouter_test_unit","SELECT 1")
  with self.assertRaises(ValueError): M.default_query_runner("mysql://u:x@localhost/other_project","SELECT 1")
if __name__=="__main__": unittest.main()
