#!/usr/bin/env python3
import importlib.util,json,pathlib,subprocess,tarfile,tempfile,unittest
ROOT=pathlib.Path(__file__).parent; spec=importlib.util.spec_from_file_location("release",ROOT/"prepare-hardening-release.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
class ReleaseTest(unittest.TestCase):
 def snap(self):
  return {name:[] for name in M.REQUIRED_SECTIONS}
 def test_manifest_is_dynamic_and_includes_dirty_source(self):
  with tempfile.TemporaryDirectory() as td:
   repo=pathlib.Path(td)/"repo"; repo.mkdir(); subprocess.run(["git","init","-q"],cwd=repo,check=True)
   subprocess.run(["git","config","user.email","test@example.invalid"],cwd=repo,check=True); subprocess.run(["git","config","user.name","test"],cwd=repo,check=True)
   (repo/"backend-rust/migrations").mkdir(parents=True); (repo/"backend-rust/migrations/1.sql").write_text("SELECT 1;\n"); (repo/"source.txt").write_text("a"); (repo/".gitignore").write_text("secret.env\n"); (repo/"secret.env").write_text("SECRET=x")
   subprocess.run(["git","add","."],cwd=repo,check=True); subprocess.run(["git","commit","-qm","base"],cwd=repo,check=True)
   (repo/"source.txt").write_text("b"); (repo/"new.txt").write_text("new"); (repo/"controller.bin").write_bytes(b"binary"); (repo/"dist").mkdir(); (repo/"dist/index.html").write_text("ui")
   out=pathlib.Path(td)/"out"; manifest=M.prepare(repo,out,repo/"controller.bin",repo/"dist")
   self.assertEqual(1,manifest["migration_count"]); self.assertTrue((out/"dirty.patch").exists()); self.assertIn("new.txt",manifest["untracked_source_files"]); self.assertEqual([],manifest["actions_performed"]); self.assertEqual(subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,capture_output=True,check=True).stdout.strip(),manifest["source_head"])
   with tarfile.open(out/"source-package.tar.gz") as archive: names=set(archive.getnames())
   self.assertIn("source/new.txt",names); self.assertIn("source/backend-rust/migrations/1.sql",names); self.assertIn("release/candidate-safety-reference.json",names); self.assertIn("release/source-head.txt",names); self.assertIn("artifacts/controller/controller.bin",names); self.assertIn("artifacts/frontend/index.html",names); self.assertNotIn("source/secret.env",names)
   self.assertEqual("observe",manifest["candidate_safety_reference"]["operating_mode"]); self.assertFalse(manifest["candidate_safety_reference"]["automatic_actions_enabled"])
   out2=pathlib.Path(td)/"out2"; manifest2=M.prepare(repo,out2,repo/"controller.bin",repo/"dist")
   self.assertEqual(manifest["source_archive"]["sha256"],manifest2["source_archive"]["sha256"])
   with self.assertRaises(ValueError): M.prepare(repo,repo/"release-output")
 def test_comparison_allows_locks_and_explicit_repairs_only(self):
  before=self.snap(); before.update({"execution_plans":[{"id":1,"snapshot_json":"x"}],"reroutes":[{"id":2,"planned_steps_json":"x"}],"locks":[{"id":9,"cleared_at":None}],"alert_deliveries":[{"id":3,"delivery_intent_id":None,"error":"url"}]})
  after=json.loads(json.dumps(before)); after["alert_deliveries"][0].update(delivery_intent_id=7,error="redacted")
  result=M.compare_snapshots(before,after,["alert_deliveries.3.delivery_intent_id","alert_deliveries.3.error"]); self.assertEqual(1,result["ordinary_lock_count"])
  after["execution_plans"][0]["snapshot_json"]="tampered"
  with self.assertRaises(ValueError): M.compare_snapshots(before,after,[])
 def test_active_execution_rejected(self):
  before=self.snap(); before["reroute_bundles"]=[{"id":1,"state":"running"}]
  with self.assertRaises(ValueError): M.compare_snapshots(before,self.snap(),[])
 def test_frozen_recovery_claim_is_preserved_without_requiring_zero_ownership(self):
  before=self.snap(); before["reroute_bundles"]=[{"id":1,"state":"compensation_blocked","lifecycle_state":"recovery_blocked","recovery_claim_token":"held-for-reconciliation"}]
  self.assertFalse(M.compare_snapshots(before,before,[])["active_execution"])
  changed=json.loads(json.dumps(before)); changed["reroute_bundles"][0]["recovery_claim_token"]=None
  with self.assertRaises(ValueError): M.compare_snapshots(before,changed,[])
 def test_composite_membership_identity_and_missing_sections(self):
  before=self.snap(); after=self.snap()
  after["device_change_window_sources"]=[{"device_id":7,"source_bundle_id":9,"created_at":"x"}]
  result=M.compare_snapshots(before,after,["device_change_window_sources.7:9.__row__"])
  self.assertIn("device_change_window_sources.7:9.__row__",result["accepted_predicted_repairs"])
  with self.assertRaises(ValueError): M.compare_snapshots({},after,[])
 def test_preview_and_intent_repairs_are_explicit_and_evidence_stays_protected(self):
  before=self.snap(); after=self.snap()
  before["action_previews"]=[{"token_hash":"a","plan_hash":"p","used_at":None,"expires_at":"future"}]
  after["action_previews"]=[{"token_hash":"a","plan_hash":"p","used_at":None,"expires_at":"now"}]
  after["alert_delivery_intents"]=[{"id":7,"alert_id":3,"channel":"email","target_key":"recipient:1","created_at":"t","state":"retry"}]
  predicted=["action_previews.a.expires_at","alert_delivery_intents.7.__row__"]
  result=M.compare_snapshots(before,after,predicted); self.assertEqual(2,len(result["accepted_predicted_repairs"]))
  after["action_previews"][0]["plan_hash"]="tampered"
  with self.assertRaises(ValueError): M.compare_snapshots(before,after,predicted+["action_previews.a.plan_hash"])
 def test_capture_sql_is_read_only(self):
  upper=M.CAPTURE_SQL.upper(); self.assertIn("START TRANSACTION READ ONLY",upper); self.assertNotIn("UPDATE ",upper); self.assertNotIn("DELETE ",upper); self.assertNotIn("INSERT ",upper)
  self.assertNotIn("REROUTES.REROUTE_ID",upper); self.assertNotIn("LOCKS.ENTITY_TYPE",upper)
  for section in ("ACTION_PREVIEWS","ALERT_DELIVERY_INTENTS","REROUTE_BUNDLE_ACTIONS","DEVICE_CHANGE_WINDOWS","DEVICE_CHANGE_WINDOW_SOURCES","RECOVERY_ATTEMPT_SOURCES"):
   self.assertIn(section,upper)
if __name__=="__main__": unittest.main()
