#!/usr/bin/env python3
import copy,importlib.util,json,pathlib,unittest
ROOT=pathlib.Path(__file__).parent; spec=importlib.util.spec_from_file_location("conversion",ROOT/"prepare-emdd-conversion.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
RAW=json.loads((ROOT/"fixtures/emdd-app-before.json").read_text())
class ConversionTest(unittest.TestCase):
 def test_real_snapshot_preserves_identity_scope_and_description(self):
  original=copy.deepcopy(RAW); out,report=M.convert(RAW)
  self.assertEqual(RAW,original); self.assertEqual(list(range(31,47)),report["preserved_action_ids"]); self.assertEqual(7,len(report["blocked_action_ids"])); self.assertEqual([],report["deletions"])
  self.assertEqual(original["preset"]["description"],out["preset"]["description"])
  e1=[a for a in out["actions"] if a["device_name"]=="eMA1" and a["template_name"]=="bgp_export_policy_set"]
  e2=[a for a in out["actions"] if a["device_name"]=="eMA2" and a["template_name"]=="bgp_export_policy_set"]
  self.assertEqual({"pfx-to-viva","no-export"},{a["params"]["policy_name"] for a in e1}); self.assertEqual({"rr-194105142-only","rr-colt-without-194105142"},{a["params"]["policy_name"] for a in e2})
  self.assertEqual([10,11],[out["actions"][i]["position"] for i in (10,11)]); self.assertEqual("1436",out["actions"][12]["params"]["mss"])
  sql=M.sql_for(out,report); self.assertIn("DECLARE EXIT HANDLER FOR SQLEXCEPTION",sql); self.assertIn("SELECT id INTO target_id",sql); self.assertNotIn("reroute_template_id=None",sql)
 def test_modified_snapshot_refuses(self):
  changed=copy.deepcopy(RAW); changed["actions"][0]["device_id"]=1
  with self.assertRaises(ValueError): M.convert(changed)
if __name__=="__main__": unittest.main()
