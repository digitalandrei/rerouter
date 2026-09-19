#!/usr/bin/env python3
import copy
import importlib.util
import json
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("ema3_prepare", ROOT / "prepare-ema3-test-preset.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
SNAPSHOT = pathlib.Path(os.environ.get("EMA3_PRESET_SNAPSHOT", ROOT / "fixtures/ema3-preset-before.json"))
RAW = json.loads(SNAPSHOT.read_text())


class Ema3PresetPreparationTest(unittest.TestCase):
    def test_derives_only_the_eight_reviewed_actions(self):
        original = copy.deepcopy(RAW)
        body, report = M.prepare(RAW)
        self.assertEqual(original, RAW)
        self.assertEqual("e-manuel-apply-ema3-test", body["name"])
        self.assertEqual({"name", "description", "actions"}, set(body))
        self.assertEqual({3}, {action["device_id"] for action in body["actions"]})
        self.assertEqual(M.EXPECTED_SOURCE_ACTION_IDS, [item["source_action_id"] for item in report["action_derivation"]])
        self.assertEqual(8, report["target"]["action_count"])

    def test_sql_is_definition_only_and_fail_closed(self):
        body, report = M.prepare(RAW)
        sql = M.sql_for(body, report)
        self.assertIn("DECLARE EXIT HANDLER FOR SQLEXCEPTION", sql)
        self.assertIn("refusing overwrite", sql)
        self.assertIn("inserted_actions <> 8", sql)
        self.assertIn("JSON_TABLE", sql)
        self.assertIn("entry_ge IS NULL", sql)
        self.assertIn("definition changed or duplicated", sql)
        self.assertIn("binding changed or duplicated", sql)
        self.assertIn("'system',NULL,'mitigation_preset_cloned'", sql)
        self.assertNotIn("INSERT INTO execution_plans", sql)
        self.assertNotIn("INSERT INTO reroutes", sql)
        self.assertNotIn("INSERT INTO locks", sql)

    def test_any_raw_snapshot_change_is_refused(self):
        changed = copy.deepcopy(RAW)
        changed[1]["value"]["enabled"] = 0
        with self.assertRaisesRegex(ValueError, "reviewed raw EMA3 snapshot"):
            M.prepare(changed)

    def test_peer_policy_drift_is_refused_after_snapshot_review(self):
        reviewed = copy.deepcopy(RAW)
        inventory = next(item["value"]["inventory"] for item in reviewed if item["kind"] == "inventory")
        inventory["peer_bindings"][0]["policy_name"] = "pfx-to-viva"
        original_fingerprint = M.SOURCE_FINGERPRINT
        try:
            M.SOURCE_FINGERPRINT = M.fingerprint(reviewed)
            with self.assertRaisesRegex(ValueError, "cached peer binding changed"):
                M.prepare(reviewed)
        finally:
            M.SOURCE_FINGERPRINT = original_fingerprint


if __name__ == "__main__":
    unittest.main()
