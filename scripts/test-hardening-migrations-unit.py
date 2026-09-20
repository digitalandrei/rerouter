#!/usr/bin/env python3
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("migration_harness", ROOT / "test-hardening-migrations.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class HarnessTest(unittest.TestCase):
    def url(self, value):
        temp = tempfile.NamedTemporaryFile("w", delete=False)
        temp.write(value); temp.close()
        self.addCleanup(pathlib.Path(temp.name).unlink)
        return pathlib.Path(temp.name)

    def test_restricts_schema_mode_and_account(self):
        database, command, environment = M.connection(
            self.url("mysql://rerouter_test_user:p%2Fq@127.0.0.1/rerouter_test_task_upgrade_69"),
            "baseline69",
        )
        self.assertEqual("rerouter_test_task_upgrade_69", database)
        self.assertEqual(["mysql", "--no-defaults"], command[:2])
        self.assertEqual("p/q", environment["MYSQL_PWD"])
        self.assertNotIn("DATABASE_URL", environment)
        with self.assertRaises(ValueError):
            M.connection(self.url("mysql://root:x@127.0.0.1/rerouter_test_task_upgrade_69"), "baseline69")
        with self.assertRaises(ValueError):
            M.connection(self.url("mysql://rerouter_test_user:x@127.0.0.1/other_upgrade_69"), "baseline69")
        with self.assertRaises(ValueError):
            M.connection(self.url("mysql://rerouter_test_user:x@127.0.0.1/rerouter_test_task_fresh_x"), "baseline56")

    def test_fixtures_cover_required_evidence(self):
        common = (ROOT / "fixtures/hardening-migrations/baseline56.sql").read_text()
        modern = (ROOT / "fixtures/hardening-migrations/baseline69.sql").read_text()
        for marker in ("fixture_unattempted", "rate limited", "action_previews"):
            self.assertIn(marker, common)
        for marker in ("immutable-consumed-plan", "immutable-inverse-a", "current-child-token", "device_change_windows"):
            self.assertIn(marker, modern)

if __name__ == "__main__":
    unittest.main()
