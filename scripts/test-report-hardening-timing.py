#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("timing", pathlib.Path(__file__).with_name("report-hardening-timing.py"))
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)


class TimingTests(unittest.TestCase):
    def test_stages_and_bucket_width_are_independent(self):
        report = timing.summarize([json.dumps({"fields": {"event_type": "hardening_timing", "stage": "collection", "elapsed_us": 1200, "outcome": "committed"}}),
            json.dumps({"timestamp": "2026-09-20T12:01:02Z", "fields": {"event_type": "flow_bucket_committed", "bucket_ts": "2026-09-20 12:00:00 UTC", "bucket_width_seconds": 60}})])
        self.assertEqual(report["stages"]["collection"]["p95_ms"], 1.2)
        self.assertEqual(report["stages"]["router_execution"]["count"], 0)
        self.assertEqual(report["bucket_close_to_commit"]["max_ms"], 2000)

    def test_delayed_firing_cannot_hide_shorter_recovery(self):
        def replay(fire, recover):
            return [{"scenario_id": "aggregate", "rule_id": 1, "transition": name, "elapsed_seconds": at, "window_start_seconds": 0 if name == "fired" else fire} for name, at in [("fired", fire), ("recovered", recover)]]
        self.assertFalse(timing.compare_replays(replay(60, 120), replay(80, 130))["windows_preserved"])
        self.assertTrue(timing.compare_replays(replay(60, 120), replay(80, 140))["windows_preserved"])
        with self.assertRaises(ValueError):
            timing.compare_replays(replay(60, 120), replay(60, 120)[:1])
        missing = replay(60, 120)
        del missing[0]["window_start_seconds"]
        with self.assertRaises(ValueError):
            timing.compare_replays(missing, replay(60, 120))
        invalid_phase = replay(60, 120)
        invalid_phase[1]["window_start_seconds"] = 59
        with self.assertRaises(ValueError):
            timing.compare_replays(invalid_phase, replay(60, 120))


if __name__ == "__main__":
    unittest.main()
