#!/usr/bin/env python3
"""Summarize structured timing logs and compare timestamped decision replays offline."""
import argparse
import collections
import datetime
import json
import math
import pathlib
import statistics

STAGES = ("collection", "evidence_advance", "bucket_commit", "decision_persist", "router_execution")


def summarize(lines):
    durations = collections.defaultdict(list)
    outcomes = collections.Counter()
    bucket_lag = []
    ignored = 0
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            ignored += 1
            continue
        fields = row.get("fields", row)
        if fields.get("event_type") == "hardening_timing":
            stage, elapsed = fields.get("stage"), fields.get("elapsed_us")
            if stage not in STAGES or isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
                raise ValueError("invalid timing observation")
            durations[stage].append(elapsed / 1000)
            outcomes[(stage, fields.get("outcome", "unknown"))] += 1
        elif fields.get("event_type") == "flow_bucket_committed" and row.get("timestamp"):
            committed = datetime.datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            bucket = datetime.datetime.fromisoformat(fields["bucket_ts"].replace(" UTC", "+00:00").replace("Z", "+00:00"))
            if bucket.tzinfo is None:
                bucket = bucket.replace(tzinfo=datetime.timezone.utc)
            lag = (committed - bucket).total_seconds() - fields["bucket_width_seconds"]
            bucket_lag.append(max(0, lag) * 1000)

    def distribution(values):
        if not values:
            return {"count": 0, "status": "no observations"}
        values = sorted(values)
        return {"count": len(values), "mean_ms": statistics.fmean(values),
                "p50_ms": values[math.ceil(len(values) * .5) - 1],
                "p95_ms": values[math.ceil(len(values) * .95) - 1], "max_ms": values[-1]}
    return {"stages": {stage: {**distribution(durations[stage]),
             "outcomes": {outcome: count for (s, outcome), count in outcomes.items() if s == stage}}
             for stage in STAGES}, "bucket_close_to_commit": distribution(bucket_lag),
             "ignored_non_json_lines": ignored}


def compare_replays(before, after):
    """Inputs are recorded transitions from the real rule engine, not simulated counts.

    Each row names scenario_id, rule_id, transition (fired/recovered), and seconds
    since the scenario's common evidence start. Missing or additional transitions
    fail closed. Each transition records its own threshold-window start.
    """
    def index(rows):
        result = {}
        for row in rows:
            key = (row["scenario_id"], row["rule_id"], row["transition"], row.get("occurrence", 1))
            at = row["elapsed_seconds"]
            if key in result or key[2] not in ("fired", "recovered") or isinstance(at, bool) or not isinstance(at, (int, float)) or not math.isfinite(at) or at < 0:
                raise ValueError("ambiguous or invalid replay transition")
            if "window_start_seconds" not in row:
                raise ValueError("every transition requires window_start_seconds")
            start = row["window_start_seconds"]
            if isinstance(start, bool) or not isinstance(start, (int, float)) or not math.isfinite(start) or not 0 <= start <= at:
                raise ValueError("invalid decision-window start")
            result[key] = (at, start)
        for key, (_, start) in result.items():
            if key[2] != "recovered":
                continue
            fired = (key[0], key[1], "fired", key[3])
            if fired not in result or start < result[fired][0]:
                raise ValueError("recovery window must start at or after corresponding firing")
        return result
    old, new = index(before), index(after)
    if not old or old.keys() != new.keys():
        raise ValueError("replays must contain identical nonempty transition identities")
    rows = [{"scenario_id": key[0], "rule_id": key[1], "transition": key[2], "occurrence": key[3],
             "before_seconds": value[0], "after_seconds": new[key][0],
             "window_before_seconds": value[0] - value[1],
             "window_after_seconds": new[key][0] - new[key][1],
             "preserved": new[key][0] >= value[0] and new[key][0] - new[key][1] >= value[0] - value[1]}
            for key, value in sorted(old.items())]
    return {"windows_preserved": all(row["preserved"] for row in rows), "transitions": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=pathlib.Path)
    parser.add_argument("--before-replay", type=pathlib.Path)
    parser.add_argument("--after-replay", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    with args.log.open() as source:
        report = summarize(source)
    if bool(args.before_replay) != bool(args.after_replay):
        parser.error("both replay files are required")
    if args.before_replay:
        report["replay"] = compare_replays(json.loads(args.before_replay.read_text()), json.loads(args.after_replay.read_text()))
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    if report.get("replay", {}).get("windows_preserved") is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
