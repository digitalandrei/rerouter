#!/usr/bin/env python3
"""Fresh/upgrade hardening migration harness for dedicated Rerouter test schemas."""
import argparse
import os
import pathlib
import subprocess
import tarfile
import tempfile
from urllib.parse import parse_qs, unquote, urlparse

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINES = {"baseline56": ("08126a1", 56), "baseline69": ("441f93d", 69)}

def connection(url_file: pathlib.Path, mode: str):
    raw = url_file.read_text().strip()
    parsed = urlparse(raw)
    database, username = unquote(parsed.path.strip("/")), unquote(parsed.username or "")
    marker = "_fresh_" if mode == "fresh" else "_upgrade_"
    if parsed.scheme not in ("mysql", "mariadb") or not parsed.hostname or marker not in database:
        raise ValueError(f"{mode} requires a dedicated rerouter_test_*{marker}* schema")
    if not database.startswith("rerouter_test_") or username.lower() == "root" or "test" not in username:
        raise ValueError("restricted non-root Rerouter test account required")
    command = ["mysql", "--no-defaults", "--batch", "--raw", "--skip-column-names",
               "--init-command=SET time_zone='+00:00'"]
    socket = parse_qs(parsed.query).get("socket", [None])[0]
    if socket:
        command += ["--socket", unquote(socket)]
    else:
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise ValueError("use the existing local service or a task-owned loopback tunnel")
        command += ["-h", parsed.hostname, "-P", str(parsed.port or 3306)]
    command += ["-u", username, database]
    environment = dict(os.environ)
    environment.pop("DATABASE_URL", None)
    environment["MYSQL_PWD"] = unquote(parsed.password or "")
    environment["REROUTER_TEST_DATABASE_URL"] = raw
    return database, command, environment

def scalar(command, environment, sql):
    result = subprocess.run(command + ["-e", sql], text=True, capture_output=True,
                            env=environment, check=True)
    return result.stdout.strip()

def migration_count(directory):
    return len(list(pathlib.Path(directory).glob("*.sql")))

def extract_baseline(commit, destination):
    archive = destination / "baseline.tar"
    with archive.open("wb") as output:
        subprocess.run(["git", "archive", "--format=tar", commit, "backend-rust/migrations"],
                       cwd=ROOT, stdout=output, check=True)
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")
    return destination / "backend-rust/migrations"

def run_migrator(directory, environment, fixture=None):
    args = ["cargo", "run", "--quiet", "--example", "verify_test_migrations", "--",
            str(directory)]
    if fixture:
        args.append(str(fixture))
    subprocess.run(args, cwd=ROOT / "backend-rust", env=environment, check=True)

def assert_equal(command, environment, sql, expected, label):
    actual = scalar(command, environment, sql)
    if actual != str(expected):
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")

def verify_common(command, environment):
    checks = [
        ("SELECT outcome FROM alert_delivery_intents WHERE alert_id=900101", "sent", "sent outcome"),
        ("SELECT outcome FROM alert_delivery_intents WHERE alert_id=900102", "suppressed", "suppressed outcome"),
        ("SELECT CONCAT(state,':',attempt_count) FROM alert_delivery_intents WHERE alert_id=900103", "retry:0", "rate limit retry"),
        ("SELECT CONCAT(state,':',attempt_count) FROM alert_delivery_intents WHERE alert_id=900104", "retry:1", "failed attempt budget"),
        ("SELECT outcome FROM alert_delivery_intents WHERE alert_id=900106", "no_audience", "sentinel outcome"),
        ("SELECT state FROM alert_delivery_intents WHERE alert_id=900107", "retry", "Teams rate limit retry"),
        ("SELECT COUNT(*) FROM alert_delivery_intents WHERE alert_id=900105", 0, "unattempted alert preserved"),
        ("SELECT COUNT(*) FROM alert_deliveries WHERE id BETWEEN 900201 AND 900206 AND delivery_intent_id IS NULL", 0, "legacy attempts linked"),
        ("SELECT JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.marker')) FROM alerts WHERE id=900101", "immutable-sent", "alert payload preserved"),
        ("SELECT used_at IS NOT NULL AND expires_at='2036-01-01 00:00:00' FROM action_previews WHERE token_hash=REPEAT('b',64)", 1, "consumed preview preserved"),
        ("SELECT used_at IS NULL AND expires_at<=UTC_TIMESTAMP() FROM action_previews WHERE token_hash=REPEAT('a',64)", 1, "unused preview expired"),
    ]
    for sql, expected, label in checks:
        assert_equal(command, environment, sql, expected, label)

def verify_baseline69(command, environment):
    checks = [
        ("SELECT CONCAT(settlement,':',claim_token) FROM recovery_attempt_sources WHERE recovery_bundle_id=900402 AND source_bundle_id=900401", "restored:legacy:child:900402", "historical restored association"),
        ("SELECT CONCAT(settlement,':',claim_token) FROM recovery_attempt_sources WHERE recovery_bundle_id=900404 AND source_bundle_id=900403", "active:current-child-token", "current ambiguous association"),
        ("SELECT CONCAT(settlement,':',claim_token) FROM recovery_attempt_sources WHERE recovery_bundle_id=900406 AND source_bundle_id=900405", "blocked:legacy:child:900406", "parent-only missing evidence remains blocked"),
        ("SELECT JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.marker')) FROM reroute_bundles WHERE id=900406", "child-parent-only", "parent-only child evidence preserved"),
        ("SELECT CONCAT(settlement,':',claim_token) FROM recovery_attempt_sources WHERE recovery_bundle_id=900408 AND source_bundle_id=900407", "active:legacy-inverse-token", "ledgerless legacy inverse association"),
        ("SELECT COUNT(*) FROM device_change_window_sources WHERE device_id=900302 AND source_bundle_id=900407", 1, "ledgerless legacy inverse membership"),
        ("SELECT CONCAT(state,':',mutation_effect,':',JSON_UNQUOTE(JSON_EXTRACT(prior_state_json,'$[0].interface'))) FROM reroutes WHERE id=900505", "failed:unknown:Gi0/2", "legacy inverse evidence preserved"),
        ("SELECT GROUP_CONCAT(CONCAT(device_id,':',source_bundle_id) ORDER BY source_bundle_id) FROM device_change_window_sources WHERE device_id=900301", "900301:900403", "only current root membership"),
        ("SELECT JSON_UNQUOTE(JSON_EXTRACT(rollback_snapshot_json,'$.marker')) FROM reroutes WHERE id=900501", "immutable-inverse-a", "reroute inverse preserved"),
        ("SELECT JSON_UNQUOTE(JSON_EXTRACT(prepared_action_json,'$.marker')) FROM reroute_bundle_actions WHERE id=900601", "immutable-prepared-a", "prepared ledger preserved"),
        ("SELECT JSON_UNQUOTE(JSON_EXTRACT(snapshot_json,'$.marker')) FROM execution_plans WHERE id=900701", "immutable-consumed-plan", "consumed plan preserved"),
        ("SELECT consumed_at IS NOT NULL AND expires_at='2036-01-01 00:00:00' FROM execution_plans WHERE id=900701", 1, "consumed plan lifetime preserved"),
        ("SELECT consumed_at IS NULL AND expires_at<=UTC_TIMESTAMP() FROM execution_plans WHERE id=900702", 1, "unused plan expired"),
    ]
    for sql, expected, label in checks:
        assert_equal(command, environment, sql, expected, label)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("fresh", "baseline56", "baseline69"))
    parser.add_argument("--db-url-file", required=True, type=pathlib.Path)
    args = parser.parse_args()
    database, command, environment = connection(args.db_url_file, args.mode)
    if scalar(command, environment, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()") != "0":
        raise ValueError("schema is not empty; reset it explicitly outside this harness")
    current = ROOT / "backend-rust/migrations"
    expected_current = migration_count(current)
    with tempfile.TemporaryDirectory(prefix="rerouter-hardening-migrations-") as tmp:
        temporary = pathlib.Path(tmp)
        if args.mode == "fresh":
            run_migrator(current, environment)
        else:
            commit, expected = BASELINES[args.mode]
            baseline = extract_baseline(commit, temporary)
            if migration_count(baseline) != expected:
                raise AssertionError(f"{args.mode} manifest count changed")
            common = ROOT / "scripts/fixtures/hardening-migrations/baseline56.sql"
            fixture = temporary / "fixture.sql"
            fixture.write_text(common.read_text() + (ROOT / "scripts/fixtures/hardening-migrations/baseline69.sql").read_text() if args.mode == "baseline69" else common.read_text())
            run_migrator(baseline, environment, fixture)
            run_migrator(current, environment)
    assert_equal(command, environment, "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1", expected_current, "dynamic migration manifest")
    for table in ("recovery_attempt_sources", "device_change_window_sources", "flow_bucket_quality", "flow_publication_barrier"):
        assert_equal(command, environment, f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='{table}'", 1, f"current table {table}")
    if args.mode != "fresh":
        verify_common(command, environment)
    if args.mode == "baseline69":
        verify_baseline69(command, environment)
    print(f"hardening migrations verified: mode={args.mode} database={database} migrations={expected_current}")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, AssertionError, subprocess.SubprocessError) as error:
        print(f"migration verification failed: {type(error).__name__}", file=os.sys.stderr)
        if isinstance(error, AssertionError):
            print(str(error), file=os.sys.stderr)
        raise SystemExit(2)
