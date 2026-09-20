#!/usr/bin/env python3
"""Validate hardening capture SQL against an approved Rerouter test schema."""
import importlib.util
import os
import pathlib
import subprocess
import sys
from urllib.parse import parse_qs, unquote, urlparse

ROOT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("release", ROOT / "prepare-hardening-release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

def main():
    raw = os.environ.get("REROUTER_TEST_DATABASE_URL", "")
    parsed = urlparse(raw)
    database = unquote(parsed.path.strip("/"))
    username = unquote(parsed.username or "")
    if parsed.scheme not in ("mysql", "mariadb") or not parsed.hostname:
        raise ValueError("REROUTER_TEST_DATABASE_URL must name an approved MariaDB test schema")
    if username.lower() == "root" or not database.startswith("rerouter_test_"):
        raise ValueError("capture SQL validation requires a non-root rerouter_test_* account")
    command = ["mysql", "--no-defaults", "--batch", "--raw", "--skip-column-names"]
    socket = parse_qs(parsed.query).get("socket", [None])[0]
    if socket:
        command += ["--socket", unquote(socket)]
    else:
        command += ["-h", parsed.hostname, "-P", str(parsed.port or 3306)]
    command += ["-u", username, database]
    environment = dict(os.environ)
    environment.pop("DATABASE_URL", None)
    environment["MYSQL_PWD"] = unquote(parsed.password or "")
    subprocess.run(
        command,
        input=release.CAPTURE_SQL,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=environment,
        check=True,
    )
    print("capture SQL matches the approved Rerouter test schema")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.SubprocessError) as error:
        print(f"capture SQL validation refused or failed: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
