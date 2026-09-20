#!/usr/bin/env bash
set -euo pipefail

# Do not inherit application DATABASE_URL. The Rust harness verifies the actual
# schema/account, uses UTC and serializes database tests across processes.
: "${REROUTER_TEST_DATABASE_URL:?Set a restricted test account URL for rerouter_test or rerouter_test_* on an existing database service}"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

cd "$repo_dir/backend-rust"
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
env -u DATABASE_URL cargo test --locked --all-targets -- --test-threads=1 --nocapture

cd "$repo_dir"
python3 scripts/test-retune-sample-counts.py
python3 scripts/test-report-hardening-timing.py
python3 scripts/test-prepare-hardening-release.py
python3 scripts/test-hardening-migrations-unit.py
python3 scripts/test-hardening-capture-sql-db.py

cd "$repo_dir/frontend"
npm run typecheck
npm test -- --run
npm run build

cd "$repo_dir/backend-rust"
cargo build --locked --features embed-ui

printf '%s\n' 'Software release checks passed. IOS/IOS-XE and supported database-engine certification are separate requirements.'
