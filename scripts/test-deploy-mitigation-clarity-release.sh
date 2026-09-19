#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"

calls=()
rrt_restore_stop(){ calls+=(stop-new); }
rrt_restore_database(){ calls+=(no-db-restore); }
rrt_restore_artifacts(){ calls+=(restore-controller restore-markers restore-frontend); }
rrt_restore_start_old(){ calls+=(start-old); }
rrt_restore_old_readiness(){ calls+=(old-ready); }
rrt_restore_failed(){ calls+=(failed); }
rrt_restore_pre_exposure_sequence
[[ ${calls[*]} == "stop-new no-db-restore restore-controller restore-markers restore-frontend start-old old-ready" ]]

new_service_started=0; calls=()
rrt_start_new_service(){ calls+=(start-new); return 1; }
if rrt_attempt_new_service_start; then exit 1; fi
[[ $new_service_started == 1 && ${calls[*]} == start-new ]]
calls=(); rrt_recovery_block_post_exposure(){ calls+=(retain-new-evidence stop-service); }
rrt_dispatch_recovery 1 "$new_service_started"
[[ ${calls[*]} == "retain-new-evidence stop-service" ]]

script="$(dirname "$0")/deploy-mitigation-clarity-release.sh"
grep -Fq "bundle #1 remains applied" "$script"
grep -Fq "parent_bundle_id IS NULL" "$script"
grep -Fq "remaining_mutations=8" "$script"
grep -Fq "recovery_claim_token IS NOT NULL" "$script"
grep -Fq "snapshot before" "$script"
grep -Fq "compare_snapshots" "$script"
grep -Fq "check_preset 2 ready before-stop" "$script"
grep -Fq "check_preset 2 ready after-restart" "$script"
grep -Fq 'diff -qr /var/www/rerouter "$release_dir/frontend"' "$script"
if grep -Eq '/api/(manual-mitigations/(preview|apply)|reroute-bundles/.*/revert|notifications/.*/test)' "$script"; then exit 1; fi

diagnostic=$(mktemp); trap 'rm -f "$diagnostic"' EXIT
printf '%s\n' '{"timestamp":"2026-09-19T00:00:00Z","level":"INFO"}' '{"id":2,"name":"e-manuel-apply-ema3-test","status":"ready","validation_error":null}' >"$diagnostic"
python3 -c 'import json,sys
found=[]
for line in open(sys.argv[1]):
 try: value=json.loads(line)
 except json.JSONDecodeError: continue
 if isinstance(value,dict) and set(value)=={"id","name","status","validation_error"} and value.get("id")==2: found.append(value)
assert len(found)==1 and found[0]["status"]=="ready"' "$diagnostic"
echo "mitigation clarity deployment recovery and preservation checks: ok"
