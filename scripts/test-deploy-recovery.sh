#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"
calls=()
rrt_recovery_block_post_exposure(){ calls+=(block); }
rrt_recovery_restore_pre_exposure(){ calls+=(restore-db restore-artifacts start-old old-readiness); }
rrt_recovery_restart_unchanged(){ calls+=(start-unchanged); }
rrt_dispatch_recovery 0 0; [[ ${calls[*]} == start-unchanged ]]
calls=(); rrt_dispatch_recovery 1 0; [[ ${calls[*]} == "restore-db restore-artifacts start-old old-readiness" ]]
calls=(); rrt_dispatch_recovery 1 1; [[ ${calls[*]} == block ]]

# Exercise the factored restore sequence: a failed DB import must never reach
# artifact restoration or old-service start.
calls=(); rrt_restore_stop(){ calls+=(stop); }; rrt_restore_database(){ calls+=(restore-db); return 1; }
rrt_restore_artifacts(){ calls+=(restore-artifacts); }; rrt_restore_start_old(){ calls+=(start-old); }; rrt_restore_old_readiness(){ calls+=(old-readiness); }; rrt_restore_failed(){ calls+=(recovery-failed); }
if rrt_restore_pre_exposure_sequence; then exit 1; fi
[[ ${calls[*]} == "stop restore-db recovery-failed" ]]

# A failed start attempt is classified as exposed before the mocked command.
new_service_started=0; rrt_start_new_service(){ calls+=(start-new); return 1; }; calls=()
if rrt_attempt_new_service_start; then exit 1; fi
[[ $new_service_started == 1 && ${calls[*]} == start-new ]]
calls=(); rrt_dispatch_recovery 1 "$new_service_started"; [[ ${calls[*]} == block ]]
echo "deployment recovery phase dispatch: ok"
