#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"

# Mock the pre-exposure path and record the application restore boundary.
calls=()
rrt_restore_stop(){ calls+=(stop-new); }
rrt_restore_database(){ calls+=(no-db-restore); }
rrt_restore_artifacts(){ calls+=(restore-controller restore-config restore-markers restore-frontend); }
rrt_restore_start_old(){ calls+=(start-old); }
rrt_restore_old_readiness(){ calls+=(old-ready); }
rrt_restore_failed(){ calls+=(failed); }
rrt_restore_pre_exposure_sequence
[[ ${calls[*]} == "stop-new no-db-restore restore-controller restore-config restore-markers restore-frontend start-old old-ready" ]]

# The concrete implementation restores controller and config before it can start old code.
script="$(dirname "$0")/deploy-ema3-lab-release.sh"
controller_line=$(grep -n 'controller.previous.*srv/rerouter/rerouter-controller' "$script" | cut -d: -f1)
config_line=$(grep -n 'config.previous.toml.*srv/rerouter/config.toml' "$script" | cut -d: -f1)
start_line=$(grep -n '^rrt_restore_start_old()' "$script" | cut -d: -f1)
[[ $controller_line -lt $start_line && $config_line -lt $start_line ]]

# Any attempted new start is classified as exposed before the start command runs.
new_service_started=0; calls=()
rrt_start_new_service(){ calls+=(start-new); return 1; }
if rrt_attempt_new_service_start; then exit 1; fi
[[ $new_service_started == 1 && ${calls[*]} == start-new ]]
echo "EMA3 lab deployment recovery boundaries: ok"
