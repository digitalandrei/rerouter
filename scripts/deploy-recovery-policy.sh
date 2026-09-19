#!/usr/bin/env bash
# Recovery dispatcher shared by the prepared release script and its mock test.
rrt_dispatch_recovery() {
  local migration_started=$1 new_service_started=$2
  if ((new_service_started)); then
    rrt_recovery_block_post_exposure
  elif ((migration_started)); then
    rrt_recovery_restore_pre_exposure
  else
    rrt_recovery_restart_unchanged
  fi
}

rrt_restore_pre_exposure_sequence() {
  rrt_restore_stop || return 1
  rrt_restore_database || { rrt_restore_failed "database restore failed; service remains stopped"; return 1; }
  rrt_restore_artifacts || { rrt_restore_failed "artifact restore failed; service remains stopped"; return 1; }
  rrt_restore_start_old || { rrt_restore_failed "old service start failed"; return 1; }
  rrt_restore_old_readiness || { rrt_restore_failed "old service readiness failed"; return 1; }
}

rrt_attempt_new_service_start() {
  new_service_started=1
  rrt_start_new_service
}
