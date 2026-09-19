#!/usr/bin/env bash
# Prepared release driver. It preserves the settled eMA3 apply/revert evidence
# and never invokes preview, apply, revert, notification, or router APIs.
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"

usage(){ echo "usage: $0 --release-dir DIR --commit SHA --controller-sha256 SHA --frontend-sha256 SHA --expected-current-controller-sha256 SHA --expected-current-frontend-sha256 SHA --backup-dir DIR" >&2; exit 64; }
release_dir= commit= controller_sha= frontend_sha= current_controller_sha= current_frontend_sha= backup_dir=
while (($#)); do
  case "$1" in
    --release-dir) release_dir=$2;; --commit) commit=$2;;
    --controller-sha256) controller_sha=$2;; --frontend-sha256) frontend_sha=$2;;
    --expected-current-controller-sha256) current_controller_sha=$2;;
    --expected-current-frontend-sha256) current_frontend_sha=$2;;
    --backup-dir) backup_dir=$2;; *) usage;;
  esac
  shift 2
done
[[ -n $release_dir && -n $commit && -n $controller_sha && -n $frontend_sha && -n $current_controller_sha && -n $current_frontend_sha && -n $backup_dir ]] || usage
[[ $EUID == 0 && $(hostname) == ematrix && $commit =~ ^[0-9a-f]{40}$ && $controller_sha =~ ^[0-9a-f]{64}$ && $frontend_sha =~ ^[0-9a-f]{64}$ && $current_controller_sha =~ ^[0-9a-f]{64}$ && $current_frontend_sha =~ ^[0-9a-f]{64}$ ]]
[[ -x $release_dir/rerouter-controller && -r $release_dir/frontend/index.html && ! -e $backup_dir ]]
[[ $(sha256sum "$release_dir/rerouter-controller" | awk '{print $1}') == "$controller_sha" ]]
[[ $(sha256sum "$release_dir/frontend/index.html" | awk '{print $1}') == "$frontend_sha" ]]
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$current_controller_sha" ]]
[[ $(sha256sum /var/www/rerouter/index.html | awk '{print $1}') == "$current_frontend_sha" ]]
[[ $(tr -d '\n' </srv/rerouter/RELEASE) == 3276418* ]]
[[ $(tr -d '\n' </srv/rerouter/FRONTEND_RELEASE) == 9193046* ]]
readonly_config_sha=6e659bfdd917f68b573b7cb5397a3080749cb27417e89750f00b8a0ba1b36972
[[ $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$readonly_config_sha" ]]

if command -v mysql >/dev/null && command -v mysqldump >/dev/null; then DB=mysql; DUMP=(mysqldump --no-tablespaces); elif command -v mariadb >/dev/null && command -v mariadb-dump >/dev/null; then DB=mariadb; DUMP=(mariadb-dump); else echo "supported database client not found" >&2; exit 1; fi
db(){ "$DB" --connect-timeout=5 "$@" rerouter; }; scalar(){ db -N -B -e "$1"; }

assert_preserved_runtime(){
  [[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 ]]
  [[ $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
  [[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe ]]
  [[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundles") == 2 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE id=1 AND parent_bundle_id IS NULL AND recovery_bundle_id IS NULL AND trigger_type='manual' AND state='succeeded' AND lifecycle_state='inactive' AND total_actions=8 AND completed_actions=8 AND remaining_mutations=0 AND recovery_claim_token IS NULL AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode'))='configuration_only'") == 1 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE id=2 AND parent_bundle_id=1 AND trigger_type='manual' AND state='succeeded' AND lifecycle_state='inactive' AND total_actions=8 AND completed_actions=8 AND remaining_mutations=0 AND recovery_claim_token IS NULL AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.kind'))='bundle_revert' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.original_bundle_id'))='1'") == 1 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE state IN ('planned','running','compensating') OR lifecycle_state IN ('recovery_claimed','recovery_running') OR recovery_claim_token IS NOT NULL") == 0 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroutes") == 16 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE bundle_id=1 AND rollback_of_reroute_id IS NULL AND state='succeeded' AND mutation_effect='changed' AND finished_at IS NOT NULL") == 8 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroutes inverse JOIN reroutes original ON original.id=inverse.rollback_of_reroute_id WHERE inverse.bundle_id=2 AND original.bundle_id=1 AND inverse.state='succeeded' AND inverse.mutation_effect='changed' AND inverse.finished_at IS NOT NULL") == 8 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE state IN ('planned','pending','running','verifying')") == 0 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundle_actions") == 16 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id=1 AND state='succeeded' AND mutation_effect='changed'") == 8 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id=2 AND state='succeeded' AND mutation_effect='changed' AND original_reroute_id IS NOT NULL") == 8 ]]
  [[ $(scalar "SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL") == 0 ]]
  [[ $(scalar "SELECT COUNT(*) FROM device_change_windows") == 0 ]]
}
assert_preserved_runtime

install -d -m 0700 "$backup_dir"
cp -a /srv/rerouter/rerouter-controller "$backup_dir/controller.previous"
cp -a /srv/rerouter/config.toml "$backup_dir/config.unchanged.toml"
cp -a /srv/rerouter/.env "$backup_dir/environment.unchanged"
cp -a /srv/rerouter/RELEASE "$backup_dir/RELEASE.previous"
cp -a /srv/rerouter/FRONTEND_RELEASE "$backup_dir/FRONTEND_RELEASE.previous"
mkdir "$backup_dir/frontend.previous"; cp -aL /var/www/rerouter/. "$backup_dir/frontend.previous/"
sha256sum "$backup_dir/controller.previous" "$backup_dir/config.unchanged.toml" "$backup_dir/environment.unchanged" "$backup_dir/frontend.previous/index.html" >"$backup_dir/artifacts.before.sha256"

web_stage="/var/www/.rerouter-recovery-progress-stage-$commit"; web_previous="/var/www/rerouter.previous-$commit"
binary_stage="/srv/rerouter/.controller-recovery-progress-stage-$commit"
[[ ! -e $web_stage && ! -e $web_previous && ! -e $binary_stage ]]
install -d -m 0755 "$web_stage"; cp -a "$release_dir/frontend/." "$web_stage/"
find "$web_stage" -type d -exec chmod 0755 {} +; find "$web_stage" -type f -exec chmod 0644 {} +
install -o root -g root -m 0755 "$release_dir/rerouter-controller" "$binary_stage"

diagnostic_binary=$binary_stage
check_config(){
  local phase=$1
  env -u DATABASE_URL -u REROUTER_CONFIG "$diagnostic_binary" --check --config /srv/rerouter/config.toml --env-file /srv/rerouter/.env >"$backup_dir/config-check.$phase.jsonl"
}
check_preset(){
  local preset_id=$1 expected=$2 phase=$3 output="$backup_dir/preset-$1-readiness.$3.jsonl"
  env -u DATABASE_URL -u REROUTER_CONFIG "$diagnostic_binary" --check-mitigation-preset "$preset_id" --config /srv/rerouter/config.toml --env-file /srv/rerouter/.env >"$output"
  python3 -c 'import json,sys
found=[]
for line in open(sys.argv[1]):
 try: value=json.loads(line)
 except json.JSONDecodeError: continue
 if isinstance(value,dict) and set(value)=={"id","name","status","validation_error"} and value.get("id")==int(sys.argv[2]): found.append(value)
assert len(found)==1 and str(found[0]["status"]).lower()==sys.argv[3]' "$output" "$preset_id" "$expected"
}
# These exit before migrations, workers, HTTP, SSH, or execution. Preset 2's
# fetch executes the new latest-recovery summary query against live MySQL.
check_config before-stop
check_preset 2 ready before-stop
check_preset 1 needs_setup before-stop

bundle_query="SELECT * FROM reroute_bundles ORDER BY id"
reroute_query="SELECT * FROM reroutes ORDER BY id"
ledger_query="SELECT * FROM reroute_bundle_actions ORDER BY bundle_id,position,id"
preset_query="SELECT p.id,p.name,p.description,p.revision,p.archived_at,p.created_by,p.updated_by,a.id,a.reroute_template_id,a.device_id,a.params_json,a.enabled,a.position FROM mitigation_presets p LEFT JOIN mitigation_preset_actions a ON a.preset_id=p.id ORDER BY p.id,a.position,a.id"
rule_query="SELECT * FROM rules ORDER BY id"
rule_action_query="SELECT * FROM rule_actions ORDER BY rule_id,position,id"
settings_query="SELECT \`key\`,value FROM system_settings ORDER BY \`key\`"
credentials_query="SELECT id,ssh_username,ssh_port,ssh_auth_method,ssh_password_encrypted,ssh_private_key_encrypted,ssh_key_passphrase_encrypted,ssh_public_key,ssh_host_fingerprint FROM devices ORDER BY id"
snapshot(){
  local phase=$1
  db -N -B -e "$bundle_query" >"$backup_dir/bundles.$phase.tsv"
  db -N -B -e "$reroute_query" >"$backup_dir/reroutes.$phase.tsv"
  db -N -B -e "$ledger_query" >"$backup_dir/bundle-ledger.$phase.tsv"
  db -N -B -e "$preset_query" >"$backup_dir/presets.$phase.tsv"
  db -N -B -e "$rule_query" >"$backup_dir/rules.$phase.tsv"
  db -N -B -e "$rule_action_query" >"$backup_dir/rule-actions.$phase.tsv"
  db -N -B -e "$settings_query" >"$backup_dir/settings.$phase.tsv"
  db -N -B -e "$credentials_query" >"$backup_dir/device-credentials.$phase.tsv"
  chmod 0600 "$backup_dir/device-credentials.$phase.tsv"
}
compare_snapshots(){
  local name
  for name in bundles reroutes bundle-ledger presets rules rule-actions settings device-credentials; do cmp --silent "$backup_dir/$name.before.tsv" "$backup_dir/$name.after.tsv"; done
}

stopped=0; migration_started=0; new_service_started=0; completed=0
rrt_restore_stop(){ systemctl stop rerouter-controller.service || true; }
rrt_restore_database(){ return 0; }
rrt_restore_artifacts(){
  cp -a "$backup_dir/controller.previous" /srv/rerouter/rerouter-controller || return 1
  cp -a "$backup_dir/RELEASE.previous" /srv/rerouter/RELEASE || return 1
  cp -a "$backup_dir/FRONTEND_RELEASE.previous" /srv/rerouter/FRONTEND_RELEASE || return 1
  if [[ -e $web_previous ]]; then [[ ! -e /var/www/rerouter ]] || mv /var/www/rerouter "$backup_dir/frontend.failed" || return 1; mv "$web_previous" /var/www/rerouter || return 1; fi
}
rrt_restore_start_old(){ systemctl start rerouter-controller.service; }
rrt_restore_old_readiness(){ for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && return 0; sleep 2; done; return 1; }
rrt_restore_failed(){ printf 'RECOVERY FAILED: %s\nOld artifacts remain in %s; service must remain stopped.\n' "$1" "$backup_dir" | tee "$backup_dir/RECOVERY-FAILED.txt" >&2; systemctl stop rerouter-controller.service || true; }
rrt_recovery_restore_pre_exposure(){ rrt_restore_pre_exposure_sequence || echo "automatic pre-exposure restore failed; manual recovery required" >&2; }
rrt_recovery_restart_unchanged(){ systemctl start rerouter-controller.service || true; }
rrt_recovery_block_post_exposure(){
  systemctl stop rerouter-controller.service || true
  { echo "RECOVERY BLOCKED: the new controller start was attempted after the eMA3 revert settled."; echo "New artifacts and durable apply/revert evidence were retained. Do not restore the old controller or database without reconciliation."; } | tee "$backup_dir/RECOVERY-BLOCKED.txt" >&2
  snapshot after-failure || true
}
recover(){ rc=$?; if ((stopped && !completed)); then rrt_dispatch_recovery "$migration_started" "$new_service_started"; fi; exit "$rc"; }
trap recover EXIT
systemctl stop rerouter-controller.service; stopped=1
assert_preserved_runtime
snapshot before
"${DUMP[@]}" --single-transaction --routines --triggers --databases rerouter | gzip -9 >"$backup_dir/database-evidence.sql.gz"; gzip -t "$backup_dir/database-evidence.sql.gz"
{
  echo "old_controller_release=$(tr -d '\n' </srv/rerouter/RELEASE)"; echo "old_frontend_release=$(tr -d '\n' </srv/rerouter/FRONTEND_RELEASE)"; echo "new_commit=$commit"
  echo "old_controller_sha256=$current_controller_sha"; echo "new_controller_sha256=$controller_sha"
  echo "old_frontend_index_sha256=$current_frontend_sha"; echo "new_frontend_index_sha256=$frontend_sha"
  echo "config_sha256=$readonly_config_sha"; echo "migration_count=69"; echo "latest_migration=20260919000200"
  echo "settled_source_bundle=1"; echo "settled_recovery_bundle=2"; echo "preserved_reroutes=16"
} >"$backup_dir/deployment-audit.manifest"
sha256sum "$backup_dir"/*.before.tsv "$backup_dir/database-evidence.sql.gz" >>"$backup_dir/deployment-audit.manifest"

# There is no new migration. Artifact replacement is the pre-exposure mutation
# phase; the controller's normal startup migration check must remain a no-op.
migration_started=1
mv "$binary_stage" /srv/rerouter/rerouter-controller
diagnostic_binary=/srv/rerouter/rerouter-controller
mv /var/www/rerouter "$web_previous"; mv "$web_stage" /var/www/rerouter
printf '%s\n' "$commit" >/srv/rerouter/RELEASE; chmod 0644 /srv/rerouter/RELEASE
printf '%s\n' "$commit" >/srv/rerouter/FRONTEND_RELEASE; chmod 0644 /srv/rerouter/FRONTEND_RELEASE
cmp --silent /srv/rerouter/config.toml "$backup_dir/config.unchanged.toml"
cmp --silent /srv/rerouter/.env "$backup_dir/environment.unchanged"

rrt_start_new_service(){ systemctl start rerouter-controller.service; }; rrt_attempt_new_service_start
for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && break; sleep 2; done
systemctl is-active --quiet rerouter-controller.service
curl --max-time 10 -fsS http://127.0.0.1:9277/api/ready >/dev/null
curl --max-time 10 -fsS http://127.0.0.1:9277/api/health >/dev/null
pid=$(systemctl show --property MainPID --value rerouter-controller.service); [[ $pid =~ ^[1-9][0-9]*$ ]]; cmp --silent "/proc/$pid/exe" /srv/rerouter/rerouter-controller
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$controller_sha" ]]
[[ $(sha256sum /var/www/rerouter/index.html | awk '{print $1}') == "$frontend_sha" ]]
[[ $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$readonly_config_sha" ]]
cmp --silent /srv/rerouter/.env "$backup_dir/environment.unchanged"
diff -qr /var/www/rerouter "$release_dir/frontend" >/dev/null
assert_preserved_runtime
check_config after-restart
check_preset 2 ready after-restart
check_preset 1 needs_setup after-restart
snapshot after
compare_snapshots
completed=1; trap - EXIT
echo "recovery progress release deployed; source #1 and revert child #2 remain settled; router actions executed: 0"
