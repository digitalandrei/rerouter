#!/usr/bin/env bash
# Prepared only: backend readiness hotfix. Run as root on ematrix after review.
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"

usage(){ echo "usage: $0 --release-dir DIR --commit SHA --controller-sha256 SHA --expected-current-controller-sha256 SHA --backup-dir DIR" >&2; exit 64; }
release_dir= commit= controller_sha= current_controller_sha= backup_dir=
while (($#)); do
  case "$1" in
    --release-dir) release_dir=$2;; --commit) commit=$2;;
    --controller-sha256) controller_sha=$2;; --expected-current-controller-sha256) current_controller_sha=$2;;
    --backup-dir) backup_dir=$2;; *) usage;;
  esac
  shift 2
done
[[ -n $release_dir && -n $commit && -n $controller_sha && -n $current_controller_sha && -n $backup_dir ]] || usage
[[ $EUID == 0 && $(hostname) == ematrix && $commit =~ ^[0-9a-f]{40}$ && $controller_sha =~ ^[0-9a-f]{64}$ && $current_controller_sha =~ ^[0-9a-f]{64}$ ]]
[[ -x $release_dir/rerouter-controller && ! -e $backup_dir ]]
[[ $(sha256sum "$release_dir/rerouter-controller" | awk '{print $1}') == "$controller_sha" ]]
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$current_controller_sha" ]]
[[ $(tr -d '\n' </srv/rerouter/RELEASE) == 4129744* ]]
readonly_config_sha=6e659bfdd917f68b573b7cb5397a3080749cb27417e89750f00b8a0ba1b36972
[[ $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$readonly_config_sha" ]]

if command -v mysql >/dev/null && command -v mysqldump >/dev/null; then DB=mysql; DUMP=(mysqldump --no-tablespaces); elif command -v mariadb >/dev/null && command -v mariadb-dump >/dev/null; then DB=mariadb; DUMP=(mariadb-dump); else echo "supported database client not found" >&2; exit 1; fi
db(){ "$DB" --connect-timeout=5 "$@" rerouter; }; scalar(){ db -N -B -e "$1"; }
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
[[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe && $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
[[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE state IN ('planned','pending','running','verifying','compensating')") == 0 ]]
[[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE state IN ('planned','running','compensating') OR remaining_mutations>0") == 0 ]]
[[ $(scalar "SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL") == 0 ]]

install -d -m 0700 "$backup_dir"
cp -a /srv/rerouter/rerouter-controller "$backup_dir/controller.previous"
cp -a /srv/rerouter/config.toml "$backup_dir/config.unchanged.toml"
cp -a /srv/rerouter/.env "$backup_dir/environment.unchanged"
cp -a /srv/rerouter/RELEASE "$backup_dir/RELEASE.previous"
if [[ -e /srv/rerouter/FRONTEND_RELEASE ]]; then cp -a /srv/rerouter/FRONTEND_RELEASE "$backup_dir/FRONTEND_RELEASE.unchanged"; else touch "$backup_dir/FRONTEND_RELEASE.was-absent"; fi
mkdir "$backup_dir/frontend.unchanged"; cp -aL /var/www/rerouter/. "$backup_dir/frontend.unchanged/"
sha256sum "$backup_dir/controller.previous" "$backup_dir/config.unchanged.toml" "$backup_dir/environment.unchanged" "$backup_dir/frontend.unchanged/index.html" >"$backup_dir/artifacts.before.sha256"

preset_query="SELECT p.id,p.name,p.description,p.revision,p.archived_at,p.created_by,p.updated_by,a.id,a.reroute_template_id,a.device_id,a.params_json,a.enabled,a.position FROM mitigation_presets p LEFT JOIN mitigation_preset_actions a ON a.preset_id=p.id ORDER BY p.id,a.position,a.id"
rule_query="SELECT * FROM rules ORDER BY id"
rule_action_query="SELECT * FROM rule_actions ORDER BY rule_id,position,id"
settings_query="SELECT \`key\`,value FROM system_settings ORDER BY \`key\`"
credentials_query="SELECT id,ssh_username,ssh_port,ssh_auth_method,ssh_password_encrypted,ssh_private_key_encrypted,ssh_key_passphrase_encrypted,ssh_public_key,ssh_host_fingerprint FROM devices ORDER BY id"
rule_state_query="SELECT * FROM rule_states ORDER BY rule_id"
db -N -B -e "$preset_query" >"$backup_dir/presets.before.tsv"
db -N -B -e "$rule_query" >"$backup_dir/rules.before.tsv"
db -N -B -e "$rule_action_query" >"$backup_dir/rule-actions.before.tsv"
db -N -B -e "$settings_query" >"$backup_dir/settings.before.tsv"
db -N -B -e "$credentials_query" >"$backup_dir/device-credentials.before.tsv"; chmod 0600 "$backup_dir/device-credentials.before.tsv"
db -N -B -e "$rule_state_query" >"$backup_dir/rule-states.before.tsv"
reroutes_before=$(scalar "SELECT COUNT(*) FROM reroutes"); bundles_before=$(scalar "SELECT COUNT(*) FROM reroute_bundles"); locks_before=$(scalar "SELECT COUNT(*) FROM locks")
presets_before=$(scalar "SELECT COUNT(*) FROM mitigation_presets"); preset_actions_before=$(scalar "SELECT COUNT(*) FROM mitigation_preset_actions"); rules_before=$(scalar "SELECT COUNT(*) FROM rules")
{
  echo "old_release=$(tr -d '\n' </srv/rerouter/RELEASE)"; echo "new_commit=$commit"
  echo "old_controller_sha256=$current_controller_sha"; echo "new_controller_sha256=$controller_sha"; echo "config_sha256=$readonly_config_sha"
  echo "migration_count=69"; echo "latest_migration=20260919000200"; echo "operating_mode=observe"; echo "automatic_actions_enabled=false"
  echo "presets=$presets_before"; echo "preset_actions=$preset_actions_before"; echo "rules=$rules_before"
  echo "reroutes=$reroutes_before"; echo "bundles=$bundles_before"; echo "locks=$locks_before"
} >"$backup_dir/deployment-audit.manifest"
sha256sum "$backup_dir/presets.before.tsv" "$backup_dir/rules.before.tsv" "$backup_dir/rule-actions.before.tsv" "$backup_dir/settings.before.tsv" "$backup_dir/device-credentials.before.tsv" >>"$backup_dir/deployment-audit.manifest"

binary_stage="/srv/rerouter/.controller-readiness-stage-$commit"
[[ ! -e $binary_stage ]]; install -o root -g root -m 0755 "$release_dir/rerouter-controller" "$binary_stage"
diagnostic_binary=$binary_stage

# DB/config-only diagnostic: no HTTP auth, preview, scheduler, router, or notification path.
check_diagnostic(){
  local preset_id=$1 expected=$2 phase=$3
  local output="$backup_dir/preset-$preset_id-readiness.$phase.jsonl"
  env -u DATABASE_URL -u REROUTER_CONFIG "$diagnostic_binary" --check-mitigation-preset "$preset_id" --config /srv/rerouter/config.toml --env-file /srv/rerouter/.env >"$output"
  python3 -c 'import json,sys
found=[]
for line in open(sys.argv[1]):
 try: value=json.loads(line)
 except json.JSONDecodeError: continue
 if isinstance(value,dict) and set(value)=={"id","name","status","validation_error"} and value.get("id")==int(sys.argv[2]): found.append(value)
assert len(found)==1 and str(found[0]["status"]).lower()==sys.argv[3]' "$output" "$preset_id" "$expected"
}
check_diagnostic 2 ready before-stop
check_diagnostic 1 needs_setup before-stop

stopped=0; migration_started=0; new_service_started=0; completed=0
rrt_restore_stop(){ systemctl stop rerouter-controller.service || true; }
rrt_restore_database(){ return 0; }
rrt_restore_artifacts(){ cp -a "$backup_dir/controller.previous" /srv/rerouter/rerouter-controller && cp -a "$backup_dir/RELEASE.previous" /srv/rerouter/RELEASE; }
rrt_restore_start_old(){ systemctl start rerouter-controller.service; }
rrt_restore_old_readiness(){ for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && return 0; sleep 2; done; return 1; }
rrt_restore_failed(){ printf 'RECOVERY FAILED: %s\nOld controller remains in %s; service must remain stopped.\n' "$1" "$backup_dir" | tee "$backup_dir/RECOVERY-FAILED.txt" >&2; systemctl stop rerouter-controller.service || true; }
rrt_recovery_restore_pre_exposure(){ rrt_restore_pre_exposure_sequence || echo "automatic pre-exposure restore failed; manual recovery required" >&2; }
rrt_recovery_restart_unchanged(){ systemctl start rerouter-controller.service || true; }
rrt_recovery_block_post_exposure(){
  systemctl stop rerouter-controller.service || true
  { echo "RECOVERY BLOCKED: the hotfix controller start was attempted and durable writes may exist."; echo "New controller and database evidence were retained; old controller was not restarted."; } | tee "$backup_dir/RECOVERY-BLOCKED.txt" >&2
  scalar "SELECT COUNT(*) FROM reroutes" >"$backup_dir/reroute-count.after-failure" || true
  scalar "SELECT COUNT(*) FROM reroute_bundles" >"$backup_dir/bundle-count.after-failure" || true
  scalar "SELECT COUNT(*) FROM audit_logs" >"$backup_dir/audit-count.after-failure" || true
}
recover(){ rc=$?; if ((stopped && !completed)); then rrt_dispatch_recovery "$migration_started" "$new_service_started"; fi; exit "$rc"; }
trap recover EXIT
systemctl stop rerouter-controller.service; stopped=1; migration_started=1

"${DUMP[@]}" --single-transaction --routines --triggers --databases rerouter | gzip -9 >"$backup_dir/database-evidence.sql.gz"; gzip -t "$backup_dir/database-evidence.sql.gz"
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
[[ $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$readonly_config_sha" ]]
cmp --silent /srv/rerouter/.env "$backup_dir/environment.unchanged"

mv "$binary_stage" /srv/rerouter/rerouter-controller; chown root:root /srv/rerouter/rerouter-controller; chmod 0755 /srv/rerouter/rerouter-controller
diagnostic_binary=/srv/rerouter/rerouter-controller
printf '%s\n' "$commit" >/srv/rerouter/RELEASE; chmod 0644 /srv/rerouter/RELEASE
rrt_start_new_service(){ systemctl start rerouter-controller.service; }; rrt_attempt_new_service_start
for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && break; sleep 2; done
systemctl is-active --quiet rerouter-controller.service; curl --max-time 10 -fsS http://127.0.0.1:9277/api/ready >/dev/null; curl --max-time 10 -fsS http://127.0.0.1:9277/api/health >/dev/null
pid=$(systemctl show --property MainPID --value rerouter-controller.service); [[ $pid =~ ^[1-9][0-9]*$ ]]; cmp --silent "/proc/$pid/exe" /srv/rerouter/rerouter-controller
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$controller_sha" && $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$readonly_config_sha" ]]
check_diagnostic 2 ready after-restart
check_diagnostic 1 needs_setup after-restart
cmp --silent /srv/rerouter/.env "$backup_dir/environment.unchanged"; diff -qr /var/www/rerouter "$backup_dir/frontend.unchanged" >/dev/null
if [[ -e $backup_dir/FRONTEND_RELEASE.unchanged ]]; then cmp --silent /srv/rerouter/FRONTEND_RELEASE "$backup_dir/FRONTEND_RELEASE.unchanged"; else [[ ! -e /srv/rerouter/FRONTEND_RELEASE ]]; fi
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
[[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe && $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
db -N -B -e "$preset_query" >"$backup_dir/presets.after.tsv"; db -N -B -e "$rule_query" >"$backup_dir/rules.after.tsv"; db -N -B -e "$rule_action_query" >"$backup_dir/rule-actions.after.tsv"; db -N -B -e "$settings_query" >"$backup_dir/settings.after.tsv"; db -N -B -e "$credentials_query" >"$backup_dir/device-credentials.after.tsv"; chmod 0600 "$backup_dir/device-credentials.after.tsv"
db -N -B -e "$rule_state_query" >"$backup_dir/rule-states.after.tsv"
cmp --silent "$backup_dir/presets.before.tsv" "$backup_dir/presets.after.tsv"; cmp --silent "$backup_dir/rules.before.tsv" "$backup_dir/rules.after.tsv"; cmp --silent "$backup_dir/rule-actions.before.tsv" "$backup_dir/rule-actions.after.tsv"; cmp --silent "$backup_dir/settings.before.tsv" "$backup_dir/settings.after.tsv"; cmp --silent "$backup_dir/device-credentials.before.tsv" "$backup_dir/device-credentials.after.tsv"
[[ $(scalar "SELECT COUNT(*) FROM mitigation_presets") == "$presets_before" && $(scalar "SELECT COUNT(*) FROM mitigation_preset_actions") == "$preset_actions_before" && $(scalar "SELECT COUNT(*) FROM rules") == "$rules_before" ]]
[[ $(scalar "SELECT COUNT(*) FROM reroutes") == "$reroutes_before" && $(scalar "SELECT COUNT(*) FROM reroute_bundles") == "$bundles_before" && $(scalar "SELECT COUNT(*) FROM locks") == "$locks_before" ]]
completed=1; trap - EXIT
echo "backend readiness hotfix deployed; config/frontend/env/definitions/rules/run counts unchanged; router actions executed: 0"
