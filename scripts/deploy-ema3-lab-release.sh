#!/usr/bin/env bash
# Prepared deployment only. Run as root on ematrix after reviewing artifacts and hashes.
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"

usage(){ echo "usage: $0 --release-dir DIR --commit SHA --controller-sha256 SHA --frontend-sha256 SHA --config-sha256 SHA --expected-current-config-sha256 SHA --backup-dir DIR" >&2; exit 64; }
release_dir= commit= controller_sha= frontend_sha= config_sha= current_config_sha= backup_dir=
while (($#)); do
  case "$1" in
    --release-dir) release_dir=$2;; --commit) commit=$2;;
    --controller-sha256) controller_sha=$2;; --frontend-sha256) frontend_sha=$2;;
    --config-sha256) config_sha=$2;; --expected-current-config-sha256) current_config_sha=$2;;
    --backup-dir) backup_dir=$2;; *) usage;;
  esac
  shift 2
done
[[ -n $release_dir && -n $commit && -n $controller_sha && -n $frontend_sha && -n $config_sha && -n $current_config_sha && -n $backup_dir ]] || usage
[[ $EUID == 0 && $(hostname) == ematrix && $commit =~ ^[0-9a-f]{40}$ && $controller_sha =~ ^[0-9a-f]{64}$ && $frontend_sha =~ ^[0-9a-f]{64}$ && $config_sha =~ ^[0-9a-f]{64}$ && $current_config_sha =~ ^[0-9a-f]{64}$ ]]
[[ -x $release_dir/rerouter-controller && -r $release_dir/frontend/index.html && -r $release_dir/config.toml && ! -e $backup_dir ]]
[[ $(sha256sum "$release_dir/rerouter-controller" | awk '{print $1}') == "$controller_sha" ]]
[[ $(sha256sum "$release_dir/frontend/index.html" | awk '{print $1}') == "$frontend_sha" ]]
[[ $(sha256sum "$release_dir/config.toml" | awk '{print $1}') == "$config_sha" ]]
[[ $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$current_config_sha" ]]
! grep -Fq '[[safety.configuration_test_devices]]' /srv/rerouter/config.toml
[[ $(grep -Fc '[[safety.configuration_test_devices]]' "$release_dir/config.toml") == 1 ]]

# The reviewed config is the exact current file plus one bounded EMA3 lab entry.
old_config_size=$(stat -c %s /srv/rerouter/config.toml)
cmp --silent -n "$old_config_size" /srv/rerouter/config.toml "$release_dir/config.toml"
suffix=$(mktemp); trap 'rm -f "$suffix"' EXIT
tail -c "+$((old_config_size + 1))" "$release_dir/config.toml" >"$suffix"
expected_suffix=$(mktemp)
cat >"$expected_suffix" <<'EOF'

[[safety.configuration_test_devices]]
device_id = 3
host = "192.168.200.93"
port = 22
pinned_host_fingerprint = "SHA256:g5STRLrA9f983JajxTP48qew0+w+MJEyIEOnugXmlyA"
EOF
cmp --silent "$suffix" "$expected_suffix"
rm -f "$suffix" "$expected_suffix"; trap - EXIT

if command -v mysql >/dev/null && command -v mysqldump >/dev/null; then DB=mysql; DUMP=(mysqldump --no-tablespaces); elif command -v mariadb >/dev/null && command -v mariadb-dump >/dev/null; then DB=mariadb; DUMP=(mariadb-dump); else echo "supported database client not found" >&2; exit 1; fi
db(){ "$DB" --connect-timeout=5 "$@" rerouter; }; scalar(){ db -N -B -e "$1"; }
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
[[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe && $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
[[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE state IN ('planned','pending','running','verifying','compensating')") == 0 ]]
[[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE state IN ('planned','running','compensating') OR remaining_mutations>0") == 0 ]]
[[ $(scalar "SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL") == 0 ]]
[[ $(scalar "SELECT COUNT(*) FROM devices WHERE id=3 AND BINARY name='eMA3' AND BINARY hostname='192.168.200.93' AND ssh_port=22 AND BINARY ssh_host_fingerprint='SHA256:g5STRLrA9f983JajxTP48qew0+w+MJEyIEOnugXmlyA'") == 1 ]]

install -d -m 0700 "$backup_dir"
cp -a /srv/rerouter/rerouter-controller "$backup_dir/controller.previous"
cp -a /srv/rerouter/config.toml "$backup_dir/config.previous.toml"
cp -a /srv/rerouter/.env "$backup_dir/environment.previous"
for marker in RELEASE FRONTEND_RELEASE; do if [[ -e /srv/rerouter/$marker ]]; then cp -a "/srv/rerouter/$marker" "$backup_dir/$marker.previous"; else touch "$backup_dir/$marker.was-absent"; fi; done
mkdir "$backup_dir/frontend.previous"; cp -aL /var/www/rerouter/. "$backup_dir/frontend.previous/"
{
  echo "commit=$commit"; echo "controller_sha256=$controller_sha"; echo "frontend_index_sha256=$frontend_sha"
  echo "old_config_sha256=$current_config_sha"; echo "new_config_sha256=$config_sha"
  echo "migration_count=69"; echo "latest_migration=20260919000200"; echo "operating_mode=observe"; echo "automatic_actions_enabled=false"
  echo "active_reroutes=0"; echo "active_bundles=0"; echo "active_locks=0"
} >"$backup_dir/deployment-audit.manifest"
sha256sum "$backup_dir/controller.previous" "$backup_dir/config.previous.toml" "$backup_dir/environment.previous" >"$backup_dir/manifest.sha256"

web_stage="/var/www/.rerouter-ema3-stage-$commit"; web_previous="/var/www/rerouter.previous-$commit"
binary_stage="/srv/rerouter/.controller-ema3-stage-$commit"; config_stage="/srv/rerouter/.config-ema3-stage-$commit"
[[ ! -e $web_stage && ! -e $web_previous && ! -e $binary_stage && ! -e $config_stage ]]
install -d -m 0755 "$web_stage"; cp -a "$release_dir/frontend/." "$web_stage/"
[[ ! -d /var/www/rerouter/assets ]] || { mkdir -p "$web_stage/assets"; cp -anL /var/www/rerouter/assets/. "$web_stage/assets/"; }
find "$web_stage" -type d -exec chmod 0755 {} +; find "$web_stage" -type f -exec chmod 0644 {} +
install -o root -g root -m 0755 "$release_dir/rerouter-controller" "$binary_stage"
cp --preserve=mode,ownership,timestamps "$release_dir/config.toml" "$config_stage"
chown --reference=/srv/rerouter/config.toml "$config_stage"; chmod --reference=/srv/rerouter/config.toml "$config_stage"

stopped=0; migration_started=0; new_service_started=0; completed=0
rrt_restore_stop(){ systemctl stop rerouter-controller.service || true; }
rrt_restore_database(){ return 0; }
rrt_restore_artifacts(){
  cp -a "$backup_dir/controller.previous" /srv/rerouter/rerouter-controller || return 1
  cp -a "$backup_dir/config.previous.toml" /srv/rerouter/config.toml || return 1
  for marker in RELEASE FRONTEND_RELEASE; do if [[ -e $backup_dir/$marker.previous ]]; then cp -a "$backup_dir/$marker.previous" "/srv/rerouter/$marker" || return 1; else rm -f "/srv/rerouter/$marker" || return 1; fi; done
  if [[ -e $web_previous ]]; then [[ ! -e /var/www/rerouter ]] || mv /var/www/rerouter "$backup_dir/frontend.failed" || return 1; mv "$web_previous" /var/www/rerouter || return 1; fi
}
rrt_restore_start_old(){ systemctl start rerouter-controller.service; }
rrt_restore_old_readiness(){ for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && return 0; sleep 2; done; return 1; }
rrt_restore_failed(){ printf 'RECOVERY FAILED: %s\nOld artifacts/config are in %s; service must remain stopped.\n' "$1" "$backup_dir" | tee "$backup_dir/RECOVERY-FAILED.txt" >&2; systemctl stop rerouter-controller.service || true; }
rrt_recovery_restore_pre_exposure(){ rrt_restore_pre_exposure_sequence || echo "automatic pre-exposure restore failed; manual recovery required" >&2; }
rrt_recovery_restart_unchanged(){ systemctl start rerouter-controller.service || true; }
rrt_recovery_block_post_exposure(){
  systemctl stop rerouter-controller.service || true
  { echo "RECOVERY BLOCKED: the new controller start was attempted and durable lab-mode writes may exist."; echo "New artifacts, config, database, and evidence were retained; old controller was not restarted."; } | tee "$backup_dir/RECOVERY-BLOCKED.txt" >&2
  scalar "SELECT COUNT(*) FROM reroutes" >"$backup_dir/reroute-count.after-failure" || true
  scalar "SELECT COUNT(*) FROM reroute_bundles" >"$backup_dir/bundle-count.after-failure" || true
  scalar "SELECT COUNT(*) FROM audit_logs" >"$backup_dir/audit-count.after-failure" || true
}
recover(){ rc=$?; if ((stopped && !completed)); then rrt_dispatch_recovery "$migration_started" "$new_service_started"; fi; exit "$rc"; }
trap recover EXIT
systemctl stop rerouter-controller.service; stopped=1; migration_started=1

reroutes_before=$(scalar "SELECT COUNT(*) FROM reroutes"); bundles_before=$(scalar "SELECT COUNT(*) FROM reroute_bundles"); locks_before=$(scalar "SELECT COUNT(*) FROM locks")
"${DUMP[@]}" --single-transaction --routines --triggers --databases rerouter | gzip -9 >"$backup_dir/database-evidence.sql.gz"; gzip -t "$backup_dir/database-evidence.sql.gz"
env -u DATABASE_URL -u REROUTER_CONFIG "$binary_stage" --migrate --config "$config_stage" --env-file /srv/rerouter/.env
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]

mv "$binary_stage" /srv/rerouter/rerouter-controller; mv "$config_stage" /srv/rerouter/config.toml
mv /var/www/rerouter "$web_previous"; mv "$web_stage" /var/www/rerouter
printf '%s\n' "$commit" >/srv/rerouter/RELEASE; chmod 0644 /srv/rerouter/RELEASE
printf '%s\n' "$commit" >/srv/rerouter/FRONTEND_RELEASE; chmod 0644 /srv/rerouter/FRONTEND_RELEASE
cmp --silent /srv/rerouter/.env "$backup_dir/environment.previous"
rrt_start_new_service(){ systemctl start rerouter-controller.service; }; rrt_attempt_new_service_start
for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && break; sleep 2; done
systemctl is-active --quiet rerouter-controller.service; curl --max-time 10 -fsS http://127.0.0.1:9277/api/ready >/dev/null; curl --max-time 10 -fsS http://127.0.0.1:9277/api/health >/dev/null
pid=$(systemctl show --property MainPID --value rerouter-controller.service); [[ $pid =~ ^[1-9][0-9]*$ ]]; cmp --silent "/proc/$pid/exe" /srv/rerouter/rerouter-controller
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$controller_sha" && $(sha256sum /var/www/rerouter/index.html | awk '{print $1}') == "$frontend_sha" && $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$config_sha" ]]
cmp --silent /srv/rerouter/.env "$backup_dir/environment.previous"
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
[[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe && $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
[[ $(scalar "SELECT COUNT(*) FROM reroutes") == "$reroutes_before" && $(scalar "SELECT COUNT(*) FROM reroute_bundles") == "$bundles_before" && $(scalar "SELECT COUNT(*) FROM locks") == "$locks_before" ]]
completed=1; trap - EXIT
echo "EMA3 lab release deployed; schema stayed at 69; router actions executed: 0"
