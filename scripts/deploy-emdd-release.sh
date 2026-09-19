#!/usr/bin/env bash
# Prepared only: run on ematrix after artifact, SQL, hashes, and rollback review.
set -euo pipefail
source "$(dirname "$0")/deploy-recovery-policy.sh"
usage(){ echo "usage: $0 --release-dir DIR --commit SHA --controller-sha256 SHA --frontend-sha256 SHA --conversion-sql FILE --conversion-sha256 SHA --backup-dir DIR" >&2; exit 64; }
release_dir= commit= controller_sha= frontend_sha= conversion_sql= conversion_sha= backup_dir=
while (($#)); do case "$1" in --release-dir) release_dir=$2;; --commit) commit=$2;; --controller-sha256) controller_sha=$2;; --frontend-sha256) frontend_sha=$2;; --conversion-sql) conversion_sql=$2;; --conversion-sha256) conversion_sha=$2;; --backup-dir) backup_dir=$2;; *) usage;; esac; shift 2; done
[[ -n $release_dir && -n $commit && -n $controller_sha && -n $frontend_sha && -n $conversion_sql && -n $conversion_sha && -n $backup_dir ]] || usage
[[ $(hostname) == ematrix && $commit =~ ^[0-9a-f]{40}$ && $controller_sha =~ ^[0-9a-f]{64}$ && $frontend_sha =~ ^[0-9a-f]{64}$ && $conversion_sha =~ ^[0-9a-f]{64}$ ]]
[[ -x $release_dir/rerouter-controller && -r $release_dir/frontend/index.html && -r $conversion_sql && ! -e $backup_dir ]]
[[ $(sha256sum "$release_dir/rerouter-controller"|awk '{print $1}') == "$controller_sha" ]]
[[ $(sha256sum "$release_dir/frontend/index.html"|awk '{print $1}') == "$frontend_sha" ]]
[[ $(sha256sum "$conversion_sql"|awk '{print $1}') == "$conversion_sha" ]]

if command -v mysql >/dev/null && command -v mysqldump >/dev/null; then DB=mysql; DUMP=(mysqldump --no-tablespaces); elif command -v mariadb >/dev/null && command -v mariadb-dump >/dev/null; then DB=mariadb; DUMP=(mariadb-dump); else echo "supported database client not found" >&2; exit 1; fi
db(){ "$DB" --connect-timeout=5 "$@" rerouter; }; scalar(){ db -N -B -e "$1"; }
[[ $(scalar "SELECT VERSION()") =~ ^8\.4\. || $DB == mariadb ]]
[[ $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260917000700 && $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 67 ]]
[[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe && $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
[[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE state IN ('planned','pending','running','verifying','compensating')") == 0 ]]
[[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE state IN ('planned','running','compensating')") == 0 && $(scalar "SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL") == 0 ]]

install -d -m 0700 "$backup_dir"
cp -a /srv/rerouter/.env "$backup_dir/environment.previous"; cp -a /srv/rerouter/config.toml "$backup_dir/config.previous.toml"; cp -a /srv/rerouter/rerouter-controller "$backup_dir/controller.previous"
if [[ -e /srv/rerouter/RELEASE ]]; then cp -a /srv/rerouter/RELEASE "$backup_dir/RELEASE.previous"; else touch "$backup_dir/RELEASE.was-absent"; fi
mkdir "$backup_dir/frontend.previous"; cp -aL /var/www/rerouter/. "$backup_dir/frontend.previous/"
sha256sum "$backup_dir"/controller.previous "$backup_dir"/environment.previous "$backup_dir"/config.previous.toml >"$backup_dir/manifest.sha256"

web_stage="/var/www/.rerouter-stage-$commit"; web_previous="/var/www/rerouter.previous-$commit"; binary_stage="/srv/rerouter/.controller-stage-$commit"
[[ ! -e $web_stage && ! -e $web_previous && ! -e $binary_stage ]]; install -d -m 0755 "$web_stage"; cp -a "$release_dir/frontend/." "$web_stage/"
[[ ! -d /var/www/rerouter/assets ]] || cp -anL /var/www/rerouter/assets/. "$web_stage/assets/"
find "$web_stage" -type d -exec chmod 0755 {} +; find "$web_stage" -type f -exec chmod 0644 {} +
install -o root -g root -m 0755 "$release_dir/rerouter-controller" "$binary_stage"

stopped=0; migration_started=0; new_service_started=0; completed=0
restore_pre_exposure(){
  echo "release failed before the new service was exposed; restoring the stopped-window application snapshot" >&2
  rrt_restore_pre_exposure_sequence
}
rrt_restore_stop(){ systemctl stop rerouter-controller.service || true; }
rrt_restore_database(){
  "$DB" --connect-timeout=5 -e "DROP DATABASE IF EXISTS rerouter" || return 1
  gzip -dc "$backup_dir/database.stopped.sql.gz" | "$DB" --connect-timeout=5 || return 1
}
rrt_restore_artifacts(){
  cp -a "$backup_dir/controller.previous" /srv/rerouter/rerouter-controller || return 1
  chown root:root /srv/rerouter/rerouter-controller || return 1; chmod 0755 /srv/rerouter/rerouter-controller || return 1
  if [[ -e $backup_dir/RELEASE.previous ]]; then cp -a "$backup_dir/RELEASE.previous" /srv/rerouter/RELEASE || return 1; else rm -f /srv/rerouter/RELEASE || return 1; fi
  if [[ -e $web_previous ]]; then mv /var/www/rerouter "$backup_dir/frontend.failed" || return 1; mv "$web_previous" /var/www/rerouter || return 1; fi
}
rrt_restore_start_old(){ systemctl start rerouter-controller.service; }
rrt_restore_old_readiness(){ for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && return 0; sleep 2; done; return 1; }
rrt_restore_failed(){ printf 'RECOVERY FAILED: %s\nUse database.stopped.sql.gz and matching old artifacts; application service must remain stopped.\n' "$1" | tee "$backup_dir/RECOVERY-FAILED.txt" >&2; systemctl stop rerouter-controller.service || true; }
block_post_exposure(){
  systemctl stop rerouter-controller.service || true
  { echo "RECOVERY BLOCKED: the new service was started and may have accepted durable writes."; echo "Database was not rolled back. Old binary was not restarted against migration 69."; echo "Inspect reroute/preset/audit deltas and choose a forward fix or explicitly restore database.stopped.sql.gz."; } | tee "$backup_dir/RECOVERY-BLOCKED.txt" >&2
  scalar "SELECT COUNT(*) FROM reroutes" >"$backup_dir/reroute-count.after-failure" || true
  scalar "SELECT COUNT(*) FROM mitigation_presets" >"$backup_dir/definition-count.after-failure" || true
}
rrt_recovery_block_post_exposure(){ block_post_exposure; }
rrt_recovery_restore_pre_exposure(){ if ! restore_pre_exposure; then echo "automatic pre-exposure restore failed; manual recovery required" >&2; fi; }
rrt_recovery_restart_unchanged(){ echo "pre-migration failure; restarting unchanged old service" >&2; systemctl start rerouter-controller.service || true; }
recover(){ rc=$?; if ((stopped && !completed)); then rrt_dispatch_recovery "$migration_started" "$new_service_started"; fi; exit "$rc"; }
trap recover EXIT
systemctl stop rerouter-controller.service; stopped=1

# Capture the mutable detection truth under the stopped window. Migration may add columns,
# so compare only the 67-baseline condition/flag fields plus current state.
rule_query="SELECT r.id,r.name,r.interface_id,r.device_id,r.metric,r.metric_aggregation,r.flow_direction,r.flow_protocol,r.flow_port,r.flow_port_kind,r.operator,r.threshold_value,r.duration_seconds,r.consecutive_samples,r.severity,r.enabled,r.automatic_reroute_enabled,r.manual_apply_enabled,r.reroute_template_id,rs.current_state FROM rules r LEFT JOIN rule_states rs ON rs.rule_id=r.id ORDER BY r.id"
db -N -B -e "$rule_query" >"$backup_dir/rules.stopped.tsv"; [[ $(wc -l <"$backup_dir/rules.stopped.tsv") == 13 ]]
reroutes_before=$(scalar "SELECT COUNT(*) FROM reroutes"); definitions_before=$(scalar "SELECT COUNT(*) FROM mitigation_presets")
"${DUMP[@]}" --single-transaction --routines --triggers --databases rerouter | gzip -9 >"$backup_dir/database.stopped.sql.gz"
gzip -t "$backup_dir/database.stopped.sql.gz"

migration_started=1
env -u DATABASE_URL -u REROUTER_CONFIG "$binary_stage" --migrate --config /srv/rerouter/config.toml --env-file /srv/rerouter/.env
[[ $(scalar "SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1") == 69 && $(scalar "SELECT MAX(version) FROM _sqlx_migrations WHERE success=1") == 20260919000200 ]]
db <"$conversion_sql"
db -N -B -e "$rule_query" >"$backup_dir/rules.after-conversion.tsv"; cmp --silent "$backup_dir/rules.stopped.tsv" "$backup_dir/rules.after-conversion.tsv"

mv "$binary_stage" /srv/rerouter/rerouter-controller; chown root:root /srv/rerouter/rerouter-controller; chmod 0755 /srv/rerouter/rerouter-controller
cmp --silent /srv/rerouter/.env "$backup_dir/environment.previous"; cmp --silent /srv/rerouter/config.toml "$backup_dir/config.previous.toml"
mv /var/www/rerouter "$web_previous"; mv "$web_stage" /var/www/rerouter
printf '%s\n' "$commit" >/srv/rerouter/RELEASE; chmod 0644 /srv/rerouter/RELEASE
rrt_start_new_service(){ systemctl start rerouter-controller.service; }
rrt_attempt_new_service_start
for _ in $(seq 1 30); do systemctl is-active --quiet rerouter-controller.service && curl --max-time 3 -fsS http://127.0.0.1:9277/api/ready >/dev/null && break; sleep 2; done
systemctl is-active --quiet rerouter-controller.service; curl --max-time 10 -fsS http://127.0.0.1:9277/api/ready >/dev/null; curl --max-time 10 -fsS http://127.0.0.1:9277/api/health >/dev/null
pid=$(systemctl show --property MainPID --value rerouter-controller.service); [[ $pid =~ ^[1-9][0-9]*$ ]]; cmp --silent "/proc/$pid/exe" /srv/rerouter/rerouter-controller
[[ $(sha256sum /srv/rerouter/rerouter-controller|awk '{print $1}') == "$controller_sha" && $(sha256sum /var/www/rerouter/index.html|awk '{print $1}') == "$frontend_sha" ]]
[[ $(scalar "SELECT value FROM system_settings WHERE \`key\`='operating_mode'") == observe && $(scalar "SELECT value FROM system_settings WHERE \`key\`='automatic_actions_enabled'") == false ]]
[[ $(scalar "SELECT COUNT(*) FROM reroutes") == "$reroutes_before" ]]
definitions_after=$(scalar "SELECT COUNT(*) FROM mitigation_presets"); completed=1; trap - EXIT
printf 'Definition count: %s -> %s; executed actions during release: 0; pending router prerequisites: 2.\n' "$definitions_before" "$definitions_after"
