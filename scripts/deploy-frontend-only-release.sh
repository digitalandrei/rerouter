#!/usr/bin/env bash
# Prepared frontend-only deployment. Never stops/restarts the controller or mutates the database.
set -euo pipefail
usage(){ echo "usage: $0 --frontend-dir DIR --commit SHA --expected-controller-sha256 SHA --expected-config-sha256 SHA --expected-current-frontend-sha256 SHA --expected-release VALUE --expected-frontend-release VALUE --backup-dir DIR" >&2; exit 64; }
frontend_dir= commit= controller_sha= config_sha= current_frontend_sha= expected_release= expected_frontend_release= backup_dir=
while (($#)); do case "$1" in
  --frontend-dir) frontend_dir=$2;; --commit) commit=$2;; --expected-controller-sha256) controller_sha=$2;;
  --expected-config-sha256) config_sha=$2;; --expected-release) expected_release=$2;;
  --expected-current-frontend-sha256) current_frontend_sha=$2;;
  --expected-frontend-release) expected_frontend_release=$2;; --backup-dir) backup_dir=$2;; *) usage;; esac; shift 2; done
[[ -n $frontend_dir && -n $commit && -n $controller_sha && -n $config_sha && -n $current_frontend_sha && -n $expected_release && -n $expected_frontend_release && -n $backup_dir ]] || usage
[[ $EUID == 0 && $(hostname) == ematrix && $commit =~ ^[0-9a-f]{40}$ && $controller_sha =~ ^[0-9a-f]{64}$ && $config_sha =~ ^[0-9a-f]{64}$ && $current_frontend_sha =~ ^[0-9a-f]{64}$ ]]
[[ -r $frontend_dir/index.html && ! -e $backup_dir ]]
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$controller_sha" ]]
[[ $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$config_sha" ]]
[[ $(sha256sum /var/www/rerouter/index.html | awk '{print $1}') == "$current_frontend_sha" ]]
[[ $(tr -d '\n' </srv/rerouter/RELEASE) == "$expected_release" ]]
[[ $(tr -d '\n' </srv/rerouter/FRONTEND_RELEASE) == "$expected_frontend_release" ]]
systemctl is-active --quiet rerouter-controller.service
pid_before=$(systemctl show --property MainPID --value rerouter-controller.service); [[ $pid_before =~ ^[1-9][0-9]*$ ]]
[[ $(sha256sum "/proc/$pid_before/exe" | awk '{print $1}') == "$controller_sha" ]]
if command -v mysql >/dev/null; then DB=mysql; else DB=mariadb; fi
db(){ "$DB" --connect-timeout=5 "$@" rerouter; }; scalar(){ db -N -B -e "$1"; }
assert_runtime(){
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE id=1 AND state='succeeded' AND lifecycle_state='active' AND total_actions=8 AND completed_actions=8 AND remaining_mutations=8 AND recovery_claim_token IS NULL") == 1 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroute_bundles WHERE state IN ('planned','running','compensating') OR lifecycle_state IN ('recovery_claimed','recovery_running') OR recovery_claim_token IS NOT NULL") == 0 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE bundle_id=1 AND state='succeeded' AND mutation_effect='changed'") == 8 ]]
  [[ $(scalar "SELECT COUNT(*) FROM reroutes WHERE state IN ('planned','pending','running','verifying','compensating')") == 0 ]]
  [[ $(scalar "SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL") == 0 ]]
}
assert_runtime
db_hash_before=$(db -N -B -e "SELECT id,state,lifecycle_state,total_actions,completed_actions,remaining_mutations,COALESCE(recovery_claim_token,'') FROM reroute_bundles ORDER BY id; SELECT id,state,mutation_effect,COALESCE(rollback_of_reroute_id,0) FROM reroutes ORDER BY id; SELECT id,scope,scope_ref,COALESCE(cleared_at,'') FROM locks ORDER BY id" | sha256sum | awk '{print $1}')
install -d -m 0700 "$backup_dir"; mkdir "$backup_dir/frontend.previous"; cp -aL /var/www/rerouter/. "$backup_dir/frontend.previous/"; cp -a /srv/rerouter/FRONTEND_RELEASE "$backup_dir/FRONTEND_RELEASE.previous"
stage="/var/www/.rerouter-frontend-stage-$commit"; previous="/var/www/rerouter.previous-$commit"; [[ ! -e $stage && ! -e $previous ]]
install -d -m 0755 "$stage"; cp -a "$frontend_dir/." "$stage/"; find "$stage" -type d -exec chmod 0755 {} +; find "$stage" -type f -exec chmod 0644 {} +
completed=0
restore(){ rc=$?; if (( ! completed )); then if [[ -e $previous ]]; then [[ ! -e /var/www/rerouter ]] || mv /var/www/rerouter "$backup_dir/frontend.failed"; mv "$previous" /var/www/rerouter; fi; cp -a "$backup_dir/FRONTEND_RELEASE.previous" /srv/rerouter/FRONTEND_RELEASE; fi; exit "$rc"; }
trap restore EXIT
mv /var/www/rerouter "$previous"; mv "$stage" /var/www/rerouter
printf '%s\n' "$commit" >/srv/rerouter/FRONTEND_RELEASE; chmod 0644 /srv/rerouter/FRONTEND_RELEASE
diff -qr /var/www/rerouter "$frontend_dir" >/dev/null
[[ $(tr -d '\n' </srv/rerouter/FRONTEND_RELEASE) == "$commit" ]]
[[ $(sha256sum /srv/rerouter/rerouter-controller | awk '{print $1}') == "$controller_sha" && $(sha256sum /srv/rerouter/config.toml | awk '{print $1}') == "$config_sha" ]]
[[ $(tr -d '\n' </srv/rerouter/RELEASE) == "$expected_release" ]]
pid_after=$(systemctl show --property MainPID --value rerouter-controller.service); [[ $pid_after == "$pid_before" ]]; systemctl is-active --quiet rerouter-controller.service
assert_runtime
db_hash_after=$(db -N -B -e "SELECT id,state,lifecycle_state,total_actions,completed_actions,remaining_mutations,COALESCE(recovery_claim_token,'') FROM reroute_bundles ORDER BY id; SELECT id,state,mutation_effect,COALESCE(rollback_of_reroute_id,0) FROM reroutes ORDER BY id; SELECT id,scope,scope_ref,COALESCE(cleared_at,'') FROM locks ORDER BY id" | sha256sum | awk '{print $1}')
[[ $db_hash_after == "$db_hash_before" ]]
completed=1; trap - EXIT
echo "frontend-only release deployed; controller PID, config, RELEASE, bundle #1, reroutes, and locks unchanged"
