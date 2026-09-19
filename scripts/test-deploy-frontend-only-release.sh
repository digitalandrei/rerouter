#!/usr/bin/env bash
set -euo pipefail
script=$(dirname "$0")/deploy-frontend-only-release.sh
grep -Fq 'pid_after' "$script"
grep -Fq '[[ $pid_after == "$pid_before" ]]' "$script"
grep -Fq 'db_hash_after == "$db_hash_before"' "$script"
grep -Fq "total_actions=8" "$script"
grep -Fq "remaining_mutations=8" "$script"
grep -Fq 'diff -qr /var/www/rerouter "$frontend_dir"' "$script"
grep -Fq 'sha256sum /var/www/rerouter/index.html' "$script"
grep -Fq 'if [[ -e $previous ]]; then' "$script"
grep -Fq '[[ ! -e /var/www/rerouter ]] || mv /var/www/rerouter' "$script"
! grep -Eq 'systemctl (stop|start|restart)|--migrate|/api/.+(preview|apply|revert)|INSERT |UPDATE |DELETE ' "$script"
echo "frontend-only deployment invariants: ok"
