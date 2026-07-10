#!/bin/sh
set -eu

destination=${1:-/etc/nginx/snippets/rerouter-cloudflare-origin-ranges.conf}
ranges=$(mktemp)
output=$(mktemp)
staged=
cleanup() {
    rm -f "$ranges" "$output"
    if [ -n "$staged" ]; then
        rm -f "$staged"
    fi
}
trap cleanup EXIT HUP INT TERM

curl -LfsS --max-time 20 https://www.cloudflare.com/ips-v4 >"$ranges"
curl -LfsS --max-time 20 https://www.cloudflare.com/ips-v6 >>"$ranges"

{
    printf '%s\n' '# Generated from Cloudflare official IP lists. Do not edit by hand.'
    while IFS= read -r cidr; do
        case "$cidr" in
            ''|*[!0-9A-Fa-f:./]*)
                printf 'invalid Cloudflare CIDR: %s\n' "$cidr" >&2
                exit 1
                ;;
        esac
        printf 'allow %s;\n' "$cidr"
    done <"$ranges"
} >"$output"

test "$(wc -l <"$output")" -gt 20

case "$destination" in
    */*) destination_dir=${destination%/*} ;;
    *) destination_dir=. ;;
esac
if [ ! -d "$destination_dir" ]; then
    install -d -m 0755 "$destination_dir"
fi
staged=$(mktemp "$destination_dir/.rerouter-cloudflare-ranges.XXXXXX")
install -m 0644 "$output" "$staged"
mv -f "$staged" "$destination"
staged=
printf 'wrote %s\n' "$destination"
