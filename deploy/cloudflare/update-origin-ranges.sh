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

# Structural check on top of the charset check: exactly one '/', a plausible
# address part, and an in-range prefix length. Rejects e.g. 999.1.2.3/8 and '1.2.3.4//'.
valid_cidr() {
    case "$1" in
        */*/*|*/|/*) return 1 ;;
        */*) : ;;
        *) return 1 ;;   # Cloudflare publishes CIDRs, not bare addresses
    esac
    addr=${1%/*}
    plen=${1##*/}
    case "$plen" in ''|*[!0-9]*) return 1 ;; esac
    case "$addr" in
        *:*)   # IPv6: charset already limited; bound the prefix
            [ "$plen" -le 128 ] || return 1 ;;
        *)     # IPv4: four dotted octets 0-255
            [ "$plen" -le 32 ] || return 1
            # A trailing dot does not yield an empty final field under POSIX
            # word-splitting, so reject dot-boundary addresses before splitting.
            case "$addr" in .*|*.) return 1 ;; esac
            oldifs=$IFS; IFS=.
            set -- $addr
            IFS=$oldifs
            [ "$#" -eq 4 ] || return 1
            for o in "$1" "$2" "$3" "$4"; do
                case "$o" in ''|*[!0-9]*) return 1 ;; esac
                [ "$o" -le 255 ] || return 1
            done ;;
    esac
    return 0
}

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
        if ! valid_cidr "$cidr"; then
            printf 'invalid Cloudflare CIDR: %s\n' "$cidr" >&2
            exit 1
        fi
        printf 'allow %s;\n' "$cidr"
    done <"$ranges"
} >"$output"

test "$(wc -l <"$output")" -gt 20

if command -v nginx >/dev/null 2>&1; then
    testconf=$(mktemp) || exit 1
    printf 'events{}\nhttp{ server{ include %s; } }\n' "$output" >"$testconf"
    if ! nginx -t -c "$testconf" >/dev/null 2>&1; then
        printf 'generated ranges failed nginx -t; refusing to install\n' >&2
        rm -f "$testconf"
        exit 1
    fi
    rm -f "$testconf"
fi

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
