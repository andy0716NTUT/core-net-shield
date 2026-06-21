#!/bin/sh
set -eu

BLOCK_LOG="${BLOCK_LOG:-/var/log/net_guard/block.log}"
VIOLATION_DB="${VIOLATION_DB:-/var/log/net_guard/violations.db}"
PROC_NODE="${PROC_NODE:-/proc/net_guard}"

usage() {
    echo "Usage: $0 <ip>|--all"
}

valid_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) {
                    exit 1
                }
            }
        }'
}

sync_proc_remove() {
    ip="$1"
    if [ -w "$PROC_NODE" ]; then
        printf -- '-%s\n' "$ip" > "$PROC_NODE" || true
    fi
}

remove_iptables_drop() {
    ip="$1"
    while iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; do
        iptables -D INPUT -s "$ip" -j DROP || break
    done
}

clear_violation() {
    ip="$1"
    tmp="$(mktemp)"
    if [ -s "$VIOLATION_DB" ]; then
        awk -v ip="$ip" '$1 != ip { print }' "$VIOLATION_DB" > "$tmp"
    fi
    cat "$tmp" > "$VIOLATION_DB"
    rm -f "$tmp"
}

unban_ip() {
    ip="$1"
    valid_ipv4 "$ip"
    remove_iptables_drop "$ip"
    sync_proc_remove "$ip"
    clear_violation "$ip"
    printf '%s MANUAL_UNBAN %s\n' "$(date '+%F %T')" "$ip" >> "$BLOCK_LOG"
    echo "unban: cleared $ip"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "unban: please run as root" >&2
    exit 1
fi

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 1
fi

mkdir -p "$(dirname "$BLOCK_LOG")" "$(dirname "$VIOLATION_DB")"
touch "$BLOCK_LOG" "$VIOLATION_DB"

case "$1" in
    --all)
        ips="$(mktemp)"
        if [ -s "$VIOLATION_DB" ]; then
            awk '{ print $1 }' "$VIOLATION_DB" >> "$ips"
        fi
        if [ -s "$BLOCK_LOG" ]; then
            awk '/ BLOCKED | PERMABANNED / { print $4 }' "$BLOCK_LOG" >> "$ips"
        fi
        sort -u "$ips" | while IFS= read -r ip; do
            [ -n "$ip" ] || continue
            valid_ipv4 "$ip" || continue
            remove_iptables_drop "$ip"
            sync_proc_remove "$ip"
            printf '%s MANUAL_UNBAN %s\n' "$(date '+%F %T')" "$ip" >> "$BLOCK_LOG"
        done
        : > "$VIOLATION_DB"
        rm -f "$ips"
        echo "unban: cleared all tracked IPs"
        ;;
    *)
        unban_ip "$1"
        ;;
esac
