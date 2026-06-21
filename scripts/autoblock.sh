#!/bin/sh
set -eu

ALERT_LOG="${ALERT_LOG:-/var/log/net_guard/alert.log}"
BLOCK_LOG="${BLOCK_LOG:-/var/log/net_guard/block.log}"
PROC_NODE="${PROC_NODE:-/proc/net_guard}"

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

sync_proc_add() {
    ip="$1"
    if [ -w "$PROC_NODE" ]; then
        printf '+%s\n' "$ip" > "$PROC_NODE" || true
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "autoblock: please run as root" >&2
    exit 1
fi

mkdir -p "$(dirname "$ALERT_LOG")" "$(dirname "$BLOCK_LOG")"
touch "$ALERT_LOG" "$BLOCK_LOG"

grep -Eo 'src=([0-9]{1,3}\.){3}[0-9]{1,3}' "$ALERT_LOG" \
    | cut -d= -f2 \
    | sort -u \
    | while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        valid_ipv4 "$ip" || continue

        if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            sync_proc_add "$ip"
            continue
        fi

        if iptables -A INPUT -s "$ip" -j DROP; then
            printf '%s BLOCKED %s\n' "$(date '+%F %T')" "$ip" >> "$BLOCK_LOG"
            sync_proc_add "$ip"
            echo "autoblock: blocked $ip"
        fi
    done
