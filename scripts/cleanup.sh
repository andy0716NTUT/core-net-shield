#!/bin/sh
set -eu

BLOCK_LOG="${BLOCK_LOG:-/var/log/net_guard/block.log}"
PROC_NODE="${PROC_NODE:-/proc/net_guard}"
BLOCK_DURATION_SEC="${BLOCK_DURATION_SEC:-1800}"

sync_proc_remove() {
    ip="$1"
    if [ -w "$PROC_NODE" ]; then
        printf -- '-%s\n' "$ip" > "$PROC_NODE" || true
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "cleanup: please run as root" >&2
    exit 1
fi

mkdir -p "$(dirname "$BLOCK_LOG")"
touch "$BLOCK_LOG"

now="$(date +%s)"
tmp="$(mktemp)"

while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        *" BLOCKED "*)
            case "$line" in
                *" UNBLOCKED"*)
                    printf '%s\n' "$line" >> "$tmp"
                    continue
                    ;;
            esac

            block_date="$(printf '%s\n' "$line" | awk '{print $1}')"
            block_time="$(printf '%s\n' "$line" | awk '{print $2}')"
            ip="$(printf '%s\n' "$line" | awk '{print $4}')"
            block_epoch="$(date -d "$block_date $block_time" +%s 2>/dev/null || echo 0)"

            if [ "$block_epoch" -gt 0 ] && [ $((now - block_epoch)) -ge "$BLOCK_DURATION_SEC" ]; then
                if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
                    iptables -D INPUT -s "$ip" -j DROP || true
                fi
                sync_proc_remove "$ip"
                printf '%s | %s UNBLOCKED\n' "$line" "$(date '+%F %T')" >> "$tmp"
                echo "cleanup: unblocked $ip"
            else
                printf '%s\n' "$line" >> "$tmp"
            fi
            ;;
        *)
            printf '%s\n' "$line" >> "$tmp"
            ;;
    esac
done < "$BLOCK_LOG"

cat "$tmp" > "$BLOCK_LOG"
rm -f "$tmp"
