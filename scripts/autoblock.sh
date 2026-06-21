#!/bin/sh
set -eu

ALERT_LOG="${ALERT_LOG:-/var/log/net_guard/alert.log}"
BLOCK_LOG="${BLOCK_LOG:-/var/log/net_guard/block.log}"
VIOLATION_DB="${VIOLATION_DB:-/var/log/net_guard/violations.db}"
OFFSET_FILE="${OFFSET_FILE:-/var/log/net_guard/alert.offset}"
PROC_NODE="${PROC_NODE:-/proc/net_guard}"
PERMABAN_THRESHOLD="${PERMABAN_THRESHOLD:-5}"

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

increment_violation() {
    ip="$1"
    now="$(date +%s)"
    old_count=0
    old_status=ACTIVE

    if [ -s "$VIOLATION_DB" ]; then
        old_record="$(awk -v ip="$ip" '$1 == ip { print $0; exit }' "$VIOLATION_DB")"
        if [ -n "$old_record" ]; then
            old_count="$(printf '%s\n' "$old_record" | awk '{print $2}')"
            old_status="$(printf '%s\n' "$old_record" | awk '{print $3}')"
        fi
    fi

    case "$old_count" in
        ''|*[!0-9]*) old_count=0 ;;
    esac

    new_count=$((old_count + 1))
    new_status="$old_status"
    if [ "$new_count" -ge "$PERMABAN_THRESHOLD" ]; then
        new_status=PERMABANNED
    fi

    tmp="$(mktemp)"
    if [ -s "$VIOLATION_DB" ]; then
        awk -v ip="$ip" '$1 != ip { print }' "$VIOLATION_DB" > "$tmp"
    fi
    printf '%s %s %s %s\n' "$ip" "$new_count" "$new_status" "$now" >> "$tmp"
    cat "$tmp" > "$VIOLATION_DB"
    rm -f "$tmp"

    printf '%s %s %s %s\n' "$old_count" "$new_count" "$old_status" "$new_status"
}

block_ip() {
    ip="$1"
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        sync_proc_add "$ip"
        return 1
    fi

    iptables -A INPUT -s "$ip" -j DROP
    sync_proc_add "$ip"
    return 0
}

if [ "$(id -u)" -ne 0 ]; then
    echo "autoblock: please run as root" >&2
    exit 1
fi

mkdir -p "$(dirname "$ALERT_LOG")" "$(dirname "$BLOCK_LOG")" "$(dirname "$VIOLATION_DB")"
touch "$ALERT_LOG" "$BLOCK_LOG" "$VIOLATION_DB" "$OFFSET_FILE"

current_size="$(wc -c < "$ALERT_LOG" | awk '{print $1}')"
last_offset="$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)"
case "$last_offset" in
    ''|*[!0-9]*) last_offset=0 ;;
esac

if [ "$current_size" -lt "$last_offset" ]; then
    last_offset=0
fi

if [ "$current_size" -eq "$last_offset" ]; then
    exit 0
fi

new_alerts="$(mktemp)"
tail -c +"$((last_offset + 1))" "$ALERT_LOG" > "$new_alerts"
printf '%s\n' "$current_size" > "$OFFSET_FILE"

grep -Eo 'src=([0-9]{1,3}\.){3}[0-9]{1,3}' "$new_alerts" \
    | cut -d= -f2 \
    | while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        valid_ipv4 "$ip" || continue

        result="$(increment_violation "$ip")"
        old_count="$(printf '%s\n' "$result" | awk '{print $1}')"
        new_count="$(printf '%s\n' "$result" | awk '{print $2}')"
        old_status="$(printf '%s\n' "$result" | awk '{print $3}')"
        new_status="$(printf '%s\n' "$result" | awk '{print $4}')"

        if block_ip "$ip"; then
            printf '%s BLOCKED %s\n' "$(date '+%F %T')" "$ip" >> "$BLOCK_LOG"
            echo "autoblock: blocked $ip (violations=$new_count)"
        fi

        if [ "$new_status" = "PERMABANNED" ] && [ "$old_status" != "PERMABANNED" ]; then
            printf '%s PERMABANNED %s violations=%s previous=%s\n' \
                "$(date '+%F %T')" "$ip" "$new_count" "$old_count" >> "$BLOCK_LOG"
            echo "autoblock: permanently banned $ip (violations=$new_count)"
        fi
    done

rm -f "$new_alerts"
