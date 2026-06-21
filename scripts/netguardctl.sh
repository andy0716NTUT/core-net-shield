#!/bin/sh
set -eu

PROC_NODE="${PROC_NODE:-/proc/net_guard}"
LOG_DIR="${LOG_DIR:-/var/log/net_guard}"
PROJECT_DIR="${PROJECT_DIR:-/home/andy/core-net-shield}"
ALERT_LOG="${ALERT_LOG:-$LOG_DIR/alert.log}"
BLOCK_LOG="${BLOCK_LOG:-$LOG_DIR/block.log}"
VIOLATION_DB="${VIOLATION_DB:-$LOG_DIR/violations.db}"
OFFSET_FILE="${OFFSET_FILE:-$LOG_DIR/alert.offset}"
MODULE_NAME="${MODULE_NAME:-net_guard}"
KERNEL_DIR="${KERNEL_DIR:-$PROJECT_DIR/kernel}"
SCRIPT_DIR="${SCRIPT_DIR:-$PROJECT_DIR/scripts}"

usage() {
    printf '%s\n' \
        'Usage: netguardctl <command> [args]' \
        '' \
        'Commands:' \
        '  status                Show /proc/net_guard status' \
        '  alerts [n]            Show last n alert.log lines (default: 20)' \
        '  blocks [n]            Show last n block.log lines (default: 20)' \
        '  violations            Show violation database' \
        '  banned                Show currently blocked IPs from /proc/net_guard' \
        '  ban <ip>              Manually block an IP and sync /proc' \
        '  unban <ip>            Manually unban one IP and clear its violation record' \
        '  unban-all             Manually unban all tracked IPs' \
        '  run-autoblock         Run autoblock.sh once' \
        '  run-cleanup           Run cleanup.sh once' \
        '  logs                  Show all Net Guard log file paths' \
        '  reset-logs            Truncate alert/block/violation/offset logs' \
        '  load                  Build/load module through kernel Makefile' \
        '  unload                Unload module through kernel Makefile' \
        '  reload                Unload then load module' \
        '  cron                  Show root crontab Net Guard entries' \
        '  install-cron          Install root crontab Net Guard entries' \
        '  remove-cron           Remove root crontab Net Guard entries' \
        '  help                  Show this help'
}

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "netguardctl: command requires root; retry with sudo" >&2
        exit 1
    fi
}

ensure_log_dir() {
    mkdir -p "$LOG_DIR"
    touch "$ALERT_LOG" "$BLOCK_LOG" "$VIOLATION_DB" "$OFFSET_FILE"
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

sync_proc_add() {
    ip="$1"
    if [ -w "$PROC_NODE" ]; then
        printf '+%s\n' "$ip" > "$PROC_NODE" || true
    fi
}

sync_proc_remove() {
    ip="$1"
    if [ -w "$PROC_NODE" ]; then
        printf -- '-%s\n' "$ip" > "$PROC_NODE" || true
    fi
}

tail_lines() {
    file="$1"
    count="${2:-20}"
    case "$count" in
        ''|*[!0-9]*) count=20 ;;
    esac
    if [ -s "$file" ]; then
        tail -n "$count" "$file"
    else
        echo "(empty) $file"
    fi
}

show_banned() {
    if [ ! -r "$PROC_NODE" ]; then
        echo "netguardctl: $PROC_NODE is not readable; is the module loaded?" >&2
        exit 1
    fi

    awk '
        /^Currently Blocked IPs:/ { in_list = 1; next }
        /^=+/ { if (in_list) exit }
        in_list {
            gsub(/^ +| +$/, "", $0)
            if ($0 != "" && $0 != "(none)") print $0
        }' "$PROC_NODE"
}

manual_ban() {
    ip="$1"
    valid_ipv4 "$ip"
    ensure_log_dir

    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        sync_proc_add "$ip"
        echo "netguardctl: already blocked $ip"
        return
    fi

    iptables -A INPUT -s "$ip" -j DROP
    sync_proc_add "$ip"
    printf '%s MANUAL_BLOCK %s\n' "$(date '+%F %T')" "$ip" >> "$BLOCK_LOG"
    echo "netguardctl: blocked $ip"
}

install_cron() {
    tmp="$(mktemp)"
    crontab -l 2>/dev/null \
        | grep -v "$SCRIPT_DIR/autoblock.sh" \
        | grep -v "$SCRIPT_DIR/cleanup.sh" > "$tmp" || true

    printf '%s\n' "* * * * * $SCRIPT_DIR/autoblock.sh >> $LOG_DIR/autoblock_cron.log 2>&1" >> "$tmp"
    printf '%s\n' "*/5 * * * * $SCRIPT_DIR/cleanup.sh >> $LOG_DIR/cleanup_cron.log 2>&1" >> "$tmp"
    crontab "$tmp"
    rm -f "$tmp"
    echo "netguardctl: installed root crontab entries"
}

remove_cron() {
    tmp="$(mktemp)"
    crontab -l 2>/dev/null \
        | grep -v "$SCRIPT_DIR/autoblock.sh" \
        | grep -v "$SCRIPT_DIR/cleanup.sh" > "$tmp" || true
    crontab "$tmp"
    rm -f "$tmp"
    echo "netguardctl: removed root crontab entries"
}

cmd="${1:-help}"
case "$cmd" in
    status)
        cat "$PROC_NODE"
        ;;
    alerts)
        tail_lines "$ALERT_LOG" "${2:-20}"
        ;;
    blocks)
        tail_lines "$BLOCK_LOG" "${2:-20}"
        ;;
    violations)
        if [ -s "$VIOLATION_DB" ]; then
            cat "$VIOLATION_DB"
        else
            echo "(no violations)"
        fi
        ;;
    banned)
        show_banned
        ;;
    ban)
        need_root
        [ "$#" -eq 2 ] || { echo "Usage: netguardctl ban <ip>" >&2; exit 1; }
        manual_ban "$2"
        ;;
    unban)
        need_root
        [ "$#" -eq 2 ] || { echo "Usage: netguardctl unban <ip>" >&2; exit 1; }
        "$SCRIPT_DIR/unban.sh" "$2"
        ;;
    unban-all)
        need_root
        "$SCRIPT_DIR/unban.sh" --all
        ;;
    run-autoblock)
        need_root
        "$SCRIPT_DIR/autoblock.sh"
        ;;
    run-cleanup)
        need_root
        "$SCRIPT_DIR/cleanup.sh"
        ;;
    logs)
        printf 'alert.log      %s\n' "$ALERT_LOG"
        printf 'block.log      %s\n' "$BLOCK_LOG"
        printf 'violations.db  %s\n' "$VIOLATION_DB"
        printf 'alert.offset   %s\n' "$OFFSET_FILE"
        ;;
    reset-logs)
        need_root
        ensure_log_dir
        : > "$ALERT_LOG"
        : > "$BLOCK_LOG"
        : > "$VIOLATION_DB"
        : > "$OFFSET_FILE"
        echo "netguardctl: reset logs"
        ;;
    load)
        need_root
        make -C "$KERNEL_DIR" load
        ;;
    unload)
        need_root
        make -C "$KERNEL_DIR" unload
        ;;
    reload)
        need_root
        make -C "$KERNEL_DIR" unload || true
        make -C "$KERNEL_DIR" load
        ;;
    cron)
        need_root
        crontab -l 2>/dev/null | grep -E "$SCRIPT_DIR/(autoblock|cleanup)\.sh" || echo "(no Net Guard cron entries)"
        ;;
    install-cron)
        need_root
        install_cron
        ;;
    remove-cron)
        need_root
        remove_cron
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        echo "netguardctl: unknown command: $cmd" >&2
        usage >&2
        exit 1
        ;;
esac
