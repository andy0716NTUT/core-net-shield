#!/usr/bin/env python3
"""Run Net Guard integration tests from Windows over SSH.

This script intentionally uses only the Python standard library and the
Windows OpenSSH tools (`ssh` and `scp`). If SSH key login is not configured,
OpenSSH will prompt for the SSH password in the console.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REMOTE_TEST = r"""#!/bin/sh
set -eu

TEST_IP_TEMP="{test_ip_temp}"
TEST_IP_PERM="{test_ip_perm}"
BASE="{log_dir}"
PROJECT="{project_path}"
ALERT_LOG="$BASE/alert.log"
BLOCK_LOG="$BASE/block.log"
VIOLATION_DB="$BASE/violations.db"
OFFSET_FILE="$BASE/alert.offset"
AUTOBLOCK="$PROJECT/scripts/autoblock.sh"
CLEANUP="$PROJECT/scripts/cleanup.sh"
UNBAN="$PROJECT/scripts/unban.sh"

reset_ip() {{
    ip="$1"
    while iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; do
        iptables -D INPUT -s "$ip" -j DROP || break
    done
    if [ -w /proc/net_guard ]; then
        printf -- '-%s\n' "$ip" > /proc/net_guard || true
    fi
}}

assert_rule() {{
    ip="$1"
    iptables -C INPUT -s "$ip" -j DROP
}}

assert_no_rule() {{
    ip="$1"
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "ERROR: expected no iptables DROP rule for $ip" >&2
        exit 1
    fi
}}

require_file() {{
    path="$1"
    if [ ! -e "$path" ]; then
        echo "ERROR: missing $path" >&2
        exit 1
    fi
}}

require_file /proc/net_guard
require_file "$AUTOBLOCK"
require_file "$CLEANUP"
require_file "$UNBAN"

mkdir -p "$BASE"
touch "$ALERT_LOG" "$BLOCK_LOG" "$VIOLATION_DB" "$OFFSET_FILE"
chmod +x "$AUTOBLOCK" "$CLEANUP" "$UNBAN"

reset_ip "$TEST_IP_TEMP"
reset_ip "$TEST_IP_PERM"
: > "$ALERT_LOG"
: > "$BLOCK_LOG"
: > "$VIOLATION_DB"
: > "$OFFSET_FILE"

echo "== Net Guard status =="
cat /proc/net_guard

printf '[2026-06-21 00:00:00] [ALERT] PORT SCAN src=%s port_count=22 ports=1,2,3\n' "$TEST_IP_TEMP" >> "$ALERT_LOG"
"$AUTOBLOCK"
assert_rule "$TEST_IP_TEMP"
grep -q "^$TEST_IP_TEMP 1 ACTIVE " "$VIOLATION_DB"
BLOCK_DURATION_SEC=0 "$CLEANUP"
assert_no_rule "$TEST_IP_TEMP"
echo "TEST1 temporary block cleanup: PASS"

i=1
while [ "$i" -le 5 ]; do
    printf '[2026-06-21 00:00:0%s] [ALERT] PORT SCAN src=%s port_count=22 ports=1,2,3\n' "$i" "$TEST_IP_PERM" >> "$ALERT_LOG"
    i=$((i + 1))
done

"$AUTOBLOCK"
assert_rule "$TEST_IP_PERM"
grep -q "^$TEST_IP_PERM 5 PERMABANNED " "$VIOLATION_DB"
BLOCK_DURATION_SEC=0 "$CLEANUP"
assert_rule "$TEST_IP_PERM"
echo "TEST2 permaban survives cleanup: PASS"

"$UNBAN" "$TEST_IP_PERM"
assert_no_rule "$TEST_IP_PERM"
if grep -q "^$TEST_IP_PERM " "$VIOLATION_DB"; then
    echo "ERROR: violation record still exists after unban" >&2
    exit 1
fi
echo "TEST3 manual unban clears rule and db: PASS"

"$UNBAN" "$TEST_IP_TEMP"
assert_no_rule "$TEST_IP_TEMP"
if grep -q "^$TEST_IP_TEMP " "$VIOLATION_DB"; then
    echo "ERROR: temporary test violation record still exists after unban" >&2
    exit 1
fi

reset_ip "$TEST_IP_TEMP"
reset_ip "$TEST_IP_PERM"

echo "== violations.db =="
cat "$VIOLATION_DB"
echo "== block.log =="
cat "$BLOCK_LOG"
echo "== final /proc/net_guard =="
cat /proc/net_guard
echo "ALL TESTS PASSED"
"""


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print(f"\n$ {' '.join(cmd)}")
    completed = subprocess.run(cmd, text=True)
    if check and completed.returncode != 0:
        raise SystemExit(completed.returncode)
    return completed


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"Missing required command: {name}")


def remote_target(user: str, host: str) -> str:
    return f"{user}@{host}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Net Guard integration tests on a remote Ubuntu host from Windows."
    )
    parser.add_argument("--host", default="192.168.64.129", help="Remote Ubuntu host/IP.")
    parser.add_argument("--user", default="andy", help="Remote SSH user.")
    parser.add_argument(
        "--sudo-password",
        default="andy",
        help="Password piped to sudo on the remote host. Do not use on shared terminals.",
    )
    parser.add_argument(
        "--project-path",
        default="/home/andy/core-net-shield",
        help="Remote project path.",
    )
    parser.add_argument(
        "--log-dir",
        default="/var/log/net_guard",
        help="Remote Net Guard log directory.",
    )
    parser.add_argument(
        "--test-ip-temp",
        default="203.0.113.10",
        help="Reserved test IP used for temporary block tests.",
    )
    parser.add_argument(
        "--test-ip-perm",
        default="203.0.113.20",
        help="Reserved test IP used for permanent ban tests.",
    )
    parser.add_argument(
        "--remote-script",
        default="/tmp/net_guard_windows_test.sh",
        help="Temporary remote script path.",
    )
    args = parser.parse_args()

    require_tool("ssh")
    require_tool("scp")

    script = REMOTE_TEST.format(
        test_ip_temp=args.test_ip_temp,
        test_ip_perm=args.test_ip_perm,
        log_dir=args.log_dir,
        project_path=args.project_path,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        local_script = Path(tmpdir) / "net_guard_windows_test.sh"
        local_script.write_text(script, encoding="utf-8", newline="\n")

        target = remote_target(args.user, args.host)
        run(["scp", str(local_script), f"{target}:{args.remote_script}"])

        sudo_command = (
            f"chmod +x {args.remote_script} && "
            f"printf '%s\\n' '{args.sudo_password}' | sudo -S -p '' {args.remote_script}; "
            "rc=$?; "
            f"rm -f {args.remote_script}; "
            "exit $rc"
        )
        run(["ssh", target, sudo_command])

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
