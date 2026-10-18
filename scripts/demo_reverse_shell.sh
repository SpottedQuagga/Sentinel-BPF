#!/bin/bash
# ==============================================================================
# SentinelBPF: Reverse Shell Simulation Demo
#
# SAFETY INVARIANT (AGENTS.md):
# - This script MUST only run in a disposable Linux VM with user permission.
# - Network traffic is strictly confined to 127.0.0.1 (loopback only).
# - Never connects to external IP addresses.
# ==============================================================================

set -euo pipefail

PORT=4444
TARGET_IP="127.0.0.1"

echo "=== [SentinelBPF Demo] Reverse Shell Detection Test ==="
echo "Note: Before running this demo, ensure config.yaml has:"
echo "      rules.treat_loopback_as_external: true"
echo ""

# Check if nc or python3 is available
if ! command -v nc >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "Error: nc or python3 required for test."
    exit 1
fi

echo "[1/3] Starting temporary listener on $TARGET_IP:$PORT..."
nc -l -p "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

trap 'kill $LISTENER_PID 2>/dev/null || true' EXIT
sleep 0.5

echo "[2/3] Simulating reverse shell connection to $TARGET_IP:$PORT..."
echo "      (Triggering: connect -> dup2(fd, 0/1/2) -> exec sh)"

if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import socket, subprocess, os
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('$TARGET_IP', $PORT))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(['/bin/sh', '-c', 'echo SentinelBPF_Test_Successful; exit 0'])
except Exception as e:
    pass
" || true
else
    # Fallback to nc traditional if available
    nc "$TARGET_IP" "$PORT" -e /bin/sh 2>/dev/null || true
fi

echo "[3/3] Execution completed. Check the SentinelBPF web UI or daemon log for:"
echo "      Rule: reverse_shell (CRITICAL) - MITRE T1059.004"
