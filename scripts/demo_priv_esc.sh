#!/bin/bash
# ==============================================================================
# SentinelBPF: Privilege Escalation Simulation Demo
#
# SAFETY INVARIANT (AGENTS.md):
# - This script MUST only run in a disposable Linux VM with user permission.
# - Does not modify system credentials or grant real privileges.
# ==============================================================================

set -euo pipefail

echo "=== [SentinelBPF Demo] Privilege Escalation Detection Test ==="
echo ""

echo "[1/2] Invoking unprivileged setuid(0) syscall via Python..."
python3 -c "
import os
try:
    # Attempt to setuid to root (UID 0) as non-root caller
    # Kernel will return EPERM (-1), but eBPF sys_enter_setuid tracepoint catches the attempt!
    os.setuid(0)
except PermissionError:
    print('[+] Caught expected PermissionError from kernel. eBPF hook observed syscall.')
except Exception as e:
    print(f'[-] Unexpected: {e}')
" || true

echo ""
echo "[2/2] Invoking sudo check..."
sudo -n true 2>/dev/null || true

echo ""
echo "Simulation completed. Check SentinelBPF alerts for:"
echo "Rule: privilege_escalation (HIGH) - MITRE T1548.001"
