#!/bin/bash
# ==============================================================================
# SentinelBPF: Sensitive File Tampering Simulation Demo
#
# SAFETY INVARIANT (AGENTS.md):
# - Never modify /etc/passwd, /etc/shadow, or /etc/sudoers.
# - Open with O_WRONLY in append mode without writing, or test on non-destructive open.
# ==============================================================================

set -euo pipefail

echo "=== [SentinelBPF Demo] File Tampering Detection Test ==="
echo ""
echo "[1/1] Attempting write-mode open on /etc/shadow without modifying content..."

python3 -c "
import os
try:
    # Attempt to open /etc/shadow in append mode (O_WRONLY | O_APPEND)
    # Even if permission is denied, sys_enter_openat registers the attempt!
    fd = os.open('/etc/shadow', os.O_WRONLY | os.O_APPEND)
    os.close(fd)
except PermissionError:
    print('[+] Caught expected PermissionError (permission denied). eBPF sys_enter_openat captured attempt.')
except Exception as e:
    print(f'[-] Result: {e}')
" || true

echo ""
echo "Simulation completed. Check SentinelBPF alerts for:"
echo "Rule: file_tampering (HIGH) - MITRE T1565.001"
