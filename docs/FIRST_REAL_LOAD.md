# docs/FIRST_REAL_LOAD.md

> **Read this before you run sudo.**
> SentinelBPF is detection-only. It never blocks or kills anything.
> Use a disposable Linux VM or WSL2 you are comfortable recovering.

---

## 1. Pre-flight (no sudo required)

Run all of these. They need no root.

```bash
cd ~/SentinelBPF
scripts/sentinelctl.sh doctor          # tools, binary, BTF, cgroup v2
ls -l /sys/kernel/btf/vmlinux          # must exist
stat -fc %T /sys/fs/cgroup             # expect: cgroup2fs
uname -r
ulimit -l                              # expect: unlimited or large
```

If `/sys/kernel/btf/vmlinux` is missing the kernel needs `CONFIG_DEBUG_INFO_BTF=y`.
On WSL2 Ubuntu 24.04 it is present by default.

---

## 2. The load

**Terminal 1:**

```bash
cd ~/SentinelBPF
sudo ./bin/sentinel-daemon --config config.yaml
```

Or via the control script (interactive terminal required):

```bash
scripts/sentinelctl.sh real
```

### Expected startup log (exact strings from `cmd/sentinel-daemon/main.go`)

```
2026/10/11 HH:MM:SS [SentinelBPF] Starting daemon version 1.0.0 (PID: <pid>)
2026/10/11 HH:MM:SS [INFO] Initializing eBPF subsystem...
2026/10/11 HH:MM:SS [INFO] Attached eBPF programs and opened ring buffer reader.
2026/10/11 HH:MM:SS [INFO] SentinelBPF API & WebSocket server listening on http://127.0.0.1:8080
```

The third line confirms all tracepoints loaded.
`[WARN] Failed to add self to ignored_pids map` is non-fatal.
`[FATAL]` means the load failed — see Section 6.

---

## 3. Verify attachment (Terminal 2, daemon still running)

```bash
sudo bpftool prog show | grep -i -E 'sched_process|sys_enter|sentinel'
sudo bpftool map show
curl -s http://127.0.0.1:8080/api/v1/status
```

**Expected `/api/v1/status` on an idle system:**

```json
{
  "active_processes": 30,
  "kernel_drops": 0,
  "mock": false,
  "uptime_seconds": 5
}
```

`mock: false` confirms live eBPF mode. `kernel_drops: 0` means the ring buffer is
keeping up. `active_processes` will be a small positive number.

Expected `bpftool prog show`: up to 10 programs listed.
`sys_enter_dup2` may be absent on some kernels — that is normal (optional hook).

---

## 4. Prove capture is real (benign activity)

In Terminal 2:

```bash
ls /tmp
cat /etc/hostname
curl -s http://127.0.0.1:8080/api/v1/processes | python3 -m json.tool | grep -A5 'ls'
```

The `ls` and `cat` execs should appear in the process list.
No alerts will fire — this confirms exec events reach user space.

---

## 5. Capture a failure

```bash
sudo ./bin/sentinel-daemon --config config.yaml 2>&1 | tee /tmp/sentinel-load.log
```

When reporting a failure paste all of:
1. `uname -r`
2. `bpftool version`
3. The complete `/tmp/sentinel-load.log` (including the `[ERROR] eBPF Verifier Error:` block)

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `[FATAL] root privileges (EUID 0) required` | Not root | Use `sudo` |
| `[FATAL] kernel BTF (/sys/kernel/btf/vmlinux) not accessible` | No BTF in kernel | Rebuild kernel with `CONFIG_DEBUG_INFO_BTF=y` |
| `[FATAL] remove memlock limit: ...` | Kernel < 5.11 | Use kernel 5.11+; or `ulimit -l unlimited` |
| `[ERROR] eBPF Verifier Error:` then `[FATAL]` | Verifier rejected | Paste full log; check `bpftool feature probe kernel` |
| `[WARN] attach syscalls/sys_enter_dup2 (optional): ...` | arm64 or no dup2 tracepoint | Non-fatal; dup3 covers the same case |
| `[FATAL] bind: address already in use` | Port 8080 taken | Change `server.port` in `config.yaml` |
| `permission denied on tracefs` | tracefs not mounted | `mount -t tracefs nodev /sys/kernel/tracing` |
| `container_id` always empty | cgroup v1 not v2 | Boot with `systemd.unified_cgroup_hierarchy=1` |

---

## 7. Stop procedure

In Terminal 1, press **Ctrl+C**.

Expected shutdown log:

```
2026/10/11 HH:MM:SS [INFO] Received signal interrupt. Initiating graceful shutdown...
2026/10/11 HH:MM:SS [INFO] SentinelBPF daemon stopped cleanly.
```

Confirm programs detached (Terminal 2):

```bash
sudo bpftool prog show | grep -i -E 'sched_process|sys_enter'
# Expected: no output (programs removed from kernel)
```

---

## 8. Reminders

- SentinelBPF **detects and alerts only**. It never blocks, filters, or kills anything.
- Use a disposable VM or WSL2 you are comfortable recovering.
- Do not run `scripts/demo_*` until you confirm the daemon sees live events.
- If any log string here differs from what you see, trust your terminal and file an issue.
