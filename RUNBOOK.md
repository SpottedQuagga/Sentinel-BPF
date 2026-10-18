# SentinelBPF Runbook

How to start, use and stop SentinelBPF. Written for the person running it, not the person developing it.

> **Status honesty.** Simulation mode (Section 2) has been run. **Real mode (Section 5) has not yet been run on a kernel.** Until you complete `docs/FIRST_REAL_LOAD.md` and it works, treat real mode as untested. Anything marked *(confirm)* was written from the design docs and should be checked against the code.

SentinelBPF **detects and alerts only**. It never blocks or kills anything.

---

## 1. One-time setup

Everything below runs **inside WSL2** (or any Linux). In PowerShell, open WSL first:

```powershell
wsl -d Ubuntu-24.04
cd ~/SentinelBPF
```

Install the helper and check your machine:

```bash
chmod +x scripts/sentinelctl.sh
scripts/sentinelctl.sh doctor        # shows what is installed and what is missing
scripts/sentinelctl.sh build         # builds the eBPF object, Go bindings and bin/sentinel-daemon
scripts/sentinelctl.sh ui-install    # installs dashboard dependencies (needs internet, once)
```

To avoid typing the long path, add an alias (optional):

```bash
echo "alias sctl='~/SentinelBPF/scripts/sentinelctl.sh'" >> ~/.bashrc && source ~/.bashrc
```

The rest of this document writes the full path.

---

## 2. Quick start: simulation mode (no root, safe)

Simulation runs the whole daemon and dashboard on **synthetic events**. It proves the software works. It does **not** prove the kernel programs load or capture real activity.

```bash
scripts/sentinelctl.sh up
```

Then open **http://localhost:3000** in your Windows browser. You should see:

- a green connection indicator
- a **SIMULATION** badge *(added by the V3 agent session; if missing, that task is not done yet)*
- mock alerts (for example a reverse shell to a documentation address, and a write attempt on `/etc/shadow`)
- a process tree and an event log

To look at it from the terminal instead:

```bash
scripts/sentinelctl.sh status
scripts/sentinelctl.sh alerts
scripts/sentinelctl.sh procs
```

Stop everything:

```bash
scripts/sentinelctl.sh down
```

Prefer to see the daemon logs directly? Run it in the foreground (Ctrl+C to stop):

```bash
scripts/sentinelctl.sh mock
```

---

## 3. Command reference

| Command | What it does | Root? |
| :--- | :--- | :--- |
| `doctor` | Checks tools, kernel BTF, cgroup v2, binary, config, dashboard deps | No |
| `build` | `make all` | No |
| `check` | `go vet`, `gofmt` (must be clean), `go test -race` | No |
| `ui-install` | `npm install` in `web-ui` | No |
| `up` / `down` | Start / stop mock daemon and dashboard in the background | No |
| `mock` | Mock daemon in the foreground | No |
| `logs [daemon\|ui]` | Follow a log file under `.run/` | No |
| `status`, `health`, `alerts`, `procs` | Query the running daemon | No |
| `ws` | Print WebSocket message types (needs `scripts/wsprobe`) | No |
| `real` | Load eBPF programs for real | **Yes** (asks first) |

Overrides (environment variables): `SENTINEL_CONFIG`, `SENTINEL_URL`, `SENTINEL_TOKEN`, `NEXT_PUBLIC_WS_URL`.

---

## 4. Ports, URLs and endpoints

| What | Where |
| :--- | :--- |
| Dashboard | http://localhost:3000 |
| Daemon API | http://127.0.0.1:8080 |
| WebSocket | ws://127.0.0.1:8080/ws |
| Logs and PID files | `.run/` in the repo (git-ignored) |

| Route | Auth |
| :--- | :--- |
| `/health`, `/api/v1/health` | none |
| `/api/v1/status`, `/api/v1/alerts`, `/api/v1/processes`, `/api/v1/process/<pid>` | bearer token, only if `auth_token` is set |
| `/ws`, `/api/v1/ws` | origin check; token if set *(confirm how the browser supplies it)* |

Security defaults: the daemon binds to `127.0.0.1` and checks WebSocket origins (`http://localhost:3000` and `http://127.0.0.1:3000`). Leave `auth_token` empty for local use. If you set one, export it so the helper can use it:

```bash
export SENTINEL_TOKEN='your-token'
```

Do not paste tokens into chats or commit them.

---

## 5. Real mode (root, after the first load is verified)

1. Read and follow **`docs/FIRST_REAL_LOAD.md`** first. It has the pre-flight checks, expected output and troubleshooting.
2. Use a disposable VM or WSL2 that you are comfortable loading eBPF programs into.
3. Start it from an interactive terminal:

   ```bash
   scripts/sentinelctl.sh real
   ```

   It shows what it will run, then asks you to type `LOAD`.
4. In a **second** terminal, start the dashboard against it:

   ```bash
   cd ~/SentinelBPF/web-ui && npm run dev
   ```

   (Do **not** use `up` at the same time. `up` starts the mock daemon on the same port.)
5. Stop with **Ctrl+C** in the daemon terminal. Then confirm nothing is left attached:

   ```bash
   sudo bpftool prog show | grep -i -E 'sentinel|sched_process|sys_enter' || echo "nothing attached"
   ```

If the load fails, copy the **entire** output (including any verifier log) and `uname -r`, and share it. That is exactly what is needed to diagnose it.

Do **not** run the `scripts/demo_*` attack simulations until real mode loads cleanly, and then only in a disposable VM, on loopback, after reading what each script does.

---

## 6. Reading the dashboard

| Panel | What it tells you |
| :--- | :--- |
| Connection indicator | Whether the browser is connected to the daemon (auto-reconnects) |
| Alert feed | Severity-coloured alerts. CRITICAL is a reverse shell or container mount breakout |
| Event log | Raw events, filterable by type, PID, command, container |
| Process tree | Parent/child hierarchy; alerting processes are highlighted |
| Metrics | Events per second, alert counts, **drop counters** |

Remember what an alert means: a process **attempted** something. The hooks run at syscall entry, before the kernel decides whether it succeeds, so an alert is not proof of compromise. Rising **drop counters** mean events are being lost (ring buffer full or a slow consumer).

---

## 7. Everyday operations

| I want to... | Do this |
| :--- | :--- |
| Rebuild after changing C or Go code | `scripts/sentinelctl.sh build` |
| Run all checks before committing | `scripts/sentinelctl.sh check` |
| Demo on a single machine with loopback connections counting as external | set `rules.treat_loopback_as_external: true` in `config.yaml`, restart. Set it back to `false` afterwards |
| Change ring buffer size | `bpf.ring_buffer_size` in `config.yaml`, in bytes, must be a power of two (default 16777216 = 16 MiB). Needs a restart |
| Silence a legitimate tool | add it to the rule's allowlist in `config.yaml`; do not disable the rule |
| Start from a clean build | `rm -f internal/bpf/sentinel_bpfel_x86.* bin/sentinel-daemon bpf/vmlinux.h && scripts/sentinelctl.sh build` |
| Copy WSL changes back to Windows | see the `rsync` command in `PROJECT_STATUS_REPORT_V2.md`; it has no `--delete` |

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
| :--- | :--- | :--- |
| `bin/sentinel-daemon` not found | Not built | `scripts/sentinelctl.sh build` |
| `up` says daemon not healthy | Port 8080 in use, or config error | `scripts/sentinelctl.sh logs`; check for another process on 8080 |
| Dashboard says disconnected | Wrong WebSocket URL, origin blocked, or token required | Check `NEXT_PUBLIC_WS_URL` (default `ws://127.0.0.1:8080/ws`); open the dashboard as `http://localhost:3000`; check `allowed_origins` in `config.yaml` |
| API returns 401 | `auth_token` is set | `export SENTINEL_TOKEN=...` |
| `up` says dashboard dependencies missing | `npm install` not run | `scripts/sentinelctl.sh ui-install` |
| `missing go.sum entry` | Module checksums not downloaded | `go mod tidy` (needs internet; ask before changing dependencies) |
| `Error: missing package, are you running via go generate?` | Old build target | Use `make all` / `scripts/sentinelctl.sh build` |
| `$'\r': command not found` in a script | Windows line endings | `sed -i 's/\r$//' scripts/*.sh` and make sure `.gitattributes` forces LF |
| `make` cannot generate `vmlinux.h` | No kernel BTF | `ls /sys/kernel/btf/vmlinux`; real mode needs it |
| Container names missing in real mode | cgroup v1 | needs cgroup v2 (`stat -fc %T /sys/fs/cgroup` should print `cgroup2fs`) |
| Dashboard works in simulation, real mode shows nothing | Expected until the first real load is verified | Follow `docs/FIRST_REAL_LOAD.md` |

---

## 9. Never do this

- Do not run `real` or any `sudo` command on a machine you are not willing to experiment on.
- Do not run `scripts/demo_*` without reading them and without a disposable VM. Reverse-shell tests must stay on `127.0.0.1`.
- Do not expose port 8080 beyond localhost, and do not weaken the origin or token checks to make something work.
- Do not quote performance numbers. None have been measured.
