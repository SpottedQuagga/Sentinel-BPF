# SentinelBPF

SentinelBPF is a Linux host intrusion detection tool built on eBPF (Extended Berkeley Packet Filter) and modern Linux kernel observability features (CO-RE, libbpf).

The system observes kernel events (process execution, file modifications, network connections, privilege modifications, and descriptor duplication), evaluates stateful detection rules in user space, and exposes real-time telemetry through a high-performance WebSocket API and interactive web dashboard.

> **Scope Note**: SentinelBPF is strictly **detection-only**. It observes and alerts; it does not block, filter, terminate processes, or modify kernel state.

---

## Architecture Overview

```
+-----------------------------------------------------------------+
|                        Linux Kernel Space                       |
|  - eBPF Programs (sched_process_exec, exit, fork)               |
|  - Syscall Entry Hooks (openat, connect, dup2/3, ptrace, mount) |
|  - BPF Ring Buffer (16 MB default)                              |
+--------------------------------|--------------------------------+
                                 | bpf_ringbuf_consume
+--------------------------------v--------------------------------+
|                   SentinelBPF Daemon (Go 1.21+)                 |
|  - Ring Buffer Consumer (Non-blocking worker)                   |
|  - Process Ancestry & Container Tracker (cgroup v2 correlation) |
|  - Stateful Rules Engine (Reverse shell, Setuid, Tampering)     |
|  - Alert De-duplication Cache                                   |
|  - WebSocket Hub (Per-client queues with alert prioritization)  |
|  - HTTP REST API & Static Asset Server                          |
+--------------------------------|--------------------------------+
                                 | WebSocket / HTTP
+--------------------------------v--------------------------------+
|                    Dashboard (Next.js / React)                  |
|  - D3.js Interactive Process Lineage Tree (Virtual Root PID 0)  |
|  - ECharts Metrics (Events/sec, Drops, Severity Breakdown)      |
|  - Live Alert Feed & Event Stream (10 Hz batched rendering)     |
+-----------------------------------------------------------------+
```

---

## Detection Capabilities

SentinelBPF detects suspicious behaviors through dedicated rule modules:

1. **Reverse Shell Detection**:
   Stateful detection tracking a 3-stage progression:
   1. Outbound network connection to an external address (`sys_enter_connect`).
   2. File descriptor duplication redirecting `stdin`, `stdout`, or `stderr` (fd 0, 1, or 2) to the socket (`sys_enter_dup2` / `sys_enter_dup3`).
   3. Shell binary execution (`sched_process_exec`).
2. **Privilege Escalation**:
   Detects unauthorized `setuid` / `setresuid` transitions to UID 0 from non-root callers, along with suspicious setuid binary executions.
3. **Sensitive File Tampering**:
   Detects modification attempts (`O_WRONLY`, `O_RDWR`, `O_CREAT`) against security-critical paths (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ld.so.preload`, `~/.ssh/authorized_keys`, crontabs).
4. **Process Injection & Evasion**:
   Monitors `sys_enter_ptrace` calls targeting arbitrary processes.
5. **Unauthorized Filesystem Mount**:
   Detects `sys_enter_mount` invocations within container boundaries.

---

## Repository Structure

```
├── bpf/
│   ├── sentinel.bpf.c         # eBPF C program (CO-RE, ring buffer, tracepoints)
│   ├── sentinel.h             # Shared event struct (strictly 480 bytes)
│   └── vmlinux.h              # Generated kernel types (git-ignored)
├── cmd/
│   └── sentinel-daemon/
│       └── main.go            # Daemon entry point, signal handling, wiring
├── internal/
│   ├── api/                   # HTTP and WebSocket handlers
│   ├── bpf/                   # cilium/ebpf loader and ring buffer reader
│   ├── config/                # YAML configuration and validation
│   ├── container/             # cgroup ID to container ID resolution
│   ├── events/                # Event struct decoding (480-byte binary layout)
│   ├── hub/                   # WebSocket hub with backpressure and client queues
│   ├── proctable/             # Process table and lineage tracking
│   └── rules/                 # Detection rule engine, deduplication, state machines
├── web-ui/                    # Next.js frontend with D3.js & ECharts
├── scripts/                   # Safe attack-simulation and validation scripts
├── Makefile                   # Build targets
├── config.yaml                # Default configuration
├── PROPOSED_SOLUTION.md       # Detailed technical design specification
└── AGENTS.md                  # Development guidelines and safety invariants
```

---

## Quickstart

### Prerequisites

- **Linux Kernel**: Version 5.8 or newer with `CONFIG_DEBUG_INFO_BTF=y`.
- **eBPF Build Tools**: `clang` (>= 11), `llvm`, `libbpf-dev`, `make`.
- **Go**: Version **1.21 or newer** (required — uses `binary.NativeEndian`).
- **Node.js**: Version 18 or newer (for dashboard).
- **Permissions**: Root privileges (`sudo` or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE`) to load eBPF programs into the kernel.

### Building

```bash
# 1. Generate vmlinux.h from running kernel
make vmlinux

# 2. Compile eBPF program and generate Go bindings
make build-ebpf

# 3. Build Go daemon binary (output in bin/sentinel-daemon)
make build-daemon

# 4. Build web UI assets
make build-ui
```

### Running

```bash
# Run daemon with default configuration (requires root)
sudo ./bin/sentinel-daemon --config config.yaml

# Run dashboard in development mode
cd web-ui && npm run dev
```

Dashboard is accessible at: `http://localhost:3000` (or `http://localhost:8080` when hosted by daemon).

---

## API Routes

| Route | Auth required (when `auth_token` is set) |
| :--- | :--- |
| `GET /health` | No |
| `GET /api/v1/health` | No |
| `GET /api/v1/status` | Bearer token or `?token=` |
| `GET /api/v1/alerts` | Bearer token or `?token=` |
| `GET /api/v1/processes` | Bearer token or `?token=` |
| `GET /api/v1/process/<pid>` | Bearer token or `?token=` |
| `WS /ws` | Origin check + `?token=` if `auth_token` set |
| `WS /api/v1/ws` | Origin check + `?token=` if `auth_token` set |

WebSocket auth note: browsers cannot set custom headers on WebSocket upgrades.
The token is passed as a query parameter (`?token=<value>`).
Default WebSocket URL used by the dashboard: `ws://127.0.0.1:8080/ws`
(override with `NEXT_PUBLIC_WS_URL`).

---

## Testing & Verification

```bash
# Run Go unit tests (requires no privileges)
go test -race -count=1 ./cmd/... ./internal/...

# Run Go static analysis
go vet ./cmd/... ./internal/...
gofmt -l .    # no output = clean

# Run Frontend linting and tests
cd web-ui && npm run lint && npm test
```

---

## Operations

- **Simulation mode (no root)**: `scripts/sentinelctl.sh up`
- **Live kernel mode**: see [`docs/FIRST_REAL_LOAD.md`](docs/FIRST_REAL_LOAD.md)
- **Day-to-day operations**: see [`docs/RUNBOOK.md`](docs/RUNBOOK.md)

---

## Performance Benchmarks

All benchmarks must be measured in controlled Linux environments.

| Metric | Target | Measured Value | Kernel Version | Environment |
| :--- | :--- | :--- | :--- | :--- |
| CPU Overhead | < 1.5% | TBD | TBD | TBD |
| Resident Memory (Daemon) | < 64 MB | TBD | TBD | TBD |
| Ring Buffer Loss Rate | 0.00% under 10k eps | TBD | TBD | TBD |
| Event Latency (Kernel to WS) | < 5 ms | TBD | TBD | TBD |

---

## Limitations

1. **Detection Only**: SentinelBPF does not terminate, isolate, or prevent suspicious activity.
2. **Syscall TOCTOU**: Syscall entry tracepoints capture arguments in user space before kernel execution. Pointers may be modified by concurrent threads (time-of-check to time-of-use).
3. **Ring Buffer Overflows**: In extreme bursts, if user space cannot drain the ring buffer fast enough, events are dropped in the kernel. Drops are tracked and reported.
4. **Root Compromise**: If an attacker gains full root privileges and manipulates kernel memory or disables eBPF subsystems, user-space detection tools can be blinded.
5. **No `/tmp` Execution Rule**: There is no rule implementation for `/tmp` execution in `internal/rules/` and no corresponding configuration section in `config.yaml`.
6. **Frontend `npm test` Placeholder**: `web-ui/package.json` defines `"test"` as a dummy `echo`, not a real test framework (e.g. Jest or Vitest).
7. **Mock Mode Is Synthetic**: Mock mode does not exercise real kernel hooks, so ring-buffer-health tiles and event counts are not real kernel measurements in mock mode.
8. **Fatal Hook Attachments**: 9 of 10 eBPF hooks are fatal if they fail to attach on the real kernel path; the daemon exits immediately if any syscall tracepoint attachment fails.
9. **IPv4 Only**: Detection rules handle IPv4 traffic only; IPv6 endpoints are not evaluated.
10. **Embedded Frontend Config**: `NEXT_PUBLIC_*` values are embedded in the browser bundle at build time, so WebSocket token setup is suitable for local/demo use only, not for production secret management.
