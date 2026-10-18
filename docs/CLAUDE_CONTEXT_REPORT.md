# SentinelBPF: Comprehensive System Context & Status Report

> **Target Audience:** Independent LLM context initialization (zero-repo-access Claude chat) and academic evaluator review.  
> **Classification:** Operating Systems Course Project (Third Year B.Tech / BE Computer Engineering).  
> **Evidence Tagging Key:**
> - `[VERIFIED]` Verified via direct shell command execution in this session (see Appendix A).
> - `[CODE]` Inspected directly in the codebase (`file:line` reference provided).
> - `[DOC]` Sourced from documentation without independent live runtime verification.
> - `[UNKNOWN]` Not verifiable with available non-root / non-interactive environment capabilities.

---

## Table of Contents

- [Section 1. Metadata](#section-1-metadata)
- [Section 2. Project Summary](#section-2-project-summary)
- [Section 3. Architecture and Code Map](#section-3-architecture-and-code-map)
  - [3.1 Repository Layout](#31-repository-layout)
  - [3.2 End-to-End Data Flow](#32-end-to-end-data-flow)
  - [3.3 Shared Struct Contract (`struct event`)](#33-shared-struct-contract-struct-event)
  - [3.4 Kernel Hooks & Attachment Table](#34-kernel-hooks--attachment-table)
  - [3.5 eBPF Maps](#35-ebpf-maps)
  - [3.6 Stateful Detection Rules Matrix](#36-stateful-detection-rules-matrix)
  - [3.7 Configuration Schema](#37-configuration-schema)
  - [3.8 HTTP REST API Routes](#38-http-rest-api-routes)
  - [3.9 WebSocket Protocol Specification](#39-websocket-protocol-specification)
  - [3.10 Frontend Architecture & UI Structure](#310-frontend-architecture--ui-structure)
  - [3.11 Memory Bounds & Queue Capacities](#311-memory-bounds--queue-capacities)
  - [3.12 Operating Systems Concepts to Code Map](#312-operating-systems-concepts-to-code-map)
- [Section 4. How to Build and Run (As It Works Today)](#section-4-how-to-build-and-run-as-it-works-today)
- [Section 5. Verification Matrix](#section-5-verification-matrix) *(Pending Phase B)*
- [Section 6. Status: Done, Partial, Remaining](#section-6-status-done-partial-remaining) *(Pending Phase C)*
- [Section 7. Known Issues and Suspects Analysis](#section-7-known-issues-and-suspects-analysis) *(Pending Phase C)*
- [Section 8. Documents Inventory](#section-8-documents-inventory) *(Pending Phase D)*
- [Section 9. Errors Encountered and Root-Cause Fixes](#section-9-errors-encountered-and-root-cause-fixes) *(Pending Phase D)*
- [Section 10. Safety and Guardrails for Future AI Agents](#section-10-safety-and-guardrails-for-future-ai-agents) *(Pending Phase D)*
- [Section 11. Proposed Next Steps](#section-11-proposed-next-steps) *(Pending Phase D)*
- [Section 12. Checklist for Claude Chat Inquiries](#section-12-checklist-for-claude-chat-inquiries) *(Pending Phase D)*
- [Section 13. Glossary](#section-13-glossary) *(Pending Phase D)*
- [Appendix A. Raw Verification Evidence](#appendix-a-raw-verification-evidence) *(Populated across phases)*

---

## Section 1. Metadata

- **Report Generation Timestamp:** `Sun Oct 18 09:14:39 UTC 2026` `[VERIFIED]`
- **Active Repository Path:** `/home/aayush/SentinelBPF` in WSL2 Ubuntu 24.04 `[VERIFIED]`
- **Source of Truth Distinction:** The canonical, active development repository resides exclusively inside Linux filesystem path `/home/aayush/SentinelBPF` in WSL2. The Windows host path (`C:\Users\aayus\OneDrive\Desktop\OS_Project`) is a host-mounted mirror that is stale for build binaries and node_modules. All compilations and executions must happen in Linux WSL2 `[VERIFIED]`.
- **Operating System Kernel:** Linux `6.18.54.1-microsoft-standard-WSL2` x86_64 `[VERIFIED]`
- **Go Toolchain:** `go version go1.22.2 linux/amd64` `[VERIFIED]`
- **C Compiler (eBPF):** `Ubuntu clang version 18.1.3 (1ubuntu1)` `[VERIFIED]`
- **BPF Inspection Utility:** `bpftool v7.4.0` `[VERIFIED]`
- **Node.js Environment:** `/usr/bin/node` (`v18.19.1`), `/usr/bin/npm` `[VERIFIED]`
- **Version Control Status:** `fatal: not a git repository (or any of the parent directories): .git` `[VERIFIED]`. The repository currently lacks a `.git` database. No commit history or undo stack exists.

---

## Section 2. Project Summary

- **Core Definition:** SentinelBPF is a Linux Host Intrusion Detection System (HIDS) engineered using modern extended Berkeley Packet Filters (eBPF) with Compile Once – Run Everywhere (CO-RE) technology `[DOC: PROPOSED_SOLUTION.md]`.
- **Detection-Only Architecture:** SentinelBPF is strictly non-intrusive and observational. It **never blocks, terminates, alters, or kills any user space process or syscall** `[DOC: AGENTS.md]`. It generates real-time telemetry and alerts for security monitoring.
- **Three-Tier Architecture:**
  1. *Kernel Layer (`bpf/`):* C programs compiled via Clang into BPF bytecode, verified by the in-kernel verifier, hooking process events and syscall entries to stream fixed 480-byte records into a high-performance BPF ring buffer `[CODE: bpf/sentinel.bpf.c:28-33]`.
  2. *Daemon Layer (`cmd/`, `internal/`):* A Go daemon utilizing `cilium/ebpf` to drain the ring buffer, decode binary records, track process hierarchies, evaluate stateful threat heuristics, and expose HTTP REST endpoints and a WebSocket broadcast hub `[CODE: cmd/sentinel-daemon/main.go:80-140]`.
  3. *Dashboard Layer (`web-ui/`):* A Next.js 14 React single-page application utilizing D3.js for SVG process trees, real-time alert feeds, and telemetry charts `[CODE: web-ui/package.json:12-18]`.
- **Mock Simulation Mode:** The Go daemon supports a standalone simulation engine (`--mock`) that emits synthetic process lifecycles and realistic attack chains (reverse shell, file tampering) without requiring Linux root privileges or an eBPF-capable kernel `[CODE: internal/bpf/bpf.go:81-184]`.
- **Syscall Hook Semantics (TOCTOU):** Syscall entry tracepoints (`sys_enter_*`) intercept arguments prior to kernel permission validation and prior to execution completion. Intercepted events represent an **attempt**, not confirmed execution. User space memory pointers can theoretically change between inspection and execution (Time-of-Check to Time-of-Use race) `[DOC: AGENTS.md]`.
- **Academic Context:** Developed as a third-year (TY) engineering Operating Systems capstone project. It bridges foundational OS theory with modern Linux kernel instrumentation, directly demonstrating:
  - Process creation, execution, and termination lifecycles (`fork`, `execve`, `exit`)
  - User space to kernel space transitions via system calls
  - Linux kernel verification, safety constraints, and BPF bytecode JIT compilation
  - Zero-copy ring buffer IPC between kernel and user space
  - Process credentials and privilege models (`uid`, `euid`, `gid`, `setuid` privilege escalation)
  - POSIX file descriptor table manipulation (`dup2`, `dup3`, socket descriptor redirection)
  - Network socket initialization and state tracking (`connect` syscall)
  - Namespace and cgroup v2 tracking for container boundary isolation
  - Asynchronous concurrency, non-blocking I/O, and consumer backpressure mechanics.

---

## Section 3. Architecture and Code Map

### 3.1 Repository Layout

```
.
├── bpf/
│   ├── sentinel.bpf.c              # Core eBPF C program (10 tracepoint hooks, ring buffer submit)
│   ├── sentinel.h                  # Shared struct event contract (480 bytes)
│   └── vmlinux.h                   # Generated Linux kernel type definitions (CO-RE)
├── cmd/
│   └── sentinel-daemon/
│       └── main.go                 # Daemon entrypoint, flag parsing, lifecycle & OS signals
├── internal/
│   ├── api/
│   │   ├── server.go               # HTTP REST routes, CORS, auth middleware, WS upgrade
│   │   └── server_test.go          # API route unit tests
│   ├── bpf/
│   │   ├── bpf.go                  # Common BPF interfaces & mock event stream generator
│   │   ├── bpf_linux.go            # cilium/ebpf loader, link attachment, live ringbuf reader
│   │   ├── bpf_stub.go             # Non-Linux stub implementations
│   │   ├── gen.go                  # go:generate bpf2go directive
│   │   ├── sentinel_bpfel_x86.go   # Generated Go bindings for x86 eBPF objects
│   │   └── sentinel_bpfel_x86.o    # Compiled eBPF ELF object file (10 sections)
│   ├── config/
│   │   ├── config.go               # YAML configuration parser and validator
│   │   └── config_test.go          # Comprehensive positive and negative config tests
│   ├── container/
│   │   ├── container.go            # cgroup v2 ID to container ID resolution
│   │   └── container_test.go       # Container tracker unit tests
│   ├── events/
│   │   ├── event.go                # Decoded Event struct, FromRaw binary decoder
│   │   └── event_test.go           # 480-byte binary decoding test
│   ├── hub/
│   │   ├── hub.go                  # WebSocket client manager, fan-out, per-client queues
│   │   └── hub_test.go             # Slow-client dropping and prioritization tests
│   ├── proctable/
│   │   ├── proctable.go            # Thread-safe PID table, lineage tracker, /proc fallback
│   │   └── proctable_test.go       # Lineage, reparenting, and cycle prevention tests
│   └── rules/
│       ├── file_tampering.go       # Openat on sensitive files (/etc/shadow, etc.)
│       ├── mount.go                # Unauthorized mount and container breakout detection
│       ├── priv_esc.go             # Setuid(0) by non-root, sudo execution
│       ├── ptrace.go               # Ptrace process injection detection
│       ├── reverse_shell.go        # 3-stage state machine (connect -> dup -> exec shell)
│       ├── rule.go                 # Rule interface, engine evaluator, deduplication cache
│       └── rules_test.go           # Table-driven unit tests for all rule heuristics
├── scripts/
│   ├── demo_file_tamper.sh         # Demonstration script (DO NOT RUN WITHOUT USER APPROVAL)
│   ├── demo_priv_esc.sh            # Demonstration script (DO NOT RUN WITHOUT USER APPROVAL)
│   ├── demo_reverse_shell.sh       # Demonstration script (DO NOT RUN WITHOUT USER APPROVAL)
│   ├── sentinelctl.sh              # Management helper script
│   ├── test_e2e_mock.sh            # End-to-end mock verification script
│   └── wsprobe/
│       ├── go.mod                  # Wsprobe module
│       └── main.go                 # Standalone WebSocket client probe
├── web-ui/                         # Next.js 14 Dashboard
│   ├── package.json                # Frontend dependencies and scripts
│   ├── next.config.js              # Next.js standalone configuration & strictMode
│   └── src/
│       ├── app/
│       │   ├── globals.css         # Dark theme CSS tokens & glassmorphism
│       │   ├── layout.tsx          # Root HTML layout
│       │   └── page.tsx            # Main dashboard shell & tab coordinator
│       ├── components/
│       │   ├── AlertFeed.tsx       # Filterable security incident feed
│       │   ├── Header.tsx          # Top nav, status pill, SIMULATION badge
│       │   ├── LiveEventStream.tsx # Raw kernel event stream table
│       │   ├── MetricsChart.tsx    # Throughput and drop visualizer
│       │   ├── MetricsOverview.tsx # KPI summary cards
│       │   └── ProcessTree.tsx     # D3.js interactive SVG process tree
│       ├── hooks/
│       │   └── useWebSocket.ts     # WS client, reconnect backoff, 10 Hz flush batching
│       └── types/
│           └── index.ts            # TypeScript protocol definitions
├── docs/                           # Documentation
│   ├── FIRST_REAL_LOAD.md          # Guide for first root VM eBPF execution
│   └── RUNBOOK.md                  # Operational troubleshooting runbook
├── config.yaml                     # Active daemon YAML configuration
├── Makefile                        # Build pipeline automation
└── AGENTS.md                       # AI coding agent operational guidelines
```
*Discrepancy with `AGENTS.md`:* The repository layout matches `AGENTS.md` closely, with the addition of `scripts/wsprobe/`, `scripts/test_e2e_mock.sh`, `internal/bpf/gen.go`, and `docs/FIRST_REAL_LOAD.md`.

---

### 3.2 End-to-End Data Flow

1. **Kernel Trigger:** Kernel fires a tracepoint hook (e.g. `sched_process_exec` or `sys_enter_openat`).
2. **eBPF Execution:** Kernel runs the attached eBPF program (`bpf/sentinel.bpf.c`), extracts task context (`task_struct`, credentials, arguments) via CO-RE helpers.
3. **Ring Buffer Submission:** eBPF program calls `bpf_ringbuf_reserve`, zeroes the struct, populates fields, and calls `bpf_ringbuf_submit`. Drops increment `drops` map on buffer exhaustion `[CODE: bpf/sentinel.bpf.c:51-60]`.
4. **Ring Buffer Polling:** Go daemon's `LinuxRingbufReader` drains binary records in a tight loop via `ringbuf.Reader.ReadInto` with zero heavy operations `[CODE: internal/bpf/bpf_linux.go:64-77]`.
5. **Decoding:** Binary record is parsed by `events.FromRaw` into structured `events.Event` `[CODE: internal/events/event.go:144-185]`.
6. **State Tracking:** Event is ingested into `proctable.Table` to track exec/fork/exit lineage and `container.Tracker` to associate cgroup IDs `[CODE: cmd/sentinel-daemon/main.go:163-174]`.
7. **Rule Evaluation:** `rules.Engine` passes event to registered detection heuristics, generating alerts with cooldown de-duplication `[CODE: internal/rules/rule.go:119-163]`.
8. **Hub Fan-Out:** `hub.Hub` broadcasts events and alerts to active WebSocket client queues. Alerts are prioritized over raw events `[CODE: internal/hub/hub.go:88-113]`.
9. **Dashboard Render:** Next.js frontend batches incoming socket messages at 10 Hz into React state to update the Live Events table, Alert Feed, and D3 Process Tree `[CODE: web-ui/src/hooks/useWebSocket.ts:40-77]`.

---

### 3.3 Shared Struct Contract (`struct event`)

Defined in `bpf/sentinel.h` `[CODE: bpf/sentinel.h:27-64]`. Exactly **480 bytes**, 8-byte aligned, zero implicit compiler padding:

| Field Group | Fields | Types | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- | :--- |
| **64-bit Core** | `timestamp_ns`, `cgroup_id`, `event_type`, `retval`, `flags` | `__u64` | 40 | Monotonic time, cgroup v2 ID, event discriminator, return/exit value, open/ptrace flags |
| **32-bit Process** | `pid`, `tid`, `ppid`, `uid`, `gid`, `euid`, `egid`, `fd`, `oldfd`, `newfd` | `__u32` | 40 | Process/thread identifiers, real & effective creds, file descriptors |
| **16/32-bit Net** | `saddr`, `daddr`, `sport`, `dport`, `family`, `protocol` | `__u32` (addrs), `__u16` (ports/family/proto) | 16 | IPv4 source/destination, ports, socket family |
| **Buffers** | `comm[16]`, `pcomm[16]`, `path[256]`, `extra[96]` | `char` arrays | 384 | Task comm, parent comm, target file/binary path, arguments/mount source |
| **Total** | | | **480** | Validated via `_Static_assert` in C and unit test in Go |

*Assertions:*
- C Compile-time Assert: `_Static_assert(sizeof(struct event) == 480, "struct event must be exactly 480 bytes");` `[CODE: bpf/sentinel.h:63]`
- Go Decoding Assert: `internal/events/event_test.go:59-60` (`TestDecodeRawEvent`) verifies encoded buffer length equals 480.

---

### 3.4 Kernel Hooks & Attachment Table

All 10 eBPF programs compiled in `internal/bpf/sentinel_bpfel_x86.o` and loaded by `internal/bpf/bpf_linux.go:195-236` `[CODE]`:

| Program Name | Section Name (ELF) | Section Type | Loader Attachment API | Fatal or Optional? |
| :--- | :--- | :--- | :--- | :--- |
| `sched_process_exec` | `tp_btf/sched_process_exec` | BPF_PROG_TYPE_TRACING | `link.AttachTracing()` | **FATAL** (`bpf_linux.go:201`) |
| `sched_process_exit` | `tracepoint/sched/sched_process_exit` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("sched", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `sched_process_fork` | `tracepoint/sched/sched_process_fork` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("sched", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `trace_sys_enter_openat` | `tracepoint/syscalls/sys_enter_openat` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `trace_sys_enter_connect` | `tracepoint/syscalls/sys_enter_connect` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `trace_sys_enter_dup3` | `tracepoint/syscalls/sys_enter_dup3` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `trace_sys_enter_dup2` | `tracepoint/syscalls/sys_enter_dup2` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **OPTIONAL** (`bpf_linux.go:219`) |
| `trace_sys_enter_ptrace` | `tracepoint/syscalls/sys_enter_ptrace` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `trace_sys_enter_mount` | `tracepoint/syscalls/sys_enter_mount` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **FATAL** (`bpf_linux.go:233`) |
| `trace_sys_enter_setuid` | `tracepoint/syscalls/sys_enter_setuid` | BPF_PROG_TYPE_TRACEPOINT | `link.Tracepoint("syscalls", ...)` | **FATAL** (`bpf_linux.go:233`) |

*Critical Note:* `sys_enter_dup2` is the **only optional hook** (to accommodate arm64 and architectures without `dup2`). The other 9 attachments are strictly fatal `[CODE: internal/bpf/bpf_linux.go:213-236]`.

---

### 3.5 eBPF Maps

Exact map identifiers declared in `bpf/sentinel.bpf.c`:

| Map Name in C | Type | Max Entries | Key / Value Size | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `events` | `BPF_MAP_TYPE_RINGBUF` | `16777216` (16 MiB) | 0 / 0 | Kernel-to-userspace zero-copy lockless event ring buffer `[CODE: bpf/sentinel.bpf.c:32]` |
| `drops` | `BPF_MAP_TYPE_PERCPU_ARRAY` | `1` | 4 bytes (`__u32`) / 8 bytes (`__u64`) | Kernel drop counter incremented when ring buffer is full `[CODE: bpf/sentinel.bpf.c:40]` |
| `ignored_pids` | `BPF_MAP_TYPE_HASH` | `1024` | 4 bytes (`__u32`) / 1 byte (`__u8`) | PIDs ignored by eBPF filter (used by daemon self-filtering) `[CODE: bpf/sentinel.bpf.c:48]` |

---

### 3.6 Stateful Detection Rules Matrix

| Rule Name | Source File | Trigger Summary | MITRE Tag | Config Section | Allowlist Logic | Cooldown Key |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `reverse_shell` | `internal/rules/reverse_shell.go:34` | 3-stage state machine: external connect -> socket dup to fd 0/1/2 -> shell execution | `T1059.004` | `rules.reverse_shell` | Only configured shell binaries trigger stage 3 | `reverse_shell:<pid>:<path>` (`rule.go:138`) |
| `privilege_escalation` | `internal/rules/priv_esc.go:11` | Non-root caller (`euid != 0`) executing `setuid(0)`, or non-root executing elevation tools (`sudo`, `pkexec`, `su`, `doas`) | `T1548.001` / `T1548.003` | `rules.privilege_escalation` | Legitimate setuid execution where `euid == 0` (e.g. `/usr/bin/passwd`) is ignored | `privilege_escalation:<pid>:<path>` (`rule.go:138`) |
| `file_tampering` | `internal/rules/file_tampering.go:12` | `openat` with write flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`) on sensitive files | `T1565.001` | `rules.file_tampering` | Configured allowlist binaries matching `comm` or resolved `/proc` path | `file_tampering:<pid>:<path>` (`rule.go:138`) |
| `process_injection` | `internal/rules/ptrace.go:10` | `ptrace` system call invoked against other processes | `T1055.008` | `rules.process_injection` | Known debuggers (`gdb`, `lldb`, `strace`, `dlv`) | `process_injection:<pid>:<path>` (`rule.go:138`) |
| `unauthorized_mount` | `internal/rules/mount.go:11` | `mount` system call invoked, especially inside containers (Severity High) | `T1611` | `rules.unauthorized_mount` | None (Host mounts flagged Medium, container mounts High) | `unauthorized_mount:<pid>:<path>` (`rule.go:138`) |

---

### 3.7 Configuration Schema

Defined in `config.yaml` `[CODE: config.yaml:1-79]`:

```yaml
server:
  host: "127.0.0.1"                     # Localhost default
  port: 8080                            # Default HTTP/WS daemon port
  auth_token: ""                        # empty (Authentication disabled by default; redact if set)
  allowed_origins:                      # CORS and WebSocket origins
    - "http://localhost:3000"
    - "http://127.0.0.1:3000"
    - "http://localhost:8080"
    - "http://127.0.0.1:8080"

bpf:
  ring_buffer_size: 16777216            # 16 MiB (must be power of 2)
  event_buffer_size: 65536              # Userspace channel capacity

rules:
  treat_loopback_as_external: false     # Set true only in sandboxed test suites
  alert_cooldown_seconds: 10            # Deduplication cooldown window

  reverse_shell:
    enabled: true
    connection_timeout_seconds: 30      # Expiration timeout for stage 1 & 2
    shell_binaries:
      - "/bin/sh"
      - "/bin/bash"
      - "/bin/zsh"
      - "/bin/dash"
      - "/usr/bin/sh"
      - "/usr/bin/bash"
      - "/usr/bin/python"
      - "/usr/bin/python3"
      - "/usr/bin/perl"
      - "/usr/bin/ruby"
      - "/bin/nc"
      - "/usr/bin/nc"
      - "/bin/socat"
      - "/usr/bin/socat"

  privilege_escalation:
    enabled: true
    monitor_setuid_binaries: true

  file_tampering:
    enabled: true
    sensitive_paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/sudoers"
      - "/etc/ld.so.preload"
      - "/etc/pam.d"
      - "/etc/crontab"
    allowlisted_binaries:
      - "/usr/bin/passwd"
      - "/usr/sbin/useradd"
      - "/usr/sbin/usermod"
      - "/usr/sbin/vipw"
      - "/usr/bin/chsh"
      - "/usr/bin/gpasswd"

  process_injection:
    enabled: true

  unauthorized_mount:
    enabled: true

logging:
  level: "info"
  format: "text"
```

---

### 3.8 HTTP REST API Routes

Implemented in `internal/api/server.go:56-65` `[CODE]`:

| Route | Method | Auth Requirement (when `auth_token` is set) | Description |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | Public (No Auth) | Liveness check returning `{"status":"healthy"}` |
| `/api/v1/health` | `GET` | Public (No Auth) | Alias for `/health` |
| `/api/v1/status` | `GET` | `Bearer <token>` or `?token=` | Uptime, event counts, drops, active processes, clients, mock flag |
| `/api/v1/alerts` | `GET` | `Bearer <token>` or `?token=` | Recent security alert history (supports `?limit=N`, default 100) |
| `/api/v1/processes` | `GET` | `Bearer <token>` or `?token=` | Snapshot of all active cached processes in process table |
| `/api/v1/process/{pid}`| `GET` | `Bearer <token>` or `?token=` | Process details and ancestral lineage up to root PID 0 |
| `/ws` | `GET` (Upgrade) | `?token=` or `Authorization` | Real-time WebSocket event, alert, and metrics feed |
| `/api/v1/ws` | `GET` (Upgrade) | `?token=` or `Authorization` | Alias for `/ws` |

---

### 3.9 WebSocket Protocol Specification

| Message `type` | Origin | Handled in Frontend? | File & Line Reference | Documented in `PROPOSED_SOLUTION.md`? |
| :--- | :--- | :--- | :--- | :--- |
| `hello` | Daemon -> Client | Yes (sets `isMock`) | `server.go:231`, `useWebSocket.ts:98` | Yes (Section 8) |
| `snapshot` | Daemon -> Client | Yes (loads initial alerts & mock) | `server.go:242`, `useWebSocket.ts:102, 120` | Yes (Section 8) |
| `initial_state`| Daemon -> Client | Yes (loads initial alerts & mock) | `server.go:255`, `useWebSocket.ts:102, 121` | Yes (Section 8) |
| `event` | Daemon -> Client | Yes (pushed to event buffer) | `hub.go:90`, `useWebSocket.ts:108` | Yes (Section 8) |
| `alert` | Daemon -> Client | Yes (pushed to alert buffer) | `hub.go:104`, `useWebSocket.ts:112` | Yes (Section 8) |
| `metrics` | Daemon -> Client | Yes (sets telemetry state) | `hub.go:118`, `useWebSocket.ts:116` | Yes (Section 8) |

*Simulation Flag:* The `mock: true` boolean is transmitted in both `hello` and `snapshot`/`initial_state` payloads `[CODE: internal/api/server.go:232, 247]`.

---

### 3.10 Frontend Architecture & UI Structure

- **Framework:** Next.js 14 App Router with standalone output configuration `[CODE: web-ui/next.config.js:4]`.
- **Primary Views (Tabs):**
  1. `overview`: KPI summary cards (`MetricsOverview.tsx`), throughput charts (`MetricsChart.tsx`), alert snippet feed, and live event snippet stream `[CODE: web-ui/src/app/page.tsx:30-46]`.
  2. `tree`: Fullscreen interactive SVG process lineage tree built with D3.js (`ProcessTree.tsx`) `[CODE: web-ui/src/app/page.tsx:48-52]`.
  3. `alerts`: Complete historical security alerts feed with search and severity filter pills (`AlertFeed.tsx`) `[CODE: web-ui/src/app/page.tsx:54-58]`.
  4. `events`: Full-page searchable and clearable kernel event stream table (`LiveEventStream.tsx`) `[CODE: web-ui/src/app/page.tsx:60-64]`.
- **WebSocket URL Construction:** Resolves `process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:8080/ws'` `[CODE: web-ui/src/hooks/useWebSocket.ts:82]`.
- **Render Throttle & Batching:** Incoming WebSocket messages are queued in `useRef` arrays and flushed to React state at 10 Hz (`FLUSH_INTERVAL_MS = 100`) via `setInterval` to prevent DOM rendering saturation `[CODE: web-ui/src/hooks/useWebSocket.ts:40-77]`.
- **List Capacities:** Hard bounded in React state:
  - `MAX_EVENT_HISTORY = 5000` `[CODE: web-ui/src/hooks/useWebSocket.ts:12]`
  - `MAX_ALERT_HISTORY = 500` `[CODE: web-ui/src/hooks/useWebSocket.ts:13]`
- **SIMULATION Badge Rendering:** Rendered in `Header.tsx:86-102` inside the title area with `id="simulation-badge"`. Conditionally displayed when `isMock === true` `[CODE: web-ui/src/components/Header.tsx:86]`.

---

### 3.11 Memory Bounds & Queue Capacities

Every dynamic structure in SentinelBPF is strictly bounded to prevent memory leaks or denial of service:

| Component / Structure | Bound / Limit | Enforcement Mechanism & Source |
| :--- | :--- | :--- |
| **Kernel Ring Buffer** | 16 MiB (16,777,216 bytes) | Kernel-enforced ring buffer `[CODE: bpf/sentinel.bpf.c:32]` |
| **Internal Event Channel** | 65,536 events | Buffered Go channel; drops non-blocking `[CODE: internal/bpf/bpf_linux.go:79-84]` |
| **Process Table Cache** | 10,000 processes | Evicts exited processes first, then oldest `[CODE: cmd/main.go:88, proctable.go:55]` |
| **Process Lineage Depth**| 32 ancestors | Cycle-prevention depth cutoff `[CODE: internal/proctable/proctable.go:153]` |
| **Rule Engine Alert History**| 5,000 alerts | Bounded FIFO slice eviction `[CODE: internal/rules/rule.go:88, 153]` |
| **Rule Cooldown Map** | 1,024 entries | Pruned of expired entries periodically `[CODE: internal/rules/rule.go:183]` |
| **Per-Client WS Queue** | 1,024 messages | Client dropped if buffer fills `[CODE: internal/hub/hub.go:69, 81]` |
| **Hub Client Registry** | 64 concurrent changes | Buffered register/unregister channels `[CODE: internal/hub/hub.go:44-45]` |
| **Frontend Event History** | 5,000 records | `slice(combined.length - 5000)` `[CODE: web-ui/src/hooks/useWebSocket.ts:49]` |
| **Frontend Alert History** | 500 records | `slice(0, 500)` `[CODE: web-ui/src/hooks/useWebSocket.ts:62]` |

---

### 3.12 Operating Systems Concepts to Code Map

| OS Concept | Code Location (`file:line`) | Concrete Implementation in SentinelBPF |
| :--- | :--- | :--- |
| **Process Execution & Lifecycle** | `bpf/sentinel.bpf.c:99-137`, `internal/proctable/proctable.go:79-125` | Hooks `sched_process_exec`, `sched_process_fork`, and `sched_process_exit` to build real-time process hierarchy trees. |
| **System Call Tracepoints** | `bpf/sentinel.bpf.c:139-390`, `internal/bpf/bpf_linux.go:213-236` | Intercepts system call entries (`sys_enter_openat`, `connect`, `dup3`, `ptrace`, `mount`, `setuid`) before execution. |
| **Kernel Verifier Safety** | `bpf/sentinel.bpf.c:51-60`, `internal/bpf/bpf_linux.go:173-179` | Restricts C code to bounded loops, probe read helpers, memory zeroing, and GPL licensing required by the Linux kernel verifier. |
| **Lockless Ring Buffer IPC** | `bpf/sentinel.bpf.c:30-33`, `internal/bpf/bpf_linux.go:54-89` | Uses Linux BPF ring buffer for high-throughput zero-copy event transport from kernel space to user space. |
| **Real vs. Effective UID** | `internal/rules/priv_esc.go:40-45`, `bpf/sentinel.bpf.c:75` | Reads `cred->uid` and `cred->euid`; checks effective UID so legitimate setuid binaries (`/usr/bin/passwd`) running as root are not falsely alerted. |
| **File Descriptor Redirection** | `internal/rules/reverse_shell.go:96-109`, `bpf/sentinel.bpf.c:215-245` | Observes `dup2`/`dup3` duplicating a network socket descriptor onto `stdin` (0), `stdout` (1), or `stderr` (2). |
| **Network Sockets & Endpoints**| `internal/rules/reverse_shell.go:79-95`, `bpf/sentinel.bpf.c:175-213` | Parses `sockaddr_in` from `sys_enter_connect` to record destination IPv4 address and destination port. |
| **Namespaces & Cgroup Isolation**| `internal/container/container.go:30-75`, `bpf/sentinel.bpf.c:70` | Reads `cgroup_id` via `bpf_get_current_cgroup_id()` to detect container boundaries and container breakout mount attempts. |
| **Asynchronous Backpressure** | `internal/bpf/bpf_linux.go:79-85`, `internal/hub/hub.go:80-85` | Implements non-blocking channel selects that drop events on user space congestion while recording drops, preventing kernel reader stalls. |

---

## Section 4. How to Build and Run (As It Works Today)

### 4.1 First-Time Setup & Prerequisites
On Ubuntu / Debian WSL2:
```bash
sudo apt update && sudo apt install -y clang llvm libbpf-dev linux-tools-generic bpftool make nodejs npm
```
*Verification of Toolchain:*
Ensure Linux Node.js is selected (`which node npm` must output `/usr/bin/node` and `/usr/bin/npm`). Never run Windows `npm.cmd` from WSL2.

### 4.2 Building the Components
```bash
# 1. Generate vmlinux.h from running kernel BTF (only needed if kernel changes)
make vmlinux

# 2. Build eBPF C programs and regenerate Go bpf2go bindings
make build-ebpf

# 3. Build daemon executable into bin/sentinel-daemon
make build-daemon

# 4. Build frontend Next.js application
make build-ui
```

### 4.3 Running Daemon in Mock Mode (No Root Required)
```bash
# Verify port 8080 is available
ss -ltn | grep 8080 || echo "Port 8080 is free"

# Launch mock daemon
./bin/sentinel-daemon --config config.yaml --mock
```
*Daemon Ports:* Binds HTTP & WebSocket on `http://127.0.0.1:8080`.

### 4.4 Running Dashboard
```bash
cd web-ui
npm run dev
```
*Frontend Port:* Binds Next.js UI on `http://localhost:3000`.

### 4.5 Clean Termination & Zombie Process Cleanup
```bash
# Gracefully stop daemon
pkill -TERM -f sentinel-daemon

# Verify port 8080 is completely released
ss -ltn | grep 8080 || echo "8080 free again"
```

### 4.6 Real eBPF Mode Execution (Requires Root - Run ONLY on disposable Linux VM)
```bash
# CAUTION: Never run without explicit user consent on a designated VM
sudo ./bin/sentinel-daemon --config config.yaml
```

---

*(Sections 5 to 13 and Appendix A will be completed in subsequent phases as mandated by `REPORT_INSTRUCTIONS.md`)*
