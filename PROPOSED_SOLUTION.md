# SentinelBPF: Proposed Solution & Architecture Specification

## 1. System Overview

SentinelBPF is a host-based intrusion detection system (HIDS) for Linux systems operating on modern kernels (5.8+) using eBPF (Extended Berkeley Packet Filter) with CO-RE (Compile Once - Run Everywhere).

SentinelBPF is strictly **detection-only**. It intercepts system events at the kernel boundary with minimal overhead, streams structured records to user space through an efficient BPF ring buffer, evaluates detection rules against process state machines, and provides real-time visibility through a modern web dashboard.

```
+-------------------------------------------------------------------------+
|                              Linux Kernel                               |
|                                                                         |
|  [tracepoint/sched/sched_process_exec]                                  |
|  [tracepoint/sched/sched_process_exit]                                  |
|  [tracepoint/sched/sched_process_fork]       [BPF Ring Buffer: 16MB]    |
|  [sys_enter_openat]                  ----->  +------------------------+ |
|  [sys_enter_connect]                         | 480-byte event records | |
|  [sys_enter_dup2 / dup3]                     +------------------------+ |
|  [sys_enter_ptrace, mount, setuid]                       |              |
+----------------------------------------------------------|--------------+
                                                           | bpf_ringbuf_consume
+----------------------------------------------------------v--------------+
|                    SentinelBPF Daemon (Go Userspace)                    |
|                                                                         |
|  +---------------------+    +-------------------+    +---------------+  |
|  | Ring Buffer Reader  |--->| Event Dispatcher  |--->| Rules Engine  |  |
|  +---------------------+    +-------------------+    +---------------+  |
|                                       |                     |           |
|                             +---------v---------+           v           |
|                             | Process Table &   |      [Alert Engine]   |
|                             | Container Tracker |           |           |
|                             +-------------------+           |           |
|                                       |                     |           |
|                               +-------v---------------------v-------+   |
|                               |       Hub & WebSocket Server        |   |
|                               +-------------------------------------+   |
+--------------------------------------------------|----------------------+
                                                   | WS /api/v1/ws
+--------------------------------------------------v----------------------+
|                     Web Dashboard (Next.js / React)                     |
|  - D3.js Process Lineage Tree                                           |
|  - ECharts Metrics & Drop Telemetry                                     |
|  - Live Alert Stream & Event Log (Batched 10Hz UI updates)              |
+-------------------------------------------------------------------------+
```

---

## 2. Kernel Hooks & Telemetry Model

SentinelBPF hooks low-overhead tracepoints and syscall entries:

| Hook Type | Hook Name | Purpose | Kernel Filtering |
| :--- | :--- | :--- | :--- |
| `tp_btf` / `tracepoint` | `sched/sched_process_exec` | Process execution, binary path, argument extraction | Ignore daemon PID |
| `tracepoint` | `sched/sched_process_exit` | Process termination, process table cleanup | Ignore daemon PID |
| `tracepoint` | `sched/sched_process_fork` | Child/Parent PID tracking, lineage maintenance | Ignore daemon PID |
| `tracepoint` | `syscalls/sys_enter_openat` | File tampering & sensitive path access | Write flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`) |
| `tracepoint` | `syscalls/sys_enter_connect` | Network connections, socket to remote IP:port | Non-UNIX families checked |
| `tracepoint` | `syscalls/sys_enter_dup2` / `dup3` | Socket file descriptor duplication | `newfd` in 0, 1, or 2 |
| `tracepoint` | `syscalls/sys_enter_ptrace` | Process injection & memory manipulation | Requests modifying memory/registers |
| `tracepoint` | `syscalls/sys_enter_mount` | Filesystem mounting, container escape attempts | None (low frequency) |
| `tracepoint` | `syscalls/sys_enter_setuid` | Privilege escalation attempts | `euid != 0` check |

---

## 3. Memory & Buffer Safety

1. **BPF Ring Buffer**: A single multi-producer single-consumer (MPSC) BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`) with default capacity of 16 MB (`1 << 24` bytes).
2. **Zero-Copy Reservation**: The eBPF program calls `bpf_ringbuf_reserve()`. If memory allocation fails, the event is dropped and an atomic per-CPU counter (`drops`) is incremented.
3. **Zeroed Memory**: The reserved memory slot is zero-initialized using `__builtin_memset` via the `reserve()` helper to ensure no kernel memory leakage.
4. **User-Space Non-Blocking Reader**: The ring buffer reader thread in Go only reads and unpacks raw bytes into memory, immediately pushing to a Go channel. All rule evaluation and network serialization occur in downstream worker goroutines.

---

## 4. Shared Struct Contract (`struct event`)

The contract between kernel and user space is defined in `bpf/sentinel.h`.
The struct is **strictly 480 bytes**, 8-byte aligned, with zero implicit compiler padding:

```c
struct event {
    /* 64-bit aligned fields (40 bytes) */
    __u64 timestamp_ns;  /* monotonic kernel timestamp in nanoseconds */
    __u64 cgroup_id;     /* cgroup v2 ID for container correlation   */
    __u64 event_type;    /* EVENT_EXEC, EVENT_EXIT, EVENT_OPENAT, ... */
    __u64 retval;        /* return code or syscall parameter          */
    __u64 flags;         /* open flags, clone flags, ptrace request   */

    /* 32-bit aligned fields (40 bytes) */
    __u32 pid;           /* process thread group ID                   */
    __u32 tid;           /* thread ID                                 */
    __u32 ppid;          /* parent process ID                         */
    __u32 uid;           /* real user ID                              */
    __u32 gid;           /* real group ID                             */
    __u32 euid;          /* effective user ID                         */
    __u32 egid;          /* effective group ID                        */
    __u32 fd;            /* primary file descriptor / socket fd       */
    __u32 oldfd;         /* source fd for dup2/dup3                   */
    __u32 newfd;         /* target fd for dup2/dup3                   */

    /* 16-bit aligned fields & network info (16 bytes) */
    __u32 saddr;         /* source IPv4 address (network byte order)  */
    __u32 daddr;         /* dest IPv4 address (network byte order)    */
    __u16 sport;         /* source port (network byte order)          */
    __u16 dport;         /* dest port (network byte order)            */
    __u16 family;        /* socket address family (AF_INET, etc.)     */
    __u16 protocol;      /* IP protocol (IPPROTO_TCP, etc.)           */

    /* Byte buffers (384 bytes) */
    char comm[16];       /* task_struct->comm (truncated to 16 bytes) */
    char pcomm[16];      /* parent comm                               */
    char path[256];      /* target executable or file path            */
    char extra[96];      /* arguments, mount targets, or extra ctx    */
};
```

### Exact Size & Offset Breakdown:
- Bytes 0-39: 5 `__u64` fields (40 bytes)
- Bytes 40-79: 10 `__u32` fields (40 bytes)
- Bytes 80-87: 2 `__u32` IPv4 addresses (8 bytes)
- Bytes 88-95: 4 `__u16` fields (8 bytes)
- Bytes 96-127: 2 16-byte char arrays (`comm`, `pcomm`) (32 bytes)
- Bytes 128-383: 256-byte `path` string (256 bytes)
- Bytes 384-479: 96-byte `extra` string (96 bytes)
- **Total: 480 bytes**. `sizeof(struct event) == 480`.

---

## 5. Process Table & Container Correlation

- **Process Table** (`internal/proctable`):
  - In-memory thread-safe map tracking process metadata: PID, PPID, Comm, Path, Args, StartTime, EUID, CgroupID, Parent Pointer.
  - Generates full process ancestry trees (`GetLineage(pid)`).
  - Bounded size: processes that exit (`sched_process_exit`) are culled after a cooldown to prevent memory leaks while allowing short-term correlation.
  - `/proc` fallback: only queried when a PID is missing from cache (e.g., daemon started after existing processes), rate-limited to 50 lookups/sec.
- **Container Tracking** (`internal/container`):
  - Resolves `cgroup_id` from kernel to runtime container ID (Docker, containerd, Kubernetes).
  - Caches resolution results in memory.

---

## 6. Detection Rules & State Machines

Every detection rule satisfies `Rule.Handle(ev *events.Event, state *State) []Alert`.

### 6.1 Privilege Escalation
- Identifies `sys_enter_setuid` / `setresuid` where target UID is 0 and caller `euid != 0`.
- Monitors execution of sensitive setuid binaries (`sudo`, `pkexec`, `su`).
- Normalizes paths using `filepath.Clean`.

### 6.2 Sensitive File Tampering
- Detects `sys_enter_openat` with write flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`) targeting critical system files:
  - `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/*`
  - `/etc/ld.so.preload`, `/etc/pam.d/*`
  - `/root/.ssh/*`, `~/.ssh/authorized_keys`
  - `/etc/crontab`, `/etc/cron.*`
- Allowlist engine for benign processes (`passwd`, `vipw`, `useradd`, `usermod`, `apt`, `dpkg`).

### 6.3 Process Injection / Defense Evasion
- Detects `sys_enter_ptrace` with trace/memory-write requests (`PTRACE_POKETEXT`, `PTRACE_POKEDATA`, `PTRACE_ATTACH`, `PTRACE_SEIZE`) from unapproved binaries.
- Flags debugger attachments against production processes.

### 6.4 Unauthorized Mount / Container Escape
- Monitors `sys_enter_mount` executed from non-root namespaces or within container cgroups.

### 6.5 De-duplication Engine
- De-duplicates alerts across a sliding window keyed by `(rule_name, pid, target_key)`.
- Prevents alert storms while guaranteeing distinct alerts are surfaced.

### 6.6 Reverse Shell State Machine Specification
Naive intrusion detectors flag any outbound network connection followed by a shell execution. This creates rampant false positives (e.g., CI/CD agents, administrative SSH sessions, package managers).

SentinelBPF implements a **3-stage strict state machine**:

```
 [State 0: IDLE]
       |
       | sys_enter_connect (remote external IP:port)
       v
 [State 1: CONNECTED] (records socket fd, remote ip:port, timestamp)
       |
       | sys_enter_dup2 / dup3 (oldfd == socket_fd, newfd in {0, 1, 2})
       v
 [State 2: REDIRECTED] (standard I/O redirected to socket)
       |
       | sched_process_exec (binary in shell_binaries: /bin/sh, /bin/bash, /bin/zsh, python, nc...)
       v
 [State 3: ALERT: REVERSE_SHELL_DETECTED] (Emits CRITICAL alert)
```

- **Loopback Handling**: Connections to `127.0.0.1` or `::1` are ignored by default unless `treat_loopback_as_external: true` is configured (essential for safe sandbox testing).
- **Timeout**: State expires after 30 seconds if the subsequent transitions do not occur.

---

## 7. HTTP API Routes

| Route | Auth Required (when `auth_token` is set) |
| :--- | :--- |
| `/health`, `/api/v1/health` | None |
| `/api/v1/status`, `/api/v1/alerts`, `/api/v1/processes`, `/api/v1/process/<pid>` | Bearer token or `?token=` |
| `/ws`, `/api/v1/ws` | Origin check + `?token=` if `auth_token` set |

---

## 8. WebSocket Protocol Specification

WebSocket clients connect to `ws://<host>:<port>/ws` (or `/api/v1/ws`).

### Authentication & Handshake
- Clients may authenticate using `?token=<auth_token>` or `Authorization: Bearer <auth_token>` header.
- The server validates the HTTP `Origin` header against `allowed_origins`.

### Message Types

| Type | Direction | Payload Description |
| :--- | :--- | :--- |
| `hello` | Server -> Client | Connection greeting with version and mock mode indicator |
| `snapshot` | Server -> Client | Initial snapshot: recent alerts, active processes, uptime, mock mode |
| `initial_state` | Server -> Client | Initial snapshot (alias for snapshot): recent alerts, daemon stats, active rules |
| `event` | Server -> Client | Real-time decoded kernel event record |
| `alert` | Server -> Client | Real-time security alert |
| `metrics` | Server -> Client | Periodic (1s) telemetry: drops, EPS, queue sizes, memory |
| `ping` / `pong` | Bidirectional | Liveness heartbeats every 15 seconds |

#### Hello Message (`type: "hello"`):
```json
{
  "type": "hello",
  "mock": true,
  "version": "1.0.0"
}
```
The `mock` field indicates whether the daemon is running in simulation mode (`true`) or live eBPF mode (`false`). The dashboard uses this to display a SIMULATION badge.

### Snapshot Message (`type: "snapshot"`):
```json
{
  "type": "snapshot",
  "data": {
    "alerts": [...],
    "active_processes": 42,
    "uptime_seconds": 3600,
    "mock": false
  }
}
```
The `snapshot` message carries the same payload as `initial_state` — both are sent to newly connected clients for backward compatibility. The `mock` field is optional and present on both.

### Message Shapes

#### Event Message (`type: "event"`):
```json
{
  "type": "event",
  "data": {
    "timestamp_ns": 1696377600000000,
    "event_type": "EXEC",
    "pid": 14205,
    "tid": 14205,
    "ppid": 14200,
    "uid": 1000,
    "gid": 1000,
    "euid": 1000,
    "egid": 1000,
    "comm": "bash",
    "pcomm": "sshd",
    "path": "/bin/bash",
    "extra": "-i",
    "cgroup_id": 4096,
    "container_id": "docker-abc123",
    "saddr": "192.168.1.10",
    "daddr": "10.0.0.1",
    "sport": 54322,
    "dport": 443
  }
}
```

#### Alert Message (`type: "alert"`):
```json
{
  "type": "alert",
  "data": {
    "id": "alt_01HGB45X9Z0",
    "timestamp": "2026-10-04T00:05:00Z",
    "rule_name": "reverse_shell",
    "severity": "CRITICAL",
    "mitre_technique": "T1059.004",
    "pid": 14205,
    "ppid": 14200,
    "comm": "sh",
    "path": "/bin/sh",
    "container_id": "docker-abc123",
    "message": "Reverse shell detected: standard I/O redirected to 10.0.0.1:4444 followed by shell execution",
    "details": {
      "remote_ip": "10.0.0.1",
      "remote_port": 4444,
      "redirected_fds": [0, 1, 2]
    }
  }
}
```

#### Metrics Message (`type: "metrics"`):
```json
{
  "type": "metrics",
  "data": {
    "events_per_sec": 1250,
    "kernel_drops": 0,
    "queue_drops": 0,
    "active_processes": 342,
    "active_clients": 2,
    "uptime_seconds": 3600,
    "mem_alloc_mb": 24.5
  }
}
```

---

## 8. Backpressure & Drop Policy

1. **Kernel Ring Buffer**: Fixed size (16MB). If full, `bpf_ringbuf_reserve` fails, atomic increment to `drops`.
2. **User Space Channel**: Buffered channel (capacity 65,536).
3. **WebSocket Hub Backpressure**:
   - Each connected client has an isolated buffered channel (capacity 2,048).
   - If a client's buffer reaches capacity:
     - `event` messages are dropped first.
     - `alert` messages are **never dropped** unless the client channel is completely congested.
     - Clients that stay blocked for >5 seconds are terminated to protect daemon resources.
