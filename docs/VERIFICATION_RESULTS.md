# SentinelBPF Verification Results

**Date of Execution:** 2026-10-18  
**Environment:** Linux WSL2 (`6.18.54.1-microsoft-standard-WSL2` x86_64)  
**Go Version:** `go1.22.2 linux/amd64`  
**Clang Version:** `Ubuntu clang version 18.1.3 (1ubuntu1)`  
**Node.js / npm:** `/usr/bin/node` (`v18.19.1`), `/usr/bin/npm` (`9.2.0`)  
**Repository Branch:** `main` (Initial commit: `2928c95`)

---

## 1. Verification Summary Table

| Check / Test Target | Command | Result | Exit Code | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Go Static Analysis** | `go vet ./...` | **PASS** | `0` | Zero vet diagnostics reported |
| **Go Unit Tests** | `go test ./... -count=1` | **PASS** | `0` | All 7 test suites passed (api, config, container, events, hub, proctable, rules) |
| **Go Race Detection** | `go test -race -count=1 ./...` | **PASS** | `0` | All test suites passed with 0 data races detected |
| **eBPF Build & Bindings**| `make build-ebpf` | **PASS** | `0` | Dumped `vmlinux.h`, ran `bpf2go`, generated `sentinel_bpfel_x86.o` & `.go` |
| **Daemon Build** | `make build-daemon` | **PASS** | `0` | Built executable `bin/sentinel-daemon` |
| **Web UI Build** | `cd web-ui && npm ci && npm run build` | **PASS** | `0` | Compiled Next.js 14 standalone bundle, 4/4 static pages generated |
| **End-to-End Mock Script**| `bash scripts/test_e2e_mock.sh` | **FAIL** | `1` | REST endpoints passed; failed on step 5 (`wsprobe` separate module error) |
| **Struct Event 480 Bytes**| `go test -v -run TestRawEventSize ./internal/events && go test -v -run TestFromRawDecoding ./internal/events` | **PASS** | `0` | Verified `_Static_assert` in `bpf/sentinel.h:63` and Go test assertions |

---

## 2. Raw Output Excerpts

### 2.1 Go Unit Tests (`go test ./... -count=1`)
```
?   	github.com/sentinel-bpf/sentinel/cmd/sentinel-daemon	[no test files]
?   	github.com/sentinel-bpf/sentinel/internal/bpf	[no test files]
?   	github.com/sentinel-bpf/sentinel/web-ui/node_modules/flatted/golang/pkg/flatted	[no test files]
ok  	github.com/sentinel-bpf/sentinel/internal/api	0.005s
ok  	github.com/sentinel-bpf/sentinel/internal/config	0.005s
ok  	github.com/sentinel-bpf/sentinel/internal/container	0.003s
ok  	github.com/sentinel-bpf/sentinel/internal/events	0.004s
ok  	github.com/sentinel-bpf/sentinel/internal/hub	0.069s
ok  	github.com/sentinel-bpf/sentinel/internal/proctable	0.004s
ok  	github.com/sentinel-bpf/sentinel/internal/rules	0.005s
```

### 2.2 Go Race Detection (`go test -race -count=1 ./...`)
```
?   	github.com/sentinel-bpf/sentinel/cmd/sentinel-daemon	[no test files]
?   	github.com/sentinel-bpf/sentinel/internal/bpf	[no test files]
?   	github.com/sentinel-bpf/sentinel/web-ui/node_modules/flatted/golang/pkg/flatted	[no test files]
ok  	github.com/sentinel-bpf/sentinel/internal/api	1.019s
ok  	github.com/sentinel-bpf/sentinel/internal/config	1.018s
ok  	github.com/sentinel-bpf/sentinel/internal/container	1.015s
ok  	github.com/sentinel-bpf/sentinel/internal/events	1.015s
ok  	github.com/sentinel-bpf/sentinel/internal/hub	1.075s
ok  	github.com/sentinel-bpf/sentinel/internal/proctable	1.016s
ok  	github.com/sentinel-bpf/sentinel/internal/rules	1.021s
```

### 2.3 eBPF Compilation (`make build-ebpf`)
```
Generating bpf/vmlinux.h from running kernel BTF...
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
Compiling eBPF programs and generating Go bindings via go generate...
cd internal/bpf && go generate ./...
Compiled /home/aayush/SentinelBPF/internal/bpf/sentinel_bpfel_x86.o
Stripped /home/aayush/SentinelBPF/internal/bpf/sentinel_bpfel_x86.o
Wrote /home/aayush/SentinelBPF/internal/bpf/sentinel_bpfel_x86.go
```

### 2.4 Daemon Compilation (`make build-daemon`)
```
Building SentinelBPF daemon...
go build -v -o bin/sentinel-daemon ./cmd/sentinel-daemon
github.com/sentinel-bpf/sentinel/internal/bpf
github.com/sentinel-bpf/sentinel/cmd/sentinel-daemon
```

### 2.5 Web UI Build (`npm ci && npm run build`)
```
> sentinel-bpf-dashboard@1.0.0 build
> next build

  ▲ Next.js 14.2.15

   Creating an optimized production build ...
 ✓ Compiled successfully
   Linting and checking validity of types ...
   Collecting page data ...
   Generating static pages (0/4) ...
   Generating static pages (1/4) 
   Generating static pages (2/4) 
   Generating static pages (3/4) 
 ✓ Generating static pages (4/4)
   Finalizing page optimization ...
   Collecting build traces ...

Route (app)                              Size     First Load JS
┌ ○ /                                    27.2 kB         114 kB
└ ○ /_not-found                          875 B            88 kB
+ First Load JS shared by all            87.1 kB
  ├ chunks/117-cfe36332518bb67d.js       31.6 kB
  ├ chunks/fd9d1056-75b5a93c97da044e.js  53.7 kB
  └ other shared chunks (total)          1.85 kB

○  (Static)  prerendered as static content
```

### 2.6 Struct Event 480 Bytes Assertions
```
=== RUN   TestRawEventSize
--- PASS: TestRawEventSize (0.00s)
PASS
ok  	github.com/sentinel-bpf/sentinel/internal/events	0.003s
=== RUN   TestFromRawDecoding
--- PASS: TestFromRawDecoding (0.00s)
PASS
ok  	github.com/sentinel-bpf/sentinel/internal/events	0.003s
```
Matching C declaration in `bpf/sentinel.h:62-64`:
```c
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct event) == 480, "struct event must be exactly 480 bytes");
#endif
```

### 2.7 Failure: `scripts/test_e2e_mock.sh`
```
=== 1. /health ===
{"status":"healthy","timestamp":"2026-10-18T11:07:55Z"}

=== 2. /api/v1/status ===
{"active_clients":0,"active_processes":2,"events_processed":2,"kernel_drops":0,"mock":true,"uptime_seconds":1}

=== 3. /api/v1/alerts ===
{"alerts":[],"count":0}

=== 4. /api/v1/processes ===
{"count":2,"processes":[{"pid":2001,"ppid":1000,"uid":1000,"gid":1000,"euid":1000,"egid":1000,"comm":"worker","path":"/bin/sh","args":"-c","cgroup_id":2,"start_time_ns":1792321674860549437,"exited":false},{"pid":2002,"ppid":1000,"uid":1000,"gid":1000,"euid":1000,"egid":1000,"comm":"worker","path":"/bin/bash","args":"-c","cgroup_id":2,"start_time_ns":1792321675210262239,"exited":false}]}

=== 5. wsprobe ===
main module (github.com/sentinel-bpf/sentinel) does not contain package github.com/sentinel-bpf/sentinel/scripts/wsprobe
```
*Failure Analysis:*
`scripts/test_e2e_mock.sh:28` runs `go run ./scripts/wsprobe -duration 10s`. However, `scripts/wsprobe` has its own standalone `go.mod` (module `wsprobe`). Because the root module is `github.com/sentinel-bpf/sentinel`, the Go toolchain rejects running `./scripts/wsprobe` as a subpackage of the root module. To fix without modifying root `go.mod`, line 28 should change directory into `scripts/wsprobe` before invoking `go run .` (e.g., `(cd scripts/wsprobe && go run . -duration 10s)`). Per hard instructions, this was recorded as a failure and source code was not modified.

---

## 3. Discrepancies Noted Between Code and Documentation

1. **`scripts/test_e2e_mock.sh` wsprobe Module Invocation:**  
   The script assumes `scripts/wsprobe` is part of the root Go module, causing an immediate failure on step 5 under `set -e`.
2. **Third-Party Go Package in `web-ui/node_modules`:**  
   `npm install` installs the `flatted` package, which includes a Go implementation in `web-ui/node_modules/flatted/golang/pkg/flatted`. An unconstrained `go test ./...` discovers and reports this package (`? ... [no test files]`).
3. **Frontend Test Script (`npm test`):**  
   `web-ui/package.json:10` defines `"test": "node -e \"console.log('Frontend unit checks passed')\""`, which is an unverified dummy echo rather than a real test framework (e.g. Jest or Vitest).
4. **`tp_btf` Hook Counts:**  
   Historical documents (`AGENT_SECOND.md:134`) referenced `tp_btf` alongside syscall tracepoints. In actual code (`bpf/sentinel.bpf.c:99` and `internal/bpf/bpf_linux.go:195-223`), **only** `sched_process_exec` uses `tp_btf` (`link.AttachTracing`). Fork (`sched_process_fork`) and exit (`sched_process_exit`) use standard tracepoints (`link.Tracepoint("sched", ...)`). This is correct by design — `tp_btf` is used for the exec hook which needs CO-RE access to `task_struct`, while fork/exit use standard tracepoints. `CLAUDE_CONTEXT_REPORT.md` Section 3.4 contains the corrected attachment table.
5. **eBPF Map Names vs. Documentation:**  
   Documents frequently instruct `bpftool map show | grep -i sentinel`. In actual code (`bpf/sentinel.bpf.c:32, 40, 48`), the map names are `events`, `drops`, and `ignored_pids`—none include the substring "sentinel". The correct inspection command is `sudo bpftool map show | grep -i -E 'events|drops|ignored_pids'`.
6. **Process Tree Mock Lineage:**  
   Previously all synthetic events hardcoded `Ppid: 1000`. This has been corrected — seed processes now use realistic multi-level ancestry (systemd(1)->sshd(100)->bash(200)->python3(300)) and dynamically generated events use correct parent PIDs. Verified: no `Ppid: 1000` remains in `internal/bpf/bpf.go`.
7. **WebSocket Client Authentication:**  
   Previously `useWebSocket.ts` did not append the `?token=` query parameter. Fixed by reading `NEXT_PUBLIC_WS_TOKEN` from the environment and appending it to the WebSocket URL (`web-ui/src/hooks/useWebSocket.ts:105-109`, `web-ui/next.config.js`). The server enforces `auth_token` via the `?token=` query parameter (`internal/api/server.go:208-220`).
8. **Missing `/tmp` Execution Rule:**  
   Audits mention `/tmp` execution detection, but there is no rule implementation for `/tmp` execution in `internal/rules/` and no configuration section in `config.yaml`.

---

## 4. Risks for the First Real eBPF Load

*(Do not execute these on the user's host machine. Reserved for an isolated disposable Linux VM)*

1. **Kernel BTF Dependency (`/sys/kernel/btf/vmlinux`):**  
   `internal/bpf/bpf_linux.go:152` checks for `/sys/kernel/btf/vmlinux` and aborts if it is absent (`CONFIG_DEBUG_INFO_BTF=y` required).
2. **Root Privilege Gate:**  
   `internal/bpf/bpf_linux.go:147` halts execution if `os.Geteuid() != 0`. Loading requires `sudo` or `CAP_BPF` / `CAP_SYS_ADMIN`.
3. **Strict Fatal Attachments on Syscall Tracepoints:**  
   In `internal/bpf/bpf_linux.go:213-236`, 9 of the 10 hooks have `opt: false`. If any syscall tracepoint (e.g., `sys_enter_mount`, `sys_enter_ptrace`, or `sys_enter_setuid`) fails to attach on the kernel, the daemon immediately exits with a fatal error.
4. **Kernel Verifier Rejections:**  
   The eBPF program relies on CO-RE relocations (`vmlinux.h`). A mismatch in kernel data structure layouts or pointer arithmetic could trigger verifier errors (`ve *ebpf.VerifierError`).
5. **Daemon Self-Tracing Loop Risk:**  
   In `internal/bpf/bpf_linux.go:182-184`, failure to add the daemon PID to `ignored_pids` only logs a warning (`[WARN] Failed to add self to ignored_pids map`) without halting. If the daemon traces its own network/file activity, an event storm could saturate the ring buffer and drop kernel events.

---

## 5. Round 3 — Re-verification After Fixes

### 5.1 Re-run Results Table

| Check / Test Target | Command | Result | Exit Code | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Go Static Analysis | `go vet ./cmd/... ./internal/...` | **PASS** | `0` | Zero vet diagnostics on scoped packages |
| Go Unit & Race Tests | `go test ./cmd/... ./internal/... -race -count=1` | **PASS** | `0` | All 8 packages pass (api, bpf, config, container, events, hub, proctable, rules) |
| Daemon Build | `make build-daemon` | **PASS** | `0` | `bin/sentinel-daemon` built successfully |
| Web UI Build | `cd web-ui && npm run build` | **PASS** | `0` | Next.js production build, 4/4 static pages |
| TypeScript Check | `npx tsc --noEmit` | **PASS** | `0` | Clean, no type errors |
| Tree Builder Test | `processTreeBuilder.test.ts` (16 processes) | **PASS** | `0` | 26/26 assertions pass, depth = 5 |
| E2E Mock Script | `bash scripts/test_e2e_mock.sh` | **PASS** | `0` | All 5 steps pass; reverse shell alert detected |

### 5.2 Task 5 — Bounded-Growth Check (Mock Daemon)

Started `./bin/sentinel-daemon --mock` and polled endpoints:

| Time | `active_processes` | `/api/v1/processes` count |
| :--- | :--- | :--- |
| ~53s | 16 | 16 |
| ~89s | 16 | 16 |
| ~218s | 16 | 16 |

**Result**: Count is stable at 16 across all readings. **No bounded growth.** Process table correctly recycles PID slots via exit events.

### 5.3 Still Open

- Problem B (tree zoom/pan/collapse/tooltip/search/alerts-only) — partially complete: zoom, pan, fit-to-view done (Task 1); collapse/expand, hover tooltip, search auto-expand, alerts-only toggle deferred per instructions.
- Frontend `npm test` remains a placeholder echo (documented as limitation #6).
- eBPF programs not loaded against a real kernel (requires root + disposable VM).

