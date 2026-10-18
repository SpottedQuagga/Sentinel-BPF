# NEXT_STEPS_FOR_AGENT.md

Instructions for the coding agent (Antigravity) for the next work session on **SentinelBPF**.

Read in this order before changing anything: `AGENTS.md`, `PROJECT_STATUS_REPORT.md` (Revision 2, the source of truth for current state), then this file. If anything here conflicts with `AGENTS.md` safety rules, `AGENTS.md` wins.

---

## 1. Where things stand

Verified by the user in WSL2 (Ubuntu 24.04, kernel 6.18.40.1-microsoft-standard-WSL2, Go 1.22.2, clang 18.1.3, bpftool 7.4.0):

| Verified | Result |
| :--- | :--- |
| `go vet ./...` | clean |
| `clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibpf -c bpf/sentinel.bpf.c` | exit 0 |
| `go test ./...` | api, config, container, events, proctable, rules **pass**; **hub FAILS** |
| Manual `bpf2go` + `go build` | works (binary builds) |
| `./bin/sentinel-daemon --config config.yaml --mock` | runs, raises mock alerts |

Not verified: the dashboard connected to a live daemon, the eBPF verifier / real kernel load, demo scripts, performance.

### Facts discovered (use these, do not re-guess)

**Real HTTP routes** (`internal/api/server.go`):

| Route | Auth |
| :--- | :--- |
| `/health`, `/api/v1/health` | none |
| `/api/v1/status` | `authMiddleware` |
| `/api/v1/alerts` | `authMiddleware` |
| `/api/v1/processes` | `authMiddleware` |
| `/api/v1/process/` (detail) | `authMiddleware` |
| `/ws`, `/api/v1/ws` | handled in `handleWebSocket` |

The docs (`README.md`, `PROPOSED_SOLUTION.md`) wrongly say `/api/health`, `/api/alerts`, `/api/processes`.

**Config schema** (`config.yaml`) uses `server.host/port/auth_token/allowed_origins`, `bpf.ring_buffer_size` (currently 16777216), `bpf.event_buffer_size`, and `rules.*`. The README uses different key names (`listen`, `ringbuf_size_kb`) and a 1 MiB default.

**Build failure:** `make build-ebpf` fails with `Error: missing package, are you running via go generate?` because `bpf2go` is run with `go run` outside `go generate`. The following manual command works:

```bash
cd internal/bpf && GOPACKAGE=bpf go run github.com/cilium/ebpf/cmd/bpf2go \
  -target amd64 -cc clang -cflags "-O2 -g -Wall -I../../bpf" \
  sentinel ../../bpf/sentinel.bpf.c
```
Generated files: `internal/bpf/sentinel_bpfel_x86.go` and `.o`.

**Failing test:** `internal/hub` `TestHubStalledClientDoesNotBlock` (`hub_test.go:99: BroadcastEvent blocked on full client buffer`).

---

## 2. Working environment (important)

- **Source of truth for this session: the Linux copy at `~/SentinelBPF` inside WSL2.** The OneDrive copy is stale. Do not edit both.
- Linux commands (`make`, `go`, `clang`, `bpftool`, `bash scripts/...`) must run **inside WSL**, not in plain PowerShell. From a Windows terminal use:
  ```powershell
  wsl -d Ubuntu-24.04 -e bash -lc "cd ~/SentinelBPF && <command>"
  ```
  If the distro has a different name, check `wsl -l -v`.
- The repo may also be opened as `\\wsl.localhost\Ubuntu-24.04\home\aayush\SentinelBPF`.
- Frontend (`web-ui`) can be built and run from either side, but pick one and say which.
- Line endings must be LF for `*.go`, `*.c`, `*.h`, `*.sh`, `Makefile`. Add a `.gitattributes` if missing:
  ```
  * text=auto
  *.sh text eol=lf
  *.go text eol=lf
  Makefile text eol=lf
  ```

---

## 3. Hard rules for this session

1. **Do not run `sudo` or load eBPF programs.** The user will do the first real kernel load. Prepare it; stop before it.
2. **Do not run `scripts/demo_*`** or any attack simulation.
3. No network connections to anything except `127.0.0.1`.
4. Ask before adding dependencies or changing the shared `struct event`, the WebSocket protocol, or the config schema (renaming config keys counts). Prefer changing docs to match code, not the reverse, unless the code is wrong.
5. Do not edit generated files by hand (`bpf/vmlinux.h`, `internal/bpf/sentinel_bpfel_x86.*`).
6. Never claim something is verified unless you ran the check and saw it pass. Paste exact output for failures.
7. Update `PROJECT_STATUS_REPORT.md` honestly at the end (see Section 6).

---

## 4. Tasks (do in this order)

### Task 1: Fix the hub backpressure bug (ISS-003)

**Problem:** `BroadcastEvent` blocks when a client's send buffer is full. A slow dashboard tab can therefore stall event delivery and, via the pipeline, the ring buffer reader.

**Required behavior:**

- Sending to a client must never block the caller.
- Full buffer on an **event**: drop that event for that client and increment a per-client dropped counter.
- Full buffer on an **alert**: never drop an alert before event. Evict the oldest queued *event* (or oldest message) to make room; if the client stays full for N consecutive attempts (pick a sensible default, make it a constant), disconnect it.
- Keep the last N alerts in a bounded ring for new clients (check whether this already exists).
- Expose aggregate dropped counts for metrics if a metrics path exists.

**Done when:**

```bash
go test -race ./internal/hub/...      # passes, including TestHubStalledClientDoesNotBlock
go test -race ./...                   # no new failures
go vet ./...
gofmt -l .                            # no output
```

Add tests for: alert delivered while event buffer is full; persistently stalled client gets disconnected; healthy clients are unaffected by a stalled one.

### Task 2: Fix `make build-ebpf` (ISS-004)

**Goal:** `make build-ebpf && make build-daemon` succeeds from a clean checkout.

- Add `internal/bpf/gen.go` (package `bpf`) with a `//go:generate` line that runs `bpf2go` with `-target amd64`, `-cc clang`, `-cflags "-O2 -g -Wall -I../../bpf"`, name `sentinel`, source `../../bpf/sentinel.bpf.c`. Drop `bpfeb`; big-endian output is not needed.
- Make the Makefile target `cd internal/bpf && go generate ./...`, with `vmlinux` as a prerequisite.
- Add an `all` target (`build-ebpf build-daemon`) since docs reference `make all`, and a `test` target.
- Do not commit `bpf/vmlinux.h`; keep it in `.gitignore`.
- Note in a comment that the target is x86_64 only, and what to change for arm64.

**Done when:** from a clean tree (`rm -f internal/bpf/sentinel_bpfel_x86.* bin/sentinel-daemon bpf/vmlinux.h`):

```bash
make all
ls -l bin/sentinel-daemon internal/bpf/sentinel_bpfel_x86.go
```

### Task 3: Verify the compiled hook list

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibpf -c bpf/sentinel.bpf.c -o /tmp/sentinel.o
llvm-objdump -h /tmp/sentinel.o || llvm-objdump-18 -h /tmp/sentinel.o
```

Confirm sections exist for: `tp_btf/sched_process_exec`, `tracepoint/sched/sched_process_fork`, `tracepoint/sched/sched_process_exit`, and `tracepoint/syscalls/sys_enter_{openat,connect,dup3,dup2,ptrace,setuid,mount}`. List any that are missing. Check the Go loader attaches the same set, and that `sys_enter_dup2` is optional.

### Task 4: Reconcile docs, config and code

Fix the **docs** to match the code (only change code if the code is wrong):

1. Update the API route table in `PROPOSED_SOLUTION.md` Section 7 and `README.md` to the real routes in Section 1 above, including the `/health` and `/api/v1/*` split and which routes need the token.
2. Update the README configuration example to the real `config.yaml` schema.
3. Resolve ring buffer size: code and config use 16 MB; docs say 1 MiB. Pick one default (state your reasoning; 16 MB is fine if justified by event rate) and make `config.yaml`, README and `PROPOSED_SOLUTION.md` agree. Confirm the value is validated as a power of two and that the BPF map size is actually set from config at load time.
4. Fix status wording: Go 1.21+ is **required** (uses `binary.NativeEndian`), not "recommended".

### Task 5: Review rule details flagged in the config

Read the rule code and report (fix only if clearly wrong, with tests):

1. `file_tampering.sensitive_paths` includes `/etc/pam.d`, which is a directory. Does matching use prefix/directory logic, so `/etc/pam.d/sshd` is caught? Add a test.
2. `allowlisted_binaries` holds full paths, but kernel events carry `comm` (max 16 chars). How is the comparison done? It must work against what the event actually contains, or against the process table's exe path. Add a test with a real-looking event.
3. Confirm privilege checks use `euid` as decided, and that path normalization (`filepath.Clean`) is applied before comparing.
4. Confirm `treat_loopback_as_external` is honoured by the reverse-shell rule and tested both ways.

### Task 6: Dashboard against the mock daemon

1. Confirm the frontend's WebSocket and fetch URLs match the real routes (`/ws`, `/api/v1/*`). Check `NEXT_PUBLIC_WS_URL` handling. Fix the frontend if it uses wrong paths.
2. Add a clearly visible **SIMULATION** badge in the UI when the daemon is in mock mode. Expose a `mock: true` field in `/api/v1/status` and in the WebSocket `hello` message (ask first if this changes the protocol; adding an optional field is acceptable if documented).
3. Verify end to end without a browser where possible:
   - start `./bin/sentinel-daemon --config config.yaml --mock` in WSL
   - `curl -s localhost:8080/health`, `/api/v1/status`, `/api/v1/alerts`, `/api/v1/processes` and paste the JSON
   - connect a WebSocket client (a small Go or Node script is fine) and show the `hello`, `snapshot`, `event` and `alert` messages arriving
4. If you can run the dev server, note that the user must open `http://localhost:3000` and visually confirm; do not claim the UI works until they confirm.

### Task 7: Tests for the paths mock mode does not cover

Mock mode only exercises the reverse-shell and file-tampering rules. Ensure unit tests exist and pass for: `/tmp` execution, privilege escalation (`setuid`, `ptrace`), container mount breakout, alert cooldown de-duplication, and process-table reparenting.

### Task 8: Prepare (do not perform) the first real kernel load

Write `docs/FIRST_REAL_LOAD.md` (or a section in `PROJECT_STATUS_REPORT.md`) containing exact commands for the **user** to run in WSL, with expected output and what to do on failure:

```bash
sudo ./bin/sentinel-daemon --config config.yaml
sudo bpftool prog show | grep -i -E 'sentinel|sched_process|sys_enter'
sudo bpftool map show
```

Include how to capture the verifier log on rejection, and a short troubleshooting table (memlock, BTF, missing tracepoint, verifier errors). Stop after writing it.

### Task 9: Sync and housekeeping

- Confirm `.gitignore` covers `bpf/vmlinux.h`, `bin/`, `web-ui/node_modules/`, `web-ui/.next/`.
- Offer the user the command to copy changes back to the Windows copy, but do not run it automatically:
  ```bash
  rsync -a --exclude node_modules --exclude .next --exclude bin --exclude 'bpf/vmlinux.h' \
    ~/SentinelBPF/ /mnt/c/Users/aayus/OneDrive/Desktop/OS_Project/
  ```
  (no `--delete`).
- Remove absolute `file:///c:/Users/...` links from docs; use relative links.

---

## 5. Definition of done for this session

- [ ] `go vet ./...`, `gofmt -l .` clean
- [ ] `go test -race ./...` passes, including hub
- [ ] `make all` works from a clean tree
- [ ] Hook list from the compiled object reported
- [ ] Docs, config and code agree on routes, config keys, ring buffer size, Go version
- [ ] Rule review items answered, with tests for fixes
- [ ] Mock daemon verified through `curl` and a WebSocket client; SIMULATION indicator added
- [ ] `FIRST_REAL_LOAD.md` written for the user
- [ ] `PROJECT_STATUS_REPORT.md` updated: errors with exact text, a verification table with only things actually run, resolved issues (ISS-003, ISS-004, ISS-005) marked resolved **only** after re-running their checks

## 6. Reporting format

At the end, give the user:

1. A table: task, status (`DONE` / `DONE-UNVERIFIED` / `BLOCKED`), evidence (the command and result).
2. Every error encountered, with exact text.
3. Anything you could not verify and why.
4. The exact commands the user should run next (first real load), and what they should paste back if it fails.

## 7. Stop and ask the user if

- A fix would change the event struct, protocol shape or config key names.
- A test failure is not understood after two attempts.
- Anything requires `sudo`, a real kernel load, or non-loopback network access.
