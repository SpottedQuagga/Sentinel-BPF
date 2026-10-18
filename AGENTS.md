# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Cursor, Copilot, etc.) working on **SentinelBPF**. Read this file first, then `README.md` (what the project is) and `PROPOSED_SOLUTION.md` (how it is designed).

## Project summary

SentinelBPF is a Linux host intrusion detection tool built on eBPF.

- **Kernel side** (`bpf/`): C eBPF programs (CO-RE, libbpf) that capture events and push fixed-size records to a ring buffer.
- **Daemon** (`cmd/`, `internal/`): Go with `cilium/ebpf`. Reads the ring buffer, tracks processes, evaluates rules, serves WebSocket/HTTP.
- **Dashboard** (`web-ui/`): Next.js + React, D3.js (process tree), ECharts (metrics).

Detection only. The tool observes and alerts; it never blocks or kills anything.

## Commands

| Task | Command |
| :--- | :--- |
| Generate `vmlinux.h` | `make vmlinux` |
| Build eBPF + bindings | `make build-ebpf` |
| Build daemon | `make build-daemon` |
| Build dashboard | `make build-ui` |
| Go unit tests | `go test ./cmd/... ./internal/...` |
| Go static checks | `go vet ./cmd/... ./internal/...` and `gofmt -l .` |
| Frontend lint/tests | `cd web-ui && npm run lint && npm test` |
| Run daemon (needs root, VM only) | `sudo ./bin/sentinel-daemon --config config.yaml` |

Prefer `go test`, `go vet`, builds and linters for verification. They need no privileges.

## Repository layout

```
bpf/                 sentinel.bpf.c, sentinel.h (shared event struct), vmlinux.h (generated, git-ignored)
cmd/sentinel-daemon/ main.go: flags, wiring, signal handling
internal/bpf/        bpf2go bindings + loader/attach code
internal/events/     Event type, decoding
internal/proctable/  pid -> process info, lineage
internal/container/  cgroup id -> container id
internal/rules/      Rule interface + implementations + dedupe
internal/hub/        WebSocket fan-out, batching, backpressure
internal/api/        HTTP + WebSocket handlers
internal/config/     YAML config + validation
web-ui/              Next.js app
scripts/             Demo and test scripts
```

If the actual layout differs from this list, trust the repository and update this file.

## Safety rules (read before running anything)

1. **Do not load eBPF programs or run `sudo` commands unless the user has said they are in a disposable Linux VM and has asked you to.** Loading eBPF needs root and touches the running kernel.
2. **Never run the demo or attack-simulation scripts** (`scripts/demo_*`, reverse shell, mount, ptrace, setuid tests) on the user's host without explicit confirmation. Describe what they do and ask first.
3. Never run commands that modify `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, or mount filesystems.
4. Reverse-shell tests must stay on loopback (`127.0.0.1`). Never connect to external addresses.
5. Do not exfiltrate, print or commit secrets (`auth_token`, keys, `.env` files).
6. No destructive git operations (force push, history rewrite, deleting branches) without being asked.

## Boundaries

**Always**
- Run `gofmt`, `go vet ./cmd/... ./internal/...` and `go test ./cmd/... ./internal/...` before declaring Go work done.
- Add or update unit tests when changing rule logic.
- Keep `README.md`, `PROPOSED_SOLUTION.md` and `config.yaml` consistent with code changes.
- State what you could not verify (for example, "not run against a real kernel").

**Ask first**
- Adding a new third-party dependency.
- Changing the shared event struct, the WebSocket protocol, or the config schema (these affect multiple components).
- Adding or removing a kernel hook.
- Anything that needs root or network access.

**Never**
- Invent benchmark numbers, performance claims, or test results. The README performance table stays `TBD` until measured.
- Edit generated files by hand (`vmlinux.h`, `internal/bpf/sentinel_bpf*.go`). Regenerate them.
- Commit `vmlinux.h`, binaries, `node_modules/`, or `.next/`.
- Weaken a security default (localhost bind, auth token, origin check) to make something work.
- Claim detection of something the hooks cannot observe.

## Kernel-side (eBPF C) rules

- Every program must pass the verifier. Keep programs small; no unbounded loops; bound all string and buffer reads.
- Always check the result of `bpf_ringbuf_reserve` and increment the `drops` counter on failure.
- Ring buffer memory is not zeroed. `memset` the event before filling it (the existing `reserve()` helper does this; use it).
- License string must stay `"GPL"` (required for many helpers).
- Do kernel-side filtering only when it is cheap and obviously correct (for example, write-flag check on `openat`, fd 0 to 2 on `dup`). Put anything stateful or policy-driven in user space.
- Read user memory with `bpf_probe_read_user*` and kernel memory with `bpf_probe_read_kernel*`. Do not mix them up.
- Use CO-RE accessors (`BPF_CORE_READ`) for `task_struct`, `cred`, `nsproxy` fields. Never hard-code struct offsets.
- Syscall entry hooks see arguments **before** the permission check and **before** the result is known. An event means "attempted". User-space pointers can be modified by other threads after being read (TOCTOU). Do not describe these hooks as preventing or confirming anything.
- Exec detection uses `sched_process_exec` (`tp_btf`), not `sys_enter_execve`.
- `sys_enter_dup2` does not exist on arm64. Attaching it must be optional.

### Shared struct contract

`struct event` in `bpf/sentinel.h` is the contract between kernel and user space. Current size is **480 bytes**, 8-byte aligned, no implicit padding.

If you change it:
1. Edit `bpf/sentinel.h`.
2. Run `make build-ebpf` to regenerate Go bindings.
3. Update `events.FromRaw` and any code reading changed fields.
4. Update the event-field table in `PROPOSED_SOLUTION.md`.
5. Keep field order so that `u64`s come first and there is no padding.

## Daemon (Go) rules

- Go 1.21+ (uses `binary.NativeEndian`). Format with `gofmt`. Return errors with context (`fmt.Errorf("attach tracepoint %s: %w", name, err)`); do not panic outside `main`.
- **The ring buffer reader loop must never block or do slow work.** No JSON encoding, disk I/O, network I/O or long-held locks in it. Decode, push to a buffered channel, continue.
- Count and expose both kernel drops (`drops` map) and user-space queue drops.
- Do not read `/proc` in the hot path. Use it only for bootstrap and for cache misses, rate-limited.
- Convert `[N]int8` C strings to Go strings up to the first NUL using the shared helper.
- Bound every in-memory structure (process table, alert history, per-client queues).
- Handle `SIGINT`/`SIGTERM`: close links and the ring buffer reader, then exit cleanly.
- Insert the daemon's own PID into `ignored_pids` at startup so it does not trace itself.
- Use contexts and `errgroup`/WaitGroups for goroutine lifecycle. No leaked goroutines.

### Rules (detection logic)

- Rules implement `Rule.Handle(ev, state) []Alert` and must be deterministic and side-effect free beyond their own per-pid state.
- Use **effective UID** (`euid`) for "non-root" checks so setuid tools such as `passwd` are not flagged.
- Normalise paths with `filepath.Clean` before comparing.
- De-duplicate alerts by `(rule, pid, key)` with a cooldown.
- Reverse shell logic follows the state machine in `PROPOSED_SOLUTION.md` section 6.6 (connect -> dup to fd 0/1/2 -> shell). Do not simplify it to "connect + exec", which causes false positives.
- Every rule needs table-driven tests covering: a positive case, a benign look-alike, an allowlisted case, and a de-duplication case.
- Loopback counts as external only when `treat_loopback_as_external` is true.

### Hub / API

- Never let a slow WebSocket client stall the reader. Per-client buffered channel; drop non-alert messages first; disconnect persistently slow clients.
- Alerts are never dropped before events.
- Default bind is `127.0.0.1`. Check the `Origin` header. Enforce `auth_token` when set.
- Changes to message shapes must update the protocol table in `PROPOSED_SOLUTION.md` section 7 and the frontend types in the same change.

## Frontend rules

- WebSocket client with exponential-backoff reconnect and a visible connection indicator.
- Keep bounded history (for example, last 5,000 events). Never append without a limit.
- Buffer incoming messages and flush to React state at roughly 5 to 10 Hz. Do not set state per message.
- Virtualize long lists.
- Do not use `localStorage` or `sessionStorage` for event or alert data.
- Process tree uses a virtual root (pid 0) so the hierarchy has a single root.
- WebSocket URL comes from `NEXT_PUBLIC_WS_URL`.
- Use TypeScript types that mirror the protocol; avoid `any` for message payloads.

## Testing expectations

| Change | Minimum verification |
| :--- | :--- |
| Rule logic | Unit tests with synthetic events; `go test ./cmd/... ./internal/...` |
| Event struct / decoding | Test that decodes a known 480-byte buffer; size assertion |
| eBPF C | Compiles via `make build-ebpf`; if a VM is available and the user allows it, load and check `bpftool prog show`; otherwise say it was not loaded |
| Hub / API | Test with an in-process WebSocket client, including a stalled client |
| Frontend | Lint, type-check, component tests where present |
| Config | Validation tests for bad values (non-power-of-two ring size, bad CIDR, relative paths) |

Negative tests matter: normal workloads (`apt update`, `ssh`, `sudo passwd`, builds) must not raise alerts. When a legitimate tool triggers a rule, fix it with an allowlist or a better condition, not by disabling the rule.

## Documentation rules

- Keep tone factual. No marketing phrases ("next-generation", "near-zero overhead") without measurements.
- Benchmarks: report only measured values with kernel version, hardware, commands and run count. Otherwise leave `TBD`.
- Document limitations honestly (detection only, argument race, event loss, root compromise).
- If you change behaviour, config keys, endpoints, or hooks, update the docs in the same change.

## Git and PR conventions

- Small, focused commits. Conventional style: `feat(rules): ...`, `fix(bpf): ...`, `docs: ...`, `test: ...`, `chore: ...`.
- Do not mix generated-file churn with logic changes unless unavoidable.
- PR description: what changed, why, how it was verified, and what was not verified.

## Definition of done

A task is done when:

1. Code builds (`make build-daemon`, and `make build-ui` if the frontend changed).
2. `gofmt`, `go vet ./cmd/... ./internal/...`, `go test ./cmd/... ./internal/...` pass (and frontend lint/tests if touched).
3. New or changed behaviour has tests.
4. Docs and `config.yaml` match the code.
5. The summary to the user lists what was verified and anything that could not be (kernel load, real container test, performance).

## When uncertain

- If a requirement conflicts with this file or the design docs, ask the user rather than guessing.
- If the verifier or compiler rejects something, read the full error, simplify the program, and explain the fix. Do not paper over it with larger buffers or disabled checks.
- If you cannot test something because it needs root or a VM, say so plainly and give the exact commands the user can run.
