# REPORT_INSTRUCTIONS.md

Instructions for the coding agent (Antigravity). Your job in this session is to **write one report**: `docs/CLAUDE_CONTEXT_REPORT.md`.

## 0. Why this report exists

The user will give your report to a **brand-new Claude chat** that has no memory of this project and **no access to the repository**. That reader will use it to keep helping the user (reviewing your work, writing your next prompts, preparing the OS-course presentation). So the report must be:

- **Self-contained:** the reader understands the project, its current state, its problems and how to run it without opening any other file.
- **Evidence-based:** every claim says how it is known. The reader will treat what you write as ground truth, so a wrong claim does damage.
- **Honest about gaps:** `UNKNOWN` and `NOT RUN` are good answers. Over-claiming is the worst failure.

Earlier agent reports in this project over-claimed ("no open issues", "~95%", checks marked passed without output, retyped output with typos). Do not repeat that.

---

## 1. Rules

**You may create or modify only `docs/CLAUDE_CONTEXT_REPORT.md`** (and scratch files under `/tmp`). Do not change code, config, docs, git state or dependencies. Do not run `git init`, `git add` or `git commit`. This is a read-and-report session.

Safety (from `AGENTS.md`, still in force):
1. No `sudo`. Do not load eBPF programs.
2. Do not run `scripts/demo_*` or any attack simulation.
3. Loopback (`127.0.0.1`) only. No `npm install`.
4. Never print or write secrets. For `auth_token`, record only `empty` or `set (value redacted)`.

Evidence rules:
1. **Tag every factual statement** with one of:
   - `[VERIFIED]` you ran a command this session and saw the result. Give the command and put the raw output in Appendix A.
   - `[CODE]` you read it in a file. Give `file:line`.
   - `[DOC]` a document says it, and you did not check it. Give the document name.
   - `[UNKNOWN]` you could not determine it.
2. Paste raw output by **copying it**, never retyping it. Do not "clean up" paths or numbers. If output is long, truncate and write `[truncated: N lines omitted]`.
3. No invented numbers, percentages or benchmarks. If you give a completion estimate, show how you got it.
4. If a command fails or times out, paste the exact error and record `NOT RUN` with the reason.
5. Use relative paths and relative links only (no `file:///` links).

Working style (the model provider times out on long requests):
- **Write the report in phases (Section 3). Save the file after every phase, then stop and say one line.** Do not try to do it all in one turn.
- Add sections to the file one at a time. Do not rewrite the whole file to add a section.
- Use `timeout 300` for slow commands. Paste only what is needed.
- If you hit a timeout or 5xx error: re-read `docs/CLAUDE_CONTEXT_REPORT.md`, state which sections are already done, and continue from the next unfinished one. Do not start over.
- Always use the Linux Node: `which node npm` must print `/usr/bin/...` before any frontend command. If it prints `/mnt/c/...`, stop and say so.

---

## 2. Read these first (in this order)

`AGENTS.md`, `PROJECT_OVERVIEW.md`, `PROPOSED_SOLUTION.md`, `README.md`, `config.yaml`, `PROJECT_STATUS_REPORT_V2.md`, `AGENT_SECOND.md`, `NEXT_STEPS_FOR_AGENT_V3.md`, `PROJECT_AUDIT_REPORT.md`, `SESSION_REPORT_V3.md`, `RUNBOOK.md` (if present). List which of these exist and which are missing in Section 10 of the report. Where documents disagree with the code, **the code wins**; record the disagreement.

---

## 3. Phases

Complete one phase per turn. Update the report file, reply with a single line ("Phase N done, sections X to Y written"), and stop.

### Phase A: Sections 1 to 4 (facts from the repo)
### Phase B: Section 5 (verification, runs commands)
### Phase C: Sections 6 to 7 (status and known issues, runs commands)
### Phase D: Sections 8 to 13 and the final self-check (Section 6 of this file)

---

## 4. Report structure and how to gather each section

Use exactly this section order and these titles in `docs/CLAUDE_CONTEXT_REPORT.md`. Start the file with a table of contents.

### Section 1. Metadata
Gather:
```bash
date -u; pwd; uname -r; go version; clang --version | head -1; bpftool version 2>&1 | head -1
which node npm; node -v
git rev-parse --is-inside-work-tree 2>&1; git log --oneline -n 5 2>&1; git status --short 2>&1 | head -20
```
Write: date, repo path, tool versions, whether the repo is under git (and if not, say so plainly), and which copy is the source of truth (`~/SentinelBPF` in WSL2; the OneDrive copy is stale).

### Section 2. Project summary
One short section, from the docs, tagged `[DOC]`: what SentinelBPF is, what it detects, **detection only (never blocks)**, the three layers (kernel C eBPF, Go daemon, Next.js dashboard), mock mode, and that syscall-entry hooks mean an event is an **attempt** (TOCTOU). Add one paragraph on the context: this is a third-year (TY) engineering **Operating Systems course project**, and list the OS concepts the project covers (processes, system calls, kernel vs user space, the eBPF verifier, ring buffer, credentials, file descriptors and sockets, namespaces and cgroups, concurrency and backpressure).

### Section 3. Architecture and code map
Gather (exclude `node_modules`, `.next`, `bin`, `.run`):
```bash
find . -path ./web-ui/node_modules -prune -o -path ./web-ui/.next -prune -o -path ./bin -prune -o -path ./.git -prune -o -type f -print | sort | head -200
wc -l bpf/*.c bpf/sentinel.h internal/*/*.go cmd/*/*.go | tail -60
```
Write, each with `file:line` tags:
1. **Repo layout** (directory to purpose), noting where reality differs from `AGENTS.md`.
2. **Data flow** (kernel hook, ring buffer, reader, decode, process table, rules, hub, API, dashboard) in a short numbered list.
3. **`struct event`:** every field, type and size from `bpf/sentinel.h`, total size, and the test that asserts 480 bytes.
4. **Hooks table:** every program name, section type (from `llvm-objdump -h internal/bpf/sentinel_bpfel_x86.o`), and how the Go loader attaches it (`file:line`), and which attach failures are fatal vs optional.
5. **BPF maps:** the exact map names from the C source (needed for `bpftool map show` greps).
6. **Rules table:** rule name, file, trigger summary, MITRE tag, config keys, allowlist logic, cooldown key (`file:line`).
7. **Config schema:** every key in `config.yaml` with its default (redact `auth_token`).
8. **HTTP routes** with auth requirement (`internal/api/server.go`).
9. **WebSocket protocol:** every message type the daemon sends (`file:line`), every type the frontend handles (`file:line`), and whether each is in `PROPOSED_SOLUTION.md` Section 7. Include the optional `mock` field.
10. **Frontend:** the components, the tabs, how the WebSocket URL is built, buffering and caps (events, alerts), where the SIMULATION badge is rendered.
11. **Bounds:** every bounded structure and its limit (process table, alert history, per-client queues, frontend lists, ring buffer).
12. **OS concepts to code map:** a table `concept | where it appears (file:line) | one-sentence explanation`. Cover at least: fork/exec/exit, syscall tracepoints, verifier-checked kernel programs, ring buffer, uid vs euid, fd duplication (`dup`), sockets (`connect`), mount namespace or cgroup id, backpressure.

### Section 4. How to build and run (as it works today)
Write the exact commands, tested in Section 5, for: first-time setup, build (`make all`), tests, running the daemon in mock mode, running the dashboard, stopping everything, and (not executed) the real-mode command. Include ports, the Windows-npm-in-WSL pitfall and its fix, and how to check for zombie daemons (`pkill -f sentinel-daemon`, `ss -ltn | grep 8080`). Tag each command as verified or not.

### Section 5. Verification matrix (Phase B)
Run each command below and record the raw output in Appendix A. Do not delete any files. The matrix columns are: `ID | check | command | result (PASS / FAIL / NOT RUN) | evidence ref`.

```bash
make build-daemon                      # non-destructive build check
go vet $(go list ./... | grep -v /node_modules/)
gofmt -l cmd internal scripts          # PASS only if the output is EMPTY (exit status is not proof)
go test -race -count=1 $(go list ./... | grep -v /node_modules/)
go test -list '.*' ./internal/...      # test inventory per package
llvm-objdump -h internal/bpf/sentinel_bpfel_x86.o | grep -E 'tp_btf|tracepoint'
cd web-ui && npm run lint && timeout 300 npm run build; cd ..
go mod verify
```

Mock daemon and API (port 8080 must be free first: `ss -ltn | grep 8080 || echo free`):
```bash
./bin/sentinel-daemon --config config.yaml --mock > /tmp/mock.log 2>&1 &  pid=$!; sleep 3
curl -s localhost:8080/health
curl -s localhost:8080/api/v1/status
curl -s localhost:8080/api/v1/alerts    | head -c 1200
curl -s localhost:8080/api/v1/processes | head -c 1200
curl -s localhost:8080/api/v1/process/1 | head -c 600
timeout 20 go run ./scripts/wsprobe
for i in 1 2 3; do curl -s localhost:8080/api/v1/status | grep -o '"active_processes":[0-9]*'; sleep 10; done
kill -TERM $pid; wait $pid; echo "exit status: $?"; tail -n 15 /tmp/mock.log
ss -ltn | grep 8080 || echo "8080 free again"
```

Non-root kernel readiness checks (read-only; if a command needs root, record that instead of using sudo):
```bash
ls -l /sys/kernel/btf/vmlinux
stat -fc %T /sys/fs/cgroup                 # cgroup2fs expected
ulimit -l
zcat /proc/config.gz 2>&1 | grep -E 'FTRACE_SYSCALLS|DEBUG_INFO_BTF|CONFIG_CGROUPS|BPF_SYSCALL|BPF_JIT' || echo "config.gz not readable or no match"
ls /sys/kernel/tracing/events/syscalls/sys_enter_openat 2>&1 | head -3
```

Mark as `BROWSER-ONLY` (needs the user) anything that requires looking at the dashboard, and `ROOT-ONLY` anything that requires `sudo` or a kernel load. Do not claim the dashboard works in a browser.

### Section 6. Status: done, partial, remaining (Phase C)
A table per component (eBPF C, Go daemon, rules, hub, API/WebSocket, dashboard, build pipeline, mock mode, docs, scripts, tests). Columns: `component | code written? | tests exist (names) | verified how | gap`. Give a **completion estimate only if you show the method** (for example: "written" vs "verified" per row, counted from the table). State plainly that real-kernel behavior has not been verified unless Section 5 shows otherwise.

Also list "not started": first real kernel load, detection on real syscalls, demo scripts on a real kernel, container test, benchmarks (README table must stay `TBD` until measured).

### Section 7. Known issues and suspects (Phase C)
The list below comes from a reviewer who **never ran the code**. These are claims to check, not facts. For each, run the check, then record `OPEN`, `FIXED`, `NOT A BUG` or `UNKNOWN`, with evidence (`file:line` or Appendix A reference). Add any new problems you find.

| ID | Claim to check | How to check |
| :--- | :--- | :--- |
| K1 | The dashboard shows no SIMULATION badge although the daemon sends `"mock":true`. Is the badge in the DOM, hidden, or just faint? | Trace `hello` to `raw.mock` to `isMock` to `Header.tsx` (`file:line`). You cannot run a browser: mark the visual result `BROWSER-ONLY` and give the user this Console snippet to run on the dashboard page: `(()=>{const b=document.getElementById('simulation-badge');return b?[b.outerHTML.slice(0,200),JSON.stringify(b.getBoundingClientRect()),getComputedStyle(b).display,getComputedStyle(b).opacity]:'NOT IN DOM'})()` |
| K2 | The Live Events table shows rows in identical pairs, and identical alerts appear in the same second. Possible duplicate WebSocket connections (React StrictMode, or a socket not closed on effect cleanup). | `grep` `reactStrictMode` in `web-ui/next.config.*`; read `useWebSocket.ts` cleanup; with the mock running, `curl .../api/v1/status` and note `active_clients` while **no** browser tab is open (expect 0); tell the user to re-check with exactly one tab open (expect 1; 2 means a frontend bug); check wsprobe output for repeated messages |
| K3 | Overview "active alerts" and the Alerts-tab count may differ. | Read where each count is computed (`file:line`) |
| K4 | Mock hard-codes `Ppid: 1000` (`bpf.go` around lines 99 to 156), so the process tree is flat and lineage/reparenting are never exercised by mock. | Read the mock generator; list which unit tests cover lineage and reparenting |
| K5 | Process-tree root label is clipped on first render (`ProcessTree.tsx` initial transform near line 162, `translate(80, ...)`). | Report whether it has already been changed. Do not change it |
| K6 | The repo may not be under git, so there is no undo. | `git rev-parse` output from Section 1. Do not run `git init` |
| K7 | The frontend does not append `auth_token` to the WebSocket URL, so the dashboard only connects when `auth_token` is empty. | Read `server.go` auth handling and `useWebSocket.ts` URL building (`file:line`) |
| K8 | The hub sends one `event` message per event (no server-side batching). | Read `hub.go`; state the batching behavior and per-client queue size |
| K9 | `IgnoreSelf` failure is only a warning, so the daemon might trace itself. | Read the loader (`file:line`) |
| K10 | If the WSL2 kernel lacks syscall tracepoints, 7 of 10 hooks cannot attach and, because attach failure is fatal (except `dup2`), the daemon will not start. | Use the non-root checks in Section 5 and the loader code; state what is `UNKNOWN` without root |
| K11 | `bpftool map show \| grep -i sentinel` in docs probably matches nothing, because map names come from the C source. | Compare the doc command with the real map names from Section 3 |
| K12 | `go test ./...` also picks up a Go package inside `web-ui/node_modules`. | Show where it appears in the unfiltered `go test ./...` output (one run, no `-race`) |
| K13 | Docs drift: routes, config keys, ring buffer size (16 MiB vs 1 MiB), "Go 1.21+ required", `tp_btf` for fork/exit (only exec is `tp_btf`), WebSocket message named `events` (real name is `event`), `file:///` links. | `grep -rn` across `README.md`, `PROPOSED_SOLUTION.md`, `PROJECT_OVERVIEW.md`, `AGENTS.md`, `*.md`; list each remaining wrong line as `file:line` |
| K14 | Rule details unreviewed: does `/etc/pam.d` match by directory prefix; how are full-path allowlists compared with a 16-char `comm`; is `euid` used; is `filepath.Clean` applied; is `treat_loopback_as_external` honored and tested both ways; does the `/tmp` execution rule have a config section; does "connect + exec only" avoid alerting? | Read `internal/rules/` and its tests (`file:line` and test names) |
| K15 | Missing tests: `/tmp` execution, `setuid`/`ptrace`, mount breakout, cooldown dedupe for real rule output, process-table reparenting, config validation negatives. | Map each to an existing test name or say `MISSING` |
| K16 | `npm test` may be a placeholder (no real frontend tests). | Read `web-ui/package.json` and the test setup |
| K17 | Process-table eviction may remove a live parent ("exited first, then arbitrary"). | Read `proctable.go` eviction (`file:line`) |

### Section 8. Documents inventory
A table: `file | exists? | last modified | purpose | known inaccuracies`. Use `ls -l --time-style=long-iso`. Say which documents are stale or overclaim (for example `PROJECT_STATUS_REPORT_V2.md`).

### Section 9. Errors encountered and fixes (exact text)
Include every real error you know of or hit in this session, with the exact text. Seed list (verify which are in the repo history or logs, and add what you encounter): `Error: missing package, are you running via go generate?`; `missing go.sum entry`; `BroadcastEvent blocked on full client buffer`; `Upstream idle timeout exceeded` (HTTP 504, retryable, provider side); `UNC paths are not supported` and `Couldn't find any pages or app directory` (Windows npm used from WSL); `sh: 1: next: Permission denied` (Windows-installed `node_modules`). For each: cause, fix, and status.

### Section 10. Safety and working rules for future agents
Summarize `AGENTS.md` (no sudo or eBPF load by the agent, no demo scripts, loopback only, ask first before changing `struct event`, the WebSocket protocol, config keys, dependencies or hooks, no generated-file edits, no invented numbers, never claim "verified" without raw output). Add the process lessons: small steps, paste raw output, use the Linux Node, no retyping output.

### Section 11. Next steps (your proposal)
An ordered list, labelled **proposal**. Distinguish what the **agent** can do from what **only the user** can do (the first real `sudo` load, the browser check, Docker container tests, benchmarks). Do not suggest running anything that needs root.

### Section 12. What the new Claude chat should ask the user for
A short list (for example: the latest report copy, the agent's last output, browser results for K1 and K2, a pasted verifier log if a real load was attempted).

### Section 13. Glossary
Ten or fewer terms a reader needs: eBPF, verifier, CO-RE, `tp_btf`, tracepoint, ring buffer, TOCTOU, euid, cgroup, MITRE ATT&CK tag, mock mode.

### Appendix A. Raw evidence
One block per verification ID, in this form:
```
[V1]
$ <exact command>
<raw output, copied>
exit: <n>
```

---

## 5. Format requirements

- Markdown, tables for matrices, fenced blocks for output. Target length 400 to 700 lines.
- Table of contents at the top; sections numbered as above.
- Write in a factual tone. No marketing words ("robust", "enterprise-grade"). No percentages without a method.
- Tag every factual statement as described in Section 1 of this file.
- Relative paths and links only. No secrets.

---

## 6. Final self-check (Phase D)

Before declaring done, run and paste the results in Appendix A:
```bash
grep -n -i -E 'auth_token *[:=] *[^ ]' docs/CLAUDE_CONTEXT_REPORT.md | grep -v -i 'redacted\|empty' || echo "no token values found"
grep -c 'file:///' docs/CLAUDE_CONTEXT_REPORT.md
grep -n -i -E 'verified|confirmed|passes|PASS' docs/CLAUDE_CONTEXT_REPORT.md | grep -v '\[VERIFIED\]\|Appendix\|PASS /' | head -30
```
Then confirm each of these and list any that are not true:
- [ ] Every section from 1 to 13 exists, in order
- [ ] Every factual line carries a tag; no `[VERIFIED]` without an Appendix A entry
- [ ] Every `NOT RUN`, `BROWSER-ONLY`, `ROOT-ONLY` and `UNKNOWN` is listed in one place (add a short "Unverified items" list at the end of Section 6)
- [ ] K1 to K17 each have a status and evidence
- [ ] No secrets, no absolute `file:///` links
- [ ] Raw output was copied, not retyped

## 7. What to tell the user at the end

Send the user a short message with:
1. The path of the report and how many `[VERIFIED]`, `[CODE]`, `[DOC]` and `[UNKNOWN]` items it contains.
2. K1 to K17 as a one-line-each table (status only).
3. Every error you hit, with exact text.
4. What the **user** must do next: the browser checks for K1 and K2 (give the Console snippet and the one-tab `active_clients` check), the `git init` baseline commit, and (later) the first real kernel load. Do not perform those yourself.

## 8. Stop and ask the user if

- A command would need `sudo`, a kernel load or non-loopback network access
- You are tempted to change code, docs or config to make the report look better
- Documents disagree and you cannot tell which one is right
- Anything you are about to write is a guess: write `[UNKNOWN]` instead
