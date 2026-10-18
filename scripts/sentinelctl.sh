#!/usr/bin/env bash
# sentinelctl: start, stop and inspect SentinelBPF from one place.
#
# Install as scripts/sentinelctl.sh in the repo (chmod +x). Run inside WSL2/Linux.
#
# Safe subcommands need no root: help, doctor, build, check, up, down, status,
# health, alerts, procs, ws, logs, mock.
# 'real' loads eBPF programs with sudo. It needs an interactive terminal and an
# explicit confirmation. Automated agents must never run it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT/.run"
BIN="$ROOT/bin/sentinel-daemon"
CONFIG="${SENTINEL_CONFIG:-$ROOT/config.yaml}"
BASE_URL="${SENTINEL_URL:-http://127.0.0.1:8080}"
TOKEN="${SENTINEL_TOKEN:-}"            # optional; never printed
export NEXT_PUBLIC_WS_URL="${NEXT_PUBLIC_WS_URL:-ws://127.0.0.1:8080/ws}"

die() { echo "error: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
SentinelBPF control script

Usage: scripts/sentinelctl.sh <command>

Setup and checks
  doctor     Check tools, kernel BTF, cgroup v2 and the built binary (no root)
  build      make all: eBPF object, Go bindings, daemon
  check      go vet, gofmt (must be clean), go test -race
  ui-install npm install in web-ui (needed once)

Simulation (no root, safe anywhere)
  up         Start the mock daemon and the dashboard in the background
  down       Stop everything that 'up' started
  mock       Run the mock daemon in the foreground (Ctrl+C to stop)
  logs [daemon|ui]   Follow a log file (default: daemon)

Inspect a running daemon
  status     /api/v1/status
  health     /health
  alerts     /api/v1/alerts
  procs      /api/v1/processes
  ws         Print WebSocket message types (needs scripts/wsprobe)

Real kernel monitoring (root, disposable VM or WSL2 only)
  real       Load eBPF programs. Interactive only. See docs/FIRST_REAL_LOAD.md

Environment overrides
  SENTINEL_CONFIG   config file          (default: ./config.yaml)
  SENTINEL_URL      daemon base URL      (default: http://127.0.0.1:8080)
  SENTINEL_TOKEN    bearer token, if auth_token is set in the config
  NEXT_PUBLIC_WS_URL  dashboard WebSocket URL (default: ws://127.0.0.1:8080/ws)
EOF
}

need_bin() {
  [[ -x "$BIN" ]] || die "daemon binary not found at $BIN. Run: scripts/sentinelctl.sh build"
}

is_running() {
  local f="$RUN_DIR/$1.pid"
  [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null
}

start_bg() {
  local name="$1"; shift
  mkdir -p "$RUN_DIR"
  if is_running "$name"; then
    echo "$name already running (pid $(cat "$RUN_DIR/$name.pid"))"
    return 0
  fi
  setsid nohup "$@" >"$RUN_DIR/$name.log" 2>&1 &
  echo $! >"$RUN_DIR/$name.pid"
  echo "started $name (pid $!), log: $RUN_DIR/$name.log"
}

stop_bg() {
  local name="$1" f="$RUN_DIR/$1.pid"
  if is_running "$name"; then
    local pid
    pid="$(cat "$f")"
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    echo "stopped $name"
  else
    echo "$name not running"
  fi
  rm -f "$f"
}

wait_health() {
  local i
  for i in $(seq 1 20); do
    curl -fsS "$BASE_URL/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

api() {
  local path="$1" out
  local args=(-fsS)
  [[ -n "$TOKEN" ]] && args+=(-H "Authorization: Bearer $TOKEN")
  if ! out="$(curl "${args[@]}" "$BASE_URL$path")"; then
    die "request to $BASE_URL$path failed. Is the daemon running? (scripts/sentinelctl.sh up)"
  fi
  if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$out" | jq .
  else
    printf '%s\n' "$out"
  fi
}

cmd_doctor() {
  local bad=0
  chk() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
      printf '  ok       %s\n' "$label"
    else
      printf '  MISSING  %s\n' "$label"
      bad=1
    fi
  }
  echo "Tools"
  chk "go"      command -v go
  chk "clang"   command -v clang
  chk "bpftool" command -v bpftool
  chk "make"    command -v make
  chk "node"    command -v node
  chk "npm"     command -v npm
  chk "curl"    command -v curl
  echo "Kernel (needed for real mode only)"
  chk "kernel BTF: /sys/kernel/btf/vmlinux" test -r /sys/kernel/btf/vmlinux
  chk "cgroup v2 (container tagging)" bash -c '[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ]'
  echo "Project"
  chk "daemon binary: bin/sentinel-daemon" test -x "$BIN"
  chk "config: $CONFIG" test -r "$CONFIG"
  chk "dashboard deps: web-ui/node_modules" test -d "$ROOT/web-ui/node_modules"
  echo
  if command -v go >/dev/null 2>&1; then go version; fi
  uname -r
  if ((bad)); then
    echo "Some items are missing. Simulation needs only go, make, curl, node, npm and a built binary."
    return 1
  fi
  echo "All checks passed."
}

cmd_build() { cd "$ROOT" && make all; }

cmd_check() {
  cd "$ROOT"
  go vet ./...
  local unformatted
  unformatted="$(gofmt -l .)"
  if [[ -n "$unformatted" ]]; then
    echo "gofmt: these files need formatting:" >&2
    echo "$unformatted" >&2
    exit 1
  fi
  echo "gofmt: clean"
  go test -race -count=1 ./...
}

cmd_ui_install() { cd "$ROOT/web-ui" && npm install; }

cmd_mock() {
  need_bin
  exec "$BIN" --config "$CONFIG" --mock
}

cmd_up() {
  need_bin
  start_bg daemon "$BIN" --config "$CONFIG" --mock
  if wait_health; then
    echo "daemon healthy at $BASE_URL"
  else
    echo "daemon did not become healthy in 10s. Last log lines:" >&2
    tail -n 20 "$RUN_DIR/daemon.log" >&2 || true
    exit 1
  fi
  if [[ -d "$ROOT/web-ui/node_modules" ]]; then
    start_bg ui bash -c "cd '$ROOT/web-ui' && exec npm run dev"
    echo
    echo "Open http://localhost:3000 in your browser."
    echo "You should see a SIMULATION indicator and a green connection status."
  else
    echo "dashboard dependencies missing. Run: scripts/sentinelctl.sh ui-install, then 'up' again."
  fi
  echo "Stop with: scripts/sentinelctl.sh down"
}

cmd_down() {
  stop_bg ui
  stop_bg daemon
}

cmd_logs() {
  local which="${1:-daemon}"
  [[ -f "$RUN_DIR/$which.log" ]] || die "no log at $RUN_DIR/$which.log (not started yet?)"
  exec tail -n 50 -f "$RUN_DIR/$which.log"
}

cmd_ws() {
  [[ -d "$ROOT/scripts/wsprobe" ]] || die "scripts/wsprobe not found (added in NEXT_STEPS_FOR_AGENT_V3 Task 5)"
  cd "$ROOT" && go run ./scripts/wsprobe
}

cmd_real() {
  need_bin
  if [[ ! -t 0 || ! -t 1 ]]; then
    die "'real' needs an interactive terminal. Automated agents must not run it."
  fi
  cat <<EOF
This will run, with root:
  sudo $BIN --config $CONFIG

It loads eBPF programs into the running kernel. Use a disposable VM or WSL2.
SentinelBPF only observes and alerts. It never blocks or kills anything.
Read docs/FIRST_REAL_LOAD.md first. If loading fails, copy the whole output.
EOF
  local answer
  read -r -p "Type LOAD to continue: " answer
  [[ "$answer" == "LOAD" ]] || die "aborted"
  exec sudo "$BIN" --config "$CONFIG"
}

main() {
  local cmd="${1:-help}"
  shift || true
  case "$cmd" in
    help|-h|--help) usage ;;
    doctor)     cmd_doctor ;;
    build)      cmd_build ;;
    check)      cmd_check ;;
    ui-install) cmd_ui_install ;;
    up)         cmd_up ;;
    down)       cmd_down ;;
    mock)       cmd_mock ;;
    logs)       cmd_logs "$@" ;;
    status)     api /api/v1/status ;;
    health)     api /health ;;
    alerts)     api /api/v1/alerts ;;
    procs)      api /api/v1/processes ;;
    ws)         cmd_ws ;;
    real)       cmd_real ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
