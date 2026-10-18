#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

./bin/sentinel-daemon --config config.yaml --mock > /tmp/daemon.log 2>&1 &
DPID=$!

sleep 1

echo "=== 1. /health ==="
curl -s http://127.0.0.1:8080/health
echo ""

echo "=== 2. /api/v1/status ==="
curl -s http://127.0.0.1:8080/api/v1/status
echo ""

echo "=== 3. /api/v1/alerts ==="
curl -s http://127.0.0.1:8080/api/v1/alerts
echo ""

echo "=== 4. /api/v1/processes ==="
curl -s http://127.0.0.1:8080/api/v1/processes
echo ""

echo "=== 5. wsprobe ==="
(cd scripts/wsprobe && go run . -duration 10s)

echo "=== Stopping daemon ==="
kill -TERM "$DPID"
wait "$DPID" 2>/dev/null || true
echo "Daemon exit status: $?"
echo "=== Daemon Log Output ==="
cat /tmp/daemon.log
