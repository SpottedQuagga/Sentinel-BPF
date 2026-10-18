#!/bin/bash
cd ~/SentinelBPF
./bin/sentinel-daemon --config config.yaml --mock > /tmp/mock2.log 2>&1 &
PID=$!
echo "pid=$PID"
sleep 3
kill -TERM $PID
sleep 2
echo "exit status: $?"
cat /tmp/mock2.log