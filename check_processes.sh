#!/bin/bash
for i in 1 2 3 4 5 6; do
    curl -s localhost:8080/api/v1/status | grep -o '"active_processes":[0-9]*'
    sleep 20
done