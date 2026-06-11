#!/usr/bin/env bash
set -euo pipefail

for name in claude-elo-shim claude-elo-adapter; do
  PID_FILE="/tmp/$name.pid"
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    kill "$(cat "$PID_FILE")"
    rm -f "$PID_FILE"
    echo "$name stopped"
  else
    rm -f "$PID_FILE"
    echo "$name not running"
  fi
done
