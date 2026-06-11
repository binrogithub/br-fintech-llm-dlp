#!/usr/bin/env bash
# claude-elo 专属 anthropic adapter 实例：复用 ~/litellm-anthropic-adapter/server.js
# （不改共享实例），下游指向 elo-shim(:4020) 以注入 guardrails。
set -euo pipefail

ADAPTER_JS="${ELO_ADAPTER_JS:-$HOME/litellm-anthropic-adapter/server.js}"
PID_FILE="${ELO_ADAPTER_PID_FILE:-/tmp/claude-elo-adapter.pid}"
LOG_FILE="${ELO_ADAPTER_LOG_FILE:-/tmp/claude-elo-adapter.log}"
PORT="${ELO_ADAPTER_PORT:-4021}"
SHIM_PORT="${ELO_SHIM_PORT:-4020}"

if [[ ! -f "$ADAPTER_JS" ]]; then
  echo "elo-adapter: $ADAPTER_JS not found" >&2
  exit 1
fi

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "elo-adapter already running: pid $(cat "$PID_FILE")"
  exit 0
fi

export ADAPTER_PORT="$PORT"
export LITELLM_CHAT_URL="http://127.0.0.1:$SHIM_PORT/v1/chat/completions"

if command -v setsid >/dev/null 2>&1; then
  setsid node "$ADAPTER_JS" > "$LOG_FILE" 2>&1 < /dev/null &
else
  nohup node "$ADAPTER_JS" > "$LOG_FILE" 2>&1 < /dev/null &
fi
echo "$!" > "$PID_FILE"

for _ in {1..30}; do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "elo-adapter started: http://127.0.0.1:$PORT -> shim :$SHIM_PORT"
    exit 0
  fi
  sleep 0.2
done

echo "elo-adapter failed to start; see $LOG_FILE" >&2
exit 1
