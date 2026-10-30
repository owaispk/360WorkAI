#!/usr/bin/env bash
# Runs the WorkAI360 API (http://localhost:5080) and web host (http://localhost:5081).
#   scripts/dev.sh start | stop | status | restart
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
RUN_DIR="${WORKAI360_RUN_DIR:-$ROOT/.run}"
mkdir -p "$RUN_DIR"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Development}"
API_URL="${WORKAI360_API_URL:-http://localhost:5080}"
WEB_URL="${WORKAI360_WEB_URL:-http://localhost:5081}"

start_one() { # name project url
  local name=$1 project=$2 url=$3
  if [[ -f "$RUN_DIR/$name.pid" ]] && kill -0 "$(cat "$RUN_DIR/$name.pid")" 2>/dev/null; then echo "$name already running"; return; fi
  cd "$ROOT/src/$project"
  # Run the built app directly (not `dotnet run`, which forks it) so the PID file names the real process.
  Den__ApiBaseUrl="$API_URL" Auth__WebUrl="$WEB_URL" Auth__ApiPublicUrl="$API_URL" setsid nohup "bin/Debug/net10.0/$project" --urls "$url" >"$RUN_DIR/$name.log" 2>&1 &
  echo $! >"$RUN_DIR/$name.pid"
  cd "$ROOT"
}

case "${1:-status}" in
  start)
    dotnet build -c Debug -v quiet --nologo >/dev/null
    for url in "$API_URL" "$WEB_URL"; do
      if curl -fsS -m 1 -o /dev/null "$url" 2>/dev/null && [[ ! -f "$RUN_DIR/api.pid" && ! -f "$RUN_DIR/web.pid" ]]; then echo "$url is already in use by another process" >&2; exit 1; fi
    done
    start_one api WorkAI360.Api "$API_URL"
    start_one web WorkAI360.Web "$WEB_URL"
    for _ in $(seq 1 60); do
      if curl -fsS -m 2 "$API_URL/health" >/dev/null 2>&1 && curl -fsS -m 2 "$WEB_URL/api/health" >/dev/null 2>&1; then echo "up: api=$API_URL web=$WEB_URL"; exit 0; fi
      sleep 1
    done
    echo "did not come up; see $RUN_DIR/*.log" >&2; exit 1 ;;
  stop)
    for name in api web; do
      if [[ -f "$RUN_DIR/$name.pid" ]]; then
        pid=$(cat "$RUN_DIR/$name.pid")
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$RUN_DIR/$name.pid"
      fi
    done
    echo stopped ;;
  restart) "$0" stop; sleep 2; "$0" start ;;
  status)
    curl -fsS -m 2 "$API_URL/health" 2>/dev/null && echo || echo "api down"
    curl -fsS -m 2 "$WEB_URL/api/health" 2>/dev/null && echo || echo "web down" ;;
  *) echo "usage: $0 start|stop|status|restart" >&2; exit 2 ;;
esac
