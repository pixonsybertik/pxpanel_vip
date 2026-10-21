#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8000}"
HOST="0.0.0.0"

# DATA_DIR: Railway volume or local
export DATA_DIR="${RAILWAY_VOLUME_MOUNT_PATH:-${DATA_DIR:-./data}}"
mkdir -p "$DATA_DIR"

echo "[PXPanel] Railway start · host=${HOST} port=${PORT} data=${DATA_DIR}"
echo "[PXPanel] RAILWAY_PUBLIC_DOMAIN=${RAILWAY_PUBLIC_DOMAIN:-unset}"

# Uvicorn tuned for Railway edge proxy + long-lived WebSocket:
# - proxy-headers / forwarded-allow-ips: trust X-Forwarded-* from Railway edge
# - timeout-keep-alive > edge idle expectations
# - ws-ping-interval/timeout: application-level WS keepalive (helps NAT + edge)
# - workers=1: required for in-memory connection state + WS
exec python -m uvicorn main:app \
  --host "$HOST" \
  --port "$PORT" \
  --proxy-headers \
  --forwarded-allow-ips='*' \
  --timeout-keep-alive 75 \
  --timeout-graceful-shutdown 15 \
  --ws-ping-interval 20 \
  --ws-ping-timeout 30 \
  --ws-max-size 16777216 \
  --limit-concurrency 2000 \
  --backlog 2048 \
  --log-level info \
  --no-access-log \
  --workers 1
