#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8000}"
HOST="0.0.0.0"
export DATA_DIR="${RAILWAY_VOLUME_MOUNT_PATH:-${DATA_DIR:-./data}}"
mkdir -p "$DATA_DIR"

echo "[PX] start host=${HOST} port=${PORT} data=${DATA_DIR}"

exec python -m uvicorn main:app \
  --host "$HOST" \
  --port "$PORT" \
  --proxy-headers \
  --forwarded-allow-ips='*' \
  --timeout-keep-alive 300 \
  --timeout-graceful-shutdown 25 \
  --ws-ping-interval 20 \
  --ws-ping-timeout 60 \
  --ws-max-size 33554432 \
  --limit-concurrency 5000 \
  --backlog 4096 \
  --log-level info \
  --no-access-log \
  --workers 1
