#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=./target/release/fuzzer
LOG_DIR=./logs
SYNC_DIR=./sync
MAX_DISK_GB=10

while true; do
  # Disk guard: stop if sync/ exceeds MAX_DISK_GB to prevent disk exhaustion.
  DISK_USED_GB=$(du -s --block-size=1G "$SYNC_DIR" 2>/dev/null | awk '{print $1}')
  if [ "${DISK_USED_GB:-0}" -ge "$MAX_DISK_GB" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Disk guard: sync/ = ${DISK_USED_GB}GB >= ${MAX_DISK_GB}GB – wiping queue." | tee -a "$LOG_DIR/campaign.log"
    find "$SYNC_DIR/queue" -name "*.bin" -delete 2>/dev/null || true
  fi

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting fuzzer campaign..." | tee -a "$LOG_DIR/campaign.log"
  "$BIN" \
    --qemu-bin /usr/bin/qemu-system-x86_64 \
    --machine pc \
    --iterations 200000 \
    --timeout-ms 2000 \
    --max-commands 24 \
    --jobs 8 \
    --seed-dir ./corpus \
    --sync-dir ./sync \
    --sync-interval 200 \
    --crashes-dir ./crashes \
    2>&1 | tee -a "$LOG_DIR/campaign.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Campaign finished, restarting..." | tee -a "$LOG_DIR/campaign.log"
  sleep 2
done
