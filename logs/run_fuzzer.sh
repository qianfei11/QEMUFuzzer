#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=./target/release/fuzzer
LOG_DIR=./logs

while true; do
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting fuzzer campaign..." | tee -a "$LOG_DIR/campaign.log"
  "$BIN" \
    --qemu-bin /usr/bin/qemu-system-x86_64 \
    --machine q35 \
    --iterations 200000 \
    --timeout-ms 800 \
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
