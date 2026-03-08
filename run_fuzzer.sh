#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(realpath "$0")")"
BIN=./target/release/fuzzer
LOG_DIR=./logs
SYNC_DIR=./sync
ASAN_BIN=./qemu-asan/bin/qemu-system-x86_64
MAX_DISK_GB=15

# ASan runtime options: halt on first error, no leak detection (QEMU has intentional
# exit-time leaks that would flood the crash directory with noise).
export ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0
export UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1

# Launch ASan campaign as a background loop sharing the same corpus.
# Uses 4 workers (ASan is ~2-3× slower than vanilla; 4×ASan ≈ 1-2×vanilla throughput).
# Writes crashes to ./crashes-asan/ so they are separate from vanilla crashes.
run_asan_campaign() {
  if [ ! -x "$ASAN_BIN" ]; then
    echo "[asan] ASan QEMU not found at $ASAN_BIN – skipping ASan campaign." >&2
    return
  fi
  mkdir -p "$LOG_DIR" crashes-asan
  while true; do
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [asan] Starting ASan campaign..." \
      | tee -a "$LOG_DIR/campaign-asan.log"
    "$BIN" \
      --qemu-bin "$ASAN_BIN" \
      --machine pc \
      --iterations 50000 \
      --timeout-ms 8000 \
      --max-commands 24 \
      --jobs 4 \
      --seed-dir ./corpus \
      --sync-dir ./sync \
      --sync-interval 200 \
      --crashes-dir ./crashes-asan \
      2>&1 | tee -a "$LOG_DIR/campaign-asan.log"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [asan] Campaign finished, restarting..." \
      | tee -a "$LOG_DIR/campaign-asan.log"
    sleep 2
  done
}

run_asan_campaign &
ASAN_PID=$!
trap 'kill $ASAN_PID 2>/dev/null; true' EXIT INT TERM

while true; do
  # Disk guard: wipe corpus queue if sync/ exceeds MAX_DISK_GB.
  DISK_USED_GB=$(du -s --block-size=1G "$SYNC_DIR" 2>/dev/null | awk '{print $1}')
  if [ "${DISK_USED_GB:-0}" -ge "$MAX_DISK_GB" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Disk guard: sync/ = ${DISK_USED_GB}GB >= ${MAX_DISK_GB}GB – wiping queue." | tee -a "$LOG_DIR/campaign.log"
    find "$SYNC_DIR/queue" -name "*.bin" -delete 2>/dev/null || true
  fi

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting vanilla campaign..." | tee -a "$LOG_DIR/campaign.log"
  "$BIN" \
    --qemu-bin /usr/bin/qemu-system-x86_64 \
    --machine pc \
    --iterations 200000 \
    --timeout-ms 4000 \
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
