#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(realpath "$0")")"
BIN=./target/release/fuzzer
LOG_DIR=./logs
SYNC_DIR=./sync
ASAN_BIN=./qemu-asan/bin/qemu-system-x86_64
MAX_DISK_GB=15

# ASan runtime options: halt on first real memory error, no leak detection (QEMU has
# intentional exit-time leaks that would flood crash dir with noise).
# UBSan: do NOT halt (QEMU uses void* function-pointer casts extensively for polymorphism;
# UBSan flags every such call as "incorrect function type" which is a pervasive false
# positive.  We keep print_stacktrace=1 so warnings are visible in logs but don't abort.)
export ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0
export UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=1

# Launch ASan campaign as a background loop sharing the same corpus.
# Workers use IDs 8-11 (vanilla uses 0-7) to avoid queue directory conflicts.
# Each worker is a separate process (--worker-id N --jobs 1) so they can be
# individually restarted on failure and cross-sync with vanilla workers.
# ASan is ~2-3× slower than vanilla; 4 workers ≈ 1-2× vanilla throughput.
run_asan_campaign() {
  if [ ! -x "$ASAN_BIN" ]; then
    echo "[asan] ASan QEMU not found at $ASAN_BIN – skipping ASan campaign." >&2
    return
  fi
  mkdir -p "$LOG_DIR" crashes-asan
  while true; do
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [asan] Starting ASan campaign (workers 008-011)..." \
      | tee -a "$LOG_DIR/campaign-asan.log"

    # Launch 4 workers in parallel, each with a unique ID that doesn't overlap vanilla.
    local asan_pids=()
    for i in 0 1 2 3; do
      wid=$((i + 8))
      "$BIN" \
        --qemu-bin "$ASAN_BIN" \
        --machine pc \
        --iterations 50000 \
        --timeout-ms 8000 \
        --max-commands 24 \
        --worker-id "$wid" \
        --jobs 1 \
        --seed-dir ./corpus \
        --sync-dir ./sync \
        --sync-interval 200 \
        --crashes-dir ./crashes-asan \
        2>&1 | tee -a "$LOG_DIR/campaign-asan.log" &
      asan_pids+=($!)
    done

    # Wait for all 4 workers to finish (or fail).
    for pid in "${asan_pids[@]}"; do
      wait "$pid" 2>/dev/null || true
    done

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
    find "$SYNC_DIR/queue" -type f ! -name ".*" -delete 2>/dev/null || true
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
