# QEMU Virtual Device Fuzzer (LibAFL, Rust)

This project fuzzes a stable QEMU system binary through its QMP control surface using LibAFL.

## Target

- Tested target binary: `/usr/bin/qemu-system-x86_64`
- Tested version: `QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.12)`

## What It Does

- Launches QEMU in headless mode with `-qmp stdio`.
- Converts each mutated byte input into a bounded sequence of QMP/HMP/device commands.
- Always appends a final `{"execute":"quit"}` so each test case terminates cleanly.
- Runs single-worker or parallel multi-worker campaigns (`--jobs N`).
- Uses persistent per-worker on-disk queues/objectives.
- Periodically syncs queue inputs from disk across workers.
- Tracks crashes/timeouts as objective findings on disk.

## Build

```bash
cargo build -p fuzzer
```

## Run

```bash
cargo run -p fuzzer -- \
  --qemu-bin /usr/bin/qemu-system-x86_64 \
  --machine q35 \
  --iterations 400 \
  --timeout-ms 1000 \
  --max-commands 24 \
  --jobs 1 \
  --seed-dir ./corpus \
  --sync-dir ./sync \
  --sync-interval 50 \
  --crashes-dir ./crashes
```

## Parallel Campaign

```bash
cargo run -p fuzzer -- \
  --qemu-bin /usr/bin/qemu-system-x86_64 \
  --machine q35 \
  --iterations 5000 \
  --timeout-ms 1000 \
  --max-commands 24 \
  --jobs 4 \
  --seed-dir ./corpus \
  --sync-dir ./sync \
  --sync-interval 100 \
  --crashes-dir ./crashes
```

## Help

```bash
cargo run -p fuzzer -- --help
```

## Notes

- If `--seed-dir` is empty, default seed inputs are created automatically.
- Queue files are persisted under `--sync-dir/queue/worker-XXX`.
- Objective files are persisted under `--crashes-dir/worker-XXX` (or directly in `--crashes-dir` for single-worker mode).
