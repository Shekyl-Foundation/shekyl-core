#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# GAP-7 floor capture: worst-case cold-block connect verification on the
# stated minimum spec (rule 76: Raspberry Pi 4 Model B; reference-device
# discipline per PERFORMANCE_BASELINE.md §8.2 — active cooling, stock clock,
# toolchain and RUSTFLAGS named, capture archived under docs/benchmarks/).
#
# Run ON the Pi. Records stdout AND a thermal/clock sidecar into the capture,
# because a floor device that throttles under sustained verification is a
# FINDING about the floor, not an artifact to smooth (steering ruling,
# 2026-09-04).
#
# Rule 76 §4: values AND INCREMENTS are measured ON this device — the multi-
# point budget sweep runs here in full so the marginal cost per weight-byte
# is the Pi's own, never the dev box's linearity reused.
#
# RandomX mode: the verification path is LIGHT/CACHE MODE BY CONSTRUCTION —
# shekyl-pow-randomx is a cache+VM substrate computing dataset items from the
# ~256 MB cache on the fly; no dataset/fast arm exists in the crate
# (rust/shekyl-pow-randomx/src/lib.rs:46-72). Recorded in the header so the
# mode is part of verify_floor, not an implementation detail.
#
# Phases (run separately; the C++ build is hours on a Pi):
#   ./scripts/bench/gap7_pi4_gate.sh pins   # fixture positive limbs on aarch64 (run FIRST)
#   ./scripts/bench/gap7_pi4_gate.sh rust   # terms sweep + multi-point budget fill + pow
#   ./scripts/bench/gap7_pi4_gate.sh cpp    # shipped-BP+ microbench (needs unit_tests built)
#
# Per FA-6 §8.2, pin the CPU before capture:
#   export RUSTFLAGS='-C target-cpu=cortex-a72'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUST_ROOT="${REPO_ROOT}/rust"
OUT_DIR="${REPO_ROOT}/docs/benchmarks"

PHASE="${1:-}"
if [[ -z "${PHASE}" ]] || [[ ! "${PHASE}" =~ ^(pins|rust|cpp)$ ]]; then
  echo "usage: $0 pins|rust|cpp" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${OUT_DIR}/gap7_block_verify_pi4_${PHASE}_${STAMP}.txt"

read_temp() {
  # sysfs primary: vcgencmd can EXIST while /dev/vcio does not (observed on
  # skl-pi during the pins capture — the command's presence is not its
  # workingness), and sysfs needs no device node or sudo.
  printf 'temp_mC=%s clock_kHz=%s' \
    "$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo NA)" \
    "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo NA)"
}

thermal_sampler() {
  while :; do
    printf '# thermal %s %s\n' "$(date -u +%H:%M:%S)" "$(read_temp)"
    sleep 15
  done
}

{
  echo "# GAP-7 floor capture — worst-case cold-block connect verification"
  echo "# phase=${PHASE}"
  echo "# captured_utc=${STAMP}"
  echo "# host=$(uname -n)  uname=$(uname -a)"
  echo "# device_row: Raspberry Pi 4 Model B, 4 GB, active cooling, USB3 SSD (PERFORMANCE_BASELINE.md §8.2)"
  echo "# git_rev=$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  echo "# rustc=$(rustc -V 2>/dev/null || echo NA)"
  echo "# RUSTFLAGS=${RUSTFLAGS:-<unset>} (pin -C target-cpu=cortex-a72 per FA-6 §8.2)"
  echo "# randomx_mode=light/cache BY CONSTRUCTION — not a configuration that can drift between runs: shekyl-pow-randomx is a cache+VM substrate with no dataset arm (rust/shekyl-pow-randomx/src/lib.rs:46-72)"
  echo "# storage_deviation: run from SD (mmcblk0p2); §8.2 row's USB3 SSD present but unmounted — not mounted deliberately; measured path is CPU-bound and in-memory, so the deviation does not enter verify_floor"
  echo "# ram_as_found: 8 GB (Rev 1.4 board) vs the June row's 4 GB — rule 76 names the MODEL and Model B matches; RandomX is light/cache (~256 MB) and the FCMP terms are CPU-bound, so 8 vs 4 GB cannot bind HERE — a future floor measurement that IS memory-sensitive must not inherit this row's device as 'the floor'"
  echo "# thermal_start: $(read_temp)"
} | tee "${OUT_FILE}"

thermal_sampler >> "${OUT_FILE}" &
SAMPLER_PID=$!
trap 'kill "${SAMPLER_PID}" 2>/dev/null || true' EXIT

case "${PHASE}" in
  pins)
    # Positive limbs ON THE FLOOR first: a fixture that fails to verify on
    # aarch64 would make every later timing a measurement of a reject path.
    (cd "${RUST_ROOT}" && cargo test --release -p shekyl-ffi --test block_connect_pins) 2>&1 | tee -a "${OUT_FILE}"
    ;;
  rust)
    # Terms sweep + FULL multi-point budget fill + pow — the increments are
    # measured here (rule 76 §4), not scaled from anywhere.
    (cd "${RUST_ROOT}" && cargo bench -p shekyl-ffi --bench block_connect_verify) 2>&1 | tee -a "${OUT_FILE}"
    ;;
  cpp)
    BIN="${REPO_ROOT}/build/tests/unit_tests/unit_tests"
    if [[ ! -x "${BIN}" ]]; then
      echo "unit_tests not built. Build first (expect HOURS on a Pi; -j2 to avoid OOM at link):" | tee -a "${OUT_FILE}"
      echo "  cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && cmake --build build -j2 --target unit_tests" | tee -a "${OUT_FILE}"
      exit 3
    fi
    # The timing instrument is DISABLED_ in default ctest runs (correctness
    # coverage lives in bulletproofs_plus.cpp); this gate opts in.
    "${BIN}" --gtest_filter='gap7_bp_bench.*' --gtest_also_run_disabled_tests 2>&1 | tee -a "${OUT_FILE}"
    ;;
esac

{
  echo "# thermal_end: $(read_temp)"
  echo "# done_utc=$(date -u +%Y%m%dT%H%M%SZ)"
} | tee -a "${OUT_FILE}"

echo "[gap7_pi4_gate] capture: ${OUT_FILE}"
