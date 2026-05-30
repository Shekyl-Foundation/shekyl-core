#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# Capture the C++ wallet2 benchmark baseline on the current machine.
# Intended to run on a reference machine with consistent toolchain, quiet
# background workload, and stable CPU frequency scaling.
#
# Output:  docs/benchmarks/wallet2_baseline_v0.json  (overwritten).
#
# This script is run by humans, not CI. The CI workflow (commit 3.3)
# performs a slightly different capture path optimized for per-PR
# comparison; this one is the authoritative rolling-baseline source.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build/bench}"
OUTPUT_PATH="${OUTPUT_PATH:-${REPO_ROOT}/docs/benchmarks/wallet2_baseline_v0.json}"
REPETITIONS="${REPETITIONS:-5}"
MIN_TIME="${MIN_TIME:-1.0}"

echo "[capture_cpp_baseline] repo root : ${REPO_ROOT}"
echo "[capture_cpp_baseline] build dir : ${BUILD_DIR}"
echo "[capture_cpp_baseline] output   : ${OUTPUT_PATH}"
echo "[capture_cpp_baseline] reps     : ${REPETITIONS}, min_time : ${MIN_TIME}s"

# ---- configure -------------------------------------------------------------

if [[ ! -d "${BUILD_DIR}" ]]; then
  mkdir -p "${BUILD_DIR}"
fi

cmake \
  -S "${REPO_ROOT}" \
  -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHEKYL_WALLET_BENCH=ON \
  -DBUILD_TESTS=ON \
  -GNinja 2>/dev/null \
  || cmake \
       -S "${REPO_ROOT}" \
       -B "${BUILD_DIR}" \
       -DCMAKE_BUILD_TYPE=Release \
       -DBUILD_SHEKYL_WALLET_BENCH=ON \
       -DBUILD_TESTS=ON

# ---- build (just the bench target, not the whole tree) --------------------

cmake --build "${BUILD_DIR}" --target shekyl-wallet-bench --parallel

BENCH_BIN="$(find "${BUILD_DIR}" -name shekyl-wallet-bench -type f -executable | head -n 1)"
if [[ -z "${BENCH_BIN}" ]]; then
  echo "[capture_cpp_baseline] ERROR: could not locate built binary" >&2
  exit 1
fi
echo "[capture_cpp_baseline] binary   : ${BENCH_BIN}"

# ---- run -------------------------------------------------------------------

TMP_BENCH_JSON="$(mktemp)"
trap 'rm -f "${TMP_BENCH_JSON}"' EXIT

"${BENCH_BIN}" \
  --benchmark_format=json \
  --benchmark_out="${TMP_BENCH_JSON}" \
  --benchmark_out_format=json \
  --benchmark_repetitions="${REPETITIONS}" \
  --benchmark_report_aggregates_only=false \
  --benchmark_display_aggregates_only=false \
  --benchmark_min_time="${MIN_TIME}s" \
  >/dev/null

# ---- envelope --------------------------------------------------------------

GIT_REV="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
GIT_DIRTY="$(git -C "${REPO_ROOT}" diff --quiet 2>/dev/null || echo 'dirty')"
KERNEL="$(uname -srvmo)"
CPU_MODEL="$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo 'unknown')"
COMPILER="$(cmake --system-information 2>/dev/null | grep -m1 'CMAKE_CXX_COMPILER ' | awk -F'"' '{print $2}' || echo 'unknown')"
COMPILER_VER="$( "${COMPILER}" --version 2>/dev/null | head -n 1 || echo 'unknown' )"

# Emit the envelope + the raw google-benchmark payload inline. jq is used
# if available for pretty-printing; falls back to python -m json.tool; falls
# back to raw concatenation as a last resort.
PRETTY_JSON="$(
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg schema_version "wallet2_baseline_v0" \
      --arg git_rev "${GIT_REV}" \
      --arg git_dirty "${GIT_DIRTY}" \
      --arg kernel "${KERNEL}" \
      --arg cpu_model "${CPU_MODEL}" \
      --arg compiler "${COMPILER}" \
      --arg compiler_version "${COMPILER_VER}" \
      --argjson benchmarks "$(cat "${TMP_BENCH_JSON}")" \
      '{
         schema_version: $schema_version,
         captured_on: {
           git_rev: $git_rev,
           git_dirty: $git_dirty,
           kernel: $kernel,
           cpu_model: $cpu_model,
           compiler: $compiler,
           compiler_version: $compiler_version
         },
         google_benchmark: $benchmarks
       }'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, os, sys
with open(os.environ["TMP_BENCH_JSON"]) as f:
  benchmarks = json.load(f)
envelope = {
  "schema_version": "wallet2_baseline_v0",
  "captured_on": {
    "git_rev": os.environ["GIT_REV"],
    "git_dirty": os.environ["GIT_DIRTY"],
    "kernel": os.environ["KERNEL"],
    "cpu_model": os.environ["CPU_MODEL"],
    "compiler": os.environ["COMPILER"],
    "compiler_version": os.environ["COMPILER_VER"],
  },
  "google_benchmark": benchmarks,
}
print(json.dumps(envelope, indent=2))
'
  else
    # Minimal fallback. Not pretty-printed; downstream consumers must be
    # json-tolerant. This path should be rare (every dev box has jq or python).
    printf '{"schema_version":"wallet2_baseline_v0","captured_on":{"git_rev":"%s","git_dirty":"%s","kernel":"%s","cpu_model":"%s","compiler":"%s","compiler_version":"%s"},"google_benchmark":' \
      "${GIT_REV}" "${GIT_DIRTY}" "${KERNEL}" "${CPU_MODEL}" "${COMPILER}" "${COMPILER_VER}"
    cat "${TMP_BENCH_JSON}"
    printf '}'
  fi
)"

export TMP_BENCH_JSON GIT_REV GIT_DIRTY KERNEL CPU_MODEL COMPILER COMPILER_VER

mkdir -p "$(dirname "${OUTPUT_PATH}")"
printf '%s\n' "${PRETTY_JSON}" > "${OUTPUT_PATH}"

echo "[capture_cpp_baseline] wrote ${OUTPUT_PATH}"
echo "[capture_cpp_baseline] review the numbers, then commit the file as a follow-up to"
echo "[capture_cpp_baseline] the harness commit. Do not commit baselines captured on"
echo "[capture_cpp_baseline] a laptop running other workloads; they are misleading."
