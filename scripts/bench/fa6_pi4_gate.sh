#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# FA-6 §8.5.1 / §8.7 Pi 4 gate capture.
#
# Run on Raspberry Pi 4 Model B (4 GB), active cooling, USB3 SSD host,
# per FA-6_VIEW_TAG_ML_KEM.md §8.2. Records stdout to
# docs/benchmarks/fa6_decap_prefilter_pi4_<scenario>.txt
#
# Requires: rustup toolchain from rust-toolchain.toml, release build.
#
# Usage:
#   ./scripts/bench/fa6_pi4_gate.sh smoke
#   ./scripts/bench/fa6_pi4_gate.sh a
#   ./scripts/bench/fa6_pi4_gate.sh b

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUST_ROOT="${REPO_ROOT}/rust"
OUT_DIR="${REPO_ROOT}/docs/benchmarks"

SCENARIO="${1:-}"
if [[ -z "${SCENARIO}" ]] || [[ ! "${SCENARIO}" =~ ^(smoke|a|b)$ ]]; then
  echo "usage: $0 smoke|a|b" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${OUT_DIR}/fa6_decap_prefilter_pi4_${SCENARIO}_${STAMP}.txt"

echo "[fa6_pi4_gate] scenario=${SCENARIO}"
echo "[fa6_pi4_gate] output=${OUT_FILE}"
echo "[fa6_pi4_gate] uname: $(uname -a)"

{
  echo "# FA-6 decap pre-filter gate capture"
  echo "# scenario=${SCENARIO}"
  echo "# captured_utc=${STAMP}"
  echo "# host=$(uname -n)"
  echo "# uname=$(uname -a)"
  echo "# rustc=$(rustc --version 2>/dev/null || echo missing)"
  echo "#"
  cd "${RUST_ROOT}"
  cargo run --release -p shekyl-crypto-pq --bin fa6_decap_prefilter_gate -- --scenario "${SCENARIO}"
} | tee "${OUT_FILE}"

echo "[fa6_pi4_gate] done — archive path in PERFORMANCE_BASELINE.md §FA-6"
