#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# C2a′ economics dual-leg + accumulation CI gate — STAGE_1_PR_7 §5.8 / §7.4 E1.
#
# Invoked by `.github/workflows/economics-c2a-prime.yml`. Subcommands:
#
#   preflight   — oracle-constant guards (no harness required; passes today)
#   layer1      — Layer 1 per-quantity dual-leg KAT (legs A + B)
#   layer2      — Layer 2 multi-block accumulation + cap invariant + A vs B
#   layer3      — Layer 3 pop-replay reorg coupling
#   all         — preflight + layers 1–3 (local developer convenience)
#
# Harness naming contract (implementer MUST match — CI selects by these filters):
#
#   unit_tests (gtest):
#     EconomicsC2aPrime/Layer1.*
#     EconomicsC2aPrime/Layer2.*
#
#   core_tests (--filter glob):
#     economics_c2a_prime_layer3*
#
#   Rust (cargo test filter on test fn name):
#     c2a_prime_layer1*
#     c2a_prime_layer2*
#
# Build layout: `${BUILD_DIR:-./build}` with Release + BUILD_TESTS=ON.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
UNIT_TESTS="$BUILD_DIR/tests/unit_tests/unit_tests"
CORE_TESTS="$BUILD_DIR/tests/core_tests/core_tests"
ECONOMICS_JSON="$REPO_ROOT/config/economics_params.json"

# Monero-era tail subsidy (3×10¹¹) — twelve digits after the leading 3.
STALE_FINAL_SUBSIDY_RG='(\b300_?000_?000_?000\b|\b300000000000\b|3\s*\*\s*10\s*\^\s*11)'

die() {
  echo "FATAL: $*" >&2
  exit 1
}

require_repo_root() {
  cd "$REPO_ROOT"
}

require_build_tree() {
  if [[ ! -x "$UNIT_TESTS" ]]; then
    die "unit_tests binary missing at $UNIT_TESTS — configure with BUILD_TESTS=ON"
  fi
  if [[ ! -x "$CORE_TESTS" ]]; then
    die "core_tests binary missing at $CORE_TESTS — configure with BUILD_TESTS=ON"
  fi
}

require_ripgrep() {
  if ! command -v rg >/dev/null 2>&1; then
    die "ripgrep (rg) is required for economics C2a′ preflight — install via apt"
  fi
}

count_gtest_cases() {
  local filter="$1"
  # --gtest_list_tests is a boolean flag; the suite filter is --gtest_filter.
  "$UNIT_TESTS" --gtest_list_tests --gtest_filter="$filter" 2>/dev/null | grep -c '^  ' || true
}

count_core_tests() {
  local filter="$1"
  "$CORE_TESTS" --list_tests 2>/dev/null | grep -c "$filter" || true
}

require_gtest_harness() {
  local layer="$1" filter="$2"
  local count
  count="$(count_gtest_cases "$filter")"
  if [[ "$count" -eq 0 ]]; then
    die "no C2a′ Layer ${layer} gtest cases (filter '${filter}'). \
Land harness in tests/unit_tests/ per docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md §5.8."
  fi
  echo "Layer ${layer}: found ${count} gtest case(s) matching ${filter}"
}

run_gtest_layer() {
  local filter="$1"
  echo "==> gtest ${filter}"
  "$UNIT_TESTS" --gtest_filter="$filter"
}

run_core_tests_layer() {
  local filter="$1"
  echo "==> core_tests --filter=${filter}"
  "$CORE_TESTS" --filter="$filter"
}

rust_test_exists() {
  local crate="$1" pattern="$2"
  cargo test --locked -p "$crate" -- --list 2>/dev/null | grep -q "$pattern"
}

run_rust_layer1() {
  echo "==> cargo test shekyl-economics (Layer 1 leg B)"
  (
    cd "$REPO_ROOT/rust"
    cargo test --locked -p shekyl-economics --no-run
    if rust_test_exists shekyl-economics c2a_prime_layer1; then
      cargo test --locked -p shekyl-economics c2a_prime_layer1
    else
      die "no Rust Layer 1 leg-B test (c2a_prime_layer1*) in shekyl-economics — land with C2 in 7-base"
    fi
  )
}

run_rust_layer2() {
  echo "==> cargo test shekyl-economics-sim (Layer 2 leg B / B-accum)"
  (
    cd "$REPO_ROOT/rust"
    cargo test --locked -p shekyl-economics-sim --no-run
    cargo test --locked -p shekyl-economics --no-run
    cargo test --locked -p shekyl-economics-sim sim_defaults_match_canonical_economics_config
    if rust_test_exists shekyl-economics c2a_prime_layer2; then
      cargo test --locked -p shekyl-economics c2a_prime_layer2
    elif rust_test_exists shekyl-economics-sim c2a_prime_layer2; then
      cargo test --locked -p shekyl-economics-sim c2a_prime_layer2
    else
      die "no Rust Layer 2 B-accum test (c2a_prime_layer2*) — land with C2/C2a′ in 7-base"
    fi
  )
}

cmd_preflight() {
  require_repo_root
  require_ripgrep

  if ! command -v python3 >/dev/null 2>&1; then
    die "python3 required for economics_params.json oracle check"
  fi

  if [[ ! -f "$ECONOMICS_JSON" ]]; then
    die "missing authoritative oracle: $ECONOMICS_JSON"
  fi

  python3 - <<'PY'
import json
import sys
from pathlib import Path

path = Path("config/economics_params.json")
cfg = json.loads(path.read_text())
key = "final_subsidy_per_minute"
val = cfg.get(key)
if val != 300_000_000:
    print(f"FATAL: {key}={val!r}; authoritative Shekyl value is 300_000_000", file=sys.stderr)
    sys.exit(1)
print(f"OK: {key}={val} (authoritative JSON oracle)")
PY

  # Monero-era tail subsidy scale (3×10¹¹) — economics oracle paths only (§7.4 E3).
  if rg -n "$STALE_FINAL_SUBSIDY_RG" \
    rust/shekyl-economics \
    rust/shekyl-economics-sim/src \
    cmake/generate_economics_params.py \
    config/economics_params.json 2>/dev/null; then
    die "stale Monero-scale final_subsidy literal in economics oracle path (§7.4 E3)"
  fi
  echo "OK: no Monero-scale final_subsidy literals in economics oracle paths"
}

cmd_layer1() {
  require_repo_root
  require_build_tree
  require_gtest_harness 1 'EconomicsC2aPrime/Layer1.*'
  run_gtest_layer 'EconomicsC2aPrime/Layer1.*'
  run_rust_layer1
}

cmd_layer2() {
  require_repo_root
  require_build_tree
  require_gtest_harness 2 'EconomicsC2aPrime/Layer2.*'
  run_gtest_layer 'EconomicsC2aPrime/Layer2.*'
  run_rust_layer2
}

cmd_layer3() {
  require_repo_root
  require_build_tree
  local filter='economics_c2a_prime_layer3*'
  local count
  count="$(count_core_tests "$filter")"
  if [[ "$count" -eq 0 ]]; then
    die "no C2a′ Layer 3 core_tests (filter '${filter}'). \
Land pop-replay harness per STAGE_1_PR_7 §5.8."
  fi
  echo "Layer 3: found ${count} core_tests case(s) matching ${filter}"
  run_core_tests_layer "$filter"
}

usage() {
  echo "Usage: $(basename "$0") {preflight|layer1|layer2|layer3|all}" >&2
  exit 2
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    preflight) cmd_preflight ;;
    layer1) cmd_layer1 ;;
    layer2) cmd_layer2 ;;
    layer3) cmd_layer3 ;;
    all)
      cmd_preflight
      cmd_layer1
      cmd_layer2
      cmd_layer3
      ;;
    *) usage ;;
  esac
}

main "$@"
