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
#   preflight    — oracle-constant guards (no harness required; passes today)
#   layer1       — Layer 1 per-quantity dual-leg KAT (legs A + B)
#   layer2       — Layer 2 multi-block accumulation + cap invariant + A vs B
#   layer3       — Layer 3 pop-replay reorg coupling
#   conservation — archival budget supply-conservation KAT (C-1 fast-follow,
#                  REWARD_EMISSION_E3_GATING_ROUND.md §9.9): labeled-row
#                  identity through the real connect path + pop/reconnect
#   all          — preflight + layers 1–3 + conservation (local convenience)
#
# Harness naming contract (implementer MUST match — CI selects by these filters):
#
#   unit_tests (gtest):
#     EconomicsC2aPrime.Layer1*
#     EconomicsC2aPrime.Layer2*
#
#   core_tests (--filter glob):
#     economics_c2a_prime_layer3*
#     archival_budget_conservation*
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

verify_stale_subsidy_regex_probes() {
  # Self-check the Monero-scale (3×10¹¹) stale-literal regex before grep runs.
  # Documented probe set (§7.4 E3):
  #   300_000_000_000, 300000000000, 3 * 10^11  → match (positives)
  #   300000000 (Shekyl authoritative), 30000000000 (3×10¹⁰ near-miss) → no match
  local line matched expect
  _probe() {
    line="$1"
    expect="$2" # match | nomatch
    if printf '%s\n' "$line" | rg -q "$STALE_FINAL_SUBSIDY_RG"; then
      matched=1
    else
      matched=0
    fi
    if [[ "$expect" == match && "$matched" -eq 0 ]]; then
      die "stale-subsidy regex probe failed: '${line}' should match"
    fi
    if [[ "$expect" == nomatch && "$matched" -eq 1 ]]; then
      die "stale-subsidy regex probe failed: '${line}' should not match"
    fi
    echo "OK: regex probe ${expect} — '${line}'"
  }
  _probe '300_000_000_000' match
  _probe '300000000000' match
  _probe '3 * 10^11' match
  _probe '300000000' nomatch
  _probe '30000000000' nomatch
}

verify_build_artifact_layout() {
  # Layer jobs consume the build/ tarball from the build job. The CALIBRATION
  # build is CMAKE_BUILD_TYPE=Release, so BUILD_SHARED_LIBS defaults OFF
  # (CMakeLists.txt:608-612 flips it ON only for Debug). Internal libraries are
  # static .a archives and the test binaries are statically linked against them,
  # so no internal .so files exist — the binaries are self-contained. This must
  # stay in lockstep with the build job's manifest step in economics-c2a-prime.yml.
  # tests/data/ is repo-tracked and comes from checkout, not the tarball.
  local missing=0
  local required=(
    "$BUILD_DIR/tests/unit_tests/unit_tests"
    "$BUILD_DIR/tests/core_tests/core_tests"
  )
  for path in "${required[@]}"; do
    if [[ ! -e "$path" ]]; then
      echo "FATAL: build artifact missing ${path#"$REPO_ROOT/"}" >&2
      missing=1
    fi
  done
  if [[ "$missing" -ne 0 ]]; then
    die "build artifact layout incomplete — expand tarball or fix build job packaging"
  fi
  if [[ ! -d "$REPO_ROOT/tests/data" ]]; then
    die "tests/data/ missing from checkout — unit_tests needs --data-dir or DEFAULT_DATA_DIR"
  fi
  echo "OK: build artifact layout (statically-linked test binaries); tests/data from checkout"
}

count_gtest_cases() {
  local filter="$1"
  local out rc
  # --gtest_list_tests is a boolean flag; the suite filter is --gtest_filter.
  #
  # stderr is CAPTURED, not discarded. Discarding it made this function
  # unable to tell "the binary ran and matched nothing" from "the binary
  # never ran at all" -- and the caller reports the first, so a missing
  # shared library or an unrunnable binary was announced as "land the
  # harness in tests/unit_tests/". That is a gate misnaming its own
  # subject (47-gate-subject-assertion.mdc); the distinction is made here
  # so the message points at the real cause.
  #
  # Verdict captured before any pipe (rule 46): `grep -c` on its own line
  # would otherwise be the exit status this function reports.
  out="$("$UNIT_TESTS" --gtest_list_tests --gtest_filter="$filter" 2>&1)"
  rc=$?
  if (( rc != 0 )); then
    die "unit_tests could not be listed (exit ${rc}) for filter '${filter}'. \
This is NOT a missing harness -- the binary exists but did not run. \
Its output was:
${out}"
  fi
  printf '%s\n' "$out" | grep -c '^  ' || true
}

count_core_tests() {
  local filter="$1"
  # core_tests --filter uses glob; strip trailing * for fixed-string prefix match.
  local prefix="${filter%\*}"
  "$CORE_TESTS" --list_tests 2>/dev/null | grep -cF "$prefix" || true
}

require_gtest_harness() {
  local layer="$1" filter="$2"
  local count
  count="$(count_gtest_cases "$filter")"
  if [[ "$count" -eq 0 ]]; then
    # Reaching here means the binary RAN and matched nothing -- the
    # unrunnable case is caught in count_gtest_cases with its own
    # message. Both possibilities are named because the harness file
    # existing in the tree is not evidence it reached the binary.
    die "no C2a′ Layer ${layer} gtest cases (filter '${filter}'). \
unit_tests ran but matched nothing: either the harness is absent, or it \
is present in tests/unit_tests/ and did not reach this binary (stale \
build artifact, or a source file not compiled into the target). Check \
tests/unit_tests/economics_c2a_prime.cpp and its CMakeLists entry before \
assuming the former. Spec: docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md §5.8."
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
  "$CORE_TESTS" --generate_and_play_test_data --filter="$filter"
}

rust_test_exists() {
  local crate="$1" pattern="$2"
  local listing
  (
    cd "$REPO_ROOT/rust"
    listing="$(cargo test --locked -p "$crate" -- --list 2>/dev/null)" || true
    printf '%s\n' "$listing" | rg -q "$pattern"
  )
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
  verify_stale_subsidy_regex_probes

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
  verify_build_artifact_layout
  require_build_tree
  require_gtest_harness 1 'EconomicsC2aPrime.Layer1*'
  run_gtest_layer 'EconomicsC2aPrime.Layer1*'
  run_rust_layer1
}

cmd_layer2() {
  require_repo_root
  verify_build_artifact_layout
  require_build_tree
  require_gtest_harness 2 'EconomicsC2aPrime.Layer2*'
  run_gtest_layer 'EconomicsC2aPrime.Layer2*'
  run_rust_layer2
}

# The ONE fail-closed core_tests gate: refuses to pass green when the filter
# matches zero registered tests (the convention-theater class). Every
# core_tests lane goes through here — a gate fix applied to a per-lane copy
# leaves the other lanes theater.
run_core_tests_gate() {
  local filter="$1" label="$2" hint="$3"
  require_repo_root
  verify_build_artifact_layout
  require_build_tree
  local count
  count="$(count_core_tests "$filter")"
  if [[ "$count" -eq 0 ]]; then
    die "no ${label} core_tests (filter '${filter}'). ${hint}"
  fi
  echo "${label}: found ${count} core_tests case(s) matching ${filter}"
  run_core_tests_layer "$filter"
}

cmd_layer3() {
  run_core_tests_gate 'economics_c2a_prime_layer3*' 'C2a′ Layer 3' \
    'Land pop-replay harness per STAGE_1_PR_7 §5.8.'
}

cmd_conservation() {
  run_core_tests_gate 'archival_budget_conservation*' 'archival budget conservation' \
    'Land the C-1 conservation KAT per REWARD_EMISSION_E3_GATING_ROUND.md §9.9.'
}

usage() {
  echo "Usage: $(basename "$0") {preflight|layer1|layer2|layer3|conservation|all}" >&2
  exit 2
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    preflight) cmd_preflight ;;
    layer1) cmd_layer1 ;;
    layer2) cmd_layer2 ;;
    layer3) cmd_layer3 ;;
    conservation) cmd_conservation ;;
    all)
      cmd_preflight
      cmd_layer1
      cmd_layer2
      cmd_layer3
      cmd_conservation
      ;;
    *) usage ;;
  esac
}

main "$@"
