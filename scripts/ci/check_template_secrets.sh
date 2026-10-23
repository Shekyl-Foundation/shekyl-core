#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# The node's template draws its secrets from the OS (DRS_X_STORE_FLIP.md
# DX-Q3, Q4).
#
# The tip follower builds the node's one block template
# (rust/shekyl-chain-ingest/src/template.rs). Its coinbase transaction
# secret is OS-random per template and its draw commitment is
# `commit_and_discard`'s. The scenario driver, a test instrument, builds
# with a counter-derived secret and a commitment stamped over
# CONFORMING_DRAW_COMMITMENT, so its blocks are reproducible. Either value
# in a production block is a key anyone can guess.
#
# Contract:
#   1. the production code of the crates that build, carry and serve the
#      template names neither CONFORMING_DRAW_COMMITMENT nor the scenario's
#      builder;
#   2. the producer draws from the OS and commits through
#      commit_and_discard;
#   3. the scenario's builder still uses both test values where this gate
#      expects them (rule 47: a moved subject fails loudly, never passes
#      on zero hits);
#   4. shekyl-ffi, which builds the C++ template's coinbase extra, names
#      the conforming value only in its coinbase-extra module — the
#      test-support writer `shekyl_test_coinbase_extra` and that module's
#      tests — its production writer commits through commit_and_discard,
#      and no C++ under src/ calls the test writer.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 1
fi

# rg exit-code discipline: 0 = matches, 1 = no matches, >1 = scan error.
scan() {
  local rc=0
  rg "$@" || rc=$?
  if (( rc > 1 )); then
    echo "FAIL: rg exited ${rc} (scan error, not no-match) during: rg $*" >&2
    return "${rc}"
  fi
  return 0
}

PRODUCER="rust/shekyl-chain-ingest/src/template.rs"
SCENARIO="rust/shekyl-chain-ingest/src/scenario.rs"
# The production sources of the crates that build, post and serve the
# template. Test modules, test support and the test-only scenario driver
# (`cfg(any(test, feature = "harness"))`, a TEST_ONLY feature) are out.
PRODUCTION_DIRS=(
  rust/shekyl-chain-ingest/src
  rust/shekyl-node/src
  rust/shekyl-block-template/src
  rust/shekyl-miner/src
  rust/shekyl-daemon-rpc/src
  rust/shekyl-daemon/src
)
FFI_DIR="rust/shekyl-ffi/src"
FFI_EXTRA="rust/shekyl-ffi/src/tx_extra_codec_ffi.rs"
TEST_GLOBS=(
  --glob '!*_tests.rs'
  --glob '!tests.rs'
  --glob '!test_support.rs'
  --glob '!scenario*.rs'
)

FAIL=0

for f in "$PRODUCER" "$SCENARIO" "$FFI_EXTRA"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: $f not found — a pinned file moved; update this gate" >&2
    exit 1
  fi
done
for d in "${PRODUCTION_DIRS[@]}"; do
  if [[ ! -d "$d" ]]; then
    echo "FAIL: $d not found — a pinned crate moved; update this gate" >&2
    exit 1
  fi
done

# -- 1. No test value in production code ------------------------------------
hits="$(scan -n 'CONFORMING_DRAW_COMMITMENT|scenario::build_template' "${TEST_GLOBS[@]}" "${PRODUCTION_DIRS[@]}" || true)"
if [[ -n "$hits" ]]; then
  echo "FAIL: a test-only template value is named in production code:" >&2
  echo "$hits" >&2
  echo "  The node's template draws its coinbase secret from the OS and its" >&2
  echo "  draw commitment from commit_and_discard (template.rs)." >&2
  FAIL=1
fi

# -- 2. The producer draws from the OS --------------------------------------
for needle in 'OsRng' 'commit_and_discard\(\)'; do
  found="$(scan -c "$needle" "$PRODUCER" || true)"
  if [[ -z "$found" ]]; then
    echo "FAIL: ${PRODUCER} no longer names ${needle} — the template's secrets must be the OS's" >&2
    FAIL=1
  fi
done

# -- 3. The subject this gate excludes is where it is expected ---------------
for needle in 'CONFORMING_DRAW_COMMITMENT' 'counter\.to_le_bytes\(\)'; do
  found="$(scan -c "$needle" "$SCENARIO" || true)"
  if [[ -z "$found" ]]; then
    echo "FAIL: ${SCENARIO} no longer names ${needle} — the test values moved; point this gate at them" >&2
    FAIL=1
  fi
done

# -- 4. shekyl-ffi: the conforming value only in the test-support writer ----
ffi_hits="$(scan -l 'CONFORMING_DRAW_COMMITMENT' "${TEST_GLOBS[@]}" "$FFI_DIR" || true)"
if [[ -n "$ffi_hits" && "$ffi_hits" != "$FFI_EXTRA" ]]; then
  echo "FAIL: shekyl-ffi names CONFORMING_DRAW_COMMITMENT outside ${FFI_EXTRA}:" >&2
  echo "$ffi_hits" >&2
  FAIL=1
fi
for needle in 'fn shekyl_test_coinbase_extra' 'commit_and_discard\(\)\.ok\(\)'; do
  found="$(scan -c "$needle" "$FFI_EXTRA" || true)"
  if [[ -z "$found" ]]; then
    echo "FAIL: ${FFI_EXTRA} no longer names ${needle} — the coinbase writers moved; update this gate" >&2
    FAIL=1
  fi
done
cpp_callers="$(scan -n 'shekyl_test_coinbase_extra\(' src --glob '!src/shekyl/shekyl_ffi.h' || true)"
if [[ -n "$cpp_callers" ]]; then
  echo "FAIL: production C++ calls the test coinbase writer, whose draw commitment anyone can guess:" >&2
  echo "$cpp_callers" >&2
  FAIL=1
fi

if (( FAIL )); then
  exit 1
fi
echo "OK: the node's template takes its coinbase secret and draw commitment from the OS"
