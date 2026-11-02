#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# PoW test-seam containment (CEN-D2).
#
# set_pow_hash_override_for_tests replaced the ratified RandomX dispatch
# with an arbitrary hash function. Its last caller left with the C++ chain
# tests, and the seam was deleted with it (rule 15). This gate's subject is
# that absence: a reintroduction is the failure. The production hash it
# stands next to is the Rust one since the DRS-X flip deleted
# `src/crypto/pow_randomx.cpp`: `shekyl_pow_randomx::compute_hash`, which
# the ingest's substrate calls for every block it judges (rule 47: the
# gate asserts its subject exists before it reports the seam absent).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 1
fi

if [[ ! -f rust/shekyl-pow-randomx/src/vm.rs ]]; then
  echo "FAIL: rust/shekyl-pow-randomx/src/vm.rs is missing — the production hash this gate stands next to is gone" >&2
  exit 1
fi

if ! rg -q 'pub fn compute_hash\(' rust/shekyl-pow-randomx/src/vm.rs; then
  echo "FAIL: compute_hash is not defined in rust/shekyl-pow-randomx/src/vm.rs" >&2
  exit 1
fi

if ! rg -q 'compute_hash' rust/shekyl-chain-ingest/src/substrate.rs; then
  echo "FAIL: the ingest's substrate no longer calls compute_hash — the production dispatch moved; re-anchor this gate" >&2
  exit 1
fi

rc=0
hits="$(rg -n 'set_pow_hash_override_for_tests' src tests rust || rc=$?)"
if (( rc > 1 )); then
  echo "FAIL: rg exited ${rc} scanning for the deleted seam" >&2
  exit 1
fi
if [[ -n "${hits}" ]]; then
  echo "FAIL: set_pow_hash_override_for_tests is back:" >&2
  echo "${hits}" >&2
  exit 1
fi

echo "OK: set_pow_hash_override_for_tests is absent; compute_hash remains the production hash"
