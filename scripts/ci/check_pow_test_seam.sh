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
# that absence: a reintroduction is the failure.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 1
fi

if [[ ! -f src/crypto/pow_randomx.cpp ]]; then
  echo "FAIL: src/crypto/pow_randomx.cpp is missing — the production hash this gate stands next to is gone" >&2
  exit 1
fi

if ! rg -q 'bool hash_pow_randomx\(' src/crypto/pow_randomx.cpp; then
  echo "FAIL: hash_pow_randomx is not defined in src/crypto/pow_randomx.cpp" >&2
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

echo "OK: set_pow_hash_override_for_tests is absent; hash_pow_randomx remains"
