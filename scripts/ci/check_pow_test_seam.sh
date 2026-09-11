#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# PoW test-seam containment (CEN-D2 fix, PR #604).
#
# set_pow_schema_override_for_tests replaces the ratified RandomX dispatch
# with an arbitrary schema. That is exactly the capability a production
# caller must never have: installing a schema that always "succeeds" would
# re-open the fail-open this seam exists to test against. The seam's own
# comment claims production never calls it — this gate is what makes that
# claim true rather than aspirational.
#
# Contract, three ways:
#   1. the symbol appears ONLY in its declaration, its definition, and tests;
#   2. the declaration and definition still exist (a renamed seam must fail
#      loudly, not pass vacuously — rule 47);
#   3. at least one test calls it (a seam no test uses is dead production
#      surface, and rule 15 says delete it rather than carry it).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Dependency precondition: rg is the load-bearing tool; a missing rg must be
# a loud failure, not a silently-green gate.
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

SYMBOL="set_pow_schema_override_for_tests"
DECL="src/crypto/pow_registry.h"
DEFN="src/crypto/pow_registry.cpp"

FAIL=0

# Guardrail (rule 47): the pinned files must exist, or the invariants below
# pass on zero hits and the gate reports green over a moved subject.
for f in "$DECL" "$DEFN"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: $f not found — a pinned file moved; update this gate, do not let it pass silently" >&2
    exit 1
  fi
done

# -- Invariant 1: the seam exists where it is pinned ------------------------
for f in "$DECL" "$DEFN"; do
  hits="$(scan -c "$SYMBOL" "$f" || true)"
  if [[ -z "$hits" ]]; then
    echo "FAIL: ${SYMBOL} not found in ${f} — renamed or deleted; update this gate (absence of signal is first evidence the subject is absent)" >&2
    FAIL=1
  fi
done

# -- Invariant 2: at least one test uses it --------------------------------
test_hits="$(scan -l "$SYMBOL" tests/ || true)"
if [[ -z "$test_hits" ]]; then
  echo "FAIL: no test calls ${SYMBOL} — a test seam no test uses is dead production surface (rule 15: delete it)" >&2
  FAIL=1
fi

# -- Invariant 3: no production caller -------------------------------------
#
# Everything outside the declaration, the definition and tests/ is a
# production reference. There is deliberately no allow-marker: an exemption
# here would be an exemption from the seam's whole point.
DECL_RE="${DECL//./\\.}"
DEFN_RE="${DEFN//./\\.}"
stray="$(scan -n "$SYMBOL" src/ | scan -v "^(${DECL_RE}|${DEFN_RE}):" || true)"
if [[ -n "$stray" ]]; then
  echo "FAIL: ${SYMBOL} referenced outside its declaration/definition — production must never install a PoW schema:" >&2
  echo "$stray" >&2
  FAIL=1
fi

if (( FAIL )); then
  exit 1
fi
echo "PoW test-seam containment: OK"
