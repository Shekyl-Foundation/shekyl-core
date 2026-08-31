#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The debit-authorization predicate has ONE implementation.
#
# A VALUE-OUT bond-post authorizes against the bond record's COMMITTED
# bond_spend_pk, never the persona's identity key -- which a serving host
# holds, and which would therefore turn a host compromise into a collateral
# drain. That predicate lives in `shekyl-archival-retention::debit_auth_pin`
# and is reached from C++ only through `shekyl_archival_debit_auth_pin`.
#
# The selector is `bond_debit > 0`, NOT the post kind: consumers are Unbond
# and the DROP arm of HoldingsUpdate. Rebond and HoldingsUpdate-add are
# credit paths (bond_debit == 0) authorized by the IDENTITY key, so this gate
# must not be read as prescribing the record-key pin for them.
#
# WHY A GATE AND NOT A COMMENT: it was implemented three times. The per-tx
# path and the checkpoint fast path in blockchain.cpp each spelled it out,
# and the Rust submit battery was about to be a fourth. The copies are far
# apart, they read as ordinary two-line conditions, and a drift between them
# is a consensus split between fast-syncing and fully-verifying nodes -- the
# failure mode the fast-path arm was itself written to prevent.
#
# The gate is narrow on purpose: it forbids a COMPARISON against a stored
# record's bond_spend_pk. Marshalling that key across the FFI (.data()/.size()
# as arguments), storing it, and the separate §9.11 coupling belt on the VIN's
# bond_spend_pk are all untouched -- that belt asks whether the wire carried a
# key at all, which is a different question from who is authorized.
set -uo pipefail

cd "$(dirname "$0")/../.."

fail=0

# ── Rule 47: assert the subject exists before asserting its absence ──────
# Absence of a hit is only evidence if the thing being centralised is there.
# Anchored on the open paren: an unanchored `pub fn debit_auth_pin` also
# matches `debit_auth_pin_renamed`, so the assertion would survive the very
# rename it exists to catch (observed 2026-08-29 -- the first draft of this
# gate passed its own bite).
if ! rg -q 'pub fn debit_auth_pin\(' rust/shekyl-archival-retention/src/debit_auth.rs; then
  echo "FAIL: debit_auth_pin is missing from shekyl-archival-retention -- this gate"
  echo "      would pass vacuously against a tree that lost the shared predicate."
  fail=1
fi

# CALL sites, not occurrences: counting the symbol would also count the
# `shekyl_ffi.h` declaration and the wrapper's own definition, so the count
# could never fall below two and the arm could never fail (observed
# 2026-08-29 -- the first draft of this arm passed its own bite).
# Three sites authorize a value-out today: the per-tx Unbond verify, the
# per-tx HoldingsUpdate-DROP verify, and the checkpoint fast path. (Rebond
# is not one -- credit path, identity key.)
callers=$(rg -n --no-filename 'archival_debit_auth_pin\(' src/ -g '*.cpp' \
          | rg -v '^\s*[0-9]+:bool archival_debit_auth_pin\(' \
          | rg -v 'shekyl_archival_debit_auth_pin\(' \
          | wc -l | tr -d ' ')
if [ "${callers:-0}" -lt 3 ]; then
  echo "FAIL: expected at least 3 C++ call sites for the shared debit pin"
  echo "      (per-tx debit verifies + the checkpoint fast path); found ${callers:-0}."
  echo "      A dropped caller means an arm stopped authorizing its value-out,"
  echo "      which the comparison arm below cannot see -- there is nothing to"
  echo "      compare when the check is simply gone."
  fail=1
fi

# ── The invariant: no C++ site compares against a stored bond_spend_pk ───
hits=$(rg -n --no-heading 'record\.bond_spend_pk|\.bond_spend_pk\s*$' src/ -g '*.cpp' -g '*.h' \
        | rg '(==|!=)' || true)
if [ -n "$hits" ]; then
  echo "FAIL: a C++ site compares against a stored record's bond_spend_pk."
  echo "      The debit-auth predicate has one implementation"
  echo "      (shekyl-archival-retention::debit_auth_pin); call"
  echo "      shekyl_archival_debit_auth_pin instead of re-deriving it."
  echo "$hits"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "PASS: the debit-auth predicate is single-sourced."
fi
exit "$fail"
