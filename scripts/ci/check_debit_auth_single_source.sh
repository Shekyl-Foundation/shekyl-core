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

# Each REQUIRED site by name, not a count. A count cannot tell a removed
# checkpoint call from a new unrelated one, and it counts comments; both were
# true of the previous version. These are the four places consensus decides a
# value-out is authorized, and each is asserted to reach the shared predicate:
#
#   blockchain.cpp   "Unbond"                 per-tx debit verify
#   blockchain.cpp   "HoldingsUpdate-drop"    per-tx debit verify
#   blockchain.cpp   "block fast-check debit" checkpoint fast path
#   daemon_submit_ffi.cpp                     the submit gather's work gate
#
# Comments are stripped first, so a mention in prose cannot stand in for a
# call. Adding a fifth value-out arm means adding its row here — deliberately,
# because a new arm that authorizes nothing is the failure this gate exists
# for and it cannot be detected by looking at the arms that do.
# Comment-stripped file body, captured rather than piped. `rg -q` exits on the
# first match, which SIGPIPEs the upstream `sed`, which under `pipefail` makes
# the whole pipeline non-zero -- i.e. every required call would read as ABSENT
# and the gate would fail closed for the wrong reason (rule 46: a gate verdict
# never travels through a pipe). Observed on the first run of this arm.
code_only() { sed 's://.*::' "$1"; }

require_call() {
  local file="$1" needle="$2" label="$3" body hits
  body=$(code_only "$file")
  hits=$(printf '%s\n' "$body" | rg -c "$needle" || true)
  if [ "${hits:-0}" -lt 1 ]; then
    echo "FAIL: ${label} no longer reaches the shared debit pin."
    echo "      An arm that stops authorizing its value-out is invisible to the"
    echo "      comparison check below -- there is nothing to compare when the"
    echo "      check is simply gone."
    fail=1
  fi
}

require_call src/cryptonote_core/blockchain.cpp \
  'archival_debit_auth_pin\(record, auth_pubkey, "Unbond"\)' \
  "per-tx Unbond verify"
require_call src/cryptonote_core/blockchain.cpp \
  'archival_debit_auth_pin\(record, auth_pubkey, "HoldingsUpdate-drop"\)' \
  "per-tx HoldingsUpdate-drop verify"
require_call src/cryptonote_core/blockchain.cpp \
  'archival_debit_auth_pin\(record,' \
  "checkpoint fast path"
require_call src/rpc/daemon_submit_ffi.cpp \
  'shekyl_archival_debit_auth_pin\(' \
  "submit gather work gate"

# And the Rust submit battery, which the previous version never checked at
# all: it could have inlined its own comparison and passed.
rust_pin=$(rg -c 'debit_auth_pin\(record\.bond_spend_pk\(\)' \
             rust/shekyl-daemon-rpc/src/submit/verifier.rs || true)
if [ "${rust_pin:-0}" -lt 1 ]; then
  echo "FAIL: the Rust submit battery no longer calls debit_auth_pin."
  echo "      UB3 is the debit arm's authorization; an inlined comparison"
  echo "      there is a fourth implementation of the predicate."
  fail=1
fi

# ── The invariant: no C++ STATEMENT compares an auth key to a stored key ──
#
# Statement-scoped, not line-scoped. The first draft matched `bond_spend_pk`
# and a comparison operator on the same physical line, with the receiver
# spelled literally `record` -- so it caught the shape I happened to bite it
# with and missed the ones a real re-implementation would take: the operands
# reversed, the comparison wrapped across lines, or the record held in a
# variable named anything else. clang-format wraps at 100 columns, and this
# predicate is longer than that, so the split form is the LIKELY one.
#
# So: strip comments, join each statement onto one line, then require a
# statement to mention a bond_spend_pk, a comparison operator, AND an auth
# key (pqc_auths / auth_pubkey / auth_key). That last conjunct is what keeps
# the §9.11 vin belt out of the net -- `bond.bond_spend_pk.size() != LEN`
# asks whether the WIRE carried a key, names no auth key, and is a different
# question from who is authorized.
#
# HONEST LIMIT, because a gate advertised as complete is worse than one whose
# reach is written down: this cannot catch a copy split across statements
# (`const auto& k = rec.bond_spend_pk;` then `if (auth == k)`), because the
# operands never meet in one statement. No grep can. What it does catch is
# the realistic accident -- someone re-spelling the predicate inline, the way
# it was already spelled three times -- and the call-site count above catches
# an arm dropping the shared pin entirely. Structural enforcement would need
# a clang-based check over the AST; that is the reopening criterion (rule 21)
# if a split-statement copy ever lands.
statements=$(rg --no-line-number --no-heading '' src/ -g '*.cpp' -g '*.h' \
              | sed 's://.*::' \
              | tr '\n' ' ' \
              | sed 's:;:;\n:g')
hits=$(printf '%s\n' "$statements" \
        | rg 'bond_spend_pk' \
        | rg '(==|!=)' \
        | rg '(pqc_auths|auth_pubkey|auth_key)' || true)
if [ -n "$hits" ]; then
  echo "FAIL: a C++ statement compares an auth key against a stored bond_spend_pk."
  echo "      The debit-auth predicate has one implementation"
  echo "      (shekyl-archival-retention::debit_auth_pin); call"
  echo "      shekyl_archival_debit_auth_pin instead of re-deriving it."
  printf '%s\n' "$hits"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "PASS: the debit-auth predicate is single-sourced."
fi
exit "$fail"
