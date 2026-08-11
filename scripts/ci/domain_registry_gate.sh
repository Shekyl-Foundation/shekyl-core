#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# SA-3b domain-registry gate. Keeps docs/design/CRYPTO_DOMAIN_REGISTRY.tsv in
# lockstep with the code by two blunt-but-firing tripwires. It does NOT parse
# call arguments (multi-line calls defeat that) and it does NOT grep by prefix.
#
# WHY call-site-anchored, not prefix-anchored: Shekyl's domain strings share no
# common prefix — "shekyl/", "shekyl-", "Shekyl ", "Monero ", "bulletproof" all
# occur. A "shekyl/"-anchored grep would silently miss shekyl-pqc-leaf,
# Shekyl FROST SAL v1, the frozen Monero DSTs, and more. That blind spot is the
# exact SA §3.1 defect this round exists to close, so the anchor is the mechanism
# entry point / the registered literal, never the spelling.
#
# TRIPWIRE 1 — row-presence (all rows, every mechanism). For each registered
# literal, rg -F for b"<literal>" in its defining file. Fires on: a value change
# (byte edit), a rename, a move, or a deletion without a registry update. This is
# the drift-closer.
#
# TRIPWIRE 2 — entry-point count-pin (mechanisms whose entry point ALWAYS carries
# a domain: 1 cSHAKE, 3 FROST transcript). Any new such call site changes the
# count and fails, forcing the author to register the new domain and bump the pin.
# Mechanisms 2 (HKDF), 4 (Blake2b), 5 (keccak) are NOT count-pinned: their entry
# points (Hkdf::new, Blake2b512, keccak256) are general-purpose primitives used
# for non-domain hashing too, so a call-site count would be noise, not signal.
# For those mechanisms new domains are caught by row-presence + the distinctness
# test (rust/shekyl-crypto-pq/tests/domain_registry.rs) + review.
#
# Requires ripgrep (rg). CI installs it in an explicit step before this runs.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
REGISTRY="docs/design/CRYPTO_DOMAIN_REGISTRY.tsv"

if ! command -v rg >/dev/null 2>&1; then
  echo "FATAL: ripgrep (rg) not found — CI must install it before this gate." >&2
  exit 2
fi
if [[ ! -f "$REGISTRY" ]]; then
  echo "FATAL: registry not found at $REGISTRY" >&2
  exit 2
fi

fail=0

# ── Tripwire 1: row-presence ────────────────────────────────────────────────
rows=0
while IFS=$'\t' read -r mech literal file _const _status _key _notes; do
  [[ -z "${mech:-}" || "${mech:0:1}" == "#" ]] && continue
  rows=$((rows + 1))
  if [[ ! -f "$file" ]]; then
    echo "MISSING FILE: [$mech] $file (for literal b\"$literal\")" >&2
    fail=1
    continue
  fi
  # rg -F: fixed-string, so backslash escapes (\0, \x03) match the source's own
  # escapes verbatim. The trailing " makes the match exact (no substring drift:
  # "bulletproof" does not match inside "bulletproof_plus"). Accept either the
  # byte-string form b"..." or the &str form "..." — some frozen DSTs (the
  # bulletproof generator names) are passed as &str and .as_bytes()'d downstream.
  if ! rg -F -q -- "b\"$literal\"" "$file" && ! rg -F -q -- "\"$literal\"" "$file"; then
    echo "NOT FOUND: b\"$literal\" (nor \"$literal\") present in $file  [mech $mech]" >&2
    fail=1
  fi
done < "$REGISTRY"
echo "row-presence: checked $rows registered literals"

# ── Tripwire 2: entry-point count-pins (mech 1 cSHAKE, mech 3 FROST) ─────────
# Production trees only (exclude tests/benches/fuzz/examples dirs). Inline
# #[cfg(test)] sites in src/ are included in the pin by design: a new test that
# calls a domain-carrying entry point should still trip a look.
PROD_GLOBS=(-g 'rust/**/*.rs' -g '!**/tests/**' -g '!**/benches/**' -g '!**/fuzz/**' -g '!**/examples/**')

count_pattern() {
  # count total matches (not lines) of a regex across production rust code
  rg -o --no-filename "${PROD_GLOBS[@]}" "$1" rust 2>/dev/null | wc -l | tr -d ' '
}

# --- mech 1: cSHAKE256 customization call sites ---
MECH1_EXPECTED=36
mech1=$(count_pattern 'cshake256_(?:32|64)\(|CShake256Core::new\(')
if [[ "$mech1" != "$MECH1_EXPECTED" ]]; then
  echo "COUNT DRIFT mech 1 (cSHAKE call sites): found $mech1, pinned $MECH1_EXPECTED." >&2
  echo "  A cSHAKE call site was added/removed. Register the new domain in $REGISTRY and update the pin." >&2
  fail=1
fi

# --- mech 3: FROST transcript labels ---
MECH3_EXPECTED=2
mech3=$(count_pattern 'RecommendedTranscript::new\(|\.domain_separate\(')
if [[ "$mech3" != "$MECH3_EXPECTED" ]]; then
  echo "COUNT DRIFT mech 3 (FROST transcript labels): found $mech3, pinned $MECH3_EXPECTED." >&2
  echo "  A FROST transcript label site was added/removed. Register it in $REGISTRY and update the pin." >&2
  fail=1
fi

echo "count-pins: mech1(cSHAKE)=$mech1 mech3(FROST)=$mech3"

if [[ "$fail" -ne 0 ]]; then
  echo "domain-registry gate: FAIL" >&2
  exit 1
fi
echo "domain-registry gate: PASS"
