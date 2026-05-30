#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_zeroize.sh — mid-rewire hardening-pass commit 5, §3.5.
#
# Last-line-of-defense that every `[u8; N]` or `Vec<u8>` field
# declared inside `rust/shekyl-engine-state/src/**/*.rs` (production
# code — test modules are elided) is either:
#
#   1. Wrapped in a zeroize-on-drop type (`Zeroizing<...>` or
#      `SecretKey<...>`) at the same-line declaration site, OR
#   2. Enumerated in `rust/shekyl-engine-state/.zeroize-allowlist`
#      as a deliberate public-bytes field (public keys, block
#      hashes, tx hashes, key images, mirror-struct schema fields,
#      runtime-only indexes).
#
# The schema snapshot from hardening-pass commit 4
# (`docs/MID_REWIRE_HARDENING.md` §3.4) catches wire-format changes
# but cannot catch a `Zeroizing<[u8; 32]>` → `[u8; 32]` unwrap — the
# two produce byte-for-byte identical postcard output, so the
# snapshot is blind to this gap. This script closes it.
#
# Policy is codified in `.cursor/rules/42-serialization-policy.mdc`
# and documented in §3.5. Exit code 0 = clean; non-zero = either a
# missing allowlist entry (someone added an unwrapped field) or a
# stale allowlist entry (someone removed a field without also
# removing the allowlist line).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRATE_DIR="${REPO_ROOT}/rust/shekyl-engine-state"
SRC_DIR="${CRATE_DIR}/src"
ALLOWLIST="${CRATE_DIR}/.zeroize-allowlist"

if [ ! -f "${ALLOWLIST}" ]; then
  echo "FATAL: allowlist missing at ${ALLOWLIST}"
  echo "       Commit 5 of the hardening pass requires an authored"
  echo "       allowlist; see docs/MID_REWIRE_HARDENING.md §3.5."
  exit 2
fi

# ---- Pass 1: collect field-declaration hits ----------------------------
#
# Walk every production `.rs` file under `src/`, strip test modules
# (`#[cfg(test)] mod tests { ... }` is our convention), then scan for
# lines that declare a field whose type contains `[u8; N]` or
# `Vec<u8>`. Paren-depth tracking excludes function-parameter lines in
# multi-line signatures (e.g. `pub fn new(tx_keys: BTreeMap<[u8; 32],
# …>, …)`); comment/doc lines are stripped; `use` / `type` / `fn` /
# `let` / `match` / `impl` / return-arrow lines are excluded. The
# remaining hits are strict field declarations, including tuple-struct
# single-liners like `pub struct PaymentId(pub [u8; 8]);`.
HITS=$(
  for f in "${SRC_DIR}"/*.rs; do
    # Use awk to walk the file, tracking paren depth across lines so
    # we can tell "inside a multi-line fn sig" from "struct body."
    awk -v file="${f#${REPO_ROOT}/}" '
      BEGIN { pdepth = 0; test_seen = 0 }

      # Stop at the first #[cfg(test)] — Rust test modules are not
      # persisted, so their field declarations are out of scope.
      /^[ \t]*#\[cfg\(test\)\]/ { test_seen = 1 }
      { if (test_seen) next }

      {
        line = $0
        # Strip end-of-line comments (best-effort; struct fields do
        # not contain `//` inside string literals in this crate).
        sub(/[ \t]*\/\/.*$/, "", line)

        # Skip entirely-commented doc lines before paren-depth update.
        if ($0 ~ /^[ \t]*\/\/\//) next
        if ($0 ~ /^[ \t]*\/\//) next
        if (line ~ /^[ \t]*$/) next

        # Count parens before deciding; a struct-field line contributes
        # zero net parens, so the check happens at the pre-update depth.
        start_depth = pdepth

        # Skip lines that smell like function signatures / bodies /
        # expressions before scoring for field-shape.
        skip = 0
        if (line ~ /\<fn[ \t]+[A-Za-z_]/) skip = 1
        if (line ~ /\<let[ \t]+[A-Za-z_]/) skip = 1
        if (line ~ /\<for[ \t]+[A-Za-z_]/) skip = 1
        if (line ~ /\<match[ \t]/) skip = 1
        if (line ~ /\<impl\>/) skip = 1
        if (line ~ /\<use[ \t]/) skip = 1
        if (line ~ /^[ \t]*type[ \t]/) skip = 1
        if (line ~ /->/) skip = 1
        if (line ~ /^[ \t]*assert/) skip = 1

        if (!skip && start_depth == 0 && line ~ /(\[u8;|Vec<u8>)/) {
          # Require a field-shape match:
          #   - normal field:   (pub )? NAME :  TYPE
          #   - tuple-struct:   (pub )? struct NAME ( ... TYPE ... ) ;
          if (line ~ /^[ \t]*(#\[[^]]+\][ \t]*)?(pub(\([^)]*\))?[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*:/ \
              || line ~ /^[ \t]*(pub[ \t]+)?struct[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\(.*(\[u8;|Vec<u8>)/) {
            # Normalize: strip leading whitespace and trailing comma.
            norm = line
            sub(/^[ \t]+/, "", norm)
            sub(/[ \t]*,[ \t]*$/, "", norm)
            sub(/[ \t]+$/, "", norm)
            printf "%s|%s\n", file, norm
          }
        }

        # Update paren depth for the next line.
        opens = gsub(/\(/, "(", line)
        closes = gsub(/\)/, ")", line)
        pdepth += opens - closes
        if (pdepth < 0) pdepth = 0
      }
    ' "$f"
  done
)

# ---- Pass 2: filter out Zeroizing / SecretKey wrappers ----------------
#
# A field like `Option<Zeroizing<[u8; 32]>>` contains `Zeroizing<` on
# the same line; it is wrapped and auto-passes. Any other typed secret
# wrapper registered here wraps a `Zeroizing<T>` internally, so
# carrying them in the filter list stays safe.
UNWRAPPED_HITS=$(
  if [ -n "${HITS}" ]; then
    echo "${HITS}" | grep -Ev 'Zeroizing<|SecretKey<' || true
  fi
)

# ---- Pass 3: diff against the allowlist -------------------------------
#
# The allowlist enumerates every deliberate public-bytes field as
# `<relative-path>|<normalized field-decl>` (see §3.5 and the policy
# rule 42-serialization-policy.mdc for the entry format). Stripping
# comments and blank lines gives us the active set.
ACTIVE_ALLOW=$(
  grep -Ev '^[ \t]*(#|$)' "${ALLOWLIST}" | sed 's/[ \t]*$//' || true
)

# Missing: a live hit is not in the allowlist.
MISSING=$(
  { [ -n "${UNWRAPPED_HITS}" ] && echo "${UNWRAPPED_HITS}"; } \
    | grep -Fxv -f <(echo "${ACTIVE_ALLOW}") \
    || true
)

# Stale: an allowlist entry no longer matches any live hit.
STALE=$(
  { [ -n "${ACTIVE_ALLOW}" ] && echo "${ACTIVE_ALLOW}"; } \
    | grep -Fxv -f <(echo "${UNWRAPPED_HITS}") \
    || true
)

FAIL=0
if [ -n "${MISSING}" ]; then
  FAIL=1
  echo "FATAL: unwrapped byte-shaped field(s) without allowlist entry"
  echo
  echo "${MISSING}" | sed 's/^/  /'
  echo
  echo "Every [u8; N] or Vec<u8> field in shekyl-engine-state must"
  echo "either be wrapped in Zeroizing<...> / SecretKey<...>, OR be"
  echo "listed in:"
  echo "  ${ALLOWLIST#${REPO_ROOT}/}"
  echo
  echo "with a comment explaining why the bytes are public (public key,"
  echo "block hash, tx hash, key image, mirror-struct schema, runtime"
  echo "index, etc.)."
  echo
  echo "Policy: .cursor/rules/42-serialization-policy.mdc"
  echo "        docs/MID_REWIRE_HARDENING.md §3.5"
fi

if [ -n "${STALE}" ]; then
  FAIL=1
  echo "FATAL: stale allowlist entry — field no longer exists"
  echo
  echo "${STALE}" | sed 's/^/  /'
  echo
  echo "The listed entries are in ${ALLOWLIST#${REPO_ROOT}/}"
  echo "but do not match any current field declaration. Remove the"
  echo "entries from the allowlist in this commit; leaving them"
  echo "in place would silently permit a future field with the same"
  echo "spelling to land unwrapped."
fi

if [ "${FAIL}" -ne 0 ]; then
  exit 1
fi

echo "Zeroizing-field discipline clean: $(echo "${HITS}" | grep -c '.' || true) candidate field(s) scanned, all wrapped or allowlisted."
