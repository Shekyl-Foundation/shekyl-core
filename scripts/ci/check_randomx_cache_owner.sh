#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# One owner of every RandomX cache (docs/design/RANDOMX_CACHE_ACTOR.md,
# HA-R1…HA-R8).
#
# A cache is 256 MiB. In the daemon one crate builds, holds and frees one:
# `shekyl-hasher`, whose cap is three. Every other consumer hashes through
# a job on that hasher and holds no cache, so the cap is the memory. A
# second `PreparedCache::derive`, or an `Arc<PreparedCache>` held anywhere
# else, is a cache the cap does not count.
#
# The gate: `PreparedCache::derive` and `Arc<PreparedCache>` appear in Rust
# code only under the paths in ALLOWED:
#
#   - rust/shekyl-hasher/src            the owner;
#   - rust/shekyl-pow-randomx/src       the verifier, which defines both;
#   - rust/shekyl-pow-randomx/benches   the derive and hash benches;
#   - rust/shekyl-pow-randomx/examples  the request-cost measurement;
#   - rust/shekyl-randomx-differential  the differential harness's parity
#                                       and corpus modes, which compare the
#                                       verifier with the C reference and
#                                       never run in the daemon;
#   - rust/shekyl-verify-cost/benches   the block-connect cost bench.
#
# Comment lines are not code: a doc may cite either name.
#
# Rule 47, both ways:
#
#   - every allowed path exists and matches at least once. An allowance
#     that matches nothing is a door nobody uses and nobody watches; a
#     renamed directory would otherwise leave the list naming nothing.
#     Red edit: add `rust/shekyl-pow-randomx/tests` to ALLOWED (no test
#     there derives a cache), or rename an allowed directory.
#   - a match anywhere else fails, naming the file and line. Red edit: add
#     `let _cache = shekyl_pow_randomx::PreparedCache::derive(seed);` to
#     any file under rust/shekyl-chain-ingest/src.
#
# Exits (rule 46): rg's status is read outside the substitution, and a
# scan error is a failure, never "no hit".

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

fail() {
  echo "FAIL: check_randomx_cache_owner: $*" >&2
  exit 1
}

command -v rg >/dev/null 2>&1 \
  || fail "ripgrep (rg) not found: the gate cannot enforce its contract"

ALLOWED=(
  "rust/shekyl-hasher/src"
  "rust/shekyl-pow-randomx/src"
  "rust/shekyl-pow-randomx/benches"
  "rust/shekyl-pow-randomx/examples"
  "rust/shekyl-randomx-differential"
  "rust/shekyl-verify-cost/benches"
)

PATTERN='PreparedCache::derive|Arc<PreparedCache>'

# Subject: the two names exist where they are defined. A rename of either
# would leave the pattern matching nothing, and every scan below green.
rg -q 'pub fn derive\(' rust/shekyl-pow-randomx/src/prepared_cache.rs \
  || fail "PreparedCache::derive is not defined in rust/shekyl-pow-randomx/src/prepared_cache.rs: the pattern names nothing; re-anchor this gate"
rg -q 'pub struct PreparedCache' rust/shekyl-pow-randomx/src/prepared_cache.rs \
  || fail "PreparedCache is not defined in rust/shekyl-pow-randomx/src/prepared_cache.rs: re-anchor this gate"

# Every match in Rust code under rust/, comment lines dropped. The vendored
# tree and the build output are not first-party code.
rc=0
hits="$(rg -n --no-heading -g '*.rs' -g '!rust/target/**' -g '!rust/shekyl-oxide/**' \
  -e "$PATTERN" rust)" || rc=$?
if (( rc > 1 )); then
  fail "rg exited ${rc} scanning rust/"
fi
code_hits="$(printf '%s\n' "$hits" | awk -F: '
  NF >= 3 {
    line = $0
    sub(/^[^:]*:[^:]*:/, "", line)
    if (line ~ /^[[:space:]]*\/\//) next
    print $0
  }')"

[[ -n "$code_hits" ]] \
  || fail "no use of PreparedCache::derive or Arc<PreparedCache> anywhere under rust/: the scan read nothing"

# Each allowed path exists and has a match.
for allowed in "${ALLOWED[@]}"; do
  [[ -d "$allowed" ]] \
    || fail "allowed path ${allowed} does not exist: the allowance names nothing; update ALLOWED"
  printf '%s\n' "$code_hits" | grep -q "^${allowed}/" \
    || fail "allowed path ${allowed} holds no use of PreparedCache::derive or Arc<PreparedCache>: remove it from ALLOWED"
done

# Every match is under an allowed path.
outside="$code_hits"
for allowed in "${ALLOWED[@]}"; do
  outside="$(printf '%s\n' "$outside" | grep -v "^${allowed}/" || true)"
done
if [[ -n "$outside" ]]; then
  echo "FAIL: check_randomx_cache_owner: a RandomX cache is built or held outside its owner:" >&2
  printf '%s\n' "$outside" >&2
  echo "Hash through a shekyl-hasher job instead (Hasher::run, lend or lend_warm); see docs/design/RANDOMX_CACHE_ACTOR.md §5.3." >&2
  exit 1
fi

echo "OK: PreparedCache::derive and Arc<PreparedCache> are used only under: ${ALLOWED[*]}"
