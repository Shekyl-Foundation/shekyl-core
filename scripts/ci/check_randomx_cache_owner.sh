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
# a job on that hasher and holds no cache, so the cap is the memory. Naming
# `PreparedCache` outside the allowed paths is a cache the cap does not
# count, whichever way it is spelled: a field, a path-qualified `Arc`, or
# `PreparedCache::derive`. `CacheStore` was deleted and may not return in
# Rust code at all, including those paths.
#
# The gate: the identifier `PreparedCache` appears in Rust code only under
# the paths in ALLOWED:
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
#     `let _cache: shekyl_pow_randomx::PreparedCache;` to any file under
#     rust/shekyl-chain-ingest/src. An `Arc<shekyl_pow_randomx::PreparedCache>`
#     is the same failure: the identifier, not one spelling of it.
#   - `CacheStore` in any Rust file fails, allowed paths included. Red
#     edit: add `struct CacheStore;` under rust/shekyl-hasher/src.
#
# Exits (rule 46): rg's status is read outside the substitution, and a
# scan error is a failure, never "no hit". A match is `grep -q` on a
# here-string, never a pipe: under pipefail an early `grep -q` SIGPIPEs
# its producer and a real match reads as failure once the hit list
# outgrows the pipe buffer.

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

# The type, not one way of constructing or holding it. A path-qualified
# `Arc<shekyl_pow_randomx::PreparedCache>` and a field `cache: PreparedCache`
# are the same use as `PreparedCache::derive`.
PATTERN='\bPreparedCache\b'
# The deleted store. No path is allowed to grow it back.
DELETED='\bCacheStore\b'

# Subject: the two names exist where they are defined. A rename of either
# would leave the pattern matching nothing, and every scan below green.
rg -q 'pub fn derive\(' rust/shekyl-pow-randomx/src/prepared_cache.rs \
  || fail "PreparedCache::derive is not defined in rust/shekyl-pow-randomx/src/prepared_cache.rs: the pattern names nothing; re-anchor this gate"
rg -q 'pub struct PreparedCache' rust/shekyl-pow-randomx/src/prepared_cache.rs \
  || fail "PreparedCache is not defined in rust/shekyl-pow-randomx/src/prepared_cache.rs: re-anchor this gate"

# Full-line comments are not code: a doc may cite the name. A block
# comment is code, so a citation hidden in one fails closed.
strip_comments() {
  awk -F: '
    NF >= 3 {
      line = $0
      sub(/^[^:]*:[^:]*:/, "", line)
      if (line ~ /^[[:space:]]*\/\//) next
      print $0
    }'
}

# rg over rust/. Status is the substitution's, read on the next line:
# exit 1 is no hit, above 1 is a scan error. The vendored tree and the
# build output are not first-party code.
scan() {
  local pattern="$1"
  local rc=0
  local hits
  hits="$(rg -n --no-heading -g '*.rs' -g '!rust/target/**' -g '!rust/shekyl-oxide/**' \
    -e "$pattern" rust)" || rc=$?
  if (( rc > 1 )); then
    fail "rg exited ${rc} scanning rust/ for ${pattern}"
  fi
  printf '%s\n' "$hits" | strip_comments
}

code_hits="$(scan "$PATTERN")"
[[ -n "$code_hits" ]] \
  || fail "no use of PreparedCache anywhere under rust/: the scan read nothing"

# Each allowed path exists and has a match. The hit list is already in
# memory; grep reads it from a here-string, so a match cannot SIGPIPE
# the producer (rule 46).
for allowed in "${ALLOWED[@]}"; do
  [[ -d "$allowed" ]] \
    || fail "allowed path ${allowed} does not exist: the allowance names nothing; update ALLOWED"
  grep -q "^${allowed}/" <<<"$code_hits" \
    || fail "allowed path ${allowed} holds no use of PreparedCache: remove it from ALLOWED"
done

# Every match is under an allowed path. The filter is a read of the
# captured list, not a pipe whose empty result could be a grep error.
outside=""
while IFS= read -r hit || [[ -n "$hit" ]]; do
  [[ -z "$hit" ]] && continue
  kept=1
  for allowed in "${ALLOWED[@]}"; do
    if [[ "$hit" == "$allowed/"* ]]; then
      kept=0
      break
    fi
  done
  if (( kept )); then
    outside+="${hit}"$'\n'
  fi
done <<<"$code_hits"
if [[ -n "$outside" ]]; then
  echo "FAIL: check_randomx_cache_owner: a RandomX cache is built or held outside its owner:" >&2
  printf '%s\n' "$outside" >&2
  echo "Hash through a shekyl-hasher job instead (Hasher::run, lend or lend_warm); see docs/design/RANDOMX_CACHE_ACTOR.md §5.3." >&2
  exit 1
fi

# The store is gone. A hit in an allowed path is still the type coming back.
deleted="$(scan "$DELETED")"
if [[ -n "$deleted" ]]; then
  echo "FAIL: check_randomx_cache_owner: CacheStore was deleted and may not return:" >&2
  printf '%s\n' "$deleted" >&2
  echo "A cache is a job on shekyl-hasher, not a store. See docs/design/RANDOMX_CACHE_ACTOR.md §7." >&2
  exit 1
fi

echo "OK: PreparedCache is used only under: ${ALLOWED[*]}; CacheStore is absent"
