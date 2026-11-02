#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Binary-level symbol-isolation gate on the linked `shekyld` daemon.
# Usage: check_randomx_symbol_isolation.sh <path-to-shekyld>
#
# Six checks, each anchored to a behavior that must not change
# silently (no filesystem/convention checks — every check reads the
# actual linked binary):
#
#   1. None of the RandomX v2 C library's 10 C-ABI entry points
#      (`docs/design/RANDOMX_V2_RUST.md` §7.1 explicit list — NOT a
#      `randomx_*` glob, per §7.1's own caveat that Rust-internal
#      symbols may contain "randomx" without linking the C library)
#      appears in the daemon. Fires if the vendored C library (v1 or
#      v2) is ever re-linked into consensus verification.
#   2. No deleted CryptoNote DAA symbol (`cryptonote::next_difficulty`
#      family) appears. This is the binary-level strengthening of the
#      consensus-invariants source grep (invariant 1 of
#      check_consensus_invariants.sh); the source-level FOLLOWUPS
#      disposition sketched an unmangled-name grep, which can never
#      match a C++-mangled symbol — this check demangles first.
#   3. A `shekyl_pow_randomx` substring IS present. The C-ABI export
#      (`shekyl_pow_randomx_v2_hash`) is a one-line wrapper the linker
#      may inline under LTO (Ubuntu 24.04 / gcc 14); the crate's
#      rust-mangled symbols still carry the substring. Guards against
#      the inverse failure: a daemon that silently dropped the Rust
#      verifier (and also proves this script is looking at a binary
#      that actually embeds the verifier — on a shared-library build
#      the verifier lives in a .so and every presence check here would
#      fail loudly instead of passing vacuously).
#   4. `aes`-crate symbols (`_ZN3aes`) are present — the expected
#      disposition recorded when Phase 2b added aes-0.9.0: the crate's
#      Rust-mangled internals are visible in a verifier-linked static
#      daemon. Empirically verified against a Release build at the
#      wiring PR (9 matches).
#   5. `cn_slow_hash` and the unprefixed `slow_hash_{allocate,free}_state`
#      C ABI are absent. Phase 4 deleted CryptoNight; a reappearance
#      means slow-hash.c was re-linked. The daemon called the unprefixed
#      names (miner.cpp / blockchain.cpp), not `cn_slow_hash_allocate_state`.
#   6. The pinned PoW test setter is absent from the linked daemon, and
#      the deleted schema-level names stay deleted. Source containment
#      of `cryptonote::set_pow_hash_override_for_tests` is
#      scripts/ci/check_pow_test_seam.sh. This is the binary counterpart:
#      -ffunction-sections/--gc-sections must drop that setter, so its
#      PRESENCE means a production object referenced it or gc-sections
#      fell off. Exact names, same dialect as checks 1/2/5 — a glob
#      cannot catch an arbitrarily renamed seam, and this check does
#      not claim to. A new setter is a new name added here and in
#      check_pow_test_seam.sh together. The former presence anchors
#      (`cryptonote::hash_pow_randomx`, `s_pow_hash_override_for_tests`)
#      left with the seam; checks 3 and 4 are the remaining anchors that
#      make this absence falsifiable.
#
# Checks 3 and 4 make 1, 2, 5 and 6 falsifiable: a stripped binary or a
# wrong path cannot pass all six.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path-to-shekyld>" >&2
  exit 2
fi
BIN="$1"

if [ ! -f "$BIN" ]; then
  echo "FATAL: '$BIN' does not exist (build the 'daemon' target first)" >&2
  exit 2
fi

# Whole-symbol-table dumps, computed once. `nm` without -g includes
# local (t/d) symbols: Rust staticlib internals are local after the
# final link. `--demangle` for check 2's C++ names.
SYMS="$(nm "$BIN" 2>/dev/null || true)"
SYMS_DEMANGLED="$(nm --demangle "$BIN" 2>/dev/null || true)"

if [ -z "$SYMS" ]; then
  echo "FATAL: nm produced no symbols for '$BIN' (stripped binary or wrong file)" >&2
  exit 1
fi
# Check 2 greps the demangled table; if the demangle invocation yielded
# nothing (non-GNU nm, demangler failure) that check would pass vacuously
# while checks 1/3/4 still pass on the populated $SYMS.
if [ -z "$SYMS_DEMANGLED" ]; then
  echo "FATAL: nm --demangle produced no symbols for '$BIN'" >&2
  exit 1
fi

fail=0

# --- Check 1: banned RandomX C-ABI entry points (§7.1 explicit list) ---
BANNED_RANDOMX='randomx_alloc_cache|randomx_alloc_dataset|randomx_create_vm|randomx_init_cache|randomx_init_dataset|randomx_destroy_vm|randomx_vm_set_cache|randomx_calculate_hash|randomx_dataset_item_count|randomx_get_flags'
# [[:space:]] rather than a literal space before the symbol name: GNU nm
# separates columns with single spaces, but tab-separating nm variants
# exist, and a missed banned symbol here would pass vacuously.
if matches="$(printf '%s\n' "$SYMS" | grep -E "[[:space:]](${BANNED_RANDOMX})$")"; then
  echo "FAIL: RandomX C library symbols present in daemon (RANDOMX_V2_RUST.md §7.1):" >&2
  printf '%s\n' "$matches" >&2
  fail=1
else
  echo "OK: no banned RandomX C-ABI symbol in daemon (10-symbol §7.1 list)"
fi

# --- Check 2: deleted CryptoNote DAA symbols (demangled) ---
if matches="$(printf '%s\n' "$SYMS_DEMANGLED" | grep -E 'cryptonote::next_difficulty(_64)?\(')"; then
  echo "FAIL: deleted DAA symbol present in daemon:" >&2
  printf '%s\n' "$matches" >&2
  fail=1
else
  echo "OK: no deleted CryptoNote DAA symbol (next_difficulty family)"
fi

# --- Check 3: Rust verifier symbols present ---
# No `grep -q` on these presence checks: -q exits at the first match and
# SIGPIPEs the upstream printf on a large symbol table, which under
# `pipefail` turns a FOUND symbol into a failed pipeline (observed on the
# 24k-line Release shekyld table). Plain grep >/dev/null reads the whole
# stream. Substring, not an end-anchored C ABI: LTO may inline
# `shekyl_pow_randomx_v2_hash` while the crate's mangled names remain.
if printf '%s\n' "$SYMS" | grep 'shekyl_pow_randomx' >/dev/null; then
  echo "OK: Rust verifier symbols (shekyl_pow_randomx) present"
else
  echo "FAIL: no shekyl_pow_randomx symbol in '$BIN'." >&2
  echo "  Either the daemon dropped the Rust verifier, or this is a" >&2
  echo "  shared-library build (the verifier lives in a .so). Run this" >&2
  echo "  check against a static Release build (the CI shape)." >&2
  fail=1
fi

# --- Check 4: aes-crate symbols present (expected disposition) ---
if printf '%s\n' "$SYMS" | grep '_ZN3aes' >/dev/null; then
  echo "OK: aes-crate symbols (_ZN3aes) present, per the recorded disposition"
else
  echo "FAIL: no aes-crate symbols found; the verifier's AES layer is" >&2
  echo "  expected to be visible in a static verifier-linked daemon." >&2
  fail=1
fi

# --- Check 5: CryptoNight slow-hash must not be linked into the daemon ---
# Phase 4 deleted cn_slow_hash (wallet2/RPC-payment callers are gone). A
# daemon that still exports the C ABI would mean the object file was
# re-linked. Presence of any of the three C symbols is the fail.
if matches="$(printf '%s\n' "$SYMS" | grep -E '[[:space:]](cn_slow_hash|cn_slow_hash_allocate_state|cn_slow_hash_free_state|slow_hash_allocate_state|slow_hash_free_state)$')"; then
  echo "FAIL: CryptoNight slow-hash symbol present in daemon:" >&2
  printf '%s\n' "$matches" >&2
  fail=1
else
  echo "OK: no cn_slow_hash family in daemon"
fi

# --- Check 6: pinned PoW test setter unreachable from production ---
# The seam's dispatch and slot left with the C++ override. Absence of the
# setter and of the deleted schema names is the remaining subject; checks
# 3 and 4 are the presence anchors that keep this from passing vacuously.
# Exact setter: function symbols only.
if matches="$(printf '%s\n' "$SYMS_DEMANGLED" | grep -E '[[:space:]][TtWw][[:space:]]cryptonote::set_pow_hash_override_for_tests\(')"; then
  echo "FAIL: PoW hash override setter reachable from production (survived --gc-sections):" >&2
  printf '%s\n' "$matches" >&2
  echo "  Production must never install a PoW hash override (CEN-D2)." >&2
  echo "  A production object references the seam, or the build lost" >&2
  echo "  -ffunction-sections/--gc-sections." >&2
  fail=1
else
  echo "OK: set_pow_hash_override_for_tests absent from daemon (link-time unreachable)"
fi
# Deleted schema-level names (same shape as check 5). Currently absent;
# the check exists so a re-link turns red, not because they are present.
if matches="$(printf '%s\n' "$SYMS_DEMANGLED" | grep -E 'IPowSchema|set_pow_schema_override_for_tests|get_pow_for_height')"; then
  echo "FAIL: deleted PoW-schema symbol present in daemon:" >&2
  printf '%s\n' "$matches" >&2
  fail=1
else
  echo "OK: no deleted PoW-schema symbol (IPowSchema / schema override / get_pow_for_height)"
fi

exit "$fail"
