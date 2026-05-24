#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Per `docs/design/RANDOMX_V2_PHASE2F_PLAN.md` §3.6 R1-E1:
# enforce the three crate-level isolation invariants for
# `rust/shekyl-pow-randomx/`. Modeled on
# `scripts/ci/check_randomx_fpu_rounding.sh` shape: `set -euo
# pipefail` preamble, fixed-pattern grep with zero-hit assertion,
# exit non-zero on any match with line-number output to stderr.
#
# Pattern A bans runtime-mutable lazy-state types from being
# imported at non-test module scope. The crate's threat model
# (`RANDOMX_V2_RUST.md` §7.2) forbids module-level mutable state;
# the import-level ban is stricter and eliminates the disambiguation
# between module-level and function-local usage by rejecting the
# import outright.
#
# Pattern B bans module-level `static` items (whether `static FOO`
# or `static mut FOO`). Robustness chain (§3.6 Round 3): the
# column-0 anchoring relies on `cargo fmt --check` enforcing
# column-0 for module-level items. rustfmt's default style places
# module-level items at column 0; function-local items (including
# function-local `static REGEX: OnceLock<...> = ...;` declarations
# inside `fn` bodies) are indented to at least column 4. Pattern B
# matches column-0 `static` items and does not match function-local
# items. If a future PR weakens the formatting gate's coverage on
# this crate, the column-0 heuristic weakens correspondingly; the
# mitigation is to re-anchor Pattern B against rustfmt's invariants
# at the time of that change.
#
# Pattern C bans FFI exports from this crate. All C-ABI exports
# live in `shekyl-ffi` (Phase 2F Decision #5). The pattern matches
# *exporters* (`#[no_mangle]` / `#[unsafe(no_mangle)]` /
# `#[export_name(...)]` / `#[unsafe(export_name(...))]` /
# `extern "C" fn ...` definition form). An `extern "C" { fn foo(); }`
# *import* block consuming an FFI surface is not matched (no `fn`
# token after `"C"` in the inline form). The leading `^[[:space:]]*`
# anchor ensures rustdoc citations in `lib.rs` (lines that begin
# with `//!` not whitespace + the attribute or extern-fn token) do
# not match.

set -euo pipefail

CRATE_SRC="rust/shekyl-pow-randomx/src"

if [[ ! -d "${CRATE_SRC}" ]]; then
  echo "FATAL: ${CRATE_SRC} not found" >&2
  exit 1
fi

# Pattern A: ban runtime-mutable lazy-state imports at module scope
# (rejected via column-0 `^use ` anchor; in-fn `use` is indented).
# Permitted exception: NONE.
PATTERN_RUNTIME_STATE='^use[[:space:]]+(once_cell|lazy_static)|^use[[:space:]]+std::sync::(OnceLock|LazyLock)|^use[[:space:]]+core::sync::(OnceLock|LazyLock)|^lazy_static!'

# Pattern B: ban module-level `static` items (mut or otherwise).
# Function-local statics are inside fn bodies (indented per rustfmt);
# column-0 `static` is by definition module-level.
# Permitted exception: `const` items (different keyword; not
# matched).
PATTERN_MODULE_STATIC='^(pub(\([^)]+\))?[[:space:]]+)?(unsafe[[:space:]]+)?static[[:space:]]+'

# Pattern C: ban FFI exports from this crate. All C-ABI exports
# live in `shekyl-ffi` (Phase 2F Decision #5).
# Permitted exception: NONE. An `extern "C" { fn foo(); }` *import*
# block consuming an FFI surface is not matched (this pattern
# requires `extern "C" fn` definition form, with `fn` after `"C"`).
PATTERN_FFI_EXPORT='^[[:space:]]*(#\[no_mangle\]|#\[unsafe\(no_mangle\)\]|#\[export_name|#\[unsafe\(export_name|extern[[:space:]]+"C"[[:space:]]+fn[[:space:]])'

failures=0

for pat_name in PATTERN_RUNTIME_STATE PATTERN_MODULE_STATIC PATTERN_FFI_EXPORT; do
  pat="${!pat_name}"
  HITS="$(grep -rEn "${pat}" "${CRATE_SRC}" || true)"
  if [[ -n "${HITS}" ]]; then
    echo "FATAL: ${pat_name} matched in ${CRATE_SRC}:" >&2
    echo "${HITS}" >&2
    failures=$((failures + 1))
  fi
done

if [[ ${failures} -ne 0 ]]; then
  exit 1
fi

echo "RandomX crate-invariant grep clean."
