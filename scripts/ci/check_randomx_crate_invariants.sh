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
# (rejected via column-0 anchor; in-fn `use` is indented per rustfmt).
# Permitted exception: NONE.
#
# The single-line regex below matches a column-0 import (with
# optional `pub` / `pub(crate)` / `pub(super)` / `pub(in path)`
# prefix, mirroring Pattern B's prefix coverage) whose right-hand
# side mentions any of the banned identifiers *on the same line*.
# This catches:
#
#   - `use std::sync::OnceLock;`
#   - `use std::sync::OnceLock as Foo;`
#   - `pub use std::sync::OnceLock;`
#   - `pub(crate) use std::sync::OnceLock;`
#   - `use std::sync::{OnceLock, Mutex};` (single-line grouped form)
#   - `use once_cell::sync::Lazy;`
#   - `use lazy_static::lazy_static;`
#   - `lazy_static! { ... }` (column-0 macro invocation)
#
# It does *not*, on its own, catch the rustfmt-default multi-line
# grouped form (PR #72 Copilot finding NF7), where the `use` opener
# carries no banned identifier and the indented identifier lines
# fail the column-0 anchor:
#
#   use std::sync::{
#       Mutex,
#       OnceLock,    // <-- bypasses the single-line regex
#   };
#
# The bypass is closed by a per-file POSIX awk scanner below
# (`SCAN_USE_BLOCKS_AWK`), which accumulates any column-0 `use`
# statement that opens an unclosed brace block until the matching
# closing brace is seen, then scans the accumulated buffer for the
# same banned tokens. The awk scanner and the single-line regex
# together cover both grouping styles.
#
# False-positive surface (banned identifier as a substring of an
# unrelated path component) is bounded: the banned tokens
# `once_cell` / `lazy_static` / `OnceLock` / `LazyLock` are
# reserved-style library names that don't recur in unrelated Rust
# paths. A future false positive is caught at the gate-fire and
# resolved by tightening the regex; the failure mode is loud, not
# silent.
PATTERN_RUNTIME_STATE='^(pub(\([^)]+\))?[[:space:]]+)?use[[:space:]]+.*(once_cell|lazy_static|OnceLock|LazyLock)|^lazy_static!'

# Multi-line bypass closure for Pattern A (PR #72 NF7). Per-file
# POSIX awk scanner: when a column-0 `use` line opens an unclosed
# brace block, accumulate subsequent lines (tracking nested braces
# via balanced `{`/`}` counts so `use foo::{bar::{baz, OnceLock}}`
# spread across lines is handled correctly) until depth returns to
# zero, then scan the accumulated buffer for the same banned
# tokens as the single-line regex. The two arms (single-line grep
# regex above, multi-line awk scanner here) jointly enforce the
# Pattern A invariant regardless of import-formatting style.
RUNTIME_STATE_TOKENS='(once_cell|lazy_static|OnceLock|LazyLock)'
SCAN_USE_BLOCKS_AWK='
  function count_open(s,    tmp) { tmp = s; return gsub(/\{/, "&", tmp) }
  function count_close(s,    tmp) { tmp = s; return gsub(/\}/, "&", tmp) }
  /^(pub(\([^)]+\))?[[:space:]]+)?use[[:space:]]+.*\{[^}]*$/ {
    start = NR
    buf = $0
    depth = count_open($0) - count_close($0)
    while (depth > 0 && (getline line) > 0) {
      buf = buf " " line
      depth += count_open(line) - count_close(line)
    }
    if (buf ~ tokens) {
      print FILENAME ":" start ":" buf
    }
  }
'

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
#
# The `extern "C" fn` arm allows an optional `pub` / `pub(crate)` /
# `pub(super)` / `pub(in path)` visibility prefix and an optional
# `unsafe` keyword before `extern`, mirroring Pattern A's prefix
# coverage. This catches the export-intent shape independent of
# whether `#[no_mangle]` is currently present:
#
#   - `extern "C" fn foo() {}`
#   - `pub extern "C" fn foo() {}`
#   - `pub(crate) extern "C" fn foo() {}`
#   - `unsafe extern "C" fn foo() {}`
#   - `pub unsafe extern "C" fn foo() {}`
#
# The shape gate is independent of the `#[no_mangle]` /
# `#[export_name(...)]` arms above: a future contributor adding
# `pub extern "C" fn` (Rust-mangled, not actually C-callable) and
# later attaching `#[no_mangle]` would have the shape arm fire on
# the first commit rather than only the second, closing the door on
# stepwise FFI-export drift.
PATTERN_FFI_EXPORT='^[[:space:]]*(#\[no_mangle\]|#\[unsafe\(no_mangle\)\]|#\[export_name|#\[unsafe\(export_name|(pub(\([^)]+\))?[[:space:]]+)?(unsafe[[:space:]]+)?extern[[:space:]]+"C"[[:space:]]+fn[[:space:]])'

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

# Multi-line bypass closure for Pattern A: per-file awk pass over
# every `.rs` source under `${CRATE_SRC}`. See SCAN_USE_BLOCKS_AWK
# definition above for the rationale and PR #72 NF7 reference.
while IFS= read -r f; do
  HITS_MULTI="$(awk -v tokens="${RUNTIME_STATE_TOKENS}" "${SCAN_USE_BLOCKS_AWK}" "${f}")"
  if [[ -n "${HITS_MULTI}" ]]; then
    echo "FATAL: PATTERN_RUNTIME_STATE matched multi-line use block in ${CRATE_SRC}:" >&2
    echo "${HITS_MULTI}" >&2
    failures=$((failures + 1))
  fi
done < <(find "${CRATE_SRC}" -name '*.rs' -type f)

if [[ ${failures} -ne 0 ]]; then
  exit 1
fi

echo "RandomX crate-invariant grep clean."
