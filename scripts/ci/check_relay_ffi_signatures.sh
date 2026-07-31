#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Relay-FFI signature gate: the hand-written C++ declarations in
# src/shekyl/shekyl_ffi.h must agree with the Rust definitions in
# rust/shekyl-ffi/src/relay_zone_ffi/mod.rs — checked by generating a
# declarations-only header from the Rust source (cbindgen) and compiling it
# into one TU with the hand-written header, where any disagreement is a
# conflicting-declaration compile error. See relay_ffi_signature_gate.cpp
# for the full mechanism note and the negative controls run at introduction.
#
# Scope: the relay surface only, deliberately. Full-surface generation is
# blocked on a named cbindgen limitation (cross-crate constant re-exports
# render as unresolved identifiers — the account/PQ surface); the relay
# module defines every crossing type in-file, so single-file generation is
# exact. The FOLLOWUPS entry tracks the full-surface extension.
#
# Pin source of truth: CBINDGEN_PIN below. Workflows install via
#   cargo install cbindgen --version "$(scripts/ci/check_relay_ffi_signatures.sh --print-pin)" --locked

set -euo pipefail

cd "$(dirname "$0")/../.."

CBINDGEN_PIN="0.29.4"

if [ "${1:-}" = "--print-pin" ]; then
  echo "${CBINDGEN_PIN}"
  exit 0
fi

if ! command -v cbindgen >/dev/null 2>&1; then
  echo "error: cbindgen not found. Install with:" >&2
  echo "  cargo install cbindgen --version ${CBINDGEN_PIN} --locked" >&2
  exit 2
fi

have="$(cbindgen --version | awk '{print $2}')"
if [ "${have}" != "${CBINDGEN_PIN}" ]; then
  # Generation output can differ across cbindgen versions. CI installs the
  # pin from --print-pin; a local mismatch is a hard error under CI=true so
  # the job cannot silently compare against a different generator.
  if [ -n "${CI:-}" ]; then
    echo "error: cbindgen ${have} != pinned ${CBINDGEN_PIN}" >&2
    exit 2
  fi
  echo "warning: cbindgen ${have} != pinned ${CBINDGEN_PIN}; CI uses the pin" >&2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

cbindgen \
  --config scripts/ci/cbindgen-relay-signatures.toml \
  --output "${workdir}/shekyl_ffi_generated_relay.h" \
  rust/shekyl-ffi/src/relay_zone_ffi/mod.rs 2>"${workdir}/cbindgen.log" \
  || { cat "${workdir}/cbindgen.log" >&2; exit 1; }

# Three-way completeness: Rust export count == generated count == handwritten
# header count. Intersection-only conflicting-declaration checks miss a
# handwritten header that simply omits an export (generated redeclares it
# alone; the compile still passes). The gen-side half also closes the
# sealed-empty-gate mode. Comment lines are stripped from the generated and
# handwritten sides because rustdoc/header comments mention export names;
# declarations are matched at the call-parenthesis so pointer-returning
# exports (`RelayZoneHandle *shekyl_relay_zone_new(`) count the same as
# space-preceded ones — the whitespace-anchored first draft of this check
# under-counted by exactly that one export, caught by this guard's first run.
#
# `grep -c` exits 1 on zero matches; under pipefail that would abort before
# the comparison message. `|| true` keeps the count as the signal.
exports_in_rust="$(grep -cE 'pub (unsafe )?extern "C" fn shekyl_relay_zone_' rust/shekyl-ffi/src/relay_zone_ffi/mod.rs || true)"
exports_in_gen="$(grep -v '^\s*//' "${workdir}/shekyl_ffi_generated_relay.h" | grep -cE '(^|[ *(])shekyl_relay_zone_[a-z_]+\(' || true)"
exports_in_header="$(grep -v '^\s*//' src/shekyl/shekyl_ffi.h | grep -cE '(^|[ *(])shekyl_relay_zone_[a-z_]+\(' || true)"

if [ "${exports_in_rust}" -eq 0 ]; then
  echo "error: Rust module defines 0 shekyl_relay_zone_ exports — count pattern is wrong or the surface moved" >&2
  exit 1
fi
if [ "${exports_in_gen}" -ne "${exports_in_rust}" ] || [ "${exports_in_header}" -ne "${exports_in_rust}" ]; then
  echo "error: relay export counts disagree — Rust=${exports_in_rust} generated=${exports_in_gen} handwritten=${exports_in_header}" >&2
  echo "       (all three must match; partial generation or a missing/extra header declaration under-checks)" >&2
  exit 1
fi

g++ -fsyntax-only -std=c++17 -I "${workdir}" -I src scripts/ci/relay_ffi_signature_gate.cpp

echo "relay FFI signatures: hand-written header agrees with the Rust definitions (${exports_in_rust} exports checked)"
