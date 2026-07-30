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

set -euo pipefail

cd "$(dirname "$0")/../.."

CBINDGEN_PIN="0.29.4"

if ! command -v cbindgen >/dev/null 2>&1; then
  echo "error: cbindgen not found. Install with:" >&2
  echo "  cargo install cbindgen --version ${CBINDGEN_PIN} --locked" >&2
  exit 2
fi

have="$(cbindgen --version | awk '{print $2}')"
if [ "${have}" != "${CBINDGEN_PIN}" ]; then
  # Generation output can differ across cbindgen versions; CI pins the
  # install, so a local mismatch is a warning rather than a failure.
  echo "warning: cbindgen ${have} != pinned ${CBINDGEN_PIN}; CI uses the pin" >&2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

cbindgen \
  --config scripts/ci/cbindgen-relay-signatures.toml \
  --output "${workdir}/shekyl_ffi_generated_relay.h" \
  rust/shekyl-ffi/src/relay_zone_ffi/mod.rs 2>"${workdir}/cbindgen.log" \
  || { cat "${workdir}/cbindgen.log" >&2; exit 1; }

# The generated header must actually cover the surface: an empty or partial
# generation passing the compile would be the sealed-empty-gate failure mode.
# Comment lines are stripped from the generated side because cbindgen copies
# rustdoc comments, which mention export names; declarations are matched at
# the call-parenthesis so pointer-returning exports (`RelayZoneHandle
# *shekyl_relay_zone_new(`) count the same as space-preceded ones — the
# whitespace-anchored first draft of this check under-counted by exactly
# that one export, caught by this guard's own first run.
exports_in_rust="$(grep -cE 'pub (unsafe )?extern "C" fn shekyl_relay_zone_' rust/shekyl-ffi/src/relay_zone_ffi/mod.rs)"
exports_in_gen="$(grep -v '^\s*//' "${workdir}/shekyl_ffi_generated_relay.h" | grep -cE '(^|[ *(])shekyl_relay_zone_[a-z_]+\(')"
if [ "${exports_in_gen}" -lt "${exports_in_rust}" ]; then
  echo "error: generated header covers ${exports_in_gen} exports but the Rust module defines ${exports_in_rust} — generation is partial, the compile below would under-check" >&2
  exit 1
fi

g++ -fsyntax-only -std=c++17 -I "${workdir}" -I src scripts/ci/relay_ffi_signature_gate.cpp

echo "relay FFI signatures: hand-written header agrees with the Rust definitions (${exports_in_rust} exports checked)"
