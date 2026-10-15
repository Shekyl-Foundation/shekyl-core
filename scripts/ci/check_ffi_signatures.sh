#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# FFI signature gate: the hand-written C++ declarations in
# src/shekyl/shekyl_ffi.h must agree with the Rust definitions they name.
# For each gated Rust source file, a declarations-only header is generated
# from the Rust source (cbindgen) and compiled into one TU with the
# hand-written header, where any disagreement is a conflicting-declaration
# compile error. See ffi_signature_gate.cpp for the full mechanism note and
# the negative controls run at introduction.
#
# Two directions. Signatures are compared for the files in SURFACES. And
# every function the header declares anywhere must be a Rust export, so a
# declaration cannot outlive the function it names.
#
# Signature scope: the files in SURFACES below, deliberately. Full-surface generation
# is blocked on a named cbindgen limitation (cross-crate constant re-exports
# render as unresolved identifiers — the account/PQ surface). A file is
# gateable when every type crossing the boundary is defined in-file or is
# only referenced through a pointer (it then generates as an opaque forward
# declaration, which redeclares legally). The FOLLOWUPS entry tracks the
# full-surface extension. A file whose C ABI changes joins SURFACES in the
# change that changes it (rule 40).
#
# Pin source of truth: CBINDGEN_PIN below. Workflows install via
#   cargo install cbindgen --version "$(scripts/ci/check_ffi_signatures.sh --print-pin)" --locked

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

# name:path — one gated Rust source file each. The name is the generated
# header's suffix, which ffi_signature_gate.cpp includes.
SURFACES=(
  "relay:rust/shekyl-ffi/src/relay_zone_ffi/mod.rs"
  "rpc_peerlist:rust/shekyl-ffi/src/rpc_peerlist_ffi.rs"
  "close_cause:rust/shekyl-ffi/src/close_cause_ffi.rs"
  # The daemon's entry types and the snapshot field-count export
  # (DAEMON_CONFIG_CUTOVER.md §2.9); the C++ reads the snapshot these define.
  "daemon_entry:rust/shekyl-daemon/src/entry.rs"
  "tx_extra_codec:rust/shekyl-ffi/src/tx_extra_codec_ffi.rs"
)

# The hand-written header with comment lines removed: rustdoc and header
# comments mention export names.
header_decls="$(grep -v '^\s*//' src/shekyl/shekyl_ffi.h)"
total=0

for surface in "${SURFACES[@]}"; do
  name="${surface%%:*}"
  source="${surface#*:}"
  generated="${workdir}/shekyl_ffi_generated_${name}.h"

  cbindgen \
    --config scripts/ci/cbindgen-ffi-signatures.toml \
    --output "${generated}" \
    "${source}" 2>"${workdir}/cbindgen.log" \
    || { cat "${workdir}/cbindgen.log" >&2; exit 1; }

  # Completeness, by name: every export the Rust file defines must be
  # declared in the generated header and in the hand-written one. The
  # compile below only compares declarations both headers carry, so a
  # hand-written header that omits an export would pass it alone, and so
  # would a generation that silently produced nothing (the sealed-empty
  # gate). Declarations are matched at the call parenthesis so a
  # pointer-returning export (`T *shekyl_x(`) is found like any other; the
  # name class carries digits because export names do.
  #
  # `grep` exits 1 on no match; under pipefail that would abort before the
  # message. `|| true` keeps the empty result as the signal.
  exports="$(grep -oE 'pub (unsafe )?extern "C" fn shekyl_[a-z0-9_]+' "${source}" | awk '{print $NF}' | sort -u || true)"
  if [ -z "${exports}" ]; then
    echo "error: ${source} defines no shekyl_ export — the pattern is wrong or the surface moved" >&2
    exit 1
  fi
  generated_decls="$(grep -v '^\s*//' "${generated}")"
  for export in ${exports}; do
    if ! grep -qE "(^|[ *(])${export}\(" <<<"${generated_decls}"; then
      echo "error: ${export} (${source}) is missing from the generated header — partial generation under-checks" >&2
      exit 1
    fi
    if ! grep -qE "(^|[ *(])${export}\(" <<<"${header_decls}"; then
      echo "error: ${export} (${source}) has no declaration in src/shekyl/shekyl_ffi.h" >&2
      exit 1
    fi
    total=$((total + 1))
  done
done

# The other direction: every function the header declares must be exported
# by Rust somewhere. The loop above walks Rust -> header, so a declaration
# left behind when its export was removed or renamed is invisible to it (the
# generated header simply omits the name and the compile compares nothing).
# This walks header -> Rust over the WHOLE header, not per surface: a stale
# declaration is wrong whichever file its export lived in, and no manifest
# of which declaration belongs to which file has to be kept in step.
all_exports="$(grep -rhoE 'extern "C" fn shekyl_[a-z0-9_]+' rust --include='*.rs' --exclude-dir=target | awk '{print $NF}' | sort -u)"
declared="$(grep -oE '(^|[ *(])shekyl_[a-z0-9_]+\(' <<<"${header_decls}" | grep -oE 'shekyl_[a-z0-9_]+' | sort -u)"
if [ -z "${all_exports}" ] || [ -z "${declared}" ]; then
  echo "error: found no Rust exports or no header declarations — a pattern is wrong" >&2
  exit 1
fi
stale="$(comm -23 <(echo "${declared}") <(echo "${all_exports}"))"
if [ -n "${stale}" ]; then
  echo "error: src/shekyl/shekyl_ffi.h declares functions no Rust source exports:" >&2
  echo "${stale}" | sed 's/^/  /' >&2
  exit 1
fi

g++ -fsyntax-only -std=c++17 -I "${workdir}" -I src scripts/ci/ffi_signature_gate.cpp

echo "FFI signatures: hand-written header agrees with the Rust definitions (${total} exports over ${#SURFACES[@]} files checked; $(wc -l <<<"${declared}") declarations all exported)"
