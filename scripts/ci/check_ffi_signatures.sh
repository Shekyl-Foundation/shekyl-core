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
# Struct layouts are the second limb. A struct crossing the boundary is a
# definition, not a declaration, so the signature compile cannot compare
# it. Every struct the header defines is compared against its #[repr(C)]
# twin (LAYOUTS) or exempted with a reason (LAYOUT_EXEMPT); see
# ffi_layout_gate.cpp.
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

# Struct layouts. Rust=C, one pair per struct the header defines with a
# #[repr(C)] twin. ffi_layout_gate.py compares their member names in order
# and writes the size, alignment, offset and type asserts
# ffi_layout_gate.cpp compiles; see that file for the mechanism note and the
# negative controls.
LAYOUTS=(
  ShekylBuffer=ShekylBuffer
  ShekylPqcKeypair=ShekylPqcKeypair
  ShekylPqcSignatureResult=ShekylPqcSignatureResult
  ShekylPqcCanonicalLens=ShekylPqcCanonicalLens
  ShekylBurnSplit=ShekylBurnSplit
  ShekylEmissionSplit=ShekylEmissionSplit
  ShekylOutputData=ShekylOutputData
  ShekylPqcAuthResult=ShekylPqcAuthResult
  ShekylCurveTreeReplicaOutput=ShekylCurveTreeReplicaOutput
  ShekylCurveTreeReplicaTx=ShekylCurveTreeReplicaTx
  ShekylSignResult=ShekylSignResult
  ShekylArchivalVerifyCtx=shekyl_archival_verify_ctx
  ShekylArchivalPidPubkey=shekyl_archival_pid_pubkey
  ShekylArchivalAttestationVerifyCtx=shekyl_archival_attestation_verify_ctx
  ShekylArchivalShardCoverageIn=ShekylArchivalShardCoverageIn
  ShekylArchivalShardCoverageOut=ShekylArchivalShardCoverageOut
  ShekylArchivalEpochCloseBond=shekyl_archival_epoch_close_bond
  ShekylArchivalEpochCloseShard=shekyl_archival_epoch_close_shard
  ShekylArchivalCreditPair=shekyl_archival_credit_pair
  ShekylArchivalEmissionEpochSnapshot=shekyl_archival_emission_epoch_snapshot
  ShekylU128=shekyl_u128
  ShekylRelayBlob=ShekylRelayBlob
  ShekylInboundCeiling=shekyl_inbound_ceiling
  ShekylStemTallyRow=ShekylStemTallyRow
  ShekylSeamAddress=shekyl_seam_address
  ShekylSeamObserved=shekyl_seam_observed
  ShekylSeamOpenResult=shekyl_seam_open_result
  ShekylSeamBoardRow=shekyl_seam_board_row
  ShekylSeamSessionCounts=shekyl_seam_session_counts_t
  ShekylSeamHandshakeResult=shekyl_seam_handshake_result
  ShekylRpcPeerFacts=shekyl_rpc_peer_facts
  ShekylBanView=shekyl_ban_view
)

# Structs the header defines that the layout limb does not compare, each
# with its reason. ShekylOwnedBuffer is C++ only: an RAII owner of a
# ShekylBuffer, which never crosses. ShekylAllKeysBlob's array bounds are
# shekyl-crypto-pq constants that alias shekyl-address constants that alias
# further ones, the cross-crate limitation the FOLLOWUPS entry names; its
# Rust layout is pinned by the struct_layout_matches test in account_ffi.rs.
LAYOUT_EXEMPT=(ShekylOwnedBuffer ShekylAllKeysBlob)

# The files defining the constants LAYOUTS structs use as array bounds.
BOUNDS=(
  rust/shekyl-seam/src/endpoint.rs
  rust/shekyl-archival-retention/src/pass_anchor.rs
)

# Completeness, by name: every struct the header defines is compared or
# exempt. A struct added to the header without a LAYOUTS row would
# otherwise be checked by nothing.
defined="$(grep -oE '^\s*(typedef\s+)?struct\s+[A-Za-z0-9_]+\s*(\{.*)?$' src/shekyl/shekyl_ffi.h | grep -oE 'struct\s+[A-Za-z0-9_]+' | awk '{print $2}' | sort -u || true)"
listed="$( (printf '%s\n' "${LAYOUTS[@]#*=}"; printf '%s\n' "${LAYOUT_EXEMPT[@]}") | sort -u)"
if [ -z "${defined}" ]; then
  echo "error: found no struct definitions in src/shekyl/shekyl_ffi.h — the pattern is wrong" >&2
  exit 1
fi
unlisted="$(comm -23 <(echo "${defined}") <(echo "${listed}"))"
if [ -n "${unlisted}" ]; then
  echo "error: src/shekyl/shekyl_ffi.h defines structs the layout limb neither compares nor exempts:" >&2
  echo "${unlisted}" | sed 's/^/  /' >&2
  exit 1
fi
gone="$(comm -13 <(echo "${defined}") <(echo "${listed}"))"
if [ -n "${gone}" ]; then
  echo "error: the layout limb lists structs src/shekyl/shekyl_ffi.h does not define:" >&2
  echo "${gone}" | sed 's/^/  /' >&2
  exit 1
fi

: >"${workdir}/shekyl_ffi_layout_bounds.h"
for bound in "${BOUNDS[@]}"; do
  cbindgen --config scripts/ci/cbindgen-ffi-bounds.toml --output "${workdir}/bound.h" \
    "${bound}" 2>"${workdir}/cbindgen.log" \
    || { cat "${workdir}/cbindgen.log" >&2; exit 1; }
  cat "${workdir}/bound.h" >>"${workdir}/shekyl_ffi_layout_bounds.h"
done

include="$(printf '"%s", ' "${LAYOUTS[@]%%=*}")"
{ cat scripts/ci/cbindgen-ffi-layouts.toml; echo "include = [${include%, }]"; } >"${workdir}/layouts.toml"
cbindgen --config "${workdir}/layouts.toml" --output "${workdir}/shekyl_ffi_layout_rust.h" \
  rust/shekyl-ffi/src/lib.rs 2>"${workdir}/cbindgen.log" \
  || { cat "${workdir}/cbindgen.log" >&2; exit 1; }

layouts="$(python3 scripts/ci/ffi_layout_gate.py src/shekyl/shekyl_ffi.h \
  "${workdir}/shekyl_ffi_layout_rust.h" "${workdir}/shekyl_ffi_layout_asserts.h" "${LAYOUTS[@]}")"

g++ -fsyntax-only -std=c++17 -I "${workdir}" -I src scripts/ci/ffi_layout_gate.cpp

echo "FFI signatures: hand-written header agrees with the Rust definitions (${total} exports over ${#SURFACES[@]} files checked; $(wc -l <<<"${declared}") declarations all exported; ${layouts} struct layouts compared, ${#LAYOUT_EXEMPT[@]} exempt)"
