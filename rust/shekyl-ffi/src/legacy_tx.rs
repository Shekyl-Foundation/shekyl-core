// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The witness-header writer, `shekyl_fcmp_build_witness_header`, pinned to
//! `parse_prove_witness` under `feature = "multisig"`.
//!
//! The wallet's transaction exports (signing, output construction, scan and
//! recover, the PQC spend signer) are gone: the wallet is Rust
//! (`shekyl-tx-builder`, `shekyl-crypto-pq`, `shekyl-scanner`), and their last
//! reader, a C++ JSON round-trip fixture, now parses a daemon-accepted spend
//! instead (`tests/unit_tests/json_serialization.cpp`).

#[cfg(feature = "multisig")]
use super::legacy_types::*;

// Writer half of the witness seam. Its reader (`parse_prove_witness`) serves
// only the multisig coordinator, so both sit under the same feature: a default
// build exporting a writer would offer to produce bytes nothing in that build
// can consume.
#[cfg(feature = "multisig")]
/// Build the 288-byte witness header from a typed struct.
///
/// # Safety
/// - `input` must point to a valid `ProveInputFields`.
/// - `out_buf` must point to at least 288 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_build_witness_header(
    input: *const ProveInputFields,
    out_buf: *mut u8,
) -> bool {
    if input.is_null() || out_buf.is_null() {
        return false;
    }
    let inp = &*input;
    let buf = std::slice::from_raw_parts_mut(out_buf, SHEKYL_PROVE_WITNESS_HEADER_BYTES);
    buf[0..32].copy_from_slice(&inp.output_key);
    buf[32..64].copy_from_slice(&inp.key_image_gen);
    buf[64..96].copy_from_slice(&inp.commitment);
    buf[96..128].copy_from_slice(&inp.pqc_leaf_commitment);
    buf[128..160].copy_from_slice(&inp.pqc_leaf_blind);
    buf[160..192].copy_from_slice(&inp.spend_key_x);
    buf[192..224].copy_from_slice(&inp.spend_key_y);
    buf[224..256].copy_from_slice(&inp.commitment_mask);
    buf[256..288].copy_from_slice(&inp.pseudo_out_blind);
    true
}
