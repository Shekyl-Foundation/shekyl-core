// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Settlement-epoch schedule and challenge-timing FFI.

// The epoch geometry (`H_open` / `H_close` / `H_slash_deadline`) has one
// home, `shekyl_archival_retention::consensus_state`; this module marshals
// it across the C edge and computes none of it.
use shekyl_archival_retention::{
    empty_attestation_root, ATTESTATION_HEADER_LEN, MAX_ATTESTATION_RECORDS,
    MAX_ATTESTATION_WITNESS_BYTES,
};
pub use shekyl_archival_retention::{
    settlement_epoch_last_block, settlement_epoch_open_height,
    settlement_epoch_slash_deadline_height,
};

// ── Attestation-witness cross-language constant authorities (credit-wire CW-2,
//    gate CW-1b-iv). These expose the Rust-side authoritative values so C++ can
//    assert its own `config::` constants agree — the real gate replacing the "must
//    equal" doc-comment. The block-hash differential is blind to the witness (it is
//    not in the block blob), so these + the byte-pinned witness KAT are the only
//    checks on this surface. ──

/// Genesis-frozen consensus cap on attestation records per block. C++ asserts
/// `config::ARCHIVAL_MAX_ATTESTATION_RECORDS` equals this.
#[no_mangle]
pub extern "C" fn shekyl_archival_max_attestation_records() -> u64 {
    MAX_ATTESTATION_RECORDS as u64
}

/// Canonical length of one kept attestation header (`p_id ‖ s ‖ E ‖ kind`). C++
/// asserts `config::ARCHIVAL_ATTESTATION_HEADER_BYTES` equals this.
#[no_mangle]
pub extern "C" fn shekyl_archival_attestation_header_bytes() -> u64 {
    ATTESTATION_HEADER_LEN as u64
}

/// The EXACT maximum canonical byte length of a block's attestation witness
/// (`count ‖ MAX records × (nonce ‖ anchor_height_le ‖ HybridSignature)`, `SF-D8` v2).
///
/// `config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` is defined as this same
/// quantity and C++ asserts equality. Below it, C++ would reject on the wire a
/// witness Rust admits — a consensus split; above it, every block gets that much
/// free padding an attacker may fill. Equality is the only value with neither
/// property, and it makes any drift in either language's operands loud.
#[no_mangle]
pub extern "C" fn shekyl_archival_attestation_witness_max_bytes() -> u64 {
    MAX_ATTESTATION_WITNESS_BYTES as u64
}

/// Empty-set archival attestation root — `attestation_root(&[])`
/// (`ARCHIVAL_CREDIT_WIRE.md` §3). The valid empty commitment a block header
/// carries when it has no pass records; **not** the all-zero `null_hash`.
///
/// # Safety
/// `out_ptr` must be non-null and point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_attestation_root_empty(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let root = empty_attestation_root();
    std::ptr::copy_nonoverlapping(root.as_ptr(), out_ptr, 32);
    true
}

#[cfg(test)]
mod connect_order_tests {
    use super::*;
    use shekyl_archival_retention::epoch_close_height;

    /// The slash-settle operand for epoch `E` (first block above the
    /// deadline) must be STRICTLY greater than `E`'s close-fire operand —
    /// same-height is not enough, because the connect order runs
    /// `process_archival_slash_at_height` before
    /// `process_archival_epoch_close_at_height`, so at an equal height the
    /// slash pass would read settlement state the close has not written yet.
    ///
    /// The two derivations are maintained independently
    /// (`epoch_close_height` in `shekyl-archival-retention`'s
    /// consensus_state; the deadline here), so this test is the coupling:
    /// it fires if either function's shape changes, even in a direction
    /// that stays positive at small epochs. Both are affine in `E` with
    /// slope `SEB`, so strictness at sampled epochs plus slope equality
    /// proves the property for every epoch.
    #[test]
    fn slash_settle_strictly_follows_close_write_at_every_epoch() {
        let diff_at = |e: u64| {
            let close_write = epoch_close_height(e).expect("no overflow at test epochs");
            let slash_settle = settlement_epoch_slash_deadline_height(e) + 1;
            assert!(
                slash_settle > close_write,
                "epoch {e}: slash settles at {slash_settle} but close writes at \
                 {close_write} - the slash-then-close connect order would read \
                 unsettled state"
            );
            slash_settle - close_write
        };
        let d0 = diff_at(0);
        for e in [1u64, 2, 25, 10_000] {
            assert_eq!(
                d0,
                diff_at(e),
                "slash/close derivations diverge in slope at epoch {e} - one of \
                 the two independently-maintained formulas changed shape"
            );
        }
    }
}
