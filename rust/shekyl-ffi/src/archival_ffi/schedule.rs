// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Settlement-epoch schedule and challenge-timing FFI.

// The epoch geometry (`H_open` / `H_close` / `H_slash_deadline`) has one
// home, `shekyl_archival_retention::consensus_state`; this module marshals
// it across the C edge and computes none of it.
use shekyl_archival_retention::empty_attestation_root;
pub use shekyl_archival_retention::{
    settlement_epoch_last_block, settlement_epoch_open_height,
    settlement_epoch_slash_deadline_height,
};

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
