// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The end-date release's engine half (`WALLET_RPC_STAKING_OUTCOMES.md`
//! WR-Q3, WR-Q4; the amendment `ARCHIVAL_BOND_POST_DELAY.md` BD-Q3 Rule 2).
//!
//! A pending record's end date is `reference_height +
//! FCMP_REFERENCE_BLOCK_MAX_AGE`, inclusive: past it no block on any chain
//! can include the transaction. The state half
//! (`PendingPostBlock::release_ended`) releases a record once the sealed scan
//! has covered its end date and writes its outcome in the same seal. This
//! module holds what the dispatch driver and the seams share around it: the
//! pinned age limit, the mapping from a submit failure to the cause a record
//! keeps, and the log lines a release writes.

use shekyl_engine_state::pending_post_block::TerminalCause;
use shekyl_types::BlockCount;

use crate::engine::transaction_submitter::{BroadcastSubmitError, SubmitterError};

#[cfg(doc)]
use shekyl_engine_state::pending_post_block::end_date;

/// The consensus reference age limit, `FCMP_REFERENCE_BLOCK_MAX_AGE`, as the
/// span a pending record's end date is computed with
/// ([`end_date`]`(reference_height, REFERENCE_MAX_AGE)`, WR-Q3).
///
/// **The end date assumes this limit never rises** (WR-Q3's invariant). A
/// record is signed under the limit in force then and its end date computed
/// under the limit read now. Raise the limit and a stored record's end date
/// comes out too early: the wallet would release it, and the phantom-slot
/// cleanup (`stake_persist.rs`) could then drop a bond that can still land,
/// for good. Lowering it only holds funds longer. The sentinel below fails
/// the build if the limit moves, so this module is revisited with it; if the
/// limit ever becomes per-era, store the limit in force at signing beside
/// `reference_height` (rule 21).
pub(crate) const REFERENCE_MAX_AGE: BlockCount =
    BlockCount::from_raw(crate::consensus_constants::FCMP_REFERENCE_BLOCK_MAX_AGE);

const _: () = assert!(
    crate::consensus_constants::FCMP_REFERENCE_BLOCK_MAX_AGE == 100,
    "FCMP_REFERENCE_BLOCK_MAX_AGE moved: a pending record's end date assumes the limit \
     never rises (WALLET_RPC_STAKING_OUTCOMES.md WR-Q3). A raised limit releases records \
     whose transaction can still land; revisit the end-date release before updating this"
);

/// Map a submit failure to the cause a pending record keeps (BD-Q3 Rule 2),
/// or `None` when the failure is not a terminal daemon verdict. The record is
/// held either way; a terminal cause stops sends and names the outcome.
pub(crate) fn terminal_cause(e: &BroadcastSubmitError) -> Option<TerminalCause> {
    match e {
        BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal { kind }) => {
            Some(TerminalCause::from(*kind))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WR-Q3's invariant, beside the compile-time sentinel on
    /// [`REFERENCE_MAX_AGE`]: a record's end date is computed with the limit
    /// read now, so a raised limit would release records that can still
    /// land. This fails if the limit moves without the end-date release being
    /// revisited, and pins that the release uses the consensus constant.
    #[test]
    fn the_end_date_release_assumes_the_consensus_age_limit() {
        assert_eq!(
            crate::consensus_constants::FCMP_REFERENCE_BLOCK_MAX_AGE,
            100
        );
        assert_eq!(REFERENCE_MAX_AGE.to_raw(), 100);
        assert_eq!(
            REFERENCE_MAX_AGE.to_raw(),
            shekyl_curve_tree::REF_ANCHOR_AGE.to_raw()
                + shekyl_curve_tree::PROOF_VALIDITY_HORIZON.to_raw(),
            "the wallet's proof horizon and the release's limit are one number"
        );
    }

    /// Only a terminal verdict becomes a recorded cause; every other submit
    /// failure leaves the record as it is.
    #[test]
    fn only_a_terminal_verdict_maps_to_a_cause() {
        use crate::engine::error::{AmbiguousErrorKind, RetryableRejectCause, TerminalErrorKind};
        let terminal = BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal {
            kind: TerminalErrorKind::JoinMarketUnsupported,
        });
        assert_eq!(
            terminal_cause(&terminal),
            Some(TerminalCause::JoinMarketUnsupported)
        );
        let retryable = BroadcastSubmitError::Submit(SubmitterError::RejectedRetryable {
            cause: RetryableRejectCause::StaleRoot,
        });
        assert_eq!(terminal_cause(&retryable), None);
        let ambiguous = BroadcastSubmitError::Submit(SubmitterError::Ambiguous {
            kind: AmbiguousErrorKind::DaemonTimeout,
        });
        assert_eq!(terminal_cause(&ambiguous), None);
    }
}
