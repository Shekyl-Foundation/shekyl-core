// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Epoch geometry over one [`SettlementEpochBlocks`].
//!
//! [`SettlementSchedule`] is the schedule a caller holds: the genesis pin,
//! a fakechain lever's value, or the process latch via [`SettlementSchedule::effective`].
//! The free functions in the parent module are that latch's entry points.

use crate::constants::{
    effective_settlement_epoch_blocks, SETTLEMENT_EPOCH_BLOCKS, SLASH_GRACE_EPOCHS,
    W2_EPOCH_DIVISOR,
};
use shekyl_types::archival::SettlementEpochBlocks;
use shekyl_types::{BlockHeight, SettlementEpoch};

const _: () = assert!(
    SETTLEMENT_EPOCH_BLOCKS > 0,
    "settlement epoch must be nonzero"
);

/// The epoch geometry over one [`SettlementEpochBlocks`]: which epoch a
/// height sits in, where an epoch opens, closes and is slash-final, and
/// which epoch a height closes. Epoch `E` covers heights
/// `[E·SEB, (E+1)·SEB)`; its close is processed at the first height of the
/// next epoch, `(E+1)·SEB`.
///
/// **One home for the geometry** (`05-system-thinking.mdc`: a formula two
/// lanes need is a function, not a row): the serve-credit gate, the slash
/// scan, the close, the prune horizon and the FFI's schedule entry points
/// all read `H_open` / `H_close` / `H_slash_deadline` here, so no consumer
/// can re-derive one with a boundary off by one.
///
/// **Two ways to obtain one, and which is whose.** The validator reads the
/// schedule off the rule set in force
/// (`shekyl_chain_rules::RuleSet::settlement_schedule`) — the genesis
/// constant on every issued set, a regtest lever's value on a Fakechain set
/// — and so never reads a process's environment (rule 71; DRS-E4 `ARW-15`).
/// The C++ daemon, the FFI shims and the wallet, which hold no rule set,
/// read [`Self::effective`]: the process-latched schedule the daemon arms
/// at startup on FAKECHAIN only (`constants::arm_settlement_epoch_override_for_regtest`).
/// The module's free functions (`settlement_epoch_at_height`, …) are those
/// callers' entry points and are this type over `effective()`; a consumer
/// that has a rule set does not call them.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SettlementSchedule {
    blocks: SettlementEpochBlocks,
}

impl core::fmt::Debug for SettlementSchedule {
    // `SettlementSchedule(10000)`: the one number, not a nested newtype.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SettlementSchedule")
            .field(&self.blocks.get())
            .finish()
    }
}

impl SettlementSchedule {
    /// The genesis schedule: [`SETTLEMENT_EPOCH_BLOCKS`] per epoch.
    pub const GENESIS: Self = Self {
        blocks: match SettlementEpochBlocks::new(SETTLEMENT_EPOCH_BLOCKS) {
            Some(blocks) => blocks,
            None => panic!("SETTLEMENT_EPOCH_BLOCKS is non-zero (asserted above)"),
        },
    };

    /// The geometry over `blocks` per epoch.
    #[must_use]
    pub const fn new(blocks: SettlementEpochBlocks) -> Self {
        Self { blocks }
    }

    /// The process-latched schedule: the genesis pin, or — only in a
    /// process that armed via
    /// [`arm_settlement_epoch_override_for_regtest`](crate::arm_settlement_epoch_override_for_regtest)
    /// — the validated fakechain lever. For callers that hold no rule set;
    /// see the type's doc.
    #[must_use]
    pub fn effective() -> Self {
        Self {
            blocks: SettlementEpochBlocks::new(effective_settlement_epoch_blocks())
                .expect("the latch holds the genesis pin or a parsed lever in 2..=SEB, never zero"),
        }
    }

    /// Blocks per epoch.
    #[must_use]
    pub const fn blocks(self) -> SettlementEpochBlocks {
        self.blocks
    }

    const fn seb(self) -> u64 {
        self.blocks.get()
    }

    /// Settlement epoch containing `block_height` (`floor(height / SEB)`).
    ///
    /// Used for bond-connect `join_settlement_epoch` derivation and
    /// prune-horizon arithmetic; the daemon performs no epoch arithmetic of
    /// its own.
    #[must_use]
    pub const fn epoch_at_height(self, block_height: u64) -> u64 {
        block_height / self.seb()
    }

    /// [`Self::epoch_at_height`] in the typed domain: the settlement epoch
    /// containing `height`. The form a consumer that holds typed heights
    /// (the validator's archival transition, the as-of-height holdings fold)
    /// reads; the raw form above is the FFI's edge.
    #[must_use]
    pub const fn epoch_at(self, height: BlockHeight) -> SettlementEpoch {
        SettlementEpoch::from_raw(self.epoch_at_height(height.to_raw()))
    }

    /// Settlement epoch whose `archival_r_market` rows are readable **as of
    /// the parent block** (`H − 1`).
    ///
    /// While the parent sits in epoch `P`, every epoch **strictly below** `P`
    /// has closed. Returns `0` before the first close (no rows exist yet;
    /// LMDB NOTFOUND must still marshal as `0` — see admission's
    /// applicant-counts-itself term).
    ///
    /// Single source for the admission gather's epoch key — C++ must not
    /// re-derive `epoch_at_height(parent) − 1` by hand.
    #[must_use]
    pub const fn last_settled_epoch_as_of_parent(self, parent_height: u64) -> u64 {
        self.epoch_at_height(parent_height).saturating_sub(1)
    }

    /// Settlement epoch that closes at `block_height`, when one does:
    /// `None` at height 0 and at non-boundary heights.
    #[must_use]
    pub const fn close_due_at_height(self, block_height: u64) -> Option<u64> {
        let seb = self.seb();
        if block_height == 0 || !block_height.is_multiple_of(seb) {
            return None;
        }
        Some(block_height / seb - 1)
    }

    /// The block height at which settlement epoch `epoch` closes — the
    /// inverse of [`Self::close_due_at_height`], `(E+1)·SEB`. `None` if that
    /// would overflow `u64` (an impossible epoch). Callers needing "is
    /// epoch `E` finalized at height `H`?" write `close_height(E) <= H`
    /// rather than re-deriving `(E+1)·SEB`.
    #[must_use]
    pub const fn close_height(self, epoch: u64) -> Option<u64> {
        match epoch.checked_add(1) {
            Some(next) => next.checked_mul(self.seb()),
            None => None,
        }
    }

    /// First height of settlement epoch `epoch` — `E·SEB`, the challenge's
    /// `H_open` (`ARCHIVAL_CONSENSUS_STATE.md` §3.4). Saturates on an
    /// impossible epoch.
    #[must_use]
    pub const fn open_height(self, epoch: u64) -> u64 {
        epoch.saturating_mul(self.seb())
    }

    /// Last height of settlement epoch `epoch` — `(E+1)·SEB − 1`, the
    /// challenge's `H_close`. The height *before* [`Self::close_height`],
    /// which is where the close is processed.
    #[must_use]
    pub const fn last_block(self, epoch: u64) -> u64 {
        self.open_height(epoch.saturating_add(1)).saturating_sub(1)
    }

    /// The slash grace in blocks under this schedule —
    /// `SLASH_GRACE_EPOCHS · SEB`, one full settlement epoch
    /// (`constants::SLASH_GRACE_EPOCHS`). Scales with the epoch, so a
    /// levered schedule's grace is the same *relationship* production has,
    /// not the production number.
    #[must_use]
    pub const fn slash_grace_blocks(self) -> u64 {
        self.seb().saturating_mul(SLASH_GRACE_EPOCHS)
    }

    /// The slash deadline for settlement epoch `epoch` —
    /// `H_close(E) + grace`, i.e. `last_block(E + SLASH_GRACE_EPOCHS)`. A
    /// block connecting strictly above it folds `E`'s unanswered challenges
    /// into slashes.
    #[must_use]
    pub const fn slash_deadline_height(self, epoch: u64) -> u64 {
        self.last_block(epoch)
            .saturating_add(self.slash_grace_blocks())
    }

    /// W₂ under this schedule — blocks after a challenge's issuing block to
    /// accept its serve-credit response: `SEB / W2_EPOCH_DIVISOR`, one
    /// twentieth of the epoch (`constants::CHALLENGE_RESPONSE_BLOCKS` is
    /// this method on [`Self::GENESIS`], and the W₂ ruling's band asserts
    /// hold there).
    ///
    /// Here rather than only as a constant so that W₂ and the slash grace
    /// are drawn from **one** epoch. The coupling the slash fold relies on —
    /// the fold for `E` must not run before `E`'s last-issued challenge's
    /// window closes, `grace ≥ W₂` — is then `k·SEB ≥ SEB/20`, i.e.
    /// `k · W2_EPOCH_DIVISOR ≥ 1`, which holds on every schedule by
    /// construction (the const-assert in `constants.rs`). Before this method
    /// the grace was schedule-derived and W₂ const-derived from the
    /// production pin, and under a levered `SEB = 100` the inequality the
    /// production-pin assert "guaranteed" was inverted (grace 100, W₂ 500).
    ///
    /// Integer division, as the constant always was: a levered epoch that
    /// is not a multiple of twenty truncates (the divisibility const-assert
    /// defends the production pin only), and an epoch below twenty yields
    /// `0`. W₂ has no consensus consumer yet; one that lands reads this
    /// method, not the pin, and decides there what a zero window means.
    #[must_use]
    pub const fn challenge_response_blocks(self) -> u64 {
        self.seb() / W2_EPOCH_DIVISOR
    }

    /// Prune horizon at `block_height`: epochs strictly below the returned
    /// value are unclaimable (`E < tip − MAX_CLAIM_AGE_W`,
    /// `ARCHIVAL_CONSENSUS_STATE.md` §5) and may be deleted. `None` while
    /// the chain is younger than the window.
    #[must_use]
    pub const fn prune_below_epoch_at_height(
        self,
        block_height: u64,
        max_claim_age_w: u64,
    ) -> Option<u64> {
        let tip_epoch = self.epoch_at_height(block_height);
        if tip_epoch > max_claim_age_w {
            Some(tip_epoch - max_claim_age_w)
        } else {
            None
        }
    }
}
