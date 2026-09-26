// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `D_max`, the consensus reorg cap (`PDM-Q11`) — **the genesis rule set's
//! value**; the cap in force is `RuleSet::reorg_cap` — and the journal
//! horizon derived from it (`PDM-Q-F19`).
//!
//! # One number, three derivations
//!
//! `PDM-Q11` (RULED 2026-09-17, `ARCHIVAL_PRUNED_DAEMON_MODE.md`) froze the
//! *shape* — a detectability boundary, home `CEN-E2` (`is_alternative_block_allowed`
//! above the checkpoint) — and pinned the *numeric* **PROVISIONAL** on the
//! `bond_duration` precedent. Three surfaces derive from it: F10's discard
//! predicate (now the epoch calendar, `DRS_E1_SPRUNE.md` §2), F19's journal
//! horizon ([`journal_horizon`]), and the store's undo-log retention
//! (S-CHAIN-W SCW-7: retention `≥ D_max`, or a legal reorg returns
//! `StoreCannot::PopBelowFloor`).
//!
//! # Where the numeric comes from
//!
//! `config/consensus_constants.json` already carries
//! `archival_reorg_depth_blocks = 720` — the pass-countersignature anchor
//! depth, whose own comment names "PDM-Q11's `D_max` reorg gate" as a
//! consumer: a reorg deeper than that depth moves a canonical anchor hash
//! and invalidates admitted passes. So the cap **is** that depth, derived
//! rather than re-typed — one source in `config/`, no second 720 to drift
//! (`PDM-Q11`'s "`D_max = 720` on the `bond_duration` precedent" is the
//! same number for the same reason). The numeric stays PROVISIONAL until
//! the mechanisms that consume it have run against it; **building them is
//! what makes it testable** — which is why this constant lands with the
//! retention prune (DRS-E1 S-PRUNE) rather than after it.
//!
//! # `SEB > D_max`, asserted where the constants are
//!
//! The retention prune's pop floor (`DRS_E1_SPRUNE.md` §7) is a belt
//! *because* the undo floor `tip − D_max` sits strictly above the body
//! horizon's `h_scarce + 1`, and that ordering is exactly
//! `SETTLEMENT_EPOCH_BLOCKS > D_max`. Asserted at compile time on the
//! production constants. The cap is rule-set data (`RuleSet::reorg_cap`;
//! `GENESIS` carries this constant, a Fakechain set names its own), and
//! the store's undo retention is boxed between them — at least the
//! in-force set's cap, strictly inside the session's epoch — at open and at
//! every connect, so a regtest that shortens the epoch runs a rule set
//! whose cap fits (rule 71: nettype selects data, the data satisfies the
//! same invariant).

use shekyl_archival_retention::{
    ARCHIVAL_REORG_DEPTH_BLOCKS, CHALLENGE_RESOLUTION_BLOCKS, FAILURE_WINDOW_N,
    SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_types::{BlockCount, BlockHeight};

/// The genesis rule set's reorg cap: the deepest reorganisation a node on
/// the issued rules is built to follow (`PDM-Q11`, shape frozen; numeric
/// **PROVISIONAL**, derived from `archival_reorg_depth_blocks` — module
/// docs). Consumers read the cap **in force** through
/// [`RuleSet::reorg_cap`](crate::RuleSet::reorg_cap); this constant is that
/// field's value on `GENESIS` and the production pair's term in the
/// `SEB > D_max` assertion below.
pub const D_MAX: BlockCount = BlockCount::from_raw(ARCHIVAL_REORG_DEPTH_BLOCKS);

const _: () = assert!(
    SETTLEMENT_EPOCH_BLOCKS > D_MAX.to_raw(),
    "SETTLEMENT_EPOCH_BLOCKS <= D_MAX: the retention prune's undo floor (tip - D_max) would not \
     sit above the body horizon (DRS_E1_SPRUNE.md §3, §7); re-pin one with the other"
);

const _: () = assert!(
    D_MAX.to_raw() > 0,
    "D_MAX is zero: no undo row would be retained and no reorg could be followed"
);

/// The height below which the seven window-retired archival journals may
/// be retired (`PDM-Q-F19`, `PDM-Q-F16`): `tip − (CRB + n·SEB + D_max)`,
/// or `None` while the chain is shorter than that expression — **under the
/// production schedule and reorg cap**.
///
/// Minted here because `D_max` lives here and `CRB`, `n` and `SEB` live in
/// `shekyl-archival-retention`; consumed by S-ARCH's journal writers when
/// they land (they have no Rust writer yet). `shekyl_archival_failure_window_params`
/// is *not* this — it returns the m-of-n `(m, n, serve_budget)`. A session
/// running a shortened schedule (the store's `Horizons`) uses
/// [`journal_horizon_under`] with its own pair.
#[must_use]
pub fn journal_horizon(tip: BlockHeight) -> Option<BlockHeight> {
    journal_horizon_under(tip, SETTLEMENT_EPOCH_BLOCKS, D_MAX)
}

/// [`journal_horizon`] under a session's schedule: `tip − (CRB + n·SEB +
/// reorg_cap)` for the `epoch_blocks` and `reorg_cap` the session runs —
/// the same pair the store refuses at open unless `0 < reorg_cap <
/// epoch_blocks`. `CRB` and `n` are consensus constants and do not vary
/// by nettype (rule 71: nettype selects the schedule's data, never the
/// expression). `None` while the chain is shorter than the window.
#[must_use]
pub fn journal_horizon_under(
    tip: BlockHeight,
    epoch_blocks: u64,
    reorg_cap: BlockCount,
) -> Option<BlockHeight> {
    let window = CHALLENGE_RESOLUTION_BLOCKS
        .checked_add(u64::from(FAILURE_WINDOW_N).checked_mul(epoch_blocks)?)?
        .checked_add(reorg_cap.to_raw())?;
    tip.to_raw().checked_sub(window).map(BlockHeight::from_raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_is_the_anchor_depth_and_below_the_epoch() {
        assert_eq!(D_MAX.to_raw(), 720, "PDM-Q11's provisional numeric");
        assert_eq!(
            D_MAX.to_raw(),
            ARCHIVAL_REORG_DEPTH_BLOCKS,
            "one source in config/"
        );
        assert!(SETTLEMENT_EPOCH_BLOCKS > D_MAX.to_raw());
    }

    #[test]
    fn the_journal_horizon_is_f19s_expression_and_none_below_it() {
        let window = CHALLENGE_RESOLUTION_BLOCKS
            + u64::from(FAILURE_WINDOW_N) * SETTLEMENT_EPOCH_BLOCKS
            + 720;
        assert_eq!(journal_horizon(BlockHeight::from_raw(window - 1)), None);
        assert_eq!(
            journal_horizon(BlockHeight::from_raw(window)),
            Some(BlockHeight::from_raw(0))
        );
        assert_eq!(
            journal_horizon(BlockHeight::from_raw(window + 5)),
            Some(BlockHeight::from_raw(5))
        );
    }

    #[test]
    fn a_shortened_session_pair_moves_the_horizon_with_it() {
        // A 100-block epoch and a 50-block cap: the window is CRB + n·100 + 50.
        let short = CHALLENGE_RESOLUTION_BLOCKS + u64::from(FAILURE_WINDOW_N) * 100 + 50;
        let cap = BlockCount::from_raw(50);
        assert_eq!(
            journal_horizon_under(BlockHeight::from_raw(short - 1), 100, cap),
            None
        );
        assert_eq!(
            journal_horizon_under(BlockHeight::from_raw(short + 3), 100, cap),
            Some(BlockHeight::from_raw(3))
        );
        assert_eq!(
            journal_horizon_under(
                BlockHeight::from_raw(short + 3),
                SETTLEMENT_EPOCH_BLOCKS,
                D_MAX
            ),
            journal_horizon(BlockHeight::from_raw(short + 3)),
            "the production pair is the one-argument form"
        );
    }
}
