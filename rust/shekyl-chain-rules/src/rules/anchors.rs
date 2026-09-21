// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E — the anchor model's rules (`CHAIN_RULES_SLICE_3.md`).
//!
//! The rows of [`ReleaseAnchors`](crate::ReleaseAnchors), `PDM-Q5`'s
//! release-carried table. Two are this crate's; one is not yet:
//!
//! - **CEN-E5** — the binary's anchors agree with the file it opens. Not a
//!   per-block predicate: it is run **once, by the writer, at open**, over
//!   the recorded chain ([`E5::conflict_with`]), and its verdict is a
//!   [`AnchorConflict`] the writer remedies (pop, or refuse to run) rather
//!   than an `InvalidBlock`. The first row this crate enforces at a site
//!   other than `validate` — `RowStatus::EnforcedAt` is its registry status
//!   (slice 3 Q4), excluded from per-block completeness because no
//!   per-block coverage could ever contain it.
//! - **CEN-E1** — a block connecting at an anchored height carries that
//!   anchor's hash. Per block, view-bound; lands with the `Trust` input
//!   that carries the anchors into `validate`.
//! - **CEN-E2** — an alternative block at or below the last anchor is
//!   refused; `D_max`'s second band lands in the same function (`PDM-Q11`).
//!   **No Rust site**: the store admits no alternative block, and on the
//!   main chain the floor holds by construction (a candidate at `tip + 1`
//!   is above every anchor `≤ tip`). Subsumed behind the alt `ChainView`
//!   (slice 9) *and* `D_max`'s numeric (`PDM-Q11`, provisional) — the D5
//!   shape, with two blockers rather than one.

use shekyl_types::BlockHeight;

use crate::anchors::{AnchorConflict, ReleaseAnchors};
use crate::census::CenRow;
use crate::rules::Rule;
use crate::view::{AtHeight, ChainView};

/// CEN-E5: at open, every anchor the binary carries at or below the
/// recorded tip names the block the file actually recorded there.
///
/// What survives of the census row after `PDM-Q-F23` removed the runtime
/// checkpoint file: C2-R1b clause (3), run once at init over the compiled-in
/// set (`blockchain.cpp:6368` `check_against_checkpoints`). The C++ folds
/// check and remedy into one function; here the **check** is this rule's
/// and the **remedy** is [`AnchorConflict::remedy`]'s to state and the
/// writer's to execute — the crate has no store handle and cannot pop.
pub(crate) struct E5;

impl Rule for E5 {
    const ROW: CenRow = CenRow::E5;
}

impl E5 {
    /// The first anchor the recorded chain contradicts, if any, in height
    /// order. Anchors above the tip are not yet checkable and are skipped,
    /// as the C++ `continue`s past `pt.first >= blockchain_height`.
    ///
    /// `Err` is the view failing to answer — a fault, not a conflict.
    pub(crate) fn conflict_with<'id, V: ChainView<'id>>(
        anchors: &ReleaseAnchors,
        view: &V,
    ) -> Result<Option<AnchorConflict>, V::Fault> {
        let Some(tip) = view.tip()? else {
            // An empty file contradicts nothing: there is no block for an
            // anchor to disagree with (the C++ skips every point at or
            // above height 0 when the DB is empty).
            return Ok(None);
        };
        for anchor in anchors.entries() {
            if anchor.height > tip.height {
                break;
            }
            let recorded = match view.block_at(anchor.height)? {
                AtHeight::Recorded(block) => Some(block.hash),
                // Heights at or below the tip are dense (the store's
                // invariant); a hole at an anchored height is the file
                // missing a block it claims to have — a conflict, with
                // nothing recorded to name.
                AtHeight::AboveTip => None,
            };
            if recorded != Some(anchor.hash) {
                return Ok(Some(AnchorConflict {
                    height: anchor.height,
                    expected: anchor.hash,
                    recorded,
                }));
            }
        }
        Ok(None)
    }
}

/// The C2-R1b clause (3) rollback target: two blocks before the conflict,
/// floored at height 1 — genesis cannot be popped (`pop_block_from_blockchain`
/// throws at `height() == 1`; `StoreCannot::PopBelowFloor` in the Rust
/// store), so a conflict at height 1 or 2 rolls back to 1, not to a
/// saturated 0 that would abort mid-rollback on the genesis guard
/// (`blockchain.cpp:6403`–`:6409`, review round 4 of C2-R1b).
pub(crate) const fn rollback_target(conflict_at: BlockHeight) -> BlockHeight {
    const TWO_BEFORE: u64 = 2;
    const FLOOR: u64 = 1;
    let raw = conflict_at.to_raw();
    if raw >= TWO_BEFORE + FLOOR {
        BlockHeight::from_raw(raw - TWO_BEFORE)
    } else {
        BlockHeight::from_raw(FLOOR)
    }
}

#[cfg(test)]
#[path = "anchors_tests.rs"]
mod anchors_tests;
