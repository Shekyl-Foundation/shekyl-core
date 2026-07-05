//! The entry-seam **plan** — the single-sourced consumer of both
//! [`draw_entry_gap`](crate::draw_entry_gap) values.
//!
//! `draw_entry_gap` returns `(spread, bond_first)`; this module is the one
//! place that converts that pair into the relative placement of the two seam
//! events. Single-sourcing the *consumption* (not just the draw) closes two
//! conformance failure modes the design record names:
//!
//! 1. **The dropped order-coin.** A consumer that wires only the `spread`
//!    delay and discards `bond_first` collapses the adversary's ordering
//!    prior from 0.5 to certainty — half the golden-vector-certified
//!    decorrelation (`stake_engine.rs` consumer-site disclosure;
//!    `ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §4). [`plan_entry_seam`]
//!    consumes the full draw tuple, so a caller *cannot* plan without the
//!    coin.
//! 2. **The triangular mis-build.** Independently jittering both event times
//!    around a common anchor yields a separation that is the difference of
//!    two uniforms — triangular, peaked at zero, the opposite of a standoff
//!    (the conformance-critical construction note,
//!    `ARCHIVAL_FIREWALL_GATE6.md` §10.12 / the staking-sim `standoff`
//!    module docs). The plan bakes the correct shape: the **first** event
//!    sits at the private-intent anchor, the **second** at `anchor + spread`,
//!    and the coin decides which event goes first.
//!
//! # Logical time, not wall clock
//!
//! Offsets are in **blocks relative to the private-intent anchor** `t0` — the
//! caller's private moment of decision, which never appears in the plan (it is
//! the principal's secret; per-`P` independence comes from `t0` being
//! private). The planner is pure integer arithmetic: no float, no clock, no
//! RNG — deterministic and bit-identical across architectures, the same
//! posture as [`draw_entry_gap`](crate::draw_entry_gap) itself. The wallet
//! and the simulator import this same function, so "what we validated is
//! what ships" holds for the *consumption* of the draw exactly as it already
//! holds for the draw.

/// The planned relative placement of the two entry-seam events, in blocks
/// from the private-intent anchor `t0`.
///
/// Exactly one of the two offsets is `0` (that event fires at the anchor);
/// the other equals the drawn `spread` (`~ U[0, window]`). Which is which is
/// the `bond_first` order-coin's decision. A `spread` of `0` places both
/// events at the anchor — the no-standoff degenerate case the drawn window
/// makes rare and the caller's degeneracy guard polices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntrySeamPlan {
    /// Blocks from the anchor to `P`'s observable funding/entry event.
    pub entry_offset_blocks: u64,
    /// Blocks from the anchor to the bond-post broadcast.
    pub bond_post_offset_blocks: u64,
}

impl EntrySeamPlan {
    /// `true` when the plan places the bond-post strictly before the entry
    /// event — the inversion that removes the adversary's "bond-post follows
    /// a recent spend" ordering prior.
    pub fn is_inverted(&self) -> bool {
        self.bond_post_offset_blocks < self.entry_offset_blocks
    }
}

/// Convert a [`draw_entry_gap`](crate::draw_entry_gap) result into the
/// relative event placement, per the conformance-correct construction: the
/// first event at the anchor, the second at `anchor + spread`, order decided
/// by the fair coin.
///
/// Takes the draw's `(spread_blocks, bond_first)` tuple **whole** — the
/// signature composes directly with `draw_entry_gap` / a guarded wrapper, and
/// makes silently dropping the order-coin (failure mode 1 in the module docs)
/// inexpressible at this seam.
pub fn plan_entry_seam((spread_blocks, bond_first): (u64, bool)) -> EntrySeamPlan {
    if bond_first {
        EntrySeamPlan {
            bond_post_offset_blocks: 0,
            entry_offset_blocks: spread_blocks,
        }
    } else {
        EntrySeamPlan {
            entry_offset_blocks: 0,
            bond_post_offset_blocks: spread_blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::draw::{draw_entry_gap, GapRng};

    #[test]
    fn coin_decides_which_event_anchors() {
        let inverted = plan_entry_seam((42, true));
        assert_eq!(inverted.bond_post_offset_blocks, 0);
        assert_eq!(inverted.entry_offset_blocks, 42);
        assert!(inverted.is_inverted());

        let causal = plan_entry_seam((42, false));
        assert_eq!(causal.entry_offset_blocks, 0);
        assert_eq!(causal.bond_post_offset_blocks, 42);
        assert!(!causal.is_inverted());
    }

    #[test]
    fn zero_spread_degenerates_to_coincident_events_either_way() {
        for coin in [false, true] {
            let plan = plan_entry_seam((0, coin));
            assert_eq!(plan.entry_offset_blocks, 0);
            assert_eq!(plan.bond_post_offset_blocks, 0);
            assert!(!plan.is_inverted(), "coincident events are not inverted");
        }
    }

    /// The separation of a *planned* pair is exactly the drawn spread —
    /// uniform, not triangular. This is the anti-mis-build property: planning
    /// never re-jitters, it places.
    #[test]
    fn separation_is_the_drawn_spread_exactly() {
        struct Counter(u64);
        impl GapRng for Counter {
            fn next_u64(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
        }
        let mut rng = Counter(7);
        for _ in 0..1000 {
            let draw = draw_entry_gap(crate::DEFAULT_ENTRY_GAP_WINDOW, &mut rng);
            let plan = plan_entry_seam(draw);
            let separation = plan
                .entry_offset_blocks
                .abs_diff(plan.bond_post_offset_blocks);
            assert_eq!(separation, draw.0, "planning must place, never re-jitter");
            assert!(separation <= crate::DEFAULT_ENTRY_GAP_WINDOW);
            // The first event always sits at the anchor.
            assert_eq!(
                plan.entry_offset_blocks.min(plan.bond_post_offset_blocks),
                0
            );
        }
    }
}
