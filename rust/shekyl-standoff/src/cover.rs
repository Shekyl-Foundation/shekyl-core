// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The funding-seam **cover-amount** draw — the amount-axis sibling of the
//! entry-gap timing draw, float-free by construction.
//!
//! Where [`crate::draw::draw_entry_gap`] decorrelates *when* `P` funds and
//! enters, this draws *how much* the principal sends on top of the public
//! `bond_floor`: `cover ~ U[COVER_MIN_ATOMIC, COVER_RUNG_ATOMIC)` —
//! one full rung wide, so funded amounts **tile** the line and no value
//! identifies a bond. See [`draw_cover_amount`] for why that is the property
//! and entropy quantity is not.
//!
//! **Not the primary defense.** Amounts are CT-hidden; attribution is already
//! denied on chain. This is defense in depth against the value acting as a
//! *filter* that narrows the candidate set before a timing attack.
//!
//! The count-dependent `span(C)` response curve that used to live here is
//! **RETIRED** (`ARCHIVAL_COVER_DRAW.md`, ratified 2026-07-21): it keyed the
//! draw to public chain state, which made the cover interval publicly
//! computable, and it required a canonical standing-bond-count aggregate that
//! was never built and is explicitly not to be built. The bound here is a
//! pinned consensus constant instead — no population read, no manipulation
//! surface, no draw-vs-post desync.
//!
//! Same float-free discipline as the entry-gap draw: pure integer arithmetic,
//! bit-identical across architectures, golden-vector-pinnable — because two
//! wallets computing a different cover from the same inputs would draw from
//! *different distributions*, and that divergence **is** the cross-wallet
//! uniformity break the whole mechanism exists to close.

use crate::draw::{bounded_uniform, GapRng};

/// One bond rung in atomic units — the width of the cover draw's support.
///
/// Mirrors `shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC`. Kept local
/// because this crate deliberately has no retention dependency (it is the
/// leaf-most draw crate); the equality is asserted by
/// `shekyl-engine-core`, which depends on both, so the mirror cannot drift
/// silently.
pub const COVER_RUNG_ATOMIC: u64 = 750_000_000;

/// Lower edge of the cover draw, in atomic units — the **postability floor**.
///
/// A bond post costs `bond_floor + fee`, and the persona's only money at its
/// first post is what the funding transfer gave it, so a cover below the fee
/// yields a funded persona that structurally cannot bond
/// (`bond_assembly::InsufficientFunding`). Drawing from `(0, RUNG)` would make
/// that reachable by chance, so the draw's support starts here instead:
/// **postability is an enforced invariant, not a user responsibility.**
///
/// **Pinned, never derived from a live fee estimate.** Fee rates come from a
/// daemon snapshot (`shekyl_rpc_client::FeeRate`); deriving the
/// bound from one would give wallets *different draw supports*, which is the
/// cross-wallet uniformity break the whole mechanism exists to close — two
/// wallets drawing from different distributions is itself the leak. Every
/// wallet must pin the same number.
///
/// Sized at `RUNG / 100` — generous for a single-input / two-output FCMP++
/// bond post, while the excluded region stays 1 % of the band, far too thin to
/// serve as a filter. **Reopening criterion:** a review against real fee rates
/// before genesis, or any change to the bond post's structural weight. If
/// real fees ever exceed it the failure is loud, not silent — assembly refuses
/// with `InsufficientFunding` and the user tops up — but the constant should
/// be raised rather than relied on to degrade.
pub const COVER_MIN_ATOMIC: u64 = COVER_RUNG_ATOMIC / 100;

// Two structural preconditions, asserted at compile time so a future constant
// change fails the build with a clear message rather than a subtle defect:
//   - `> 0`: a zero postability floor makes a funded-but-unbondable persona
//     reachable by an unlucky draw.
//   - `< RUNG`: the draw computes `RUNG - MIN - 1` as the exclusive-upper span;
//     `MIN >= RUNG` would underflow during const-eval (and would also mean the
//     support `[MIN, RUNG)` is empty). Guards the subtraction at its source.
const _: () = assert!(
    COVER_MIN_ATOMIC > 0 && COVER_MIN_ATOMIC < COVER_RUNG_ATOMIC,
    "COVER_MIN_ATOMIC must satisfy 0 < MIN < COVER_RUNG_ATOMIC \
     (positive postability floor; non-empty half-open draw support)"
);

/// Draw the funding-seam cover: uniform over `[COVER_MIN_ATOMIC,
/// COVER_RUNG_ATOMIC)` — one full rung wide, upper-exclusive.
///
/// # What this defends, and what it does not
///
/// Amounts are CT-hidden, so this is **not** the primary defense — attribution
/// is already denied on chain (`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §18.9:
/// "the funding/change legs are CT-hidden"). This is **defense in depth**: it
/// removes any tell *in the transaction value* that a bond was executed at all.
///
/// Why that matters even against an observer who cannot read amounts: a value
/// tell is a **filter that feeds the timing attack**. If an amount announced
/// "this is a bond funding", an adversary would pre-narrow the candidate set
/// before doing any timing work, collapsing `N` from *every transaction in the
/// window* to *transactions with a bond-shaped amount*. The ambient cover is
/// not something we provision — only something we can forfeit — and a
/// recognizable amount forfeits it.
///
/// # Why one rung, upper-exclusive
///
/// A `k`-shard bond is funded with `RUNG·k + cover`, so the funded amount lands
/// uniformly in `[RUNG·k + MIN, RUNG·(k+1))`. Consecutive `k` **tile** the line:
/// every amount above the postability floor is a plausible funding for *some*
/// `k`. There is no value an observer can point at and say "that is not a
/// bond", which is the same statement as "no value says it is". A wider draw
/// would overlap bands without buying anything; a narrower one would leave gaps
/// that are exactly the filter this exists to remove.
///
/// The entropy *quantity* is not the property — **non-identifiability** is.
/// Enough randomness to defeat exact-match is the whole requirement; calibrating
/// how much was the retired `span(C)` curve's error
/// (`ARCHIVAL_COVER_DRAW.md`, retired 2026-07-21).
///
/// Excluding `cover == 0` is deliberate and is *not* the "never shrink the
/// set" mistake: `0` reconstructs `funded == bond_floor` exactly, which is the
/// tell itself. Contrast the entry-gap spread, where `0` is kept because the
/// anchor `t0` is private and a zero spread produces no observable at all.
#[must_use]
pub fn draw_cover_amount<R: GapRng + ?Sized>(rng: &mut R) -> u64 {
    // `bounded_uniform` is inclusive of `max`, so pass `RUNG - MIN - 1` to make
    // the upper edge exclusive: the draw spans `[MIN, RUNG)`.
    const SPAN_MAX: u64 = COVER_RUNG_ATOMIC - COVER_MIN_ATOMIC - 1;
    COVER_MIN_ATOMIC + bounded_uniform(rng, SPAN_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::draw::GapRng;

    struct Seq(Vec<u64>, usize);
    impl GapRng for Seq {
        fn next_u64(&mut self) -> u64 {
            let v = self.0[self.1 % self.0.len()];
            self.1 += 1;
            v
        }
    }

    #[test]
    fn draw_is_within_the_half_open_rung() {
        // Sweep a wide spread of raw RNG words; every draw must land in
        // [MIN, RUNG) — the postability floor at the bottom, upper-exclusive
        // at the top so consecutive shard-count bands tile without overlap.
        let mut rng = Seq(
            vec![0, 1, u64::MAX, u64::MAX / 2, 12_345, 999_999_999_999, 7],
            0,
        );
        for _ in 0..64 {
            let cover = draw_cover_amount(&mut rng);
            assert!(
                cover >= COVER_MIN_ATOMIC,
                "cover {cover} below postability floor"
            );
            assert!(
                cover < COVER_RUNG_ATOMIC,
                "cover {cover} reached or passed the rung"
            );
        }
    }

    #[test]
    fn zero_cover_is_unreachable() {
        // `cover == 0` reconstructs `funded == bond_floor` exactly — the tell
        // the draw exists to remove. Unlike the entry-gap spread (where 0 is
        // kept, because `t0` is private and a zero spread is unobservable),
        // excluding it here removes an identifying value rather than shrinking
        // a cover set.
        let mut rng = Seq(vec![0], 0);
        assert!(draw_cover_amount(&mut rng) >= COVER_MIN_ATOMIC);
    }

    #[test]
    fn bands_tile_across_shard_counts() {
        // funded(k) = RUNG*k + cover lands in [RUNG*k + MIN, RUNG*(k+1)).
        // Consecutive k therefore tile: every amount above the floor is a
        // plausible funding for some k, so no value identifies a bond.
        let mut rng = Seq(vec![u64::MAX, 0, 42], 0);
        for k in 1u64..8 {
            let funded = COVER_RUNG_ATOMIC * k + draw_cover_amount(&mut rng);
            assert!(funded >= COVER_RUNG_ATOMIC * k + COVER_MIN_ATOMIC);
            assert!(funded < COVER_RUNG_ATOMIC * (k + 1));
        }
    }
}
