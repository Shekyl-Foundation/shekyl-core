// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The funding-seam **cover-amount** draw — the amount-axis sibling of the
//! entry-gap timing draw, float-free by construction.
//!
//! Where [`crate::draw::draw_entry_gap`] decorrelates *when* `P` funds and
//! enters, this draws *how much* the principal sends on top of the public
//! `bond_floor`: `cover ~ U(0, bond_floor)` = `U[1, rung)`. That
//! puts the funded amount strictly between rung multiples, so a bond post can
//! never be *proven* to be one. See [`draw_cover_amount`] for the full role.
//!
//! **Not the primary defense.** Amounts are CT-hidden; attribution is already
//! denied on chain. This is defense in depth: it removes any tell in the
//! transaction *value* that a bond happened at all.
//!
//! The count-dependent `span(C)` response curve that used to live here is
//! **RETIRED** (`ARCHIVAL_COVER_DRAW.md`, ratified 2026-07-21): it keyed the
//! draw to public chain state, which handed an on-chain observer the exact
//! predictor the wallet used, and it required a canonical standing-bond-count
//! aggregate that was never built and is explicitly not to be built. The bound
//! here is a fixed consensus constant and the draw is pure entropy — **no
//! on-chain input of any kind** (method note 7, `ARCHIVAL_FIREWALL_GATE6.md`).
//!
//! Same float-free discipline as the entry-gap draw: pure integer arithmetic,
//! bit-identical across architectures, golden-vector-pinnable — every wallet
//! draws from the same fixed distribution, so "what we validated is what
//! ships" holds by construction.

use crate::draw::{bounded_uniform, GapRng};

/// Draw the funding-seam cover, strictly `0 < cover < rung` — uniform over
/// `[1, rung)`, `rung` one bond rung: the archival bond floor, which the
/// caller passes (`shekyl_archival_retention::archival_params().bond_floor_atomic`;
/// 750 000 000 at the gate-4 pin). This crate reads no consensus constant of
/// its own: it is the dependency-free path a wallet ships.
///
/// # What the cover is for (two roles; verified at source, `ARCHIVAL_COVER_DRAW.md`)
///
/// 1. **Unprovability (the role this draw exists for).** A bond's staked floor
///    is always an exact rung multiple `k·RUNG`. Adding `cover ∈ (0, RUNG)`
///    puts the funded amount **strictly between** rung multiples —
///    `funded(k) ∈ (k·RUNG, (k+1)·RUNG)` — so it is never a "clean rung" and is
///    indistinguishable from any ordinary transfer of the same amount. A bond
///    post, already unlinkable, becomes impossible to *prove* is a bond post.
///    Defense in depth on top of CT-hidden amounts.
/// 2. **Anti-re-link runway (a consequence, not this draw's constraint).** `P`
///    pays fees from cover; if it depletes, `P` re-funds from the principal —
///    a *second* principal→`P` link, the one edge the firewall protects
///    (§2.2). But the user tops up working capital separately, so this role
///    does **not** bind the draw: even a near-zero cover survives it.
///
/// # Two hard invariants
///
/// - **No on-chain input, ever.** The bound is a fixed consensus constant, and
///   the draw is pure OS entropy. Deriving `cover` from *anything an observer
///   can read on chain* (a live-bond count, a fee snapshot, a balance) hands
///   the attacker the exact predictor the wallet uses — which is why the
///   count-keyed `span(C)` curve was retired (`ARCHIVAL_COVER_DRAW.md`,
///   2026-07-21) and is method note 7 in `ARCHIVAL_FIREWALL_GATE6.md`.
/// - **Strictly positive.** `cover == 0` is the reserved DQ6 opt-out sentinel
///   (stake-only, disclosed cost); the draw never produces it, so the sentinel
///   stays unambiguous. `cover == RUNG` is excluded too, so the funded amount
///   never lands *on* the next rung boundary.
#[must_use]
pub fn draw_cover_amount<R: GapRng + ?Sized>(rng: &mut R, rung: u64) -> u64 {
    // `cover ∈ [1, rung)`: `bounded_uniform` is inclusive of `max`, so
    // `1 + U[0, rung-2]` gives `[1, rung-1]` — strictly `0 < cover < rung`.
    // A rung of 2 has the one cover 1; a rung below 2 has none, and the
    // archival parameters refuse a floor that small.
    debug_assert!(
        rung >= 2,
        "a cover rung below 2 has no cover strictly inside it"
    );
    1 + bounded_uniform(rng, rung.saturating_sub(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate-4 rung, a test vector.
    const COVER_RUNG_ATOMIC: u64 = 750_000_000;

    struct Seq(Vec<u64>, usize);
    impl GapRng for Seq {
        fn next_u64(&mut self) -> u64 {
            let v = self.0[self.1 % self.0.len()];
            self.1 += 1;
            v
        }
    }

    #[test]
    fn draw_is_strictly_between_zero_and_the_rung() {
        // Every draw must satisfy 0 < cover < RUNG — including the extreme raw
        // RNG words (0 and u64::MAX), which must not escape either bound.
        let mut rng = Seq(
            vec![0, 1, u64::MAX, u64::MAX / 2, 12_345, 999_999_999_999, 7],
            0,
        );
        for _ in 0..64 {
            let cover = draw_cover_amount(&mut rng, COVER_RUNG_ATOMIC);
            assert!(
                cover > 0,
                "cover {cover} hit the reserved opt-out sentinel 0"
            );
            assert!(cover < COVER_RUNG_ATOMIC, "cover {cover} reached the rung");
        }
    }

    #[test]
    fn zero_cover_is_unreachable() {
        // `cover == 0` is the reserved DQ6 opt-out sentinel; the draw must never
        // produce it (a raw 0 word maps to 1), so the sentinel stays
        // unambiguous. `cover == 0` would also put `funded` exactly on a rung
        // boundary — the very tell the draw removes.
        let mut rng = Seq(vec![0], 0);
        assert_eq!(
            draw_cover_amount(&mut rng, COVER_RUNG_ATOMIC),
            1,
            "raw 0 must map to 1, not 0"
        );
    }

    #[test]
    fn funded_is_strictly_between_rung_multiples() {
        // funded(k) = RUNG*k + cover with cover in (0, RUNG) lands strictly in
        // (RUNG*k, RUNG*(k+1)) — never ON a rung boundary, so it is never a
        // clean bond floor and cannot be proven to be a bond funding.
        let mut rng = Seq(vec![u64::MAX, 1, 42, u64::MAX / 3], 0);
        for k in 1u64..8 {
            let funded = COVER_RUNG_ATOMIC * k + draw_cover_amount(&mut rng, COVER_RUNG_ATOMIC);
            assert!(
                funded > COVER_RUNG_ATOMIC * k,
                "funded {funded} on lower boundary"
            );
            assert!(
                funded < COVER_RUNG_ATOMIC * (k + 1),
                "funded {funded} on/over upper boundary"
            );
        }
    }
}
