// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 2d-1 SP-6 (part 2) — [`PReconcileSet`]: the typed reconcile evidence `P` hands
//! 2d-2.
//!
//! Binds the matched bond-posts to the [`VerifiedRange`] they were exhaustively
//! gathered over, so **"absence ≠ unscanned" is unrepresentable**. The 2d-2 reconcile
//! GC (SP-R0) consumes this to remove phantom `bonded_slots`, and it must GC a slot
//! **only** on *confirmed-absence within `covered`*, never on absence inferred from an
//! unscanned gap (a withholding source must not be able to induce a wrongful,
//! permanent removal — `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §3 half (B)).
//!
//! The binding is the type-safety spine: `VerifiedRange` (the exhaustiveness evidence)
//! and `BondPostMatch` (the matches) exist separately, but **nothing should let a
//! consumer reason about a match set's absence over a range it was not gathered for**.
//! [`PReconcileSet`] is that binding — its constructor takes a [`VerifiedRange`], which is
//! produced **only** by the verification-gated path (per-batch
//! [`verify_exhaustive`](super::exhaustiveness::verify_exhaustive), the
//! [`extend`](super::exhaustiveness::VerifiedRange::extend)-by-`VerifiedBatch` advance, or — at
//! the one seal-trust boundary — reconstruction from our own sealed verified frontier), **never
//! by hand** (see `VerifiedRange`'s verified-advance discipline). So a value of this type is proof
//! its matches are complete within an exhaustively-verified range, and the absence query is gated
//! on that range.
//!
//! **Exhaustiveness, not canonicity.** `covered` claims "scanned every block in
//! `[low, high)` on the chain served," not "this is the most-work chain." The GC
//! consumes a `PReconcileSet` **plus a separate canonicity token** (trusted-posture or
//! 2d-2 multi-source), so "GC on exhaustive-but-uncanonical evidence" stays
//! unrepresentable at the boundary (see the trust-anchor resolution in the 2d-1 plan).

use std::collections::BTreeMap;

use shekyl_types::{BlockHeight, PCanonicalId};

use super::exhaustiveness::VerifiedRange;
use super::scan_step::BondPostMatch;

/// The reconcile outcome for one persona. **Absence is concludable only within
/// `covered`** — [`OutsideCovered`](Self::OutsideCovered) is a *distinct* verdict from
/// [`AbsentWithinCovered`](Self::AbsentWithinCovered), so a consumer cannot read "not
/// scanned" as "not present" (the SP-6 absence-≠-unscanned rule, made unrepresentable
/// to violate rather than left as a caller obligation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconcileVerdict {
    /// A bond-post for this persona was found within `covered` — present. `height` /
    /// `post_kind` are its earliest post (the scan accumulates in height order).
    Present { height: BlockHeight, post_kind: u8 },
    /// No bond-post for this persona anywhere in `covered`, **and** the queried height
    /// is within `covered` — **confirmed-absent** (the range was exhaustively scanned,
    /// so a missing post is provably missing, not merely undelivered). GC-eligible for
    /// the 2d-2 reconcile, paired with a canonicity token.
    AbsentWithinCovered,
    /// The queried height is **outside** `covered` — absence is *unknown* (unscanned),
    /// never "absent." The GC must not act on this.
    OutsideCovered,
}

/// The reconcile evidence `P` hands 2d-2: every matched bond-post **plus** the
/// [`VerifiedRange`] they were gathered over **plus** the per-persona watch
/// floors that scope the match set's completeness. Constructible only via
/// [`from_verified_scan`](Self::from_verified_scan), which takes a [`VerifiedRange`]
/// (producible only by the verification-gated path, never by hand), so the match set can
/// never be divorced from the verified range its absence is valid over.
///
/// The floors are the third leg of the absence gate: the sweep scans every
/// block in `covered`, but it *watches* only the personas in its scan union —
/// a persona that joined the union after coverage advanced (the bond-watch
/// probe-adoption path) has no match rows for the blocks scanned before it
/// joined, and treating that gap as absence permanently GC'd a real bond.
/// A persona's absence is concludable only over `[floor, high)`; a persona
/// with no floor row was never watched and gets no absence claim at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PReconcileSet {
    covered: VerifiedRange,
    matches: Vec<BondPostMatch>,
    watch_floors: BTreeMap<PCanonicalId, BlockHeight>,
}

#[allow(dead_code)] // transient — exercised by the SP-5 sweep + 2d-2 SP-R0 once they land.
impl PReconcileSet {
    /// Build from a completed verified scan: the verified `covered` range, **every**
    /// bond-post match found within it, and each watched persona's floor (the
    /// first scanned height it was watched at).
    ///
    /// Three obligations, split by who can keep them. *Completeness-per-persona*
    /// is the caller's (the SP-5 sweep): from each persona's floor onward it
    /// scans every block in `covered` with that persona watched, so it sees
    /// every match — the type cannot check that. *Verification* is the type's:
    /// `covered` is a [`VerifiedRange`], so it cannot be a hand-built or
    /// source-claimed range. *Provenance* is the query gate's:
    /// [`reconcile`](Self::reconcile) refuses to convert "no match row" into an
    /// absence claim below a persona's floor or for an unfloored persona. The
    /// split is the point — the halves the type can enforce are exactly the
    /// halves a withholding source (or an incomplete watch) would attack.
    pub(crate) fn from_verified_scan(
        covered: VerifiedRange,
        matches: Vec<BondPostMatch>,
        watch_floors: BTreeMap<PCanonicalId, BlockHeight>,
    ) -> Self {
        Self {
            covered,
            matches,
            watch_floors,
        }
    }

    /// The exhaustively-verified range the matches are complete over.
    pub(crate) fn covered(&self) -> VerifiedRange {
        self.covered
    }

    /// The matched bond-posts (presence claims), in scan (height) order.
    pub(crate) fn matches(&self) -> &[BondPostMatch] {
        &self.matches
    }

    /// Full-scan reconcile: the whole-`covered` absence form (SP-R0 arms #2/#3 —
    /// "no post anywhere the scan has exhaustively covered"). Encapsulates the
    /// evidence-height bookkeeping: with nothing covered (`high == 0`) every
    /// verdict is [`ReconcileVerdict::OutsideCovered`] (absence unknown, GC
    /// must not act); otherwise the evidence height is the last covered block.
    pub(crate) fn reconcile_full_scan(&self, persona: PCanonicalId) -> ReconcileVerdict {
        let high = self.covered.high().to_raw();
        if high == 0 {
            return ReconcileVerdict::OutsideCovered;
        }
        self.reconcile(persona, BlockHeight::from_raw(high - 1))
    }

    /// Reconcile one persona against the verified evidence. `evidence_height` is the
    /// height whose coverage makes the verdict **meaningful** — typically the slot's bond
    /// height: an absence is only sound if the range since the persona could first have
    /// posted was exhaustively scanned. It gates the verdict on `evidence_height ∈
    /// covered`; it is **not** a temporal "as-of" filter on presence.
    ///
    /// **Presence is ANY matched post for the persona within `covered`.** A persona that
    /// posted *anywhere* it could is not phantom — there is deliberately no "only posts ≤
    /// `evidence_height`" filter. A real persona whose bond-post lands a block or two
    /// *after* `evidence_height` must never read `AbsentWithinCovered`: that would be a
    /// wrongful **permanent** GC — the exact stuck-funds failure this design forbids. If
    /// SP-R0 ever needs a finer temporal policy it filters [`matches`](Self::matches)
    /// itself; the type's job is the absence-≠-unscanned gate, not the GC's presence
    /// policy.
    ///
    /// The three-valued [`ReconcileVerdict`] makes absence-≠-unscanned unrepresentable: a
    /// caller **cannot** obtain `AbsentWithinCovered` for a height the scan did not cover
    /// — it gets `OutsideCovered` and must not GC. The same rule holds per persona:
    /// a height covered while the persona was **not watched** (below its floor, or a
    /// persona with no floor row at all) is unscanned *for that persona* and reads
    /// `OutsideCovered` — the gate that keeps a probe-adopted bond, whose blocks were
    /// scanned before its persona joined the union, out of the wrongful-GC path.
    pub(crate) fn reconcile(
        &self,
        persona: PCanonicalId,
        evidence_height: BlockHeight,
    ) -> ReconcileVerdict {
        // Gate first: absence is only meaningful where we exhaustively scanned. A point
        // outside `[low, high)` is unscanned, so neither presence nor absence is a
        // claim we may make.
        if evidence_height < self.covered.low() || evidence_height >= self.covered.high() {
            return ReconcileVerdict::OutsideCovered;
        }
        // Presence = the persona posted *anywhere* in `covered`, NOT only at/before
        // `evidence_height` (see the docstring: a temporal filter here would wrongly GC a
        // real persona that posted later). `find` returns the earliest match in scan
        // order, reported as the representative post. Checked BEFORE the
        // provenance gate: a match row is positive evidence regardless of when
        // the persona joined the watch, so `Present` is never suppressed.
        if let Some(m) = self.matches.iter().find(|m| m.p_canonical_id == persona) {
            return ReconcileVerdict::Present {
                height: m.height,
                post_kind: m.post_kind,
            };
        }
        // Provenance gate: absence is only meaningful where this persona was
        // WATCHED while the scan covered it. A persona with no floor row was
        // never in the scan union — its match rows cannot exist, so "no match"
        // is not evidence. Below its floor, coverage advanced unwatched — the
        // probe-adoption shape where a real bond's blocks were scanned before
        // the persona joined; same rule.
        match self.watch_floors.get(&persona) {
            None => ReconcileVerdict::OutsideCovered,
            Some(floor) if evidence_height < *floor => ReconcileVerdict::OutsideCovered,
            Some(_) => ReconcileVerdict::AbsentWithinCovered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::pscan::exhaustiveness::verify_exhaustive;
    use crate::engine::test_support::make_synthetic_block;

    /// A real [`VerifiedRange`] `[first, first + len)` produced through the **verified
    /// production path** — `verify_exhaustive` over a synthetic chain — rather than the
    /// `genesis_empty` / seal-reconstruct lifecycle constructors. This keeps the tests
    /// honest: a `PReconcileSet` here is built from genuinely verified evidence, not a
    /// hand-forged range.
    fn covered_range(first: u64, len: u64) -> VerifiedRange {
        let mut blocks = Vec::new();
        let mut prev = [0u8; 32];
        for h in first..first + len {
            let sb = make_synthetic_block(h, prev);
            prev = sb.block.hash();
            blocks.push(sb);
        }
        verify_exhaustive(BlockHeight::from_raw(first), [0u8; 32], &blocks)
            .expect("a correctly chained synthetic batch verifies")
            .range()
    }

    fn persona(b: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([b; 32])
    }

    fn post(height: u64, p: u8, kind: u8) -> BondPostMatch {
        BondPostMatch {
            height: BlockHeight::from_raw(height),
            p_canonical_id: persona(p),
            post_kind: kind,
        }
    }

    /// Watch floors for the given `(id byte, floor height)` pairs — the
    /// provenance rows a real sweep would have recorded for personas watched
    /// from those heights.
    fn floors(rows: &[(u8, u64)]) -> BTreeMap<PCanonicalId, BlockHeight> {
        rows.iter()
            .map(|(b, h)| (persona(*b), BlockHeight::from_raw(*h)))
            .collect()
    }

    #[test]
    fn binds_matches_to_their_verified_covered_range() {
        let covered = covered_range(100, 3); // [100, 103)
        let set = PReconcileSet::from_verified_scan(
            covered,
            vec![post(101, 0xAA, 0)],
            floors(&[(0xAA, 0)]),
        );
        assert_eq!(set.covered(), covered);
        assert_eq!(set.matches().len(), 1);
        assert_eq!(set.matches()[0].p_canonical_id, persona(0xAA));
    }

    #[test]
    fn present_for_a_persona_matched_within_covered() {
        let set = PReconcileSet::from_verified_scan(
            covered_range(100, 3),
            vec![post(101, 0xAA, 7)],
            floors(&[(0xAA, 0)]),
        );
        assert_eq!(
            set.reconcile(persona(0xAA), BlockHeight::from_raw(101)),
            ReconcileVerdict::Present {
                height: BlockHeight::from_raw(101),
                post_kind: 7,
            }
        );
    }

    #[test]
    fn absent_within_covered_for_an_unmatched_persona() {
        // Persona 0xBB has no post; queried at a height inside [100, 103) → provably
        // absent, because the range was exhaustively scanned.
        let set = PReconcileSet::from_verified_scan(
            covered_range(100, 3),
            vec![post(101, 0xAA, 0)],
            floors(&[(0xAA, 0), (0xBB, 0)]),
        );
        assert_eq!(
            set.reconcile(persona(0xBB), BlockHeight::from_raw(102)),
            ReconcileVerdict::AbsentWithinCovered
        );
    }

    #[test]
    fn outside_covered_is_distinct_from_absent() {
        // The spine: the SAME unmatched persona gives a DIFFERENT verdict depending on
        // whether the queried height was scanned. Inside → AbsentWithinCovered; outside
        // → OutsideCovered. "Not found" must never collapse into "absent" off-range.
        let set = PReconcileSet::from_verified_scan(
            covered_range(100, 3), // [100, 103)
            vec![post(101, 0xAA, 0)],
            floors(&[(0xAA, 0), (0xBB, 0)]),
        );
        let unmatched = persona(0xBB);
        assert_eq!(
            set.reconcile(unmatched, BlockHeight::from_raw(101)),
            ReconcileVerdict::AbsentWithinCovered,
            "in-range absence is a real claim"
        );
        assert_eq!(
            set.reconcile(unmatched, BlockHeight::from_raw(500)),
            ReconcileVerdict::OutsideCovered,
            "off-range, the same 'not found' is unknown, not absent"
        );
    }

    #[test]
    fn presence_is_any_post_in_covered_not_an_as_of_filter() {
        // The persona's only post lands AFTER the asserted evidence_height. It must read
        // Present — a temporal "absent if posted after evidence_height" filter would
        // wrongly GC a real persona (permanent stuck funds). Presence = posted anywhere
        // in covered.
        let set = PReconcileSet::from_verified_scan(
            covered_range(0, 10),   // [0, 10)
            vec![post(7, 0xAA, 0)], // the persona's post is at height 7
            floors(&[(0xAA, 0)]),
        );
        assert_eq!(
            set.reconcile(persona(0xAA), BlockHeight::from_raw(2)), // asserted as of height 2
            ReconcileVerdict::Present {
                height: BlockHeight::from_raw(7),
                post_kind: 0,
            },
            "a post anywhere in covered is Present, even when it lands after evidence_height"
        );
        // The covered gate still applies: a height the scan didn't reach is OutsideCovered.
        assert_eq!(
            set.reconcile(persona(0xAA), BlockHeight::from_raw(50)),
            ReconcileVerdict::OutsideCovered
        );
    }

    #[test]
    fn covered_boundaries_are_half_open() {
        let set =
            PReconcileSet::from_verified_scan(covered_range(100, 3), vec![], floors(&[(0xCC, 0)])); // [100,103)
        let p = persona(0xCC);
        // low (100) is inside; low-1 (99) is outside.
        assert_eq!(
            set.reconcile(p, BlockHeight::from_raw(100)),
            ReconcileVerdict::AbsentWithinCovered
        );
        assert_eq!(
            set.reconcile(p, BlockHeight::from_raw(99)),
            ReconcileVerdict::OutsideCovered
        );
        // high-1 (102) is inside; high (103) is outside (half-open).
        assert_eq!(
            set.reconcile(p, BlockHeight::from_raw(102)),
            ReconcileVerdict::AbsentWithinCovered
        );
        assert_eq!(
            set.reconcile(p, BlockHeight::from_raw(103)),
            ReconcileVerdict::OutsideCovered
        );
    }

    /// The full-scan form: empty covered ⇒ `OutsideCovered` (never GC);
    /// non-empty ⇒ identical to `reconcile` at the last covered height.
    #[test]
    fn reconcile_full_scan_gates_on_coverage() {
        use crate::engine::pscan::exhaustiveness::VerifiedBatch;
        let persona = PCanonicalId::from_bytes([9; 32]);
        let empty = PReconcileSet::from_verified_scan(
            VerifiedBatch::for_test(0, 0, [1; 32]).range(),
            Vec::new(),
            floors(&[(9, 0)]),
        );
        assert_eq!(
            empty.reconcile_full_scan(persona),
            ReconcileVerdict::OutsideCovered
        );
        let covered = PReconcileSet::from_verified_scan(
            VerifiedBatch::for_test(0, 42, [1; 32]).range(),
            Vec::new(),
            floors(&[(9, 0)]),
        );
        assert_eq!(
            covered.reconcile_full_scan(persona),
            covered.reconcile(persona, BlockHeight::from_raw(41))
        );
        assert_eq!(
            covered.reconcile_full_scan(persona),
            ReconcileVerdict::AbsentWithinCovered
        );
    }

    /// The provenance gate (SA-R-6 bond-watch review): "no match row" for a
    /// persona that was never watched, or below the height it entered the
    /// watch, is NOT absence — it reads `OutsideCovered`. This is the exact
    /// probe-adoption shape: coverage advanced over the bond's blocks before
    /// the persona joined the scan union, so the match set cannot contain its
    /// post and an absence verdict would GC a real bond.
    #[test]
    fn absence_requires_the_persona_watched_over_the_queried_height() {
        let set = PReconcileSet::from_verified_scan(
            covered_range(0, 200),  // [0, 200) — coverage well past the bond
            vec![],                 // no match rows: the bond was never watched-scanned
            floors(&[(0xAA, 150)]), // 0xAA joined the union at 150
        );
        // Below the floor: covered, but unwatched for this persona → unknown.
        assert_eq!(
            set.reconcile(persona(0xAA), BlockHeight::from_raw(50)),
            ReconcileVerdict::OutsideCovered,
            "covered-but-unwatched must not read as absent"
        );
        // At/above the floor: watched and covered → a real absence claim.
        assert_eq!(
            set.reconcile(persona(0xAA), BlockHeight::from_raw(150)),
            ReconcileVerdict::AbsentWithinCovered
        );
        // A persona with no floor row at all was never watched → unknown at
        // every height, including via the full-scan form.
        assert_eq!(
            set.reconcile(persona(0xBB), BlockHeight::from_raw(50)),
            ReconcileVerdict::OutsideCovered
        );
        assert_eq!(
            set.reconcile_full_scan(persona(0xBB)),
            ReconcileVerdict::OutsideCovered,
            "the full-scan form must not manufacture absence for an unwatched persona"
        );
    }

    /// `Present` is positive evidence and is never suppressed by the
    /// provenance gate: a match row proves the post regardless of when the
    /// persona joined the watch.
    #[test]
    fn presence_is_not_gated_by_the_watch_floor() {
        let set = PReconcileSet::from_verified_scan(
            covered_range(0, 200),
            vec![post(30, 0xAA, 0)],
            floors(&[(0xAA, 150)]),
        );
        assert_eq!(
            set.reconcile(persona(0xAA), BlockHeight::from_raw(50)),
            ReconcileVerdict::Present {
                height: BlockHeight::from_raw(30),
                post_kind: 0,
            }
        );
    }
}
