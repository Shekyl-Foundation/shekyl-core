// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 2d-1 SP-7 — [`CoverDiscovery`]: the **funding-side completeness gate** that closes
//! `TM-3` (the induced cold-start re-link).
//!
//! The funding-side twin of SP-6's [`PReconcileSet`](super::reconcile::PReconcileSet).
//! SP-6 gave the *reconcile* a `covered` range so it never GCs on a withheld block;
//! cold-start cover-discovery needs the same defense. The attack: a withholding C3 source
//! serves every block **except** the one carrying `P`'s cold-start cover output. The scan
//! looks complete, `P` concludes its funding never arrived, and `P` **re-funds from the
//! principal** — a *second* cold-start event on the attacker's infrastructure, correlated
//! with the first. The attacker induces the exact re-link the cover exists to prevent, by
//! controlling availability rather than breaking crypto
//! (`ARCHIVAL_FIREWALL_THREATS.md` A2 / `TM-3`).
//!
//! ## The verdict is a wrap, not a new scan
//!
//! Cover *identification* is already guaranteed: the FA-6 view-tag pre-filter is
//! false-negative-free (the tag derives from a single shared-secret recompute called
//! identically by sender and scanner), so the funding scan **cannot reject an owned
//! output** (`shekyl-scanner/src/scan.rs` recovery path). So SP-7 does not build cover
//! identification — it **wraps** the existing funding-scan result together with SP-6's
//! [`VerifiedRange`] into the three-valued verdict, the funding-side mirror of
//! [`PReconcileSet::reconcile`](super::reconcile::PReconcileSet::reconcile):
//!
//! - **`Found`** — the cover matched (within the scanned range).
//! - **`AbsentVerified`** — the cover-expected window is **within** a `VerifiedRange` and
//!   the cover was not found: provably absent, not merely undelivered.
//! - **`Incomplete`** — the window is not (yet) within `covered`: a gap the source may be
//!   withholding. **Wait, never re-fund.**
//!
//! Gate-first, exactly like SP-6: `AbsentVerified` is produced **only** when the whole
//! cover window was exhaustively scanned — the funding-side "absence concludable only
//! within `covered`."
//!
//! ## Why exhaustiveness is not enough — the tip-currency token
//!
//! [`verify_exhaustive`](super::exhaustiveness::verify_exhaustive) catches a *gap* (a
//! stripped cover-tx breaks continuity → `Incomplete`), but **not** a complete-but-stale
//! or fork chain: a self-consistent prefix or fork where the cover is genuinely absent on
//! the served chain yet present on the real current one. `verify_exhaustive` *passes* on
//! the fork, so `AbsentVerified` is true for the served chain and wrong for the network.
//! Therefore `AbsentVerified` **alone cannot authorize a re-fund** — it needs a
//! [`TipCurrencyToken`] certifying the served chain is current. This is exactly SP-6's GC
//! needing a canonicity token alongside `AbsentWithinCovered`: same shape, same handoff.
//! Cover-discovery is the one **non-lag-tolerant** consumer (it decides at cold-start,
//! time-sensitively, where a withholding source attacks by claiming a stale tip and hiding
//! the cover above it), which is *why* tip-currency is SP-7's load-bearing 2d-2 dependency
//! and not a footnote.
//!
//! ## Why `Found` needs no token — the asymmetry is deliberate
//!
//! `AbsentVerified` is token-gated; `Found` is not, and `classify` returns `Found` for any
//! recovered cover regardless of `covered`. That is intentional. The symmetric attack is a
//! **fork-cover**: a source serves a cover present on a served fork but absent on the
//! canonical chain, so `P` sees `Found` and proceeds. The wrong-`Found` harm is **bounded
//! and detectable**, categorically unlike the wrong-`AbsentVerified` silent re-link — which
//! is *exactly* why the token gates one side and not the other:
//!
//! - **Posture-resolved** — a trusted node (①/②) serves the canonical chain; an untrusted
//!   remote (③) is the same bounded-risk posture as everywhere else in 2d-2.
//! - **Finality-gated** — `P` cannot spend the cover until it is finality-deep, so a
//!   transient fork reorgs out before the spend.
//! - **Detectable, not silent** — spending a fork-only cover produces a bond-post invalid
//!   on the canonical chain: the stake **visibly fails** (a loud error), not a silent
//!   origin correlation.
//!
//! So wrong-`Found` is a detectable stake failure; wrong-`AbsentVerified` is a silent,
//! permanent re-link. The token gates the silent-and-irreversible side, and only that side.
//!
//! ## And even then — surface, never auto-re-fund
//!
//! A re-fund input requires `AbsentVerified` **plus** a tip-currency token
//! ([`CoverDiscovery::refund_consideration`]); `Incomplete` and token-less absence cannot
//! produce one, so "re-fund on a gap" and "re-fund on exhaustive-but-stale evidence" are
//! both *unrepresentable*. Even a valid consideration is **routed to an operator
//! decision**, never an auto-re-fund — auto-re-fund is precisely the induced relink `TM-3`
//! describes. A prolonged `Incomplete` **surfaces** ("your funding source may be stale or
//! withholding"); there is no timeout path that manufactures a re-fund.

use shekyl_types::BlockHeight;

use super::exhaustiveness::VerifiedRange;
use super::scan_step::BlockRange;

/// The minimal public descriptor that `P`'s cold-start cover funding **arrived**. The
/// gate only needs "arrived" (don't re-fund); the height is diagnostic — but it is a row
/// of `P`'s cold-start cover-funding history (persona-sensitive even though on-chain
/// public), so it carries a **redacting `Debug`**, the same discipline as
/// [`BondPostMatch`](super::scan_step::BondPostMatch). The cover output itself stays in
/// the actor's funding state; this only signals it arrived.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // transient — the cold-start lifecycle is the lib consumer (unwired).
pub(crate) struct CoverFound {
    height: BlockHeight,
}

impl std::fmt::Debug for CoverFound {
    /// Redacted — the cover-funding height is `P`'s cold-start funding moment, persona
    /// history that must not leak through a log / `{:?}` path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoverFound(<redacted persona-history>)")
    }
}

#[allow(dead_code)] // transient — the cold-start lifecycle is the lib consumer.
impl CoverFound {
    /// The cover was found at `height`.
    pub(crate) fn at(height: BlockHeight) -> Self {
        Self { height }
    }

    /// The (diagnostic) height the cover funded at.
    pub(crate) fn height(&self) -> BlockHeight {
        self.height
    }
}

/// Proof that `P`'s tip is **current** — the served chain is the network's current chain,
/// not a stale/truncated prefix or a fork. The funding-side analog of SP-6's canonicity
/// token (see the module docs on why exhaustiveness alone is insufficient).
///
/// **Posture-supplied.** A trusted node (postures ①/②) supplies it *by trust* — a trusted
/// node's reported tip is taken as current, so the re-fund gate works in trusted postures
/// **now**. An untrusted remote (posture ③) needs the 2d-2 §4 multi-source tip
/// cross-check; that producer is **deferred** (rule-21 reopen criterion: 2d-2 §4
/// posture/tip-currency machinery lands). The token *type* exists now so the gate's
/// signature can require it, making "re-fund on exhaustive-but-stale evidence"
/// unrepresentable at the boundary regardless of when ③'s producer arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // transient — ③ producer is 2d-2 §4; trusted producer wired at cold-start.
pub(crate) struct TipCurrencyToken {
    basis: TipBasis,
}

/// How a [`TipCurrencyToken`] was justified. Only `TrustedNode` is constructible in 2d-1;
/// the multi-source basis (posture ③) is a 2d-2 §4 obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // transient — MultiSource (③) lands with 2d-2 §4.
enum TipBasis {
    /// Postures ①/②: a local or own-remote **trusted** node's tip is taken as current.
    TrustedNode,
}

#[allow(dead_code)] // transient — the trusted producer is wired at cold-start; ③ is 2d-2 §4.
impl TipCurrencyToken {
    /// Trusted-posture (①/②) token: a trusted node's reported tip is taken as current. The
    /// *only* basis 2d-1 supplies; posture ③'s multi-source token is 2d-2 §4.
    pub(crate) fn trusted_node() -> Self {
        Self {
            basis: TipBasis::TrustedNode,
        }
    }
}

/// The cold-start cover-discovery verdict (the funding-side twin of SP-6's reconcile). See
/// the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // transient — the cold-start lifecycle is the lib consumer (unwired).
pub(crate) enum CoverDiscovery {
    /// The cover arrived (found within the scanned range) — no re-fund.
    Found(CoverFound),
    /// The cover-expected window was **exhaustively scanned** (within this
    /// [`VerifiedRange`]) and the cover was **not** found — provably absent, not merely
    /// undelivered. A re-fund input *only* when paired with a [`TipCurrencyToken`].
    AbsentVerified(VerifiedRange),
    /// The view is not (yet) provably complete over the cover window — a gap the source
    /// may be withholding. **Wait**; surface if prolonged; **never** a re-fund input.
    Incomplete,
}

#[allow(dead_code)] // transient — the cold-start lifecycle is the lib consumer.
impl CoverDiscovery {
    /// Classify the cold-start cover from the funding-scan result (`cover_found` — the
    /// height the false-negative-free scan recovered the cover at, or `None`) and SP-6's
    /// `covered` range, over the `cover_window` where the cover could appear.
    ///
    /// **Gate-first** (the funding-side "absence concludable only within `covered`"):
    /// `AbsentVerified` is returned **only** when the *whole, non-empty* `cover_window`
    /// lies within `covered`. A window reaching beyond the verified frontier is
    /// `Incomplete` (wait), never `AbsentVerified` — otherwise a source could induce a
    /// re-fund by serving an exhaustive range that simply does not reach the cover's
    /// height.
    ///
    /// `cover_found` and `covered` must come from the **same scan** — that consistency is
    /// the producer's (call-site's) obligation; the *consumer* sees only the bound
    /// [`CoverDiscovery`] / [`RefundConsideration`], never the raw inputs.
    pub(crate) fn classify(
        cover_window: BlockRange,
        cover_found: Option<BlockHeight>,
        covered: VerifiedRange,
    ) -> Self {
        // An empty `cover_window` is a caller bug (the cover must have *somewhere* to
        // appear). Catch it loudly in dev, AND fail closed in release via the non-empty
        // check in the `AbsentVerified` gate below — never mint a vacuous "provably absent
        // over an empty window," which would open a `RefundConsideration` path on nonsense.
        debug_assert!(
            cover_window.start() < cover_window.end(),
            "cover_window must be non-empty (the range where the cover could appear)"
        );
        if let Some(height) = cover_found {
            // A recovered cover is conclusive wherever it sits (presence is unconditional —
            // see the module doc on why `Found` needs no token), but it should fall within
            // the queried window: a tripwire for a scan/window misalignment.
            debug_assert!(
                cover_window.start() <= height && height < cover_window.end(),
                "recovered cover height outside the cover window (scan/window misalignment)"
            );
            return Self::Found(CoverFound::at(height));
        }
        // Not found. Provably absent ONLY if the entire, **non-empty** window was
        // exhaustively scanned. An empty window fails the first conjunct and falls to
        // `Incomplete` — the release fail-closed for the dev `debug_assert` above.
        if cover_window.start() < cover_window.end()
            && covered.low() <= cover_window.start()
            && cover_window.end() <= covered.high()
        {
            Self::AbsentVerified(covered)
        } else {
            Self::Incomplete
        }
    }

    /// The **only** path to a re-fund consideration: `AbsentVerified` (provably absent in a
    /// verified range) **plus** a [`TipCurrencyToken`] (the served chain is current).
    ///
    /// Returns `None` for `Found` (nothing to re-fund), `Incomplete` (a withheld gap), and
    /// `AbsentVerified` **without** a token (exhaustive but not provably current — a fork
    /// or stale tip). So "re-fund on a gap" and "re-fund on exhaustive-but-stale evidence"
    /// are both unrepresentable. A returned [`RefundConsideration`] is still only a
    /// *consideration* — the consumer routes it to an operator decision, never an
    /// auto-re-fund (`TM-3`).
    pub(crate) fn refund_consideration(
        self,
        tip: Option<TipCurrencyToken>,
    ) -> Option<RefundConsideration> {
        match (self, tip) {
            (Self::AbsentVerified(covered), Some(token)) => Some(RefundConsideration {
                covered,
                _tip: token,
            }),
            _ => None,
        }
    }
}

/// Proof that a cold-start re-fund **may be considered**: the cover is provably absent
/// over a [`VerifiedRange`] **and** the served chain is current (a [`TipCurrencyToken`]).
/// Constructible **only** via [`CoverDiscovery::refund_consideration`] from an
/// `AbsentVerified` verdict plus a token — there is no path from `Incomplete` or from
/// token-less absence.
///
/// **A consideration is not an authorization.** The consumer surfaces it to the operator
/// (the original funding tx likely never confirmed → retry-broadcast it, or decide to
/// re-fund) — it must **never** auto-mint a second cold-start link, which is the induced
/// relink `TM-3` exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // transient — the cold-start operator-surface is the lib consumer.
pub(crate) struct RefundConsideration {
    covered: VerifiedRange,
    // Held as proof the served chain was certified current. `_`-prefixed: the verdict it
    // gated is the value; the token need not be re-read, only required to construct this.
    _tip: TipCurrencyToken,
}

#[allow(dead_code)] // transient — the cold-start operator-surface is the lib consumer.
impl RefundConsideration {
    /// The verified range over which the cover was provably absent (for the operator
    /// surface: "no cover in `[low, high)`, on a chain certified current").
    pub(crate) fn covered(&self) -> VerifiedRange {
        self.covered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::pscan::exhaustiveness::verify_exhaustive;
    use crate::engine::test_support::make_synthetic_block;

    /// A real [`VerifiedRange`] `[first, first + len)` through the verified path (the
    /// production way to get one — not a hand-forged range).
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

    fn window(start: u64, end: u64) -> BlockRange {
        BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end)).expect("range")
    }

    #[test]
    fn found_when_the_cover_was_recovered() {
        let v = CoverDiscovery::classify(
            window(100, 110),
            Some(BlockHeight::from_raw(104)),
            covered_range(0, 200),
        );
        assert_eq!(
            v,
            CoverDiscovery::Found(CoverFound::at(BlockHeight::from_raw(104)))
        );
    }

    #[test]
    fn absent_verified_only_when_the_whole_window_is_covered() {
        // Window [100, 110) entirely within covered [0, 200), cover not found → provably
        // absent.
        let v = CoverDiscovery::classify(window(100, 110), None, covered_range(0, 200));
        assert!(matches!(v, CoverDiscovery::AbsentVerified(_)), "got {v:?}");
    }

    #[test]
    fn incomplete_when_the_window_reaches_beyond_covered() {
        // Covered only [0, 105); the window [100, 110) reaches past the verified frontier,
        // so the cover's possible heights [105, 110) were NOT exhaustively scanned. Absence
        // is NOT a claim we may make — Incomplete, never AbsentVerified (the gate that
        // stops a source inducing a re-fund by under-serving the window's tail).
        let v = CoverDiscovery::classify(window(100, 110), None, covered_range(0, 105));
        assert_eq!(v, CoverDiscovery::Incomplete);
    }

    #[test]
    #[should_panic(expected = "cover_window must be non-empty")]
    fn empty_cover_window_is_rejected_in_dev() {
        // An empty window is a caller bug: it would vacuously satisfy whole-window
        // containment and mint AbsentVerified (→ a re-fund path on nonsense). The dev
        // debug_assert rejects it loudly; the non-empty conjunct in the AbsentVerified gate
        // is the release fail-closed (→ Incomplete) behind it.
        let _ = CoverDiscovery::classify(window(100, 100), None, covered_range(0, 200));
    }

    #[test]
    fn refund_consideration_needs_absent_verified_and_a_token() {
        let absent = CoverDiscovery::classify(window(100, 110), None, covered_range(0, 200));
        // AbsentVerified + a trusted-posture token → a consideration (works now).
        assert!(absent
            .refund_consideration(Some(TipCurrencyToken::trusted_node()))
            .is_some());
        // AbsentVerified WITHOUT a token (exhaustive but not provably current) → none.
        assert!(absent.refund_consideration(None).is_none());
    }

    #[test]
    fn neither_incomplete_nor_found_can_produce_a_refund_consideration() {
        // Incomplete: even with a token, no consideration — "re-fund on a withheld gap" is
        // unrepresentable.
        assert!(CoverDiscovery::Incomplete
            .refund_consideration(Some(TipCurrencyToken::trusted_node()))
            .is_none());
        // Found: nothing to re-fund.
        assert!(
            CoverDiscovery::Found(CoverFound::at(BlockHeight::from_raw(1)))
                .refund_consideration(Some(TipCurrencyToken::trusted_node()))
                .is_none()
        );
    }

    #[test]
    fn cover_found_debug_is_redacted() {
        let rendered = format!("{:?}", CoverFound::at(BlockHeight::from_raw(123_456)));
        assert!(rendered.contains("redacted"), "must redact: {rendered}");
        assert!(
            !rendered.contains("123456"),
            "the funding height must not appear: {rendered}"
        );
    }
}
