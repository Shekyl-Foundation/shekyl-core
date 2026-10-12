// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`alt_against`]: the alt tier — an alternative block judged against the
//! chain it extends (DRS-E5 slice 9, `DRS_E5_POOL_ALT_PRUNE.md` §2.1).
//!
//! # The cheap tier makes no chain-state read
//!
//! An alternative block's chain has not been executed: the recorded chain
//! to the fork point, then alt entries whose bodies no store has applied.
//! Such a chain can answer **header** questions — a parent's hash,
//! timestamp, cumulative difficulty — and no other. So this tier runs the
//! [`HeaderRule`](crate::rules::HeaderRule)s of `validate`'s ladder, the
//! three rows only an alternative has ([`rules::alt`](crate::rules::alt):
//! CEN-K1b, CEN-E2, CEN-D5), and nothing whose operand is chain state —
//! which set, in which order, is itself a row (CEN-K4, recorded when the
//! ladder ends). Any
//! check that reads executed state — a bonded key, a bond snapshot, a tree
//! root, a key image — is **promotion-tier**, on the ground `DRS_E5` §2.1
//! already gives CEN-B5: an unexecuted alternative cannot answer it, and
//! promotion validates every block of the alternative against executed
//! state through `validate`, where the read is correct and costs nothing
//! extra (`E5-Q4`, ruled β 2026-10-11). The attestation set (CEN-B4) is
//! such a check and has no step here; the witness the candidate carries
//! rides to the store unjudged, for promotion to judge.
//!
//! The bound is the belt: a view that implements only
//! [`HeaderView`](crate::HeaderView) — the store's `AltView` — cannot be
//! handed to a `BlockRule`, and this function's signature cannot name
//! `ChainView`. Nothing judged here is a [`ChainValid`](crate::ChainValid)
//! and nothing converts an [`AltValid`] into one.
//!
//! # What the caller derives
//!
//! Two inputs no header view states. The **view** is the stitched chain:
//! `tip()` is the candidate's parent and `header_at(h)` the recorded row at
//! or below the fork point, the alt entry above it. The **fork** is where
//! the alternative leaves the recorded chain and where that chain ends
//! ([`Fork`]) — CEN-E2's operands, derived by the store from the same
//! snapshot the view reads (`AltView::fork`).
//!
//! # The ladder
//!
//! The C++'s `handle_alternative_block` (`blockchain.cpp:1974`–`:2358`), in
//! its order where the order is a rule: the height-0 claim first
//! (CEN-K1b, before any header is read); the anchor floor and reorg cap
//! (CEN-E2, before any header is read); then the definitions over the
//! stitched view — the seed (CEN-D3), the newest-11 window (CEN-C3, the
//! C++'s `timestamps.resize(11)`), the target (CEN-D5 over D4, D6 the zero
//! guard), the cumulative difficulty after the block — and the header
//! predicates in census order: C1, C2, D1 (PoW at the alt target), E1, F4,
//! F5, F6. The expensive step, the longhash, is `form`'s and has been paid
//! before this tier is reached, so the cheap exits here save header reads,
//! not hashing.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, BlockWeight};

use crate::block::{Candidate, StructurallyValid};
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, Stale};
use crate::rule_set::RuleSet;
use crate::rules::alt::{K1b, D5, E2, K4};
use crate::rules::anchors::E1;
use crate::rules::block_weight::block_weight;
use crate::rules::difficulty::D4;
use crate::rules::miner::{F4, F5, F6};
use crate::rules::pow::{D1b, D1, D3};
use crate::rules::timestamps::{C1, C2, C3};
use crate::rules::{self, BlockContext, FormContext};
use crate::trust::Trust;
use crate::verdict::Verdict;
use crate::view::{HeaderView, Tip};

/// Where an alternative chain leaves the recorded one, and where the
/// recorded one ends — CEN-E2's operands.
///
/// `root` is the last recorded block the alternative shares (the store's
/// `AltChain::root`); `recorded_tip` is the recorded chain's tip in the
/// same snapshot. The blocks the alternative would pop are
/// `recorded_tip.height − root.height`. Both halves come from one
/// snapshot: a root from one read and a tip from another can disagree,
/// and a root above the tip is read as popping nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fork {
    /// The fork point: a recorded block, at or below `recorded_tip`.
    pub root: Tip,
    /// The recorded chain's tip.
    pub recorded_tip: Tip,
}

/// An alternative block the cheap tier admitted: what the store's AL1
/// records (`DRS_E5` §2.1, `AltBlockFacts`), and nothing more.
///
/// Not a [`ChainValid`](crate::ChainValid), and nothing converts it into
/// one: the rows evaluated are the header rules and the alt arms
/// ([`coverage`](Self::coverage) says which), and a block this admits is
/// re-judged in full by `validate` when its chain is promoted. Carries no
/// brand — the view it was judged against is a stitched chain, not a
/// batch, and the store accepts it only into the alt table.
///
/// The derived facts are the candidate's position and work — the
/// connecting height the stitched view derived, the cumulative difficulty
/// after it, the wire weight of the bodies it carries. No supply figure:
/// the parent's `coins_generated` is executed-chain state this tier does
/// not read (CEN-K8), so the row has no honest value for one.
pub struct AltValid {
    candidate: Candidate,
    hash: BlockHash,
    height: BlockHeight,
    cumulative_difficulty: CumulativeDifficulty,
    block_weight: BlockWeight,
    rule_set: RuleSet,
    coverage: RuleCoverage,
}

impl core::fmt::Debug for AltValid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AltValid")
            .field("hash", &self.hash)
            .field("height", &self.height)
            .field("cumulative_difficulty", &self.cumulative_difficulty)
            .field("block_weight", &self.block_weight)
            .field("rule_set", &self.rule_set)
            .field("coverage", &self.coverage)
            .finish_non_exhaustive()
    }
}

impl AltValid {
    /// The block as received: header, miner transaction, listed bodies
    /// and the attestation witness beside it.
    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// The candidate, consumed — the bodies are the pool's to hold until
    /// promotion; the block is the alt row's.
    #[must_use]
    pub fn into_candidate(self) -> Candidate {
        self.candidate
    }

    /// The block's identity (CEN-B6, derived by `form`).
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The height the stitched chain derives for the block: its parent's
    /// plus one — never the coinbase's claim (CEN-F5 compared the two).
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// The alternative chain's cumulative difficulty through this block:
    /// the parent's plus the target the block met (CEN-D5/D1).
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> CumulativeDifficulty {
        self.cumulative_difficulty
    }

    /// The wire weight of the coinbase and every listed body the candidate
    /// carries — a measurement of the bytes, bounded by no median here.
    #[must_use]
    pub const fn block_weight(&self) -> BlockWeight {
        self.block_weight
    }

    /// The rule set the block was judged under.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSet {
        self.rule_set
    }

    /// The rows this tier evaluated and the block passed. A subset of the
    /// census by design — the header rules and the alt arms — and never
    /// parity evidence for the block: that is promotion's `ChainValid`.
    #[must_use]
    pub const fn coverage(&self) -> &RuleCoverage {
        &self.coverage
    }
}

/// Run the listed header rules in order; the first refusal is the verdict.
/// A [`ViewRead`](crate::ViewRead) becomes [`Fault`] through [`From`].
macro_rules! judge_header {
    ($cx:expr, $view:expr, $coverage:expr; $($rule:ty),+ $(,)?) => {
        $(
            if let Err(refused) =
                rules::run_header::<$rule, H>(&$cx, $view, &mut $coverage).map_err(Fault::from)?
            {
                return Ok(Err(refused));
            }
        )+
    };
}

/// The alt tier: judge a [`StructurallyValid`] block against the
/// alternative chain `alt_view` stitches, under `rule_set` and `trust`,
/// for the fork `fork` describes.
///
/// `formed` is `form`'s token for the same candidate, under the same
/// `rule_set` and with the seed claim read from the alternative chain (the
/// seed height may itself be an alt entry; the stitched view answers it,
/// as the C++'s `get_block_id_by_height` over the alt chain did,
/// `blockchain.cpp:2089`–`:2101`). The rule-set claim is checked as
/// `validate` checks it, and a mismatch is [`Stale::RuleSet`], not a
/// verdict; the seed claim is CEN-D3's.
///
/// `Ok(Ok(valid))`: every header rule and alt arm passed, and `valid` is
/// what AL1 stores. `Ok(Err(refused))`: the first row that refused, at its
/// locus. `Err(fault)`: the view could not answer, answered with a hole
/// or with bytes no conforming store holds, or a claim went stale.
///
/// # Errors
///
/// [`Fault::View`] on the view's own fault; [`Fault::Corrupt`] when the
/// stitched chain is not the chain it claims (a hole below the parent, a
/// non-monotone cumulative difficulty); [`Fault::Stale`] when `formed`'s
/// rule set or seed is not this view's.
pub fn alt_against<'id, H: HeaderView<'id>>(
    formed: StructurallyValid,
    alt_view: &H,
    fork: &Fork,
    rule_set: &RuleSet,
    trust: &Trust,
) -> Result<Verdict<AltValid>, Fault<H::Fault>> {
    if formed.rule_set() != *rule_set {
        return Err(Fault::Stale(Stale::RuleSet {
            formed_under: Box::new(formed.rule_set()),
            in_force: Box::new(*rule_set),
            retry: formed.attempt().next(),
        }));
    }

    let mut coverage = *formed.coverage();

    // Before any header is read: the height-0 claim (CEN-K1b, the C++'s
    // first exit) and the two bands over the fork (CEN-E2). Neither reads
    // the view; both are the cheapest refusals the tier has.
    let form_cx = FormContext::new(formed.candidate(), rule_set);
    if let Err(refused) = rules::run_form::<K1b>(&form_cx, &mut coverage) {
        return Ok(Err(refused));
    }
    if let Err(refused) = E2::check(fork, rule_set, trust, &mut coverage) {
        return Ok(Err(refused));
    }

    // The definitions over the stitched chain, as `validate` derives them
    // over the recorded one: the connecting height from the view's tip
    // (the parent, so `root + 1 + entries` — CEN-K1a's `≥ 1` is the
    // store's construction), the seed, the newest-11 window, the target
    // (CEN-D5 over D4; D6's zero guard refuses), the work after the block.
    let tip = alt_view.tip().map_err(Fault::View)?;
    let connecting = Tip::connecting_height(tip.as_ref());
    D3::verify_seed(alt_view, connecting, &formed, &mut coverage)?;
    let mtp_window = C3::window(alt_view, connecting, &mut coverage)?;
    let target = match D5::target(alt_view, connecting, rule_set, &mut coverage)? {
        Ok(target) => target,
        Err(refused) => return Ok(Err(refused)),
    };
    let cumulative_difficulty = D4::cumulative_after(alt_view, connecting, target)?;
    D1b::record(&mut coverage);

    // The header predicates, in census order (`DRS_E5` §2.1, CEN-K4's
    // ladder): no A2 (the parent is the view's tip by construction of the
    // chain), no B5 and no B4 (chain-state reads; promotion's), no body
    // rule and no slot loop (nothing here has a body the chain executed).
    let cx = BlockContext::new(&formed, tip, mtp_window, target, trust);
    judge_header!(cx, alt_view, coverage; C1, C2, D1, E1, F4, F5, F6);

    // The ladder ran to its end: the block is accepted into storage after
    // these rows and no other (CEN-K4 — the tier is the row).
    K4::record(&mut coverage);

    let hash = formed.hash();
    let block_weight = block_weight(formed.candidate());
    let (candidate, _stateless) = formed.into_parts();
    Ok(Ok(AltValid {
        candidate,
        hash,
        height: connecting,
        cumulative_difficulty,
        block_weight,
        rule_set: *rule_set,
        coverage,
    }))
}

#[cfg(test)]
#[path = "alt_tests.rs"]
mod tests;
