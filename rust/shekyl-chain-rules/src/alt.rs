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
//! # What the caller derives, and what the view must say itself
//!
//! The **view** is the stitched chain: `tip()` is the candidate's parent
//! and `header_at(h)` the recorded row at or below the fork point, the alt
//! entry above it. The **fork** is where the alternative leaves the
//! recorded chain and where that chain ends ([`Fork`]) — CEN-E2's
//! operands. Both come from one snapshot, and the view states the fork
//! ([`AltChainView::fork`]) rather than the caller passing it beside the
//! view: a fork from one read and a chain from another could describe two
//! different alternatives, and E2 would then judge a pop the chain does
//! not cause. The type makes that pair unrepresentable; the store's
//! `AltView` answers from the `AltChain` it was built over.
//!
//! The one relation the view cannot state is that it was built for *this*
//! candidate. The store derives the chain from the candidate's `previous`,
//! but this function sees a view and a token, not that derivation, so the
//! ladder's first header predicate is CEN-A2 — the candidate's `previous`
//! is the tip's hash — as it is `validate`'s. A view handed over for
//! another block refuses at A2 and mints nothing; on the store's path the
//! row costs one comparison and never fires.
//!
//! The verdict is branded to the view type that minted it, as
//! [`ChainValid`](crate::ChainValid) is. The store's `insert_alt_block`
//! names its `AltView`, so a verdict from any other `AltChainView` does
//! not unify with the row it would write. The tier and the write stay two
//! operations: a later switch judges on a snapshot, then pops, then
//! inserts, and the token has to exist between those steps.
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
//! predicates in census order, the header ladder's three segments — A2,
//! then C1, C2, D1, then E1, F4, F5, F6 — which `validate` runs with its
//! chain-state rules between the calls. The expensive step, the
//! longhash, is `form`'s and has been paid before this tier is reached, so
//! the cheap exits here save header reads, not hashing.

use core::marker::PhantomData;

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, BlockWeight};

use crate::block::{Candidate, StructurallyValid};
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, Stale};
use crate::header_ladder::{self, HeaderFacts};
use crate::rule_set::RuleSet;
use crate::rules::alt::{K1b, D5, E2, K4};
use crate::rules::block_weight::block_weight;
use crate::rules::{self, FormContext};
use crate::trust::Trust;
use crate::verdict::{Brand, Verdict};
use crate::view::{HeaderView, Tip};

/// The alt tier's view: a [`HeaderView`] over a stitched alternative chain
/// that also states the [`Fork`] it describes.
///
/// `fork()` and the header reads answer from one snapshot — the store's
/// `AltView` holds the `AltChain` the walk built and the recorded tip it
/// read first. There is no constructor-side way to pair a chain with a
/// fork from another read, which is why [`alt_against`] takes the view and
/// nothing beside it for E2's operands.
pub trait AltChainView<'id>: HeaderView<'id> {
    /// Where this chain leaves the recorded one, and where the recorded one
    /// ends, on the snapshot the chain was built over.
    fn fork(&self) -> Fork;
}

/// A root placed above the recorded tip. Not a fork: the span of recorded
/// blocks it would pop is not a [`BlockCount`](shekyl_types::BlockCount).
///
/// [`Fork::new`] is the only constructor, so this pair cannot be judged.
/// The store's `AltChain::build` reports the same pair as SI-7 on
/// `block_heights` — the height came from `height_of` — before a [`Fork`]
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvertedFork {
    /// The claimed fork point.
    pub root: Tip,
    /// The recorded tip it sits above.
    pub recorded_tip: Tip,
}

/// Where an alternative chain leaves the recorded one, and where the
/// recorded one ends — CEN-E2's operands.
///
/// `root` is the last recorded block the alternative shares (the store's
/// `AltChain::root`); `recorded_tip` is the recorded chain's tip in the
/// same snapshot. The blocks the alternative would pop are
/// [`pops`](Self::pops): `recorded_tip.height − root.height`. A root above
/// the tip is not a value ([`Fork::new`] returns [`InvertedFork`]); the
/// saturated zero that used to admit it is not a span this type can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fork {
    root: Tip,
    recorded_tip: Tip,
}

impl Fork {
    /// `root` at or below `recorded_tip`. A root above the tip is
    /// [`InvertedFork`].
    pub const fn new(root: Tip, recorded_tip: Tip) -> Result<Self, InvertedFork> {
        if root.height.to_raw() > recorded_tip.height.to_raw() {
            Err(InvertedFork { root, recorded_tip })
        } else {
            Ok(Self { root, recorded_tip })
        }
    }

    /// The fork point: a recorded block, at or below [`recorded_tip`](Self::recorded_tip).
    #[must_use]
    pub const fn root(self) -> Tip {
        self.root
    }

    /// The recorded chain's tip on the snapshot the fork was read from.
    #[must_use]
    pub const fn recorded_tip(self) -> Tip {
        self.recorded_tip
    }

    /// Recorded blocks the alternative would pop. Defined for every `Fork`:
    /// [`new`](Self::new) refused a root above the tip.
    #[must_use]
    pub const fn pops(self) -> BlockCount {
        self.recorded_tip
            .height
            .checked_sub(self.root.height)
            .expect("Fork::new refused a root above its recorded tip")
    }
}

/// An alternative block the cheap tier admitted: what the store's AL1
/// records (`DRS_E5` §2.1, `AltBlockFacts`), and nothing more.
///
/// Not a [`ChainValid`](crate::ChainValid), and nothing converts it into
/// one: the rows evaluated are the header rules and the alt arms
/// ([`coverage`](Self::coverage) says which), and a block this admits is
/// re-judged in full by `validate` when its chain is promoted.
///
/// Branded as `ChainValid` is: `'id` invariant, and `V` the view type that
/// minted it. The store's `insert_alt_block` takes
/// `AltValid<'_, AltView<'_>>`, so a verdict from any other view does not
/// unify with the row. `'id` is the view's, not the write batch's: the
/// token is minted before `write` opens, and a batch's `'id` does not exist
/// yet. Not `Clone`.
///
/// ```compile_fail
/// use shekyl_chain_rules::AltValid;
/// // Would compile if `'id` were covariant; the brand is invariant.
/// fn relabel<'long: 'short, 'short, V>(valid: AltValid<'long, V>) -> AltValid<'short, V> {
///     valid
/// }
/// ```
///
/// The derived facts are the candidate's position and work — the
/// connecting height the stitched view derived, the cumulative difficulty
/// after it, the wire weight of the bodies it carries. No supply figure:
/// the parent's `coins_generated` is executed-chain state this tier does
/// not read (CEN-K8), so the row has no honest value for one.
pub struct AltValid<'id, V> {
    candidate: Candidate,
    hash: BlockHash,
    height: BlockHeight,
    cumulative_difficulty: CumulativeDifficulty,
    block_weight: BlockWeight,
    rule_set: RuleSet,
    coverage: RuleCoverage,
    _brand: Brand<'id>,
    _view: PhantomData<fn(V) -> V>,
}

impl<V> core::fmt::Debug for AltValid<'_, V> {
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

impl<'id, V> AltValid<'id, V> {
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

/// The alt tier: judge a [`StructurallyValid`] block against the
/// alternative chain `alt_view` stitches, under `rule_set` and `trust`,
/// for the fork the view describes ([`AltChainView::fork`]).
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
/// locus — CEN-A2 among them, when the view's tip is not the candidate's
/// `previous` (module docs). `Err(fault)`: the view could not answer,
/// answered with a hole or with bytes no conforming store holds, or a
/// claim went stale.
///
/// # Errors
///
/// [`Fault::View`] on the view's own fault; [`Fault::Corrupt`] when the
/// stitched chain is not the chain it claims (a hole below the parent, a
/// non-monotone cumulative difficulty); [`Fault::Stale`] when `formed`'s
/// rule set or seed is not this view's.
pub fn alt_against<'id, H: AltChainView<'id>>(
    formed: StructurallyValid,
    alt_view: &H,
    rule_set: &RuleSet,
    trust: &Trust,
) -> Result<Verdict<AltValid<'id, H>>, Fault<H::Fault>> {
    if formed.rule_set() != *rule_set {
        return Err(Fault::Stale(Stale::RuleSet {
            formed_under: Box::new(formed.rule_set()),
            in_force: Box::new(*rule_set),
            retry: formed.attempt().next(),
        }));
    }

    let mut coverage = *formed.coverage();

    // Before any header is read: the height-0 claim (CEN-K1b, the C++'s
    // first exit) and the two bands over the fork the view states (CEN-E2).
    // Neither reads a header; both are the cheapest refusals the tier has.
    let form_cx = FormContext::new(formed.candidate(), rule_set);
    if let Err(refused) = rules::run_form::<K1b>(&form_cx, &mut coverage) {
        return Ok(Err(refused));
    }
    if let Err(refused) = E2::check(&alt_view.fork(), rule_set, trust, &mut coverage) {
        return Ok(Err(refused));
    }

    // The definitions over the stitched chain, the same derivation
    // `validate` runs over the recorded one. CEN-D5 records only when that
    // derivation produced a target: a D6 refusal is D4's verdict.
    let HeaderFacts {
        connecting,
        cumulative_difficulty,
        context,
    } = match header_ladder::derive(&formed, alt_view, rule_set, trust, &mut coverage)? {
        Ok(facts) => facts,
        Err(refused) => return Ok(Err(refused)),
    };
    D5::record(&mut coverage);

    // The header ladder (`DRS_E5` §2.1, CEN-K4): the three segments
    // `validate` calls with B5, B4 and G1 between them. Nothing between
    // them here — those three read chain state.
    if let Err(refused) = header_ladder::judge_header_ladder(&context, alt_view, &mut coverage)? {
        return Ok(Err(refused));
    }

    // The ladder ran to its end: the block is accepted into storage after
    // these rows and no other (CEN-K4 — the tier is the row).
    K4::record(&mut coverage);

    let hash = formed.hash();
    let block_weight = block_weight(context.formed.candidate());
    drop(context);
    let (candidate, _stateless) = formed.into_parts();
    Ok(Ok(AltValid {
        candidate,
        hash,
        height: connecting,
        cumulative_difficulty,
        block_weight,
        rule_set: *rule_set,
        coverage,
        _brand: PhantomData,
        _view: PhantomData,
    }))
}

#[cfg(test)]
#[path = "alt_tests.rs"]
mod tests;
