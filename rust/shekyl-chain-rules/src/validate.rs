// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The entry points: [`form`] then [`validate`] for a block — two stages —
//! and [`tx_form`] / [`tx_against`] for one transaction.
//!
//! # Two stages, one property
//!
//! [`form`] is **stateless**: the candidate, a `RuleSet`, a
//! [`Substrate`] (clock, longhash) and a seed claim in; a
//! [`StructurallyValid`] out. It runs outside the exclusive write
//! transaction, in parallel with other blocks, and it is where the expensive
//! call lives. [`validate`] is **view-bound**: a `StructurallyValid`, a
//! `ChainView<'id>` and the rule set in force in; a `ChainValid<'id, V>` out.
//! It runs inside the transaction C2-R8 Q3 projects the view from, and it
//! verifies the claims `form` was given — the seed, the rule set — against
//! that view before judging anything (`CHAIN_RULES_SLICE_2.md` §4.2, Q1/Q8).
//! The partition is view-dependence and nothing else (Q9).
//!
//! Both are generic over their substrate (`S: Substrate`, `V: ChainView<'id>`,
//! never `&dyn`), so DRS-E5's pool decorator and the daemon's verifier
//! implement the traits without this crate naming them. Each returns a
//! fault in the outer position and a verdict in the inner one; `validate`'s
//! outer position is a [`Fault<V::Fault>`] — the view's, or one of the two
//! kinds this crate defines (`fault.rs`). Inside a view-reading rule, `?`
//! propagates a fault and only a fault; a refusal is always written out as
//! [`refused`](crate::refused) at the site that judged, so the row is named
//! where the decision is made.
//!
//! # The pipeline
//!
//! `form` runs the stateless block rules in census order through
//! [`rules::run_form`]; `validate` checks the two claims, then runs the
//! view-bound block rules through [`rules::run`], then judges each
//! transaction by form and against the view, unions the coverages (the
//! stateless stage's included), and mints the `ChainValid` only after the
//! last rule passed. Coverage is never complete for any rule set until
//! every row has landed, so no verdict minted before then can be mistaken
//! for parity evidence.

use shekyl_types::BlockHash;
use shekyl_wire::Transaction;

use crate::block::{Candidate, StructurallyValid, ValidatedBlock};
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, FormAttempt, Stale};
use crate::rule_set::RuleSet;
use crate::rules::anchors::E1;
use crate::rules::difficulty::D4;
use crate::rules::header::{B1, B2, B5, B6, B7};
use crate::rules::miner::{Emission, F1, F10, F3, F4, F5, F6, F7, F9};
use crate::rules::pow::{D1b, D1, D2, D3};
use crate::rules::timestamps::{C1, C2, C3};
use crate::rules::topology::A2;
use crate::rules::tx::{H1, H16, H3, H4};
use crate::rules::{self, BlockContext, FormContext};
use crate::substrate::Substrate;
use crate::trust::Trust;
use crate::verdict::{ChainValid, InvalidBlock, TxSlot, Verdict};
use crate::view::{ChainView, Tip};

/// Run the listed stateless rules in order; the first refusal is the verdict.
///
/// A macro rather than a loop because each rule is a distinct *type*
/// (SCW-18): the list is the slice's declaration of which rows the stage
/// evaluates, and a rule missing from it is a row missing from coverage —
/// which `ChainValid::mint` refuses if the row is `implemented` (G9).
macro_rules! judge_form {
    ($cx:expr, $coverage:expr; $($rule:ty),+ $(,)?) => {
        $(
            if let Err(refused) = rules::run_form::<$rule>(&$cx, &mut $coverage) {
                return Ok(Err(refused));
            }
        )+
    };
}

/// Run the listed view-bound rules in order; the first refusal is the
/// verdict. A view fault is wrapped into its arm of [`Fault`].
macro_rules! judge_block {
    ($cx:expr, $view:expr, $coverage:expr; $($rule:ty),+ $(,)?) => {
        $(
            if let Err(refused) =
                rules::run::<$rule, V>(&$cx, $view, &mut $coverage).map_err(Fault::View)?
            {
                return Ok(Err(refused));
            }
        )+
    };
}

/// The stateless stage: judge a candidate on every rule decidable without
/// the chain, and establish what the view-bound stage will read.
///
/// `rule_set` and `seed` are the caller's **claims** — the rules in force
/// at the height this block will connect at, and the block id at the seed
/// height (CEN-D3) — read from whatever snapshot the caller has. `validate`
/// verifies both against the committing view and returns a
/// [`Stale`] fault, not a refusal, if either moved (a reorg at least
/// `SEEDHASH_EPOCH_LAG` deep between the stages, or a rule-set boundary).
/// `attempt` is which try this is: a driver starts at
/// [`FormAttempt::FIRST`] and may only try again with the attempt a `Stale`
/// hands back (`fault.rs`: the bound is the type).
///
/// Returns `Err(fault)` if the substrate could not answer — the clock, the
/// verifier — which is not a judgement about the block; `Ok(Err(refused))`
/// if a stateless rule refused; `Ok(Ok(formed))` otherwise.
pub fn form<S: Substrate>(
    candidate: Candidate,
    rule_set: &RuleSet,
    substrate: &S,
    seed: BlockHash,
    attempt: FormAttempt,
) -> Result<Verdict<StructurallyValid>, S::Fault> {
    // Read the clock once, before any rule: every stateless judgement is
    // against one instant, and the instant travels on the token.
    let clock = substrate.local_clock()?;
    let mut coverage = RuleCoverage::EMPTY;

    // Stateless block-level predicates, in census order: the header rows,
    // then the coinbase's shape (4.F — one field of the block, judged here
    // because the coinbase never passes the per-transaction path).
    let cx = FormContext::new(&candidate, rule_set);
    judge_form!(cx, coverage; B1, B2, B7, F1, F3, F7, F9, F10);

    // Two definitions, after the cheap refusals and outside any
    // transaction. The identity first (B6: one keccak over the hashing
    // blob; a view-bound rule — E1 — reads it while the rules run, so it is
    // derived here, once, and travels on the token), then the expensive one
    // (D2; the seed is the caller's claim, D3 verifies it in `validate`).
    let hash = B6::identity(&candidate.block, &mut coverage);
    let pow = D2::longhash(substrate, &candidate, seed, &mut coverage)?;

    Ok(Ok(StructurallyValid::new(
        candidate, *rule_set, coverage, clock, hash, seed, pow, attempt,
    )))
}

/// The view-bound stage: judge a [`StructurallyValid`] against the chain it
/// will connect onto, under `rule_set`, with what this node takes on the
/// release's word (`trust`: the anchors CEN-E1 reads; from slice 6, the
/// below-anchor posture — `PDM-Q5`, `trust.rs`). `rule_set` and `trust`
/// are orthogonal inputs: the first is consensus, the second is node
/// state, and `connect` compares only the first against what is in force.
///
/// Returns, in order of what happened:
///
/// * `Err(Fault::Stale(_))` — a claim `form` was given does not hold against
///   this view: the seed (CEN-D3) or the rule set. Not a judgement about
///   the block; the payload says whether the driver may redo `form`.
/// * `Err(Fault::View(fault))` — the view's substrate failed before a
///   verdict was reached. Not a judgement about the block; the caller halts.
/// * `Err(Fault::Corrupt(_))` — the view answered with data no conforming
///   store holds. The writer halt.
/// * `Ok(Err(refused))` — a rule refused. `refused.rule` is the census row,
///   `refused.locus` where in the candidate it pointed.
/// * `Ok(Ok(valid))` — every rule the set enforces passed.
///   `valid.coverage()` records which rows were actually evaluated, the
///   stateless stage's included.
///
/// The miner transaction and each listed transaction are judged by
/// [`tx_form`] (at their slot) then [`tx_against`]; a refusal from the
/// latter is re-homed from [`TxSlot::Lone`] to the slot the transaction
/// occupies.
///
/// The verdict inherits the view's brand *and* its type. Judged against one
/// view, it cannot be connected under another — the store's `connect` takes
/// a `ChainValid<'id, StoreView<'_, 'id>>`, and a verdict from a different
/// transaction, or from an unbranded view that merely borrowed the `'id`,
/// does not unify with it:
///
/// ```compile_fail
/// use core::convert::Infallible;
/// use core::marker::PhantomData;
/// use shekyl_chain_rules::*;
/// use shekyl_types::{BlockHeight, CurveTreeRoot, KeyImage};
///
/// struct View<'id>(PhantomData<fn(&'id ()) -> &'id ()>);
/// impl<'id> ChainView<'id> for View<'id> {
///     type Fault = Infallible;
///     fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
///         Ok(false)
///     }
///     fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
///         Ok(AtHeight::AboveTip)
///     }
///     fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
///         Ok(AtHeight::AboveTip)
///     }
///     fn tip(&self) -> Result<Option<Tip>, Infallible> {
///         Ok(None)
///     }
/// }
/// // Each call brands a fresh view, as the store's `write` does.
/// fn with_view<R>(f: impl for<'id> FnOnce(View<'id>) -> R) -> R {
///     f(View(PhantomData))
/// }
/// // The store's `connect`: the verdict must carry *this* view's brand.
/// fn connect<'id>(_view: &View<'id>, _valid: ChainValid<'id, View<'id>>) {}
/// fn formed() -> StructurallyValid {
///     unimplemented!()
/// }
///
/// with_view(|outer| {
///     with_view(|inner| {
///         let valid = validate(formed(), &inner, &RuleSet::GENESIS)
///             .unwrap()
///             .unwrap();
///         connect(&outer, valid); // judged against `inner`: does not compile
///     })
/// });
/// ```
///
/// An unbranded view that implements `ChainView` for every `'id` still
/// cannot satisfy `connect`: it mints `ChainValid<'id, Evil>`, not
/// `ChainValid<'id, View<'id>>`.
///
/// ```compile_fail
/// use core::convert::Infallible;
/// use core::marker::PhantomData;
/// use shekyl_chain_rules::*;
/// use shekyl_types::{BlockHeight, CurveTreeRoot, KeyImage};
///
/// struct View<'id>(PhantomData<fn(&'id ()) -> &'id ()>);
/// impl<'id> ChainView<'id> for View<'id> {
///     type Fault = Infallible;
///     fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> { Ok(false) }
///     fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
///         Ok(AtHeight::AboveTip)
///     }
///     fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
///         Ok(AtHeight::AboveTip)
///     }
///     fn tip(&self) -> Result<Option<Tip>, Infallible> {
///         Ok(None)
///     }
/// }
/// struct Evil;
/// impl<'id> ChainView<'id> for Evil {
///     type Fault = Infallible;
///     fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> { Ok(false) }
///     fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
///         Ok(AtHeight::AboveTip)
///     }
///     fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
///         Ok(AtHeight::AboveTip)
///     }
///     fn tip(&self) -> Result<Option<Tip>, Infallible> {
///         Ok(None)
///     }
/// }
/// fn connect<'id>(_: &View<'id>, _: ChainValid<'id, View<'id>>) {}
/// fn formed() -> StructurallyValid { unimplemented!() }
///
/// fn with_view<R>(f: impl for<'id> FnOnce(View<'id>) -> R) -> R {
///     f(View(PhantomData))
/// }
/// with_view(|view| {
///     let valid = validate(formed(), &Evil, &RuleSet::GENESIS, &Trust::UNANCHORED).unwrap().unwrap();
///     connect(&view, valid); // ChainValid<Evil> ≠ ChainValid<View>
/// });
/// ```
pub fn validate<'id, V: ChainView<'id>>(
    formed: StructurallyValid,
    view: &V,
    rule_set: &RuleSet,
    trust: &Trust,
) -> Result<Verdict<ChainValid<'id, V>>, Fault<V::Fault>> {
    // The stateless stage's rule-set claim, checked before any rule reads
    // the wrong parameters. A mismatch is the world having moved, not a
    // verdict — and the retry is bounded by the attempt the token carries.
    if formed.rule_set() != *rule_set {
        return Err(Fault::Stale(Stale::RuleSet {
            formed_under: formed.rule_set(),
            in_force: *rule_set,
            retry: formed.attempt().next(),
        }));
    }

    let mut coverage = *formed.coverage();

    // Definitions the predicates read, derived once and recorded where they
    // are derived: the connecting height (one tip read), the seed
    // verification (D3), the MTP window (C3), the target (D4, minted
    // through D6) and the work it implies, the comparison (D1b). B6 was
    // recorded by `form` (the identity is stateless) and rides on the token.
    let tip = view.tip().map_err(Fault::View)?;
    let connecting = Tip::connecting_height(tip.as_ref());
    // The seed claim first: a stale seed means the longhash below was
    // computed against a chain this is not, and nothing else is worth
    // judging until `form` is redone.
    D3::verify_seed(view, connecting, &formed, &mut coverage)?;
    let mtp_window = C3::window(view, connecting, &mut coverage).map_err(Fault::View)?;
    let target = match D4::target(view, connecting, rule_set, &mut coverage)? {
        Ok(target) => target,
        // CEN-D6: the ratified algorithm derived zero for this height; the
        // block is refused, as the C++ refuses it. A verdict, not a fault
        // (rules::difficulty module docs).
        Err(refused) => return Ok(Err(refused)),
    };
    let cumulative_difficulty = D4::cumulative_after(view, connecting, target)?;
    D1b::record(&mut coverage);

    // View-bound block-level predicates (4.A–4.G), in census order.
    let cx = BlockContext::new(&formed, tip, mtp_window, target, trust);
    judge_block!(cx, view, coverage; A2, B5, C1, C2, D1, E1, F4, F5, F6);

    // The 4.F definitions (F11, F13, F15, F20). Recording them is what
    // `covers_landed` holds this stage to. F14b reads the priced value
    // here when the median exists; `connect` persists that row's paid
    // reward, so the value does not ride on the verdict yet. Nothing here
    // refuses; a fault is the view's.
    Emission::derive(view, connecting, &mut coverage)?;

    let candidate = cx.candidate();
    let miner = (TxSlot::Miner, &candidate.block.miner_transaction);
    let listed = candidate
        .transactions
        .iter()
        .enumerate()
        .map(|(n, tx)| (TxSlot::Listed(n), tx));
    for (slot, tx) in core::iter::once(miner).chain(listed) {
        match judge_tx(tx, slot, view, rule_set).map_err(Fault::View)? {
            Ok(tx_coverage) => coverage.union(&tx_coverage),
            // `tx_form` refuses at the slot it was given; `tx_against` still
            // writes `Lone` (slice 6 adopts the slot), so the re-home stays.
            Err(refused) => {
                return Ok(Err(InvalidBlock::new(
                    refused.rule,
                    refused.locus.rehome(slot),
                )));
            }
        }
    }

    let hash = formed.hash();
    let (candidate, _stateless) = formed.into_parts();
    let block = ValidatedBlock::derive(candidate, hash, target, cumulative_difficulty);
    Ok(Ok(ChainValid::mint(block, rule_set, coverage)))
}

/// Run the listed per-transaction rules in order; the first refusal is the
/// verdict (`tx_form` returns a `Verdict` directly, so `?` is that return).
/// Out-of-scope rows are recorded vacuous by [`rules::run_tx`].
macro_rules! judge_tx {
    ($cx:expr, $coverage:expr; $($rule:ty),+ $(,)?) => {
        $(
            rules::run_tx::<$rule>(&$cx, &mut $coverage)?;
        )+
    };
}

/// Stateless per-transaction rules (census 4.H): everything decidable from
/// the transaction's bytes alone. Shared verbatim by block connect and pool
/// admission — the C++ `ver_non_input_consensus`'s two sites, one function.
///
/// `slot` is where the transaction sits — the pool passes [`TxSlot::Lone`],
/// `validate` the block's own `Miner` / `Listed(n)` — and is where a refusal
/// points. The transaction's kind (coinbase position or not) is derived from
/// the slot, never from its bytes (slice 5 Q2 as amended: a sole-`gen`
/// transaction outside the miner slot is judged as a non-coinbase
/// transaction); rules scoped to non-coinbase transactions are recorded
/// vacuous at the miner slot.
///
/// `_rule_set` is the contract's parameter (`CHAIN_RULES_CRATE.md` §4.6) and
/// the pool's call site; no 4.H row reads it today — every 4.H limit is a
/// frozen constant beside its rule (`rules::tx`, the F21 arrangement) — and
/// the first row that varies by schedule step is its first reader.
pub fn tx_form(tx: &Transaction, slot: TxSlot, _rule_set: &RuleSet) -> Verdict<RuleCoverage> {
    let cx = rules::TxContext::new(tx, slot);
    let mut coverage = RuleCoverage::EMPTY;
    judge_tx!(cx, coverage; H1, H3, H4, H16);
    Ok(coverage)
}

/// Stateful per-transaction rules (census 4.I): everything that needs the
/// recorded chain — spent key images, the membership anchor. The pool passes
/// its view decorator here.
///
/// A refusal's locus is [`TxSlot::Lone`]; `validate` re-homes it.
pub fn tx_against<'id, V: ChainView<'id>>(
    tx: &Transaction,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Verdict<RuleCoverage>, V::Fault> {
    // 4.I rules land with their slice (DRS-D12); nothing reads the
    // transaction, the view, or the rule set yet.
    let _ = (tx, view, rule_set);
    Ok(Ok(RuleCoverage::EMPTY))
}

/// [`tx_form`] then [`tx_against`], coverages unioned. The locus of a
/// refusal is left as the callee wrote it.
fn judge_tx<'id, V: ChainView<'id>>(
    tx: &Transaction,
    slot: TxSlot,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Verdict<RuleCoverage>, V::Fault> {
    let mut coverage = match tx_form(tx, slot, rule_set) {
        Ok(coverage) => coverage,
        Err(refused) => return Ok(Err(refused)),
    };
    Ok(tx_against(tx, view, rule_set)?.map(|against| {
        coverage.union(&against);
        coverage
    }))
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod validate_tests;
