// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What `validate` hands back: a branded [`ChainValid`] or an
//! [`InvalidBlock`] that names the census row and where it pointed.
//!
//! These two are the *verdict* — judged and passed, judged and refused. A
//! view whose substrate failed is neither, and travels in the other position
//! of `validate`'s return (`view.rs`, "Three answers, three positions").

use core::fmt;
use core::marker::PhantomData;

use crate::block::ValidatedBlock;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rule_set::{RuleSet, RuleSetId};
use crate::view::ChainView;

/// Judged-and-refused (`Err`) or judged-and-passed (`Ok`). Never a fault.
pub type Verdict<T> = Result<T, InvalidBlock>;

/// Invariant in `'id`: neither shrinks nor grows, so a value branded with
/// one transaction's lifetime is not a value branded with any other's.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// A block judged valid under one rule set against one view of one
/// transaction.
///
/// The store's `connect` takes this and nothing else (S-CHAIN-W). The type
/// carries two brands: `'id` (the batch) and `V` (the view type that minted
/// it). An unbranded `impl<'id> ChainView<'id> for Evil` can still pick up a
/// batch's `'id`, but it produces `ChainValid<'id, Evil>`, which does not
/// unify with the `ChainValid<'id, StoreView<'_, 'id>>` `connect` will
/// demand — G4 is a type, not a convention. A verdict cannot be carried
/// from one transaction to another:
///
/// ```compile_fail
/// use shekyl_chain_rules::ChainValid;
/// // Would compile if `'id` were covariant; the brand is invariant.
/// fn relabel<'long: 'short, 'short, V>(valid: ChainValid<'long, V>) -> ChainValid<'short, V> {
///     valid
/// }
/// ```
///
/// Nor can one be assembled by hand (G5):
///
/// ```compile_fail
/// use shekyl_chain_rules::ChainValid;
/// let forged: ChainValid<'static, ()> = ChainValid {
///     block: todo!(),
///     rule_set: todo!(),
///     coverage: todo!(),
///     _brand: todo!(),
///     _view: todo!(),
/// };
/// ```
///
/// Not `Clone`: a second copy of a brand-bearing token has no meaning.
pub struct ChainValid<'id, V> {
    block: ValidatedBlock,
    rule_set: RuleSet,
    coverage: RuleCoverage,
    _brand: Brand<'id>,
    _view: PhantomData<fn(V) -> V>,
}

/// Hand-written rather than derived: a derive would add a `V: Debug` bound,
/// and `V` is a brand — the store's view need not be `Debug` for a token
/// minted against it to be. Prints what the token asserts, not the marker.
impl<V> fmt::Debug for ChainValid<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainValid")
            .field("block", &self.block)
            .field("rule_set", &self.rule_set)
            .field("coverage", &self.coverage)
            .finish_non_exhaustive()
    }
}

impl<'id, V: ChainView<'id>> ChainValid<'id, V> {
    /// Mint the token. Called by `validate` once every rule has passed.
    ///
    /// Panics if an `implemented` row the rule set enforces is missing from
    /// `coverage` — that is a crate wiring bug (G9), not a verdict about the
    /// block. The check is a `panic!`, not `debug_assert`, so a release
    /// build cannot mint a token that skipped a landed rule.
    pub(crate) fn mint(block: ValidatedBlock, rule_set: &RuleSet, coverage: RuleCoverage) -> Self {
        if !coverage.covers_landed(rule_set) {
            panic!(
                "shekyl-chain-rules: ChainValid minted without evaluating every implemented row the rule set enforces (G9)"
            );
        }
        Self {
            block,
            rule_set: *rule_set,
            coverage,
            _brand: PhantomData,
            _view: PhantomData,
        }
    }

    /// The block as judged, identities derived.
    #[must_use]
    pub const fn block(&self) -> &ValidatedBlock {
        &self.block
    }

    /// The rule set the block was judged under — the set, not only its
    /// id. A Fakechain `Fixed` target reuses [`RuleSetId::GENESIS`], so
    /// `connect` compares this with the issued set `in_force` names.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSet {
        self.rule_set
    }

    /// The id of the set the block was judged under. What the store
    /// persists as `hf_versions`; not a proxy for set equality.
    #[must_use]
    pub const fn rule_set_id(&self) -> RuleSetId {
        self.rule_set.id()
    }

    /// The rows actually evaluated. `RuleCoverage::EMPTY` until rules land;
    /// only coverage complete for the rule set is parity evidence.
    #[must_use]
    pub const fn coverage(&self) -> &RuleCoverage {
        &self.coverage
    }
}

/// Which transaction of a candidate a refusal points into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxSlot {
    /// The block's embedded miner transaction.
    Miner,
    /// The listed transaction at this position in the candidate's order.
    Listed(usize),
    /// A transaction judged on its own by `tx_form` / `tx_against` — the
    /// pool's position. `validate` never passes it: both stages take the
    /// slot from their caller and name it in a refusal, so a verdict from
    /// `validate` carries `Miner` or `Listed(n)` by construction.
    Lone,
}

/// Where in the candidate a refusal points.
///
/// One verdict type for block-, transaction- and input-level refusals, the
/// level carried here rather than in three error types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Locus {
    /// The block as a whole: header, topology, body-level rules.
    Block,
    /// One transaction.
    Tx {
        /// Which one.
        slot: TxSlot,
    },
    /// One input of one transaction.
    Input {
        /// Which transaction.
        slot: TxSlot,
        /// The input's position in that transaction.
        input: usize,
    },
}

impl fmt::Display for TxSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Miner => f.write_str("miner tx"),
            Self::Listed(n) => write!(f, "tx #{n}"),
            Self::Lone => f.write_str("tx"),
        }
    }
}

impl fmt::Display for Locus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => f.write_str("block"),
            Self::Tx { slot } => write!(f, "{slot}"),
            Self::Input { slot, input } => write!(f, "{slot} input #{input}"),
        }
    }
}

/// The refusal: which census row the candidate failed, and where.
///
/// A typed row, never a string, never "some rejection" (G3). It carries
/// nothing a store error could map onto — no message, no source — and no
/// `From` reaches it from one (G2; `check_store_error_conversion_ban.py`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidBlock {
    /// The row that refused.
    pub rule: CenRow,
    /// Where it pointed.
    pub locus: Locus,
}

impl InvalidBlock {
    /// Name the row and the place. The form a rule writes at the site that
    /// judged.
    #[must_use]
    pub const fn new(rule: CenRow, locus: Locus) -> Self {
        Self { rule, locus }
    }
}

/// A judged-and-refused verdict in the outer-`Result` position every
/// view-reading entry point uses. `?` cannot produce this — a rule that
/// refuses writes `return refused(...)`.
#[inline]
pub const fn refused<T, F>(rule: CenRow, locus: Locus) -> Result<Verdict<T>, F> {
    Ok(Err(InvalidBlock::new(rule, locus)))
}

impl fmt::Display for InvalidBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} refused at {}", self.rule, self.locus)
    }
}

impl std::error::Error for InvalidBlock {}

#[cfg(test)]
#[path = "verdict_tests.rs"]
mod verdict_tests;
