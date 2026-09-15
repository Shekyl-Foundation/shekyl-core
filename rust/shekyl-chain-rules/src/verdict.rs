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
use crate::rule_set::RuleSetId;

/// Judged-and-refused (`Err`) or judged-and-passed (`Ok`). Never a fault.
pub type Verdict<T> = Result<T, InvalidBlock>;

/// Invariant in `'id`: neither shrinks nor grows, so a value branded with
/// one transaction's lifetime is not a value branded with any other's.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// A block judged valid under one rule set against one view of one
/// transaction.
///
/// The store's `connect` takes this and nothing else (S-CHAIN-W); a
/// `ChainValid<'id>` in hand *is* the evidence that every rule the set
/// enforces — and [`coverage`](Self::coverage) records which — passed. It is
/// minted only by `validate`, from which it inherits `'id`, the brand of the
/// `ChainView` it was judged against. A verdict cannot be carried from one
/// transaction to another:
///
/// ```compile_fail
/// use shekyl_chain_rules::ChainValid;
/// // Would compile if `'id` were covariant; the brand is invariant.
/// fn relabel<'long: 'short, 'short>(valid: ChainValid<'long>) -> ChainValid<'short> {
///     valid
/// }
/// ```
///
/// Nor can one be assembled by hand (G5):
///
/// ```compile_fail
/// use shekyl_chain_rules::ChainValid;
/// let forged: ChainValid<'static> = ChainValid {
///     block: todo!(),
///     rule_set: todo!(),
///     coverage: todo!(),
///     _brand: todo!(),
/// };
/// ```
///
/// Not `Clone`: a second copy of a brand-bearing token has no meaning.
#[derive(Debug)]
pub struct ChainValid<'id> {
    block: ValidatedBlock,
    rule_set: RuleSetId,
    coverage: RuleCoverage,
    _brand: Brand<'id>,
}

impl<'id> ChainValid<'id> {
    /// Mint the token. Called by `validate` once every rule has passed.
    pub(crate) const fn mint(
        block: ValidatedBlock,
        rule_set: RuleSetId,
        coverage: RuleCoverage,
    ) -> Self {
        Self {
            block,
            rule_set,
            coverage,
            _brand: PhantomData,
        }
    }

    /// The block as judged, identities derived.
    #[must_use]
    pub const fn block(&self) -> &ValidatedBlock {
        &self.block
    }

    /// The rule set the block was judged under.
    #[must_use]
    pub const fn rule_set_id(&self) -> RuleSetId {
        self.rule_set
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
    /// pool's position. `validate` never leaves this in a verdict: it
    /// re-homes it to the real slot.
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

impl Locus {
    /// Replace [`TxSlot::Lone`] with the slot the transaction occupies in
    /// the candidate. Every other locus is returned unchanged.
    pub(crate) const fn rehome(self, into: TxSlot) -> Self {
        match self {
            Self::Tx { slot: TxSlot::Lone } => Self::Tx { slot: into },
            Self::Input {
                slot: TxSlot::Lone,
                input,
            } => Self::Input { slot: into, input },
            other => other,
        }
    }
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

impl fmt::Display for InvalidBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} refused at {}", self.rule, self.locus)
    }
}

impl std::error::Error for InvalidBlock {}

#[cfg(test)]
#[path = "verdict_tests.rs"]
mod verdict_tests;
