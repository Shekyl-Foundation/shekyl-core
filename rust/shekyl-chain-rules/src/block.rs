// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block at each stage of judgement: the untrusted [`Candidate`] going
//! into `form`, the [`StructurallyValid`] it hands to `validate`, and the
//! typed [`ValidatedBlock`] coming out inside a `ChainValid`.

use core::fmt;

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, PowHash, PqcAuthHash, PrunableHash, Timestamp, TxHash};
use shekyl_wire::{Block, BlockHeader, Transaction};

use crate::coverage::RuleCoverage;
use crate::fault::FormAttempt;
use crate::rule_set::{RuleSet, RuleSetId};
use crate::rules::difficulty::Target;
use crate::rules::miner::Emission;

/// A transaction's identities, derived once (CEN-B6) beside its body.
///
/// The txid and the two **discardable components** it was built over: the
/// digest of the per-input `pqc_auths` (the txid's third component,
/// `PDM-Q-F26`) and the digest of the prunable region (its fourth, S-CHAIN-W
/// SCW-10) — the values the chain store records as `txs_pqc_auth_hash` and
/// `txs_prunable_hash` so a node that keeps only the skeleton can still
/// reconstruct the txid it accepted (`Transaction::hash_with_supplied_components`).
/// All three come from the same `validate`, copied from
/// [`Transaction::txid_parts`] so no consumer re-hashes a body and the store
/// never derives a consensus-visible value (C2-R8 Q4).
///
/// `pqc_auth_hash` is `None` exactly when the txid is **3-part** — a
/// coinbase, a serve-credit, the malformed gen-first and no-input shapes —
/// a fact about the identity, not about what was kept; see [`PqcAuthHash`].
/// For a coinbase `prunable_hash` is `keccak256("")` — what the C++ store
/// writes — not the txid's null-hash substitute; see [`PrunableHash`].
///
/// The store row this feeds (`txs_pqc_auth_hash`, `DAEMON_REDB_STORE.md`
/// §7.7 item 3) is held to a **three-leg** invariant, because under
/// `PDM-Q6` a hash row *without* its segment is the steady state of every
/// 4-part tx below the universal window `W`, not a fault:
///
/// 1. hash row present ⇔ txid 4-part — permanent, written at connect,
///    never deleted (`validate` rejects the shapes — gen-first or no-input
///    with auths — that could split "4-part" from "segment non-empty");
/// 2. segment present ⇒ hash row present — a body the store cannot verify
///    is the violation;
/// 3. hash row present ∧ segment absent ⇔ *discarded* — below `W` and not
///    a retention exception, or never held (a band-1 skeleton). One store
///    state with one meaning, however the node arrived at it.
///
/// So `None` here is *the txid has no third component*; leg 3 is *the
/// component exists and the bytes do not*. Different facts, never one
/// representation. A `PDM-Q6` ruling that keeps `pqc_auths` universal
/// retires the *row*, not the component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxIdentity {
    /// The transaction hash (txid).
    pub hash: TxHash,
    /// The txid's third component, or `None` for a 3-part txid.
    pub pqc_auth_hash: Option<PqcAuthHash>,
    /// `keccak256` of the prunable byte region.
    pub prunable_hash: PrunableHash,
}

impl TxIdentity {
    fn of(tx: &Transaction) -> Self {
        let parts = tx.txid_parts();
        Self {
            hash: parts.hash,
            pqc_auth_hash: parts.pqc_auth_hash,
            prunable_hash: parts.prunable_hash,
        }
    }
}

/// The untrusted input to `validate`: the block as received, plus the bodies
/// of the transactions its header lists, in listed order.
///
/// Public fields — this is the outside. Nothing about it has been checked,
/// including whether `transactions` are the bodies `block.transaction_hashes`
/// names; that is a 4.G rule and lands with its slice. One value rather than
/// two arguments (round-1 ruling Q9). `#[non_exhaustive]` so a third
/// component later is a constructor-site addition, not a breaking struct
/// literal (the Q9 "non-breaking" claim; Copilot #753).
///
/// ```compile_fail
/// use shekyl_chain_rules::Candidate;
/// let _ = Candidate { block: todo!(), transactions: todo!() };
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The block: header, miner transaction, listed transaction hashes.
    pub block: Block,
    /// The listed transactions' bodies, in the header's order.
    pub transactions: Vec<Transaction>,
}

impl Candidate {
    /// Assemble a candidate from the block as received and the listed
    /// bodies, in listed order.
    #[must_use]
    pub fn new(block: Block, transactions: Vec<Transaction>) -> Self {
        Self {
            block,
            transactions,
        }
    }
}

/// A candidate that passed the **stateless stage** (`form`): every rule
/// decidable without the chain, plus what those rules established and the
/// view-bound stage will read or verify.
///
/// The token between the two stages (`CHAIN_RULES_SLICE_2.md` §4.2). `form`
/// runs outside the write transaction, in parallel; `validate` takes this
/// type — never a bare `Candidate` — so the view-bound stage cannot be
/// reached without the stateless one, the same move that makes a
/// `ChainValid` unmintable outside `connect`. What it carries besides the
/// candidate:
///
/// * `rule_set` — the rules the caller **claimed** were in force, as the
///   set itself (not only its id). `validate` compares with `PartialEq`
///   and returns [`Stale::RuleSet`](crate::Stale::RuleSet) on a mismatch.
///   The id alone is not the set: a Fakechain `Fixed` target reuses
///   `RuleSetId::GENESIS` (Q10), so two sets at the same id can differ.
/// * `seed` — the block id the caller **claimed** sits at the seed height
///   (CEN-D3). `validate` verifies it against the committing view and
///   returns [`Stale::Seed`](crate::Stale::Seed) on a mismatch.
/// * `pow` — the RandomX longhash under that seed (CEN-D2), computed here
///   because it is the most expensive call in the validator and this stage
///   runs outside the write transaction.
/// * `judged_at` — the wall clock at `form`. **This makes the verdict
///   time-dependent**: a `StructurallyValid`, and the `ChainValid` minted
///   from it, is no longer a pure function of `(candidate, view, rule_set)`.
///   The FTL leg (CEN-C1) was judged against *this* instant. The window is
///   small because the brand ties a `ChainValid` to a live batch, but
///   anything that caches or defers one lets that leg go stale silently —
///   which is why the instant is carried rather than forgotten: a consumer
///   can see how old the judgement is.
/// * `attempt` — which try at `form` this is, so a `Stale` fault can say
///   whether another is allowed ([`Retry`](crate::Retry)).
///
/// Constructed only by `form`; the fields are private and there is no
/// public constructor (G5):
///
/// ```compile_fail
/// use shekyl_chain_rules::StructurallyValid;
/// let forged = StructurallyValid {
///     candidate: todo!(),
///     rule_set: todo!(),
///     coverage: todo!(),
///     judged_at: todo!(),
///     seed: todo!(),
///     pow: todo!(),
///     attempt: todo!(),
/// };
/// ```
///
/// Not `Clone`: a stage token has one consumer.
#[must_use = "a StructurallyValid is the input to `validate`; dropping it discards the stateless stage's work"]
pub struct StructurallyValid {
    candidate: Candidate,
    rule_set: RuleSet,
    coverage: RuleCoverage,
    judged_at: Timestamp,
    hash: BlockHash,
    seed: BlockHash,
    pow: PowHash,
    attempt: FormAttempt,
}

impl StructurallyValid {
    /// Called by `form` once every stateless rule has passed, and nowhere
    /// else.
    #[expect(
        clippy::too_many_arguments,
        reason = "one field per stateless-stage output; a builder would let a caller omit one"
    )]
    pub(crate) const fn new(
        candidate: Candidate,
        rule_set: RuleSet,
        coverage: RuleCoverage,
        judged_at: Timestamp,
        hash: BlockHash,
        seed: BlockHash,
        pow: PowHash,
        attempt: FormAttempt,
    ) -> Self {
        Self {
            candidate,
            rule_set,
            coverage,
            judged_at,
            hash,
            seed,
            pow,
            attempt,
        }
    }

    /// The candidate, still untrusted on every view-bound row.
    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// The rule set `form` judged under — a claim `validate` checks by
    /// value, not by id.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSet {
        self.rule_set
    }

    /// The id of the set `form` judged under. What the store persists;
    /// not a proxy for set equality (a Fakechain `Fixed` target reuses
    /// [`RuleSetId::GENESIS`](crate::RuleSetId::GENESIS)).
    #[must_use]
    pub const fn rule_set_id(&self) -> RuleSetId {
        self.rule_set.id()
    }

    /// The stateless rows that ran and passed.
    #[must_use]
    pub const fn coverage(&self) -> &RuleCoverage {
        &self.coverage
    }

    /// The wall clock at `form` — the instant CEN-C1 was (or will be)
    /// judged against. See the type's docs on time-dependence.
    #[must_use]
    pub const fn judged_at(&self) -> Timestamp {
        self.judged_at
    }

    /// The block's identity (CEN-B6), derived once by `form` — stateless,
    /// outside any transaction — and read by every rule that needs it while
    /// the view-bound stage runs (CEN-E1 first; `CHAIN_RULES_SLICE_3.md`
    /// F8). `ValidatedBlock::derive` carries this value into the verdict;
    /// nothing derives the identity a second time.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The seed the caller claimed for CEN-D3 — verified, not trusted, by
    /// `validate`.
    #[must_use]
    pub const fn seed(&self) -> BlockHash {
        self.seed
    }

    /// The longhash under the claimed seed (CEN-D2) — what CEN-D1 compares
    /// against the target once the seed is verified.
    #[must_use]
    pub const fn pow(&self) -> PowHash {
        self.pow
    }

    /// Which attempt at `form` produced this.
    #[must_use]
    pub const fn attempt(&self) -> FormAttempt {
        self.attempt
    }

    /// Hand the candidate and the stateless coverage to the view-bound
    /// stage, consuming the token.
    pub(crate) fn into_parts(self) -> (Candidate, RuleCoverage) {
        (self.candidate, self.coverage)
    }
}

impl fmt::Debug for StructurallyValid {
    // The candidate is summarised (identity + listed count), not dumped: a
    // block body is kilobytes and a failing assertion wants the token's claims.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructurallyValid")
            .field("hash", &self.hash)
            .field("transactions", &self.candidate.transactions.len())
            .field("rule_set", &self.rule_set)
            .field("coverage", &self.coverage)
            .field("judged_at", &self.judged_at)
            .field("seed", &self.seed)
            .field("pow", &self.pow)
            .field("attempt", &self.attempt)
            .finish()
    }
}

/// The typed payload a `ChainValid` wraps.
///
/// The candidate exactly as judged — the block is kept whole, so what the
/// store persists is what the rules saw — with every identity derived once:
/// `Block::hash`, and per transaction a [`TxIdentity`] copied from
/// [`Transaction::txid_parts`] (CEN-B6's definition applied), each paired
/// with its body. No consumer re-hashes and no two values can disagree
/// about which block or transaction they describe (ruling Q4/L4: one value
/// per identity).
///
/// Constructed only by `validate`. The fields are private and there is no
/// public constructor: a `ValidatedBlock` in hand was judged (G5).
///
/// ```compile_fail
/// use shekyl_chain_rules::ValidatedBlock;
/// let forged = ValidatedBlock {
///     hash: todo!(),
///     block: todo!(),
///     miner_tx: todo!(),
///     transactions: todo!(),
///     target: todo!(),
///     cumulative_difficulty: todo!(),
///     emission: todo!(),
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedBlock {
    hash: BlockHash,
    block: Block,
    miner_tx: TxIdentity,
    transactions: Vec<(TxIdentity, Transaction)>,
    target: Target,
    cumulative_difficulty: CumulativeDifficulty,
    emission: Emission,
}

impl ValidatedBlock {
    /// Assemble the verdict's block. Called by `validate` after the last
    /// rule has passed and nowhere else. The block's identity is **not**
    /// derived here: `form` derived it once under CEN-B6 and the token
    /// carried it (`StructurallyValid::hash`), because a view-bound rule
    /// reads it while the rules run (CEN-E1). The slice-1 placement —
    /// *"derived after the last rule has passed"* — rested on the premise
    /// that no rule reads the identity; E1 refuted the premise
    /// (`CHAIN_RULES_SLICE_3.md` F8, Q7). The transaction identities are
    /// derived here, once; the target and the cumulative work are CEN-D4's
    /// derivation, recorded where it ran; the emission is 4.F's
    /// (`Emission::derive`), likewise.
    pub(crate) fn derive(
        candidate: Candidate,
        hash: BlockHash,
        target: Target,
        cumulative_difficulty: CumulativeDifficulty,
        emission: Emission,
    ) -> Self {
        let Candidate {
            block,
            transactions,
        } = candidate;
        Self {
            hash,
            miner_tx: TxIdentity::of(&block.miner_transaction),
            block,
            transactions: transactions
                .into_iter()
                .map(|tx| (TxIdentity::of(&tx), tx))
                .collect(),
            target,
            cumulative_difficulty,
            emission,
        }
    }

    /// The emission this block was priced at (CEN-F11 / F13 / F15 / F20):
    /// the volume window and the subsidy — configured at genesis, derived
    /// from the parent's accumulator above it. What slice 7's paid-reward
    /// rows and `connect`'s `coins_generated` derivation consume.
    #[must_use]
    pub const fn emission(&self) -> Emission {
        self.emission
    }

    /// The difficulty this block was judged against (CEN-D4, D6).
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// Work through this block: the parent's cumulative difficulty plus
    /// the target. What the store records as `block_info.cumulative_
    /// difficulty` — derived here, never by the store (C2-R8 Q4; slice 2
    /// Q5).
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> CumulativeDifficulty {
        self.cumulative_difficulty
    }

    /// The block's identity.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The block as judged: header, miner transaction, listed hashes.
    #[must_use]
    pub const fn block(&self) -> &Block {
        &self.block
    }

    /// The header as judged.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.block.header
    }

    /// The miner transaction with its identities.
    #[must_use]
    pub const fn miner_tx(&self) -> (TxIdentity, &Transaction) {
        (self.miner_tx, &self.block.miner_transaction)
    }

    /// The listed transactions' bodies with their identities, in the
    /// header's order.
    #[must_use]
    pub fn transactions(&self) -> &[(TxIdentity, Transaction)] {
        &self.transactions
    }
}
