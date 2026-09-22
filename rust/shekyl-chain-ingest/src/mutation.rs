// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mutation family — systematic invalidations of a valid chain, each
//! with the census row that refuses it named **from the spec**
//! (`DRS_E2_REPLAY_DRIVER.md` §3.10; §7 item 8d).
//!
//! [`Mutated`] wraps any Extend-only [`Source`] and replaces the `Extend`
//! at one height with [`Mutation::apply`]'s candidate. One block, one
//! deliberate violation, everything else valid — so a refusal on any
//! *other* row is itself a finding, and the family's tests assert the row,
//! never merely "refused".
//!
//! # The oracle is the census, not the C++
//!
//! Every [`Mutation`] names its [`Mutation::expected`] row. What a consumer
//! asserts depends on that row's own status ([`CenRow::status`]):
//!
//! - `Implemented` — the run's refusal is `(height, InvalidBlock { rule:
//!   expected, .. })`.
//! - `Pending` — the rule is not in Rust yet, and the family **pins what
//!   happens today** (§3.10's last column: the block connects, or a store
//!   belt halts the run). The pin is not acceptance of the gap; it is the
//!   gap made a red test the moment the row is ported, because the branch
//!   is chosen by the census at every run. The census is the falsifier.
//!
//! A regtest daemon's verdict is secondary evidence (§1.3) and lives in
//! item 8's regtest leg; trace tag `0x03` stays RESERVED.
//!
//! # Heights are the pipeline's
//!
//! An `Extend` carries no height. The wrapper counts from its inner
//! source's `first_height`, exactly as the pipeline will, and mutates the
//! `n`th `Extend` where `first + n == at`. It never reorders, renumbers or
//! adds events, and it is **Extend-only**: a `Rewind` from the inner source
//! is a wrapper fault, not something to pass through — a mutation on a fork
//! is the reorg × mutation cross §3.10 names as out of scope.

use core::fmt;

use shekyl_chain_rules::{Candidate, CenRow};
use shekyl_difficulty::{check_hash, Difficulty, FTL_SECONDS};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};
use shekyl_wire::{Input, Transaction};

use crate::source::{IngestEvent, Sequenced, Source};

/// One systematic invalidation. Exhaustive: [`Mutation::ALL`] is every
/// variant, and a match over it is a compile-time census of the family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mutation {
    /// `major_version` bumped past the version the rule set admits.
    HeaderVersion,
    /// `previous` names a hash the chain never held.
    Orphan,
    /// `curve_tree_root` replaced by a root the tree never had.
    WrongRoot,
    /// `timestamp` = `clock + FTL + 1`: one second past the future-time
    /// limit the substrate's clock allows. Closes §5's FTL row.
    FutureTimestamp,
    /// `timestamp` = `0`: at or below every MTP median.
    StaleTimestamp,
    /// The nonce re-mined so the longhash satisfies the target under a
    /// **wrong** seed and fails it under the true one. The pipeline claims
    /// the true seed (RD-Q5), so `form` hashes under it and D1 refuses.
    /// "Bad seed" is a block *mined* against the wrong seed — the seed is
    /// not in the block.
    PowUnderWrongSeed,
    /// The coinbase's clear output amount off by one.
    WrongReward,
    /// Two listed bodies swapped; the header's `tx_hashes` untouched.
    ReorderedBodies,
    /// A listed spend reuses a key image an earlier block spent.
    DoubleSpend,
}

impl Mutation {
    /// Every mutation, in the table's order (§3.10).
    pub const ALL: [Self; 9] = [
        Self::HeaderVersion,
        Self::Orphan,
        Self::WrongRoot,
        Self::FutureTimestamp,
        Self::StaleTimestamp,
        Self::PowUnderWrongSeed,
        Self::WrongReward,
        Self::ReorderedBodies,
        Self::DoubleSpend,
    ];

    /// The census row that refuses this mutation — the spec's answer,
    /// whether or not Rust holds the row yet (module docs).
    #[must_use]
    pub const fn expected(self) -> CenRow {
        match self {
            Self::HeaderVersion => CenRow::B1,
            Self::Orphan => CenRow::A2,
            Self::WrongRoot => CenRow::B5,
            Self::FutureTimestamp => CenRow::C1,
            Self::StaleTimestamp => CenRow::C2,
            Self::PowUnderWrongSeed => CenRow::D1,
            Self::WrongReward => CenRow::F13,
            Self::ReorderedBodies => CenRow::G2,
            Self::DoubleSpend => CenRow::I7,
        }
    }

    /// Whether the mutation needs the [`Environment::pow`] leg.
    #[must_use]
    pub const fn needs_pow(self) -> bool {
        matches!(self, Self::PowUnderWrongSeed)
    }

    /// Apply this mutation to a valid `candidate` at its height, given the
    /// environment the run will judge it in and the key images the chain
    /// spent before it.
    ///
    /// # Errors
    ///
    /// [`Unmutable`] when the candidate cannot carry this violation (no
    /// listed body to reorder, no earlier spend to repeat) or the
    /// environment lacks the leg the mutation needs.
    pub fn apply(
        self,
        mut candidate: Candidate,
        env: &Environment<'_>,
        spent_before: &[[u8; 32]],
    ) -> Result<Candidate, Unmutable> {
        let header = &mut candidate.block.header;
        match self {
            Self::HeaderVersion => {
                header.major_version = header
                    .major_version
                    .checked_add(1)
                    .ok_or(Unmutable::HeaderVersionSaturated)?;
            }
            Self::Orphan => header.previous = BlockHash::from_bytes([0x77; 32]),
            Self::WrongRoot => header.curve_tree_root = CurveTreeRoot::from_bytes([0x5a; 32]),
            Self::FutureTimestamp => {
                header.timestamp = env
                    .clock
                    .to_raw()
                    .saturating_add(FTL_SECONDS)
                    .saturating_add(1);
            }
            Self::StaleTimestamp => header.timestamp = 0,
            Self::PowUnderWrongSeed => {
                let pow = env.pow.as_ref().ok_or(Unmutable::NoPowEnvironment)?;
                candidate.block.header.nonce = pow.mine_against_wrong_seed(&candidate)?;
            }
            Self::WrongReward => {
                let output = candidate
                    .block
                    .miner_transaction
                    .prefix
                    .outputs
                    .first_mut()
                    .ok_or(Unmutable::NoCoinbaseOutput)?;
                output.amount = output.amount.wrapping_add(1);
            }
            Self::ReorderedBodies => {
                if candidate.transactions.len() < 2 {
                    return Err(Unmutable::TooFewBodies {
                        listed: candidate.transactions.len(),
                    });
                }
                candidate.transactions.swap(0, 1);
            }
            Self::DoubleSpend => {
                let &reused = spent_before.first().ok_or(Unmutable::NothingSpentBefore)?;
                let mut inputs = candidate
                    .transactions
                    .iter_mut()
                    .flat_map(|tx| tx.prefix.inputs.iter_mut());
                match inputs.find(|input| matches!(input, Input::ToKey { .. })) {
                    Some(Input::ToKey { key_image, .. }) => *key_image = reused,
                    _ => return Err(Unmutable::NoSpendToRepeat),
                }
                // One violation: the body changed, so the header lists the
                // new hash — otherwise this would also be `ReorderedBodies`'
                // body ↔ hash disagreement (G2), and a G2 refusal would
                // mask the I7 one this mutation exists to provoke.
                candidate.block.transaction_hashes = candidate
                    .transactions
                    .iter()
                    .map(Transaction::hash)
                    .collect();
            }
        }
        Ok(candidate)
    }
}

impl fmt::Display for Mutation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} (expects {})", self.expected().as_str())
    }
}

/// What a mutation needs to know about the run that will judge it
/// (§3.10, *Environment a mutation needs*).
pub struct Environment<'a> {
    /// The clock the substrate will report — C1's bound is computed from
    /// it, not guessed.
    pub clock: Timestamp,
    /// The PoW leg, for [`Mutation::PowUnderWrongSeed`] only.
    pub pow: Option<Pow<'a>>,
}

/// The PoW leg of an [`Environment`]: enough to mine a block against the
/// wrong seed and know it fails under the right one.
pub struct Pow<'a> {
    /// The longhash the substrate computes — the fixture's mock or the
    /// production verifier.
    pub longhash: &'a dyn Fn(&[u8], &BlockHash) -> PowHash,
    /// The target the block must satisfy (D1b's `check_hash` operand).
    pub difficulty: Difficulty,
    /// The seed the chain actually holds at the block's seed height — what
    /// the pipeline will claim.
    pub true_seed: BlockHash,
    /// The seed the block is mined against instead.
    pub wrong_seed: BlockHash,
    /// How many nonces to try before giving up. At difficulty 2 a nonce
    /// qualifies with probability 1/4; `u32::MAX` is not a budget anyone
    /// wants to wait for.
    pub nonce_budget: u32,
}

impl Pow<'_> {
    /// Whether `blob` satisfies the target under `seed` — D1b's comparison,
    /// evaluated by the one KAT-ported function.
    fn satisfies(&self, blob: &[u8], seed: &BlockHash) -> bool {
        check_hash((self.longhash)(blob, seed).as_bytes(), self.difficulty)
    }

    /// The first nonce in `0..nonce_budget` whose longhash satisfies the
    /// target under [`Self::wrong_seed`] **and fails it** under
    /// [`Self::true_seed`] — both legs, so the mutated block is not merely
    /// unlucky under the true seed but *valid* under the wrong one.
    fn mine_against_wrong_seed(&self, candidate: &Candidate) -> Result<u32, Unmutable> {
        if self.true_seed == self.wrong_seed {
            return Err(Unmutable::SeedsCoincide);
        }
        let mut block = candidate.block.clone();
        for nonce in 0..self.nonce_budget {
            block.header.nonce = nonce;
            let blob = block.pow_blob();
            if self.satisfies(&blob, &self.wrong_seed) && !self.satisfies(&blob, &self.true_seed) {
                return Ok(nonce);
            }
        }
        Err(Unmutable::NonceBudgetExhausted {
            tried: self.nonce_budget,
        })
    }
}

/// Why a candidate could not carry a mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unmutable {
    /// `major_version` is already `u8::MAX`.
    #[error("major_version is u8::MAX; nothing to bump to")]
    HeaderVersionSaturated,
    /// `PowUnderWrongSeed` without an [`Environment::pow`].
    #[error("PowUnderWrongSeed needs the environment's PoW leg")]
    NoPowEnvironment,
    /// The two seeds are equal, so no nonce can pass one and fail the other.
    #[error("true and wrong seed coincide; no nonce can separate them")]
    SeedsCoincide,
    /// No qualifying nonce within the budget.
    #[error("no nonce in 0..{tried} passes under the wrong seed and fails under the true one")]
    NonceBudgetExhausted {
        /// Nonces tried.
        tried: u32,
    },
    /// The coinbase has no output to misprice.
    #[error("the miner transaction has no output")]
    NoCoinbaseOutput,
    /// Fewer than two listed bodies.
    #[error("{listed} listed body(ies); two are needed to reorder")]
    TooFewBodies {
        /// Bodies the candidate lists.
        listed: usize,
    },
    /// No key image was spent before this height.
    #[error("nothing was spent before this height; no key image to reuse")]
    NothingSpentBefore,
    /// The candidate lists no `ToKey` input to repurpose.
    #[error("the candidate has no ToKey input to repeat a spend through")]
    NoSpendToRepeat,
}

/// A [`Source`] that replays `inner` and replaces the `Extend` at `at`
/// with a mutated candidate (module docs).
pub struct Mutated<'a, S> {
    inner: S,
    at: BlockHeight,
    mutation: Mutation,
    env: Environment<'a>,
    /// Height of the next `Extend` the inner source yields.
    next_height: BlockHeight,
    /// Key images spent by the `Extend`s passed through so far.
    spent: Vec<[u8; 32]>,
    applied: bool,
}

impl<'a, S: Source> Mutated<'a, S> {
    /// Wrap `inner`, mutating its `Extend` at `at`. `at` below the inner
    /// source's first height can never fire; the wrapper reports that at
    /// exhaustion as [`MutationFault::NeverReached`] rather than
    /// passing a valid chain off as a mutated one.
    pub fn new(inner: S, at: BlockHeight, mutation: Mutation, env: Environment<'a>) -> Self {
        let next_height = inner.first_height();
        Self {
            inner,
            at,
            mutation,
            env,
            next_height,
            spent: Vec::new(),
            applied: false,
        }
    }

    /// The mutation this source applies.
    #[must_use]
    pub const fn mutation(&self) -> Mutation {
        self.mutation
    }

    /// The height it applies it at.
    #[must_use]
    pub const fn at(&self) -> BlockHeight {
        self.at
    }

    fn remember_spends(&mut self, candidate: &Candidate) {
        for tx in &candidate.transactions {
            for input in &tx.prefix.inputs {
                if let Input::ToKey { key_image, .. } = input {
                    self.spent.push(*key_image);
                }
            }
        }
    }
}

/// Why the wrapper could not produce its next event.
#[derive(Debug, thiserror::Error)]
pub enum MutationFault<F> {
    /// The inner source's fault.
    #[error("inner source: {0:?}")]
    Inner(F),
    /// The inner source emitted a `Rewind`; the family is Extend-only.
    #[error("the inner source emitted Rewind {{ to: {to} }}; the mutation family is Extend-only")]
    Rewind {
        /// The rewind's target.
        to: BlockHeight,
    },
    /// The candidate at `at` could not carry the mutation.
    #[error("{mutation} at height {at}: {cause}")]
    Unmutable {
        /// Which mutation.
        mutation: Mutation,
        /// Where.
        at: BlockHeight,
        /// Why.
        cause: Unmutable,
    },
    /// The inner source ended before `at`; nothing was mutated.
    #[error("the inner source ended at height {last} without reaching {at}; nothing was mutated")]
    NeverReached {
        /// The mutation height.
        at: BlockHeight,
        /// The height after the last `Extend` the inner source yielded.
        last: BlockHeight,
    },
}

impl<S: Source> Source for Mutated<'_, S> {
    type Fault = MutationFault<S::Fault>;

    fn first_height(&self) -> BlockHeight {
        self.inner.first_height()
    }

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault> {
        let Some(Sequenced { seq, event }) = self.inner.next().map_err(MutationFault::Inner)?
        else {
            if !self.applied {
                return Err(MutationFault::NeverReached {
                    at: self.at,
                    last: self.next_height,
                });
            }
            return Ok(None);
        };
        let candidate = match event {
            IngestEvent::Extend(candidate) => candidate,
            IngestEvent::Rewind { to } => return Err(MutationFault::Rewind { to }),
        };
        let height = self.next_height;
        self.next_height = BlockHeight::from_raw(height.to_raw() + 1);
        let candidate = if height == self.at {
            self.applied = true;
            Box::new(
                self.mutation
                    .apply(*candidate, &self.env, &self.spent)
                    .map_err(|cause| MutationFault::Unmutable {
                        mutation: self.mutation,
                        at: self.at,
                        cause,
                    })?,
            )
        } else {
            self.remember_spends(&candidate);
            candidate
        };
        Ok(Some(Sequenced {
            seq,
            event: IngestEvent::Extend(candidate),
        }))
    }
}
