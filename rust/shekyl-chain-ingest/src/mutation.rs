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
//! *other* row is itself a finding, and the family's tests assert the row
//! and [`Mutation::expected_place`], never merely "refused".
//!
//! # The oracle is the census, not the C++
//!
//! Every [`Mutation`] names its [`Mutation::expected`] row and the
//! [`ExpectedPlace`] that row points at. What a consumer asserts depends
//! on that row's own status ([`CenRow::status`](shekyl_chain_rules::CenRow::status)):
//!
//! - `Implemented` — the run's refusal is `(height, InvalidBlock { rule:
//!   expected, locus: the place })`. A place the spec has not named
//!   ([`ExpectedPlace::Unnamed`]) is a failed assertion, not a guessed
//!   block locus.
//! - `Pending` — the rule is not in Rust yet, and the family **pins what
//!   happens today** (§3.10's last column: the block connects, or a store
//!   belt halts the run). The pin is not acceptance of the gap; it is the
//!   gap made a red test the moment the row is ported, because the branch
//!   is chosen by the census at every run. The census is the falsifier.
//!
//! A regtest daemon's verdict is secondary evidence (§1.3) and lives in
//! item 8's regtest leg; trace tag `0x03` stays RESERVED.
//!
//! # A provocation the row cannot judge is [`Unmutable`]
//!
//! CEN-C1 and CEN-C2 do not read the timestamp at genesis, so a timestamp
//! mutation there would connect. `clock + FTL + 1` that does not fit in a
//! `u64` is not past the limit either: the predicate's saturating subtract
//! still accepts `u64::MAX`. Both are faults, not candidates.
//!
//! # Heights are the pipeline's
//!
//! An `Extend` carries no height. The wrapper counts from its inner
//! source's `first_height` by [`BlockCount::ONE`], and mutates the `Extend`
//! where that count equals `at`. The cursor moves only after the event
//! exists. The block at `u64::MAX` is yielded; the event after it is
//! [`MutationFault::HeightExhausted`]. A fault is not retryable
//! ([`MutationFault::Stopped`]). The wrapper never reorders, renumbers or
//! adds events, and it is **Extend-only**: a `Rewind` from the inner source
//! is a wrapper fault — a mutation on a fork is the reorg × mutation cross
//! §3.10 names as out of scope.

use core::fmt;

use shekyl_chain_rules::{Candidate, CenRow};
use shekyl_difficulty::{check_hash, is_timestamp_below_ftl, Difficulty, FTL_SECONDS};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};
use shekyl_wire::{Input, Transaction};

use crate::source::{IngestEvent, Sequenced, Source};

/// One second past the future-time limit CEN-C1 accepts (`clock + FTL`).
const PAST_FTL: u64 = FTL_SECONDS + 1;

/// A timestamp at the bottom of the range. CEN-C2 requires a timestamp
/// strictly above the median; zero is below every median a chain can hold.
const STALE_TIMESTAMP: u64 = 0;

/// How far `major_version` moves. One step past the version the rule set
/// admits is CEN-B1's inequality.
const VERSION_STEP: u8 = 1;

/// How far the coinbase's clear output amount moves. One atomic unit is
/// CEN-F18's inequality (exact payout).
const REWARD_OFF_BY: u64 = 1;

/// `previous` no chain holds. Not [`BlockHash::NULL`]: that value is
/// genesis's parent, and using it would be a genesis claim.
const ORPHAN_PARENT: [u8; 32] = [0x77; 32];

/// Fill for a curve-tree root this family uses as "never recorded".
/// Distinct from the empty root (zero) and from fixture roots, which fill
/// `0x5c`.
const UNHELD_ROOT_FILL: u8 = 0x5a;
pub(crate) const UNHELD_ROOT: [u8; 32] = [UNHELD_ROOT_FILL; 32];

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
    /// [`Unmutable`] at genesis and when that instant does not fit.
    FutureTimestamp,
    /// `timestamp` = `0`: at or below every MTP median.
    /// [`Unmutable`] at genesis, where CEN-C2 does not judge.
    StaleTimestamp,
    /// The nonce re-mined so the longhash satisfies the target under a
    /// **wrong** seed and fails it under the true one. The pipeline claims
    /// the true seed (RD-Q5), so `form` hashes under it and D1 refuses.
    /// "Bad seed" is a block *mined* against the wrong seed — the seed is
    /// not in the block.
    PowUnderWrongSeed,
    /// The coinbase's clear output amount off by one. Expects **CEN-F18**,
    /// the exact-payout predicate — not F13, the base-subsidy *definition*,
    /// which the family named until E6 slice 4 landed F13 as a value pin
    /// and showed the key was wrong (`CHAIN_RULES_SLICE_4.md` Q8: a
    /// definition row refuses nothing, so a mutation keyed to it flips to
    /// expecting a refusal that never comes the day the row is ported).
    WrongReward,
    /// Two listed bodies swapped; the header's `tx_hashes` untouched.
    ReorderedBodies,
    /// A listed spend reuses a key image an earlier block spent.
    DoubleSpend,
}

/// Where [`Mutation::expected`]'s row points when it refuses.
///
/// The level the spec names, not a fabricated slot. [`Self::Input`] asserts
/// `Locus::Input` without inventing which input; the rule fills the slot
/// when it is ported. [`Self::Unnamed`] is a row whose place §3.10 does not
/// yet state — the refusal branch fails until the slice that ports the row
/// names it here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExpectedPlace {
    /// The refusal points at the block.
    Block,
    /// The refusal points at the miner transaction — every 4.F row's place
    /// (`Locus::Tx { slot: TxSlot::Miner }`, `CHAIN_RULES_SLICE_4.md` Q6).
    Miner,
    /// The refusal points at an input (CEN-I7, §3.10).
    Input,
    /// The spec has not named the place. Not a guessed block locus.
    Unnamed,
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
            Self::WrongReward => CenRow::F18,
            Self::ReorderedBodies => CenRow::G2,
            Self::DoubleSpend => CenRow::I7,
        }
    }

    /// Where [`Self::expected`] points. Exhaustive, so a new mutation names
    /// its place at the same time as its row.
    #[must_use]
    pub const fn expected_place(self) -> ExpectedPlace {
        match self {
            Self::HeaderVersion
            | Self::Orphan
            | Self::WrongRoot
            | Self::FutureTimestamp
            | Self::StaleTimestamp
            | Self::PowUnderWrongSeed => ExpectedPlace::Block,
            Self::DoubleSpend => ExpectedPlace::Input,
            // 4.F named its locus with slice 4 (Q6): the miner transaction.
            Self::WrongReward => ExpectedPlace::Miner,
            // 4.G has not named a locus. Guessing `Block` would make the
            // port go red for the test's assumption.
            Self::ReorderedBodies => ExpectedPlace::Unnamed,
        }
    }

    /// CEN-C1 and CEN-C2 return before reading the timestamp when the
    /// connecting height is genesis. A timestamp written there is not
    /// their violation.
    fn refuse_genesis(self, at: BlockHeight) -> Result<(), Unmutable> {
        if at.is_zero() {
            Err(Unmutable::GenesisExempt(self))
        } else {
            Ok(())
        }
    }

    /// Apply this mutation to a valid `candidate` connecting at `at`, given
    /// the environment the run will judge it in and the key images the chain
    /// spent before it.
    ///
    /// # Errors
    ///
    /// [`Unmutable`] when the candidate cannot carry this violation (no
    /// listed body to reorder, no earlier spend to repeat, a timestamp the
    /// named row will not judge) or the environment lacks the leg the
    /// mutation needs.
    pub fn apply(
        self,
        mut candidate: Candidate,
        env: &Environment<'_>,
        spent_before: &[[u8; 32]],
        at: BlockHeight,
    ) -> Result<Candidate, Unmutable> {
        match self {
            Self::HeaderVersion => {
                let version = &mut candidate.block.header.major_version;
                *version = version
                    .checked_add(VERSION_STEP)
                    .ok_or(Unmutable::HeaderVersionSaturated)?;
            }
            Self::Orphan => {
                candidate.block.header.previous = BlockHash::from_bytes(ORPHAN_PARENT);
            }
            Self::WrongRoot => {
                candidate.block.header.curve_tree_root = CurveTreeRoot::from_bytes(UNHELD_ROOT);
            }
            Self::FutureTimestamp => {
                self.refuse_genesis(at)?;
                let timestamp = env
                    .clock
                    .checked_add_secs(PAST_FTL)
                    .ok_or(Unmutable::NoRepresentableFuture)?;
                debug_assert!(
                    !is_timestamp_below_ftl(timestamp, env.clock),
                    "PAST_FTL must be the instant CEN-C1 refuses"
                );
                candidate.block.header.timestamp = timestamp.to_raw();
            }
            Self::StaleTimestamp => {
                self.refuse_genesis(at)?;
                candidate.block.header.timestamp = STALE_TIMESTAMP;
            }
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
                output.amount = output
                    .amount
                    .checked_add(REWARD_OFF_BY)
                    .ok_or(Unmutable::RewardSaturated)?;
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
    /// The PoW leg, for [`Mutation::PowUnderWrongSeed`] only. Absent for
    /// every other mutation; supplying it there is ignored.
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
    /// qualifies under one seed with probability 1/2, and under one seed
    /// while failing the other with probability 1/4. `u32::MAX` is not a
    /// budget anyone wants to wait for.
    pub nonce_budget: u32,
}

/// The first nonce in `0..budget` for which `accept` holds.
pub(crate) fn first_nonce(budget: u32, mut accept: impl FnMut(u32) -> bool) -> Option<u32> {
    (0..budget).find(|&nonce| accept(nonce))
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
        first_nonce(self.nonce_budget, |nonce| {
            block.header.nonce = nonce;
            let blob = block.pow_blob();
            self.satisfies(&blob, &self.wrong_seed) && !self.satisfies(&blob, &self.true_seed)
        })
        .ok_or(Unmutable::NonceBudgetExhausted {
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
    /// The clear amount is `u64::MAX`; one atomic unit does not fit.
    #[error("the coinbase amount is u64::MAX; one atomic unit does not fit")]
    RewardSaturated,
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
    /// CEN-C1 and CEN-C2 do not judge genesis, so a timestamp written
    /// there is not their violation.
    #[error("{0} is exempt at genesis; CEN-C1 and CEN-C2 do not judge height 0")]
    GenesisExempt(Mutation),
    /// `clock + FTL + 1` does not fit in a timestamp. `u64::MAX` is still
    /// at or below the limit the saturating predicate accepts.
    #[error("clock + FTL + 1 does not fit in a timestamp; CEN-C1 would still accept u64::MAX")]
    NoRepresentableFuture,
}

/// Where the next [`IngestEvent::Extend`] will be placed.
///
/// Three states, and the transitions are one way: [`Self::At`] steps by
/// [`BlockCount::ONE`] after an event is built; the step off `u64::MAX`
/// is [`Self::PastEnd`]; any fault is [`Self::Faulted`] and stays there.
/// A pull is not retryable — the inner event was consumed — so a second
/// `next` after a fault must not assign the failed height to a later event.
enum Cursor {
    /// The next `Extend` connects at this height.
    At(BlockHeight),
    /// `u64::MAX` has been yielded. Another event has no height.
    PastEnd,
    /// `next` has already failed.
    Faulted,
}

/// A [`Source`] that replays `inner` and replaces the `Extend` at `at`
/// with a mutated candidate (module docs).
pub struct Mutated<'a, S> {
    inner: S,
    at: BlockHeight,
    mutation: Mutation,
    env: Environment<'a>,
    /// Height of the next `Extend`, or why no further one can be placed.
    cursor: Cursor,
    /// Key images spent by the `Extend`s passed through so far.
    spent: Vec<[u8; 32]>,
    /// Whether the `Extend` at `at` was yielded.
    applied: bool,
}

impl<'a, S: Source> Mutated<'a, S> {
    /// Wrap `inner`, mutating its `Extend` at `at`. `at` below the inner
    /// source's first height can never fire; the wrapper reports that at
    /// exhaustion as [`MutationFault::NeverReached`] rather than
    /// passing a valid chain off as a mutated one.
    pub fn new(inner: S, at: BlockHeight, mutation: Mutation, env: Environment<'a>) -> Self {
        let cursor = Cursor::At(inner.first_height());
        Self {
            inner,
            at,
            mutation,
            env,
            cursor,
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

    /// Record the fault and refuse every later pull.
    fn fail<T>(&mut self, fault: MutationFault<S::Fault>) -> Result<T, MutationFault<S::Fault>> {
        self.cursor = Cursor::Faulted;
        Err(fault)
    }

    /// The inner source ended. A mutation that fired is a clean end; one
    /// that never fired is [`MutationFault::NeverReached`].
    fn end(&self) -> Result<Option<Sequenced<IngestEvent>>, MutationFault<S::Fault>> {
        if self.applied {
            Ok(None)
        } else {
            Err(MutationFault::NeverReached {
                at: self.at,
                next: match self.cursor {
                    Cursor::At(height) => Some(height),
                    Cursor::PastEnd | Cursor::Faulted => None,
                },
            })
        }
    }

    /// `u64::MAX` was yielded. Another event is [`MutationFault::HeightExhausted`],
    /// except a `Rewind`, which is still the Extend-only fault.
    fn pull_past_end(&mut self) -> Result<Option<Sequenced<IngestEvent>>, MutationFault<S::Fault>> {
        match self.inner.next() {
            Err(fault) => self.fail(MutationFault::Inner(fault)),
            Ok(None) => self.end(),
            Ok(Some(Sequenced {
                event: IngestEvent::Rewind { to },
                ..
            })) => self.fail(MutationFault::Rewind { to }),
            Ok(Some(_)) => self.fail(MutationFault::HeightExhausted {
                after: BlockHeight::from_raw(u64::MAX),
            }),
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
    #[error("the inner source ended before height {at}; nothing was mutated")]
    NeverReached {
        /// The mutation height.
        at: BlockHeight,
        /// The height the next `Extend` would have carried. `None` once
        /// `u64::MAX` has been yielded — no further height exists, and
        /// `at` was below the inner source's first height.
        next: Option<BlockHeight>,
    },
    /// The inner source emitted another event after the block at `u64::MAX`.
    #[error("no height follows {after}; the mutation family cannot place another block")]
    HeightExhausted {
        /// The last height that was yielded.
        after: BlockHeight,
    },
    /// `next` was called again after a fault. The inner event was consumed;
    /// assigning its height to a later event would mutate the wrong block.
    #[error("the wrapper already faulted; a pull is not retryable")]
    Stopped,
}

impl<S: Source> Source for Mutated<'_, S> {
    type Fault = MutationFault<S::Fault>;

    fn first_height(&self) -> BlockHeight {
        self.inner.first_height()
    }

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault> {
        let height = match self.cursor {
            Cursor::Faulted => return Err(MutationFault::Stopped),
            Cursor::PastEnd => return self.pull_past_end(),
            Cursor::At(height) => height,
        };
        let pulled = match self.inner.next() {
            Ok(event) => event,
            Err(fault) => return self.fail(MutationFault::Inner(fault)),
        };
        let Some(Sequenced { seq, event }) = pulled else {
            return self.end();
        };
        let candidate = match event {
            IngestEvent::Extend(candidate) => candidate,
            IngestEvent::Rewind { to } => return self.fail(MutationFault::Rewind { to }),
        };
        let produced = if height == self.at {
            match self
                .mutation
                .apply(*candidate, &self.env, &self.spent, height)
            {
                Ok(mutated) => Box::new(mutated),
                Err(cause) => {
                    return self.fail(MutationFault::Unmutable {
                        mutation: self.mutation,
                        at: self.at,
                        cause,
                    });
                }
            }
        } else {
            self.remember_spends(&candidate);
            candidate
        };
        // The event exists. Now the cursor may move.
        self.cursor = match height.checked_add(BlockCount::ONE) {
            Some(next) => Cursor::At(next),
            None => Cursor::PastEnd,
        };
        if height == self.at {
            self.applied = true;
        }
        Ok(Some(Sequenced {
            seq,
            event: IngestEvent::Extend(produced),
        }))
    }
}
