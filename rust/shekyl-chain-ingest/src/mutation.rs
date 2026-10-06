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
//!   happens today** (§3.10's last column: the block connects; until E6
//!   slice 6 ported CEN-I7 one pin was a store belt halting the run). The
//!   pin is not acceptance of the gap; it is the
//!   gap made a red test the moment the row is ported, because the branch
//!   is chosen by the census at every run. The census is the falsifier.
//!   **No member names a pending row since E6 slice 7 wave B** (F18 was
//!   the last); the arm is a panic naming what a new member must add.
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
//! adds events, and it is **Extend-only**: a `Rewind` or an `Inject` from
//! the inner source is a wrapper fault — a mutation on a fork is the
//! reorg × mutation cross §3.10 names as out of scope, and a mutation over
//! an out-of-band write has no family (the one chain carrying an `Inject`
//! is `emission-claim`, which no mutation targets).

use core::fmt;

use shekyl_chain_rules::{ArchivalKey, Candidate, CenRow};
use shekyl_difficulty::{check_hash, is_timestamp_below_ftl, Difficulty, FTL_SECONDS};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};
use shekyl_wire::{Ct, Input, Transaction};

use crate::source::{IngestEvent, Sequenced, ServeCredit, Source};

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

/// A `referenceBlock` no chain holds — [`Mutation::UnknownReference`]'s.
/// Its own value, like [`ORPHAN_PARENT`]: this module is production code
/// and cannot reach the rules harness's `UNRECORDED_REFERENCE` (a
/// test-only feature); the two need not agree, only both be unheld.
const UNHELD_REFERENCE: BlockHash = BlockHash::from_bytes([0x99; 32]);

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
    /// CEN-G2's index arm at `Listed(0)` — the first mismatching index.
    ReorderedBodies,
    /// One listed body dropped; the header still declares its hash.
    /// CEN-G2's length arm, at the block (the evidence is two lengths).
    MissingBody,
    /// The listed body at index 0 replaced by a transaction the header
    /// never lists (the same body, its `unlock_time` moved, so it parses,
    /// hashes differently, and is otherwise the spend it was); the count
    /// unchanged. CEN-G2's index arm at `Listed(0)`.
    SubstitutedBody,
    /// A listed spend reuses a key image an earlier block spent.
    DoubleSpend,
    /// A listed spend's `referenceBlock` names a hash the chain never held
    /// (the harness's `UNRECORDED_REFERENCE`). CEN-I10, at the transaction.
    UnknownReference,
    /// A listed spend's `referenceBlock` is the candidate's own parent — a
    /// block the chain holds, one block old, `MIN_AGE − 1` too young.
    /// CEN-I11, at the transaction. The old edge of the window is the
    /// mock's (`I11::window`): a chain past `MAX_AGE` is longer than the
    /// mutation fixtures build (§3.10).
    ReferenceTooRecent,
    /// One byte of a listed spend's first `pqc_auths` slot's signature
    /// flipped. CEN-I18, at that input. The signature is forged and the
    /// body left alone: a driven chain's spends are signed once, by the
    /// wallet, and the body-changed-under-a-signature case is the mock's.
    ForgedSignature,
    /// A body an earlier block already carries, listed again (the header
    /// lists its hash). CEN-G1's chain arm, at the slot — **before** the
    /// slot loop, or I7 would refuse it first (slice 7 Q8's ordering pin).
    RelistedTransaction,
    /// The candidate's own first body listed a second time. CEN-G1's
    /// intra-block arm, at the second slot — before L1 can see the double.
    DoubledListing,
    /// A second serve-credit body carrying a `(P, shard, E)` the block
    /// already carries: the first serve-credit body cloned with its
    /// `unlock_time` moved (a different transaction, the same key).
    /// CEN-G7, at the second vin.
    DuplicateServeCredit,
    /// A second bond post for a `P` the block already posts for, the same
    /// way. CEN-G10, at the second vin.
    ///
    /// There is no `DuplicateClaim` beside it. An emission claim's twin
    /// has to be a claim the emission rows admit — a proof over the tree
    /// at its reference (CEN-J21), a budget row for its epoch (J23) — and
    /// no body this family can hand-build is one. CEN-G9's witness through
    /// the production pipeline is the driver's: two assembled claims by
    /// one persona for one epoch, listed in one block
    /// (`scenario_emission_tests`, E6 slice 8 row 9).
    DuplicateBondPost,
    /// Bodies from the environment's supply listed until the block's weight
    /// exceeds the bound the caller states (`2 × M`). CEN-F14, at the block.
    OverweightBlock,
}

/// What the chain below the mutated height established, as the wrapper
/// collected it from the `Extend`s passed through: the key images spent
/// (`DoubleSpend`'s operand) and the first listed body
/// (`RelistedTransaction`'s).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Before {
    /// Key images spent by the blocks below the mutated height.
    pub spent: Vec<[u8; 32]>,
    /// The first transaction any block below listed, if one did.
    pub listed: Option<Transaction>,
}

impl Before {
    /// Fold one connected candidate's contribution.
    pub fn remember(&mut self, candidate: &Candidate) {
        for tx in &candidate.transactions {
            for input in &tx.prefix.inputs {
                if let Input::ToKey { key_image, .. } = input {
                    self.spent.push(*key_image);
                }
            }
        }
        if self.listed.is_none() {
            self.listed = candidate.transactions.first().cloned();
        }
    }
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
    /// The refusal points at a listed transaction (`Locus::Tx { slot:
    /// TxSlot::Listed(_) }`) — CEN-I10 and CEN-I11, whose subject is the
    /// transaction's reference, not an input (§3.10).
    Listed,
    /// The spec has not named the place. Not a guessed block locus.
    Unnamed,
}

impl Mutation {
    /// Every mutation, in the table's order (§3.10).
    pub const ALL: [Self; 19] = [
        Self::HeaderVersion,
        Self::Orphan,
        Self::WrongRoot,
        Self::FutureTimestamp,
        Self::StaleTimestamp,
        Self::PowUnderWrongSeed,
        Self::WrongReward,
        Self::ReorderedBodies,
        Self::MissingBody,
        Self::SubstitutedBody,
        Self::RelistedTransaction,
        Self::DoubledListing,
        Self::DuplicateServeCredit,
        Self::DuplicateBondPost,
        Self::OverweightBlock,
        Self::DoubleSpend,
        Self::UnknownReference,
        Self::ReferenceTooRecent,
        Self::ForgedSignature,
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
            Self::ReorderedBodies | Self::MissingBody | Self::SubstitutedBody => CenRow::G2,
            Self::RelistedTransaction | Self::DoubledListing => CenRow::G1,
            Self::DuplicateServeCredit => CenRow::G7,
            Self::DuplicateBondPost => CenRow::G10,
            Self::OverweightBlock => CenRow::F14,
            Self::DoubleSpend => CenRow::I7,
            Self::UnknownReference => CenRow::I10,
            Self::ReferenceTooRecent => CenRow::I11,
            Self::ForgedSignature => CenRow::I18,
        }
    }

    /// Where [`Self::expected`] points. Exhaustive, so a new mutation names
    /// its place at the same time as its row.
    #[must_use]
    pub const fn expected_place(self) -> ExpectedPlace {
        match self {
            // The header rows and D1 name the block; so does CEN-G2's
            // length arm (slice 7 Q8: two lengths, no slot) — `MissingBody`.
            Self::HeaderVersion
            | Self::Orphan
            | Self::WrongRoot
            | Self::FutureTimestamp
            | Self::StaleTimestamp
            // F14's evidence is the block's summed weight (slice 7 Q8).
            | Self::PowUnderWrongSeed
            | Self::MissingBody
            | Self::OverweightBlock => ExpectedPlace::Block,
            // The three archival passes name the second occurrence's vin.
            Self::DoubleSpend
            | Self::ForgedSignature
            | Self::DuplicateServeCredit
            | Self::DuplicateBondPost => ExpectedPlace::Input,
            // I10/I11 name the transaction; so does CEN-G2's index arm (slice
            // 7 Q8: the first mismatching index — `Listed(0)` for both G2
            // mutations, since both move the body at 0) and both of G1's arms
            // (the slot whose hash the rule looked up).
            Self::UnknownReference
            | Self::ReferenceTooRecent
            | Self::ReorderedBodies
            | Self::SubstitutedBody
            | Self::RelistedTransaction
            | Self::DoubledListing => ExpectedPlace::Listed,
            // 4.F named its locus with slice 4 (Q6): the miner transaction.
            Self::WrongReward => ExpectedPlace::Miner,
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
        before: &Before,
        at: BlockHeight,
    ) -> Result<Candidate, Unmutable> {
        let spent_before = before.spent.as_slice();
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
            Self::MissingBody => {
                // The header keeps every hash; the last body is gone.
                if candidate.transactions.pop().is_none() {
                    return Err(Unmutable::TooFewBodies { listed: 0 });
                }
            }
            Self::SubstitutedBody => {
                // The header keeps its hash; the body under it is another
                // transaction — this one with its `unlock_time` moved, which
                // changes the prefix and so the hash while leaving a body
                // that parses. One violation: the header is not re-listed,
                // because the disagreement *is* the violation.
                let Some(first) = candidate.transactions.first_mut() else {
                    return Err(Unmutable::TooFewBodies { listed: 0 });
                };
                move_unlock_time(first)?;
            }
            Self::RelistedTransaction => {
                // A body a block below already carries, listed again; the
                // header lists it (G2 agrees) so the disagreement is G1's
                // alone — and G1's before I7's, which the same image would
                // also trip if the rule ran after the loop.
                let earlier = before
                    .listed
                    .clone()
                    .ok_or(Unmutable::NothingListedBefore)?;
                candidate.transactions.push(earlier);
                relist(&mut candidate);
            }
            Self::DoubledListing => {
                let Some(first) = candidate.transactions.first().cloned() else {
                    return Err(Unmutable::TooFewBodies { listed: 0 });
                };
                candidate.transactions.push(first);
                relist(&mut candidate);
            }
            Self::DuplicateServeCredit => {
                // A serve-credit body carries no `pqc_auths` (CEN-H20), so
                // its twin is the same body with its `unlock_time` moved: a
                // different transaction, the same `(P, shard, E)`.
                let mut twin = candidate
                    .transactions
                    .iter()
                    .find(|tx| {
                        tx.prefix
                            .inputs
                            .iter()
                            .any(|input| ArchivalKind::ServeCredit.carried_by(input))
                    })
                    .cloned()
                    .ok_or(Unmutable::NoArchivalBodyToDuplicate {
                        kind: ArchivalKind::ServeCredit,
                    })?;
                move_unlock_time(&mut twin)?;
                candidate.transactions.push(twin);
                relist(&mut candidate);
            }
            Self::DuplicateBondPost => {
                Self::list_supplied_twin(&mut candidate, env, ArchivalKind::BondPost)?;
            }
            Self::OverweightBlock => {
                let supply = env.overweight.as_ref().ok_or(Unmutable::NoBodySupply)?;
                let weight = |c: &Candidate| -> u64 {
                    let bodies: usize = c.transactions.iter().map(Transaction::weight).sum();
                    u64::try_from(c.block.miner_transaction.weight() + bodies).expect("fits")
                };
                let mut bodies = supply.bodies.iter();
                while weight(&candidate) <= supply.bound {
                    let body = bodies.next().ok_or(Unmutable::BodySupplyExhausted {
                        reached: weight(&candidate),
                        bound: supply.bound,
                    })?;
                    candidate.transactions.push(body.clone());
                }
                relist(&mut candidate);
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
                relist(&mut candidate);
            }
            Self::UnknownReference => {
                Self::move_reference(&mut candidate, UNHELD_REFERENCE)?;
            }
            Self::ReferenceTooRecent => {
                // The parent is on the chain (I10 passes) and one block old
                // (I11 refuses): the young edge, from the driver.
                let parent = candidate.block.header.previous;
                Self::move_reference(&mut candidate, parent)?;
            }
            Self::ForgedSignature => {
                let mut signatures =
                    candidate
                        .transactions
                        .iter_mut()
                        .filter_map(|tx| match &mut tx.ct {
                            Ct::Fcmp { pqc_auths, .. } => pqc_auths.first_mut(),
                            Ct::Null(_) => None,
                        });
                let Some(last) = signatures
                    .next()
                    .and_then(|auth| auth.hybrid_signature.last_mut())
                else {
                    return Err(Unmutable::NoSignatureToForge);
                };
                *last ^= 0x01;
                // The auths are the txid's third component: one violation
                // only if the header follows the body.
                relist(&mut candidate);
            }
        }
        Ok(candidate)
    }

    /// Point the first listed spend's `referenceBlock` at `reference` and
    /// re-list the header (one violation, as `DoubleSpend` does).
    fn move_reference(candidate: &mut Candidate, reference: BlockHash) -> Result<(), Unmutable> {
        let mut references = candidate
            .transactions
            .iter_mut()
            .filter_map(|tx| match &mut tx.ct {
                Ct::Fcmp {
                    reference_block, ..
                } => Some(reference_block),
                Ct::Null(_) => None,
            });
        let Some(reference_block) = references.next() else {
            return Err(Unmutable::NoReferenceToMove);
        };
        *reference_block = reference;
        relist(candidate);
        Ok(())
    }
}

/// Which archival body a `Duplicate*` mutation clones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchivalKind {
    /// A parseable serve-credit vin (`ArchivalServeCreditResponse`).
    ServeCredit,
    /// A bond post.
    BondPost,
}

impl ArchivalKind {
    /// Whether `input` carries a key this kind duplicates — the rule's own
    /// parse (`ArchivalKey::of`), so the family and the validator agree on
    /// what has a key; an unparseable vin is another row's and has none.
    fn carried_by(self, input: &Input) -> bool {
        matches!(
            (self, ArchivalKey::of(input)),
            (Self::ServeCredit, Some(ArchivalKey::ServeCredit { .. }))
                | (Self::BondPost, Some(ArchivalKey::BondPost { .. }))
        )
    }
}

/// Whether two archival keys collide under their rule: one `(P, shard, E)`
/// (G7), one `P` (G10). G9's shared-`(P, E)` rule has no mutation here
/// (`DuplicateBondPost` docs), so a claim key collides only with itself.
fn collides(a: &ArchivalKey, b: &ArchivalKey) -> bool {
    match (a, b) {
        (ArchivalKey::BondPost { p }, ArchivalKey::BondPost { p: q }) => p == q,
        (a, b) => a == b,
    }
}

impl Mutation {
    /// List a body from the environment's twins that collides, under
    /// `kind`'s rule, with a key the candidate already carries. A bond-post
    /// body is signed over its content (its `pqc_auths` slot, CEN-I18), so
    /// a second valid body with the same key cannot be made from the first
    /// — the caller supplies one it built with the keys.
    fn list_supplied_twin(
        candidate: &mut Candidate,
        env: &Environment<'_>,
        kind: ArchivalKind,
    ) -> Result<(), Unmutable> {
        let keys: Vec<ArchivalKey> = candidate
            .transactions
            .iter()
            .flat_map(|tx| tx.prefix.inputs.iter())
            .filter(|input| kind.carried_by(input))
            .filter_map(ArchivalKey::of)
            .collect();
        if keys.is_empty() {
            return Err(Unmutable::NoArchivalBodyToDuplicate { kind });
        }
        let listed: Vec<_> = candidate.block.transaction_hashes.clone();
        let twin = env
            .twins
            .iter()
            .find(|twin| {
                !listed.contains(&twin.hash())
                    && twin
                        .prefix
                        .inputs
                        .iter()
                        .filter_map(ArchivalKey::of)
                        .any(|theirs| keys.iter().any(|ours| collides(ours, &theirs)))
            })
            .cloned()
            .ok_or(Unmutable::NoTwinSupplied { kind })?;
        candidate.transactions.push(twin);
        relist(candidate);
        Ok(())
    }
}

/// Move a body's `unlock_time` by one: a different prefix, a different
/// hash, a body that still parses.
fn move_unlock_time(tx: &mut Transaction) -> Result<(), Unmutable> {
    tx.prefix.unlock_time = tx
        .prefix
        .unlock_time
        .checked_add(1)
        .ok_or(Unmutable::UnlockTimeSaturated)?;
    Ok(())
}

/// The header lists the bodies as they now are: a body mutation is one
/// violation only if the hashes follow it (G2 would otherwise mask it).
fn relist(candidate: &mut Candidate) {
    candidate.block.transaction_hashes = candidate
        .transactions
        .iter()
        .map(Transaction::hash)
        .collect();
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
    /// The weight leg, for [`Mutation::OverweightBlock`] only: valid bodies
    /// the caller built for the mutated height, and the bound to pass.
    /// Absent, the mutation is [`Unmutable::NoBodySupply`] — a corpus chain
    /// carries no spare bodies, and the bound (`2 × M`) is the validator's
    /// to know, not this wrapper's.
    pub overweight: Option<Overweight<'a>>,
    /// Twins for [`Mutation::DuplicateBondPost`]: bodies valid at the
    /// mutated height whose archival key collides with one the block
    /// already carries. A bond-post body is signed over its content, so
    /// the family cannot forge a second from the first; a serve-credit body
    /// carries no signature slot and needs none. Empty for a corpus chain.
    pub twins: &'a [Transaction],
}

/// The weight leg of an [`Environment`].
pub struct Overweight<'a> {
    /// Bodies valid at the mutated height, each with a fresh key image,
    /// listed in order until the block passes `bound`.
    pub bodies: &'a [Transaction],
    /// The weight the block must exceed — `2 × M` for the effective median
    /// in force, which the caller states (the fixture chains are young, so
    /// `M` is the zone).
    pub bound: u64,
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
    /// Too few listed bodies for the mutation: two to reorder, one to drop
    /// or substitute.
    #[error("{listed} listed body(ies); the mutation needs more")]
    TooFewBodies {
        /// Bodies the candidate lists.
        listed: usize,
    },
    /// A body whose `unlock_time` is `u64::MAX`; moving it by one does not
    /// fit (`SubstitutedBody`, the `Duplicate*` twins).
    #[error("the body's unlock_time is u64::MAX; nothing to move it to")]
    UnlockTimeSaturated,
    /// [`Mutation::RelistedTransaction`] with no block below listing a body.
    #[error("no block below this height listed a transaction; nothing to re-list")]
    NothingListedBefore,
    /// A `Duplicate*` mutation on a block carrying no parseable body of its
    /// kind.
    #[error("the candidate carries no parseable {kind:?} body to duplicate")]
    NoArchivalBodyToDuplicate {
        /// The kind sought.
        kind: ArchivalKind,
    },
    /// [`Mutation::OverweightBlock`] without an [`Environment::overweight`].
    #[error("OverweightBlock needs the environment's body supply and bound")]
    NoBodySupply,
    /// A `Duplicate*` mutation whose twin must be supplied
    /// ([`Environment::twins`]) found none colliding with the block's keys.
    #[error("no supplied twin collides with the block's {kind:?} key")]
    NoTwinSupplied {
        /// The kind sought.
        kind: ArchivalKind,
    },
    /// The supply ran out before the block passed the bound.
    #[error("the body supply ran out at {reached} bytes, under the bound {bound}")]
    BodySupplyExhausted {
        /// The block's weight when the supply ran out.
        reached: u64,
        /// The bound it had to pass.
        bound: u64,
    },
    /// No key image was spent before this height.
    #[error("nothing was spent before this height; no key image to reuse")]
    NothingSpentBefore,
    /// The candidate lists no `ToKey` input to repurpose.
    #[error("the candidate has no ToKey input to repeat a spend through")]
    NoSpendToRepeat,
    /// [`Mutation::UnknownReference`] / [`Mutation::ReferenceTooRecent`] on
    /// a block that lists no `Fcmp` body.
    #[error("the candidate lists no Fcmp body whose reference could move")]
    NoReferenceToMove,
    /// [`Mutation::ForgedSignature`] on a block that lists no body with a
    /// `pqc_auths` slot carrying a signature.
    #[error("the candidate lists no pqc_auths slot with a signature to forge")]
    NoSignatureToForge,
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
    /// What the `Extend`s passed through so far established.
    before: Before,
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
            before: Before::default(),
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
    /// except a `Rewind` or an `Inject`, which are still the Extend-only
    /// faults.
    fn pull_past_end(&mut self) -> Result<Option<Sequenced<IngestEvent>>, MutationFault<S::Fault>> {
        match self.inner.next() {
            Err(fault) => self.fail(MutationFault::Inner(fault)),
            Ok(None) => self.end(),
            Ok(Some(Sequenced {
                event: IngestEvent::Rewind { to },
                ..
            })) => self.fail(MutationFault::Rewind { to }),
            Ok(Some(Sequenced {
                event: IngestEvent::Inject(credit),
                ..
            })) => self.fail(MutationFault::Inject(credit)),
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
    /// The inner source emitted an `Inject`; the family is Extend-only.
    #[error("the inner source emitted an out-of-band serve credit for {persona} (shard {shard}, epoch {epoch}); the mutation family is Extend-only", persona = .0.persona, shard = .0.shard, epoch = .0.epoch)]
    Inject(ServeCredit),
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
            IngestEvent::Inject(credit) => return self.fail(MutationFault::Inject(credit)),
        };
        let produced = if height == self.at {
            match self
                .mutation
                .apply(*candidate, &self.env, &self.before, height)
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
            self.before.remember(&candidate);
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
