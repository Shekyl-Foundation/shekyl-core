// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool: the transactions it holds, the key images they spend, and the
//! pool file (DRS-E5 PR-b; `DRS_E5_POOL_ALT_PRUNE.md` §2.2, `DRS_E1_SPOOL.md`).
//!
//! Every transaction enters through [`Pool::admit`], which runs the door
//! ([`crate::door::judge`]) and writes the pool file (P1) only after the
//! door has decided: nothing the chain or the policy refused is stored, and
//! a write never precedes the judgement it records.
//!
//! The index is in memory — the parsed transaction, its record and the key
//! images it spends — and the file is its durable copy. The file is
//! discardable by ruling (`SPL-Q8`): a pool that loses it loses only the
//! transactions it held, never a fact the chain needs.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use shekyl_chain_rules::{
    AdmissionPolicy, AtHeight, ChainView, Fault, HeaderView, InvalidBlock, RuleSet, StatelessPass,
    Tip,
};
use shekyl_chain_store::pool::{PoolOpen, PoolRecord, PoolStore, ReceivedHour};
use shekyl_chain_store::store::StoreError;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHeight, KeyImage, TxHash, UnixSeconds};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{Ct, Input};
use shekyl_wire::Transaction;

use crate::door::{self, DoorFault, Judged};
use crate::evict::Limits;
use crate::rate::{AdmissionRank, FeeRate};
use crate::view::KeyImages;

/// Step 1 of the door, relative to the pool lock.
///
/// [`Step1::Prepared`] was computed before the lock, so admission does not
/// verify signatures and proofs while it holds the pool. [`Step1::Judge`]
/// runs step 1 under the lock, reusing `prior` when the claim still holds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Step1 {
    /// Judge step 1 here, reusing `prior` when it holds.
    Judge(Option<StatelessPass>),
    /// Step 1 already ran. An error is the refusal, and it is not run again.
    Prepared(Result<StatelessPass, InvalidBlock>),
}

/// How a transaction reached the door — which decides only whether it is
/// public on admission. Crate-private (the review of #1102, S6): only
/// [`Pool::returned`] and [`Pool::supplement`] reach [`Arrival::Carried`],
/// so no caller can admit a peer's transaction as public and skip its
/// embargo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// From a peer or this node's own submit: not public until the relay's
    /// fluff event says so.
    Relayed,
    /// A block carried it: returned from a block a switch popped, or
    /// listed by an alternative block the store holds (CEN-K9). Public,
    /// because the block published it. Held only if the door admits it: the
    /// store holds every such block's bodies for any switch, so the pool's
    /// answer decides relay and templates and nothing else (`block.rs`).
    Carried,
}

/// A transaction the pool already accounts for (CEN-M1): nothing is
/// judged again. A held one a block carries is made public; nothing else
/// changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duplicate {
    /// The pool holds it.
    InPool,
    /// The chain holds it.
    OnChain,
}

/// What [`Pool::admit`] did with a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The door admitted it, and the pool holds it, having evicted
    /// `evicted` in the same write to make room (CEN-M10: entries paying
    /// less per weight, the cheapest first).
    Admitted {
        /// What left to make room, in eviction order.
        evicted: Vec<TxHash>,
    },
    /// Already accounted for (CEN-M1).
    Duplicate(Duplicate),
    /// Refused, and not held: the door's answer.
    Refused(Judged),
    /// Refused, and not held: the pool is full and holds nothing it would
    /// give up for this transaction (CEN-M10; `evict.rs`). Decided before
    /// the door's crypto for a candidate that pays no more per weight than
    /// the cheapest admitted entry.
    PoolFull,
}

/// What the pool could not do — never a judgement about a transaction.
#[derive(Debug)]
pub enum PoolFault<F> {
    /// The chain view faulted, or a judgement against it could not be made
    /// ([`Fault`]).
    Chain(Fault<F>),
    /// The connecting height the door priced against is no longer the tip.
    /// Nothing was written. The caller reads the chain again and judges
    /// once more.
    TipMoved {
        /// The connecting height the window was read at.
        asked: BlockHeight,
        /// The connecting height read again after the window answered above
        /// the tip.
        now: BlockHeight,
    },
    /// The pool file faulted.
    Store(StoreError),
}

impl<F> PoolFault<F> {
    /// The door's fault as the pool's. A chain fault stays one. A tip that
    /// moved is named, and the transaction stays unjudged.
    pub(crate) fn door(fault: DoorFault<F>) -> Self {
        match fault {
            DoorFault::Chain(fault) => Self::Chain(fault),
            DoorFault::TipMoved { asked, now } => Self::TipMoved { asked, now },
        }
    }
}

impl<F> From<StoreError> for PoolFault<F> {
    fn from(fault: StoreError) -> Self {
        Self::Store(fault)
    }
}

/// One held transaction: the parsed body, its record (what the file holds),
/// and what the pool derives and keeps in memory only — the weight and fee,
/// which the bytes say, and the door's stateless pass (CEN-M8's cache and
/// more: the review of #1102, S1), which an untrusted file must not supply
/// (`codec/pool.rs`).
#[derive(Clone, Debug)]
pub(crate) struct Held {
    pub(crate) tx: Transaction,
    pub(crate) record: PoolRecord,
    pub(crate) weight: u64,
    pub(crate) fee: AtomicUnits,
    /// The door's step 1 when it last admitted this transaction, which
    /// holds while its rule set and its claim do; `None` until a judgement
    /// here (a row read back from the file).
    pub(crate) pass: Option<StatelessPass>,
}

impl Held {
    /// `tx` under `record`, its weight and fee read off its bytes.
    pub(crate) fn of(tx: Transaction, record: PoolRecord, pass: Option<StatelessPass>) -> Self {
        Self {
            weight: u64::try_from(tx.weight()).unwrap_or(u64::MAX),
            fee: AtomicUnits::from_raw(fee_of(&tx)),
            tx,
            record,
            pass,
        }
    }

    /// The key images this transaction spends, in input order.
    pub(crate) fn key_images(&self) -> Vec<KeyImage> {
        key_images_of(&self.tx)
    }

    /// This entry's fee per weight.
    pub(crate) fn rate(&self) -> FeeRate {
        FeeRate::new(self.fee.to_raw(), self.weight)
    }

    /// This entry in the order eviction and template selection share.
    pub(crate) fn rank(&self, txid: TxHash) -> AdmissionRank {
        AdmissionRank::new(self.rate(), self.record.received, txid)
    }
}

/// The key images `tx` spends: one per `ToKey` input.
pub(crate) fn key_images_of(tx: &Transaction) -> Vec<KeyImage> {
    tx.prefix
        .inputs
        .iter()
        .filter_map(|input| match input {
            Input::ToKey { key_image, .. } => Some(KeyImage::from_bytes(*key_image)),
            _ => None,
        })
        .collect()
}

/// The pool.
pub struct Pool {
    store: PoolStore,
    key_images: KeyImages,
    held: BTreeMap<TxHash, Held>,
    /// CEN-M10's limits, read off the chain (`Limits::at`) at open and set
    /// by the writer at each connect ([`Pool::set_limits`]).
    limits: Limits,
    /// Step 1 already run outside the pool lock, consumed by the next
    /// reconcile. Not durable: the file must not supply a pass.
    prepared: HashMap<TxHash, Result<StatelessPass, InvalidBlock>>,
    /// The tip the entries were last judged against, with the work that
    /// ordered it. `None` when they were not judged at one tip.
    /// [`Pool::judged_at`] is the tip a template compares to its parent.
    judged_at: Option<JudgedTip>,
}

/// A tip the pool judged against, and the fork-choice work through it.
///
/// Work, not height, orders two tips: a reorg can land at the same height
/// or a shorter one and still be the chain. A stale snapshot of the lighter
/// tip must not move this, and must not leave it naming the lighter tip
/// after a heavier one was judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct JudgedTip {
    tip: Tip,
    work: CumulativeDifficulty,
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool")
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// The pool file at `path`, with nothing in memory yet — [`Pool::open`]'s
    /// first step, which then reads the file back and reconciles it.
    pub(crate) fn create(
        path: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<(Self, PoolOpen), StoreError> {
        let (store, how) = PoolStore::create(path)?;
        Ok((
            Self {
                store,
                key_images: KeyImages::default(),
                held: BTreeMap::new(),
                limits,
                prepared: HashMap::new(),
                judged_at: None,
            },
            how,
        ))
    }

    /// Admit `tx`, relayed — from a peer or this node's own submit — at
    /// `now`, against `chain` under `rule_set` and `policy`: the one way
    /// into the pool from outside it. Not public until the relay's fluff
    /// event says so.
    ///
    /// CEN-M1 first: a transaction the pool or the chain already holds is
    /// a [`Duplicate`] and nothing is judged. Then CEN-M10's rising
    /// minimum, then the door. An admitted transaction is written to the
    /// file (P1) and its key images enter the map (CEN-M7). Everything else
    /// is refused and leaves no trace.
    ///
    /// # Errors
    ///
    /// [`PoolFault::Chain`] if the view faulted; [`PoolFault::TipMoved`] if
    /// the tip dropped under the relay-floor window; [`PoolFault::Store`]
    /// if the file did. Nothing was admitted.
    pub fn admit<'id, V: ChainView<'id>>(
        &mut self,
        tx: Transaction,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Admission, PoolFault<V::Fault>> {
        self.admit_from(
            tx,
            Step1::Judge(None),
            Arrival::Relayed,
            now,
            chain,
            rule_set,
            policy,
        )
    }

    /// [`Pool::admit`] with `prior`, a pass the caller computed for `tx`
    /// before taking the pool ([`crate::stateless`]): the door uses it when
    /// its claim still holds here and judges step 1 again otherwise, so a
    /// submit's verification runs outside whatever lock guards the pool
    /// (the review of #1102, S1).
    ///
    /// # Errors
    ///
    /// As [`Pool::admit`].
    pub fn admit_judged<'id, V: ChainView<'id>>(
        &mut self,
        tx: Transaction,
        prior: Option<StatelessPass>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Admission, PoolFault<V::Fault>> {
        self.admit_from(
            tx,
            Step1::Judge(prior),
            Arrival::Relayed,
            now,
            chain,
            rule_set,
            policy,
        )
    }

    /// Admission by `arrival`. A held transaction a block carries is made
    /// public (P2): a block has published it on every node, and a pool
    /// that kept it hidden would answer peer sync differently for a
    /// transaction it held in its stem phase than for one it did not — a
    /// possession oracle for anyone who can send an alternative block.
    #[allow(
        clippy::too_many_arguments,
        reason = "admit's arguments, the prior pass and the arrival"
    )]
    pub(crate) fn admit_from<'id, V: ChainView<'id>>(
        &mut self,
        tx: Transaction,
        step1: Step1,
        arrival: Arrival,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Admission, PoolFault<V::Fault>> {
        let txid = tx.txid_parts().hash;
        let carried = arrival == Arrival::Carried;
        if let Some(held) = self.held.get_mut(&txid) {
            if carried && !held.record.public {
                self.store.write(|batch| batch.publish(&txid))?;
                held.record.public = true;
            }
            return Ok(Admission::Duplicate(Duplicate::InPool));
        }
        if chain
            .has_transaction(&txid)
            .map_err(|fault| PoolFault::Chain(Fault::View(fault)))?
        {
            return Ok(Admission::Duplicate(Duplicate::OnChain));
        }
        // CEN-M10's rising minimum, before the door's crypto: a full pool
        // holds nothing it would give up for a candidate paying no more per
        // weight than its cheapest admitted entry.
        let weight = u64::try_from(tx.weight()).unwrap_or(u64::MAX);
        let rate = FeeRate::new(fee_of(&tx), weight);
        if self.room_for(weight, rate).is_none() {
            return Ok(Admission::PoolFull);
        }
        // A step 1 that already refused is the door's answer. It is not
        // run again under this lock. One that passed is the prior `judge`
        // reuses while its claim holds.
        let prior = match step1 {
            Step1::Prepared(Err(refused)) => {
                return Ok(Admission::Refused(Judged::Stateless(refused)));
            }
            Step1::Prepared(Ok(pass)) => Some(pass),
            Step1::Judge(prior) => prior,
        };
        let judged = door::judge(
            &tx,
            chain,
            &self.key_images,
            rule_set,
            policy,
            prior.as_ref(),
        )
        .map_err(PoolFault::door)?;
        let Judged::Admitted { pass, .. } = judged else {
            return Ok(Admission::Refused(judged));
        };
        let Some(evicted) = self.room_for(weight, rate) else {
            return Ok(Admission::PoolFull);
        };
        let record = PoolRecord {
            received: ReceivedHour::of(now),
            public: carried,
        };
        let blob = tx.serialize();
        self.store.write(|batch| {
            evicted.iter().try_for_each(|gone| batch.remove(gone))?;
            batch.insert(txid, &record, &blob)
        })?;
        for gone in &evicted {
            self.drop_held(gone);
        }
        self.hold(txid, Held::of(tx, record, Some(*pass)));
        if let Ok(Some(tip)) = chain.tip() {
            self.note_admitted(chain, tip);
        }
        Ok(Admission::Admitted { evicted })
    }

    /// Record that this admission judged at `tip`.
    ///
    /// A heavier tip replaces the marker, so a template still holding the
    /// lighter snapshot sees a different parent and evicts nothing. The same
    /// tip refreshes it. Equal work under another hash clears it: the two
    /// chains are not ordered. A lighter tip leaves the marker, so a stale
    /// snapshot cannot blank a heavier one or restore the old identity.
    fn note_admitted<'id, V: HeaderView<'id>>(&mut self, chain: &V, tip: Tip) {
        self.judged_at = match tip_with_work(chain, tip) {
            Some(admitted) => judged_tip_after(self.judged_at, admitted),
            None => None,
        };
    }

    /// The reconcile re-judged every entry at `tip`. That tip is the marker,
    /// including when it is lighter than the one an earlier admission saw:
    /// the entries now agree with it. No readable work means they do not.
    pub(crate) fn note_reconciled<'id, V: HeaderView<'id>>(&mut self, chain: &V, tip: Option<Tip>) {
        self.judged_at = tip.and_then(|tip| tip_with_work(chain, tip));
    }

    /// The tip the entries were last judged against. `None` before any
    /// judgement against a chain with a tip, when the last judgement was
    /// against a chain of equal work and a different hash, or when that
    /// tip's work could not be read. A template selects only when this is
    /// its own parent; otherwise it would refuse, and evict, entries valid
    /// at the tip they were judged at.
    #[must_use]
    pub const fn judged_at(&self) -> Option<Tip> {
        match self.judged_at {
            Some(JudgedTip { tip, .. }) => Some(tip),
            None => None,
        }
    }

    /// Put `held` in the index and its key images in the map (CEN-M7).
    pub(crate) fn hold(&mut self, txid: TxHash, held: Held) {
        self.key_images.insert(txid, held.key_images());
        self.held.insert(txid, held);
    }

    /// Entries whose step 1 must run before the next reconcile: none yet
    /// (a file entry), or a pass whose claim no longer holds against
    /// `chain` under `rule_set` (a reorg moved its reference, or the rule
    /// set changed). The caller runs step 1 outside the pool lock and
    /// stages it ([`Pool::stage_step1`]), so [`Pool::reconcile`] verifies
    /// nothing while it holds the pool. Reads the chain; verifies nothing.
    ///
    /// # Errors
    ///
    /// The chain view's.
    pub fn needing_step1<'id, V: ChainView<'id>>(
        &self,
        chain: &V,
        rule_set: &RuleSet,
    ) -> Result<Vec<(TxHash, Transaction)>, V::Fault> {
        let connecting = shekyl_chain_rules::Tip::connecting_height(chain.tip()?.as_ref());
        let mut needing = Vec::new();
        for (txid, held) in &self.held {
            let holds = match &held.pass {
                None => false,
                Some(pass) => {
                    let claims = shekyl_chain_rules::ReferenceClaims::for_transaction(
                        chain, connecting, &held.tx,
                    )?;
                    pass.holds_under(&held.tx, rule_set, &claims)
                }
            };
            if !holds {
                needing.push((*txid, held.tx.clone()));
            }
        }
        Ok(needing)
    }

    /// Remember step 1 for `txid` until the next reconcile consumes it.
    /// An entry that left the pool since the caller read it is ignored.
    pub fn stage_step1(&mut self, txid: TxHash, step1: Result<StatelessPass, InvalidBlock>) {
        if self.held.contains_key(&txid) {
            self.prepared.insert(txid, step1);
        }
    }

    /// Every staged step 1, for the reconcile that consumes them. Taken
    /// before the held index is borrowed.
    pub(crate) fn take_planted(&mut self) -> HashMap<TxHash, Result<StatelessPass, InvalidBlock>> {
        std::mem::take(&mut self.prepared)
    }

    /// Put `held`, read back from the file at open, in the index — and not
    /// its key images: the file is not trusted (two entries in it may claim
    /// one image), and the reconcile that follows builds the map.
    pub(crate) fn load(&mut self, txid: TxHash, held: Held) {
        self.held.insert(txid, held);
    }

    /// Drop `txid` from the index and its key images from the map — after
    /// the file has dropped it.
    pub(crate) fn drop_held(&mut self, txid: &TxHash) {
        if let Some(held) = self.held.remove(txid) {
            self.key_images.remove(txid, held.key_images());
        }
    }

    /// Put a reconcile's outcome in the index once the file holds it: each
    /// entry's judgement (`None` drops it, `Some` is the door's pass), and
    /// the key-image map the reconcile built beside the live one.
    pub(crate) fn install(
        &mut self,
        judged: &BTreeMap<TxHash, Option<StatelessPass>>,
        key_images: KeyImages,
    ) {
        for (txid, outcome) in judged {
            match outcome {
                None => {
                    self.held.remove(txid);
                }
                Some(pass) => {
                    if let Some(held) = self.held.get_mut(txid) {
                        held.pass = Some(*pass);
                    }
                }
            }
        }
        self.key_images = key_images;
    }

    /// The next write to the pool file whose closure returns `Ok` aborts as
    /// a commit failure ([`PoolStore::refuse_next_commit`]). Test builds
    /// only (`pool-commit-fault`).
    #[cfg(feature = "pool-commit-fault")]
    pub fn refuse_next_commit(&self) {
        self.store.refuse_next_commit();
    }

    /// The pool file.
    pub(crate) const fn store(&self) -> &PoolStore {
        &self.store
    }

    /// The index.
    pub(crate) const fn held(&self) -> &BTreeMap<TxHash, Held> {
        &self.held
    }

    /// The index, to change one entry's in-memory record after the file
    /// holds the change.
    pub(crate) fn held_mut(&mut self) -> &mut BTreeMap<TxHash, Held> {
        &mut self.held
    }

    /// The record the pool holds for `txid` — every entry's, the stem phase
    /// included; outside the crate, [`crate::RelayView::record`].
    #[must_use]
    pub(crate) fn record(&self, txid: &TxHash) -> Option<PoolRecord> {
        self.held.get(txid).map(|held| held.record)
    }

    /// How many transactions the pool holds, the stem phase included.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether the pool holds none.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// CEN-M10's limits in force.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Set CEN-M10's limits: the writer's, at each connect, from
    /// [`Limits::at`] over the chain it connected. Entries over a cap that
    /// shrank leave at the next [`Pool::evict`].
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// The key images the pool's entries spend (CEN-M7's map), the stem
    /// phase's included.
    #[must_use]
    pub(crate) fn key_images(&self) -> &KeyImages {
        &self.key_images
    }
}

#[cfg(any(test, feature = "pool-commit-fault"))]
impl Pool {
    /// Hold `tx` under `record` without the door — for the tests of what the
    /// pool does with what it holds (eviction's arithmetic, a write that
    /// faults), never of what it admits. Written to the file and the index
    /// as `admit` would. Test builds only (`pool-commit-fault`).
    ///
    /// # Panics
    ///
    /// When the pool file refuses the write.
    pub fn plant(&mut self, tx: Transaction, record: PoolRecord) -> TxHash {
        let txid = tx.txid_parts().hash;
        let blob = tx.serialize();
        self.store
            .write(|batch| batch.insert(txid, &record, &blob))
            .expect("plant");
        self.hold(txid, Held::of(tx, record, None));
        txid
    }
}

/// The admission's tip with the work through its own header, or `None`
/// when this view does not record that header.
fn tip_with_work<'id, V: HeaderView<'id>>(chain: &V, tip: Tip) -> Option<JudgedTip> {
    match chain.header_at(tip.height) {
        Ok(AtHeight::Recorded(record)) if record.hash == tip.hash => Some(JudgedTip {
            tip,
            work: record.cumulative_difficulty,
        }),
        _ => None,
    }
}

/// The marker after an admission judged at `admitted`.
///
/// Heavier work replaces it. The same tip refreshes it. Equal work under
/// another hash clears it. Lighter work leaves it.
fn judged_tip_after(recorded: Option<JudgedTip>, admitted: JudgedTip) -> Option<JudgedTip> {
    match recorded {
        None => Some(admitted),
        Some(at) if at.tip == admitted.tip => Some(admitted),
        Some(at) if admitted.work > at.work => Some(admitted),
        Some(at) if admitted.work == at.work => None,
        Some(at) => Some(at),
    }
}

/// The fee `tx` pays: the `Fcmp` field, zero on a `Null` ct (which the door
/// refused off the coinbase before anything reads this).
pub(crate) fn fee_of(tx: &Transaction) -> u64 {
    match &tx.ct {
        Ct::Fcmp { fee, .. } => *fee,
        Ct::Null(_) => 0,
    }
}

#[cfg(test)]
#[path = "pool_tests.rs"]
mod pool_tests;
