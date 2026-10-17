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

use std::collections::BTreeMap;
use std::path::Path;

use shekyl_chain_rules::{AdmissionPolicy, ChainView, Fault, RuleSet};
use shekyl_chain_store::pool::{PoolOpen, PoolRecord, PoolStore, ProvenReference, Standing};
use shekyl_chain_store::store::StoreError;
use shekyl_types::{KeyImage, TxHash, UnixSeconds};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{Ct, Input};
use shekyl_wire::Transaction;

use crate::door::{self, Judged};
use crate::view::KeyImages;

/// How a transaction reached the door.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// From a peer or this node's own submit: not public until the relay's
    /// fluff event says so.
    Relayed,
    /// From a block the chain popped (CEN-K10): public, because a block
    /// carried it, and kept if the chain-bound half refuses it.
    Returned,
}

/// A transaction the pool already accounts for (CEN-M1): nothing is
/// judged again and nothing changes.
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
    /// The door admitted it; the pool holds it as [`Standing::Admitted`].
    Admitted,
    /// A returned transaction the chain-bound half refused: held as
    /// [`Standing::Kept`] — never relayed, never selected, and evicted by
    /// CEN-M10 (CEN-K10).
    Kept,
    /// Already accounted for (CEN-M1).
    Duplicate(Duplicate),
    /// Refused, and not held: the door's answer.
    Refused(Judged),
}

/// What the pool could not do — never a judgement about a transaction.
#[derive(Debug)]
pub enum PoolFault<F> {
    /// The chain view faulted, or a judgement against it could not be made
    /// ([`Fault`]).
    Chain(Fault<F>),
    /// The pool file faulted.
    Store(StoreError),
}

impl<F> From<StoreError> for PoolFault<F> {
    fn from(fault: StoreError) -> Self {
        Self::Store(fault)
    }
}

/// One held transaction.
#[derive(Clone, Debug)]
pub(crate) struct Held {
    pub(crate) tx: Transaction,
    pub(crate) record: PoolRecord,
}

impl Held {
    /// The key images this transaction spends, in input order.
    pub(crate) fn key_images(&self) -> Vec<KeyImage> {
        key_images_of(&self.tx)
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
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<(Self, PoolOpen), StoreError> {
        let (store, how) = PoolStore::create(path)?;
        Ok((
            Self {
                store,
                key_images: KeyImages::default(),
                held: BTreeMap::new(),
            },
            how,
        ))
    }

    /// Admit `tx`, which arrived as `arrival` at `now`, against `chain`
    /// under `rule_set` and `policy` — the one way into the pool.
    ///
    /// CEN-M1 first: a transaction the pool or the chain already holds is
    /// a [`Duplicate`] and nothing is judged. Then the door. An admitted
    /// transaction is written to the file (P1) and its key images enter the
    /// map (CEN-M7); a returned one the chain-bound half refused is written
    /// as kept and spends nothing in the map — it is not a pool-valid
    /// transaction, so it blocks no other spend. Everything else is refused
    /// and leaves no trace.
    ///
    /// # Errors
    ///
    /// [`PoolFault::Chain`] if the view faulted; [`PoolFault::Store`] if the
    /// file did. Either way nothing was admitted.
    pub fn admit<'id, V: ChainView<'id>>(
        &mut self,
        tx: Transaction,
        arrival: Arrival,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Admission, PoolFault<V::Fault>> {
        let txid = tx.txid_parts().hash;
        if self.held.contains_key(&txid) {
            return Ok(Admission::Duplicate(Duplicate::InPool));
        }
        if chain
            .has_transaction(&txid)
            .map_err(|fault| PoolFault::Chain(Fault::View(fault)))?
        {
            return Ok(Admission::Duplicate(Duplicate::OnChain));
        }
        let judged = door::judge(&tx, chain, &self.key_images, rule_set, policy)
            .map_err(PoolFault::Chain)?;
        let (standing, admission) = match (judged, arrival) {
            (Judged::Admitted { proven, .. }, _) => (
                Standing::Admitted {
                    proven: proven.map(ProvenReference::of),
                },
                Admission::Admitted,
            ),
            (Judged::Chain(_), Arrival::Returned) => (Standing::Kept, Admission::Kept),
            (refused, _) => return Ok(Admission::Refused(refused)),
        };
        let record = PoolRecord {
            weight: u64::try_from(tx.weight()).unwrap_or(u64::MAX),
            fee: AtomicUnits::from_raw(fee_of(&tx)),
            receive_time: now,
            public: arrival == Arrival::Returned,
            standing,
        };
        let blob = tx.serialize();
        self.store
            .write(|batch| batch.insert(txid, &record, &blob))?;
        self.hold(txid, Held { tx, record });
        Ok(admission)
    }

    /// Put `held` in the index: an admitted entry's key images enter the
    /// map (CEN-M7); a kept one's do not — it is not a pool-valid
    /// transaction, so it blocks no other spend.
    pub(crate) fn hold(&mut self, txid: TxHash, held: Held) {
        if matches!(held.record.standing, Standing::Admitted { .. }) {
            self.key_images.insert(txid, held.key_images());
        }
        self.held.insert(txid, held);
    }

    /// Take every entry out of the index, emptying the key-image map with
    /// it — the reconcile's start. The file is untouched.
    pub(crate) fn take_all(&mut self) -> BTreeMap<TxHash, Held> {
        self.key_images = KeyImages::default();
        core::mem::take(&mut self.held)
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

    /// The record the pool holds for `txid`.
    #[must_use]
    pub fn record(&self, txid: &TxHash) -> Option<PoolRecord> {
        self.held.get(txid).map(|held| held.record)
    }

    /// How many transactions the pool holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether the pool holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The key images the pool's admitted entries spend (CEN-M7's map).
    #[must_use]
    pub fn key_images(&self) -> &KeyImages {
        &self.key_images
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
