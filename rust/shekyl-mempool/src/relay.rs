// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay interface (DRS-E5 PR-b b3): the pool knows one relay fact,
//! whether a transaction is public yet (`DAEMON_RELAY_PRIVACY.md` D++
//! acceptance criterion 2), and this module is every way it is read or
//! written.
//!
//! **Written by the relay's fluff event** ([`Pool::fluffed`]), for a
//! transaction that arrived by relay or this node's own submit. A
//! transaction returned from a popped block is admitted public: a block
//! carried it, so the network already holds it, and a stem phase for it
//! would hide nothing — it would only keep a transaction the chain has
//! published out of the next template. Nothing clears the bit.
//!
//! **Read through one predicate** ([`shown`]): what the node shows the
//! world — the pool listing, peer pool sync and the block template — is a
//! public entry. A stem-phase transaction is in none of them.
//!
//! Stem, fluff, embargo, the arrival connector and the originator's
//! re-broadcast responsibility are `shekyl-relay`'s (DX-F6). The relay
//! takes [`Pool::unpublished`] at open: after a restart nothing tells this
//! node's own transactions from arrivals still in stem, and the relay
//! handles them alike.

use shekyl_chain_store::pool::PoolRecord;
use shekyl_chain_store::store::StoreError;
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

use crate::pool::Pool;
use crate::rate::FeeRate;
use crate::view::KeyImages;

/// Whether the node may show `record`'s transaction to anyone: public.
/// Criterion 2's one check — the listing, peer sync and the template all
/// ask it.
#[must_use]
pub const fn shown(record: &PoolRecord) -> bool {
    record.public
}

/// The pool as the relay and the submit shim read it: every entry, those
/// still in their stem phase included (the review of #1102, S6). Criterion 2
/// is what such a reader enforces, not what it is given: nothing that
/// answers a peer or a foreign caller reads the pool through this — a
/// fluffy block's missing-transaction answer, `is_key_image_spent`, a
/// listing — but through [`shown`] (the listing, peer sync and the
/// template), as the C++ paths filter on `relay_category::broadcasted`.
#[derive(Clone, Copy)]
pub struct RelayView<'p> {
    pool: &'p Pool,
}

impl RelayView<'_> {
    /// The record the pool holds for `txid`.
    #[must_use]
    pub fn record(&self, txid: &TxHash) -> Option<PoolRecord> {
        self.pool.record(txid)
    }

    /// The key images the pool's entries spend (CEN-M7's map).
    #[must_use]
    pub fn key_images(&self) -> &KeyImages {
        self.pool.key_images()
    }

    /// Whether CEN-M10's rising minimum refuses a transaction of `tx`'s
    /// weight and fee against the pool as it stands — the answer
    /// [`Pool::admit`] gives a fresh submission as `Admission::PoolFull`,
    /// asked without admitting anything. An entry at the same rate is never
    /// evicted for it (only strictly cheaper ones are), so for a held `tx`
    /// this is the answer another transaction at its weight and fee would
    /// get: what a concealed duplicate must answer, so that resubmitting a
    /// stem transaction is no presence oracle when the pool is full (Copilot,
    /// #1102).
    #[must_use]
    pub fn refuses_for_room(&self, tx: &Transaction) -> bool {
        let weight = u64::try_from(tx.weight()).unwrap_or(u64::MAX);
        self.pool
            .room_for(weight, FeeRate::new(crate::pool::fee_of(tx), weight))
            .is_none()
    }

    /// How many transactions the pool holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Whether the pool holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }
}

/// One entry of [`Pool::listing`]: what a pool listing says of a shown
/// transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listed {
    /// Its weight.
    pub weight: u64,
    /// The fee it pays.
    pub fee: AtomicUnits,
}

impl Pool {
    /// The pool as the relay reads it ([`RelayView`]).
    #[must_use]
    pub const fn relay_view(&self) -> RelayView<'_> {
        RelayView { pool: self }
    }

    /// The relay's fluff event: `txid` is public now. `Ok(false)` when the
    /// pool does not hold it — the relay fluffed something the pool has
    /// already dropped, which is not an error. Idempotent.
    ///
    /// # Errors
    ///
    /// The pool file's; the bit is set in memory only after the file holds
    /// it.
    pub fn fluffed(&mut self, txid: &TxHash) -> Result<bool, StoreError> {
        if !self.held().contains_key(txid) {
            return Ok(false);
        }
        self.store().write(|batch| batch.publish(txid))?;
        if let Some(held) = self.held_mut().get_mut(txid) {
            held.record.public = true;
        }
        Ok(true)
    }

    /// The pool listing: every entry the node shows ([`shown`]), with its
    /// weight and fee — never when this node received it (the review of
    /// #1102, S7: a receive time across many nodes' listings points at a
    /// transaction's origin).
    pub fn listing(&self) -> impl Iterator<Item = (TxHash, Listed)> + '_ {
        self.held()
            .iter()
            .filter(|(_, held)| shown(&held.record))
            .map(|(txid, held)| {
                (
                    *txid,
                    Listed {
                        weight: held.weight,
                        fee: held.fee,
                    },
                )
            })
    }

    /// What peer pool sync may offer: the transactions the node shows.
    pub fn peer_sync(&self) -> impl Iterator<Item = (TxHash, &Transaction)> + '_ {
        self.held()
            .iter()
            .filter(|(_, held)| shown(&held.record))
            .map(|(txid, held)| (*txid, &held.tx))
    }

    /// The body of `txid` if the node shows it: what a compact block's
    /// listed hash is resolved from (`DRS_X_STORE_FLIP.md` PR2-Q4). An entry
    /// the pool holds that is not public is `None`, as if not held: a node
    /// that resolved a stem transaction from its pool would tell the block's
    /// sender, by not asking for it, that it holds it.
    #[must_use]
    pub fn shown_body(&self, txid: &TxHash) -> Option<&Transaction> {
        self.held()
            .get(txid)
            .filter(|held| shown(&held.record))
            .map(|held| &held.tx)
    }

    /// What the relay still holds back: entries not yet public — what it
    /// takes at open (module docs).
    pub fn unpublished(&self) -> impl Iterator<Item = (TxHash, &Transaction)> + '_ {
        self.held()
            .iter()
            .filter(|(_, held)| !held.record.public)
            .map(|(txid, held)| (*txid, &held.tx))
    }
}
