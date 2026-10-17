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
//! public entry the door admitted. A stem-phase transaction is in none of
//! them, and a kept one (CEN-K10) is in none of them either: it is not a
//! pool-valid transaction.
//!
//! Stem, fluff, embargo, the arrival connector and the originator's
//! re-broadcast responsibility are `shekyl-relay`'s (DX-F6). The relay
//! takes [`Pool::unpublished`] at open: after a restart nothing tells this
//! node's own transactions from arrivals still in stem, and the relay
//! handles them alike.

use shekyl_chain_store::pool::{PoolRecord, Standing};
use shekyl_chain_store::store::StoreError;
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

use crate::pool::Pool;

/// Whether the node may show `record`'s transaction to anyone: public, and
/// admitted. Criterion 2's one check — the listing, peer sync and the
/// template all ask it.
#[must_use]
pub fn shown(record: &PoolRecord) -> bool {
    record.public && record.standing == Standing::Admitted
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

    /// What the relay still holds back: admitted entries not yet public —
    /// what it takes at open (module docs).
    pub fn unpublished(&self) -> impl Iterator<Item = (TxHash, &Transaction)> + '_ {
        self.held()
            .iter()
            .filter(|(_, held)| !held.record.public && held.record.standing == Standing::Admitted)
            .map(|(txid, held)| (*txid, &held.tx))
    }
}
