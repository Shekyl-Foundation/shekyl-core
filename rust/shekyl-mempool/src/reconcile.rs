// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Reconcile against the chain — at open (`E5-8`; `DRS_E1_SPOOL.md` SPL-7,
//! `SPL-Q5`) and whenever the chain under the pool moves.
//!
//! The pool file and the chain file are two files and two commits: a block
//! connect commits the chain first and the pool second, so a crash between
//! the two leaves a mined transaction still in the pool file. Nothing about
//! the pool file is trusted on that account. Reconciling is **one function,
//! and it is the door**: every held transaction is taken out of the index
//! and offered to [`door::judge`] again, against the chain as it now
//! stands, in the order the pool first held them (so where two entries
//! spend one key image, the earlier keeps it). What the door admits stays;
//! what the chain holds leaves; what the chain-bound half refuses is kept,
//! never relayed and never selected, for CEN-M10 to evict — a later reorg
//! may make it valid again (CEN-K10's retention); what the bytes or the
//! policy refuse leaves.
//!
//! No other path decides whether a held transaction is still valid, so the
//! pool after a restart, after a switch and after a connect is the pool the
//! door would build from the same transactions.

use std::collections::BTreeMap;
use std::path::Path;

use shekyl_chain_rules::{AdmissionPolicy, ChainView, Fault, RuleSet};
use shekyl_chain_store::pool::{PoolOpen, PoolRecord, ProvenReference, Standing};
use shekyl_types::TxHash;
use shekyl_wire::Transaction;

use crate::door::{self, Judged};
use crate::pool::{Held, Pool, PoolFault};

/// Why reconciling removed a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Removed {
    /// The chain holds it: mined.
    Mined,
    /// The door refused it on its bytes or by policy.
    Refused(Judged),
    /// Its stored bytes do not parse. The file is the pool's own, so this
    /// is a file this binary did not write; the entry is dropped, which the
    /// discardable file allows (`SPL-Q8`).
    Unparseable,
}

/// What a reconcile did, entry by entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Held and admitted by the door against the current chain.
    pub admitted: Vec<TxHash>,
    /// Held and kept: refused by the chain-bound half.
    pub kept: Vec<TxHash>,
    /// Removed, with why.
    pub removed: Vec<(TxHash, Removed)>,
}

impl Pool {
    /// Open the pool file at `path` and reconcile what it holds against
    /// `chain` ([`Pool::reconcile`]). A file this creates or recreates
    /// (`SPL-Q8`) holds nothing, and the reconcile is empty.
    ///
    /// # Errors
    ///
    /// The store's (a foreign file, an engine fault) or the chain view's.
    pub fn open<'id, V: ChainView<'id>>(
        path: impl AsRef<Path>,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<(Self, PoolOpen, Reconciled), PoolFault<V::Fault>> {
        let (mut pool, how) = Self::create(path)?;
        let mut unparseable = Vec::new();
        let snapshot = pool.store().begin_read()?;
        for entry in snapshot.entries()? {
            let entry = entry?;
            let blob = entry.blob(&snapshot)?;
            match Transaction::from_bytes(&blob) {
                Ok(tx) => pool.hold(
                    entry.txid,
                    Held {
                        tx,
                        record: entry.record,
                    },
                ),
                Err(_) => unparseable.push(entry.txid),
            }
        }
        drop(snapshot);
        let mut reconciled = pool.reconcile(chain, rule_set, policy)?;
        if !unparseable.is_empty() {
            pool.store()
                .write(|batch| unparseable.iter().try_for_each(|txid| batch.remove(txid)))?;
            reconciled.removed.extend(
                unparseable
                    .into_iter()
                    .map(|txid| (txid, Removed::Unparseable)),
            );
        }
        Ok((pool, how, reconciled))
    }

    /// Offer every held transaction to the door again against `chain`, in
    /// the order the pool first held them (module docs), and write what
    /// changed: removals (P3) and standings (P2). The public bit and the
    /// receive time are the entry's own and survive.
    ///
    /// # Errors
    ///
    /// The chain view's or the store's. On a store fault the in-memory index
    /// is the reconciled one and the file is behind it; the next reconcile
    /// (at the latest, the next open) brings the file up.
    pub fn reconcile<'id, V: ChainView<'id>>(
        &mut self,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Reconciled, PoolFault<V::Fault>> {
        let mut order: Vec<(TxHash, Held)> = self.take_all().into_iter().collect();
        order.sort_by_key(|(txid, held)| (held.record.receive_time, *txid));

        let mut reconciled = Reconciled::default();
        let mut changes: BTreeMap<TxHash, Option<Standing>> = BTreeMap::new();
        for (txid, held) in order {
            if chain
                .has_transaction(&txid)
                .map_err(|fault| PoolFault::Chain(Fault::View(fault)))?
            {
                changes.insert(txid, None);
                reconciled.removed.push((txid, Removed::Mined));
                continue;
            }
            let judged = door::judge(&held.tx, chain, self.key_images(), rule_set, policy)
                .map_err(PoolFault::Chain)?;
            let standing = match judged {
                Judged::Admitted { proven, .. } => Standing::Admitted {
                    proven: proven.map(ProvenReference::of),
                },
                Judged::Chain(_) => Standing::Kept,
                refused => {
                    changes.insert(txid, None);
                    reconciled.removed.push((txid, Removed::Refused(refused)));
                    continue;
                }
            };
            if standing != held.record.standing {
                changes.insert(txid, Some(standing));
            }
            match standing {
                Standing::Admitted { .. } => reconciled.admitted.push(txid),
                Standing::Kept => reconciled.kept.push(txid),
            }
            self.hold(
                txid,
                Held {
                    record: PoolRecord {
                        standing,
                        ..held.record
                    },
                    tx: held.tx,
                },
            );
        }
        if !changes.is_empty() {
            self.store().write(|batch| {
                changes.iter().try_for_each(|(txid, change)| match change {
                    None => batch.remove(txid),
                    Some(standing) => batch.stand(txid, *standing),
                })
            })?;
        }
        Ok(reconciled)
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod reconcile_tests;
