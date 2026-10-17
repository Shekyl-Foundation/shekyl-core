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
//! and it is the door**: every held transaction is offered to
//! [`door::judge`] again, against the chain as it now stands, in the order
//! the pool first held them (so where two entries spend one key image, the
//! earlier keeps it). What the door admits stays; what the chain holds
//! leaves.
//!
//! **Kept has one entry point**: [`Pool::admit`], for a transaction a
//! switch returned (CEN-K10). The reconcile never makes an entry kept. An
//! admitted entry the door now refuses leaves, whatever refused it: a
//! relayed transaction a connect made invalid is a double spend already
//! mined or a reference past CEN-I11's window, and neither comes back
//! except through a switch that returns the block's own transaction — which
//! the switch's returns offer again. A kept entry becomes admitted when the
//! whole door admits it, leaves on a refusal on its bytes, and otherwise
//! stays kept until CEN-M10 ages it out.
//!
//! No other path decides whether a held transaction is still valid, so the
//! pool after a restart, after a switch and after a connect is the pool the
//! door would build from the same transactions.

use std::collections::BTreeMap;
use std::path::Path;

use shekyl_chain_rules::{AdmissionPolicy, ChainView, Fault, RuleSet, VerifiedReference};
use shekyl_chain_store::pool::{PoolOpen, ReceivedHour, Standing};
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use crate::door::{self, Judged};
use crate::pool::{Held, Pool, PoolFault};
use crate::view::KeyImages;

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
    /// Its stored bytes are a transaction, and not the one its key names.
    Misfiled,
    /// Its record or its bytes could not be read back: a row that does not
    /// decode, or a record without its bytes. Dropped by itself — a
    /// discardable cache never stops the daemon starting.
    Unreadable,
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
    /// `chain` ([`Pool::reconcile`]) at `now`. A file this creates or
    /// recreates (`SPL-Q8`) holds nothing, and the reconcile is empty.
    ///
    /// **Nothing in the file is trusted** (the review of #1102, S2). Each
    /// row is read on its own: one whose record or bytes cannot be read,
    /// whose bytes do not parse, or whose bytes are not the transaction its
    /// key names is dropped by itself. The weight and fee are read off the
    /// bytes, a receive time later than `now` is clamped to it, and every
    /// entry runs the whole door with no CEN-M8 anchor (the file carries
    /// none).
    ///
    /// # Errors
    ///
    /// The store's (a foreign file, an engine fault) or the chain view's.
    pub fn open<'id, V: ChainView<'id>>(
        path: impl AsRef<Path>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<(Self, PoolOpen, Reconciled), PoolFault<V::Fault>> {
        let (mut pool, how) = Self::create(path)?;
        let latest = ReceivedHour::of(now);
        let mut dropped = Vec::new();
        let snapshot = pool.store().begin_read()?;
        let txids: Vec<TxHash> = snapshot.txids()?.collect::<Result<_, _>>()?;
        for txid in txids {
            let (Ok(Some(mut record)), Ok(Some(blob))) =
                (snapshot.record(&txid), snapshot.blob(&txid))
            else {
                dropped.push((txid, Removed::Unreadable));
                continue;
            };
            let tx = match Transaction::from_bytes(&blob) {
                Ok(tx) if tx.txid_parts().hash == txid => tx,
                Ok(_) => {
                    dropped.push((txid, Removed::Misfiled));
                    continue;
                }
                Err(_) => {
                    dropped.push((txid, Removed::Unparseable));
                    continue;
                }
            };
            record.received = record.received.min(latest);
            pool.load(txid, Held::of(tx, record, None));
        }
        drop(snapshot);
        let mut reconciled = pool.reconcile(chain, rule_set, policy)?;
        if !dropped.is_empty() {
            pool.store()
                .write(|batch| dropped.iter().try_for_each(|(txid, _)| batch.remove(txid)))?;
            reconciled.removed.extend(dropped);
        }
        Ok((pool, how, reconciled))
    }

    /// Offer every held transaction to the door again against `chain`, in
    /// the order the pool first held them (module docs), and write what
    /// changed: removals (P3) and standings (P2). The public bit and the
    /// receive hour are the entry's own and survive; CEN-M8's anchor is
    /// the door's latest, in memory.
    ///
    /// The judgements are made against a key-image map built beside the
    /// live one, the file is written, and only then does the index take the
    /// result: the index never runs ahead of the file.
    ///
    /// # Errors
    ///
    /// The chain view's or the store's. Either way neither the index nor
    /// the file changed, and the next reconcile makes the same judgements.
    pub fn reconcile<'id, V: ChainView<'id>>(
        &mut self,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Reconciled, PoolFault<V::Fault>> {
        let mut order: Vec<(&TxHash, &Held)> = self.held().iter().collect();
        order.sort_by_key(|(txid, held)| (held.record.received, **txid));

        let mut reconciled = Reconciled::default();
        // Every entry's outcome, for the index; `writes`, the file's changes.
        let mut judged_all: BTreeMap<TxHash, Option<(Standing, Option<VerifiedReference>)>> =
            BTreeMap::new();
        let mut writes: BTreeMap<TxHash, Option<Standing>> = BTreeMap::new();
        let mut key_images = KeyImages::default();
        for (txid, held) in order {
            if chain
                .has_transaction(txid)
                .map_err(|fault| PoolFault::Chain(Fault::View(fault)))?
            {
                judged_all.insert(*txid, None);
                writes.insert(*txid, None);
                reconciled.removed.push((*txid, Removed::Mined));
                continue;
            }
            // CEN-M8: the anchor this node verified the proof against when it
            // last admitted the entry; the door skips the FCMP++ verify when
            // the chain still claims exactly that.
            let cached = match held.record.standing {
                Standing::Admitted => held.proven,
                Standing::Kept { .. } => None,
            };
            let judged = door::judge(&held.tx, chain, &key_images, rule_set, policy, cached)
                .map_err(PoolFault::Chain)?;
            let (standing, proven) = match judged {
                Judged::Admitted { proven, .. } => (Standing::Admitted, proven),
                // A kept entry stays kept on any refusal but its bytes'
                // (module docs); an admitted one is never made kept.
                Judged::Chain { .. } | Judged::Policy(_)
                    if matches!(held.record.standing, Standing::Kept { .. }) =>
                {
                    (held.record.standing, None)
                }
                refused => {
                    judged_all.insert(*txid, None);
                    writes.insert(*txid, None);
                    reconciled.removed.push((*txid, Removed::Refused(refused)));
                    continue;
                }
            };
            judged_all.insert(*txid, Some((standing, proven)));
            if standing != held.record.standing {
                writes.insert(*txid, Some(standing));
            }
            match standing {
                Standing::Admitted => {
                    key_images.insert(*txid, held.key_images());
                    reconciled.admitted.push(*txid);
                }
                Standing::Kept { .. } => reconciled.kept.push(*txid),
            }
        }
        if !writes.is_empty() {
            #[cfg(test)]
            let refuse = core::mem::take(&mut self.refuse_next_write);
            self.store().write(|batch| {
                writes.iter().try_for_each(|(txid, change)| match change {
                    None => batch.remove(txid),
                    Some(standing) => batch.stand(txid, *standing),
                })?;
                // The tests' write fault, after every real change so the
                // abort is seen to take them back: a standing for an entry
                // the file does not hold is the store's refusal.
                #[cfg(test)]
                if refuse {
                    batch.stand(&TxHash::from_bytes([0; 32]), Standing::Admitted)?;
                }
                Ok::<(), shekyl_chain_store::store::StoreError>(())
            })?;
        }
        self.install(&judged_all, key_images);
        Ok(reconciled)
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod reconcile_tests;
