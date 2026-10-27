// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transactions a block carried (DRS-E5 PR-b b4): the switch's returns
//! and an alternative block's bodies (CEN-K9), offered to the
//! door for relay and templates. Both run the whole door, policy included
//! (`E5-Q1`): there is no `kept_by_block` skip. A block having carried them
//! makes them public — the one way they differ from a relayed arrival —
//! and the pool holds one only if the door admits it.
//!
//! **There is no reorg retention** (CEN-K10, ruled 2026-10-17). The C++
//! pool kept a returned transaction the chain refused, because the pool
//! was where the chain parked an alternative chain's bodies (CryptoNote,
//! 2014). The store holds those now, so a refused return is dropped like
//! any refused transaction; a switch back connects it from the store.
//!
//! **The pool holds no body a switch needs.** An alternative block's listed
//! bodies are consensus data, and the store holds them beside its row
//! (`alt_block_bodies`, AL1–AL3, AL8); a demoted block's go back into the
//! store with its row. So the door's answer here — a refusal on the floor,
//! an eviction, a discarded pool file — costs a transaction its relay,
//! never the chain its switch (the review of #1102, B1).

use shekyl_chain_rules::{AdmissionPolicy, ChainView, InvalidBlock, RuleSet, StatelessPass};
use shekyl_chain_store::codec::AltBodies;
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use crate::pool::{Admission, Arrival, Pool, PoolFault, Step1};

/// What [`Pool::returned`] and [`Pool::supplement`] did: an answer per
/// transaction offered, in order, and the first fault, if one stopped a
/// judgement. A fault does not stop the offers after it — each is judged
/// on its own, and one the view could not judge is named with the fault.
#[derive(Debug)]
pub struct Offers<F> {
    /// Each transaction the door judged, with its answer.
    pub admissions: Vec<(TxHash, Admission)>,
    /// The transactions not judged, each with the fault that stopped it.
    pub faults: Vec<(TxHash, PoolFault<F>)>,
}

impl Pool {
    /// The transactions a switch's popped blocks listed
    /// (`shekyl_chain_ingest::SwitchDone::returned`), offered to the door
    /// in chain order against the chain the switch left: each is
    /// admitted, refused (whatever step refused it: a returned transaction
    /// below the floor, or whose reference is not on this chain, is refused
    /// as a relayed one is), or already accounted for.
    pub fn returned<'id, V: ChainView<'id>>(
        &mut self,
        returned: Vec<Transaction>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Offers<V::Fault> {
        self.offer(returned, Arrival::Carried, now, chain, rule_set, policy)
    }

    /// An alternative block's listed bodies, as the store holds them
    /// ([`AltBodies`]: only AL1 writes them, from the cheap tier's verdict
    /// over a block whose bodies `form` paired and judged), offered to the
    /// door for relay and templates (CEN-K9). Each is admitted and public,
    /// already accounted for (a held one is made public), or not held. The
    /// block's validity is not this answer: `form` judged its bodies on
    /// their bytes before the tier ran, and promotion judges the rest.
    pub fn supplement<'id, V: ChainView<'id>>(
        &mut self,
        listed: &AltBodies,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Offers<V::Fault> {
        self.offer(
            listed.transactions().to_vec(),
            Arrival::Carried,
            now,
            chain,
            rule_set,
            policy,
        )
    }

    /// Offer each of `transactions` to [`Pool::admit`], every one whatever
    /// the one before it answered.
    fn offer<'id, V: ChainView<'id>>(
        &mut self,
        transactions: Vec<Transaction>,
        arrival: Arrival,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Offers<V::Fault> {
        let mut offered = Offers {
            admissions: Vec::with_capacity(transactions.len()),
            faults: Vec::new(),
        };
        for tx in transactions {
            let txid = tx.txid_parts().hash;
            match self.admit_from(
                tx,
                Step1::Judge(None),
                arrival,
                now,
                chain,
                rule_set,
                policy,
            ) {
                Ok(admission) => offered.admissions.push((txid, admission)),
                Err(fault) => offered.faults.push((txid, fault)),
            }
        }
        offered
    }

    /// [`Self::returned`] with step 1 already judged, outside the pool
    /// lock. The lock then covers the duplicate check, the file, and the
    /// view-bound half of the door — not the signatures and proofs.
    pub fn offer_prepared<'id, V: ChainView<'id>>(
        &mut self,
        offers: Vec<(Transaction, Result<StatelessPass, InvalidBlock>)>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Offers<V::Fault> {
        let mut offered = Offers {
            admissions: Vec::with_capacity(offers.len()),
            faults: Vec::new(),
        };
        for (tx, step1) in offers {
            let txid = tx.txid_parts().hash;
            match self.admit_from(
                tx,
                Step1::Prepared(step1),
                Arrival::Carried,
                now,
                chain,
                rule_set,
                policy,
            ) {
                Ok(admission) => offered.admissions.push((txid, admission)),
                Err(fault) => offered.faults.push((txid, fault)),
            }
        }
        offered
    }
}
