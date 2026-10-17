// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transactions a block carried (DRS-E5 PR-b b4): the switch's returns
//! (CEN-K10) and an alternative block's bodies (CEN-K9), offered to the
//! door for relay and templates. Both run the whole door, policy included
//! (`E5-Q1`, reopened in part 2026-10-11): there is no `kept_by_block` skip.
//! A block having carried them makes them public, and a returned one the
//! chain-bound half alone refuses is kept.
//!
//! **The pool holds no body a switch needs.** An alternative block's listed
//! bodies are consensus data, and the store holds them beside its row
//! (`alt_block_bodies`, AL1–AL3, AL8); a demoted block's go back into the
//! store with its row. So the door's answer here — a refusal on the floor,
//! an eviction, a discarded pool file — costs a transaction its relay,
//! never the chain its switch (the review of #1102, B1).

use shekyl_chain_rules::{AdmissionPolicy, ChainView, RuleSet};
use shekyl_chain_store::codec::AltBodies;
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use crate::pool::{Admission, Arrival, Pool, PoolFault};

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
    /// in chain order against the chain the switch left (CEN-K10): each is
    /// admitted, kept (refused by the chain-bound half alone — its reference
    /// not on this chain or aged out of the window, its image spent here),
    /// refused (on its bytes or by policy: a returned transaction below the
    /// floor is refused as a relayed one is), or already accounted for.
    pub fn returned<'id, V: ChainView<'id>>(
        &mut self,
        returned: Vec<Transaction>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Offers<V::Fault> {
        self.offer(returned, Arrival::Returned, now, chain, rule_set, policy)
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
            Arrival::Listed,
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
            match self.admit(tx, arrival, now, chain, rule_set, policy) {
                Ok(admission) => offered.admissions.push((txid, admission)),
                Err(fault) => offered.faults.push((txid, fault)),
            }
        }
        offered
    }
}
