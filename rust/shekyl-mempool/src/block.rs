// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transactions a block carried (DRS-E5 PR-b b4): the switch's returns
//! (CEN-K10) and an alternative block's bodies (CEN-K9). Both run the whole
//! door, policy included (`E5-Q1`, reopened in part 2026-10-11): there is no
//! `kept_by_block` skip. What a block having carried them changes is two
//! things only — they are public, and the chain-bound half's refusal keeps
//! them rather than dropping them.

use shekyl_chain_rules::{AdmissionPolicy, ChainView, InvalidBlock, RuleSet};
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use crate::door::Judged;
use crate::pool::{Admission, Arrival, Pool, PoolFault};

impl Pool {
    /// The transactions a switch's popped blocks listed
    /// (`shekyl_chain_ingest::SwitchDone::returned`), offered to the door
    /// in chain order against the chain the switch left (CEN-K10): each is
    /// admitted, kept (refused by the chain-bound half — its reference not
    /// on this chain or aged out of the window, its image spent here),
    /// refused (on its bytes or by policy: a returned transaction below the
    /// floor is refused as a relayed one is), or already accounted for.
    ///
    /// # Errors
    ///
    /// The chain view's or the pool file's; the transactions before the
    /// fault were offered.
    pub fn returned<'id, V: ChainView<'id>>(
        &mut self,
        returned: Vec<Transaction>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Vec<(TxHash, Admission)>, PoolFault<V::Fault>> {
        returned
            .into_iter()
            .map(|tx| {
                let txid = tx.txid_parts().hash;
                self.admit(tx, Arrival::Block, now, chain, rule_set, policy)
                    .map(|admission| (txid, admission))
            })
            .collect()
    }

    /// An alternative block's listed bodies, offered to the door before the
    /// block is held (CEN-K9): the pool holds them for the switch that may
    /// promote the block. A body refused on its bytes refuses the block —
    /// no chain makes it valid, so neither can the block that lists it; that
    /// refusal is the answer, at `Lone`. A policy refusal does not: there is
    /// no consensus fee floor, so a block may carry what the pool will not
    /// relay. The chain-bound half's refusal keeps the body (it may read the
    /// alternative's own blocks).
    ///
    /// # Errors
    ///
    /// The chain view's or the pool file's.
    pub fn supplement<'id, V: ChainView<'id>>(
        &mut self,
        listed: Vec<Transaction>,
        now: UnixSeconds,
        chain: &V,
        rule_set: &RuleSet,
        policy: &AdmissionPolicy,
    ) -> Result<Result<(), InvalidBlock>, PoolFault<V::Fault>> {
        for tx in listed {
            if let Admission::Refused(Judged::Stateless(refused)) =
                self.admit(tx, Arrival::Block, now, chain, rule_set, policy)?
            {
                return Ok(Err(refused));
            }
        }
        Ok(Ok(()))
    }

    /// The bodies of `listed`, in order, when the pool holds every one —
    /// what a switch promoting a block needs (the pool's role for
    /// `Scenario::reorganize`'s `bodies` and the DRS-X router's). `None`
    /// when any is missing: the block cannot be promoted from this pool.
    #[must_use]
    pub fn bodies_for(&self, listed: &[TxHash]) -> Option<Vec<Transaction>> {
        listed
            .iter()
            .map(|txid| self.held().get(txid).map(|held| held.tx.clone()))
            .collect()
    }
}
