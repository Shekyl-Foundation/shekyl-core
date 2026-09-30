// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! Phase 2 of the transition: one block's inputs, in order.
//!
//! A serve credit, a bond post or an emission claim the folds cannot apply
//! refuses the block at that input (CEN-L7). A record the folds cannot read
//! is [`Corrupt`](crate::Corrupt) — bytes no conforming store holds.

use shekyl_archival_retention::{
    claimed_epochs_check_and_set, reinstate_connect, release_connect, BondPostKind as PostKind,
    ReinstateConnectError, ReleaseConnectError,
};
use shekyl_types::archival::{BondRecord, FirstPayingHeight, HeldShard, Holdings};
use shekyl_types::{PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{
    BondPost, BondPostKind as WireKind, Holdings as WireHoldings, Input,
};

use crate::fault::{RecordInvariant, ViewRead};
use crate::rules::body::ArchivalKey;
use crate::rules::Rule;
use crate::verdict::{refused, Locus, Verdict};
use crate::view::ChainView;

use super::{emptied, record_invariant, Post, RecordWriteKind, ServeCreditKey, L7};

impl super::Transition {
    // ---- phase 2: the transactions' arms ---------------------------------

    pub(super) fn apply_input<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        input: &Input,
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        match input {
            Input::Gen(_) | Input::ToKey { .. } => Ok(Ok(())),
            Input::ServeCredit { .. } => {
                // A vin the crate's one parse cannot read writes nothing;
                // the block that carries it does not connect (CEN-J1 will
                // refuse it earlier; this is the backstop).
                let Some(ArchivalKey::ServeCredit { p, shard, epoch }) = ArchivalKey::of(input)
                else {
                    return refused(L7::ROW, locus);
                };
                let persona = PCanonicalId::from_bytes(p);
                // The persona must have a record (CEN-J4's rule; SI-15 is
                // the store's belt beneath it).
                if self.post(view, persona)?.is_none() {
                    return refused(L7::ROW, locus);
                }
                self.serve_credits.push(ServeCreditKey {
                    persona,
                    shard: ShardId::from_raw(shard),
                    epoch: SettlementEpoch::from_raw(epoch),
                });
                Ok(Ok(()))
            }
            Input::BondPost(post) => match &post.kind {
                WireKind::JoinMarket {
                    bond_spend_pk,
                    endpoint,
                } => self.join(view, post, bond_spend_pk, *endpoint, locus),
                WireKind::Other(kind) => match PostKind::from_u8(*kind) {
                    Ok(PostKind::Release) => self.release(view, post, locus),
                    Ok(PostKind::Reinstate) => self.reinstate(view, post, locus),
                    // `Other(0)` cannot come off the wire (the decoder
                    // reads 0 as `JoinMarket`); an unknown kind is a post
                    // no fold applies.
                    Ok(PostKind::JoinMarket) | Err(_) => refused(L7::ROW, locus),
                },
            },
            Input::ArchivalRewardEmission { .. } => {
                let Some(ArchivalKey::Claims { p, epochs }) = ArchivalKey::of(input) else {
                    return refused(L7::ROW, locus);
                };
                self.claim(view, PCanonicalId::from_bytes(p), &epochs, locus)
            }
        }
    }

    /// JoinMarket (`db_lmdb.cpp` `apply_archival_bond_post`, the join arm):
    /// a new record joining at the open epoch, every held shard added at
    /// that epoch, no claims, no first-paying height.
    fn join<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        post: &BondPost,
        bond_spend_pk: &[u8],
        endpoint: [u8; 32],
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let persona = post.p_canonical_id;
        // A persona joins once (SI-19's insert-once, judged here first).
        if self.post(view, persona)?.is_some() {
            return refused(L7::ROW, locus);
        }
        let holdings = match &post.holdings {
            WireHoldings::CompleteTree => Holdings::CompleteTree,
            WireHoldings::ShardSetCompact(ids) => {
                if ids.is_empty() {
                    return refused(L7::ROW, locus);
                }
                let held = ids
                    .iter()
                    .map(|&id| HeldShard {
                        shard: ShardId::from_raw(id),
                        add_epoch: self.epoch,
                    })
                    .collect::<Vec<_>>();
                match Holdings::shard_set(held) {
                    Ok(holdings) => holdings,
                    Err(_) => return refused(L7::ROW, locus),
                }
            }
        };
        let record = BondRecord {
            hybrid_pubkey: post.hybrid_public_key.clone(),
            bond_spend_pk: bond_spend_pk.to_vec(),
            endpoint,
            join_settlement_epoch: self.epoch,
            bonded_total: AtomicUnits::from_raw(post.bonded_total_atomic),
            holdings,
            bad_intervals: Vec::new(),
            claimed_settlement_epochs: Vec::new(),
            first_paying_emission_height: None,
        };
        self.posts.insert(
            persona,
            Post {
                record,
                write: Some(RecordWriteKind::Insert),
            },
        );
        Ok(Ok(()))
    }

    /// Release (`apply_archival_unbond`): the fold decides; the record
    /// becomes bonded-zero with no holdings and a clean interval close.
    fn release<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        post: &BondPost,
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let persona = post.p_canonical_id;
        let epoch = self.epoch.to_raw();
        let Some(current) = self.post(view, persona)? else {
            return refused(L7::ROW, locus);
        };
        let record = &mut current.record;
        let held = match &record.holdings {
            Holdings::CompleteTree => 0,
            Holdings::ShardSet(held) => held.len(),
        };
        let connect = match release_connect(
            record.bonded_total.to_raw(),
            record.holdings.kind(),
            held,
            record.bad_intervals.len(),
            post.bond_debit,
            epoch,
        ) {
            Ok(connect) => connect,
            // The post is wrong for the record: the block is refused.
            Err(ReleaseConnectError::DebitZero | ReleaseConnectError::DebitNotRecordTotal) => {
                return refused(L7::ROW, locus);
            }
            // The record is wrong: no block can be judged against it.
            Err(ReleaseConnectError::RecordFloorInvariantBroken) => {
                return Err(record_invariant(persona, RecordInvariant::FloorBroken));
            }
            Err(ReleaseConnectError::IntervalLogFull) => {
                return Err(record_invariant(persona, RecordInvariant::IntervalLogFull));
            }
        };
        record.bonded_total = AtomicUnits::from_raw(connect.post_bonded_total);
        record.holdings = emptied();
        record.bad_intervals.push(connect.interval_close);
        current.touch();
        Ok(Ok(()))
    }

    /// Reinstate (`apply_archival_reinstate`): the fold names the open
    /// interval to close in place and the epoch that closes it.
    fn reinstate<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        post: &BondPost,
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let persona = post.p_canonical_id;
        let epoch = self.epoch.to_raw();
        let post_ids: &[u64] = match &post.holdings {
            WireHoldings::ShardSetCompact(ids) => ids,
            // A complete-tree post carries no shard list; the fold reads
            // an empty one and refuses it (`EmptyPost`), as the C++ did.
            WireHoldings::CompleteTree => &[],
        };
        let Some(current) = self.post(view, persona)? else {
            return refused(L7::ROW, locus);
        };
        let record = &mut current.record;
        let record_ids = match &record.holdings {
            Holdings::CompleteTree => Vec::new(),
            Holdings::ShardSet(held) => held.iter().map(|h| h.shard.to_raw()).collect::<Vec<_>>(),
        };
        let connect = match reinstate_connect(
            record.bonded_total.to_raw(),
            &record_ids,
            &record.bad_intervals,
            post_ids,
            epoch,
        ) {
            Ok(connect) => connect,
            Err(
                ReinstateConnectError::HoldingsChanged
                | ReinstateConnectError::EmptyPost
                | ReinstateConnectError::PostOversize
                | ReinstateConnectError::NoOpenInterval,
            ) => return refused(L7::ROW, locus),
            Err(ReinstateConnectError::RecordFloorInvariantBroken) => {
                return Err(record_invariant(persona, RecordInvariant::FloorBroken));
            }
            Err(ReinstateConnectError::MultipleOpenIntervals) => {
                return Err(record_invariant(
                    persona,
                    RecordInvariant::MultipleOpenIntervals,
                ));
            }
            Err(ReinstateConnectError::IntervalOrdering) => {
                return Err(record_invariant(persona, RecordInvariant::IntervalOrdering));
            }
            Err(ReinstateConnectError::CounterRange) => {
                return Err(record_invariant(persona, RecordInvariant::CounterRange));
            }
        };
        let Some(interval) = record.bad_intervals.get_mut(connect.closed_interval_index) else {
            return Err(record_invariant(persona, RecordInvariant::CounterRange));
        };
        interval.end_exclusive = connect.interval_end_exclusive;
        current.touch();
        Ok(Ok(()))
    }

    /// An emission claim (`apply_archival_emission_claim`): every named
    /// epoch is checked-and-set against the record's claim window, with
    /// the open epoch as `current_settled`; the first paying height is
    /// set once.
    fn claim<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        persona: PCanonicalId,
        epochs: &[u64],
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        if epochs.is_empty() {
            return refused(L7::ROW, locus);
        }
        let current_settled = self.epoch.to_raw();
        let connecting = self.connecting;
        let Some(current) = self.post(view, persona)? else {
            return refused(L7::ROW, locus);
        };
        let record = &mut current.record;
        let mut set = record
            .claimed_settlement_epochs
            .iter()
            .map(|e| e.to_raw())
            .collect::<Vec<_>>();
        for &epoch in epochs {
            match claimed_epochs_check_and_set(&mut set, epoch, current_settled) {
                Ok(true) => {}
                // Already claimed (a dedup breach past CEN-J25) or not
                // claimable (unsettled or expired): never a soft skip.
                Ok(false) | Err(_) => return refused(L7::ROW, locus),
            }
        }
        record.claimed_settlement_epochs = set.into_iter().map(SettlementEpoch::from_raw).collect();
        // Set-once. `new` is `None` at height 0, where no epoch has closed
        // and no claim can be — the C++'s 0-is-unset sentinel, by type.
        if record.first_paying_emission_height.is_none() {
            record.first_paying_emission_height = FirstPayingHeight::new(connecting);
        }
        current.touch();
        Ok(Ok(()))
    }
}
