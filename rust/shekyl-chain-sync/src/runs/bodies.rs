// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Body spans. One peer holds at most one. The coordinator decides how
//! many are in flight and which headers on `H*` still need a body.

use std::time::Instant;

use shekyl_chain_rules::RuleSet;
use shekyl_levin::{BodiesFormFault, RequestBodies, ResponseBodies, MAX_OBJECT_REQUEST_COUNT};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::{Block, TxBody};

use crate::model::{
    body_deadline, BoundArrival, CloseCause, Command, Sync, BODY_REQUESTS_IN_FLIGHT,
};
use crate::peer::BodySpan;

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    pub(crate) fn on_bodies(&mut self, session: K, bytes: &[u8], out: &mut Vec<Command<K>>) {
        if !self.peers.contains_key(&session) {
            return;
        }
        let Ok(response) = ResponseBodies::decode(bytes) else {
            self.close(session, CloseCause::BodiesUndecodable, out);
            return;
        };
        let Some(request) = self
            .peers
            .get_mut(&session)
            .and_then(|peer| peer.span.take())
        else {
            return;
        };
        let hashes: Vec<[u8; 32]> = request.hashes.iter().map(|hash| *hash.as_bytes()).collect();
        if let Err(fault) = response.check_form(&hashes) {
            if fault != BodiesFormFault::RequestRepeated {
                self.close(session, CloseCause::BodiesForm(fault), out);
            }
            return;
        }
        if let Some(state) = self.peers.get_mut(&session) {
            for hash in &response.missed_ids {
                state
                    .inventory
                    .unavailable
                    .insert(BlockHash::from_bytes(*hash));
            }
            for hash in &response.deferred {
                state
                    .inventory
                    .deferred
                    .insert(BlockHash::from_bytes(*hash));
            }
        }
        for body in &response.bodies {
            let Ok(block) = Block::from_bytes(&body.block) else {
                self.close(
                    session,
                    CloseCause::BodiesForm(BodiesFormFault::Unreadable),
                    out,
                );
                return;
            };
            let hash = block.hash();
            // A body for a header that is not in `T` — pruned, or never
            // this chain — is not the peer's fault. The span already
            // passed `check_form`. Drop that body and keep the session.
            let Some(judged) = self.judged_in_tree(hash) else {
                continue;
            };
            if let Err(refused) = shekyl_chain_rules::bind_body(&judged, body) {
                self.close(session, CloseCause::Bind(refused.rule), out);
                return;
            }
            // Until the discard rule lands, every byte is kept, so a
            // skeleton is wanted again in full. It is not a fault.
            if body.txs.iter().any(|tx| matches!(tx, TxBody::Skeleton(_))) {
                if let Some(state) = self.peers.get_mut(&session) {
                    state.inventory.skeleton.insert(hash);
                }
                continue;
            }
            let tag = self.next_tag;
            self.next_tag = self.next_tag.saturating_add(1);
            self.held.push(BoundArrival {
                tag,
                session,
                header: judged,
                body: body.clone(),
            });
        }
        self.flush_offers(out);
    }

    pub(crate) fn plan_bodies(&mut self, now: Instant, out: &mut Vec<Command<K>>) {
        let Some(seats) = self.seats else {
            return;
        };
        if seats == 0 || self.spans_in_flight() >= BODY_REQUESTS_IN_FLIGHT {
            return;
        }
        let Some(local) = self.local else {
            return;
        };
        let Some(start) = local.height else {
            return;
        };
        let Some(star_height) = self.tree.connecting(self.star.hash) else {
            return;
        };
        if star_height.to_raw() <= start.to_raw() {
            return;
        }
        let mut hashes = Vec::new();
        let mut height = start + BlockCount::ONE;
        let span_cap = usize::try_from(MAX_OBJECT_REQUEST_COUNT).unwrap_or(0);
        let room = usize::try_from(seats).unwrap_or(span_cap);
        while height.to_raw() <= star_height.to_raw() && hashes.len() < span_cap.min(room) {
            let Some(hash) = self.tree.ancestor_at(self.star.hash, height) else {
                break;
            };
            let offered = self.held.iter().any(|a| a.header.hash() == hash)
                || self.outstanding.iter().any(|a| a.header.hash() == hash);
            if !offered {
                hashes.push(hash);
            }
            height = height + BlockCount::ONE;
        }
        if hashes.is_empty() {
            return;
        }
        let end = *hashes.last().expect("non-empty");
        let Some(session) = self.body_source(end) else {
            return;
        };
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let wire: Vec<[u8; 32]> = hashes.iter().map(|hash| *hash.as_bytes()).collect();
        let transit = self
            .peers
            .get(&session)
            .map(|s| s.transit)
            .unwrap_or_default();
        if let Some(peer) = self.peers.get_mut(&session) {
            peer.span = Some(BodySpan { id, hashes });
        }
        let deadline = body_deadline(now, transit);
        out.push(Command::RequestBodies {
            session,
            deadline,
            request: RequestBodies { hashes: wire },
        });
    }

    pub(in crate::runs) fn flush_offers(&mut self, out: &mut Vec<Command<K>>) {
        let Some(seats) = self.seats else {
            return;
        };
        if seats == 0 || self.held.is_empty() {
            return;
        }
        let n = self
            .held
            .len()
            .min(usize::try_from(seats).unwrap_or(self.held.len()));
        let arrivals: Vec<_> = self.held.drain(..n).collect();
        if !arrivals.is_empty() {
            self.outstanding.extend(arrivals.iter().cloned());
            out.push(Command::Offer { arrivals });
        }
    }

    fn body_source(&self, end: BlockHash) -> Option<K> {
        // Unavailable is asked of another session first. A deferred block
        // is asked of any session that covers it, including the one that
        // deferred it. A skeleton is asked of another session.
        self.find_source(end, true)
            .or_else(|| self.find_source(end, false))
    }

    fn find_source(&self, end: BlockHash, skip_unavailable: bool) -> Option<K> {
        let end_height = self.tree.connecting(end)?;
        self.peers.iter().find_map(|(key, state)| {
            if state.gates.body_excluded || state.inventory.skeleton.contains(&end) {
                return None;
            }
            if state.span.is_some() {
                return None;
            }
            let covers = state.frontier.is_some_and(|(height, hash)| {
                height.to_raw() >= end_height.to_raw() || hash == end
            });
            let blocked = skip_unavailable && state.inventory.unavailable.contains(&end);
            (covers && !blocked).then_some(*key)
        })
    }
}
