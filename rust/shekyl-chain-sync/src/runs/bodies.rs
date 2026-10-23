// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Body spans. One peer holds at most one. The coordinator decides how
//! many are in flight and which headers on `H*` still need a body.

use std::collections::BTreeSet;
use std::time::Instant;

use shekyl_chain_rules::RuleSet;
use shekyl_levin::{BodiesFormFault, RequestBodies, ResponseBodies, MAX_OBJECT_REQUEST_COUNT};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::{Block, TxBody};

use crate::model::{
    body_deadline, BoundArrival, CloseCause, Command, Sync, BODY_REQUESTS_IN_FLIGHT,
};
use crate::peer::{BodySpan, Dispute};

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
        // A chain with no local observation has nothing to extend. The
        // cursor is the branch base, which is `L + 1` when `H*` extends
        // the local tip and the fork's child when `H*` diverges below it.
        if self.local.is_none() {
            return;
        }
        let Some(star_height) = self.tree.connecting(self.star.hash) else {
            return;
        };
        let Some(mut height) = self.tree.branch_base(self.star.hash) else {
            return;
        };
        let mut hashes = Vec::new();
        let span_cap = usize::try_from(MAX_OBJECT_REQUEST_COUNT).unwrap_or(0);
        let room = usize::try_from(seats).unwrap_or(span_cap);
        while height.to_raw() <= star_height.to_raw() && hashes.len() < span_cap.min(room) {
            if self.past_dispute(height) {
                break;
            }
            let Some(hash) = self.tree.ancestor_at(self.star.hash, height) else {
                break;
            };
            let reserved = self.body_accounted(hash);
            if !reserved {
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
            id,
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
        let Some(star_height) = self.tree.connecting(self.star.hash) else {
            return;
        };
        let Some(mut height) = self.tree.branch_base(self.star.hash) else {
            return;
        };
        let room = usize::try_from(seats).unwrap_or(0);
        let mut wanted = Vec::new();
        while height.to_raw() <= star_height.to_raw() && wanted.len() < room {
            if self.past_dispute(height) {
                break;
            }
            let Some(hash) = self.tree.ancestor_at(self.star.hash, height) else {
                break;
            };
            if self
                .outstanding
                .iter()
                .any(|arrival| arrival.header.hash() == hash)
                || self.accepted.contains(&hash)
            {
                height = height + BlockCount::ONE;
                continue;
            }
            if !self
                .held
                .iter()
                .any(|arrival| arrival.header.hash() == hash)
            {
                break;
            }
            wanted.push(hash);
            height = height + BlockCount::ONE;
        }
        if wanted.is_empty() {
            return;
        }
        let mut arrivals = Vec::with_capacity(wanted.len());
        for hash in wanted {
            let Some(pos) = self
                .held
                .iter()
                .position(|arrival| arrival.header.hash() == hash)
            else {
                break;
            };
            let arrival = self.held.remove(pos);
            self.served.insert(arrival.header.hash(), arrival.session);
            arrivals.push(arrival);
        }
        if arrivals.is_empty() {
            return;
        }
        let spent = u32::try_from(arrivals.len()).unwrap_or(seats);
        self.seats = Some(seats.saturating_sub(spent));
        self.outstanding.extend(arrivals.iter().cloned());
        out.push(Command::Offer { arrivals });
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
            // A frontier on another fork is not a source, however tall it
            // is. A frontier that is not in `T` covers only its own hash.
            let covers = state.frontier.is_some_and(|(_, hash)| {
                hash == end || self.tree.ancestor_at(hash, end_height) == Some(end)
            });
            let blocked = skip_unavailable && state.inventory.unavailable.contains(&end);
            (covers && !blocked).then_some(*key)
        })
    }

    /// Held, in flight, offered, or already accepted by the entry.
    fn body_accounted(&self, hash: BlockHash) -> bool {
        self.accepted.contains(&hash)
            || self.span_has(hash)
            || self
                .held
                .iter()
                .any(|arrival| arrival.header.hash() == hash)
            || self
                .outstanding
                .iter()
                .any(|arrival| arrival.header.hash() == hash)
    }

    fn span_has(&self, hash: BlockHash) -> bool {
        self.peers.values().any(|peer| {
            peer.span
                .as_ref()
                .is_some_and(|span| span.hashes.contains(&hash))
        })
    }

    /// `true` when `height` is past the fork a captured dispute still
    /// covers. The first such height, with no snapshot yet, captures the
    /// sessions whose header runs are still open.
    fn past_dispute(&mut self, height: BlockHeight) -> bool {
        self.retire_dispute();
        if let Some(dispute) = self.dispute.as_ref() {
            return height.to_raw() > dispute.fork.to_raw();
        }
        let Some((fork, sessions)) = self.open_dispute() else {
            return false;
        };
        if height.to_raw() <= fork.to_raw() {
            return false;
        }
        self.dispute = Some(Dispute { fork, sessions });
        true
    }

    /// Drop captured sessions whose header run has finished. An empty set
    /// ends the wait. A missed header deadline leaves through
    /// [`Self::release_dispute`], including when the run object remains.
    fn retire_dispute(&mut self) {
        let Some(dispute) = self.dispute.as_ref() else {
            return;
        };
        let finished: Vec<K> = dispute
            .sessions
            .iter()
            .copied()
            .filter(|session| self.header_run_settled(*session))
            .collect();
        let Some(dispute) = self.dispute.as_mut() else {
            return;
        };
        for session in finished {
            dispute.sessions.remove(&session);
        }
        if dispute.sessions.is_empty() {
            self.dispute = None;
        }
    }

    /// The session left the snapshot. Later sessions are not added.
    pub(super) fn release_dispute(&mut self, session: K) {
        let Some(dispute) = self.dispute.as_mut() else {
            return;
        };
        dispute.sessions.remove(&session);
        if dispute.sessions.is_empty() {
            self.dispute = None;
        }
    }

    /// Sessions whose claim exceeds `work(L)` and whose header run has not
    /// finished, with the shallowest fork those runs have named. A session
    /// that has not answered yet is in the set and does not move the fork.
    fn open_dispute(&self) -> Option<(BlockHeight, BTreeSet<K>)> {
        let local = self.local?.work;
        let mut fork: Option<BlockHeight> = None;
        let mut sessions = BTreeSet::new();
        for (session, peer) in &self.peers {
            if peer.claim.is_none_or(|claim| claim.work <= local) {
                continue;
            }
            if self.header_run_settled(*session) {
                continue;
            }
            if let Some(run) = peer.run.as_ref() {
                let at = run.chain.parent_height;
                fork = Some(match fork {
                    Some(have) if have.to_raw() <= at.to_raw() => have,
                    _ => at,
                });
            }
            sessions.insert(*session);
        }
        let fork = fork?;
        Some((fork, sessions))
    }

    /// Step 3 has finished for this session: nothing is fetching headers,
    /// or the run that remains is only proving. A heavy claim that has
    /// never been answered is still open.
    fn header_run_settled(&self, session: K) -> bool {
        let Some(peer) = self.peers.get(&session) else {
            return true;
        };
        if peer.follow_up.is_some() {
            return false;
        }
        if peer.run.is_some() {
            // This run has its headers. A later frontier request is a new
            // draw, not this run still going.
            return true;
        }
        if self
            .header_request
            .as_ref()
            .is_some_and(|request| request.session == session)
        {
            return false;
        }
        peer.gates.header_quiet
            || peer.gates.past_cap_followed
            || peer.claim.is_none_or(|claim| claim.work <= self.star.work)
    }
}
