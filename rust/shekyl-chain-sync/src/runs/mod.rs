// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A peer's header run (CS-Q2 step 3): cheap checks, the work test, and
//! the proof results. A header page is admitted in [`headers`]. Body spans,
//! the entry's outcomes, and the slot and evidence policy are the modules
//! beside this one.
//!
//! The coordinator draws the peer and the budget. The transitions here
//! change that peer's mode.

use std::time::Instant;

use shekyl_chain_rules::{
    seed_height, AtHeight, CenRow, Fault, FormAttempt, FormedHeader, HeaderJudged, HeaderView,
    Retry, RuleSet, Stale, Substrate,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PowHash, Timestamp};

use crate::branch::{BranchView, Pending};
use crate::model::{CloseCause, Command, HashClass, Job, ProveItem, Proved, Spent, Sync};
use crate::peer::{cache_for, HeaderRequest, Run};

mod bodies;
mod entry;
mod evidence;
mod headers;

struct WallClock(Timestamp);

struct NoHash;

impl Substrate for WallClock {
    type Fault = NoHash;
    type Held = ();

    fn local_clock(&self) -> Result<Timestamp, NoHash> {
        Ok(self.0)
    }

    fn longhash(&self, _pow: &[u8], _seed: &BlockHash) -> Result<PowHash, NoHash> {
        Err(NoHash)
    }
}

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    pub(crate) fn on_deadline(&mut self, session: K, request: u64) {
        // The opening's bound: fixed from its first session, so it fires
        // whether or not that session is still open.
        if self.opening == (crate::model::Opening::Open { id: request }) {
            self.opening = crate::model::Opening::Resolved;
            return;
        }
        // The evidence draw's wake: the step's draw follows this event.
        if self.draw_wake == Some(request) {
            self.draw_wake = None;
            return;
        }
        // A withdrawn request's deadline: its answer is no longer owed.
        if let Some(peer) = self.peers.get_mut(&session) {
            if let Some(at) = peer.withdrawn.iter().position(|id| *id == request) {
                peer.withdrawn.remove(at);
                return;
            }
        }
        let header = self
            .header_request
            .as_ref()
            .is_some_and(|req| req.session == session && req.id == request);
        let follow = self.peers.get(&session).is_some_and(|state| {
            state
                .follow_up
                .as_ref()
                .is_some_and(|req| req.id == request)
        });
        if header {
            self.header_request = None;
        }
        if follow {
            if let Some(state) = self.peers.get_mut(&session) {
                state.follow_up = None;
                // A run kept only for its continuation ends with it, as one
                // whose response says nothing follows does.
                if state.run.as_ref().is_some_and(Run::unhashed) {
                    state.run = None;
                }
            }
        }
        // A header-request deadline ends this session's part of a CS-Q4(c)
        // wait even when the run remains. A body span does not.
        if header || follow {
            self.release_dispute(session);
            // A header request past its deadline has resolved, for the
            // opening as an answer does.
            if let Some(peer) = self.peers.get_mut(&session) {
                peer.reply = crate::peer::HeaderReply::Resolved;
            }
        }
        if let Some(peer) = self.peers.get_mut(&session) {
            if peer.span.as_ref().is_some_and(|span| span.id == request) {
                peer.span = None;
                peer.bodies = crate::peer::BodySource::Excluded;
            }
        }
    }

    pub(crate) fn on_proven<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        job: Job,
        results: &[Proved],
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if self.announce_for(job.raw()).is_some() {
            return self.on_announced_proved(main, job, results, out);
        }
        let Some(session) = self.session_for_job(job.raw()) else {
            return Ok(());
        };
        // A proof answered for this session's headers: its request has
        // resolved for the opening (CS-Q2 step 8), whatever the results.
        if let Some(peer) = self.peers.get_mut(&session) {
            peer.reply = crate::peer::HeaderReply::Resolved;
        }
        for result in results {
            match result {
                Proved::Refused(refused) => {
                    self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                    return Ok(());
                }
                Proved::NotHeld => {
                    self.seed_not_held(session, out);
                    return Ok(());
                }
                Proved::Formed(formed) => {
                    // A job proves the run's headers in order from its first
                    // unproven one. A run cut back while the job ran no
                    // longer holds this header there: the rest of the job is
                    // not the run's, and the run is planned again.
                    let in_place = self
                        .peers
                        .get(&session)
                        .and_then(|s| s.run.as_ref())
                        .and_then(|run| run.chain.checked.get(run.chain.proven))
                        .is_some_and(|next| next.hash == formed.hash());
                    if !in_place {
                        break;
                    }
                    let judged = self.judge_formed(main, session, formed);
                    match judged {
                        Judged::View(fault) => return Err(fault),
                        Judged::Refused(row) => {
                            self.close(session, CloseCause::HeaderRefused(row), out);
                            return Ok(());
                        }
                        Judged::Stale(stale) => {
                            if let Some(next) = retry_of(&stale) {
                                if let Some(run) =
                                    self.peers.get_mut(&session).and_then(|s| s.run.as_mut())
                                {
                                    run.chain.attempt = next;
                                    run.clear_proof();
                                }
                                self.plan_proof(session, HashClass::HeaderPow, out);
                            } else {
                                self.spend(session, Spent::Stale, out);
                            }
                            return Ok(());
                        }
                        Judged::Gone => {
                            self.spend(session, Spent::Gone, out);
                            return Ok(());
                        }
                        Judged::Ok(header) => {
                            let header = *header;
                            let beats = header.cumulative_difficulty() > self.star.work;
                            let joins = self
                                .peers
                                .get(&session)
                                .and_then(|s| s.run.as_ref())
                                .is_some_and(|run| run.joins_tree(beats));
                            if !joins {
                                if let Some(run) =
                                    self.peers.get_mut(&session).and_then(|s| s.run.as_mut())
                                {
                                    run.chain.proven = run.chain.proven.saturating_add(1);
                                    run.push_held(header);
                                    run.clear_proof();
                                }
                            } else {
                                // Withheld ancestors join before the header
                                // that beat `H*`. The winner's parent is
                                // then in `T`, so its branch base is the
                                // fork and not the winner itself.
                                let (held, frontier) = if let Some(run) =
                                    self.peers.get_mut(&session).and_then(|s| s.run.as_mut())
                                {
                                    run.chain.proven = run.chain.proven.saturating_add(1);
                                    let held = run.take_held();
                                    run.clear_proof();
                                    let frontier = run
                                        .chain
                                        .checked
                                        .get(run.chain.proven.saturating_sub(1))
                                        .map(|c| (c.height, c.hash));
                                    (held, frontier)
                                } else {
                                    (Vec::new(), None)
                                };
                                for header in held {
                                    self.tree.insert(header);
                                }
                                self.tree.insert(header);
                                if let Some((height, hash)) = frontier {
                                    if let Some(state) = self.peers.get_mut(&session) {
                                        state.frontier = Some((height, hash));
                                    }
                                }
                                self.reselect(main)?;
                            }
                        }
                    }
                }
            }
        }
        if let Some(run) = self.peers.get_mut(&session).and_then(|s| s.run.as_mut()) {
            run.clear_proof();
        }
        self.evidence_alarm(session, out);
        self.settle_challenge(session);
        let class = if self
            .peers
            .get(&session)
            .and_then(|peer| peer.run.as_ref())
            .is_some_and(Run::is_evidence)
        {
            HashClass::Evidence
        } else {
            HashClass::HeaderPow
        };
        if self
            .peers
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .is_some_and(|run| run.proof().is_none() && run.chain.proven < run.chain.checked.len())
        {
            self.plan_proof(session, class, out);
        }
        Ok(())
    }

    fn plan_proof(&mut self, session: K, class: HashClass, out: &mut Vec<Command<K>>) {
        let Some(run) = self.peers.get(&session).and_then(|s| s.run.as_ref()) else {
            return;
        };
        if run.proof().is_some() || run.chain.proven >= run.chain.checked.len() {
            return;
        }
        let class = if run.is_evidence() {
            HashClass::Evidence
        } else {
            class
        };
        let Some(cache) = cache_for(run, run.chain.proven) else {
            return;
        };
        let attempt = run.chain.attempt;
        let mut items = Vec::new();
        for (offset, checked) in run.chain.checked[run.chain.proven..].iter().enumerate() {
            if cache_for(run, run.chain.proven + offset) != Some(cache) {
                break;
            }
            items.push(ProveItem {
                pow: checked.pow.write(),
                seed: checked.seed,
                target: checked.target,
                attempt,
                rule_set: checked.rule,
            });
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let armed = self
            .peers
            .get_mut(&session)
            .and_then(|peer| peer.run.as_mut())
            .is_some_and(|run| run.arm_proof(id));
        if !armed {
            return;
        }
        out.push(Command::Prove {
            job: Job::from_raw(id),
            class,
            cache,
            items,
        });
    }

    fn finish_run(&mut self, session: K, more: bool, now: Instant, out: &mut Vec<Command<K>>) {
        if !more {
            return;
        }
        let Some(run) = self.peers.get(&session).and_then(|s| s.run.as_ref()) else {
            return;
        };
        let tip = run.chain.checked.last().map(|c| (c.height, c.hash));
        let Some((height, hash)) = tip else {
            return;
        };
        self.follow_up(session, (height, hash), now, out);
    }

    /// This session's own header follow-up from one point: the run's next
    /// locator, a relocate, or the ancestors of an announcement. It does
    /// not take the extending slot.
    pub(crate) fn follow_up(
        &mut self,
        session: K,
        point: (BlockHeight, BlockHash),
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) {
        if !self.requests() {
            return;
        }
        let Some(state) = self.peers.get_mut(&session) else {
            return;
        };
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let request = HeaderRequest::new(session, id, vec![point], now, state.transit);
        let deadline = request.deadline;
        state.follow_up = Some(request);
        out.push(Command::RequestHeaders {
            session,
            id,
            deadline,
            request: shekyl_levin::RequestHeaders {
                block_ids: vec![*point.1.as_bytes()],
            },
        });
    }

    pub(crate) fn release_session(&mut self, session: K) {
        self.release_dispute(session);
        self.peers.remove(&session);
        if self.peers.is_empty() {
            self.opening = crate::model::Opening::Idle;
        }
        self.pending.remove(&session);
        if self
            .header_request
            .as_ref()
            .is_some_and(|req| req.session == session)
        {
            self.header_request = None;
        }
        self.outstanding.drop_session(session);
        self.held.drop_session(session);
        self.served.retain(|_, who| *who != session);
    }

    fn close(&mut self, session: K, cause: CloseCause, out: &mut Vec<Command<K>>) {
        self.release_session(session);
        out.push(Command::Close { session, cause });
    }

    fn drop_run(&mut self, session: K) {
        if let Some(state) = self.peers.get_mut(&session) {
            state.run = None;
        }
    }

    /// Whether the session's claim states more work than `work`.
    fn claim_exceeds(&self, session: K, work: CumulativeDifficulty) -> bool {
        self.peers
            .get(&session)
            .and_then(|state| state.claim)
            .is_some_and(|claim| claim.work > work)
    }

    /// The work through a header this node holds, in `T` or on `main` at
    /// `height`. `H*`'s work when neither answers: a held header that
    /// outweighs `H*` is in `T`, so nothing outside it does.
    fn end_work<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        hash: BlockHash,
        height: BlockHeight,
    ) -> Result<CumulativeDifficulty, H::Fault> {
        if let Some(record) = self.tree.record(hash) {
            return Ok(record.cumulative_difficulty);
        }
        Ok(match main.header_at(height)? {
            AtHeight::Recorded(record) if record.hash == hash => record.cumulative_difficulty,
            AtHeight::Recorded(_) | AtHeight::AboveTip => self.star.work,
        })
    }

    /// The session's headers from `H*` yielded nothing: its run, if any,
    /// is dropped, and it is not drawn to extend `H*` again until its
    /// claim or `H*` changes ([`crate::peer::HeaderDraw::spend`]).
    /// Without that hold, `plan` runs after every event and the extending
    /// slot is free once a response arrives, so the same request would go
    /// out again as soon as this one was answered.
    fn spend(&mut self, session: K, cause: Spent, out: &mut Vec<Command<K>>) {
        if let Some(state) = self.peers.get_mut(&session) {
            state.run = None;
            state.draw.spend();
        }
        out.push(Command::HeadersSpent { session, cause });
    }

    /// The run's next header could not be proven because the slots did
    /// not hold its seed: the run is dropped and the session is closed to
    /// header draws until the slots change (`Event::Seeds`). Not a spend:
    /// the same request would be answered once the window holds the seed,
    /// with the claim and `H*` unchanged.
    fn seed_not_held(&mut self, session: K, out: &mut Vec<Command<K>>) {
        let Some(state) = self.peers.get_mut(&session) else {
            return;
        };
        let Some(run) = state.run.take() else {
            return;
        };
        state.draw.miss_seed();
        let seed = run
            .chain
            .checked
            .get(run.chain.proven)
            .map_or(BlockHash::NULL, |checked| checked.seed);
        out.push(Command::SeedNotHeld { session, seed });
    }

    /// The ingest window's slots changed: every session closed for a seed
    /// they did not hold is open to header draws again.
    pub(crate) fn seeds_changed(&mut self) {
        for peer in self.peers.values_mut() {
            peer.draw.on_seeds();
        }
    }

    fn session_for_job(&self, job: u64) -> Option<K> {
        self.peers.iter().find_map(|(key, state)| {
            state
                .run
                .as_ref()
                .is_some_and(|run| run.proof() == Some(job))
                .then_some(*key)
        })
    }

    fn cap(&self) -> BlockCount {
        let at = self
            .local
            .and_then(|local| local.height)
            .map_or(BlockHeight::ZERO, |height| height + BlockCount::ONE);
        (self.rules)(at).reorg_cap()
    }

    fn view_for<'a, 'id, H: HeaderView<'id>>(
        &'a self,
        main: &'a H,
        parent: BlockHash,
        parent_height: BlockHeight,
        pending: Pending<'a>,
    ) -> BranchView<'a, H> {
        let base = if let Some(placed) = self.tree.placement(parent) {
            BranchView::above(main, &self.tree, parent, placed.height, placed.fork)
        } else if parent == BlockHash::NULL {
            BranchView::empty_main(main)
        } else {
            BranchView::on_main(main, parent, parent_height)
        };
        base.with_run(pending)
    }

    fn seed_of<'id, H: HeaderView<'id>>(
        view: &H,
        connecting: BlockHeight,
    ) -> Result<BlockHash, H::Fault> {
        let Some(height) = seed_height(connecting) else {
            return Ok(BlockHash::NULL);
        };
        match view.header_at(height)? {
            AtHeight::Recorded(record) => Ok(record.hash),
            AtHeight::AboveTip => Ok(BlockHash::NULL),
        }
    }

    fn judge_formed<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        session: K,
        formed: &FormedHeader,
    ) -> Judged<H::Fault> {
        let Some(run) = self.peers.get(&session).and_then(|s| s.run.as_ref()) else {
            return Judged::Gone;
        };
        // `formed` is `checked[proven]` (`on_proven`), so the headers
        // before it are this slice.
        let before = &run.chain.checked[..run.chain.proven.min(run.chain.checked.len())];
        let parent = formed.previous();
        let parent_height = before.last().map_or(run.chain.parent_height, |c| c.height);
        let view = self.view_for(main, parent, parent_height, Pending::new(before, &[]));
        match shekyl_chain_rules::judge_header(formed, &view, &formed.rule_set(), &self.trust) {
            Ok(Ok(judged)) => Judged::Ok(Box::new(judged)),
            Ok(Err(refused)) => Judged::Refused(refused.rule),
            Err(Fault::View(fault)) => Judged::View(fault),
            Err(Fault::Stale(stale)) => Judged::Stale(Box::new(stale)),
            Err(Fault::Corrupt(_)) => Judged::Gone,
        }
    }

    fn judged_in_tree(&self, hash: BlockHash) -> Option<HeaderJudged> {
        self.tree.judged(hash)
    }

    fn locate(&mut self, session: K, at: BlockHash, now: Instant, out: &mut Vec<Command<K>>) {
        if at == BlockHash::NULL {
            return;
        }
        if self
            .peers
            .get(&session)
            .is_some_and(|s| s.follow_up.is_some())
        {
            return;
        }
        let height = self
            .tree
            .connecting(at)
            .or_else(|| {
                self.local
                    .filter(|local| local.hash == at)
                    .and_then(|local| local.height)
            })
            .unwrap_or(BlockHeight::ZERO);
        self.follow_up(session, (height, at), now, out);
    }
}

enum Judged<E> {
    Ok(Box<HeaderJudged>),
    Refused(CenRow),
    Stale(Box<Stale>),
    View(E),
    Gone,
}

fn fork_depth(local: Option<BlockHeight>, fork: BlockHeight) -> BlockCount {
    match local {
        Some(local) if local.to_raw() >= fork.to_raw() => local - fork,
        _ => BlockCount::ZERO,
    }
}

fn retry_of(stale: &Stale) -> Option<FormAttempt> {
    let retry = match stale {
        Stale::Seed { retry, .. }
        | Stale::RuleSet { retry, .. }
        | Stale::Network { retry, .. }
        | Stale::Target { retry, .. }
        | Stale::Reference { retry, .. }
        | Stale::BundleBody { retry, .. } => retry,
    };
    match retry {
        Retry::Again(attempt) => Some(*attempt),
        Retry::Exhausted => None,
    }
}
