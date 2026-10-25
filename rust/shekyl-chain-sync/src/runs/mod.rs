// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A peer's header run (CS-Q2 step 3): cheap checks, the work test, and
//! the proof results. Body spans, the entry's outcomes, and the slot and
//! evidence policy are the modules beside this one.
//!
//! The coordinator draws the peer and the budget. The transitions here
//! change that peer's mode.

use std::time::Instant;

use shekyl_chain_rules::{
    seed_height, target_claim, AtHeight, CenRow, Fault, FormAttempt, FormedHeader, HeaderJudged,
    HeaderView, OpenHeader, Retry, RuleSet, Stale, Substrate,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_levin::ResponseHeaders;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PowHash, Timestamp};
use shekyl_wire::PowBlob;

use crate::branch::{BranchView, Pending};
use crate::model::{header_deadline, CloseCause, Command, HashClass, Job, ProveItem, Proved, Sync};
use crate::peer::{cache_for, Checked, HeaderRequest, Run};

mod bodies;
mod entry;
mod evidence;

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
        }
        if let Some(peer) = self.peers.get_mut(&session) {
            if peer.span.as_ref().is_some_and(|span| span.id == request) {
                peer.span = None;
                peer.gates.body_excluded = true;
            }
        }
    }

    pub(crate) fn on_headers<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        bytes: &[u8],
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if !self.peers.contains_key(&session) {
            return Ok(());
        }
        let Ok(response) = ResponseHeaders::decode(bytes) else {
            self.close(session, CloseCause::HeadersUndecodable, out);
            return Ok(());
        };
        if let Some(state) = self.peers.get_mut(&session) {
            if let Some(claim) = state.claim.as_mut() {
                claim.work = CumulativeDifficulty::from_raw(response.tip_work);
            }
        }
        if response.blobs.is_empty() {
            if response.more {
                self.close(session, CloseCause::HeadersForm, out);
            } else {
                self.finish_run(session, false, now, out);
            }
            return Ok(());
        }
        // Each blob with its identity, hashed once.
        let mut blobs = Vec::new();
        for bytes in &response.blobs {
            let Ok(pow) = PowBlob::read(bytes) else {
                self.close(session, CloseCause::HeadersForm, out);
                return Ok(());
            };
            blobs.push((pow.identity(), pow));
        }
        let parent = blobs[0].1.header.previous;
        let frontier = self
            .header_request
            .as_ref()
            .filter(|req| {
                req.session == session && req.points.iter().any(|(_, hash)| *hash == parent)
            })
            .map(|req| req.points.clone());
        let continuation = self
            .peers
            .get(&session)
            .and_then(|state| state.follow_up.as_ref())
            .filter(|req| req.points.iter().any(|(_, hash)| *hash == parent))
            .map(|req| req.points.clone());
        let from_continuation = continuation.is_some();
        let Some(points) = continuation.or(frontier) else {
            self.close(session, CloseCause::HeadersForm, out);
            return Ok(());
        };
        if from_continuation {
            if let Some(state) = self.peers.get_mut(&session) {
                state.follow_up = None;
            }
        } else if self
            .header_request
            .as_ref()
            .is_some_and(|req| req.session == session)
        {
            self.header_request = None;
        }
        if self.tree.remembers(parent) {
            self.close(session, CloseCause::InvalidAncestor, out);
            return Ok(());
        }
        let mut previous = parent;
        for (index, (hash, pow)) in blobs.iter().enumerate() {
            if index > 0 && pow.header.previous != previous {
                self.close(session, CloseCause::HeadersForm, out);
                return Ok(());
            }
            previous = *hash;
        }
        let parent_height = points
            .iter()
            .find(|(_, hash)| *hash == parent)
            .map(|(height, _)| *height)
            .or_else(|| self.tree.placement(parent).map(|placed| placed.height));
        let Some(parent_height) = parent_height else {
            self.close(session, CloseCause::HeadersForm, out);
            return Ok(());
        };
        if let Some(state) = self.peers.get_mut(&session) {
            let higher = state
                .frontier
                .is_none_or(|(height, _)| parent_height.to_raw() >= height.to_raw());
            if higher {
                state.frontier = Some((parent_height, parent));
            }
        }
        let mut fresh = Vec::new();
        for (hash, pow) in blobs {
            if self.tree.contains(hash) {
                // The session supplied a header already in `T`. Its
                // frontier is that header, which is what it can serve.
                if let Some(height) = self.tree.connecting(hash) {
                    if let Some(state) = self.peers.get_mut(&session) {
                        let higher = state
                            .frontier
                            .is_none_or(|(have, _)| height.to_raw() >= have.to_raw());
                        if higher {
                            state.frontier = Some((height, hash));
                        }
                    }
                }
                continue;
            }
            if points.iter().any(|(_, known)| *known == hash) {
                continue;
            }
            fresh.push((hash, pow));
        }
        if fresh.is_empty() {
            self.finish_run(session, response.more, now, out);
            return Ok(());
        }
        // The first new header hangs off `parent`, or off the last header
        // skipped above, which `T` or the locator places.
        let (base, base_height) = {
            let previous = fresh[0].1.header.previous;
            if previous == parent {
                (parent, parent_height)
            } else {
                let placed = self.tree.connecting(previous).or_else(|| {
                    points
                        .iter()
                        .find(|(_, hash)| *hash == previous)
                        .map(|(height, _)| *height)
                });
                let Some(height) = placed else {
                    self.close(session, CloseCause::HeadersForm, out);
                    return Ok(());
                };
                (previous, height)
            }
        };
        // A run is one chain. A response that does not continue the
        // session's run starts a new run from its own base.
        let continues = self
            .peers
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .map(|run| {
                run.chain
                    .checked
                    .last()
                    .map_or(run.chain.parent, |c| c.hash)
                    == base
            });
        if continues == Some(false) {
            self.drop_run(session);
        }
        // Pending headers are judged above the run's own parent, in `T` or
        // on main, so a height below the run is read where it lives.
        let (anchor, anchor_height) = self
            .peers
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .map_or((base, base_height), |run| {
                (run.chain.parent, run.chain.parent_height)
            });
        let cap = self.cap();
        let local_height = self.local.and_then(|local| local.height);
        let depth = fork_depth(local_height, parent_height);
        let past_cap = depth > cap
            || self
                .peers
                .get(&session)
                .and_then(|state| state.run.as_ref())
                .is_some_and(Run::past_cap);
        // The latch, or a past-cap run that already ended. A run still
        // in progress keeps its headers; "followed once" starts when it ends.
        // The evidence check's refetch from the fork is its run continuing,
        // not a second following of that branch.
        if past_cap && self.alarm {
            return Ok(());
        }
        let evidence_run = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .is_some_and(Run::is_evidence);
        if past_cap
            && !evidence_run
            && self
                .peers
                .get(&session)
                .is_some_and(|peer| peer.gates.past_cap_followed)
        {
            return Ok(());
        }
        let mut accepted: Vec<Checked> = Vec::new();
        for (hash, pow) in fresh {
            let earlier = self
                .peers
                .get(&session)
                .and_then(|s| s.run.as_ref())
                .map_or(&[][..], |run| run.chain.checked.as_slice());
            let view = self.view_for(
                main,
                anchor,
                anchor_height,
                Pending::new(earlier, &accepted),
            );
            let connecting = view
                .tip()?
                .map(|tip| tip.height + BlockCount::ONE)
                .unwrap_or(BlockHeight::ZERO);
            let seed = Self::seed_of(&view, connecting)?;
            let target = match target_claim(&view, connecting, &(self.rules)(connecting)) {
                Ok(Ok(target)) => target,
                Ok(Err(refused)) => {
                    self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                    return Ok(());
                }
                Err(Fault::View(fault)) => return Err(fault),
                Err(Fault::Stale(_) | Fault::Corrupt(_)) => {
                    self.drop_run(session);
                    return Ok(());
                }
            };
            let open = OpenHeader::from_pow(&pow, seed, target, FormAttempt::FIRST);
            let prospect = match shekyl_chain_rules::judge_header_cheap(
                &open,
                &view,
                &(self.rules)(connecting),
                &self.trust,
                &WallClock(self.wall),
            ) {
                Ok(Ok(prospect)) => prospect,
                Ok(Err(refused)) => {
                    self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                    return Ok(());
                }
                Err(fault) => match fault {
                    shekyl_chain_rules::ProspectFault::Chain(Fault::View(fault)) => {
                        return Err(fault);
                    }
                    _ => {
                        self.drop_run(session);
                        return Ok(());
                    }
                },
            };
            let checked = Checked {
                hash,
                height: prospect.connecting,
                work: prospect.cumulative_difficulty,
                seed,
                target,
                rule: (self.rules)(connecting),
                header: pow.header.clone(),
                pow,
            };
            accepted.push(checked);
        }
        let claim = self
            .peers
            .get(&session)
            .and_then(|s| s.claim)
            .map(|c| c.work);
        let run = self.peers.get_mut(&session).and_then(|s| s.run.as_mut());
        let run = if let Some(run) = run {
            run.chain.checked.extend(accepted);
            run.adopt_geometry(past_cap);
            run
        } else if let Some(state) = self.peers.get_mut(&session) {
            state.run = Some(Run::open(base, base_height, accepted, past_cap));
            state.run.as_mut().expect("just inserted")
        } else {
            return Ok(());
        };
        let work = run
            .chain
            .checked
            .last()
            .map(|c| c.work)
            .unwrap_or(CumulativeDifficulty::ZERO);
        let budget_full =
            run.chain.checked.len() >= usize::try_from(cap.to_raw()).unwrap_or(usize::MAX);
        let beats = work > self.star.work;
        let in_slot = run.is_slot();
        if past_cap {
            let evidence = self
                .peers
                .get(&session)
                .and_then(|peer| peer.run.as_ref())
                .is_some_and(Run::is_evidence);
            if evidence {
                // The check pays for every header from the fork, in order.
                // A window that no longer starts there is fetched again.
                if self
                    .peers
                    .get(&session)
                    .and_then(|peer| peer.run.as_ref())
                    .is_some_and(Run::omits_fork)
                {
                    self.refetch_evidence(session, now, out);
                    return Ok(());
                }
                self.plan_proof(session, HashClass::Evidence, out);
                self.finish_run(session, response.more, now, out);
                return Ok(());
            }
            let over = self.past_bound(session, cap);
            self.trim_window(session);
            self.note_evidence(session);
            let candidate = self
                .peers
                .get(&session)
                .and_then(|s| s.run.as_ref())
                .is_some_and(|run| run.is_candidate() || run.is_evidence());
            if over || !response.more {
                if let Some(state) = self.peers.get_mut(&session) {
                    state.gates.past_cap_followed = true;
                }
                if !candidate {
                    self.drop_run(session);
                }
                return Ok(());
            }
            self.finish_run(session, true, now, out);
            return Ok(());
        }
        if !response.more {
            if claim.is_some_and(|claim| work < claim) && !beats {
                self.close(session, CloseCause::ClaimUnmet, out);
                return Ok(());
            }
            if !beats {
                self.drop_run(session);
                return Ok(());
            }
        }
        if budget_full && !beats && !in_slot {
            self.consider_slot(session, out);
            // The peer said the chain continues. The next response is
            // hashed because the run is in the slot or challenging it.
            self.finish_run(session, response.more, now, out);
            return Ok(());
        }
        if beats || in_slot {
            self.plan_proof(session, HashClass::HeaderPow, out);
        }
        self.finish_run(session, response.more, now, out);
        Ok(())
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
        for result in results {
            match result {
                Proved::Refused(refused) => {
                    self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                    return Ok(());
                }
                Proved::NotHeld => {
                    self.drop_run(session);
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
                                self.drop_run(session);
                            }
                            return Ok(());
                        }
                        Judged::Gone => {
                            self.drop_run(session);
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
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        if let Some(state) = self.peers.get_mut(&session) {
            state.follow_up = Some(HeaderRequest {
                session,
                id,
                points: vec![(height, hash)],
            });
        }
        let transit = self
            .peers
            .get(&session)
            .map(|s| s.transit)
            .unwrap_or_default();
        out.push(Command::RequestHeaders {
            session,
            id,
            deadline: header_deadline(now, transit),
            request: shekyl_levin::RequestHeaders {
                block_ids: vec![*hash.as_bytes()],
            },
        });
    }

    pub(crate) fn release_session(&mut self, session: K) {
        self.release_dispute(session);
        self.peers.remove(&session);
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
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        if let Some(state) = self.peers.get_mut(&session) {
            state.follow_up = Some(HeaderRequest {
                session,
                id,
                points: vec![(height, at)],
            });
        }
        let transit = self
            .peers
            .get(&session)
            .map(|s| s.transit)
            .unwrap_or_default();
        out.push(Command::RequestHeaders {
            session,
            id,
            deadline: header_deadline(now, transit),
            request: shekyl_levin::RequestHeaders {
                block_ids: vec![*at.as_bytes()],
            },
        });
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
        | Stale::Target { retry, .. }
        | Stale::Reference { retry, .. } => retry,
    };
    match retry {
        Retry::Again(attempt) => Some(*attempt),
        Retry::Exhausted => None,
    }
}
