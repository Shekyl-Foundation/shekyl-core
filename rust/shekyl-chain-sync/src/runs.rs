// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A session's run (CS-Q2 step 3): cheap checks, the work test, the
//! long-run slot, PoW results, bodies, and the entry's outcomes.

use std::time::Instant;

use shekyl_chain_rules::{
    seed_height, target_claim, AtHeight, CenRow, Fault, FormAttempt, FormedHeader, HeaderJudged,
    HeaderView, InvalidBlock, OpenHeader, Retry, RuleSet, Stale, Substrate, Target,
};
use shekyl_difficulty::{CumulativeDifficulty, SEEDHASH_EPOCH_LAG};
use shekyl_levin::{BodiesFormFault, RequestBodies, ResponseBodies, ResponseHeaders};
use shekyl_peer_policy::{SyncReply, SyncReplyAction};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PowHash, Timestamp};
use shekyl_wire::{Block, PowBlob};

use crate::branch::{BranchView, Overlay};
use crate::model::{
    header_deadline, BoundArrival, CachePlan, CloseCause, Command, HashClass, Job, ProveItem,
    Proved, Sync, BODY_RATE_FLOOR, BODY_REQUESTS_IN_FLIGHT,
};
/// A header request, and the heights it named.
pub(crate) struct HeaderRequest<K> {
    pub session: K,
    pub id: u64,
    pub points: Vec<(BlockHeight, BlockHash)>,
}

/// A body span in flight.
pub(crate) struct BodyRequest<K> {
    pub session: K,
    pub id: u64,
    pub hashes: Vec<BlockHash>,
}

struct Checked {
    pow: PowBlob,
    hash: BlockHash,
    height: BlockHeight,
    previous: BlockHash,
    work: CumulativeDifficulty,
    seed: BlockHash,
    target: Target,
    rule: RuleSet,
    header: shekyl_wire::BlockHeader,
}

/// Headers received and not yet part of `T`.
pub(crate) struct Run {
    #[allow(dead_code)]
    parent: BlockHash,
    parent_height: BlockHeight,
    checked: Vec<Checked>,
    proven: usize,
    held: Vec<HeaderJudged>,
    in_slot: bool,
    job: Option<u64>,
    attempt: FormAttempt,
    past_cap: bool,
    evidence: bool,
}

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
        if header {
            self.header_request = None;
        }
        if let Some(session_state) = self.sessions.get_mut(&session) {
            if session_state
                .continuation
                .as_ref()
                .is_some_and(|req| req.id == request)
            {
                session_state.continuation = None;
            }
        }
        let body = self
            .body_requests
            .iter()
            .any(|req| req.session == session && req.id == request);
        if body {
            self.body_requests.retain(|req| req.id != request);
            if let Some(session_state) = self.sessions.get_mut(&session) {
                session_state.body_excluded = true;
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
        if !self.sessions.contains_key(&session) {
            return Ok(());
        }
        let Ok(response) = ResponseHeaders::decode(bytes) else {
            self.close(session, CloseCause::HeadersUndecodable, out);
            return Ok(());
        };
        if let Some(state) = self.sessions.get_mut(&session) {
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
        let mut blobs = Vec::new();
        for bytes in &response.blobs {
            let Ok(pow) = PowBlob::read(bytes) else {
                self.close(session, CloseCause::HeadersForm, out);
                return Ok(());
            };
            blobs.push(pow);
        }
        let parent = blobs[0].header.previous;
        let frontier = self
            .header_request
            .as_ref()
            .filter(|req| {
                req.session == session && req.points.iter().any(|(_, hash)| *hash == parent)
            })
            .map(|req| req.points.clone());
        let continuation = self
            .sessions
            .get(&session)
            .and_then(|state| state.continuation.as_ref())
            .filter(|req| req.points.iter().any(|(_, hash)| *hash == parent))
            .map(|req| req.points.clone());
        let from_continuation = continuation.is_some();
        let Some(points) = continuation.or(frontier) else {
            self.close(session, CloseCause::HeadersForm, out);
            return Ok(());
        };
        if from_continuation {
            if let Some(state) = self.sessions.get_mut(&session) {
                state.continuation = None;
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
        for (index, pow) in blobs.iter().enumerate() {
            if index > 0 && pow.header.previous != previous {
                self.close(session, CloseCause::HeadersForm, out);
                return Ok(());
            }
            previous = pow.identity();
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
        if let Some(state) = self.sessions.get_mut(&session) {
            let higher = state
                .frontier
                .is_none_or(|(height, _)| parent_height.to_raw() >= height.to_raw());
            if higher {
                state.frontier = Some((parent_height, parent));
            }
        }
        let mut fresh = Vec::new();
        for pow in blobs {
            let hash = pow.identity();
            if self.tree.contains(hash) || points.iter().any(|(_, known)| *known == hash) {
                continue;
            }
            fresh.push(pow);
        }
        if fresh.is_empty() {
            self.finish_run(session, response.more, now, out);
            return Ok(());
        }
        let cap = self.cap();
        let local_height = self.local.and_then(|local| local.height);
        let depth = fork_depth(local_height, parent_height);
        let past_cap = depth > cap;
        if past_cap
            && (self.alarm
                || self
                    .sessions
                    .get(&session)
                    .is_some_and(|s| s.past_cap_followed))
        {
            return Ok(());
        }
        let mut overlay = self.overlay_of(session);
        let mut accepted = Vec::new();
        for pow in fresh {
            let view = self.view_for(main, parent, parent_height, &overlay);
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
            let hash = pow.identity();
            let checked = Checked {
                hash,
                height: prospect.connecting,
                previous: pow.header.previous,
                work: prospect.cumulative_difficulty,
                seed,
                target,
                rule: (self.rules)(connecting),
                header: pow.header.clone(),
                pow,
            };
            overlay.push(Overlay {
                height: checked.height,
                hash: checked.hash,
                header: checked.header.clone(),
                work: checked.work,
            });
            accepted.push(checked);
        }
        let claim = self
            .sessions
            .get(&session)
            .and_then(|s| s.claim)
            .map(|c| c.work);
        let run = self.sessions.get_mut(&session).and_then(|s| s.run.as_mut());
        let run = if let Some(run) = run {
            run.checked.extend(accepted);
            run.past_cap = past_cap;
            run
        } else if let Some(state) = self.sessions.get_mut(&session) {
            state.run = Some(Run {
                parent,
                parent_height,
                checked: accepted,
                proven: 0,
                held: Vec::new(),
                in_slot: false,
                job: None,
                attempt: FormAttempt::FIRST,
                past_cap,
                evidence: false,
            });
            state.run.as_mut().expect("just inserted")
        } else {
            return Ok(());
        };
        let work = run
            .checked
            .last()
            .map(|c| c.work)
            .unwrap_or(CumulativeDifficulty::ZERO);
        let budget_full = run.checked.len() >= usize::try_from(cap.to_raw()).unwrap_or(usize::MAX);
        let beats = work > self.star.work;
        let in_slot = run.in_slot;
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
            return Ok(());
        }
        if past_cap {
            self.note_evidence(session);
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
        let Some(session) = self.session_for_job(job.raw()) else {
            return Ok(());
        };
        for result in results {
            match result {
                Proved::Refused(refused) => {
                    self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                    return Ok(());
                }
                Proved::Formed(formed) => {
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
                                    self.sessions.get_mut(&session).and_then(|s| s.run.as_mut())
                                {
                                    run.attempt = next;
                                    run.job = None;
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
                            let in_slot = self
                                .sessions
                                .get(&session)
                                .and_then(|s| s.run.as_ref())
                                .is_some_and(|run| run.in_slot);
                            let beats = header.cumulative_difficulty() > self.star.work;
                            if in_slot && !beats {
                                if let Some(run) =
                                    self.sessions.get_mut(&session).and_then(|s| s.run.as_mut())
                                {
                                    run.proven = run.proven.saturating_add(1);
                                    run.held.push(header);
                                    run.job = None;
                                }
                            } else {
                                self.tree.insert(header);
                                let (held, frontier) = if let Some(run) =
                                    self.sessions.get_mut(&session).and_then(|s| s.run.as_mut())
                                {
                                    run.proven = run.proven.saturating_add(1);
                                    let held = std::mem::take(&mut run.held);
                                    run.job = None;
                                    let frontier = run
                                        .checked
                                        .get(run.proven.saturating_sub(1))
                                        .map(|c| (c.height, c.hash));
                                    (held, frontier)
                                } else {
                                    (Vec::new(), None)
                                };
                                for header in held {
                                    self.tree.insert(header);
                                }
                                if let Some((height, hash)) = frontier {
                                    if let Some(state) = self.sessions.get_mut(&session) {
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
        if let Some(run) = self.sessions.get_mut(&session).and_then(|s| s.run.as_mut()) {
            run.job = None;
            if run.evidence && run.proven > 0 {
                let verified = run
                    .checked
                    .get(run.proven - 1)
                    .map(|c| c.work)
                    .unwrap_or(CumulativeDifficulty::ZERO);
                let parent_work = run.checked.first().map(|c| c.work).unwrap_or(verified);
                let local = self
                    .local
                    .map(|l| l.work)
                    .unwrap_or(CumulativeDifficulty::ZERO);
                if parent_work > local || verified > local {
                    // The alarm is fork-point work plus verified work. The
                    // first checked header's work is the work through it,
                    // which includes the fork. Comparing that with `L` is
                    // the check the ruling names.
                }
            }
        }
        self.evidence_alarm(session, out);
        if self
            .sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .is_some_and(|run| run.job.is_none() && run.proven < run.checked.len())
        {
            let class = if self.evidence == Some(session) {
                HashClass::Evidence
            } else {
                HashClass::HeaderPow
            };
            self.plan_proof(session, class, out);
        }
        Ok(())
    }

    pub(crate) fn on_bodies(&mut self, session: K, bytes: &[u8], out: &mut Vec<Command<K>>) {
        if !self.sessions.contains_key(&session) {
            return;
        }
        let Ok(response) = ResponseBodies::decode(bytes) else {
            self.close(session, CloseCause::BodiesUndecodable, out);
            return;
        };
        let Some(index) = self
            .body_requests
            .iter()
            .position(|req| req.session == session)
        else {
            return;
        };
        let request = self.body_requests.remove(index);
        let hashes: Vec<[u8; 32]> = request.hashes.iter().map(|hash| *hash.as_bytes()).collect();
        if let Err(fault) = response.check_form(&hashes) {
            if fault != BodiesFormFault::RequestRepeated {
                self.close(session, CloseCause::BodiesForm(fault), out);
            }
            return;
        }
        for hash in &response.missed_ids {
            if let Some(state) = self.sessions.get_mut(&session) {
                state.unavailable.insert(BlockHash::from_bytes(*hash));
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
            let Some(record) = self.tree.record(hash) else {
                continue;
            };
            let _ = record;
            let Some(judged) = self.judged_in_tree(hash) else {
                continue;
            };
            if let Err(refused) = shekyl_chain_rules::bind_body(&judged, body) {
                self.close(session, CloseCause::Bind(refused.rule), out);
                return;
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_entry<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        _tag: u64,
        reply: SyncReply,
        hash: BlockHash,
        solicited: bool,
        at: BlockHash,
        indices: &[u64],
        verdict: Option<InvalidBlock>,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        let action = reply.action(solicited);
        let session = self
            .held
            .iter()
            .find(|a| a.header.hash() == hash)
            .map(|a| a.session);
        match action {
            SyncReplyAction::Advance { relay } => {
                if relay {
                    out.push(Command::Relay { hash });
                }
            }
            SyncReplyAction::Invalidate => {
                self.tree.mark_invalid(hash);
                self.reselect(main)?;
                if let Some(session) = session {
                    let cause = if reply == SyncReply::Oversize {
                        CloseCause::Oversize
                    } else {
                        CloseCause::BlockRefused(verdict.unwrap_or(InvalidBlock::new(
                            CenRow::B6,
                            shekyl_chain_rules::Locus::Block,
                        )))
                    };
                    self.close(session, cause, out);
                }
            }
            SyncReplyAction::Relocate => {
                if let Some(session) = session {
                    if let Some(state) = self.sessions.get_mut(&session) {
                        state.header_quiet = false;
                    }
                    let _ = at;
                }
            }
            SyncReplyAction::RequestHeaders => {
                if let Some(session) = session {
                    if let Some(state) = self.sessions.get_mut(&session) {
                        state.header_quiet = false;
                    }
                }
            }
            SyncReplyAction::RequestMissing => {
                if let Some(session) = session {
                    out.push(Command::RequestMissingTxs {
                        session,
                        block: hash,
                        indices: indices.to_vec(),
                    });
                }
            }
            SyncReplyAction::Again
            | SyncReplyAction::Hold
            | SyncReplyAction::DropUnverified
            | SyncReplyAction::None => {}
        }
        let _ = solicited;
        Ok(())
    }

    pub(crate) fn on_room(&mut self, seats: u32, out: &mut Vec<Command<K>>) {
        self.seats = Some(seats);
        self.flush_offers(out);
    }

    pub(crate) fn on_announce<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        block: &[u8],
        bodies: &[Vec<u8>],
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if !self.sessions.contains_key(&session) {
            return Ok(());
        }
        let Ok(parsed) = Block::from_bytes(block) else {
            return Ok(());
        };
        let Ok(pow) = PowBlob::read(&parsed.pow_blob()) else {
            return Ok(());
        };
        let parent = pow.header.previous;
        if !self.tree.contains(parent) && self.local.is_none_or(|local| local.hash != parent) {
            return Ok(());
        }
        let height = self
            .tree
            .placement(parent)
            .map(|p| p.height)
            .or_else(|| self.local.and_then(|l| l.height))
            .unwrap_or(BlockHeight::ZERO);
        let view = self.view_for(main, parent, height, &[]);
        let connecting = view
            .tip()?
            .map(|tip| tip.height + BlockCount::ONE)
            .unwrap_or(BlockHeight::ZERO);
        let seed = Self::seed_of(&view, connecting)?;
        let Ok(Ok(target)) = target_claim(&view, connecting, &(self.rules)(connecting)) else {
            return Ok(());
        };
        let open = OpenHeader::from_pow(&pow, seed, target, FormAttempt::FIRST);
        if shekyl_chain_rules::judge_header_cheap(
            &open,
            &view,
            &(self.rules)(connecting),
            &self.trust,
            &WallClock(self.wall),
        )
        .ok()
        .and_then(Result::ok)
        .is_none()
        {
            return Ok(());
        }
        let _ = bodies;
        self.plan_one(
            session,
            pow,
            seed,
            target,
            (self.rules)(connecting),
            HashClass::Unsolicited,
            out,
        );
        Ok(())
    }

    pub(crate) fn plan_bodies(&mut self, now: Instant, out: &mut Vec<Command<K>>) {
        let Some(seats) = self.seats else {
            return;
        };
        if seats == 0 || self.body_requests.len() >= BODY_REQUESTS_IN_FLIGHT {
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
        let limit = 100usize;
        let room = usize::try_from(seats).unwrap_or(limit);
        while height.to_raw() <= star_height.to_raw() && hashes.len() < limit.min(room) {
            let Some(hash) = self.tree.ancestor_at(self.star.hash, height) else {
                break;
            };
            if !self.held.iter().any(|a| a.header.hash() == hash) {
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
            .sessions
            .get(&session)
            .map(|s| s.transit)
            .unwrap_or_default();
        self.body_requests.push(BodyRequest {
            session,
            id,
            hashes,
        });
        let bytes = u64::try_from(wire.len()).unwrap_or(1).saturating_mul(1024);
        let secs = bytes / BODY_RATE_FLOOR.max(1);
        let deadline = now
            .checked_add(transit.saturating_add(std::time::Duration::from_secs(secs)))
            .unwrap_or(now);
        out.push(Command::RequestBodies {
            session,
            deadline,
            request: RequestBodies { hashes: wire },
        });
    }

    pub(crate) fn alarm_from_tree(&mut self, out: &mut Vec<Command<K>>) {
        if self.alarm_sent {
            return;
        }
        let Some(local) = self.local else {
            return;
        };
        let cap = self.cap();
        let Some(height) = local.height else {
            return;
        };
        for hash in self.tree.tip_hashes() {
            let Some(node_height) = self.tree.connecting(hash) else {
                continue;
            };
            let Some(placed) = self.tree.placement(hash) else {
                continue;
            };
            let depth = fork_depth(Some(height), placed.fork);
            let work = self
                .tree
                .record(hash)
                .map(|r| r.cumulative_difficulty)
                .unwrap_or(CumulativeDifficulty::ZERO);
            if work > local.work && depth > cap {
                out.push(Command::RaiseAlarm {
                    fork_at: placed.fork,
                    tip: hash,
                    work,
                });
                self.alarm_sent = true;
                let _ = node_height;
                self.tree.mark_invalid(hash);
                return;
            }
        }
    }

    fn evidence_alarm(&mut self, session: K, out: &mut Vec<Command<K>>) {
        let Some(run) = self.sessions.get(&session).and_then(|s| s.run.as_ref()) else {
            return;
        };
        if !run.evidence {
            return;
        }
        let Some(work) = run
            .checked
            .get(run.proven.saturating_sub(1))
            .map(|c| c.work)
        else {
            return;
        };
        let local = self
            .local
            .map(|l| l.work)
            .unwrap_or(CumulativeDifficulty::ZERO);
        if work > local && !self.alarm_sent {
            out.push(Command::RaiseAlarm {
                fork_at: run.parent_height,
                tip: run.checked[run.proven - 1].hash,
                work,
            });
            self.alarm_sent = true;
            self.drop_run(session);
            self.evidence = None;
        }
    }

    fn note_evidence(&mut self, session: K) {
        let Some(state) = self.sessions.get_mut(&session) else {
            return;
        };
        state.past_cap_followed = true;
        let candidate = state.run.as_ref().is_some_and(|run| {
            run.checked.last().is_some_and(|c| {
                c.work
                    > self
                        .local
                        .map(|l| l.work)
                        .unwrap_or(CumulativeDifficulty::ZERO)
            })
        });
        if !candidate || state.evidence_used || self.alarm || self.evidence.is_some() {
            return;
        }
        state.evidence_used = true;
        if let Some(run) = state.run.as_mut() {
            run.evidence = true;
            run.in_slot = false;
        }
        self.evidence = Some(session);
        // The draw is uniform over one candidate here. A later response
        // adds candidates only while none is in flight.
    }

    fn consider_slot(&mut self, session: K, out: &mut Vec<Command<K>>) {
        let holder = self.slot;
        let waiting_height = self
            .sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .and_then(|run| run.checked.first().map(|c| c.height));
        let waiting_work = self
            .sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .and_then(|run| run.checked.first().map(|c| c.work));
        let displace = match (holder, waiting_height, waiting_work) {
            (Some(holder), Some(height), Some(work)) => self
                .sessions
                .get(&holder)
                .and_then(|s| s.run.as_ref())
                .and_then(|run| {
                    run.checked
                        .iter()
                        .find(|c| c.height == height)
                        .map(|c| c.work)
                })
                .is_some_and(|holder_work| work > holder_work),
            (None, _, _) => true,
            _ => false,
        };
        if !displace {
            if let Some(state) = self.sessions.get_mut(&session) {
                state.header_quiet = true;
                state.run = None;
            }
            return;
        }
        if let Some(holder) = holder {
            let cap_headers = usize::try_from(self.cap().to_raw()).unwrap_or(1);
            if let Some(state) = self.sessions.get_mut(&holder) {
                if let Some(run) = state.run.as_mut() {
                    run.in_slot = false;
                    run.checked.truncate(cap_headers);
                    run.held.clear();
                }
            }
        }
        self.slot = Some(session);
        if let Some(run) = self.sessions.get_mut(&session).and_then(|s| s.run.as_mut()) {
            run.in_slot = true;
        }
        self.plan_proof(session, HashClass::HeaderPow, out);
    }

    fn plan_proof(&mut self, session: K, class: HashClass, out: &mut Vec<Command<K>>) {
        let Some(run) = self.sessions.get(&session).and_then(|s| s.run.as_ref()) else {
            return;
        };
        if run.job.is_some() || run.proven >= run.checked.len() {
            return;
        }
        let class = if run.evidence {
            HashClass::Evidence
        } else {
            class
        };
        let cache = cache_for(run, run.proven);
        let attempt = run.attempt;
        let mut items = Vec::new();
        for (offset, checked) in run.checked[run.proven..].iter().enumerate() {
            if cache_for(run, run.proven + offset) != cache {
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
        if let Some(run) = self.sessions.get_mut(&session).and_then(|s| s.run.as_mut()) {
            run.job = Some(id);
        }
        out.push(Command::Prove {
            job: Job::from_raw(id),
            class,
            cache,
            items,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_one(
        &mut self,
        session: K,
        pow: PowBlob,
        seed: BlockHash,
        target: Target,
        rule: RuleSet,
        class: HashClass,
        out: &mut Vec<Command<K>>,
    ) {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let hash = pow.identity();
        let header = pow.header.clone();
        let checked = Checked {
            hash,
            height: BlockHeight::ZERO,
            previous: header.previous,
            work: CumulativeDifficulty::ZERO,
            seed,
            target,
            rule,
            header,
            pow,
        };
        if let Some(state) = self.sessions.get_mut(&session) {
            state.run = Some(Run {
                parent: checked.previous,
                parent_height: BlockHeight::ZERO,
                checked: vec![checked],
                proven: 0,
                held: Vec::new(),
                in_slot: false,
                job: Some(id),
                attempt: FormAttempt::FIRST,
                past_cap: false,
                evidence: false,
            });
        }
        let item = self
            .sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .and_then(|run| run.checked.first())
            .map(|c| ProveItem {
                pow: c.pow.write(),
                seed: c.seed,
                target: c.target,
                attempt: FormAttempt::FIRST,
                rule_set: c.rule,
            });
        if let Some(item) = item {
            out.push(Command::Prove {
                job: Job::from_raw(id),
                class,
                cache: CachePlan::Main(seed),
                items: vec![item],
            });
        }
    }

    fn finish_run(&mut self, session: K, more: bool, now: Instant, out: &mut Vec<Command<K>>) {
        if !more {
            return;
        }
        let Some(run) = self.sessions.get(&session).and_then(|s| s.run.as_ref()) else {
            return;
        };
        let tip = run.checked.last().map(|c| (c.height, c.hash));
        let Some((height, hash)) = tip else {
            return;
        };
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        if let Some(state) = self.sessions.get_mut(&session) {
            state.continuation = Some(HeaderRequest {
                session,
                id,
                points: vec![(height, hash)],
            });
        }
        let transit = self
            .sessions
            .get(&session)
            .map(|s| s.transit)
            .unwrap_or_default();
        out.push(Command::RequestHeaders {
            session,
            deadline: header_deadline(now, transit),
            request: shekyl_levin::RequestHeaders {
                block_ids: vec![*hash.as_bytes()],
            },
        });
    }

    fn flush_offers(&mut self, out: &mut Vec<Command<K>>) {
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
            out.push(Command::Offer { arrivals });
        }
    }

    fn close(&mut self, session: K, cause: CloseCause, out: &mut Vec<Command<K>>) {
        self.sessions.remove(&session);
        if self
            .header_request
            .as_ref()
            .is_some_and(|req| req.session == session)
        {
            self.header_request = None;
        }
        self.body_requests.retain(|req| req.session != session);
        if self.slot == Some(session) {
            self.slot = None;
        }
        if self.evidence == Some(session) {
            self.evidence = None;
        }
        out.push(Command::Close { session, cause });
    }

    fn drop_run(&mut self, session: K) {
        if let Some(state) = self.sessions.get_mut(&session) {
            state.run = None;
        }
        if self.slot == Some(session) {
            self.slot = None;
        }
    }

    fn session_for_job(&self, job: u64) -> Option<K> {
        self.sessions.iter().find_map(|(key, state)| {
            state
                .run
                .as_ref()
                .is_some_and(|run| run.job == Some(job))
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

    fn overlay_before(&self, session: K, hash: BlockHash) -> Vec<Overlay> {
        self.sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .map(|run| {
                run.checked
                    .iter()
                    .take_while(|c| c.hash != hash)
                    .map(|c| Overlay {
                        height: c.height,
                        hash: c.hash,
                        header: c.header.clone(),
                        work: c.work,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn overlay_of(&self, session: K) -> Vec<Overlay> {
        self.sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .map(|run| {
                run.checked
                    .iter()
                    .map(|c| Overlay {
                        height: c.height,
                        hash: c.hash,
                        header: c.header.clone(),
                        work: c.work,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn view_for<'a, 'id, H: HeaderView<'id>>(
        &'a self,
        main: &'a H,
        parent: BlockHash,
        parent_height: BlockHeight,
        overlay: &'a [Overlay],
    ) -> BranchView<'a, H> {
        let base = if let Some(placed) = self.tree.placement(parent) {
            BranchView::above(main, &self.tree, parent, placed.height, placed.fork)
        } else if parent == BlockHash::NULL {
            BranchView::empty_main(main)
        } else {
            BranchView::on_main(main, parent, parent_height)
        };
        base.with_run(overlay)
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
        let parent = formed.previous();
        let overlay = self.overlay_before(session, formed.hash());
        let parent_height = self
            .tree
            .placement(parent)
            .map(|p| p.height)
            .or_else(|| {
                self.sessions
                    .get(&session)
                    .and_then(|s| s.run.as_ref())
                    .map(|run| {
                        run.checked
                            .iter()
                            .find(|c| c.hash == parent)
                            .map(|c| c.height)
                            .unwrap_or(run.parent_height)
                    })
            })
            .unwrap_or(BlockHeight::ZERO);
        let view = self.view_for(main, parent, parent_height, &overlay);
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

    fn body_source(&self, end: BlockHash) -> Option<K> {
        let end_height = self.tree.connecting(end)?;
        self.sessions.iter().find_map(|(key, state)| {
            if state.body_excluded {
                return None;
            }
            if self.body_requests.iter().any(|req| req.session == *key) {
                return None;
            }
            let covers = state.frontier.is_some_and(|(height, hash)| {
                height.to_raw() >= end_height.to_raw() || hash == end
            });
            let blocked = state.unavailable.contains(&end);
            (covers && !blocked).then_some(*key)
        })
    }
}

enum Judged<E> {
    Ok(Box<HeaderJudged>),
    Refused(CenRow),
    Stale(Box<Stale>),
    View(E),
    Gone,
}

fn cache_for(run: &Run, index: usize) -> CachePlan {
    let checked = &run.checked[index];
    if run.evidence && index == 0 {
        return CachePlan::Evidence(checked.seed);
    }
    if checked.height.to_raw()
        <= run
            .parent_height
            .to_raw()
            .saturating_add(SEEDHASH_EPOCH_LAG)
    {
        CachePlan::Main(checked.seed)
    } else {
        CachePlan::Branch(checked.seed)
    }
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
