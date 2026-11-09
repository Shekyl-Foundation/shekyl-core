// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One header page, from the bytes to the run's next step.
//!
//! A page is admitted, split into the prefix this node already holds and
//! the suffix it does not, fitted to the session's run, judged, and then
//! disposed of. The run owns the fit and, once the headers are on it, what
//! a reachable page asks for.

use std::time::Instant;

use shekyl_chain_rules::{
    target_claim, AtHeight, Fault, FormAttempt, HeaderView, OpenHeader, RuleSet,
};
use shekyl_levin::ResponseHeaders;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::PowBlob;

use super::WallClock;
use crate::branch::Pending;
use crate::model::{CloseCause, Command, HashClass, HeadersFormFault, Spent, Sync};
use crate::peer::{rate, Checked, HeaderReply, PageFit, Reach, Run};

/// A page whose blobs linked, whose parent this node can place, and whose
/// request this node still owes an answer to.
struct Admitted {
    blobs: Vec<(BlockHash, PowBlob)>,
    points: Vec<(BlockHeight, BlockHash)>,
    parent: BlockHash,
    parent_height: BlockHeight,
    more: bool,
}

/// The suffix of a page that this node does not already hold.
struct FreshPage {
    /// The last held header. The first fresh header names it as `previous`.
    base: BlockHash,
    base_height: BlockHeight,
    /// The parent of the page's first blob. The reorg depth is measured here,
    /// not at `base`: the held prefix may already sit above the fork.
    parent_height: BlockHeight,
    fresh: Vec<(BlockHash, PowBlob)>,
    more: bool,
}

/// Headers the cheap check accepted, still carrying the page they came on.
struct JudgedPage {
    base: BlockHash,
    base_height: BlockHeight,
    more: bool,
    accepted: Vec<Checked>,
}

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    pub(crate) fn on_headers<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        bytes: &[u8],
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        let Some(admitted) = self.admit_page(session, bytes, now, out) else {
            return Ok(());
        };
        let Some(page) = self.split_held(main, session, admitted, now, out)? else {
            return Ok(());
        };
        if self.lay_aside(session, page.base) {
            return Ok(());
        }
        let past_cap = self.page_past_cap(session, page.parent_height);
        if self.page_settled(session, past_cap) {
            return Ok(());
        }
        let Some(mut judged) = self.judge_fresh(main, session, page, out)? else {
            return Ok(());
        };
        self.attach_page(session, &mut judged, past_cap);
        self.dispose_page(session, &judged, past_cap, now, out);
        Ok(())
    }

    /// Decode the page and match it to the request it answers.
    ///
    /// `None` when the session is gone, the response was a withdrawn
    /// request, or the page was closed or spent here.
    fn admit_page(
        &mut self,
        session: K,
        bytes: &[u8],
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) -> Option<Admitted> {
        if !self.note_header_reply(session) {
            return None;
        }
        let Ok(response) = ResponseHeaders::decode(bytes) else {
            self.close(session, CloseCause::HeadersUndecodable, out);
            return None;
        };
        if let Some(state) = self.peers.get_mut(&session) {
            if let Some(claim) = state.claim.as_mut() {
                claim.work = shekyl_difficulty::CumulativeDifficulty::from_raw(response.tip_work);
            }
        }
        if response.blobs.is_empty() {
            self.admit_empty(session, response.more, out);
            return None;
        }
        let mut blobs = Vec::with_capacity(response.blobs.len());
        for bytes in &response.blobs {
            let Ok(pow) = PowBlob::read(bytes) else {
                self.close(
                    session,
                    CloseCause::HeadersForm(HeadersFormFault::BlobUnreadable),
                    out,
                );
                return None;
            };
            blobs.push((pow.identity(), pow));
        }
        let parent = blobs[0].1.header.previous;
        let Some(matched) = self.match_parent(session, parent) else {
            self.close(
                session,
                CloseCause::HeadersForm(HeadersFormFault::ParentUnrequested),
                out,
            );
            return None;
        };
        if let Some(state) = self.peers.get_mut(&session) {
            state.rate = Some(rate(bytes.len(), matched.sent, now));
        }
        self.clear_matched_request(session, matched.continuation);
        if self.tree.remembers(parent) {
            self.close(session, CloseCause::InvalidAncestor, out);
            return None;
        }
        if !self.links(&blobs, session, out) {
            return None;
        }
        let Some(parent_height) = self.place_parent(&matched.points, parent) else {
            self.close(
                session,
                CloseCause::HeadersForm(HeadersFormFault::ParentUnplaced),
                out,
            );
            return None;
        };
        self.note_frontier(session, parent_height, parent);
        Some(Admitted {
            blobs,
            points: matched.points,
            parent,
            parent_height,
            more: response.more,
        })
    }

    /// Mark a header response received, discarding a withdrawn request's answer.
    ///
    /// Answers arrive in request order. The oldest request still owed an
    /// answer, when this node withdrew it, is this response: it was asked
    /// for, so it is not the peer's fault, and its locator is stale, so it
    /// is not judged. A follow-up sent before that withdrawal is answered
    /// first and is not that answer.
    fn note_header_reply(&mut self, session: K) -> bool {
        let Some(peer) = self.peers.get_mut(&session) else {
            return false;
        };
        if let Some(&oldest) = peer.withdrawn.first() {
            let follow_up_first = peer
                .follow_up
                .as_ref()
                .is_some_and(|request| request.id < oldest);
            if !follow_up_first {
                peer.withdrawn.remove(0);
                return false;
            }
        }
        // Received. The opening treats the request as resolved once none of
        // this response's headers still waits for its proof.
        peer.reply = HeaderReply::Received;
        true
    }

    /// A page with no blobs. More than nothing is a form fault. A chain
    /// that ends on the locator is unmet when the claim still beats the
    /// work through it, and spent otherwise: the same locator would be
    /// answered the same way.
    fn admit_empty(&mut self, session: K, more: bool, out: &mut Vec<Command<K>>) {
        if more {
            self.close(
                session,
                CloseCause::HeadersForm(HeadersFormFault::EmptyWithMore),
                out,
            );
            return;
        }
        if self.claim_exceeds(session, self.star.work) {
            self.close(session, CloseCause::ClaimUnmet, out);
            return;
        }
        self.spend(session, Spent::Exhausted, out);
    }

    /// The request whose locator contains `parent`, and whether it was the
    /// session's follow-up rather than the extending request.
    fn match_parent(&self, session: K, parent: BlockHash) -> Option<Matched> {
        let continuation = self
            .peers
            .get(&session)
            .and_then(|state| state.follow_up.as_ref())
            .filter(|request| request.points.iter().any(|(_, hash)| *hash == parent))
            .map(|request| Matched {
                points: request.points.clone(),
                sent: request.sent,
                continuation: true,
            });
        if continuation.is_some() {
            return continuation;
        }
        self.header_request
            .as_ref()
            .filter(|request| {
                request.session == session && request.points.iter().any(|(_, hash)| *hash == parent)
            })
            .map(|request| Matched {
                points: request.points.clone(),
                sent: request.sent,
                continuation: false,
            })
    }

    fn clear_matched_request(&mut self, session: K, from_continuation: bool) {
        if from_continuation {
            if let Some(state) = self.peers.get_mut(&session) {
                state.follow_up = None;
            }
            return;
        }
        if self
            .header_request
            .as_ref()
            .is_some_and(|request| request.session == session)
        {
            self.header_request = None;
        }
    }

    /// Each blob names the previous blob. The first names the request's parent.
    fn links(
        &mut self,
        blobs: &[(BlockHash, PowBlob)],
        session: K,
        out: &mut Vec<Command<K>>,
    ) -> bool {
        let mut previous = blobs[0].1.header.previous;
        for (index, (hash, pow)) in blobs.iter().enumerate() {
            if index > 0 && pow.header.previous != previous {
                self.close(
                    session,
                    CloseCause::HeadersForm(HeadersFormFault::Linkage),
                    out,
                );
                return false;
            }
            previous = *hash;
        }
        true
    }

    fn place_parent(
        &self,
        points: &[(BlockHeight, BlockHash)],
        parent: BlockHash,
    ) -> Option<BlockHeight> {
        points
            .iter()
            .find(|(_, hash)| *hash == parent)
            .map(|(height, _)| *height)
            .or_else(|| self.tree.placement(parent).map(|placed| placed.height))
    }

    fn note_frontier(&mut self, session: K, height: BlockHeight, hash: BlockHash) {
        let Some(state) = self.peers.get_mut(&session) else {
            return;
        };
        let higher = state
            .frontier
            .is_none_or(|(have, _)| height.to_raw() >= have.to_raw());
        if higher {
            state.frontier = Some((height, hash));
        }
    }

    /// Separate the prefix this node holds from the suffix it must judge.
    ///
    /// The peer answers from the child of the first locator hash it holds.
    /// The locator is sparse below its dense prefix, so a page routinely
    /// opens on headers this node holds: on main between the locator point
    /// and the fork, then in `T`. The new headers follow that prefix and
    /// are judged above its last header. A held header after a new one
    /// rejoins a chain it had left, which a peer cannot serve.
    fn split_held<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        admitted: Admitted,
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) -> Result<Option<FreshPage>, H::Fault> {
        let Admitted {
            blobs,
            points,
            parent,
            parent_height,
            more,
        } = admitted;
        let last_served = blobs.last().map(|(hash, _)| *hash);
        let mut held = parent;
        let mut held_height = parent_height;
        let mut fresh = Vec::new();
        for (index, (hash, pow)) in blobs.into_iter().enumerate() {
            let height = parent_height + BlockCount::from_raw(index as u64 + 1);
            match self.classify(main, &points, hash, height, fresh.is_empty())? {
                BlobPlace::Held { hash, height } => {
                    (held, held_height) = (hash, height);
                    self.note_frontier(session, height, hash);
                }
                BlobPlace::Fresh => fresh.push((hash, pow)),
                BlobPlace::HeldAfterNew => {
                    self.close(
                        session,
                        CloseCause::HeadersForm(HeadersFormFault::HeldAfterNew),
                        out,
                    );
                    return Ok(None);
                }
            }
        }
        if fresh.is_empty() {
            self.admit_held_page(
                main,
                session,
                &HeldPrefix {
                    points: &points,
                    hash: held,
                    height: held_height,
                    last_served,
                    more,
                },
                now,
                out,
            )?;
            return Ok(None);
        }
        debug_assert_eq!(fresh[0].1.header.previous, held);
        Ok(Some(FreshPage {
            base: held,
            base_height: held_height,
            parent_height,
            fresh,
            more,
        }))
    }

    /// One blob's place. The store is read only while the held prefix is
    /// still open: linkage makes a main header after a new one a chain the
    /// peer cannot have served, so that read would not change the place.
    /// A header already in `T` after a new one is that chain, and closes.
    fn classify<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        points: &[(BlockHeight, BlockHash)],
        hash: BlockHash,
        height: BlockHeight,
        prefix_open: bool,
    ) -> Result<BlobPlace, H::Fault> {
        let in_tree = self.tree.contains(hash);
        if !prefix_open {
            return Ok(if in_tree {
                BlobPlace::HeldAfterNew
            } else {
                BlobPlace::Fresh
            });
        }
        if in_tree {
            let height = self.tree.connecting(hash).unwrap_or(height);
            return Ok(BlobPlace::Held { hash, height });
        }
        let on_main = points.iter().any(|(_, known)| *known == hash)
            || matches!(
                main.header_at(height)?,
                AtHeight::Recorded(record) if record.hash == hash
            );
        if on_main {
            let height = self.tree.connecting(hash).unwrap_or(height);
            return Ok(BlobPlace::Held { hash, height });
        }
        Ok(BlobPlace::Fresh)
    }

    /// Every header on the page is already held.
    ///
    /// The peer's chain ends there when it sends no more. A claim above
    /// the work through that chain is unmet. Otherwise `T` did not change,
    /// so neither did `H*`, and this locator would be answered the same
    /// way. A run that already holds headers finishes; a page that is only
    /// the prefix continues from the last header served.
    fn admit_held_page<'id, 'a, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        held: &HeldPrefix<'a>,
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if !held.more {
            let end = self.end_work(main, held.hash, held.height)?;
            if self.claim_exceeds(session, end) {
                self.close(session, CloseCause::ClaimUnmet, out);
            } else {
                self.spend(session, Spent::Exhausted, out);
            }
            return Ok(());
        }
        let running = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .is_some_and(|run| !run.chain.checked.is_empty());
        if running {
            self.finish_run(session, true, now, out);
            return Ok(());
        }
        let point = held.last_served.and_then(|hash| {
            self.tree
                .connecting(hash)
                .or_else(|| {
                    held.points
                        .iter()
                        .find(|(_, known)| *known == hash)
                        .map(|(height, _)| *height)
                })
                .map(|height| (height, hash))
        });
        match point {
            Some(point) => self.follow_up(session, point, now, out),
            None => self.spend(session, Spent::Exhausted, out),
        }
        Ok(())
    }

    /// An evidence page from another chain is set aside. Any other page
    /// that does not extend the run replaces it.
    ///
    /// The evidence check proves the branch it drew, and the session's one
    /// draw is spent on it. A page that does not continue that run is the
    /// branch asked for from a locator that holds nothing of it: the claim
    /// moved while the check ran. The page adds nothing the check needs.
    /// The run stays, and the branch counts as followed until the claim
    /// moves, so the page is not asked for again.
    fn lay_aside(&mut self, session: K, base: BlockHash) -> bool {
        let fit = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .map(|run| run.page_fit(base));
        match fit {
            Some(PageFit::Aside) => {
                if let Some(state) = self.peers.get_mut(&session) {
                    state.draw.followed_past_cap();
                }
                true
            }
            Some(PageFit::Replaces) => {
                self.drop_run(session);
                false
            }
            Some(PageFit::Continues) | None => false,
        }
    }

    /// Past the reorg cap: the page's parent is deeper than the cap, or
    /// the run it extends already is.
    fn page_past_cap(&self, session: K, parent_height: BlockHeight) -> bool {
        let depth = super::fork_depth(self.local.and_then(|local| local.height), parent_height);
        depth > self.cap()
            || self
                .peers
                .get(&session)
                .and_then(|state| state.run.as_ref())
                .is_some_and(Run::past_cap)
    }

    /// A latched chain, or a past-cap branch already followed, takes no
    /// further page.
    ///
    /// A run still in progress keeps its headers. Followed-once starts
    /// when that run ends. An evidence run's refetch from the fork is the
    /// same run continuing, so it is not a second following.
    fn page_settled(&self, session: K, past_cap: bool) -> bool {
        if !past_cap {
            return false;
        }
        if self.alarm {
            return true;
        }
        let evidence = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .is_some_and(Run::is_evidence);
        !evidence
            && self
                .peers
                .get(&session)
                .is_some_and(|peer| peer.draw.past_cap_followed())
    }

    /// Cheap-check the fresh suffix above the run's parent, or above the
    /// page's base when the page opens a run.
    fn judge_fresh<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        page: FreshPage,
        out: &mut Vec<Command<K>>,
    ) -> Result<Option<JudgedPage>, H::Fault> {
        let FreshPage {
            base,
            base_height,
            fresh,
            more,
            ..
        } = page;
        let (anchor, anchor_height) = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .map_or((base, base_height), |run| {
                (run.chain.parent, run.chain.parent_height)
            });
        let mut accepted = Vec::with_capacity(fresh.len());
        for (hash, pow) in fresh {
            let checked = self.judge_one(
                main,
                session,
                &Anchor {
                    hash: anchor,
                    height: anchor_height,
                },
                &accepted,
                (hash, pow),
                out,
            )?;
            let Some(checked) = checked else {
                return Ok(None);
            };
            accepted.push(checked);
        }
        Ok(Some(JudgedPage {
            base,
            base_height,
            more,
            accepted,
        }))
    }

    fn judge_one<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        anchor: &Anchor,
        accepted: &[Checked],
        header: (BlockHash, PowBlob),
        out: &mut Vec<Command<K>>,
    ) -> Result<Option<Checked>, H::Fault> {
        let (hash, pow) = header;
        let earlier = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .map_or(&[][..], |run| run.chain.checked.as_slice());
        let view = self.view_for(
            main,
            anchor.hash,
            anchor.height,
            Pending::new(earlier, accepted),
        );
        let connecting = view
            .tip()?
            .map(|tip| tip.height + BlockCount::ONE)
            .unwrap_or(BlockHeight::ZERO);
        let seed = Self::seed_of(&view, connecting)?;
        let target = match target_claim(&view, connecting, &(self.rules)(connecting)) {
            Ok(target) => target,
            Err(Fault::View(fault)) => return Err(fault),
            Err(Fault::Stale(_) | Fault::Corrupt(_)) => {
                self.spend(session, Spent::Stale, out);
                return Ok(None);
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
                return Ok(None);
            }
            Err(fault) => match fault {
                shekyl_chain_rules::ProspectFault::Chain(Fault::View(fault)) => return Err(fault),
                _ => {
                    self.spend(session, Spent::Stale, out);
                    return Ok(None);
                }
            },
        };
        Ok(Some(Checked {
            hash,
            height: prospect.connecting,
            work: prospect.cumulative_difficulty,
            seed,
            target,
            rule: (self.rules)(connecting),
            header: pow.header.clone(),
            pow,
        }))
    }

    fn attach_page(&mut self, session: K, page: &mut JudgedPage, past_cap: bool) {
        let accepted = std::mem::take(&mut page.accepted);
        if let Some(run) = self
            .peers
            .get_mut(&session)
            .and_then(|state| state.run.as_mut())
        {
            run.chain.checked.extend(accepted);
            run.adopt_geometry(past_cap);
            return;
        }
        if let Some(state) = self.peers.get_mut(&session) {
            state.run = Some(Run::open(page.base, page.base_height, accepted, past_cap));
        }
    }

    /// Prove, spend, close, or refetch, as the run's geometry asks.
    fn dispose_page(
        &mut self,
        session: K,
        page: &JudgedPage,
        past_cap: bool,
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) {
        if past_cap {
            self.dispose_past_cap(session, page.more, now, out);
            return;
        }
        let claim = self
            .peers
            .get(&session)
            .and_then(|state| state.claim)
            .map(|claim| claim.work);
        let budget = usize::try_from(self.cap().to_raw()).unwrap_or(usize::MAX);
        let Some(reach) = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .map(|run| run.reach(page.more, claim, self.star.work, budget))
        else {
            return;
        };
        match reach {
            Reach::Unmet => self.close(session, CloseCause::ClaimUnmet, out),
            Reach::BelowStar => self.spend(session, Spent::BelowStar, out),
            Reach::FillSlot { more } => {
                self.consider_slot(session, out);
                self.finish_run(session, more, now, out);
            }
            Reach::Prove { more } => {
                self.plan_proof(session, HashClass::HeaderPow, out);
                self.finish_run(session, more, now, out);
            }
            Reach::Continue { more } => self.finish_run(session, more, now, out),
        }
    }

    /// A past-cap page. The evidence check proves from the fork, or asks
    /// again when its window no longer starts there. Any other window is
    /// trimmed, and it is followed once when it ends or passes its bound.
    fn dispose_past_cap(
        &mut self,
        session: K,
        more: bool,
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) {
        let evidence = self
            .peers
            .get(&session)
            .and_then(|peer| peer.run.as_ref())
            .is_some_and(Run::is_evidence);
        if evidence {
            let omits_fork = self
                .peers
                .get(&session)
                .and_then(|peer| peer.run.as_ref())
                .is_some_and(Run::omits_fork);
            if omits_fork {
                self.refetch_evidence(session, now, out);
                return;
            }
            self.plan_proof(session, HashClass::Evidence, out);
            self.finish_run(session, more, now, out);
            return;
        }
        let over = self.past_bound(session, self.cap());
        self.trim_window(session);
        self.note_evidence(session);
        let candidate = self
            .peers
            .get(&session)
            .and_then(|state| state.run.as_ref())
            .is_some_and(|run| run.is_candidate() || run.is_evidence());
        if over || !more {
            if let Some(state) = self.peers.get_mut(&session) {
                state.draw.followed_past_cap();
            }
            if !candidate {
                self.drop_run(session);
            }
            return;
        }
        self.finish_run(session, true, now, out);
    }
}

/// The request a page's parent answered.
struct Matched {
    points: Vec<(BlockHeight, BlockHash)>,
    sent: Instant,
    /// The session's follow-up, rather than the extending request.
    continuation: bool,
}

/// The held prefix a page reduced to when it contained nothing new.
struct HeldPrefix<'a> {
    points: &'a [(BlockHeight, BlockHash)],
    hash: BlockHash,
    height: BlockHeight,
    last_served: Option<BlockHash>,
    more: bool,
}

/// The header fresh headers are judged above.
struct Anchor {
    hash: BlockHash,
    height: BlockHeight,
}

/// Where one blob sits on a page.
enum BlobPlace {
    /// This node holds it, on main or in `T`.
    Held {
        hash: BlockHash,
        height: BlockHeight,
    },
    /// Not held. Judged when it follows the held prefix; kept when a new
    /// header already precedes it and this one is not in `T`.
    Fresh,
    /// Already in `T` after a header this node does not hold.
    HeldAfterNew,
}
