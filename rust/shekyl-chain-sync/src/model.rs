// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The coordinator. One owner, no clock of its own, no store.
//!
//! [`Sync`] looks at the set of [`crate::peer::Peer`] machines. It draws
//! a peer, sizes a request, selects `H*`, and publishes the derived
//! state. A peer's mode transition lives with the peer.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use shekyl_chain_rules::{AtHeight, HeaderView, RuleSet, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_levin::{RequestHeaders, BODIES_RESPONSE_BYTES, HEADERS_RESPONSE_BYTES};
use shekyl_types::Timestamp;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};

use crate::peer::{Dispute, HeaderRequest, Peer};

#[cfg(test)]
use crate::branch::BranchView;
use crate::claim::{self, PayloadRefused, PeerClaim};
use crate::locator::{locator, locator_heights};
use crate::state::SyncState;
use crate::tree::{HeaderTree, Star};

/// Bytes per second assumed for a header or body request's deadline.
///
/// One rate: the two deadlines are not different measurements. A full
/// header response is [`HEADERS_RESPONSE_BYTES`] (2 MiB). At 8 KiB/s that
/// response takes 256 seconds, which is slow for a single Tor stream and
/// far below a clearnet rate, so an honest peer on Tor is not declared
/// late and a stalled peer is not waited on for a LAN round trip. A body
/// deadline is [`BODIES_RESPONSE_BYTES`] at this same rate. The request
/// names hashes; the bytes the peer may send are that budget.
///
/// Assumption, replaced by CS-Q11's measurement of bytes per second over
/// Tor on the floor device. Split it only if that measurement shows the
/// header stream and the body stream need different floors.
pub const SYNC_RATE_FLOOR: u64 = 8 * 1024;

/// How many body spans may be outstanding at once.
///
/// Assumption, replaced by CS-Q11's measurement of how many spans the
/// floor device can have in flight before the entry's room is the limit.
pub const BODY_REQUESTS_IN_FLIGHT: usize = 4;

const _: () = assert!(HEADERS_RESPONSE_BYTES / SYNC_RATE_FLOOR == 256);
const _: () = assert!(BODIES_RESPONSE_BYTES / SYNC_RATE_FLOOR == 1024);

pub use crate::protocol::{
    BoundArrival, CachePlan, CloseCause, Command, Event, HashClass, Job, OfferedBody, Outcome,
    ProveItem, Proved,
};

/// The chain the model has observed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Local {
    pub(crate) hash: BlockHash,
    pub(crate) height: Option<BlockHeight>,
    pub(crate) work: CumulativeDifficulty,
}

/// The coordinator. It holds one peer machine per open session and the
/// chain those peers are building. The long-run slot and the evidence
/// check are modes of a peer, not fields beside the map.
pub struct Sync<K, R> {
    pub(crate) peers: BTreeMap<K, Peer<K>>,
    /// A claim that arrived before its session opened.
    pub(crate) pending: BTreeMap<K, PeerClaim>,
    pub(crate) local: Option<Local>,
    pub(crate) tree: HeaderTree,
    /// `H*`: the local tip, or a heavier reachable tip in `T`.
    pub(crate) star: Star,
    /// The one header request that extends `H*`, if one is out.
    /// A peer's own follow-up lives on that peer.
    pub(crate) header_request: Option<HeaderRequest<K>>,
    pub(crate) next_id: u64,
    pub(crate) next_tag: u64,
    /// Seats still free. `None` until the first `Room`. An offer spends
    /// one per arrival. `NoRoom` freezes this at zero until the next `Room`.
    pub(crate) seats: Option<u32>,
    /// The entry could not read the store. Body planning stays stopped:
    /// a later seat report does not ask for the body or offer it again.
    pub(crate) unreadable: bool,
    /// Bound bodies waiting for a seat.
    pub(crate) held: Vec<BoundArrival<K>>,
    /// Offered arrivals waiting for the entry's reply, keyed by tag.
    pub(crate) outstanding: Vec<BoundArrival<K>>,
    /// Bodies the entry accepted. The walk treats them as present.
    pub(crate) accepted: BTreeSet<BlockHash>,
    /// Who served a body, from the offer until the header leaves `T` or
    /// is refused. A promotion refusal closes that session.
    pub(crate) served: BTreeMap<BlockHash, K>,
    /// The CS-Q4(c) snapshot, while a body past its fork is waiting.
    pub(crate) dispute: Option<Dispute<K>>,
    /// CEN-C1's wall clock. The model does not read one.
    pub(crate) wall: Timestamp,
    /// The rule set in force at a height. The reorg cap is that set's.
    pub(crate) rules: R,
    /// The fill's descending frontier. Genesis means the fill is done.
    pub(crate) fill_frontier: BlockHeight,
    /// The store's latch. Read, never published as the state.
    pub(crate) alarm: bool,
    /// Raised from `T` already, so it is not raised again.
    pub(crate) alarm_sent: bool,
    /// The posture `judge_header` is given. The fill's checkpoint does
    /// not read it: until slice 6 every posture is full.
    pub(crate) trust: Trust,
}

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    /// `trust` is the posture [`shekyl_chain_rules::judge_header`] is
    /// given. Until slice 6 every [`Trust`] is the full posture, so
    /// the fill's checkpoint is genesis. `rules` is the schedule: the
    /// reorg cap is the set in force at the connecting height.
    #[must_use]
    pub fn new(trust: Trust, rules: R) -> Self {
        Self {
            peers: BTreeMap::new(),
            pending: BTreeMap::new(),
            local: None,
            tree: HeaderTree::default(),
            star: Star::local(BlockHash::NULL, CumulativeDifficulty::ZERO),
            header_request: None,
            next_id: 1,
            next_tag: 1,
            seats: None,
            unreadable: false,
            held: Vec::new(),
            outstanding: Vec::new(),
            accepted: BTreeSet::new(),
            served: BTreeMap::new(),
            dispute: None,
            wall: Timestamp::from_raw(1_700_000_100),
            rules,
            fill_frontier: BlockHeight::ZERO,
            alarm: false,
            alarm_sent: false,
            trust,
        }
    }

    /// CEN-C1's operand. Deadlines use the monotonic instant instead.
    pub fn set_wall(&mut self, wall: Timestamp) {
        self.wall = wall;
    }

    /// Record a hint. Refused only when the claim cannot be a chain.
    /// A recorded claim does not change [`Self::state`]. A claim that
    /// beats `H*` can start the one header request, whose locator is
    /// read from `main`. A claim naming a tip this node holds can make the
    /// session a body source, and bodies are planned at once.
    ///
    /// # Errors
    ///
    /// [`PayloadRefused`] when the block count is 0, or the work is
    /// below that count. The main view's fault, when the locator cannot
    /// be read.
    pub fn claim<'id, H: HeaderView<'id>>(
        &mut self,
        session: K,
        claim: PeerClaim,
        main: &H,
        now: Instant,
        rng: &mut impl RelayRng,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), ClaimError<H::Fault>> {
        let claim = claim::admit(claim).map_err(ClaimError::Refused)?;
        if let Some(open) = self.peers.get_mut(&session) {
            let changed = open.claim != Some(claim);
            open.claim = Some(claim);
            if changed {
                open.gates.header_quiet = false;
                open.gates.past_cap_followed = false;
            }
        } else {
            self.pending.insert(session, claim);
        }
        self.plan(main, now, rng, out).map_err(ClaimError::View)?;
        // The tip a claim names can make the session a body source (CS-F8).
        self.plan_bodies(now, out);
        Ok(())
    }

    /// The derived state. A claim's value is not an input.
    #[must_use]
    pub fn state(&self) -> SyncState {
        if self.peers.is_empty() {
            return SyncState::NoView;
        }
        let Some(local) = self.local else {
            return SyncState::NoView;
        };
        if self.star.work > local.work {
            return SyncState::Behind {
                have: local.work,
                best: self.star.work,
            };
        }
        if self.fill_frontier > Self::checkpoint() {
            return SyncState::Following {
                verified_to: self.fill_frontier,
            };
        }
        SyncState::Synced
    }

    /// Whether the store's latch is set. It does not withhold [`SyncState::Synced`].
    #[must_use]
    pub const fn alarm(&self) -> bool {
        self.alarm
    }

    /// `H*`: the hash and the work selection last chose.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn selected(&self) -> Star {
        self.star
    }

    /// Headers in `T`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn header_count(&self) -> usize {
        self.tree.len()
    }

    /// Whether `T` holds `hash`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn contains_header(&self, hash: BlockHash) -> bool {
        self.tree.contains(hash)
    }

    /// Whether `hash` was marked invalid, with its descendants.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn remembers_header(&self, hash: BlockHash) -> bool {
        self.tree.remembers(hash)
    }

    /// Node loads since the tree was built, or since [`Self::reset_visits`].
    #[cfg(test)]
    #[must_use]
    pub(crate) fn tree_visits(&self) -> u64 {
        self.tree.visits()
    }

    /// Start the node-load count over.
    #[cfg(test)]
    pub(crate) fn reset_visits(&self) {
        self.tree.reset_visits();
    }

    /// The peer whose run holds the long-run slot.
    pub(crate) fn slot_holder(&self) -> Option<K> {
        self.peers.iter().find_map(|(key, peer)| {
            peer.run
                .as_ref()
                .is_some_and(crate::peer::Run::is_slot)
                .then_some(*key)
        })
    }

    /// The peer whose evidence check is in flight.
    pub(crate) fn evidence_holder(&self) -> Option<K> {
        self.peers.iter().find_map(|(key, peer)| {
            peer.run
                .as_ref()
                .is_some_and(crate::peer::Run::is_evidence)
                .then_some(*key)
        })
    }

    /// Body spans the peers are serving.
    pub(crate) fn spans_in_flight(&self) -> usize {
        self.peers
            .values()
            .filter(|peer| peer.span.is_some())
            .count()
    }

    /// The peer whose run holds the long-run slot.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn slot_session(&self) -> Option<K> {
        self.slot_holder()
    }

    /// Cheap-checked headers the session's run still holds.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn run_len(&self, session: K) -> usize {
        self.peers
            .get(&session)
            .and_then(|peer| peer.run.as_ref())
            .map(|run| run.chain.checked.len())
            .unwrap_or(0)
    }

    /// The peer whose evidence check is in flight.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn evidence_session(&self) -> Option<K> {
        self.evidence_holder()
    }

    /// The run's cheap-checked headers, in order. A past-cap run keeps
    /// only its window, so this is that window.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn run_records(&self, session: K) -> Vec<shekyl_chain_rules::HeaderRecord> {
        self.peers
            .get(&session)
            .and_then(|peer| peer.run.as_ref())
            .map(|run| {
                run.chain
                    .checked
                    .iter()
                    .map(|c| shekyl_chain_rules::HeaderRecord {
                        hash: c.hash,
                        header: c.header.clone(),
                        cumulative_difficulty: c.work,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The branch whose tip is `parent`: `T` when the parent is in the
    /// tree, main when the parent is the local tip. `None` when it is
    /// neither, and the caller judges against `main` and records the result.
    #[cfg(test)]
    pub(crate) fn branch_of<'a, H>(
        &'a self,
        main: &'a H,
        parent: BlockHash,
    ) -> Option<BranchView<'a, H>> {
        if let Some(placed) = self.tree.placement(parent) {
            return Some(BranchView::above(
                main,
                &self.tree,
                parent,
                placed.height,
                placed.fork,
            ));
        }
        let local = self.local?;
        if local.hash == parent {
            return match local.height {
                Some(height) => Some(BranchView::on_main(main, parent, height)),
                None if parent == BlockHash::NULL => Some(BranchView::empty_main(main)),
                None => None,
            };
        }
        if local.height.is_none() && parent == BlockHash::NULL {
            return Some(BranchView::empty_main(main));
        }
        None
    }

    /// The transit the session opened with.
    #[must_use]
    pub fn transit(&self, session: K) -> Option<Duration> {
        self.peers.get(&session).map(|peer| peer.transit)
    }

    /// Apply one event. `main` is the chain as of `now`.
    ///
    /// # Errors
    ///
    /// The main view's own fault. A store that cannot answer is not a
    /// chain, and it is not swallowed.
    pub fn handle<'id, H: HeaderView<'id>>(
        &mut self,
        event: Event<K>,
        main: &H,
        now: Instant,
        rng: &mut impl RelayRng,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        let before = self.state();
        let header_response = matches!(event, Event::Headers { .. });
        match event {
            Event::SessionOpened { session, transit } => {
                let claim = self.pending.remove(&session);
                self.peers.insert(session, Peer::open(transit, claim));
                if self.local.is_none() {
                    self.observe(main, None)?;
                }
            }
            Event::SessionClosed { session } => self.release_session(session),
            Event::Tip { tip } => {
                self.observe(main, Some(tip.height))?;
                self.tree.connected(main, tip.height)?;
                self.prune_served();
            }
            Event::Latch { set } => self.alarm = set,
            Event::Fill { frontier } => self.fill_frontier = frontier,
            Event::Deadline { session, request } => self.on_deadline(session, request),
            Event::Headers { session, bytes } => {
                self.on_headers(main, session, &bytes, now, out)?
            }
            Event::Bodies { session, bytes } => self.on_bodies(session, &bytes, out),
            Event::Proven { job, results } => self.on_proven(main, job, &results, out)?,
            Event::Entry { tag, outcome } => self.on_entry(main, tag, outcome, now, out)?,
            Event::Room { seats } => self.on_room(seats, out),
            Event::Announce { session, body } => self.on_announce(main, session, &body, out)?,
        }
        let after = self.state();
        if after != before {
            out.push(Command::Publish { state: after });
        }
        if after == SyncState::Synced && before != SyncState::Synced {
            self.complement(rng, out);
        }
        self.alarm_from_tree(out);
        // A header response only records an evidence candidate. The draw
        // waits for the next event, so two responses can both be waiting
        // and the draw is over that set, not over whichever arrived first.
        if !header_response {
            self.start_evidence(rng, now, out);
        }
        self.plan(main, now, rng, out)?;
        self.plan_bodies(now, out);
        Ok(())
    }

    /// The fill's checkpoint. Genesis, because [`Trust`] has only the full
    /// posture until slice 6: there is no pinned checkpoint short of
    /// genesis for the fill to descend to.
    const fn checkpoint() -> BlockHeight {
        BlockHeight::ZERO
    }

    /// Read the main chain's work. `Err` is the view's fault and is
    /// returned. [`AtHeight::AboveTip`] is the view reporting that the
    /// height is not on the chain, which leaves the last observation.
    fn observe<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        at: Option<BlockHeight>,
    ) -> Result<(), H::Fault> {
        let Some(tip) = main.tip()? else {
            self.local = Some(Local {
                hash: BlockHash::NULL,
                height: None,
                work: CumulativeDifficulty::ZERO,
            });
            self.reselect(main)?;
            return Ok(());
        };
        let height = at.unwrap_or(tip.height);
        if let AtHeight::Recorded(record) = main.header_at(height)? {
            self.local = Some(Local {
                hash: record.hash,
                height: Some(height),
                work: record.cumulative_difficulty,
            });
            self.reselect(main)?;
        }
        Ok(())
    }

    pub(crate) fn reselect<'id, H: HeaderView<'id>>(&mut self, main: &H) -> Result<(), H::Fault> {
        let Some(local) = self.local else {
            return Ok(());
        };
        let at = local
            .height
            .map_or(BlockHeight::ZERO, |height| height + BlockCount::ONE);
        let cap = (self.rules)(at).reorg_cap();
        let previous = self.star.hash;
        self.star =
            self.tree
                .select(main, Star::local(local.hash, local.work), local.height, cap)?;
        if self.star.hash != previous {
            self.header_request = None;
            for peer in self.peers.values_mut() {
                peer.span = None;
                peer.gates.body_excluded = false;
            }
        }
        Ok(())
    }

    fn complement(&self, rng: &mut impl RelayRng, out: &mut Vec<Command<K>>) {
        let peers: Vec<K> = self.peers.keys().copied().collect();
        let Some(session) = draw_one(rng, &peers) else {
            return;
        };
        out.push(Command::RequestComplement { session });
    }

    /// At most one header request extends `H*`. It goes to a session
    /// whose claim beats `H*`, drawn uniformly, and the next is drawn
    /// only after this one is answered and its headers are proven, late,
    /// or its session closes.
    fn plan<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        now: Instant,
        rng: &mut impl RelayRng,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if self.header_request.is_some() || self.local.is_none() {
            return Ok(());
        }
        // A reachable run still being proven moves `H*` when its proof
        // lands. A request drawn before then carries the old locator, and
        // the peer answers with the headers already waiting on that proof.
        if self.peers.values().any(|peer| {
            peer.run
                .as_ref()
                .is_some_and(crate::peer::Run::proving_toward_star)
        }) {
            return Ok(());
        }
        let sources: Vec<K> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                !peer.gates.header_quiet
                    && !peer.gates.past_cap_followed
                    && peer.follow_up.is_none()
                    && peer.claim.is_some_and(|claim| claim.work > self.star.work)
            })
            .map(|(session, _)| *session)
            .collect();
        let Some(session) = draw_one(rng, &sources) else {
            return Ok(());
        };
        let points = self.locator_points(main)?;
        let block_ids = locator(self.star_count(), |height| {
            Ok::<_, H::Fault>(
                points
                    .iter()
                    .find(|(at, _)| *at == height)
                    .map(|(_, hash)| *hash),
            )
        })?;
        let transit = self
            .peers
            .get(&session)
            .map(|peer| peer.transit)
            .unwrap_or_default();
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.header_request = Some(HeaderRequest {
            session,
            id,
            points,
        });
        out.push(Command::RequestHeaders {
            session,
            id,
            deadline: header_deadline(now, transit),
            request: RequestHeaders { block_ids },
        });
        Ok(())
    }

    /// The locator of `H*`. `locator` names the heights. A height on the
    /// branch is that branch's ancestor; a height at or below the fork is
    /// read from `main`.
    fn locator_points<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
    ) -> Result<Vec<(BlockHeight, BlockHash)>, H::Fault> {
        let star = self.star.hash;
        let in_tree = self.tree.contains(star);
        let mut points = Vec::new();
        for height in locator_heights(self.star_count()) {
            let hash = if in_tree {
                self.tree.ancestor_at(star, height)
            } else {
                None
            };
            let hash = match hash {
                Some(hash) => Some(hash),
                None => match main.header_at(height)? {
                    AtHeight::Recorded(record) => Some(record.hash),
                    AtHeight::AboveTip => None,
                },
            };
            if let Some(hash) = hash {
                points.push((height, hash));
            }
        }
        Ok(points)
    }

    fn star_count(&self) -> ChainCount {
        if let Some(height) = self.tree.connecting(self.star.hash) {
            return ChainCount::with_tip(height).unwrap_or(ChainCount::ZERO);
        }
        self.local
            .and_then(|local| local.height)
            .and_then(ChainCount::with_tip)
            .unwrap_or(ChainCount::ZERO)
    }
}

/// A refused hint, or the main view failing while the request is built.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError<E> {
    /// The claim cannot be a chain.
    Refused(PayloadRefused),
    /// The main view could not be read.
    View(E),
}

pub(crate) fn header_deadline(now: Instant, transit: Duration) -> Instant {
    let secs = HEADERS_RESPONSE_BYTES / SYNC_RATE_FLOOR;
    now.checked_add(transit.saturating_add(Duration::from_secs(secs)))
        .unwrap_or(now)
}

/// A body deadline is the body budget at [`SYNC_RATE_FLOOR`].
pub(crate) fn body_deadline(now: Instant, transit: Duration) -> Instant {
    let secs = BODIES_RESPONSE_BYTES / SYNC_RATE_FLOOR;
    now.checked_add(transit.saturating_add(Duration::from_secs(secs)))
        .unwrap_or(now)
}

/// One uniform draw. `None` when `items` is empty.
pub(crate) fn draw_one<T: Copy>(rng: &mut impl RelayRng, items: &[T]) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let last = u64::try_from(items.len() - 1).unwrap_or(u64::MAX);
    let index = usize::try_from(bounded_uniform(rng, last)).unwrap_or(0);
    items.get(index).copied()
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
