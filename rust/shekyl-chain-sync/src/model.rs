// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The machine. One owner, no clock of its own, no store.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shekyl_chain_rules::{
    AtHeight, FormAttempt, FormedHeader, HeaderJudged, HeaderView, InvalidBlock, RuleSet, Target,
    Tip, Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_levin::{BodiesFormFault, RequestBodies, RequestHeaders, HEADERS_RESPONSE_BYTES};
use shekyl_peer_policy::SyncReply;
use shekyl_types::Timestamp;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};
use shekyl_wire::BlockBody;

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
/// deadline uses the same rate on the bytes the request asked for.
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

/// What the connector hands the model.
#[derive(Clone, Debug)]
pub enum Event<K> {
    /// A handshake completed. `transit` is the connector's declared transit.
    SessionOpened {
        /// The session.
        session: K,
        /// The connector's declared transit.
        transit: Duration,
    },
    /// The session is gone.
    SessionClosed {
        /// The session.
        session: K,
    },
    /// The local tip changed.
    Tip {
        /// The tip the connector observed.
        tip: Tip,
    },
    /// The store's `following_degraded` latch.
    Latch {
        /// Whether the latch is set.
        set: bool,
    },
    /// PDM-Q5's backward-fill frontier.
    Fill {
        /// The descending frontier.
        frontier: BlockHeight,
    },
    /// A header response, still encoded.
    Headers {
        /// The session.
        session: K,
        /// The payload bytes.
        bytes: Vec<u8>,
    },
    /// A body response, still encoded.
    Bodies {
        /// The session.
        session: K,
        /// The payload bytes.
        bytes: Vec<u8>,
    },
    /// The entry's reply for one offered arrival.
    Entry {
        /// The tag `Offer` named.
        tag: u64,
        /// The outcome, as [`SyncReply`].
        reply: SyncReply,
        /// The block.
        hash: BlockHash,
        /// Whether this node requested the body.
        solicited: bool,
        /// `Unlinked`'s missing parent. Null otherwise.
        at: BlockHash,
        /// `MissingBodies`' indices.
        indices: Vec<u64>,
        /// The refusal, when `reply` is a refusal.
        verdict: Option<InvalidBlock>,
    },
    /// How many arrivals the entry can take.
    Room {
        /// Seats free.
        seats: u32,
    },
    /// The header request's deadline passed.
    Deadline {
        /// The session the request was drawn for.
        session: K,
        /// The request id.
        request: u64,
    },
    /// An unsolicited block.
    Announce {
        /// The session.
        session: K,
        /// The block bytes.
        block: Vec<u8>,
        /// The listed bodies it carried.
        bodies: Vec<Vec<u8>>,
    },
    /// The executor's answer to a Prove command this model will issue.
    /// `job` is that command's job (§4.2). Matching it to a run, closing
    /// on [`Proved::Refused`], and re-planning a `Stale` with the fault's
    /// attempt are the run layer (§4.8).
    Proven {
        /// The job the `Prove` command named.
        job: Job,
        /// One outcome per item, in order.
        results: Vec<Proved>,
    },
}

/// The id of one Prove batch. The model mints it; `Proven` carries it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Job(u64);

impl Job {
    /// The id as a number. The edge for a test that builds a `Proven`.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

/// One item of a [`Event::Proven`] batch.
#[derive(Clone, Debug)]
pub enum Proved {
    /// `form_header` accepted the header.
    Formed(Box<FormedHeader>),
    /// `form_header` refused it. The run layer closes the supplier.
    Refused(InvalidBlock),
}

/// What the model asks the executor to do.
#[derive(Clone, Debug)]
pub enum Command<K> {
    /// The derived state changed.
    Publish {
        /// The new state.
        state: SyncState,
    },
    /// One header request extending `H*`. At most one is outstanding.
    RequestHeaders {
        /// The session drawn for this request.
        session: K,
        /// The sparse locator.
        request: RequestHeaders,
        /// When the response is late.
        deadline: Instant,
    },
    /// Bodies along `H*`.
    RequestBodies {
        /// The session.
        session: K,
        /// The span.
        request: RequestBodies,
        /// When the response is late.
        deadline: Instant,
    },
    /// Run `form_header` on each item, in order, and answer with `Proven`.
    Prove {
        /// The job `Proven` must carry.
        job: Job,
        /// Which hasher class.
        class: HashClass,
        /// Which cache the seed is hashed under.
        cache: CachePlan,
        /// The preimages, in chain order.
        items: Vec<ProveItem>,
    },
    /// Bound arrivals for the entry, in chain order.
    Offer {
        /// The contiguous run from `L + 1`.
        arrivals: Vec<BoundArrival<K>>,
    },
    /// The session failed a universal rule.
    Close {
        /// The session.
        session: K,
        /// The rule.
        cause: CloseCause,
    },
    /// A heavier chain forks past the cap. The connector writes the latch.
    RaiseAlarm {
        /// The fork point.
        fork_at: BlockHeight,
        /// The heavier tip.
        tip: BlockHash,
        /// Its work.
        work: CumulativeDifficulty,
    },
    /// The transition into `Synced`.
    RequestComplement {
        /// A session drawn uniformly.
        session: K,
    },
    /// An announced block connected.
    Relay {
        /// The block.
        hash: BlockHash,
    },
    /// An announce is missing transactions.
    RequestMissingTxs {
        /// The session.
        session: K,
        /// The block.
        block: BlockHash,
        /// The missing indices.
        indices: Vec<u64>,
    },
}

/// Which hasher class a [`Command::Prove`] runs under. The executor maps
/// these onto the budget. `Evidence` is named here; the class itself is
/// CS-3's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashClass {
    /// A header on a reachable run.
    HeaderPow,
    /// An unsolicited block.
    Unsolicited,
    /// The past-cap evidence check.
    Evidence,
}

/// Which cache one prove item's seed is hashed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePlan {
    /// On the main chain. The executor looks it up and never derives it.
    Main(BlockHash),
    /// Earned on the run's own branch. One branch seed at a time.
    Branch(BlockHash),
    /// The evidence check's first seed.
    Evidence(BlockHash),
}

/// One preimage the executor proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProveItem {
    /// The PoW preimage.
    pub pow: Vec<u8>,
    /// The seed the claim was formed under.
    pub seed: BlockHash,
    /// The target the claim was formed under.
    pub target: Target,
    /// Which attempt this is.
    pub attempt: FormAttempt,
    /// The rule set in force.
    pub rule_set: RuleSet,
}

/// One body bound to the header `T` holds, for the entry.
#[derive(Clone, Debug)]
pub struct BoundArrival<K> {
    /// The model's tag. `Entry` carries it back.
    pub tag: u64,
    /// The session that served the body.
    pub session: K,
    /// The header the proof accepted.
    pub header: HeaderJudged,
    /// The body bound to that header.
    pub body: BlockBody,
}

impl<K: PartialEq> PartialEq for Command<K> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Publish { state: a }, Self::Publish { state: b }) => a == b,
            (
                Self::RequestHeaders {
                    session: a,
                    request: b,
                    deadline: c,
                },
                Self::RequestHeaders {
                    session: d,
                    request: e,
                    deadline: f,
                },
            ) => a == d && b == e && c == f,
            (Self::RequestComplement { session: a }, Self::RequestComplement { session: b }) => {
                a == b
            }
            (
                Self::Close {
                    session: a,
                    cause: b,
                },
                Self::Close {
                    session: c,
                    cause: d,
                },
            ) => a == c && b == d,
            _ => false,
        }
    }
}

impl<K: Eq> Eq for Command<K> {}

/// Why a session is closed. Each variant is a universal rule the input
/// failed. A missed deadline is not one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseCause {
    /// The header payload did not decode.
    HeadersUndecodable,
    /// The header payload decoded and failed its form.
    HeadersForm,
    /// A cheap check or a proof refused the header.
    HeaderRefused(shekyl_chain_rules::CenRow),
    /// The header descends from one already marked invalid.
    InvalidAncestor,
    /// The peer said the chain ended below its claim.
    ClaimUnmet,
    /// The body payload did not decode.
    BodiesUndecodable,
    /// The body payload failed `check_form`.
    BodiesForm(BodiesFormFault),
    /// The body does not match the header.
    Bind(shekyl_chain_rules::CenRow),
    /// The entry refused the block the header commits to.
    BlockRefused(InvalidBlock),
    /// The body is larger than any valid block.
    Oversize,
}

/// The chain the model has observed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Local {
    pub(crate) hash: BlockHash,
    pub(crate) height: Option<BlockHeight>,
    pub(crate) work: CumulativeDifficulty,
}

/// One session. Its claim is a hint and is not read by [`Sync::state`].
pub(crate) struct Session<K> {
    pub transit: Duration,
    pub claim: Option<PeerClaim>,
    /// The highest block this session has named.
    pub frontier: Option<(BlockHeight, BlockHash)>,
    pub run: Option<crate::runs::Run>,
    /// Not asked for headers again until its claim changes.
    pub header_quiet: bool,
    /// Missed a body deadline. A source again when `H*` changes.
    pub body_excluded: bool,
    pub unavailable: std::collections::BTreeSet<BlockHash>,
    /// Held by the peer, past the body budget. Wanted again from any
    /// session that covers the hash.
    pub deferred: std::collections::BTreeSet<BlockHash>,
    /// Served as a skeleton while the node keeps the full bytes.
    /// Wanted again in full from another session. Not a fault.
    pub skeleton: std::collections::BTreeSet<BlockHash>,
    pub past_cap_followed: bool,
    pub evidence_used: bool,
    /// A header request for this session's own run, outside the `H*` draw.
    pub continuation: Option<crate::runs::HeaderRequest<K>>,
}

/// The sync model.
pub struct Sync<K, R> {
    pub(crate) sessions: BTreeMap<K, Session<K>>,
    /// A claim that arrived before its session opened.
    pub(crate) pending: BTreeMap<K, PeerClaim>,
    pub(crate) local: Option<Local>,
    pub(crate) tree: HeaderTree,
    /// `H*`: the local tip, or a heavier reachable tip in `T`.
    pub(crate) star: Star,
    /// The header request that extends `H*`, if one is out.
    pub(crate) header_request: Option<crate::runs::HeaderRequest<K>>,
    /// Body requests in flight.
    pub(crate) body_requests: Vec<crate::runs::BodyRequest<K>>,
    /// The session holding the long-run slot.
    pub(crate) slot: Option<K>,
    /// The evidence check in flight.
    pub(crate) evidence: Option<K>,
    pub(crate) next_id: u64,
    pub(crate) next_tag: u64,
    /// Seats the entry last reported. None until the first `Room`.
    pub(crate) seats: Option<u32>,
    /// Bound bodies waiting for a seat.
    pub(crate) held: Vec<BoundArrival<K>>,
    /// Offered arrivals waiting for the entry's reply, keyed by tag.
    pub(crate) outstanding: Vec<BoundArrival<K>>,
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
    /// [`Self::checkpoint`] is genesis. `rules` is the schedule: the
    /// reorg cap is the set in force at the connecting height.
    #[must_use]
    pub fn new(trust: Trust, rules: R) -> Self {
        Self {
            sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
            local: None,
            tree: HeaderTree::default(),
            star: Star::local(BlockHash::NULL, CumulativeDifficulty::ZERO),
            header_request: None,
            body_requests: Vec::new(),
            slot: None,
            evidence: None,
            next_id: 1,
            next_tag: 1,
            seats: None,
            held: Vec::new(),
            outstanding: Vec::new(),
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
    /// read from `main`.
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
        if let Some(open) = self.sessions.get_mut(&session) {
            let changed = open.claim != Some(claim);
            open.claim = Some(claim);
            if changed {
                open.header_quiet = false;
                open.past_cap_followed = false;
            }
        } else {
            self.pending.insert(session, claim);
        }
        self.plan(main, now, rng, out).map_err(ClaimError::View)?;
        Ok(())
    }

    /// The derived state. A claim's value is not an input.
    #[must_use]
    pub fn state(&self) -> SyncState {
        if self.sessions.is_empty() {
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

    /// The session holding the long-run slot.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn slot_session(&self) -> Option<K> {
        self.slot
    }

    /// Cheap-checked headers the session's run still holds.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn run_len(&self, session: K) -> usize {
        self.sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .map(|run| run.checked.len())
            .unwrap_or(0)
    }

    /// The session whose evidence check is in flight.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn evidence_session(&self) -> Option<K> {
        self.evidence
    }

    /// The run's cheap-checked headers, in order. A past-cap run keeps
    /// only its window, so this is that window.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn run_records(&self, session: K) -> Vec<shekyl_chain_rules::HeaderRecord> {
        self.sessions
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .map(|run| {
                run.checked
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
        self.sessions.get(&session).map(|s| s.transit)
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
                self.sessions.insert(
                    session,
                    Session {
                        transit,
                        claim,
                        frontier: None,
                        run: None,
                        header_quiet: false,
                        body_excluded: false,
                        unavailable: std::collections::BTreeSet::new(),
                        deferred: std::collections::BTreeSet::new(),
                        skeleton: std::collections::BTreeSet::new(),
                        past_cap_followed: false,
                        evidence_used: false,
                        continuation: None,
                    },
                );
                if self.local.is_none() {
                    self.observe(main, None)?;
                }
            }
            Event::SessionClosed { session } => {
                self.sessions.remove(&session);
                self.pending.remove(&session);
                if self
                    .header_request
                    .as_ref()
                    .is_some_and(|req| req.session == session)
                {
                    self.header_request = None;
                }
                self.body_requests.retain(|req| req.session != session);
                self.outstanding
                    .retain(|arrival| arrival.session != session);
                self.held.retain(|arrival| arrival.session != session);
                if self.slot == Some(session) {
                    self.slot = None;
                }
                if self.evidence == Some(session) {
                    self.evidence = None;
                }
            }
            Event::Tip { tip } => {
                self.observe(main, Some(tip.height))?;
                self.tree.connected(main, tip.height)?;
            }
            Event::Latch { set } => self.alarm = set,
            Event::Fill { frontier } => self.fill_frontier = frontier,
            Event::Deadline { session, request } => self.on_deadline(session, request),
            Event::Headers { session, bytes } => {
                self.on_headers(main, session, &bytes, now, out)?
            }
            Event::Bodies { session, bytes } => self.on_bodies(session, &bytes, out),
            Event::Proven { job, results } => self.on_proven(main, job, &results, out)?,
            Event::Entry {
                tag,
                reply,
                hash,
                solicited,
                at,
                indices,
                verdict,
            } => self.on_entry(
                main, tag, reply, hash, solicited, at, &indices, verdict, now, out,
            )?,
            Event::Room { seats } => self.on_room(seats, out),
            Event::Announce {
                session,
                block,
                bodies,
            } => self.on_announce(main, session, &block, &bodies, out)?,
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
            self.start_evidence(rng, out);
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
            self.body_requests.clear();
            for session in self.sessions.values_mut() {
                session.body_excluded = false;
            }
        }
        Ok(())
    }

    fn complement(&self, rng: &mut impl RelayRng, out: &mut Vec<Command<K>>) {
        let sessions: Vec<K> = self.sessions.keys().copied().collect();
        if sessions.is_empty() {
            return;
        }
        let last = u64::try_from(sessions.len() - 1).unwrap_or(u64::MAX);
        let index = usize::try_from(bounded_uniform(rng, last)).unwrap_or(0);
        let Some(session) = sessions.get(index).copied() else {
            return;
        };
        out.push(Command::RequestComplement { session });
    }

    /// At most one header request extends `H*`. It goes to a session
    /// whose claim beats `H*`, drawn uniformly, and the next is drawn
    /// only after this one is answered, late, or its session closes.
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
        let sources: Vec<K> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                !session.header_quiet
                    && !session.past_cap_followed
                    && session.continuation.is_none()
                    && session
                        .claim
                        .is_some_and(|claim| claim.work > self.star.work)
            })
            .map(|(session, _)| *session)
            .collect();
        if sources.is_empty() {
            return Ok(());
        }
        let last = u64::try_from(sources.len() - 1).unwrap_or(u64::MAX);
        let index = usize::try_from(bounded_uniform(rng, last)).unwrap_or(0);
        let Some(session) = sources.get(index).copied() else {
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
            .sessions
            .get(&session)
            .map(|session| session.transit)
            .unwrap_or_default();
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.header_request = Some(crate::runs::HeaderRequest {
            session,
            id,
            points,
        });
        out.push(Command::RequestHeaders {
            session,
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use core::num::NonZeroU128;

    use shekyl_chain_rules::{
        AtHeight, DifficultyRule, FakechainSchedule, HeaderRecord, HeaderView, RuleSet, Tip, Trust,
    };
    use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
    use shekyl_draw_rng::RelayRng;
    use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, ChainCount, CurveTreeRoot};
    use shekyl_wire::BlockHeader;

    use super::{Command, Event, Sync};
    use crate::{ClaimError, PayloadRefused, PeerClaim, SyncState};

    struct NoDraw;

    impl RelayRng for NoDraw {
        fn next_u64(&mut self) -> u64 {
            0
        }
    }

    struct Empty;

    impl HeaderView<'static> for Empty {
        type Fault = Infallible;

        fn tip(&self) -> Result<Option<Tip>, Infallible> {
            Ok(None)
        }

        fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
            Ok(AtHeight::AboveTip)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StoreDown;

    struct Faults;

    impl HeaderView<'static> for Faults {
        type Fault = StoreDown;

        fn tip(&self) -> Result<Option<Tip>, StoreDown> {
            Err(StoreDown)
        }

        fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreDown> {
            Err(StoreDown)
        }
    }

    fn issued(_: BlockHeight) -> RuleSet {
        RuleSet::GENESIS
    }

    fn open<R: Fn(BlockHeight) -> RuleSet>(
        sync: &mut Sync<u8, R>,
        session: u8,
    ) -> Vec<Command<u8>> {
        let mut out = Vec::new();
        sync.handle(
            Event::SessionOpened {
                session,
                transit: Duration::from_secs(30),
            },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        out
    }

    fn hint<R: Fn(BlockHeight) -> RuleSet>(
        sync: &mut Sync<u8, R>,
        peer: PeerClaim,
    ) -> Result<(), ClaimError<Infallible>> {
        let mut out = Vec::new();
        sync.claim(
            1,
            peer,
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
    }

    fn claim(count: u64, work: u128) -> PeerClaim {
        PeerClaim {
            count: ChainCount::from_raw(count),
            work: CumulativeDifficulty::from_raw(work),
        }
    }

    #[test]
    fn a_genesis_only_claim_is_admitted() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        // One block, target 1.
        assert_eq!(hint(&mut sync, claim(1, 1)), Ok(()));
        assert_eq!(sync.state(), SyncState::NoView);
    }

    #[test]
    fn a_block_count_of_zero_is_refused() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        assert_eq!(
            hint(&mut sync, claim(0, 1)),
            Err(ClaimError::Refused(PayloadRefused::Height))
        );
        assert_eq!(
            hint(&mut sync, claim(0, 0)),
            Err(ClaimError::Refused(PayloadRefused::Height))
        );
    }

    #[test]
    fn work_below_the_block_count_is_refused() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        assert_eq!(
            hint(&mut sync, claim(3, 2)),
            Err(ClaimError::Refused(PayloadRefused::Work))
        );
        assert_eq!(hint(&mut sync, claim(3, 3)), Ok(()));
    }

    /// Height 0 is target 1 under a fixed target, and each later block is
    /// the fixed target. That sum is an honest claim.
    #[test]
    fn a_regtest_fixed_target_admits_an_honest_claim() {
        let fixed = NonZeroU128::new(7).expect("7");
        let rules = RuleSet::fakechain(Some(fixed), FakechainSchedule::PRODUCTION);
        let DifficultyRule::Fixed(target) = rules.difficulty() else {
            panic!("the regtest set names a fixed target");
        };
        let per_block = target.difficulty().to_raw();
        assert_eq!(per_block, 7);
        let count = 3u64;
        // Block 0 is `Target::GENESIS_BLOCK` (1) under Fixed, as under
        // every rule set. The two blocks above it are the fixed target.
        let work = 1 + u128::from(count - 1) * per_block;
        assert!(
            work < GENESIS_DIFFICULTY,
            "this chain's work is the fixed targets, not the DAA constant"
        );
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        assert_eq!(hint(&mut sync, claim(count, work)), Ok(()));
    }

    #[test]
    fn a_claim_never_changes_the_state() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        let published = open(&mut sync, 1);
        assert!(published.iter().any(|command| matches!(
            command,
            Command::Publish {
                state: SyncState::Synced,
            }
        )));
        assert!(published
            .iter()
            .any(|command| matches!(command, Command::RequestComplement { session: 1 })));
        assert_eq!(sync.transit(1), Some(Duration::from_secs(30)));
        hint(&mut sync, claim(9_000, u128::MAX)).unwrap();
        assert_eq!(sync.state(), SyncState::Synced);
    }

    #[test]
    fn the_last_session_closing_returns_to_no_view() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        open(&mut sync, 1);
        open(&mut sync, 2);
        let mut out = Vec::new();
        sync.handle(
            Event::SessionClosed { session: 1 },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        assert!(out.is_empty(), "one session still has a view");
        sync.handle(
            Event::SessionClosed { session: 2 },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        assert_eq!(
            out,
            vec![Command::Publish {
                state: SyncState::NoView,
            }]
        );
    }

    #[test]
    fn a_short_fill_is_following_and_the_latch_does_not_withhold_synced() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        open(&mut sync, 1);
        let mut out = Vec::new();
        sync.handle(
            Event::Fill {
                frontier: BlockHeight::from_raw(4),
            },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        assert_eq!(
            sync.state(),
            SyncState::Following {
                verified_to: BlockHeight::from_raw(4),
            }
        );
        let published = out.len();
        sync.handle(
            Event::Latch { set: true },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        assert!(sync.alarm());
        assert_eq!(out.len(), published, "the latch is not the state");
        assert_eq!(
            sync.state(),
            SyncState::Following {
                verified_to: BlockHeight::from_raw(4),
            }
        );
        sync.handle(
            Event::Fill {
                frontier: BlockHeight::ZERO,
            },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        assert_eq!(sync.state(), SyncState::Synced);
    }

    #[test]
    fn a_store_fault_reaches_the_caller() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        let mut out = Vec::new();
        let fault = sync
            .handle(
                Event::SessionOpened {
                    session: 1,
                    transit: Duration::from_secs(1),
                },
                &Faults,
                std::time::Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect_err("tip's fault");
        assert_eq!(fault, StoreDown);
        assert!(out.is_empty(), "a failed read publishes nothing");

        struct HeaderFaults;
        impl HeaderView<'static> for HeaderFaults {
            type Fault = StoreDown;
            fn tip(&self) -> Result<Option<Tip>, StoreDown> {
                Ok(Some(Tip {
                    height: BlockHeight::from_raw(0),
                    hash: BlockHash::from_bytes([1; 32]),
                }))
            }
            fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreDown> {
                Err(StoreDown)
            }
        }
        let fault = sync
            .handle(
                Event::Tip {
                    tip: Tip {
                        height: BlockHeight::from_raw(0),
                        hash: BlockHash::from_bytes([1; 32]),
                    },
                },
                &HeaderFaults,
                std::time::Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect_err("header_at's fault");
        assert_eq!(fault, StoreDown);
        assert!(out.is_empty());
    }

    #[test]
    fn a_tip_is_read_from_the_chain() {
        struct One {
            work: CumulativeDifficulty,
        }

        impl HeaderView<'static> for One {
            type Fault = Infallible;

            fn tip(&self) -> Result<Option<Tip>, Infallible> {
                Ok(Some(Tip {
                    height: BlockHeight::from_raw(3),
                    hash: BlockHash::from_bytes([1; 32]),
                }))
            }

            fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
                if height != BlockHeight::from_raw(3) {
                    return Ok(AtHeight::AboveTip);
                }
                Ok(AtHeight::Recorded(HeaderRecord {
                    hash: BlockHash::from_bytes([1; 32]),
                    header: BlockHeader {
                        major_version: 1,
                        minor_version: 0,
                        timestamp: 1,
                        previous: BlockHash::from_bytes([0; 32]),
                        nonce: 0,
                        curve_tree_root: CurveTreeRoot::from_bytes([0; 32]),
                        attestation_root: AttestationRoot::from_bytes([0; 32]),
                    },
                    cumulative_difficulty: self.work,
                }))
            }
        }

        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        open(&mut sync, 1);
        let mut out = Vec::new();
        sync.handle(
            Event::Tip {
                tip: Tip {
                    height: BlockHeight::from_raw(3),
                    hash: BlockHash::from_bytes([1; 32]),
                },
            },
            &One {
                work: CumulativeDifficulty::from_raw(50),
            },
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        // The local chain is the best chain, so the state stays synced.
        assert!(out.is_empty());
        assert_eq!(sync.state(), SyncState::Synced);
    }

    /// One header request extends `H*`. A second source waits until that
    /// request's session closes, and then it is drawn.
    #[test]
    fn one_header_request_extends_the_frontier() {
        let mut sync = Sync::new(Trust::UNANCHORED, issued);
        open(&mut sync, 1);
        open(&mut sync, 2);
        let mut out = Vec::new();
        let mut rng = Words(vec![0, 0, 0]);
        sync.claim(
            1,
            claim(2, 2),
            &Empty,
            std::time::Instant::now(),
            &mut rng,
            &mut out,
        )
        .unwrap();
        assert_eq!(requests(&out), vec![1]);
        out.clear();
        sync.claim(
            2,
            claim(2, 3),
            &Empty,
            std::time::Instant::now(),
            &mut rng,
            &mut out,
        )
        .unwrap();
        assert!(requests(&out).is_empty(), "a request is already out");
        sync.handle(
            Event::SessionClosed { session: 1 },
            &Empty,
            std::time::Instant::now(),
            &mut rng,
            &mut out,
        )
        .unwrap();
        assert_eq!(requests(&out), vec![2]);
    }

    struct Words(Vec<u64>);

    impl RelayRng for Words {
        fn next_u64(&mut self) -> u64 {
            self.0.remove(0)
        }
    }

    fn requests(out: &[Command<u8>]) -> Vec<u8> {
        out.iter()
            .filter_map(|command| match command {
                Command::RequestHeaders { session, .. } => Some(*session),
                _ => None,
            })
            .collect()
    }
}
