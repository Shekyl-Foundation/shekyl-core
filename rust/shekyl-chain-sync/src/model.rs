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

use shekyl_chain_rules::{
    AtHeight, FormAttempt, FormedHeader, HeaderJudged, HeaderView, InvalidBlock, RuleSet, Target,
    Tip, Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_levin::{
    BodiesFormFault, RequestBodies, RequestHeaders, BODIES_RESPONSE_BYTES, HEADERS_RESPONSE_BYTES,
};
use shekyl_peer_policy::{Invalidate, SyncReply, SyncReplyAction};
use shekyl_types::Timestamp;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};
use shekyl_wire::BlockBody;

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
    /// The entry's reply for one offered arrival. The outcome names what
    /// happened. The arrival's session and hash are the outstanding tag's.
    Entry {
        /// The tag `Offer` named.
        tag: u64,
        /// What the entry reported.
        outcome: Outcome,
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
    /// An unsolicited block. It proves beside any header run on this
    /// session; it does not replace that run.
    Announce {
        /// The session.
        session: K,
        /// The block, its transactions, and its attestation witness.
        body: BlockBody,
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
    /// A [`CachePlan::Main`] seed is not in either cache slot. The executor
    /// looks a main seed up and never derives it (B2), so the header cannot
    /// be proven against this window. Not the peer's fault: the run is
    /// dropped and the session kept. A later header request fetches it
    /// again, against the window the tip has moved to by then. Dropping the
    /// run, not only the proof, is what stops the same plan being issued
    /// again on the same event.
    NotHeld,
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
        /// The id `Deadline` carries back. Minted from the same counter as a proof job.
        id: u64,
        /// The sparse locator.
        request: RequestHeaders,
        /// When the response is late.
        deadline: Instant,
    },
    /// Bodies along `H*`.
    RequestBodies {
        /// The session.
        session: K,
        /// The id `Deadline` carries back. Minted from the same counter as a proof job.
        id: u64,
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
        /// The contiguous run from the first header of `H*` not on main.
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
    /// A block connected as the new tip, and with it this node is not
    /// `Behind` (CS-Q2 step 7). It goes to every established session but
    /// the one that supplied it, whether it came as an announcement or
    /// was fetched by sync.
    Relay {
        /// The block.
        hash: BlockHash,
        /// The session that supplied it.
        from: K,
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
    /// The body came unasked, as an announcement: the entry charges it to
    /// the unsolicited share, and an oversize one does not invalidate its
    /// header.
    pub announced: bool,
}

/// What the entry did with one offered arrival.
///
/// A refusal carries the census row the entry named. The model does not
/// invent one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The block connected, at `height`. The model relays it when it is
    /// the new tip and the node, with it, is not `Behind`.
    Connected {
        /// The height the block took.
        height: BlockHeight,
    },
    /// The body matched its header, and the block was refused.
    Refused {
        /// The row the entry named.
        verdict: InvalidBlock,
    },
    /// A promotion of an already-stored block was refused.
    PromotionRefused {
        /// The row the entry named.
        verdict: InvalidBlock,
        /// The ancestor the switch refused. Not the arrival that triggered it.
        block: BlockHash,
    },
    /// Larger than any valid block.
    Oversize {
        /// A solicited body invalidates its header. An announce does not.
        invalidate: bool,
    },
    /// The parent chain reaches nothing this node holds.
    Unlinked {
        /// The missing parent.
        at: BlockHash,
    },
    /// Deeper than the cap. Nothing was stored.
    BeyondCap,
    /// An announced block is missing transactions.
    MissingBodies {
        /// The missing indices.
        indices: Vec<u64>,
    },
    /// Want the block again. The service cancelled or stopped.
    Again,
    /// The door had no room.
    NoRoom,
    /// An announce hit the unsolicited share.
    Throttled,
    /// Already held, stored beside the incumbent, switched, or unfollowable.
    Noted,
}

impl Outcome {
    /// CS-3's conversion from the entry's reply. A refusal that names no
    /// verdict is `None`: this model does not invent a census row.
    ///
    /// `height` is where a connected block went. `block` is the hash a
    /// promotion refusal names. CS-3 passes the entry's refused hash.
    /// Other replies read neither.
    #[must_use]
    pub fn from_reply(
        reply: SyncReply,
        solicited: bool,
        height: BlockHeight,
        at: BlockHash,
        block: BlockHash,
        indices: Vec<u64>,
        verdict: Option<InvalidBlock>,
    ) -> Option<Self> {
        match reply.action(solicited) {
            SyncReplyAction::Advance => Some(Self::Connected { height }),
            SyncReplyAction::Invalidate(Invalidate::Refused) => {
                verdict.map(|verdict| Self::Refused { verdict })
            }
            SyncReplyAction::Invalidate(Invalidate::PromotionRefused) => {
                verdict.map(|verdict| Self::PromotionRefused { verdict, block })
            }
            SyncReplyAction::Invalidate(Invalidate::Oversize { invalidate_header }) => {
                Some(Self::Oversize {
                    invalidate: invalidate_header,
                })
            }
            SyncReplyAction::Relocate => Some(Self::Unlinked { at }),
            SyncReplyAction::RequestHeaders => Some(Self::BeyondCap),
            SyncReplyAction::RequestMissing => Some(Self::MissingBodies { indices }),
            SyncReplyAction::Again => Some(Self::Again),
            SyncReplyAction::Hold => Some(Self::NoRoom),
            SyncReplyAction::DropUnverified => Some(Self::Throttled),
            SyncReplyAction::None => Some(Self::Noted),
        }
    }
}

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
    /// Bound bodies waiting for a seat.
    pub(crate) held: crate::arrivals::Held<K>,
    /// Offered arrivals waiting for the entry's reply, keyed by tag.
    pub(crate) outstanding: crate::arrivals::Offered<K>,
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
            held: crate::arrivals::Held::new(),
            outstanding: crate::arrivals::Offered::new(),
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
        self.state_at(local)
    }

    /// The state with `local` as the local tip.
    fn state_at(&self, local: Local) -> SyncState {
        if self.star.work > local.work {
            return SyncState::Behind {
                have: local.work,
                best: self.star.work,
                target: self.star_count(),
            };
        }
        if self.fill_frontier > Self::checkpoint() {
            return SyncState::Following {
                verified_to: self.fill_frontier,
            };
        }
        SyncState::Synced
    }

    /// Whether a block that connected at `height` is relayed (CS-Q2 step
    /// 7, amended 2026-10-24). It is when it connected as the new tip, not
    /// beneath the local tip this model has seen, and when this node, with
    /// it as the local tip, is not `Behind`. How the block arrived does not
    /// enter: an announcement and a block fetched by sync are relayed
    /// alike, and nothing is relayed while the node is behind. The state is
    /// judged as of the connect, so a synced node that fetches the next
    /// block, and is behind by that block until it connects, relays it.
    pub(crate) fn relays(
        &self,
        hash: BlockHash,
        height: BlockHeight,
        work: CumulativeDifficulty,
    ) -> bool {
        let beneath = self
            .local
            .and_then(|local| local.height)
            .is_some_and(|tip| height < tip);
        let with_it = Local {
            hash,
            height: Some(height),
            work,
        };
        !beneath && !matches!(self.state_at(with_it), SyncState::Behind { .. })
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

    /// The record `T` holds for `hash`.
    #[cfg(test)]
    pub(crate) fn header_record(
        &self,
        hash: BlockHash,
    ) -> Option<shekyl_chain_rules::HeaderRecord> {
        self.tree.record(hash)
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
