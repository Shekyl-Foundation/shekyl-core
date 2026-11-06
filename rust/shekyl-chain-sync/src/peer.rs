// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One peer's sync conversation.
//!
//! The coordinator ([`crate::model::Sync`]) decides whom to ask, how much
//! to ask for, and when this node is synced. This module is the other
//! machine: the phase of a single peer. A mode carries only the data that
//! mode uses, so a past-cap window cannot hold a proof and a slot's
//! withheld headers cannot exist on a run that joins `T`.
//!
//! The conversation is not one exclusive phase. A header run, that run's
//! follow-up request, a body span, and an unsolicited announce are
//! independent tracks, and a peer may hold more than one at once. What is
//! exclusive is the run's mode.
//!
//! The connector finishes the handshake and then emits `SessionOpened`.
//! There is no handshaking mode here. `Synced` is the coordinator's
//! derived state, not a peer's. A session that fails a universal rule is
//! removed; a missed deadline is not that failure.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use shekyl_chain_rules::{seed_height, FormAttempt, HeaderJudged, RuleSet, Target};
use shekyl_difficulty::{CumulativeDifficulty, SEEDHASH_EPOCH_LAG};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{BlockBody, PowBlob};

use crate::claim::PeerClaim;
use crate::model::{body_deadline, header_deadline, CachePlan};

/// What this peer has said about bodies, apart from any one run.
#[derive(Default)]
pub(crate) struct Inventory {
    /// The peer reported the block missing.
    pub unavailable: BTreeSet<BlockHash>,
    /// Held by the peer, past the body budget.
    pub deferred: BTreeSet<BlockHash>,
    /// Served as a skeleton while this node keeps the full bytes.
    pub skeleton: BTreeSet<BlockHash>,
}

/// Whether this session may be drawn to extend `H*`.
///
/// The holds are independent, and each releases on its own event. A new
/// claim releases all of them. A new `H*` releases the spent locator and
/// the missing seed: both were about that locator. A new seed window
/// releases only the seed. An unlinked body, or one past the cap, releases
/// the quiet hold and the spent locator so headers are asked for again; a
/// past-cap branch already followed stays followed.
#[derive(Clone, Copy, Default)]
pub(crate) struct HeaderDraw {
    /// Quieted until the claim changes.
    quiet: bool,
    /// One past-cap branch was followed. Released only by a new claim.
    past_cap: bool,
    /// The last request from this `H*` yielded nothing.
    spent: bool,
    /// The last response hashed under a seed the window did not hold.
    seed_absent: bool,
}

impl HeaderDraw {
    pub(crate) const fn open() -> Self {
        Self {
            quiet: false,
            past_cap: false,
            spent: false,
            seed_absent: false,
        }
    }

    /// Drawn for headers from the current `H*`.
    pub(crate) const fn eligible(self) -> bool {
        !self.quiet && !self.past_cap && !self.spent && !self.seed_absent
    }

    /// Header work from this `H*` is finished, for body planning.
    ///
    /// A missing seed is the window's fact, so the session may still serve
    /// bodies.
    pub(crate) const fn headers_finished(self) -> bool {
        self.quiet || self.past_cap || self.spent
    }

    /// One past-cap branch was already followed.
    pub(crate) const fn past_cap_followed(self) -> bool {
        self.past_cap
    }

    pub(crate) fn on_claim(&mut self) {
        *self = Self::open();
    }

    pub(crate) fn on_star(&mut self) {
        self.spent = false;
        self.seed_absent = false;
    }

    pub(crate) fn on_seeds(&mut self) {
        self.seed_absent = false;
    }

    /// Ask for headers again after an unlinked body or one past the cap.
    pub(crate) fn on_relocate(&mut self) {
        self.quiet = false;
        self.spent = false;
    }

    pub(crate) fn quiet(&mut self) {
        self.quiet = true;
    }

    pub(crate) fn followed_past_cap(&mut self) {
        self.past_cap = true;
    }

    pub(crate) fn spend(&mut self) {
        self.spent = true;
    }

    pub(crate) fn miss_seed(&mut self) {
        self.seed_absent = true;
    }
}

/// Whether this session is asked for bodies.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum BodySource {
    /// A source.
    #[default]
    Open,
    /// Missed a body deadline. A source again when `H*` changes.
    Excluded,
}

impl BodySource {
    pub(crate) const fn excluded(self) -> bool {
        matches!(self, Self::Excluded)
    }
}

/// The one evidence draw this session may take.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum EvidenceDraw {
    /// Not yet drawn.
    #[default]
    Available,
    /// Drawn. It is not drawn again.
    Spent,
}

impl EvidenceDraw {
    pub(crate) const fn available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Where this session's header answer stands for the opening.
///
/// A received response answers the opening once the run holds no header
/// still to prove. That is the run's cursor, read when the opening
/// settles, so it is not copied onto this state.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum HeaderReply {
    /// No header response has arrived, and the deadline has not passed.
    #[default]
    Waiting,
    /// A header response arrived.
    Received,
    /// The proof answered, or the header deadline passed.
    Resolved,
}

impl HeaderReply {
    /// Whether this reply has answered the opening.
    pub(crate) fn answers_opening(self, run: Option<&Run>) -> bool {
        match self {
            Self::Waiting => false,
            Self::Resolved => true,
            Self::Received => run.is_none_or(|run| run.chain.proven >= run.chain.checked.len()),
        }
    }
}

/// A header request, and the heights it named.
pub(crate) struct HeaderRequest<K> {
    pub session: K,
    pub id: u64,
    pub points: Vec<(BlockHeight, BlockHash)>,
    /// When it was sent. The response's rate is measured from here.
    pub sent: Instant,
    /// When its response is late: the header budget at
    /// [`crate::model::SYNC_RATE_FLOOR`] after the session's transit.
    pub deadline: Instant,
}

impl<K> HeaderRequest<K> {
    pub(crate) fn new(
        session: K,
        id: u64,
        points: Vec<(BlockHeight, BlockHash)>,
        now: Instant,
        transit: Duration,
    ) -> Self {
        Self {
            session,
            id,
            points,
            sent: now,
            deadline: header_deadline(now, transit),
        }
    }
}

/// The body span this peer is serving.
pub(crate) struct BodySpan {
    pub id: u64,
    pub hashes: Vec<BlockHash>,
    /// When it was sent. The response's rate is measured from here.
    pub sent: Instant,
    /// When its response is late: the body budget at
    /// [`crate::model::SYNC_RATE_FLOOR`] after the session's transit.
    pub deadline: Instant,
}

impl BodySpan {
    pub(crate) fn new(id: u64, hashes: Vec<BlockHash>, now: Instant, transit: Duration) -> Self {
        Self {
            id,
            hashes,
            sent: now,
            deadline: body_deadline(now, transit),
        }
    }
}

/// The rate a response of `bytes` arrived at, in bytes per second: from
/// its request's send to `now`. A response that took under a millisecond
/// is measured over one.
pub(crate) fn rate(bytes: usize, sent: Instant, now: Instant) -> u64 {
    let elapsed = now
        .saturating_duration_since(sent)
        .max(Duration::from_millis(1));
    let per_second = u128::try_from(bytes).unwrap_or(u128::MAX) * 1_000_000 / elapsed.as_micros();
    u64::try_from(per_second).unwrap_or(u64::MAX)
}

/// One CS-Q4(c) wait. `fork` is the shallowest parent height among the
/// runs that disputed `work(L)` when the first body past that fork was
/// about to be committed. `sessions` is that moment's set and does not
/// gain members later.
pub(crate) struct Dispute<K> {
    pub(crate) fork: BlockHeight,
    pub(crate) sessions: BTreeSet<K>,
}

/// An announce proving beside the header run. It does not replace the run.
pub(crate) struct Announced {
    pub job: u64,
    pub pow: PowBlob,
    pub seed: BlockHash,
    pub target: Target,
    pub rule: RuleSet,
    pub attempt: FormAttempt,
    pub body: BlockBody,
    /// The connecting height from the cheap check.
    pub height: BlockHeight,
}

/// A header this node has cheap-checked and not yet finished proving.
pub(crate) struct Checked {
    pub pow: PowBlob,
    pub hash: BlockHash,
    pub height: BlockHeight,
    pub work: shekyl_difficulty::CumulativeDifficulty,
    pub seed: BlockHash,
    pub target: Target,
    pub rule: RuleSet,
    pub header: shekyl_wire::BlockHeader,
}

/// The chain buffer every run mode shares. Proof and withheld headers
/// live on the mode, not here.
pub(crate) struct Chain {
    /// The header the run extends. Evidence re-requests from here when
    /// the cheap-check window no longer starts at the fork.
    pub parent: BlockHash,
    pub parent_height: BlockHeight,
    pub checked: Vec<Checked>,
    pub proven: usize,
    pub attempt: FormAttempt,
}

impl Chain {
    /// The index of the header at `height`, in O(1): `checked` is one
    /// chain, contiguous by height, so a height is its offset from the
    /// first header. `None` when the run does not hold that height.
    pub(crate) fn index_at(&self, height: BlockHeight) -> Option<usize> {
        crate::branch::count_pending_read();
        let first = self.checked.first()?.height.to_raw();
        let index = usize::try_from(height.to_raw().checked_sub(first)?).ok()?;
        (self.checked.get(index)?.height == height).then_some(index)
    }
}

/// The run's mode. The variants that hash carry the proof job. The
/// variants that withhold headers carry those headers.
pub(crate) enum Mode {
    /// In cap. A proved header joins `T`.
    Reachable {
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
    /// The long-run slot. Headers stay off `T` until they beat `H*`.
    Slot {
        /// Proved headers not yet admitted to `T`.
        held: Vec<HeaderJudged>,
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
    /// Verifying a prefix to compare with the slot holder.
    Challenging {
        /// Proved headers not yet admitted to `T`.
        held: Vec<HeaderJudged>,
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
    /// Past the reorg cap. The chain keeps its window and is not hashed.
    PastCap,
    /// Past the cap, heavier than the local chain, waiting for the one draw.
    EvidenceCandidate,
    /// The evidence check. A proved header joins `T`.
    Evidence {
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
}

/// How a header page meets the session's run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageFit {
    /// The page's first new header extends the run's tip.
    Continues,
    /// An evidence run keeps the branch it drew. The page is another chain.
    Aside,
    /// The page starts another chain, so the run it does not extend is replaced.
    Replaces,
}

/// What an accepted page on a reachable run asks the session to do.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// The chain ended short of its claim and short of `H*`.
    Unmet,
    /// The chain ended at or above its claim and short of `H*`.
    BelowStar,
    /// The window is full, short of `H*`, and not yet in the slot.
    FillSlot {
        /// The peer said the chain continues.
        more: bool,
    },
    /// The window beats `H*`, or it already holds the slot.
    Prove {
        /// The peer said the chain continues.
        more: bool,
    },
    /// The window still has room and does not yet beat `H*`.
    Continue {
        /// The peer said the chain continues.
        more: bool,
    },
}

/// One chain of headers a session served, above its parent (in `T` or on
/// main), and the mode that says what is done with them. A reachable
/// run's proven headers are also in `T`; it keeps them, so its chain runs
/// unbroken from the parent its view is based on.
pub(crate) struct Run {
    pub chain: Chain,
    mode: Mode,
}

impl Run {
    pub(crate) fn open(
        parent: BlockHash,
        parent_height: BlockHeight,
        checked: Vec<Checked>,
        past_cap: bool,
    ) -> Self {
        Self {
            chain: Chain {
                parent,
                parent_height,
                checked,
                proven: 0,
                attempt: FormAttempt::FIRST,
            },
            mode: if past_cap {
                Mode::PastCap
            } else {
                Mode::Reachable { proof: None }
            },
        }
    }

    pub(crate) fn past_cap(&self) -> bool {
        matches!(
            self.mode,
            Mode::PastCap | Mode::EvidenceCandidate | Mode::Evidence { .. }
        )
    }

    /// A reachable run with a proof in flight. The proof moves `H*` when it
    /// lands.
    pub(crate) fn proving_toward_star(&self) -> bool {
        matches!(self.mode, Mode::Reachable { proof: Some(_) })
    }

    /// A reachable run holding headers it is not hashing: a prefix that
    /// does not beat `H*`, kept only for its continuation.
    pub(crate) fn unhashed(&self) -> bool {
        matches!(self.mode, Mode::Reachable { proof: None })
            && self.chain.proven < self.chain.checked.len()
    }

    pub(crate) fn is_slot(&self) -> bool {
        matches!(self.mode, Mode::Slot { .. })
    }

    pub(crate) fn is_challenging(&self) -> bool {
        matches!(self.mode, Mode::Challenging { .. })
    }

    pub(crate) fn is_candidate(&self) -> bool {
        matches!(self.mode, Mode::EvidenceCandidate)
    }

    pub(crate) fn is_evidence(&self) -> bool {
        matches!(self.mode, Mode::Evidence { .. })
    }

    /// The cheap-check window no longer starts at the header after the
    /// fork. An evidence check cannot hash that suffix.
    pub(crate) fn omits_fork(&self) -> bool {
        self.chain.checked.first().is_some_and(|first| {
            first.height.to_raw() > self.chain.parent_height.to_raw().saturating_add(1)
        })
    }

    /// A proved header joins `T`. Slot and challenge headers join only
    /// once they beat `H*`. A past-cap window does not join.
    pub(crate) fn joins_tree(&self, beats_star: bool) -> bool {
        match self.mode {
            Mode::Reachable { .. } | Mode::Evidence { .. } => true,
            Mode::Slot { .. } | Mode::Challenging { .. } => beats_star,
            Mode::PastCap | Mode::EvidenceCandidate => false,
        }
    }

    /// How `base`, the parent of this page's first new header, meets the run.
    ///
    /// An evidence check proves the branch it drew. A page from another
    /// chain is set aside and the run stays. Any other run that the page
    /// does not extend is replaced.
    pub(crate) fn page_fit(&self, base: BlockHash) -> PageFit {
        let tip = self
            .chain
            .checked
            .last()
            .map_or(self.chain.parent, |checked| checked.hash);
        if tip == base {
            PageFit::Continues
        } else if self.is_evidence() {
            PageFit::Aside
        } else {
            PageFit::Replaces
        }
    }

    /// What this reachable page asks for, once its headers are on the run.
    ///
    /// A chain that ended short of `H*` is closed or spent before the slot
    /// is considered. A full window that is still short of `H*` enters the
    /// slot. A window that beats `H*`, or already holds the slot, is proved.
    pub(crate) fn reach(
        &self,
        more: bool,
        claim: Option<CumulativeDifficulty>,
        star: CumulativeDifficulty,
        budget: usize,
    ) -> Reach {
        let work = self
            .chain
            .checked
            .last()
            .map_or(CumulativeDifficulty::ZERO, |checked| checked.work);
        let beats = work > star;
        if !more {
            if claim.is_some_and(|claim| work < claim) && !beats {
                return Reach::Unmet;
            }
            if !beats {
                return Reach::BelowStar;
            }
        }
        if self.chain.checked.len() >= budget && !beats && !self.is_slot() {
            return Reach::FillSlot { more };
        }
        if beats || self.is_slot() {
            return Reach::Prove { more };
        }
        Reach::Continue { more }
    }

    /// The run's mode, as the view names it.
    pub(crate) const fn view_mode(&self) -> crate::view::SessionMode {
        use crate::view::SessionMode;
        match self.mode {
            Mode::Reachable { .. } => SessionMode::Reachable,
            Mode::Slot { .. } => SessionMode::Slot,
            Mode::Challenging { .. } => SessionMode::Challenging,
            Mode::PastCap => SessionMode::PastCap,
            Mode::EvidenceCandidate => SessionMode::EvidenceCandidate,
            Mode::Evidence { .. } => SessionMode::Evidence,
        }
    }

    pub(crate) fn proof(&self) -> Option<u64> {
        match self.mode {
            Mode::Reachable { proof }
            | Mode::Slot { proof, .. }
            | Mode::Challenging { proof, .. }
            | Mode::Evidence { proof } => proof,
            Mode::PastCap | Mode::EvidenceCandidate => None,
        }
    }

    /// Arm a proof. A window that is not hashed cannot carry one.
    pub(crate) fn arm_proof(&mut self, id: u64) -> bool {
        let slot = match &mut self.mode {
            Mode::Reachable { proof }
            | Mode::Slot { proof, .. }
            | Mode::Challenging { proof, .. }
            | Mode::Evidence { proof } => proof,
            Mode::PastCap | Mode::EvidenceCandidate => return false,
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(id);
        true
    }

    pub(crate) fn clear_proof(&mut self) {
        if let Some(slot) = self.proof_slot() {
            *slot = None;
        }
    }

    fn proof_slot(&mut self) -> Option<&mut Option<u64>> {
        match &mut self.mode {
            Mode::Reachable { proof }
            | Mode::Slot { proof, .. }
            | Mode::Challenging { proof, .. }
            | Mode::Evidence { proof } => Some(proof),
            Mode::PastCap | Mode::EvidenceCandidate => None,
        }
    }

    pub(crate) fn push_held(&mut self, header: HeaderJudged) {
        if let Some(held) = self.held_slot() {
            held.push(header);
        }
    }

    pub(crate) fn take_held(&mut self) -> Vec<HeaderJudged> {
        self.held_slot().map(std::mem::take).unwrap_or_default()
    }

    fn held_slot(&mut self) -> Option<&mut Vec<HeaderJudged>> {
        match &mut self.mode {
            Mode::Slot { held, .. } | Mode::Challenging { held, .. } => Some(held),
            _ => None,
        }
    }

    /// Past-cap is fork geometry and it sticks. A run that was hashing
    /// drops its proof: the window is not hashed until the evidence draw.
    pub(crate) fn adopt_geometry(&mut self, past_cap: bool) {
        if !past_cap || self.past_cap() {
            return;
        }
        self.mode = Mode::PastCap;
    }

    pub(crate) fn enter_slot(&mut self) {
        let proof = self.proof();
        let held = self.take_held();
        self.mode = Mode::Slot { held, proof };
    }

    pub(crate) fn enter_challenge(&mut self) {
        let proof = self.proof();
        let held = self.take_held();
        self.mode = Mode::Challenging { held, proof };
    }

    /// The slot moved to a challenger. Keep the proof; drop withheld headers.
    pub(crate) fn release_slot(&mut self) {
        let proof = self.proof();
        self.mode = Mode::Reachable { proof };
    }

    /// Heavier than the local chain, and still only a window.
    pub(crate) fn nominate(&mut self) {
        if matches!(self.mode, Mode::PastCap) {
            self.mode = Mode::EvidenceCandidate;
        }
    }

    pub(crate) fn begin_evidence(&mut self) {
        self.mode = Mode::Evidence { proof: None };
    }
}

/// `None` is an unearned seed. It is not hashed and not charged to the peer.
pub(crate) fn cache_for(run: &Run, index: usize) -> Option<CachePlan> {
    let checked = &run.chain.checked[index];
    // The evidence check's first seed is unearned: it is a block on our
    // chain, below the fork. Every header that still names it uses the
    // evidence cache. A later seed is earned on the branch.
    if run.is_evidence()
        && run
            .chain
            .checked
            .first()
            .is_some_and(|first| first.seed == checked.seed)
    {
        return Some(CachePlan::Evidence(checked.seed));
    }
    let on_main = match seed_height(checked.height) {
        None => true,
        Some(seed_at) => seed_at.to_raw() <= run.chain.parent_height.to_raw(),
    };
    if on_main {
        return Some(CachePlan::Main(checked.seed));
    }
    // A branch seed is earned once (CS-Q2 step 3): when the seed header
    // and the lag after it are proven, which is every header before the
    // first one that names the seed. The cache may then be built, and every
    // later header under that seed is hashed in the same job.
    let seed_at = seed_height(checked.height)?;
    let first_named = BlockHeight::from_raw(
        seed_at
            .to_raw()
            .saturating_add(SEEDHASH_EPOCH_LAG)
            .saturating_add(1),
    );
    let first_named = run.chain.index_at(first_named)?;
    (first_named <= run.chain.proven).then_some(CachePlan::Branch(checked.seed))
}

/// One open peer.
pub(crate) struct Peer<K> {
    pub transit: Duration,
    pub claim: Option<PeerClaim>,
    /// The highest block this peer has named.
    pub frontier: Option<(BlockHeight, BlockHash)>,
    /// Whether this session may be drawn to extend `H*`.
    pub draw: HeaderDraw,
    /// Whether this session is asked for bodies.
    pub bodies: BodySource,
    /// The one evidence draw this session may take.
    pub evidence: EvidenceDraw,
    pub inventory: Inventory,
    /// The header run. Absent when this peer is not extending a fork.
    pub run: Option<Run>,
    /// This peer's own header follow-up: the run's next locator, a
    /// relocate, or the headers asked for an announcement whose parent
    /// this node does not hold. One is in flight. The coordinator's one
    /// frontier request is not stored here.
    pub follow_up: Option<HeaderRequest<K>>,
    /// Ids of frontier requests to this peer that a new `H*` withdrew
    /// (`reselect`): their locator went stale before they were answered.
    /// Each is still owed its answer, which arrives in request order and
    /// is discarded unjudged, or passes its deadline. Ascending.
    pub withdrawn: Vec<u64>,
    /// The body span this peer is serving.
    pub span: Option<BodySpan>,
    /// Announces proving beside the run.
    pub announced: Vec<Announced>,
    /// The rate this peer's last header or body response arrived at, in
    /// bytes per second. `None` until one has.
    pub rate: Option<u64>,
    /// Where this session's header answer stands for the opening.
    pub reply: HeaderReply,
}

impl<K> Peer<K> {
    pub(crate) fn open(transit: Duration, claim: Option<PeerClaim>) -> Self {
        Self {
            transit,
            claim,
            frontier: None,
            draw: HeaderDraw::open(),
            bodies: BodySource::Open,
            evidence: EvidenceDraw::Available,
            inventory: Inventory::default(),
            run: None,
            follow_up: None,
            withdrawn: Vec::new(),
            span: None,
            announced: Vec::new(),
            rate: None,
            reply: HeaderReply::Waiting,
        }
    }
}
