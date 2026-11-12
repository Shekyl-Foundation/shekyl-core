// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The conversation between the connector and the coordinator.
//!
//! Events come in. Commands go out. The types here name that
//! conversation and nothing else: no clock, no store, no peer map.
//! [`crate::model::Sync`] is the machine that turns one into the other.

use std::time::{Duration, Instant};

use shekyl_chain_rules::{
    FormAttempt, FormedHeader, HeaderJudged, InvalidBlock, RuleSet, Target, Tip,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_levin::{BodiesFormFault, RequestBodies, RequestHeaders};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{BlockBody, TxBody};

use crate::state::SyncState;

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
    /// The latch write a [`Command::RaiseAlarm`] asked for was refused.
    /// The model retries it after [`ALARM_RETRY`](crate::ALARM_RETRY).
    AlarmRefused,
    /// The retry deadline [`Command::ArmAlarmRetry`] armed has passed.
    AlarmRetry,
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
    /// The ingest window's cache slots changed: a seed they did not hold
    /// may be held now. A session whose headers could not be proven for
    /// that reason ([`Proved::NotHeld`]) is drawn again.
    Seeds,
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
        /// The block, its transactions, and its bundle references.
        body: BlockBody,
    },
    /// A session's 2017: its answer to a 2016 the owner sent it for a block
    /// awaiting bundle bodies ([`Command::RequestBundleBodies`]). Each body
    /// is already held to the reference it answers (length and hash, §7.5).
    /// Empty when the session answered with nothing.
    BundleBodies {
        /// The session that answered.
        session: K,
        /// The block awaiting them.
        block: BlockHash,
        /// The bodies, encoded.
        bodies: Vec<Vec<u8>>,
    },
    /// What this node's body store held of a
    /// [`Command::RequestBundleBodies`], read when the owner took it. Not
    /// the session's answer: that is [`Event::BundleBodies`], and follows
    /// only when `asked`.
    HeldBundleBodies {
        /// The session the command named.
        session: K,
        /// The block awaiting them.
        block: BlockHash,
        /// The bodies the store held, encoded. May be empty.
        bodies: Vec<Vec<u8>>,
        /// Whether the rest went to `session` as a 2016. `false` when the
        /// store held every body, or the session was gone.
        asked: bool,
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
    /// dropped and the session kept, closed to header draws until the
    /// slots change ([`Event::Seeds`]), when the next header request
    /// fetches the headers again against the window as it stands then.
    /// Dropping the run, not only the proof, is what stops the same plan
    /// being issued again on the same event.
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
    /// Wake the model at `deadline` with `Event::Deadline { session, request:
    /// id }`: the opening's bound, the first session's header deadline
    /// (CS-Q2 step 8). It fires whether or not `session` is still open.
    ArmOpening {
        /// The session the opening started with.
        session: K,
        /// The id `Deadline` carries back.
        id: u64,
        /// The first session's header deadline.
        deadline: Instant,
    },
    /// Wake the model at `deadline` with `Event::Deadline { session, request:
    /// id }` for the evidence draw. A header response records a candidate
    /// and does not draw, so responses arriving together are drawn over as
    /// a set; the wake is the draw's bound when nothing else arrives (the
    /// §10 partition regtest: a node whose one peer served its heavier chain
    /// and then went quiet never began the check). One is armed at a time.
    ArmDraw {
        /// The session whose response recorded the candidate.
        session: K,
        /// The id `Deadline` carries back.
        id: u64,
        /// That session's declared transit from the response: a response
        /// another session is sending to a request of the same round is
        /// about that far away.
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
    /// Wake the model at `deadline` with [`Event::AlarmRetry`]: the retry of
    /// a refused latch write.
    ArmAlarmRetry {
        /// When to retry.
        deadline: Instant,
    },
    /// A heavier chain forks past the cap. The connector writes the latch.
    /// A refused write comes back as [`Event::AlarmRefused`]; the written
    /// latch comes back as [`Event::Latch`].
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
    /// the one that supplied it, however it arrived.
    Relay {
        /// The block.
        hash: BlockHash,
        /// The session that supplied it. `None` is a tip no session
        /// supplied, such as a block this node mined: it goes to every
        /// established session.
        from: Option<K>,
    },
    /// A block's section names bundle bodies this node was not sent (2016).
    /// The owner answers what its body store holds
    /// ([`Event::HeldBundleBodies`]) and asks `session` for the rest, whose
    /// answer is [`Event::BundleBodies`].
    RequestBundleBodies {
        /// The session that sent the block.
        session: K,
        /// The block awaiting the bodies.
        block: BlockHash,
        /// The references whose bodies were not sent, undecoded.
        references: Vec<Vec<u8>>,
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
    /// This session's headers from `H*` yielded nothing, and it is not
    /// drawn to extend `H*` again until its claim or `H*` changes. A
    /// record: the owner logs it, and nothing is sent.
    HeadersSpent {
        /// The session.
        session: K,
        /// What the response, or its proof, came to.
        cause: Spent,
    },
    /// This session's headers could not be proven: the cache for `seed`
    /// was in neither of the ingest window's slots ([`Proved::NotHeld`]).
    /// The run is dropped and the session is not drawn for headers until
    /// the slots change ([`Event::Seeds`]). A record: the owner logs it,
    /// and nothing is sent. The owner also reads the window it holds: a
    /// pair that holds `seed` by the time this command is handled was
    /// published between the lookup and now, and its change event may
    /// already have passed, so the owner raises [`Event::Seeds`] at the
    /// end of the batch.
    SeedNotHeld {
        /// The session.
        session: K,
        /// The seed the slots did not hold.
        seed: BlockHash,
    },
}

/// Why a session's headers from `H*` yielded nothing
/// ([`Command::HeadersSpent`]). Each is an answer that asking again, from
/// the same `H*`, would repeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spent {
    /// The response named no header `T` lacked, and the peer said its
    /// chain ends there.
    Exhausted,
    /// The run ended, at the peer's word, without beating `H*`.
    BelowStar,
    /// The headers could not be judged where they were placed: the view
    /// moved under them, or the run's own record did not line up.
    Stale,
    /// The run's headers were gone when the proof answered.
    Gone,
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

/// A body offered to the entry. Every transaction is full.
///
/// A skeleton is not an offer. The run records the hash and the body is
/// asked for again in full. [`Self::from_full`] is `None` when any
/// transaction is a skeleton, so an offer cannot carry one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedBody {
    /// The block blob.
    pub block: Vec<u8>,
    /// Listed transactions, whole encodings, in the block's order.
    pub txs: Vec<Vec<u8>>,
    /// The bundle references beside the block, undecoded. Empty when the
    /// block admits no bundle.
    pub bundle_references: Vec<Vec<u8>>,
    /// The bodies of those bundles the sender carried, unverified and in no
    /// set order. Assembly matches each to its reference by hash.
    pub bundle_bodies: Vec<Vec<u8>>,
}

impl OfferedBody {
    /// `body`, when every transaction is full.
    #[must_use]
    pub fn from_full(body: &BlockBody) -> Option<Self> {
        let mut txs = Vec::with_capacity(body.txs.len());
        for tx in &body.txs {
            match tx {
                TxBody::Full(bytes) => txs.push(bytes.clone()),
                TxBody::Skeleton(_) => return None,
            }
        }
        Some(Self {
            block: body.block.clone(),
            txs,
            bundle_references: body.bundle_references.clone(),
            bundle_bodies: body.bundle_bodies.clone(),
        })
    }
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
    /// The body bound to that header. Every transaction is full.
    pub body: OfferedBody,
    /// A body this node requested. An announcement is not.
    pub solicited: bool,
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
    /// The door had no room. The model holds the body and spends nothing
    /// until the next [`Event::Room`], which the owner owes after every
    /// `NoRoom` whether or not the door's count moved (2026-11-02: a count
    /// the owner thought unchanged was never re-reported, and a node sat
    /// `behind` for good with its seats frozen).
    NoRoom,
    /// The entry could not read the store that bounds an arrival. The
    /// body is not held and not asked for again. The peer did not fail.
    StoreUnreadable,
    /// An announce hit the unsolicited share.
    Throttled,
    /// Already held, stored beside the incumbent, or unfollowable. A
    /// switch whose new tip is some other block is this too: the owner
    /// translates that reply before the model sees it.
    Noted,
}

/// Which form rule a decoded header page failed. A page is a chain of
/// headers hanging off one hash the request located; each variant is a
/// way it can fail to be that. The close names the rule so a page that
/// comes back the same way on every retry says why (2026-11-03: the
/// three-miner rehearsal closed 47 sessions at `HeadersForm` and the
/// log could not say which rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadersFormFault {
    /// No headers, and the peer says more follow.
    EmptyWithMore,
    /// A header blob did not read as a proof-of-work blob.
    BlobUnreadable,
    /// The first header's parent is not a hash this session's open
    /// request located.
    ParentUnrequested,
    /// A header's parent is not the header before it.
    Linkage,
    /// The first header's parent is located and `T` does not place it.
    ParentUnplaced,
    /// A header this node holds follows one it does not: a chain
    /// rejoining what it left.
    HeldAfterNew,
}

/// Why a session is closed. Each variant is a universal rule the input
/// failed. A missed deadline is not one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseCause {
    /// The header payload did not decode.
    HeadersUndecodable,
    /// The header payload decoded and failed its form.
    HeadersForm(HeadersFormFault),
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
    /// The session announced a block and answered the 2016 for its bundle
    /// bodies with nothing. A relayer serves the bodies of the blocks it
    /// relays (`SCS-P27`), so the session is withholding them.
    BundleBodiesWithheld,
}
