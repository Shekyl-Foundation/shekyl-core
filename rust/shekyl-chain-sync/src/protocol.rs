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
    /// the one that supplied it, however it arrived.
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
    /// The witness beside the block. Empty when the set is empty.
    pub attestation_witness: Vec<u8>,
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
            attestation_witness: body.attestation_witness.clone(),
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
    /// The door had no room.
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
