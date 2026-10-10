// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`SyncedChainFacts`] — chain facts the wallet may act on, because the
//! daemon that answered them says it is synchronized (`WALLET_SIDE_STORE.md`
//! `WSS-Q14`, ruled 2026-09-19; the defect it closes is `WSS-25`).
//!
//! # Why a type and not a call-site check
//!
//! Steering's `R-B`: *every consensus-derived decision reads the configured
//! daemon, and while it reports syncing the answer is **unknown**, failing
//! safe — do not erase, post or sign.* A rule of that shape enforced by
//! call-site checks is enforced nowhere in particular: the check is invisible
//! at the signature, a new consumer inherits nothing, and its absence is what
//! `WSS-25` found — the serve-set release gate derived settlement epochs from
//! the height a bond record answered at, with no synchronization check
//! anywhere in the call chain.
//!
//! So "synced" is a **value you must hold**, not a question you are trusted to
//! ask. A function that needs a synchronized view takes `&SyncedChainFacts`;
//! there is no constructor that yields one from an unsynchronized reading, so
//! the unsynced path is a compile error rather than a missing branch. Deleting
//! the operand does not silently restore the old behaviour — it stops
//! compiling, which is what `50-testing`'s *"name the edit that makes this
//! red"* asks of a check that guards a destructive verb.
//!
//! # The predicate, and where it came from
//!
//! ```text
//! synchronized && (target_height == 0 || height >= target_height)
//! ```
//!
//! The predicate has **one site**, [`daemon_reports_synchronized`]. This
//! constructor calls it and adds chain identity; the submit watchdog's
//! `DaemonHealthContext::is_synced` calls it and adds nothing, because the
//! escape ladder needs a boolean and holds no identity to build the type
//! with. Neither derives the predicate, so a change to what "synced" means
//! cannot leave the ladder and the release gate disagreeing. Its
//! **height half** is the watchdog's own — `is_synced` was, until this type
//! landed, the only honest reading of sync state in the wallet — and the
//! `synchronized` half is what that reading lacked.
//!
//! **The predicate is ours; the C++ is provenance, not authority.** What the
//! conjunction is doing is absorbing the *shape of the response it consumes*.
//! This constructor reads `get_info`. The method is served from Rust since
//! RK-5c, at parity with the inherited handler it replaced, so the shape it
//! answers with is still the inherited one. That surface
//! encodes sync state twice: a `synchronized` bool, the protocol's own
//! predicate, **and** a `target_height` overloaded with a zero sentinel —
//! `0` when synchronized, the core's target otherwise. Both are written by
//! the daemon's `get_info` method (`rust/shekyl-daemon-rpc/src/info.rs`,
//! which keeps the sentinel until RK-D15's commit retires it). That is what
//! the guide *does*; it does not define what we require.
//!
//! We require both fields because, on that shape, **neither alone is
//! sufficient**. A daemon that has just started with no peers reports
//! `target_height == 0` — the sentinel that *means* synchronized — while
//! `synchronized` is false and its height is genesis-adjacent. That is
//! exactly `WSS-25`'s state: a rebuilt database, before the node has anyone
//! to catch up from. Reading only the sentinel mints facts for it. Reading
//! only the flag accepts a node that contradicts itself by sitting below its
//! own target. Absent on the wire, the flag reads `false` — the direction
//! that refuses.
//!
//! **This is a seam, and it simplifies when the producer moves.** The Rust
//! contract already models this correctly — `shekyl-daemon-rpc`'s `ChainTip`
//! (`chain_facts.rs`) carries a raw `target_height` and a separate
//! `synchronized` bool, and its own doc disclaims the zero sentinel as "the
//! handler's". The sentinel survives only at the wire boundary, and only
//! until the p2p layer migrates. When `get_info` gains a Rust handler over
//! `ChainTip`, the sentinel arm has nothing left to absorb and this
//! conjunction collapses to the flag. Until then a reader should not have to
//! re-derive why both fields are read: it is the guide's shape, not our
//! contract's.
//!
//! The `synchronized` half is the `WSS-24` lane's finding (PR #791), which
//! derived the same predicate independently and found the gap; `WSS-Q14`'s
//! brief said to lift the watchdog's form verbatim, and verbatim was not
//! enough. #791 landed first, with its own copy of the conjunction in the
//! anchor gate's daemon-tip reading (`stake_engine/serving/daemon_tip.rs`);
//! this PR landed second and converged it, as both lanes' docs had
//! committed: that reading decodes through [`health_from_get_info`] and takes
//! its verdict from [`daemon_reports_synchronized`].
//!
//! # The `R1` seam
//!
//! The type is wallet-side and is built from the engine's daemon client. A
//! DRS change to the daemon's chain-facts response shape lands in
//! [`health_from_get_info`], [`top_hash_from_get_info`] and
//! [`fetch_synced_chain_facts`], which read the shared
//! [`GetInfoResponse`] — the one definition of the reply, in
//! `shekyl-rpc-types` — and nowhere else. Every consumer holds the type,
//! not the response.
//!
//! # Units
//!
//! `get_info.height` is the block **count**, not the tip height:
//! the daemon reads the top block's height and reports one more, the
//! chain's length. It is
//! therefore the same quantity as [`EmissionClaimSource::chain_height`]
//! (`crate::engine::emission_source`), and it is stored here as a [`ChainCount`] so
//! the count/height confusion cannot be made by a consumer. Consumers that
//! want the newest existing block's height take [`SyncedChainFacts::tip`].

#[cfg(test)]
use serde_json::Value;
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::GetInfoResponse;
use shekyl_types::{BlockHash, BlockHeight, ChainCount};

use crate::engine::traits::daemon::DaemonHealth;

/// Chain facts from a daemon that reports itself synchronized.
///
/// Holding one is the proof — there is no other way to obtain it, and no way
/// to obtain it from a syncing daemon. See the module docs for why this is a
/// type rather than a check.
///
/// # What it does *not* prove
///
/// **It is the daemon's own claim, not an independent measurement.** Under the
/// V3.0 own-daemon deployment model that claim is trusted; under a
/// multi-daemon reopen it is not, and a daemon lying "synchronized" can hand a
/// wallet a stale view (the same trust classification the watchdog's health
/// context carries — `DAEMON_SUBMIT_VERDICT.md` §7.2). This type closes the
/// *honest-resync* hazard `WSS-25` describes, whose adversary is nobody; it is
/// not an authentication of the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyncedChainFacts {
    /// The daemon's block count at the moment it reported synchronized.
    chain_height: ChainCount,
    /// The hash of the newest block at that moment — **which** chain the
    /// count is a count of.
    ///
    /// A height alone is not an identity: two branches share every height
    /// below their fork, so a ledger that carried observations across
    /// refreshes on heights alone could not tell a reorg-and-catch-up from
    /// ordinary advance. This is the fact that makes the difference
    /// observable, and it is read from the same `get_info` reply as the
    /// count, so it costs nothing.
    top_hash: BlockHash,
}

impl SyncedChainFacts {
    /// The sole constructor: chain facts **iff** the daemon reports
    /// synchronized, otherwise `None`.
    ///
    /// `chain_height` is the response's block count, `target_height` its
    /// network estimate under the *"0 when synchronized"* convention,
    /// `synchronized` its own word, and `top_hash` the identity of the chain
    /// the count belongs to. All four come from one response — do not pair a
    /// height from one read with a target or a hash from another, which is
    /// why this takes them together rather than offering a setter.
    ///
    /// `None` is not an error. It is the `R-B` answer: while the daemon
    /// reports syncing, consensus-derived facts are **unknown**, and a caller
    /// that cannot proceed without them declines to act rather than acting on
    /// a view it cannot vouch for.
    pub(crate) fn new(
        chain_height: ChainCount,
        target_height: u64,
        synchronized: bool,
        top_hash: BlockHash,
    ) -> Option<Self> {
        daemon_reports_synchronized(chain_height, target_height, synchronized).then_some(Self {
            chain_height,
            top_hash,
        })
    }

    /// Build from the engine's [`DaemonHealth`] projection of `get_info`.
    ///
    /// The connection count is deliberately not carried: peerlessness is the
    /// watchdog's escalation axis, not a synchronization fact, and a type
    /// named for one property that silently carries another is how a consumer
    /// comes to read the wrong one.
    pub(crate) fn from_health(health: DaemonHealth, top_hash: BlockHash) -> Option<Self> {
        Self::new(
            ChainCount::from_raw(health.height),
            health.target_height,
            health.synchronized,
            top_hash,
        )
    }

    /// The hash of the newest block at the moment the daemon reported
    /// synchronized — the identity of the chain this count belongs to.
    pub(crate) fn top_hash(&self) -> BlockHash {
        self.top_hash
    }

    /// The daemon's block **count** — one more than the newest block's height.
    ///
    /// Exists for one caller: `daemon_claimed_tip`, which returns this
    /// [`ChainCount`] as the dispatch clock. The number is the Phase 1 pin
    /// (a 3-block chain reports 3); flipping to [`Self::tip`] would move
    /// every stamp down by one block. Prefer [`Self::tip`] when the
    /// consumer wants an ordinal — a consumer that wants a height and
    /// reaches for this is reintroducing the confusion the type exists to
    /// prevent.
    pub(crate) fn chain_height(&self) -> ChainCount {
        self.chain_height
    }

    /// The newest existing block's height, or `0` on an empty chain.
    ///
    /// The `0` for an empty chain matches how `EngineServeSetPinner`
    /// already stamps a `PinReport`: an empty chain has no tip, and every
    /// consumer of this value is doing elapsed-block arithmetic in which
    /// "no blocks yet" and "block zero" are the same answer.
    pub(crate) fn tip(&self) -> BlockHeight {
        tip_of(self.chain_height)
    }

    /// Confirm this witness **after** the read it vouches for, by the hash
    /// the chain reports *now* at the witness tip.
    ///
    /// A witness read before a record proves only that the daemon was
    /// synchronized before the record was gathered. It does not prove the
    /// record was gathered on the chain the witness described: a reorg can
    /// begin after `get_info`, replace the witness-tip block, and catch back
    /// up **above** that height before the record reply, and no relation
    /// between the two *heights* can see it — `record_tip >= witness_tip`
    /// reads as ordinary advance. Re-reading the block at the witness tip
    /// once the record is in hand closes that: if it is the same block
    /// before and after, the record was gathered between two identical views
    /// of it — the same-hash-same-block argument, sound for identity at that
    /// height.
    ///
    /// The re-read is at the witness **height**, not at the tip: the tip may
    /// have honestly advanced during the record read, and a tip-to-tip
    /// comparison would refuse every such refresh while proving nothing.
    ///
    /// # What the bracket does not prove
    ///
    /// It bounds the window; it does not make the reads atomic. A chain that
    /// leaves the witness block and returns to it inside the window is not
    /// seen. Blocks **above** the witness tip that arrived inside the window
    /// are not bracketed: the record may carry them, and the identity vouched
    /// for stops at the witness tip. Both residuals close only when the
    /// record carries the hash of its own gather tip — a daemon-side wire
    /// change, filed in `docs/FOLLOWUPS.md`.
    pub(crate) fn bracket(
        self,
        at_tip_now: BlockHash,
    ) -> Result<BracketedChainFacts, TimelineBreak> {
        if at_tip_now == self.top_hash {
            Ok(BracketedChainFacts { facts: self })
        } else {
            Err(TimelineBreak::WitnessBlockReplaced)
        }
    }
}

/// A sync witness re-read **after** the record it vouches for, and found to
/// stand on the same block.
///
/// The only input [`CoherentChainView::reconcile`] accepts, so a vouched view
/// cannot be minted from a witness and a record alone: the post-read is a
/// type obligation, not a step a caller remembers. Obtained only from
/// [`SyncedChainFacts::bracket`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BracketedChainFacts {
    facts: SyncedChainFacts,
}

impl BracketedChainFacts {
    /// The witness this bracket confirmed.
    pub(crate) fn facts(&self) -> &SyncedChainFacts {
        &self.facts
    }
}

/// The sync predicate: `synchronized && (target_height == 0 || height >=
/// target_height)`. **The one site.**
///
/// [`SyncedChainFacts::new`] is this plus chain identity; the submit
/// watchdog's `DaemonHealthContext::is_synced` is this alone, because the
/// ladder needs a boolean and holds no chain identity to build the type
/// with. Both call here, so a change to what "synced" means cannot leave
/// the ladder and the release gate disagreeing. The module docs carry the
/// reasoning for each arm.
pub(crate) fn daemon_reports_synchronized(
    chain_height: ChainCount,
    target_height: u64,
    synchronized: bool,
) -> bool {
    let heights_agree = target_height == 0 || chain_height.to_raw() >= target_height;
    synchronized && heights_agree
}

/// The identity of a chain at one height: **which** block sits there.
///
/// What the departure ledger rests its observations on, and what a caller
/// must re-read from the daemon before the next observation may be carried
/// across. Height alone cannot serve — see [`CoherentChainView::anchor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChainAnchor {
    pub(crate) height: BlockHeight,
    pub(crate) hash: BlockHash,
}

/// A chain reading the daemon's three reads vouch for together: the sync
/// witness, the record, and the witness block re-read after the record.
///
/// Built from the [bracketed](SyncedChainFacts::bracket) sync witness and
/// the height a bond record was answered at — the bracket is what says the
/// record was gathered on the chain the witness described, which the two
/// heights alone cannot say. The heights then answer two further questions.
/// It keeps **both** heights rather than collapsing them on construction,
/// because the two questions consumers ask of this pair are different and a
/// single number can only answer one of them:
///
/// - [`Self::at`] — *what clock may I count elapsed obligation on?* The
///   lower of the two. Under-counting costs retained disk; over-counting
///   costs a slash (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7 item 5), so when
///   the reads disagree the lower is the one to believe.
/// - [`Self::rolled_back`] — *did they disagree in the direction that means
///   the chain moved under me?* A record **below** the witness, which is the
///   signature of a rollback between the two reads.
///
/// Storing the minimum alone would have answered the first and silently
/// destroyed the second, which is why a consumer that must refuse a
/// rolled-back read (claim assembly, the exit path) could not be built on it.
///
/// # Why the disagreement happens at all
///
/// The daemon's `synchronized` flag is **sticky**. The inherited C++ sets it
/// `false → true` exactly once (`cryptonote_protocol_handler.inl:2465`, the
/// only mutation; the constructor at `:219` is the only other write) and
/// never clears it on a pop or reorg. So a rollback between the sync read
/// and the record read leaves a witness whose height is *above* the record's
/// while the flag still says synchronized.
///
/// That is why **reading the witness first is not sufficient**, and the
/// point is worth stating because the ordering argument sounds like it
/// covers this: ordering fixes which read is *older in wall-clock time*; the
/// hazard is about which *height is larger*. A sticky flag severs the two.
/// Ordering is still necessary — it makes the witness the earlier read, so a
/// record below it is the rollback signature rather than ordinary chain
/// advance — but it is the relation between the heights that carries the
/// guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoherentChainView {
    witness_tip: BlockHeight,
    witness_hash: BlockHash,
    record_tip: BlockHeight,
}

impl CoherentChainView {
    /// Reconcile the sync witness with the height a record was answered at.
    ///
    /// Takes the **bracketed** witness, and only that: a view exists only for
    /// a record that was read between two identical readings of the witness
    /// block ([`SyncedChainFacts::bracket`]). There is no way to reconcile an
    /// unbracketed witness, which is what makes "vouched" mean the post-read
    /// happened rather than that a caller remembered to do it.
    pub(crate) fn reconcile(bracketed: &BracketedChainFacts, record_height: ChainCount) -> Self {
        let synced = bracketed.facts();
        Self {
            witness_tip: synced.tip(),
            witness_hash: synced.top_hash(),
            record_tip: tip_of(record_height),
        }
    }

    /// The view **with** the anchor its observations rest on, or the reason
    /// it has none: a record below its witness is a rollback, and a view the
    /// chain has abandoned anchors nothing.
    ///
    /// This is the only way to obtain an [`AnchoredView`], which is the only
    /// view the departure ledger accepts — so "no observation is recorded
    /// without an anchor to check it against" is a property of the argument
    /// type rather than of a branch inside `observe` or a guard at its call
    /// site. The pinner and the acting lanes both go through here.
    ///
    /// # Why height monotonicity is not a timeline
    ///
    /// The ledger used to detect a broken timeline by the next sampled
    /// height being *lower*. That catches a rollback the wallet happens to
    /// refresh in the middle of, and nothing else. A reorg can rewind across
    /// an epoch open and **catch back up above** the last observed height
    /// before the next refresh — and if the replacement branch restored a
    /// shard at that epoch open and dropped it again, the surviving absence
    /// entry releases a shard that was held when it mattered. Two branches
    /// share every height below their fork, so no relation between heights
    /// can see this. The hash of the block at the observed height can: if
    /// that block has been replaced, the observation is about a chain that
    /// no longer exists.
    ///
    /// The anchor is at the **observed** height, not the tip, deliberately.
    /// The tip moves every refresh on a live chain, so a tip-to-tip
    /// comparison would mismatch constantly and prove nothing. The question
    /// is narrower: *is the block I anchored to still the block at that
    /// height?* A reorg entirely above it leaves the answer yes, and the
    /// observations correctly survive.
    ///
    /// On every path that proceeds, `at()` equals the witness tip — a record
    /// above the witness is ordinary advance and the minimum picks the
    /// witness — so the witness hash is the hash *at* `at()`, and the anchor
    /// is exactly the pair the ledger needs.
    pub(crate) fn anchored(self) -> Result<AnchoredView, TimelineBreak> {
        if self.rolled_back() {
            return Err(TimelineBreak::ChainRolledBack);
        }
        Ok(AnchoredView {
            at: self.at(),
            anchor: ChainAnchor {
                height: self.witness_tip,
                hash: self.witness_hash,
            },
        })
    }

    /// The clock elapsed-obligation arithmetic may count on: the **lower** of
    /// the two reads.
    ///
    /// The only height accessor, deliberately. A consumer that could reach
    /// the witness height alone could reintroduce the hazard this type exists
    /// to close.
    pub(crate) fn at(self) -> BlockHeight {
        self.witness_tip.min(self.record_tip)
    }

    /// The record sits **below** the witness — the chain moved backwards
    /// between the two reads.
    ///
    /// Consumers that merely *count* time may clock from [`Self::at`] and
    /// carry on; consumers that **act on the record's own contents** — a
    /// claim signed against its gather tip, an exit verdict read out of its
    /// cooldown — must refuse, because those contents are a rolled-back view
    /// of the chain and no choice of clock repairs them.
    pub(crate) fn rolled_back(self) -> bool {
        self.record_tip < self.witness_tip
    }
}

/// A coherent view **with** the anchor its observations rest on — the only
/// view the departure ledger accepts.
///
/// Obtained only from [`CoherentChainView::anchored`], which refuses a
/// rolled-back view. So a view the chain has abandoned cannot be handed to
/// the ledger at all: the invariant that every recorded observation is
/// continuity-checkable lives in this type, and a caller that skipped the
/// check has nothing to pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnchoredView {
    at: BlockHeight,
    anchor: ChainAnchor,
}

impl AnchoredView {
    /// The clock elapsed-obligation arithmetic may count on — the same
    /// lower-of-two-reads rule as [`CoherentChainView::at`].
    pub(crate) fn at(self) -> BlockHeight {
        self.at
    }

    /// The block this observation rests on: the witness block, at `at()`.
    pub(crate) fn anchor(self) -> ChainAnchor {
        self.anchor
    }
}

/// Why the wallet stopped being able to vouch for what it read.
///
/// One member per remedy rather than a bool: each reaches an operator
/// through a different action (rule 82), and the public error classes
/// downstream already distinguish "still catching up" from "cannot be
/// reached". Collapsing them costs the diagnosis. The members that name a
/// chain that moved under the reads sit here rather than in a consumer's
/// own error because the departure ledger takes a `TimelineBreak` to decide
/// it must forget, and each of them is exactly a reason to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimelineBreak {
    /// The daemon reported it is still synchronizing. Routine; retry on
    /// cadence.
    DaemonSyncing,
    /// The daemon answered and the reply did not decode as chain facts — a
    /// protocol or contract fault, **not** a connectivity problem.
    FactsUnreadable,
    /// The daemon could not be reached at all.
    DaemonUnreachable,
    /// The daemon is not one this wallet can use (`VC-4`): another RPC
    /// contract, rule set, network or chain. Retrying the same daemon cannot
    /// clear it; the remedy is a different daemon or a matching build.
    IdentityRefused(shekyl_rpc_types::IdentityMismatch),
    /// The record came back **below** the witness that preceded it: the
    /// chain rolled back between the two reads, under a `synchronized` flag
    /// that is sticky and therefore still says otherwise.
    ///
    /// A member of this family because it is the same statement as the
    /// others — *the wallet cannot vouch for what it read* — arriving by a
    /// different route. It matters that it sits here rather than in a
    /// consumer's own error: the departure ledger takes a `TimelineBreak`
    /// to decide it must forget, and a rollback is exactly a reason to.
    ChainRolledBack,
    /// The block the witness stood on was **replaced** between the witness
    /// read and the re-read that brackets the record: a reorg crossed the
    /// witness tip inside the window. The record may have been gathered on
    /// either branch, so nothing vouches for it.
    ///
    /// Distinct from [`Self::ChainRolledBack`], which the *heights* reveal;
    /// this is the case the heights cannot reveal — a reorg that caught back
    /// up — and the reason [`SyncedChainFacts::bracket`] exists.
    WitnessBlockReplaced,
}

impl TimelineBreak {
    /// Classify a failed chain-facts read by its [`DaemonFault`].
    ///
    /// The one place the contract-versus-transport distinction is drawn for
    /// chain facts, so every consumer inherits the same reading of the same
    /// error. A fault on this side of the connection (a request this wallet
    /// could not form) reads as unreadable, not unreachable: it repeats on
    /// every retry, which is the contract class's behaviour.
    ///
    /// [`DaemonFault`]: shekyl_rpc_client::DaemonFault
    pub(crate) fn from_facts_error(err: &RpcError) -> Self {
        use shekyl_rpc_client::DaemonFault;
        match err.fault() {
            DaemonFault::Unreachable => Self::DaemonUnreachable,
            DaemonFault::Identity(mismatch) => Self::IdentityRefused(mismatch),
            DaemonFault::Protocol | DaemonFault::FeeResponse | DaemonFault::Internal => {
                Self::FactsUnreadable
            }
        }
    }
}

/// A block count as the height of its newest block, or `0` on an empty chain.
///
/// One conversion, shared by [`SyncedChainFacts::tip`] and
/// [`CoherentChainView::reconcile`], so the count/height relation has a
/// single site rather than one per caller.
fn tip_of(count: ChainCount) -> BlockHeight {
    count.tip().map_or(BlockHeight::from_raw(0), |h| {
        BlockHeight::from_raw(h.to_raw())
    })
}

/// The `get_info` reply [`health_from_get_info`] and
/// [`top_hash_from_get_info`] read, with the members a test chooses.
///
/// Test daemons build the reply from this struct, so the choices live next
/// to the reader. It produces a **complete** reply: the shared type refuses
/// a document missing any member, so a double that answered with only the
/// fields this wallet reads would be answering with something no daemon
/// sends. Test-only: production reads the daemon's reply, it does not build
/// one.
#[cfg(test)]
pub(crate) struct GetInfoDocument {
    /// Block count (`get_info.height`), not the tip's index.
    pub(crate) chain_count: ChainCount,
    /// Network target under the wire's "0 when synchronized" convention.
    pub(crate) target_height: u64,
    /// The daemon's own flag.
    pub(crate) synchronized: bool,
    /// Identity of the chain `chain_count` counts.
    pub(crate) top_hash: BlockHash,
    /// Outbound peer count. Zero is "none known".
    pub(crate) outgoing_connections: u64,
    /// Inbound peer count. Same contract as [`Self::outgoing_connections`].
    pub(crate) incoming_connections: u64,
}

#[cfg(test)]
impl GetInfoDocument {
    /// The reply as the shared type. Every member this struct does not
    /// choose holds a fixed, unremarkable value.
    pub(crate) fn to_reply(&self) -> GetInfoResponse {
        use shekyl_rpc_types::{
            DaemonNetwork, HashHex, Hidden, InfoChain, InfoEconomics, InfoHealth, InfoIdentity,
            InfoPeers, InfoPool, InfoStatus, RpcStatus,
        };
        GetInfoResponse {
            status: RpcStatus::ok(),
            health: InfoHealth {
                height: self.chain_count.to_raw(),
                top_block_hash: HashHex::from_bytes(*self.top_hash.as_bytes()),
                target_height: self.target_height,
                synchronized: self.synchronized,
                busy_syncing: false,
                offline: false,
                following_degraded: false,
            },
            identity: InfoIdentity {
                nettype: DaemonNetwork::Fakechain,
                protocol_version: 3,
            },
            chain: InfoChain {
                difficulty: 1,
                cumulative_difficulty: u128::from(self.chain_count.to_raw()),
                target: 120,
                tx_count: 0,
                block_weight_limit: 600_000,
                block_weight_median: 300_000,
                adjusted_time: 1_700_000_000,
            },
            economics: InfoEconomics {
                already_generated_coins: 0,
                release_multiplier: 1_000_000,
                burn_pct: 0,
                total_burned: 0,
                staker_emission_share_effective: 0,
            },
            pool: InfoPool { tx_pool_size: 0 },
            node: Hidden::Shown(InfoStatus {
                start_time: 1_700_000_000,
                free_space: 1 << 40,
                database_size: 1 << 30,
                version: "test".to_owned(),
                outgoing_connections_count: self.outgoing_connections,
                incoming_connections_count: self.incoming_connections,
                alt_blocks_count: 0,
                rpc_connections_count: 1,
            }),
            peers: Hidden::Shown(InfoPeers {
                public_incoming_socket_count: 0,
                public_outgoing_socket_count: 0,
                tor_incoming_socket_count: 0,
                tor_outgoing_socket_count: 0,
                white_peerlist_size: 0,
                grey_peerlist_size: 0,
            }),
            restricted: false,
        }
    }

    /// The JSON object a `get_info` result carries.
    pub(crate) fn to_value(&self) -> Value {
        serde_json::to_value(self.to_reply()).expect("a get_info reply serializes")
    }
}

/// Project the daemon's `get_info` reply onto [`DaemonHealth`].
///
/// The single place this reply is read for health, shared by
/// [`DaemonEngine::get_health`](crate::engine::traits::daemon::DaemonEngine::get_health) and
/// [`fetch_synced_chain_facts`], so the two cannot come to disagree about what
/// the daemon said.
///
/// **There is nothing left to refuse here.** The reply is the shared
/// [`GetInfoResponse`], and that type decodes strictly: a document missing
/// `height`, `target_height`, `synchronized` or `top_block_hash`, or
/// carrying one of the wrong shape, never becomes a value this function is
/// handed. That is the property the hand-written decoder this replaces
/// defended field by field — above all for `target_height`, where `0` is
/// the synchronized sentinel and a default would manufacture the very claim
/// [`SyncedChainFacts::new`] exists to verify. It now holds for every
/// member, by construction.
///
/// The connection counts are a Status field, which a daemon may withhold
/// from this caller. Withheld reads as zero — "none known", which routes at
/// worst to the operator-alarm rung. The sum is `saturating_add`.
pub(crate) fn health_from_get_info(info: &GetInfoResponse) -> DaemonHealth {
    let connections = info.node.shown().map_or(0, |status| {
        status
            .outgoing_connections_count
            .saturating_add(status.incoming_connections_count)
    });
    DaemonHealth {
        connections,
        height: info.health.height,
        target_height: info.health.target_height,
        synchronized: info.health.synchronized,
    }
}

/// The chain's identity from the daemon's `get_info` reply.
///
/// Mandatory on the wire, and typed there: there is no honest default for
/// an identity, and a reply without a 32-byte hex `top_block_hash` does not
/// decode.
pub(crate) fn top_hash_from_get_info(info: &GetInfoResponse) -> BlockHash {
    BlockHash::from_bytes(info.health.top_block_hash.to_bytes())
}

/// One `get_info` read, yielding [`SyncedChainFacts`] only if the daemon says
/// it is synchronized.
///
/// Bound on bare [`Rpc`] rather than on the engine's richer daemon trait so a
/// caller holding only a persona-isolated transport can use it — the serve-set
/// pinner is exactly that caller, and routing its sync read anywhere but over
/// `P`'s own transport would break the §7.4 transport pin.
///
/// `Ok(None)` is *"the daemon is syncing"*. An `Err` is *"the daemon did not
/// answer, or answered off-contract"* — two further facts the error itself
/// separates (see Errors). Callers for whom all of these mean "do not act"
/// may collapse them, but they are different facts and this signature keeps
/// them so — an operator diagnosing a stalled release wants to know which
/// one they have (rule 82).
///
/// # Errors
///
/// A transport [`RpcError`] when the daemon did not answer; otherwise
/// [`RpcError::InvalidNode`] — the reply arrived and is not a
/// [`GetInfoResponse`]: a member absent or of the wrong shape, an unknown
/// member, or two names for one value disagreeing. The two classes are what
/// [`TimelineBreak::from_facts_error`] separates, so a contract fault
/// reaches an operator as "check the daemon's version", never as "check the
/// network".
pub(crate) async fn fetch_synced_chain_facts<R: Rpc>(
    rpc: &R,
) -> Result<Option<SyncedChainFacts>, RpcError> {
    let info: GetInfoResponse = rpc.json_rpc_call("get_info", None).await?;
    Ok(SyncedChainFacts::from_health(
        health_from_get_info(&info),
        top_hash_from_get_info(&info),
    ))
}

#[cfg(test)]
#[path = "synced_chain_facts_tests.rs"]
mod tests;
