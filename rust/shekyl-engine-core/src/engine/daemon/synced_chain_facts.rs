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
//! # The predicate: the daemon's `synchronized` flag, and nothing else
//!
//! Whether the node has caught up is the daemon's call, and it makes that
//! call with more context than the wallet has. So the wallet reads one
//! source, `get_info.synchronized`, and [`SyncedChainFacts::new`] is where
//! it is read. The submit ladder reads that same member of the same
//! [`DaemonHealth`]: there is no second health type to disagree with it.
//!
//! **The wallet does not compare its daemon's height with its target.** The
//! core's target is the tallest chain any peer has *claimed* in a handshake.
//! A comparison `height >= target` would let one peer advertising a tall
//! chain make a healthy node read as behind: the submit watchdog would wait
//! indefinitely and the persona's poller would stop serving, for the price
//! of a handshake. The target is shown to people (the CLI, the console);
//! nothing here decides on it, and the wallet's decision types do not carry
//! it.
//!
//! This was a two-field conjunction, `synchronized && (target == 0 ||
//! height >= target)`, until `CORE_RPC_VERSION` 3.46. It read two fields
//! because `get_info` wrote `target_height` as `0` for a synchronized node,
//! a sentinel that also described a daemon that had just started with no
//! peers; the flag was what told those apart. Under the sentinel the height
//! half never decided anything: a synchronized daemon always reported `0`.
//! RK-D15 retired the sentinel, the target became the core's real one, and
//! the conjunction collapsed to the flag, as this module had said it would
//! (`docs/design/DAEMON_RPC_KV_GET_INFO.md` §1 RK-D15, §5 commit 6).
//!
//! What the flag does not cover is in [`SyncedChainFacts`]'s own docs: it
//! is one-way in the daemon, so a node that synchronized once and then lost
//! every peer still reports it. The persona's poller adds its own checks
//! for that (`stake_engine/serving/daemon_tip.rs`).
//!
//! # The `R1` seam
//!
//! The type is wallet-side and is built from the engine's daemon client. A
//! DRS change to the daemon's chain-facts response shape lands in
//! [`health_from_daemon_status`], [`top_hash_from_daemon_status`] and
//! [`fetch_synced_chain_facts`], which read the shared
//! [`DaemonStatus`] — the one definition of the reply, in
//! `shekyl-rpc-types` — and nowhere else. Every consumer holds the type,
//! not the response.
//!
//! # Units
//!
//! `daemon_status.height` is the tip's height, an ordinal (IG-Q45); the
//! wallet keeps the block **count**, one more, the chain's length, computed
//! at the decode ([`health_from_daemon_status`]). It is the same quantity
//! as [`EmissionClaimSource::chain_height`]
//! (`crate::engine::emission_source`), and it is stored here as a [`ChainCount`] so
//! the count/height confusion cannot be made by a consumer. Consumers that
//! want the newest existing block's height take [`SyncedChainFacts::tip`].

#[cfg(test)]
use serde_json::Value;
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::wire::daemon::DaemonStatus;
use shekyl_types::{BlockHash, BlockHeight, ChainCount};

use crate::engine::traits::daemon::{DaemonHealth, DaemonP2p};

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
    /// `chain_height` is the response's block count, `synchronized` its own
    /// word, and `top_hash` the identity of the chain the count belongs to.
    /// All three come from one response — do not pair a height from one
    /// read with a flag or a hash from another, which is why this takes
    /// them together rather than offering a setter.
    ///
    /// `None` is not an error. It is the `R-B` answer: while the daemon
    /// reports syncing, consensus-derived facts are **unknown**, and a caller
    /// that cannot proceed without them declines to act rather than acting on
    /// a view it cannot vouch for.
    pub(crate) fn new(
        chain_height: ChainCount,
        synchronized: bool,
        top_hash: BlockHash,
    ) -> Option<Self> {
        synchronized.then_some(Self {
            chain_height,
            top_hash,
        })
    }

    /// Build from the engine's [`DaemonHealth`] projection of `get_info`.
    ///
    /// `has_peers` is deliberately not carried: peerlessness is the
    /// watchdog's escalation axis, not a synchronization fact, and a type
    /// named for one property that silently carries another is how a consumer
    /// comes to read the wrong one.
    pub(crate) fn from_health(health: DaemonHealth, top_hash: BlockHash) -> Option<Self> {
        Self::new(
            ChainCount::from_raw(health.height),
            health.synchronized,
            top_hash,
        )
    }

    /// The hash of the newest block at the moment the daemon reported
    /// synchronized — the identity of the chain this count belongs to.
    #[cfg(test)]
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
    /// seen. Its consumer is the proofs workflow, whose transaction reads
    /// carry a height and no block hash; a record that carries its own
    /// block's hash needs no bracket ([`CoherentChainView`]).
    pub(crate) fn bracket(
        self,
        at_tip_now: BlockHash,
    ) -> Result<BracketedChainFacts, TimelineBreak> {
        if at_tip_now == self.top_hash {
            Ok(BracketedChainFacts(()))
        } else {
            Err(TimelineBreak::WitnessBlockReplaced)
        }
    }
}

/// A sync witness re-read **after** the reads it vouches for, and found to
/// stand on the same block.
///
/// The post-read is a type obligation, not a step a caller remembers.
/// Obtained only from [`SyncedChainFacts::bracket`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BracketedChainFacts(());

/// The identity of a chain at one height: **which** block sits there.
///
/// What the departure ledger rests its observations on, and what a caller
/// must re-read from the daemon before the next observation may be carried
/// across. Height alone cannot serve — see [`CoherentChainView::anchored`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChainAnchor {
    pub(crate) height: BlockHeight,
    pub(crate) hash: BlockHash,
}

/// A record that carries its own chain identity, checked against the sync
/// witness read before it.
///
/// The record's reply names the block it was gathered at — its height and
/// that block's hash, read in one snapshot (IG-Q84) — so the record vouches
/// for **which** chain it describes on its own: no relation between the
/// witness and the record is needed to say that, and no re-read after the
/// record could say it better. The witness keeps the two jobs only it can
/// do: the daemon's `synchronized` (an unsynchronized daemon mints no
/// view), and the height a later record must not fall below.
///
/// - [`Self::at`] — *what clock may I count elapsed obligation on?* The
///   record's own height: the record's contents are a reading of the chain
///   at that block, so an observation drawn from them is stamped where it
///   was observed, never earlier.
/// - [`Self::rolled_back`] — *did the chain move backwards under me?* A
///   record **below** the witness, which is the signature of a rollback
///   between the two reads.
///
/// # Why the rollback check still needs the witness
///
/// The daemon's `synchronized` reads its chain-sync watch and does revert,
/// but a rollback between the sync read and the record read can still
/// leave a witness *above* the record while the flag says synchronized.
/// Reading the witness first is necessary — it makes the witness the
/// earlier read, so a record below it is the rollback signature rather than
/// ordinary chain advance — and the relation between the heights is what
/// carries the guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoherentChainView {
    witness_tip: BlockHeight,
    record: ChainAnchor,
}

impl CoherentChainView {
    /// Reconcile the sync witness with the block a record was gathered at.
    ///
    /// Takes a [`SyncedChainFacts`], and only that: a view exists only for a
    /// record read after the daemon said it was synchronized.
    pub(crate) fn reconcile(witness: &SyncedChainFacts, record: ChainAnchor) -> Self {
        Self {
            witness_tip: witness.tip(),
            record,
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
    /// A reorg can rewind across an epoch open and **catch back up above**
    /// the last observed height before the next refresh — and if the
    /// replacement branch restored a shard at that epoch open and dropped it
    /// again, a surviving absence entry would release a shard that was held
    /// when it mattered. Two branches share every height below their fork,
    /// so no relation between heights can see this. The hash of the block at
    /// the observed height can: if that block has been replaced, the
    /// observation is about a chain that no longer exists.
    ///
    /// The anchor is the record's own block, at the **observed** height. The
    /// tip moves every refresh on a live chain, so a tip-to-tip comparison
    /// would mismatch constantly and prove nothing. The question is
    /// narrower: *is the block I anchored to still the block at that
    /// height?* A reorg entirely above it leaves the answer yes, and the
    /// observations correctly survive.
    pub(crate) fn anchored(self) -> Result<AnchoredView, TimelineBreak> {
        if self.rolled_back() {
            return Err(TimelineBreak::ChainRolledBack);
        }
        Ok(AnchoredView {
            at: self.at(),
            anchor: self.record,
        })
    }

    /// The clock elapsed-obligation arithmetic may count on: the height the
    /// record was gathered at.
    ///
    /// The only height accessor, deliberately: the witness height is the
    /// earlier reading, and an observation drawn from the record stamped
    /// there would be stamped before it was seen — the release-early
    /// direction.
    pub(crate) fn at(self) -> BlockHeight {
        self.record.height
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
        self.record.height < self.witness_tip
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
            DaemonFault::Protocol
            | DaemonFault::FeeResponse
            | DaemonFault::Internal
            | DaemonFault::NotPermitted => Self::FactsUnreadable,
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
    /// The core's target, `None` when it reports none.
    pub(crate) target_height: Option<u64>,
    /// The daemon's own flag.
    pub(crate) synchronized: bool,
    /// Identity of the chain `chain_count` counts.
    pub(crate) top_hash: BlockHash,
    /// Health's `has_peers`: whether the daemon has a handshaken session.
    ///
    /// The reply this builds writes **zero for every Status and Peers
    /// count**, whatever this says. The wallet reads `has_peers` and may
    /// not read those; a reader that went back to them would see a
    /// peerless daemon in every test built on this document.
    pub(crate) has_peers: bool,
}

#[cfg(test)]
impl GetInfoDocument {
    /// The reply as the shared type. Every member this struct does not
    /// choose holds a fixed, unremarkable value.
    pub(crate) fn to_reply(&self) -> GetInfoResponse {
        use shekyl_rpc_types::{
            HashHex, Hidden, InfoChain, InfoEconomics, InfoHealth, InfoIdentity, InfoPeers,
            InfoPool, InfoStatus, RpcStatus,
        };
        GetInfoResponse {
            status: RpcStatus::ok(),
            health: InfoHealth {
                height: self.chain_count.to_raw(),
                top_block_hash: HashHex::from_bytes(*self.top_hash.as_bytes()),
                target_height: self.target_height.into(),
                synchronized: self.synchronized,
                busy_syncing: false,
                following_degraded: false,
                p2p: shekyl_rpc_types::HealthP2p::Running {
                    has_peers: self.has_peers,
                },
            },
            identity: InfoIdentity {
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
                already_generated_coins: shekyl_units::AtomicUnits::ZERO,
                release_multiplier: 1_000_000,
                burn_pct: 0,
                total_burned: shekyl_units::AtomicUnits::ZERO,
                staker_emission_share_effective: 0,
            },
            pool: InfoPool::Live { tx_pool_size: 0 },
            node: Hidden::Shown(InfoStatus {
                start_time: 1_700_000_000,
                free_space: 1 << 40,
                database_size: 1 << 30,
                version: "test".to_owned(),
                connections: shekyl_rpc_types::StatusConnections::Running {
                    outgoing: 0,
                    incoming: 0,
                },
                alt_blocks_count: 0,
                rpc_connections_count: 1,
            }),
            peers: Hidden::Shown(shekyl_rpc_types::InfoP2p::Running(
                InfoPeers::new(vec![shekyl_rpc_types::InfoConnectorPeers {
                    connector: shekyl_rpc_types::InfoConnector::Clearnet,
                    incoming_sockets: 0,
                    outgoing_sockets: 0,
                    white_peerlist_size: 0,
                    gray_peerlist_size: 0,
                }])
                .expect("one row is in order"),
            )),
            // The wallet is never the daemon's host administrator.
            host: Hidden::Withheld,
            restricted: false,
        }
    }

    /// The JSON object a `get_info` result carries.
    pub(crate) fn to_value(&self) -> Value {
        serde_json::to_value(self.to_reply()).expect("a get_info reply serializes")
    }
}

/// Project the daemon's `daemon_status` reply onto [`DaemonHealth`].
///
/// The single place this reply is read for health, shared by
/// [`DaemonEngine::get_health`](crate::engine::traits::daemon::DaemonEngine::get_health) and
/// [`fetch_synced_chain_facts`], so the two cannot come to disagree about what
/// the daemon said. The reply decodes strictly, so a document missing a
/// member, or carrying one of the wrong shape, never reaches here.
///
/// **The wire carries the tip's height, an ordinal; the wallet keeps the
/// chain's count** (IG-Q45). The count is computed here, once: the tip's
/// height plus one.
///
/// `target_height` is decoded and not carried: nothing the wallet decides
/// reads it (module docs).
///
/// **Whether the daemon has peers is Health's `peered`, and only that**
/// (RK-D14). Status's counts describe the node and are the daemon's to
/// withhold; reading a withheld Status as zero once raised a false
/// `DaemonPeerless` alarm. Health is told to every caller.
pub(crate) fn health_from_daemon_status(status: &DaemonStatus) -> DaemonHealth {
    DaemonHealth {
        p2p: if status.offline {
            DaemonP2p::Offline
        } else {
            DaemonP2p::Running {
                has_peers: status.peered.0.unwrap_or(false),
            }
        },
        height: status.height.0.saturating_add(1),
        synchronized: status.synchronized,
    }
}

/// The chain's identity from the daemon's `daemon_status` reply: its tip's
/// hash. Mandatory on the wire, and typed there.
pub(crate) fn top_hash_from_daemon_status(status: &DaemonStatus) -> BlockHash {
    BlockHash::from_bytes(status.hash.to_bytes())
}

/// One `daemon_status` read, yielding [`SyncedChainFacts`] only if the daemon says
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
/// [`DaemonStatus`]: a member absent or of the wrong shape, an unknown
/// member, or two names for one value disagreeing. The two classes are what
/// [`TimelineBreak::from_facts_error`] separates, so a contract fault
/// reaches an operator as "check the daemon's version", never as "check the
/// network".
pub(crate) async fn fetch_synced_chain_facts<R: Rpc>(
    rpc: &R,
) -> Result<Option<SyncedChainFacts>, RpcError> {
    let status = rpc
        .call::<shekyl_rpc_client::wire::DaemonStatus>(shekyl_rpc_types::kinds::NoParams)
        .await?;
    Ok(SyncedChainFacts::from_health(
        health_from_daemon_status(&status),
        top_hash_from_daemon_status(&status),
    ))
}

#[cfg(test)]
#[path = "synced_chain_facts_tests.rs"]
mod tests;
