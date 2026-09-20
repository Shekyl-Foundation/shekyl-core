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
//! The **height half** is lifted verbatim from
//! `submit_watchdog::DaemonHealthContext::is_synced`, which until this type
//! landed was the only honest reading of sync state in the wallet. The
//! watchdog now asks this constructor instead
//! ([`DaemonHealthContext::synced_facts`](crate::engine::submit_watchdog::DaemonHealthContext)),
//! so the predicate has one site and a change to it cannot leave two
//! consumers disagreeing about what "synced" means.
//!
//! **The predicate is ours; the C++ is provenance, not authority.** What the
//! conjunction is doing is absorbing the *shape of the response it consumes*.
//! This constructor reads `get_info`, which is still served by the inherited
//! C++ (`core_rpc_server.cpp`) and has no Rust handler yet. That surface
//! encodes sync state twice: a `synchronized` bool
//! (`core_rpc_server_commands_defs.h:254`, set from `check_core_ready()` at
//! `:248`) **and** a `target_height` overloaded with a zero sentinel
//! (`:209`, `is_synchronized() ? 0 : get_target_blockchain_height()`). Those
//! citations say what the guide *does*; they do not define what we require.
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
//! This correction is the `WSS-24` lane's (`fix/wss-24-own-height-daemon-tip`,
//! `serving/daemon_tip.rs`), which derived the same predicate independently
//! and found the gap; `WSS-Q14`'s brief said to lift the watchdog's form
//! verbatim, and verbatim was not enough. The two lanes converge here: this
//! constructor is the shared home, and the tip cache's reading adopts it.
//!
//! # The `R1` seam
//!
//! The type is wallet-side and is built from the engine's daemon client. A
//! DRS change to the daemon's chain-facts response shape lands in
//! [`health_from_get_info`] and [`fetch_synced_chain_facts`] and nowhere else
//! — every consumer holds the type, not the response.
//!
//! # Units
//!
//! `get_info.height` is the block **count**, not the tip height:
//! `core_rpc_server.cpp:206-207` reads the top block's height and then
//! increments it (*"turn top block height into blockchain height"*). It is
//! therefore the same quantity as [`EmissionClaimSource::chain_height`]
//! (`crate::engine::emission_source`), and it is stored here as a [`ChainCount`] so
//! the count/height confusion cannot be made by a consumer. Consumers that
//! want the newest existing block's height take [`SyncedChainFacts::tip`].

use serde_json::Value;
use shekyl_rpc_client::{Rpc, RpcError};
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
    /// `chain_height` is the response's block count and `target_height` its
    /// network estimate under the *"0 when synchronized"* convention. Both
    /// come from one response — do not pair a height from one read with a
    /// target from another, which is why this takes them together rather than
    /// offering a setter.
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
    /// Exists for one caller: `daemon_claimed_tip`, which historically
    /// labelled this count as a `BlockHeight` and must keep doing so until
    /// that off-by-one is ruled on separately (see its doc). Prefer
    /// [`Self::tip`] everywhere else — a consumer that wants a height and
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

/// A chain reading two independent reads of the same daemon both vouch for.
///
/// Built from the sync witness and the height a bond record was answered at.
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
    /// Takes the witness by reference so the caller keeps it: holding
    /// [`SyncedChainFacts`] is what says the wallet may act at all, and that
    /// permission outlives one reconciliation.
    pub(crate) fn reconcile(synced: &SyncedChainFacts, record_height: ChainCount) -> Self {
        Self {
            witness_tip: synced.tip(),
            witness_hash: synced.top_hash(),
            record_tip: tip_of(record_height),
        }
    }

    /// The chain identity this view was observed against, or `None` if the
    /// two reads disagree in the rollback direction and there is no coherent
    /// one.
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
    /// On every path that proceeds to observe, `at()` equals the witness
    /// tip — a record above the witness is ordinary advance and the minimum
    /// picks the witness; a record below is a rollback and this returns
    /// `None` — so the witness hash is the hash *at* `at()`, and the anchor
    /// is exactly the pair the ledger needs.
    pub(crate) fn anchor(self) -> Option<ChainAnchor> {
        (!self.rolled_back()).then_some(ChainAnchor {
            height: self.witness_tip,
            hash: self.witness_hash,
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

/// Why the wallet stopped being able to vouch for what it read.
///
/// Three members rather than a bool, and rather than the two this started
/// with: each reaches an operator through a different remedy (rule 82), and
/// the public error classes downstream already distinguish "still catching
/// up" from "cannot be reached". Collapsing them costs the diagnosis.
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
}

impl TimelineBreak {
    /// Classify a failed chain-facts read.
    ///
    /// The one place the `InvalidNode`-versus-transport distinction is drawn,
    /// so every consumer inherits the same reading of the same error.
    pub(crate) fn from_facts_error(err: &RpcError) -> Self {
        match err {
            RpcError::InvalidNode(_) => Self::FactsUnreadable,
            _ => Self::DaemonUnreachable,
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

/// Decode the daemon's `get_info` result into [`DaemonHealth`].
///
/// The single parse site for this response, shared by
/// [`DaemonEngine::get_health`](crate::engine::traits::daemon::DaemonEngine::get_health) and
/// [`fetch_synced_chain_facts`], so the two cannot come to disagree about what
/// the daemon said. Two decoders over one wire response with no cross-check is
/// exactly the shape that lets a field's meaning drift on one side only.
///
/// Untrusted-daemon input is parsed defensively (`20-rust-vs-cpp-policy` §3):
/// a response missing the mandatory `height` field is a malformed reply
/// ([`RpcError::InvalidNode`]), not a silently defaulted zero — a false
/// "synced at height 0" would be a *constructible* [`SyncedChainFacts`]
/// vouching for a view that does not exist.
///
/// **`target_height` is mandatory**, and is the one field here that cannot
/// take a default: `0` is not a neutral absence, it is the *synchronized
/// sentinel*, so defaulting it would have this decoder manufacture the very
/// claim [`SyncedChainFacts::new`] exists to verify. Absent or non-numeric
/// is [`RpcError::InvalidNode`]. Only the connection counts default, because
/// zero is honestly "none known" there and routes at worst to the
/// operator-alarm rung; the sum is `saturating_add` (rule §4).
///
/// # Errors
///
/// [`RpcError::InvalidNode`] when `height` is absent or not an integer.
pub(crate) fn health_from_get_info(info: &Value) -> Result<DaemonHealth, RpcError> {
    let height = info
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::InvalidNode("get_info missing height".to_string()))?;
    // **Mandatory, and this one cannot take a default.** `0` is not a
    // neutral absence here — it is the synchronized *sentinel*, so defaulting
    // an absent or non-numeric `target_height` would have the decoder
    // manufacture the very claim the constructor is supposed to verify. That
    // is fail-OPEN: `{"height": 500, "synchronized": true}` would mint facts
    // for a daemon that never said it was caught up.
    //
    // The field is declared on the response
    // (`core_rpc_server_commands_defs.h:269`, `KV_SERIALIZE(target_height)`),
    // so its absence is contract drift, not an optional-field omission.
    // Do not restore a default here for symmetry with the connection counts
    // below: those default because zero is honestly "none known" and only
    // ever routes to the operator-alarm rung, whereas zero here is an
    // assertion about the chain.
    let target_height = info
        .get("target_height")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::InvalidNode("get_info missing target_height".to_string()))?;
    let outgoing = info
        .get("outgoing_connections_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let incoming = info
        .get("incoming_connections_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let synchronized = info
        .get("synchronized")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(DaemonHealth {
        connections: outgoing.saturating_add(incoming),
        height,
        target_height,
        synchronized,
    })
}

/// Decode `top_block_hash` from the daemon's `get_info` result.
///
/// **Mandatory.** It is the chain's identity, and there is no honest
/// default for an identity: a made-up hash would let a ledger carry
/// observations across a reorg it could not see, which is the exact hazard
/// the anchor exists to close. The field is declared on the response
/// (`core_rpc_server.cpp:208`, `res.top_block_hash = pod_to_hex(top_hash)`),
/// so its absence is contract drift, not an omission.
///
/// # Errors
///
/// [`RpcError::InvalidNode`] when the field is absent, not a string, not
/// hex, or not 32 bytes.
pub(crate) fn top_hash_from_get_info(info: &Value) -> Result<BlockHash, RpcError> {
    let hex_str = info
        .get("top_block_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidNode("get_info missing top_block_hash".to_string()))?;
    let bytes = hex::decode(hex_str)
        .map_err(|e| RpcError::InvalidNode(format!("get_info top_block_hash is not hex: {e}")))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        RpcError::InvalidNode("get_info top_block_hash is not 32 bytes".to_string())
    })?;
    Ok(BlockHash::from_bytes(bytes))
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
/// answer"*. Callers for whom both mean "do not act" may collapse them, but
/// they are different facts and this signature keeps them so — an operator
/// diagnosing a stalled release wants to know which one they have (rule 82).
///
/// # Errors
///
/// [`RpcError`] from the transport, or [`RpcError::InvalidNode`] if the reply
/// is missing `height`.
pub(crate) async fn fetch_synced_chain_facts<R: Rpc>(
    rpc: &R,
) -> Result<Option<SyncedChainFacts>, RpcError> {
    let info: Value = rpc.json_rpc_call("get_info", None).await?;
    let health = health_from_get_info(&info)?;
    let top_hash = top_hash_from_get_info(&info)?;
    Ok(SyncedChainFacts::from_health(health, top_hash))
}

#[cfg(test)]
#[path = "synced_chain_facts_tests.rs"]
mod tests;
