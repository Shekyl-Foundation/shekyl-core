// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The producer behind the `SF-D5` anchor gate's height (`WSS-24`): poll the
//! configured daemon on `P`'s own transport and stamp its tip into the
//! [`DaemonTipCache`] the serving host gates on.
//!
//! The consumer half and the freshness policy live in `shekyl-p-host`
//! (`daemon_tip`); this module owns only the two things that are facts about
//! *this wallet's deployment* rather than about serving — which transport the
//! read goes over, and how often.
//!
//! # The transport is pinned by type
//!
//! The parameter is [`PersonaIsolatedTransport`], so the read goes over `P`'s
//! own circuit: [`LocalNodeRpc`](super::super::super::prpc::LocalNodeRpc) on
//! the loopback default, `PRpc` on the remote posture. The marker is what
//! forbids reaching for the principal's `DaemonClient` — which in the local
//! posture happens to dial the same host, and would still be the wrong type to
//! ask, because the pin binds the type that made the posture argument.
//!
//! **Never a peer draw.** The tip that centres the gate is a claim this
//! persona will be slashed against; sourcing it from a drawn peer would let
//! whoever answers choose which challenges `P` refuses.
//!
//! # The seam
//!
//! The reply this module reads is the daemon's `daemon_status`, defined
//! once, as `shekyl_rpc_types::wire::daemon::DaemonStatus`.
//!
//! Daemon elements still in flux stay behind a seam the wallet owns
//! (standing ruling, 2026-09-19). That is what [`PersonaIsolatedTransport`]
//! and [`TipReading`] are here — the wallet's own transport type and its
//! own typed reading. The reply is read in two places by design: the
//! members the submit watchdog and the sync witness also read are projected
//! in the shared `health_from_daemon_status` (`WSS-Q14`), and the
//! serving-only flags in [`tip_reading_from_status`]. When the reply's shape
//! moves, these two functions change while the gate, the cache, and every
//! test above them do not. The seam is load-bearing, not incidental.
//!
//! # The stamp is a block height
//!
//! `daemon_status.height` is the tip's height, an ordinal (IG-Q45); the
//! shared projection keeps the chain's count, one more. Admission centres
//! its window on `predecessor_height − 720`, a block height, so stamping the
//! count unconverted would centre `P`'s gate one block high and let it sign
//! anchors admission then refuses. The count goes back to the tip through
//! `ChainCount::tip`, here.

use std::sync::Weak;
use std::time::Duration;

use shekyl_p_host::DaemonTipCache;
use shekyl_rpc_client::wire;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::daemon::DaemonStatus;
use shekyl_types::{BlockHeight, ChainCount};

use crate::engine::daemon::synced_chain_facts::health_from_daemon_status;

use crate::engine::prpc::PersonaIsolatedTransport;

/// How often the tip is re-read, as a divisor of [`tip_max_age`].
///
/// Four reads per age bound, so three consecutive failed polls still leave
/// the gate answering. A loopback `daemon_status` is cheap; the cost of being
/// wrong here is a slash.
pub(crate) const TIP_REFRESH_INTERVAL_DIVISOR: u32 = 4;

/// How many block targets of wall clock a stamped tip may age before the
/// gate stops trusting it.
///
/// # Wall clock does not bound block distance (Copilot F1)
///
/// What the gate actually needs is a bound on **block distance**: a cached
/// tip `k` blocks behind the chain shifts `P`'s gate centre down by `k`, and
/// an honest challenge is refused once `k > L`
/// ([`PASS_ANCHOR_LAG_BLOCKS`]). An earlier version of this constant claimed
/// one block target "caps that error at one block, so cache age can never be
/// what pushes an honest `P` out of the window". **That was false**, and the
/// error is worth naming precisely because it is seductive: a block target
/// is the *expected* inter-arrival time of a Poisson process, not a ceiling
/// on it. Any number of blocks can arrive in any interval; only the
/// probability falls off.
///
/// So the honest statement is a probability, not a guarantee. With arrivals
/// Poisson at rate `1/T` and a cache of age `a`, the blocks missed are
/// `N ~ Poisson(a/T)` and the gate is pushed out when `N > L`:
///
/// | cache age | `P(N > L)` |
/// |---|---|
/// | 30 s (one refresh interval) | `6.6e-6` |
/// | 60 s | `1.7e-4` |
/// | 120 s (this bound) | `3.7e-3` |
///
/// In steady state the age at a challenge is roughly uniform on one refresh
/// interval, giving **~1.2e-6** — about one challenge in a million. The
/// `3.7e-3` row is reached only after three consecutive failed polls.
///
/// The review's framing — that five blocks inside 120 s is "an ordinary
/// event, not a tail case" — overstates it by about two and a half orders
/// of magnitude at the bound, and by six at the operating point. The
/// reasoning error it identifies is nonetheless real, and the claim above
/// is now a measured residual instead of a guarantee that cannot hold.
///
/// # This multiplier is the ruled knob, not a derivation
///
/// The value is **1** because that is what shipped and what was ruled
/// against; it is not implied by anything. Tightening it buys residual and
/// costs polls:
///
/// | budget on `P(N > L)` | age bound | multiplier | refresh interval |
/// |---|---|---|---|
/// | `1e-2` | 153 s | 1.28 | 38 s |
/// | `1e-3` | 89 s | 0.74 | 22 s |
/// | `1e-4` | 53 s | 0.44 | 13 s |
/// | `1e-5` | 33 s | 0.27 | **8 s** |
///
/// Two couplings a reader changing this must see. The refresh interval is
/// [`TIP_REFRESH_INTERVAL_DIVISOR`] of the bound, so it tightens in step and
/// the "three failed polls of slack" property is preserved at any value.
/// And it has a floor: `CLAIM_SOURCE_TIMEOUT` is 10 s, so a budget of `1e-5`
/// asks for an 8 s interval — shorter than one poll is allowed to take, which
/// is incoherent. Budgets at or below `1e-5` need the divisor revisited too.
pub(crate) const TIP_MAX_AGE_BLOCK_TARGETS: u64 = 1;

/// The age a stamped tip may reach before the gate stops trusting it.
///
/// Derived from the chain's block target and
/// [`TIP_MAX_AGE_BLOCK_TARGETS`] — no seconds literal lives here, and the
/// multiplier carries its own justification and its residual.
pub(crate) fn tip_max_age(daa_target_seconds: u64) -> Duration {
    Duration::from_secs(daa_target_seconds.saturating_mul(TIP_MAX_AGE_BLOCK_TARGETS))
}

/// The poll cadence for a given block target.
pub(crate) fn tip_refresh_interval(daa_target_seconds: u64) -> Duration {
    tip_max_age(daa_target_seconds) / TIP_REFRESH_INTERVAL_DIVISOR
}

/// Why a daemon's reported height is **not** evidence about the chain.
///
/// Each variant is a fact the daemon states about itself, so the gate's
/// refusal can be attributed rather than guessed. They are checked in a
/// fixed order and the first that holds is reported, which keeps the
/// diagnosis stable for an operator reading two polls in a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotFollowing {
    /// `offline` — the daemon is not talking to the network at all.
    Offline,
    /// `following_degraded` — it refused a switch at the prune watermark and
    /// knows it is not on the heaviest chain it has seen (`C2-R1b F-1(a)`).
    /// One-way in C++ by design, so this refusal latches until a resync;
    /// that is the direction we want, and the daemon's own log says the
    /// remedy.
    Degraded,
    /// `synchronized` is false — it has never caught up since start.
    NeverSynchronized,
    /// No peers. A daemon with nobody to learn from is not tracking the
    /// chain, whatever a sticky flag from an earlier epoch still says.
    NoPeers,
}

/// What one `daemon_status` read says about the daemon's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TipReading {
    /// The daemon is following the chain and its top block is at this height.
    Synced(BlockHeight),
    /// The daemon said something that means its height is not the chain's.
    /// The gate must not centre on it, so the cache is cleared.
    NotFollowing(NotFollowing),
    /// The reply could not be read as either. Treated as "no news": the
    /// producer stamps nothing and the held tip ages out on schedule, so a
    /// single malformed or dropped reply does not refuse challenges.
    Unusable,
}

/// Read one `daemon_status` reply into a [`TipReading`].
///
/// # The sync predicate, and why one flag is not enough
///
/// `synchronized` was **sticky** on the C++ daemon this reading was written
/// against: in `cryptonote_protocol_handler.inl` (deleted 2026-11-05) the
/// backing `m_synchronized` was written exactly twice — the constructor, and
/// a one-way `compare_exchange_strong(expected, true)`. Nothing ever stored
/// `false`: not a disconnect, not a pop, not a refused reorg. A once-synced
/// daemon that later lost every peer therefore kept reporting
/// `synchronized: true` at a frozen height, forever. Stamping that as fresh
/// re-creates the unbounded lag `WSS-24` exists to remove — by a different
/// route, and silently, because every signature stays well-formed.
///
/// The Rust daemon's flag reads `SyncState::Synced` off the chain-sync
/// watch (`shekyl-node` `facts.rs`) and falls back to `NoView` or `Behind`
/// when the view is lost, so it does revert. The wallet keeps the
/// discipline anyway: a flag is one daemon's reading of its own sync, and
/// the facts below are what this persona can check. So `synchronized` is
/// treated as **necessary and not sufficient**, and joined by facts that
/// can go false again:
///
/// | fact | reverts? |
/// |---|---|
/// | `synchronized` | on the Rust daemon, yes; the wallet does not rely on it |
/// | `offline` | yes |
/// | `degraded` | never (one-way, refusing) |
/// | `peered` | yes |
///
/// All four are Health, which the daemon tells every caller, so none
/// depends on what this connection has been granted.
///
/// The sync **verdict** is the daemon's flag, read from the one
/// [`DaemonHealth`](crate::engine::traits::daemon::DaemonHealth) projection
/// the submit ladder and `SyncedChainFacts` also read (`WSS-Q14`). This
/// reading adds, on top of it, the facts that can go false again.
///
/// **`height` against `target_height` is not one of them.** It would
/// revert, which is what this table wants, but the target is the tallest
/// chain any peer has claimed in a handshake: one peer advertising a tall
/// chain would stop this persona serving. Until `CORE_RPC_VERSION` 3.46 a
/// `BehindItsTarget` refusal stood here; it could not fire, because a
/// synchronized daemon then wrote its target as `0`, and it went with that
/// sentinel rather than become a lever (`daemon/synced_chain_facts.rs`,
/// module docs).
///
/// # The peer check reads `peered`
///
/// `peered` is in Health, a handshaken session on any connector, told to
/// every caller (RK-D14), so the check holds on every daemon whatever this
/// connection was granted. The Status part's connection counts are the
/// daemon's to withhold, and a withheld count is not a zero; they are not
/// read here.
///
/// # Untrusted input
///
/// The reply is the shared [`DaemonStatus`], which decodes strictly: a
/// document missing a member, carrying one of the wrong shape, or carrying
/// one this build does not know is not a reply, and [`refresh_tip_once`]
/// reads it as [`TipReading::Unusable`] — the held tip ages out as for a
/// dropped poll. A refusal is an error object, never a body beside a status
/// word, so there is no refused document whose members could be read as
/// evidence; it too is [`TipReading::Unusable`] — it says nothing about the
/// tip either way, so the held one ages out instead of being cleared by a
/// refusal at startup.
pub(crate) fn tip_reading_from_status(status: &DaemonStatus) -> TipReading {
    // The members the watchdog and the sync witness also read are projected
    // in the one shared place.
    let health = health_from_daemon_status(status);
    let chain_height = ChainCount::from_raw(health.height);

    // Ordered most-specific first, so the reported cause is the one an
    // operator can act on: "offline" is actionable, "never synchronized" is
    // the symptom it would also produce.
    let cause = if health.p2p.is_offline() {
        Some(NotFollowing::Offline)
    } else if status.degraded {
        Some(NotFollowing::Degraded)
    } else if !health.synchronized {
        Some(NotFollowing::NeverSynchronized)
    } else if health.p2p.has_peers() == Some(false) {
        Some(NotFollowing::NoPeers)
    } else {
        None
    };
    if let Some(cause) = cause {
        return TipReading::NotFollowing(cause);
    }

    // Chain height -> top block height, through the type: an empty chain has
    // no top block to stamp.
    match chain_height.tip() {
        Some(top_block) => TipReading::Synced(top_block),
        None => TipReading::Unusable,
    }
}

/// Read the tip once and stamp it, returning what was read.
///
/// Separate from the loop so the wiring can take a first reading *before* the
/// host binds its endpoint, rather than serving a refusal until the first
/// tick.
pub(crate) async fn refresh_tip_once<R>(rpc: &R, tip: &DaemonTipCache) -> TipReading
where
    R: PersonaIsolatedTransport,
{
    let reading = match rpc.call::<wire::DaemonStatus>(NoParams).await {
        Ok(status) => tip_reading_from_status(&status),
        // An unreachable daemon is absence of a fact, not a fact — and so is
        // a reply that is not the contract: stamp nothing and let the held
        // tip age out (`DaemonTipCache`'s contract).
        Err(_) => TipReading::Unusable,
    };
    match reading {
        TipReading::Synced(top_block_height) => tip.stamp_synced(top_block_height),
        TipReading::NotFollowing(_) => tip.stamp_not_following(),
        TipReading::Unusable => {}
    }
    reading
}

/// Poll the daemon's tip on `interval` for as long as anyone can still read
/// the cache.
///
/// # Why a `Weak` and not a cancellation token
///
/// This task's job exists exactly as long as a consumer of the cache exists,
/// and the `Weak` makes that a structural fact rather than a wiring
/// discipline. The serving task holds the only strong references (through
/// `PersonaServing` into the host's `HostSigner`); when it ends — cancelled,
/// failed to start, or dropped — the last `Arc` goes with it and the next
/// tick finds nothing to upgrade and returns. There is no token to forget to
/// cancel and no path on which the refresher outlives its reader by more
/// than one interval.
///
/// The alternative — threading the transport down through
/// [`spawn_serving_task`](super::task::spawn_serving_task) so the loop could
/// share the serving cancellation token — would add a transport type
/// parameter to the serving lifecycle in exchange for a bound the `Weak`
/// already gives.
pub(crate) async fn run_daemon_tip_refresher<R>(
    rpc: R,
    tip: Weak<DaemonTipCache>,
    interval: Duration,
) where
    R: PersonaIsolatedTransport,
{
    let mut ticker = tokio::time::interval(interval);
    // A refresh that overruns its slot must not then fire a burst of catch-up
    // reads: the tip is a level, not a stream, and only the latest matters.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let Some(tip) = tip.upgrade() else { return };
        let _reading = refresh_tip_once(&rpc, &tip).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::task::CLAIM_SOURCE_TIMEOUT;
    use super::*;
    use serde_json::json;
    use shekyl_archival_retention::pass_anchor::PASS_ANCHOR_LAG_BLOCKS;
    use shekyl_rpc_client::{Rpc, RpcError};

    /// A transport that answers every call with one canned document.
    ///
    /// `PersonaIsolatedTransport`'s doc permits test implementations
    /// explicitly ("the pin is against production misuse, not test
    /// plumbing"), and without one the dispatch below — which reading stamps
    /// what — has no oracle at all: every other test in this module calls
    /// [`reading_of`] and then stamps by hand, which is the thing
    /// under test doing the test's job.
    #[derive(Clone)]
    struct CannedRpc(std::sync::Arc<Result<Vec<u8>, RpcError>>);

    impl CannedRpc {
        /// A well-formed JSON-RPC reply carrying `result`.
        fn replying(result: &serde_json::Value) -> Self {
            Self::document(&json!({ "jsonrpc": "2.0", "id": 0, "result": result }))
        }

        /// Any document, as the daemon's bytes.
        fn document(document: &serde_json::Value) -> Self {
            Self(std::sync::Arc::new(Ok(document.to_string().into_bytes())))
        }

        /// A reply that is not the envelope the caller expects.
        fn garbage() -> Self {
            Self(std::sync::Arc::new(Ok(b"not json".to_vec())))
        }

        /// A daemon that could not be reached at all.
        fn unreachable() -> Self {
            Self(std::sync::Arc::new(Err(RpcError::ConnectionError(
                "test: no daemon".to_string(),
            ))))
        }
    }

    impl Rpc for CannedRpc {
        fn post(
            &self,
            _route: &str,
            _body: Vec<u8>,
        ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
            let answer = match &*self.0 {
                Ok(bytes) => Ok(bytes.clone()),
                Err(RpcError::ConnectionError(m)) => Err(RpcError::ConnectionError(m.clone())),
                Err(_) => Err(RpcError::InternalError("test".to_string())),
            };
            async move { answer }
        }
    }

    impl PersonaIsolatedTransport for CannedRpc {}

    /// A complete `daemon_status` reply with `over`'s members laid over it.
    ///
    /// The shared type refuses a document missing any member, so a test
    /// states the members it is about and this supplies the rest: a
    /// synchronized daemon whose tip is 9_000, with peers. A member given as
    /// JSON `null` is **removed**, which is how a test builds a reply that
    /// is missing one; [`offline_reply`] writes the `null`s an offline
    /// daemon sends.
    fn reply(over: &serde_json::Value) -> serde_json::Value {
        let mut doc = crate::engine::daemon::synced_chain_facts::DaemonStatusDocument {
            chain_count: ChainCount::from_raw(9_001),
            target_height: None,
            synchronized: true,
            top_hash: shekyl_types::BlockHash::from_bytes([0xAB; 32]),
            peered: true,
        }
        .to_value();
        let members = doc.as_object_mut().expect("a reply is an object");
        for (key, value) in over.as_object().expect("an overlay is an object") {
            if value.is_null() {
                members.remove(key);
            } else {
                members.insert(key.clone(), value.clone());
            }
        }
        doc
    }

    /// An offline daemon's reply: it says so in Health, and `peered` and the
    /// peer counts are `null`, as they are while P2P is off.
    fn offline_reply(height: u64) -> serde_json::Value {
        let mut doc = reply(&json!({ "height": height, "offline": true }));
        doc["peered"] = serde_json::Value::Null;
        doc["peer_outbound_count"] = serde_json::Value::Null;
        doc["peer_inbound_count"] = serde_json::Value::Null;
        doc
    }

    /// What [`refresh_tip_once`] reads from a reply: a document that does
    /// not decode is `Unusable`, as it is there.
    fn reading_of_document(document: serde_json::Value) -> TipReading {
        serde_json::from_value::<DaemonStatus>(document).map_or(TipReading::Unusable, |status| {
            tip_reading_from_status(&status)
        })
    }

    /// [`reading_of_document`] over [`reply`] with `over` laid on it.
    fn reading_of(over: &serde_json::Value) -> TipReading {
        reading_of_document(reply(over))
    }

    /// A refusal envelope of class not-ready.
    fn not_ready() -> serde_json::Value {
        json!({
            "code": -32004, "message": "not ready",
            "data": {"code": "daemon.unready", "parameter": {}, "message": "not ready"},
        })
    }

    /// The block target this suite reasons in, matching the mainnet default.
    const BLOCK_TARGET: u64 = 120;

    /// The stamp, pinned on its own axis.
    ///
    /// This is the most dangerous line in the module: `daemon_status.height`
    /// is the TIP's height, while the shared projection carries the chain's
    /// count, one more. Admission centres its window on
    /// `predecessor_height - 720`, a BLOCK height. An off-by-one here
    /// centres P's gate one block high and makes it sign anchors the daemon
    /// then refuses — silently, because every signature is still
    /// well-formed and every counter still reads zero.
    ///
    /// Asserted in both directions so a later refactor that drops the
    /// conversion back from the count cannot pass: the reading must equal the
    /// wire's tip AND must not equal the count derived from it.
    #[test]
    fn a_synced_daemon_reads_as_its_tip_not_the_count() {
        const TIP: u64 = 9_000;

        let reading = reading_of(&json!({ "height": TIP }));
        assert_eq!(
            reading,
            TipReading::Synced(BlockHeight::from_raw(TIP)),
            "the gate's height is the tip"
        );
        assert_ne!(
            reading,
            TipReading::Synced(BlockHeight::from_raw(TIP + 1)),
            "stamping the count centres the gate one block high"
        );
    }

    /// And the stamp survives the whole producer path, not just the parse:
    /// what reaches the cache is the block height too.
    #[tokio::test]
    async fn the_conversion_reaches_the_cache_not_only_the_reading() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        let rpc = CannedRpc::replying(&reply(&json!({ "height": 9_000 })));
        refresh_tip_once(&rpc, &tip).await;
        assert_eq!(
            tip.height(),
            Some(BlockHeight::from_raw(9_000)),
            "a gate reading 9_001 would sign anchors admission refuses"
        );
    }

    /// A daemon that has never caught up says so, and is not followed.
    #[test]
    fn a_daemon_that_never_synchronized_is_not_followed() {
        assert_eq!(
            reading_of(&json!({ "height": 4, "synchronized": false })),
            TipReading::NotFollowing(NotFollowing::NeverSynchronized)
        );
    }

    /// **A target a peer claimed does not stop this persona serving.** The
    /// daemon says it is synchronized; its target is whatever the tallest
    /// claim in a handshake was. A refusal on a height below the target
    /// would be a lever any peer could pull, so the target decides nothing.
    ///
    /// The edit that turns this red is a height comparison coming back.
    #[test]
    fn a_target_above_the_height_does_not_stop_a_synchronized_daemon_being_followed() {
        for target in [8_999u64, 9_000, 9_500, 12_000, u64::MAX] {
            assert_eq!(
                reading_of(&json!({ "height": 8_999, "target_height": target })),
                TipReading::Synced(BlockHeight::from_raw(8_999)),
                "target {target}"
            );
        }
    }

    /// The reading's sync verdict is the daemon's flag (`WSS-Q14`), whatever
    /// the heights say: over tuples that include a target above the height,
    /// one below it and none, `Synced` iff `synchronized`.
    #[test]
    fn the_sync_verdict_is_the_daemons_flag() {
        for (height, target, synchronized) in [
            (4, None, false),
            (8_999, Some(9_499), true),
            (9_499, Some(9_499), true),
            (9_000, None, true),
            (9, Some(4), false),
            (9, Some(49), false),
            (6, Some(0), true),
        ] {
            let mut over = json!({ "height": height, "synchronized": synchronized });
            if let Some(target) = target {
                over["target_height"] = json!(target);
            }
            let reading = reading_of(&over);
            assert_eq!(
                matches!(reading, TipReading::Synced(_)),
                synchronized,
                "({height}, {target:?}, {synchronized}) -> {reading:?}"
            );
        }
    }

    /// Absences, each in its named direction.
    #[test]
    fn absent_fields_take_their_named_directions() {
        assert_eq!(
            reading_of(&json!({ "height": null })),
            TipReading::Unusable,
            "no height is not height 0"
        );
        assert_eq!(
            reading_of(&json!({ "synchronized": null })),
            TipReading::Unusable,
            "a reply without `synchronized` is not the contract; it is not read \
             as synchronized, and not as a daemon that said it was not"
        );
        assert_eq!(
            reading_of(&json!({ "target_height": null })),
            TipReading::Unusable,
            "a reply without `target_height` is not the contract. The member is \
             required and may be null; absent is neither (RK-D23)"
        );
        assert_eq!(
            reading_of(&json!({ "height": "nope" })),
            TipReading::Unusable,
            "an unparseable height is never silently defaulted"
        );
    }

    /// The genesis block is a tip: height 0 on the wire is a one-block
    /// chain, stamped at 0.
    #[test]
    fn the_genesis_tip_is_stamped_at_zero() {
        assert_eq!(
            reading_of(&json!({ "height": 0 })),
            TipReading::Synced(BlockHeight::from_raw(0))
        );
    }

    /// An `Unusable` reading leaves a held tip alone; a `NotFollowing` one
    /// clears it. This is the distinction the whole no-slash-on-a-blip
    /// argument rests on, asserted through the stamping path rather than
    /// the cache's own unit tests.
    #[test]
    fn unusable_holds_the_tip_and_syncing_clears_it() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(BlockHeight::from_raw(9_000));

        // What `refresh_tip_once` does for each reading, without a transport.
        assert_eq!(reading_of(&json!({"height": "nope"})), TipReading::Unusable);
        assert_eq!(
            tip.height(),
            Some(BlockHeight::from_raw(9_000)),
            "an unreadable reply stamps nothing"
        );

        tip.stamp_not_following();
        assert_eq!(tip.height(), None);
    }

    /// The two timings are derived from the block target, and the cadence is
    /// strictly inside the age bound — otherwise a single missed poll would
    /// expire the tip.
    #[test]
    fn the_cadence_is_derived_and_strictly_inside_the_age_bound() {
        let max_age = tip_max_age(BLOCK_TARGET);
        let interval = tip_refresh_interval(BLOCK_TARGET);
        assert_eq!(max_age, Duration::from_secs(120));
        assert_eq!(interval, Duration::from_secs(30));
        assert!(
            interval * TIP_REFRESH_INTERVAL_DIVISOR <= max_age,
            "the cache must not expire before the poll that would refresh it"
        );
        // The interval must not ask for a poll shorter than one poll is
        // allowed to take. This is the floor the age-bound table names, and
        // it is what makes budgets at or below 1e-5 incoherent without also
        // revisiting the divisor.
        assert!(
            interval >= CLAIM_SOURCE_TIMEOUT,
            "a refresh interval below the RPC timeout cannot be honoured"
        );
        // The bound is stated in block targets, not seconds: changing the
        // chain's block target moves it, and no seconds literal survives in
        // the derivation.
        assert_eq!(
            tip_max_age(BLOCK_TARGET * 2),
            max_age * 2,
            "the bound tracks the block target"
        );
    }

    /// The residual the age bound leaves is a probability, and the doc
    /// states it. This pins the model's arithmetic so the table cannot
    /// drift from the constant it justifies: at the bound the cache is one
    /// block target old, so the missed-block count is Poisson(1) and the
    /// gate is pushed out when more than `L` arrive.
    #[test]
    fn the_documented_residual_matches_the_poisson_model() {
        // age / T at the bound. `u32::from` then `f64::from` are both
        // lossless, so the model's input cannot silently round.
        let targets = u32::try_from(TIP_MAX_AGE_BLOCK_TARGETS)
            .expect("the age bound is a small multiple of the block target");
        let lambda = f64::from(targets);
        let l = u32::try_from(PASS_ANCHOR_LAG_BLOCKS.to_raw()).expect("L is small");
        // P(N > L) = 1 - sum_{k=0..L} e^-lambda lambda^k / k!
        let mut term = (-lambda).exp();
        let mut cdf = term;
        for k in 1..=l {
            term *= lambda / f64::from(k);
            cdf += term;
        }
        let residual = 1.0 - cdf;
        assert!(
            (residual - 3.66e-3).abs() < 1e-4,
            "documented 3.7e-3 at the bound, computed {residual:e}"
        );
        assert!(
            residual < 1e-2,
            "a residual above 1% would make the bound indefensible without a ruling"
        );
    }

    // ── The dispatch: which reading stamps what ─────────────────────────
    //
    // These are the only tests that run `refresh_tip_once` itself. Without
    // them the match arms are unpinned: turning `Unusable => {}` into
    // `Unusable => tip.stamp_not_following()` leaves every other test in this file
    // green while re-creating the slash WSS-24 removes.

    #[tokio::test]
    async fn a_synced_reply_stamps_the_top_block_height() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        let rpc = CannedRpc::replying(&reply(&json!({ "height": 9_000 })));
        assert_eq!(
            refresh_tip_once(&rpc, &tip).await,
            TipReading::Synced(BlockHeight::from_raw(9_000))
        );
        assert_eq!(
            tip.height(),
            Some(BlockHeight::from_raw(9_000)),
            "the reading reached the cache"
        );
    }

    #[tokio::test]
    async fn a_reply_that_stopped_following_clears_a_held_tip() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(BlockHeight::from_raw(9_000));
        let rpc = CannedRpc::replying(&offline_reply(9_000));
        assert_eq!(
            refresh_tip_once(&rpc, &tip).await,
            TipReading::NotFollowing(NotFollowing::Offline)
        );
        assert_eq!(
            tip.height(),
            None,
            "a daemon that says it is offline must invalidate the tip it gave before"
        );
    }

    /// The two "no news" cases, and the property that makes them one case: a
    /// held tip SURVIVES. This is the arm a mutation would flip, and the
    /// reason it must not is that an honest persona would otherwise be
    /// slashed for a dropped loopback poll.
    #[tokio::test]
    async fn an_unreadable_or_unreachable_daemon_leaves_the_held_tip_alone() {
        for (name, rpc) in [
            ("a malformed reply", CannedRpc::garbage()),
            ("an unreachable daemon", CannedRpc::unreachable()),
        ] {
            let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
            tip.stamp_synced(BlockHeight::from_raw(9_000));
            assert_eq!(
                refresh_tip_once(&rpc, &tip).await,
                TipReading::Unusable,
                "{name} is not a fact about the tip"
            );
            assert_eq!(
                tip.height(),
                Some(BlockHeight::from_raw(9_000)),
                "{name} must not refuse challenges the held tip can still gate"
            );
        }
    }

    /// And "no news" does not manufacture a tip either: nothing stamped
    /// stays nothing stamped.
    #[tokio::test]
    async fn an_unreachable_daemon_does_not_invent_a_tip() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        assert_eq!(
            refresh_tip_once(&CannedRpc::unreachable(), &tip).await,
            TipReading::Unusable
        );
        assert_eq!(tip.height(), None);
    }

    // ── `synchronized` is necessary, not sufficient ─────────────────────
    //
    // Every case below presents `synchronized: true` and differs only in a
    // fact that CAN revert.

    /// The motivating case: a once-synced daemon that has lost every peer
    /// keeps claiming synchronization at a frozen height. Dropping the
    /// `peered` arm turns this green again, which is the whole defect.
    #[test]
    fn a_once_synced_daemon_with_no_peers_is_not_following() {
        assert_eq!(
            reading_of(&json!({ "peered": false })),
            TipReading::NotFollowing(NotFollowing::NoPeers)
        );
    }

    /// **§3.1's defect, pinned shut on this side** (RK-D14). The reply is
    /// from a node with peers whose Status counts read zero: it is followed.
    /// Then the same node behind a daemon that withholds Status altogether,
    /// as it does for a caller without the `status` grant: still followed.
    /// And the control: the same two replies from a node that really has no
    /// peers are `NoPeers`.
    ///
    /// The edit that turns this red: reading the Status counts again.
    #[test]
    fn a_node_with_peers_is_followed_whatever_status_shows() {
        for peered in [true, false] {
            let expected = if peered {
                TipReading::Synced(BlockHeight::from_raw(9_000))
            } else {
                TipReading::NotFollowing(NotFollowing::NoPeers)
            };
            let document = crate::engine::daemon::synced_chain_facts::DaemonStatusDocument {
                chain_count: ChainCount::from_raw(9_001),
                target_height: None,
                synchronized: true,
                top_hash: shekyl_types::BlockHash::from_bytes([0xAB; 32]),
                peered,
            };
            assert_eq!(
                tip_reading_from_status(&document.to_reply()),
                expected,
                "peered {peered}, Status zeroed"
            );
            assert_eq!(
                tip_reading_from_status(&document.to_reply_status_withheld()),
                expected,
                "peered {peered}, Status withheld"
            );
        }
    }

    /// The Status counts decide nothing: twenty connections reported and
    /// `peered: false` is a node with nobody through a handshake, and it is
    /// not followed.
    #[test]
    fn the_status_counts_do_not_stand_in_for_peered() {
        assert_eq!(
            reading_of(&json!({
                "peered": false, "peer_outbound_count": 8, "peer_inbound_count": 12
            })),
            TipReading::NotFollowing(NotFollowing::NoPeers)
        );
    }

    /// `degraded` is the daemon saying it knowingly is not on the heaviest
    /// chain it has seen. It is one-way — which is the safe direction here,
    /// because the refusal should latch until a resync.
    #[test]
    fn a_degraded_daemon_is_not_following_however_synchronized_it_claims_to_be() {
        assert_eq!(
            reading_of(&json!({ "degraded": true })),
            TipReading::NotFollowing(NotFollowing::Degraded)
        );
    }

    #[test]
    fn an_offline_daemon_is_not_following() {
        assert_eq!(
            reading_of_document(offline_reply(9_000)),
            TipReading::NotFollowing(NotFollowing::Offline)
        );
    }

    /// The refusal triggers, when false, do not refuse — and a reply that
    /// omits one is not read as if it had said false. A daemon whose reply
    /// lacks a member is a daemon at another version: its reply is
    /// `Unusable`, which holds the tip and lets it age out, and never
    /// `NotFollowing`, which would clear it. That keeps an upgrade skew from
    /// becoming a refusal on every poll without pretending to know a fact
    /// the reply did not carry.
    #[test]
    fn false_refusal_triggers_do_not_refuse_and_absent_ones_are_not_read() {
        assert_eq!(
            reading_of(&json!({ "offline": false, "degraded": false, "peered": true })),
            TipReading::Synced(BlockHeight::from_raw(9_000)),
        );
        for trigger in ["offline", "degraded", "peered"] {
            assert_eq!(
                reading_of(&json!({ trigger: null })),
                TipReading::Unusable,
                "a reply without `{trigger}` is not the contract"
            );
        }
    }

    /// Through the real producer, not just the parse: a peerless daemon
    /// CLEARS a held tip rather than refreshing it. The stale height must
    /// not be stamped fresh.
    #[tokio::test]
    async fn a_peerless_daemon_clears_the_tip_instead_of_restamping_it() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(BlockHeight::from_raw(9_000));
        let rpc = CannedRpc::replying(&reply(&json!({ "peered": false })));
        assert_eq!(
            refresh_tip_once(&rpc, &tip).await,
            TipReading::NotFollowing(NotFollowing::NoPeers)
        );
        assert_eq!(
            tip.height(),
            None,
            "a frozen height must not be stamped fresh forever"
        );
    }

    // ── A refusal is not evidence ────────────────────────────────────────

    /// A refusal beside a plausible body. Every member of the body would
    /// read as a healthy synced daemon; a document carrying both a result
    /// and an error is neither, and nothing in it is evidence. Reading the
    /// result out of it turns this green — with the slash-sensitive cache
    /// refreshed from a refusal.
    #[tokio::test]
    async fn a_refusal_beside_a_plausible_body_is_unusable() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        let rpc = CannedRpc::document(&json!({
            "jsonrpc": "2.0", "id": 0,
            "result": reply(&json!({ "height": 12_345 })),
            "error": not_ready(),
        }));
        assert_eq!(refresh_tip_once(&rpc, &tip).await, TipReading::Unusable);
        assert_eq!(tip.height(), None, "nothing stamped from the body");
    }

    /// Through the producer: a not-ready refusal HOLDS a held tip rather
    /// than clearing it. A refusal is the absence of a fact about the tip,
    /// so it takes the dropped-poll path and ages out on schedule.
    #[tokio::test]
    async fn a_daemon_that_is_not_ready_holds_the_tip_it_cannot_speak_to() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(BlockHeight::from_raw(9_000));
        let rpc = CannedRpc::document(&json!({
            "jsonrpc": "2.0", "id": 0, "error": not_ready(),
        }));
        assert_eq!(refresh_tip_once(&rpc, &tip).await, TipReading::Unusable);
        assert_eq!(
            tip.height(),
            Some(BlockHeight::from_raw(9_000)),
            "neither cleared by the refusal nor refreshed"
        );
    }
}
