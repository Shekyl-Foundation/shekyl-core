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
//! # `get_info` is served by C++ today, and that is why the seam matters
//!
//! The reply this module parses comes from the **C++** daemon
//! (`src/rpc/core_rpc_server.cpp` — `synchronized` at its `on_get_info`,
//! `target_height` under the "0 when synchronized" rule). There is no
//! `get_info` handler in `shekyl-daemon-rpc`: the Rust RPC tree has
//! `get_version` and `get_height`, not this method.
//!
//! Per the standing ruling (2026-09-19) we do not build *to* the C++ daemon,
//! and daemon elements still in flux stay behind a seam the wallet owns. That
//! is what [`PersonaIsolatedTransport`] and [`TipReading`] are here — the
//! wallet's own transport type and its own typed reading. The wire shape is
//! known in two places by design: the fields the submit watchdog and the sync
//! witness also read decode in the shared `health_from_get_info` (`WSS-Q14`),
//! and the serving-only flags in [`tip_reading_from_info`]. The
//! response shape **will move** when DRS lands the Rust chain store, and when
//! it does this one function changes while the gate, the cache, and every
//! test above them do not. The seam is load-bearing, not incidental.
//!
//! # Chain height is converted to block height here
//!
//! `get_info.height` is the chain height — the top block's height **plus one**
//! (`core_rpc_server.cpp`: `get_blockchain_top(res.height, top_hash);
//! ++res.height;`). Admission centres its window on `predecessor_height − 720`,
//! a block height, so stamping the chain height unconverted would centre `P`'s
//! gate one block high and let it sign anchors admission then refuses. The
//! `−1` happens once, here, through `ChainCount::tip`, at the only place the
//! RPC's convention is in view for this gate.

use std::sync::Weak;
use std::time::Duration;

use serde_json::Value;
use shekyl_p_host::DaemonTipCache;
use shekyl_rpc_types::RpcStatus;
use shekyl_types::ChainCount;

use crate::engine::daemon::synced_chain_facts::{
    daemon_reports_synchronized, health_from_get_info,
};

use crate::engine::block_fetch::refuse_unless_ok;
use crate::engine::prpc::PersonaIsolatedTransport;

/// How often the tip is re-read, as a divisor of [`tip_max_age`].
///
/// Four reads per age bound, so three consecutive failed polls still leave
/// the gate answering. A loopback `get_info` is cheap; the cost of being
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
    /// Its own `height` is behind its own `target_height`.
    BehindItsTarget,
    /// No peers. A daemon with nobody to learn from is not tracking the
    /// chain, whatever a sticky flag from an earlier epoch still says.
    NoPeers,
}

/// What one `get_info` read says about the daemon's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TipReading {
    /// The daemon is following the chain and its top block is at this height.
    Synced(u64),
    /// The daemon said something that means its height is not the chain's.
    /// The gate must not centre on it, so the cache is cleared.
    NotFollowing(NotFollowing),
    /// The reply could not be read as either. Treated as "no news": the
    /// producer stamps nothing and the held tip ages out on schedule, so a
    /// single malformed or dropped reply does not refuse challenges.
    Unusable,
}

/// Read one `get_info` reply into a [`TipReading`].
///
/// # The sync predicate, and why one flag is not enough
///
/// `synchronized` is **sticky**. In `cryptonote_protocol_handler.inl` the
/// backing `m_synchronized` is written exactly twice — the constructor, and
/// a one-way `compare_exchange_strong(expected, true)`. Nothing ever stores
/// `false`: not a disconnect, not a pop, not a refused reorg. `get_info`
/// then forces `target_height` to `0` whenever that bit is set, so the
/// height half of the predicate is satisfied by construction too.
///
/// A once-synced daemon that later loses every peer therefore keeps
/// reporting `synchronized: true, target_height: 0` at a frozen height,
/// forever. Stamping that as fresh re-creates the unbounded lag `WSS-24`
/// exists to remove — by a different route, and silently, because every
/// signature stays well-formed.
///
/// So the sticky flag is treated as **necessary and not sufficient**, and
/// joined by facts that can go false again:
///
/// | fact | reverts? | zeroed by `--restricted-rpc`? |
/// |---|---|---|
/// | `synchronized` | never (one-way) | no |
/// | `height` vs `target_height` | yes | no |
/// | `offline` | yes | no |
/// | `following_degraded` | never (one-way, refusing) | no |
/// | connection counts | yes | **yes** |
///
/// The sync **verdict** is [`daemon_reports_synchronized`] — the one site
/// (`WSS-Q14`), shared with the submit watchdog's
/// `DaemonHealthContext::is_synced` and with `SyncedChainFacts`. This
/// reading adds, on top of it, the facts that can go false again. The two
/// [`NotFollowing`] members the predicate covers are a *diagnosis* for the
/// operator, each naming the half that failed; neither is a second verdict.
/// Converged in PR #792, which landed second.
///
/// # `--restricted-rpc` zeroes the connection counts *by policy*
///
/// `core_rpc_server.cpp` writes `restricted ? 0 : …` for both connection
/// counts. On a restricted daemon "no peers" and "not telling you" are the
/// same bytes, so requiring `connections > 0` unconditionally would refuse
/// every challenge forever on that configuration — the same slash, moved to
/// a new deployment. The reply carries `restricted`, so the operand is used
/// only where it means something, and the residual is named rather than
/// papered over: **on a restricted daemon the peer check is unavailable**
/// and only `offline` / `following_degraded` remain to contradict the
/// sticky flag.
///
/// # Untrusted input (rule 20 §3)
///
/// Each absence has a named direction, and none of them is the convenient
/// one by accident:
///
/// - `status` absent or not `OK` ⇒ [`TipReading::Unusable`], **checked before
///   any other field is read**. `Rpc::json_rpc_call` only unwraps `result`;
///   it does not enforce the wire's `status`, so a daemon may answer `BUSY`
///   and a plausible body in one document. Nothing in that document is then
///   evidence. The check is [`refuse_unless_ok`] — the one shared refusal
///   every typed RPC consumer here reaches for — and the outcome is
///   *Unusable* rather than *NotFollowing* on purpose: a refusal says nothing
///   about the tip either way, so the held one ages out as for a dropped
///   poll instead of being cleared by a `BUSY` at startup.
/// - `height` absent or unparseable ⇒ [`TipReading::Unusable`]. There is no
///   safe default: a silent `0` is a claim about the chain.
/// - `target_height` absent or unparseable ⇒ [`TipReading::Unusable`], for
///   the same reason in its sharpest form: `0` is the synchronized
///   *sentinel*, so a default would have the decoder manufacture the claim
///   the predicate exists to verify. Both refusals are the shared decoder's
///   (`GetInfoFault::HeightMissing`, `GetInfoFault::TargetHeightMissing`).
/// - `synchronized` absent ⇒ `false` ⇒ refuse. The conservative direction.
/// - `offline`, `following_degraded`, `restricted` absent ⇒ `false`. These
///   are **refusal** triggers, so absent-as-true would refuse every daemon
///   too old to carry the field — a self-inflicted outage on an upgrade skew.
/// - connection counts absent ⇒ `0`, which refuses only when the daemon also
///   said it was unrestricted, i.e. when it claimed the numbers were real.
/// - `height == 0` ⇒ [`TipReading::Unusable`]: no top block to stamp, and a
///   chain always has genesis, so this is a broken reply rather than a young
///   chain.
pub(crate) fn tip_reading_from_info(info: &Value) -> TipReading {
    // Status first, before any field becomes evidence. An absent status is
    // not the contract either — a reply that omits it cannot be refused on
    // it, so it is not accepted on it.
    let Some(status) = info.get("status").and_then(Value::as_str) else {
        return TipReading::Unusable;
    };
    if refuse_unless_ok(&RpcStatus(status.to_owned()), "get_info").is_err() {
        return TipReading::Unusable;
    }
    // The fields the watchdog and the sync witness also read decode in the
    // one shared place; a reply that fails its contract is not evidence.
    let Ok(health) = health_from_get_info(info) else {
        return TipReading::Unusable;
    };
    let flag = |name: &str| info.get(name).and_then(Value::as_bool).unwrap_or(false);
    let chain_height = ChainCount::from_raw(health.height);

    // Ordered most-specific first, so the reported cause is the one an
    // operator can act on: "offline" is actionable, "never synchronized" is
    // the symptom it would also produce.
    let cause = if flag("offline") {
        Some(NotFollowing::Offline)
    } else if flag("following_degraded") {
        Some(NotFollowing::Degraded)
    } else if !health.synchronized {
        Some(NotFollowing::NeverSynchronized)
    } else if !daemon_reports_synchronized(chain_height, health.target_height, health.synchronized)
    {
        // The verdict is the shared predicate's; with the flag already
        // true, the only half left to fail is the heights.
        Some(NotFollowing::BehindItsTarget)
    } else if !flag("restricted") && health.connections == 0 {
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
        Some(top_block) => TipReading::Synced(top_block.to_raw()),
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
    let reading = match rpc.json_rpc_call::<Value>("get_info", None).await {
        Ok(info) => tip_reading_from_info(&info),
        // An unreachable daemon is absence of a fact, not a fact: stamp
        // nothing and let the held tip age out (`DaemonTipCache`'s contract).
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

    /// A transport that answers every call with one canned result.
    ///
    /// `PersonaIsolatedTransport`'s doc permits test implementations
    /// explicitly ("the pin is against production misuse, not test
    /// plumbing"), and without one the dispatch below — which reading stamps
    /// what — has no oracle at all: every other test in this module calls
    /// `tip_reading_from_info` and then stamps by hand, which is the thing
    /// under test doing the test's job.
    #[derive(Clone)]
    struct CannedRpc(std::sync::Arc<Result<Vec<u8>, RpcError>>);

    impl CannedRpc {
        /// A well-formed JSON-RPC reply carrying `result`.
        fn replying(result: &serde_json::Value) -> Self {
            Self(std::sync::Arc::new(Ok(json!({ "result": result })
                .to_string()
                .into_bytes())))
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

    /// The block target this suite reasons in, matching the mainnet default.
    const BLOCK_TARGET: u64 = 120;

    /// The conversion, pinned on its own axis.
    ///
    /// This is the most dangerous line in the module: `get_info.height` is
    /// the CHAIN height (top block + 1), while admission centres its window
    /// on `predecessor_height - 720`, a BLOCK height. An off-by-one here
    /// centres P's gate one block high and makes it sign anchors the daemon
    /// then refuses — silently, because every signature is still
    /// well-formed and every counter still reads zero.
    ///
    /// Asserted in both directions so a later refactor that moves the `-1`
    /// elsewhere, or drops it, cannot pass: the reading must equal the top
    /// block height AND must not equal the chain height it was derived from.
    #[test]
    fn a_synced_daemon_reads_as_the_top_block_height_not_the_chain_height() {
        const CHAIN_HEIGHT: u64 = 9_001;
        const TOP_BLOCK: u64 = CHAIN_HEIGHT - 1;

        let info = json!({
            "height": CHAIN_HEIGHT, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8
        });
        let reading = tip_reading_from_info(&info);
        assert_eq!(
            reading,
            TipReading::Synced(TOP_BLOCK),
            "the gate's height is the top block, not the chain height"
        );
        assert_ne!(
            reading,
            TipReading::Synced(CHAIN_HEIGHT),
            "stamping the chain height unconverted centres the gate one block high"
        );
    }

    /// And the conversion survives the whole producer path, not just the
    /// parse: what reaches the cache is the block height too.
    #[tokio::test]
    async fn the_conversion_reaches_the_cache_not_only_the_reading() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        let rpc = CannedRpc::replying(&json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8
        }));
        refresh_tip_once(&rpc, &tip).await;
        assert_eq!(
            tip.height(),
            Some(9_000),
            "a gate reading 9_001 would sign anchors admission refuses"
        );
    }

    /// The case `synchronized` exists for: a freshly started daemon with no
    /// peers reports `target_height == 0`, which the height half alone reads
    /// as synced. Dropping `synchronized` from the predicate turns this red.
    #[test]
    fn a_peerless_daemon_reporting_target_zero_is_syncing_not_synced() {
        let info = json!({
            "height": 5, "target_height": 0, "status": "OK", "synchronized": false,
            "outgoing_connections_count": 8
        });
        assert_eq!(
            tip_reading_from_info(&info),
            TipReading::NotFollowing(NotFollowing::NeverSynchronized)
        );
    }

    /// The height half of the lifted predicate, with `synchronized` true so
    /// only the heights can decide.
    #[test]
    fn a_daemon_behind_its_own_target_is_syncing() {
        let behind = json!({
            "height": 9_000, "target_height": 9_500, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8
        });
        assert_eq!(
            tip_reading_from_info(&behind),
            TipReading::NotFollowing(NotFollowing::BehindItsTarget)
        );

        let level = json!({
            "height": 9_500, "target_height": 9_500, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8
        });
        assert_eq!(
            tip_reading_from_info(&level),
            TipReading::Synced(9_499),
            "height >= target is the lifted predicate's accepting edge"
        );
    }

    /// The reading's sync verdict IS the shared predicate's (`WSS-Q14`):
    /// over the tuples the watchdog's convergence test uses, including the
    /// peerless fresh daemon, `Synced` iff `daemon_reports_synchronized`.
    ///
    /// The edit that turns this red is a second copy of the conjunction here
    /// drifting from the shared one.
    #[test]
    fn the_sync_verdict_is_the_shared_predicates() {
        for (height, target, synchronized) in [
            (5, 0, false),
            (9_000, 9_500, true),
            (9_500, 9_500, true),
            (9_001, 0, true),
            (10, 5, false),
            (7, 0, true),
        ] {
            let reading = tip_reading_from_info(&json!({
                "height": height, "target_height": target, "status": "OK",
                "synchronized": synchronized, "outgoing_connections_count": 8
            }));
            let expected =
                daemon_reports_synchronized(ChainCount::from_raw(height), target, synchronized);
            assert_eq!(
                matches!(reading, TipReading::Synced(_)),
                expected,
                "({height}, {target}, {synchronized}) -> {reading:?}"
            );
        }
    }

    /// Absences, each in its named direction.
    #[test]
    fn absent_fields_take_their_named_directions() {
        assert_eq!(
            tip_reading_from_info(&json!({
                "target_height": 0, "status": "OK", "synchronized": true,
                "outgoing_connections_count": 8
            })),
            TipReading::Unusable,
            "no height is not height 0"
        );
        assert_eq!(
            tip_reading_from_info(&json!({
                "height": 9_001, "target_height": 0, "status": "OK",
                "outgoing_connections_count": 8
            })),
            TipReading::NotFollowing(NotFollowing::NeverSynchronized),
            "absent `synchronized` is false, which refuses"
        );
        assert_eq!(
            tip_reading_from_info(&json!({
                "height": 9_001, "status": "OK", "synchronized": true,
                "outgoing_connections_count": 8
            })),
            TipReading::Unusable,
            "absent `target_height` is refused, not read as 0: 0 is the synchronized \
             sentinel, and a default would have the decoder manufacture it"
        );
        assert_eq!(
            tip_reading_from_info(
                &json!({"height": "nope", "status": "OK", "synchronized": true,
                "outgoing_connections_count": 8})
            ),
            TipReading::Unusable,
            "an unparseable height is never silently defaulted"
        );
        assert_eq!(
            tip_reading_from_info(&json!({"height": 0, "status": "OK", "synchronized": true,
                "outgoing_connections_count": 8})),
            TipReading::Unusable,
            "chain height 0 has no top block to stamp"
        );
    }

    /// An `Unusable` reading leaves a held tip alone; a `Syncing` one clears
    /// it. This is the distinction the whole no-slash-on-a-blip argument
    /// rests on, asserted through the stamping path rather than the cache's
    /// own unit tests.
    #[test]
    fn unusable_holds_the_tip_and_syncing_clears_it() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(9_000);

        // What `refresh_tip_once` does for each reading, without a transport.
        assert_eq!(
            tip_reading_from_info(&json!({"height": "nope"})),
            TipReading::Unusable
        );
        assert_eq!(
            tip.height(),
            Some(9_000),
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
        let l = u32::try_from(PASS_ANCHOR_LAG_BLOCKS).expect("L is small");
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
        let rpc = CannedRpc::replying(&json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8
        }));
        assert_eq!(
            refresh_tip_once(&rpc, &tip).await,
            TipReading::Synced(9_000)
        );
        assert_eq!(tip.height(), Some(9_000), "the reading reached the cache");
    }

    #[tokio::test]
    async fn a_reply_that_stopped_following_clears_a_held_tip() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(9_000);
        let rpc = CannedRpc::replying(&json!({
            "height": 9_001, "target_height": 12_000, "status": "OK", "synchronized": true
        }));
        assert_eq!(
            refresh_tip_once(&rpc, &tip).await,
            TipReading::NotFollowing(NotFollowing::BehindItsTarget)
        );
        assert_eq!(
            tip.height(),
            None,
            "a daemon that says it is behind must invalidate the tip it gave before"
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
            tip.stamp_synced(9_000);
            assert_eq!(
                refresh_tip_once(&rpc, &tip).await,
                TipReading::Unusable,
                "{name} is not a fact about the tip"
            );
            assert_eq!(
                tip.height(),
                Some(9_000),
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

    // ── F2: the sticky `synchronized` flag is not sufficient ────────────
    //
    // `m_synchronized` is written once, one-way, and never cleared, and
    // `get_info` forces `target_height` to 0 whenever it is set. Every case
    // below therefore presents `synchronized: true, target_height: 0` — a
    // reply the pre-F2 predicate accepted unconditionally — and differs only
    // in a fact that CAN revert.

    /// The motivating case: a once-synced daemon that has lost every peer
    /// keeps claiming synchronization at a frozen height. Dropping the
    /// `connections == 0` arm turns this green again, which is the whole
    /// defect.
    #[test]
    fn a_once_synced_daemon_with_no_peers_is_not_following() {
        let info = json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 0, "incoming_connections_count": 0
        });
        assert_eq!(
            tip_reading_from_info(&info),
            TipReading::NotFollowing(NotFollowing::NoPeers)
        );
    }

    /// One peer of either kind is enough to be learning from somebody; the
    /// check is "nobody at all", not a quorum we have no basis to set.
    #[test]
    fn a_single_peer_of_either_kind_still_counts() {
        for field in ["outgoing_connections_count", "incoming_connections_count"] {
            let info = json!({
                "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
                field: 1
            });
            assert_eq!(
                tip_reading_from_info(&info),
                TipReading::Synced(9_000),
                "{field} = 1 is somebody to learn from"
            );
        }
    }

    /// `--restricted-rpc` zeroes the connection counts BY POLICY
    /// (`core_rpc_server.cpp`: `restricted ? 0 : ...`), so on such a daemon
    /// "no peers" and "not telling you" are the same bytes. Requiring
    /// `connections > 0` unconditionally would refuse every challenge
    /// forever there — the same slash in a new deployment. The reply says
    /// `restricted`, so the operand is used only where it means something.
    #[test]
    fn a_restricted_daemons_zeroed_counts_are_not_read_as_no_peers() {
        let info = json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 0, "incoming_connections_count": 0,
            "restricted": true
        });
        assert_eq!(
            tip_reading_from_info(&info),
            TipReading::Synced(9_000),
            "a policy-zeroed count is an absent fact, not a peerless daemon"
        );
    }

    /// `following_degraded` is the daemon saying it knowingly is not on the
    /// heaviest chain it has seen. It is one-way in C++ — which is the safe
    /// direction here, because the refusal should latch until a resync.
    #[test]
    fn a_degraded_daemon_is_not_following_however_synchronized_it_claims_to_be() {
        let info = json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8, "following_degraded": true
        });
        assert_eq!(
            tip_reading_from_info(&info),
            TipReading::NotFollowing(NotFollowing::Degraded)
        );
    }

    #[test]
    fn an_offline_daemon_is_not_following() {
        let info = json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8, "offline": true
        });
        assert_eq!(
            tip_reading_from_info(&info),
            TipReading::NotFollowing(NotFollowing::Offline)
        );
    }

    /// The three refusal triggers must read as FALSE when absent. A daemon
    /// too old to carry the field would otherwise be refused on every poll —
    /// an outage we would inflict on ourselves at an upgrade skew.
    #[test]
    fn absent_refusal_triggers_do_not_refuse() {
        let info = json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 8
        });
        assert_eq!(
            tip_reading_from_info(&info),
            TipReading::Synced(9_000),
            "absent `offline` / `following_degraded` / `restricted` are all false"
        );
    }

    /// Through the real producer, not just the parse: a peerless daemon
    /// CLEARS a held tip rather than refreshing it. This is the end-to-end
    /// statement of F2 — the stale height must not be stamped fresh.
    #[tokio::test]
    async fn a_peerless_daemon_clears_the_tip_instead_of_restamping_it() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(9_000);
        let rpc = CannedRpc::replying(&json!({
            "height": 9_001, "target_height": 0, "status": "OK", "synchronized": true,
            "outgoing_connections_count": 0, "incoming_connections_count": 0
        }));
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

    // ── The wire status is part of the contract, and it is tested ────────

    /// A refusal carrying a plausible body. Every field below would read as
    /// a healthy synced daemon at 9_000; the status says none of it is
    /// evidence. Dropping the status check turns this green — with the
    /// slash-sensitive cache refreshed from a `BUSY`.
    #[test]
    fn a_non_ok_status_makes_a_plausible_body_unusable() {
        for status in ["BUSY", "Failed", "PAYMENT REQUIRED", "ok", ""] {
            let info = json!({
                "status": status, "height": 9_001, "target_height": 0,
                "synchronized": true, "outgoing_connections_count": 8
            });
            assert_eq!(
                tip_reading_from_info(&info),
                TipReading::Unusable,
                "status {status:?} must not let its body be read as a tip"
            );
        }
    }

    /// The field being absent is not the contract either. A fixture that
    /// omits it cannot fail on it, so a reply that omits it must not pass.
    #[test]
    fn an_absent_status_is_unusable_not_assumed_ok() {
        let info = json!({
            "height": 9_001, "target_height": 0, "synchronized": true,
            "outgoing_connections_count": 8
        });
        assert_eq!(tip_reading_from_info(&info), TipReading::Unusable);
    }

    /// Through the producer: a `BUSY` HOLDS a held tip rather than clearing
    /// it. `check_core_ready()` is false at startup and briefly during some
    /// reorgs; a refusal is the absence of a fact about the tip, so it takes
    /// the dropped-poll path and ages out on schedule.
    #[tokio::test]
    async fn a_busy_daemon_holds_the_tip_it_cannot_speak_to() {
        let tip = DaemonTipCache::new(tip_max_age(BLOCK_TARGET));
        tip.stamp_synced(9_000);
        let rpc = CannedRpc::replying(&json!({
            "status": "BUSY", "height": 12_345, "target_height": 0,
            "synchronized": true, "outgoing_connections_count": 8
        }));
        assert_eq!(refresh_tip_once(&rpc, &tip).await, TipReading::Unusable);
        assert_eq!(
            tip.height(),
            Some(9_000),
            "neither cleared by the refusal nor refreshed from its body"
        );
    }
}
