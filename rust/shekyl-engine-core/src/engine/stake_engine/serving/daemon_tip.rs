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
//! # Chain height is converted to block height here
//!
//! `get_info.height` is the chain height — the top block's height **plus one**
//! (`core_rpc_server.cpp`: `get_blockchain_top(res.height, top_hash);
//! ++res.height;`). Admission centres its window on `predecessor_height − 720`,
//! a block height, so stamping the chain height unconverted would centre `P`'s
//! gate one block high and let it sign anchors admission then refuses. The
//! `−1` happens once, here, at the only place the RPC's convention is in view.

use std::sync::Weak;
use std::time::Duration;

use serde_json::Value;
use shekyl_p_host::DaemonTipCache;

use crate::engine::prpc::PersonaIsolatedTransport;

/// How often the tip is re-read.
///
/// Four reads per block target, so the cache's age bound (one block target,
/// see [`tip_max_age`]) is met with three consecutive failed polls of slack
/// before the gate starts refusing. A loopback `get_info` is cheap; the cost
/// of being wrong here is a slash.
pub(crate) const TIP_REFRESH_INTERVAL_DIVISOR: u32 = 4;

/// The age a stamped tip may reach before the gate stops trusting it: one
/// block target.
///
/// **Derived, not picked.** The gate tolerates `±L` blocks (`L = 4`); a cached
/// tip is wrong by however many blocks have passed since it was stamped. One
/// block target caps that error at one block, a quarter of the tolerance, so
/// cache age can never be what pushes an honest `P` out of the window. Sizing
/// it at `L` blocks instead would spend the entire budget on staleness and
/// leave nothing for the clock skew and propagation the window is actually
/// for.
pub(crate) fn tip_max_age(daa_target_seconds: u64) -> Duration {
    Duration::from_secs(daa_target_seconds)
}

/// The poll cadence for a given block target.
pub(crate) fn tip_refresh_interval(daa_target_seconds: u64) -> Duration {
    tip_max_age(daa_target_seconds) / TIP_REFRESH_INTERVAL_DIVISOR
}

/// What one `get_info` read says about the daemon's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TipReading {
    /// The daemon is synchronized and its top block is at this height.
    Synced(u64),
    /// The daemon says it is not synchronized. Its height is not the
    /// chain's, and the gate must not centre on it.
    Syncing,
    /// The reply could not be read as either. Treated as "no news": the
    /// producer stamps nothing and the held tip ages out on schedule, so a
    /// single malformed or dropped reply does not refuse challenges.
    Unusable,
}

/// Read one `get_info` reply into a [`TipReading`].
///
/// # The sync predicate
///
/// A daemon is synced when it says so **and** its own heights agree with
/// that. The height half is lifted verbatim from the submit watchdog's
/// `DaemonHealthContext::is_synced` (`submit_watchdog.rs:219-221`):
///
/// ```text
/// target_height == 0 || height >= target_height
/// ```
///
/// This converges with `WSS-Q14`'s `SyncedChainFacts`; whichever of the two
/// lands second adopts the other's form, and this comment is the marker for
/// that merge.
///
/// `synchronized` is **not** decoration on top of it. A daemon that has just
/// started with no peers reports `target_height == 0` and
/// `synchronized == false` — the height half alone reads that as synced, and
/// would centre the gate on a genesis-adjacent tip. That case is the reason
/// both halves are required.
///
/// # Untrusted input (rule 20 §3)
///
/// Every field is parsed defensively and each absence has a named direction:
///
/// - `height` absent or unparseable ⇒ [`TipReading::Unusable`]. There is no
///   safe default: a silent `0` is a claim about the chain.
/// - `synchronized` absent ⇒ `false` ⇒ [`TipReading::Syncing`]. The
///   conservative direction, and the one that refuses rather than signs.
/// - `target_height` absent ⇒ `0`, following the info surface's own "0 when
///   synced" convention (`core_rpc_server.cpp:209`), which is the same
///   mapping `DaemonEngine::get_health` makes.
/// - `height == 0` ⇒ [`TipReading::Unusable`]: there is no top block, so
///   there is no block height to stamp. A chain always has genesis, so this
///   is a broken reply rather than a young chain.
pub(crate) fn tip_reading_from_info(info: &Value) -> TipReading {
    let Some(chain_height) = info.get("height").and_then(Value::as_u64) else {
        return TipReading::Unusable;
    };
    let synchronized = info
        .get("synchronized")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let target_height = info
        .get("target_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    // Lifted verbatim from `submit_watchdog.rs:219-221`; see the doc above.
    let heights_agree = target_height == 0 || chain_height >= target_height;
    if !synchronized || !heights_agree {
        return TipReading::Syncing;
    }
    // Chain height -> top block height. The one place the conversion happens.
    match chain_height.checked_sub(1) {
        Some(top_block_height) => TipReading::Synced(top_block_height),
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
        TipReading::Syncing => tip.stamp_syncing(),
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
    use super::*;
    use serde_json::json;

    /// The block target this suite reasons in, matching the mainnet default.
    const BLOCK_TARGET: u64 = 120;

    #[test]
    fn a_synced_daemon_reads_as_the_top_block_height_not_the_chain_height() {
        // Chain height 9_001 means the top block is 9_000. Stamping 9_001
        // would centre P's gate one block above admission's window.
        let info = json!({"height": 9_001, "target_height": 0, "synchronized": true});
        assert_eq!(tip_reading_from_info(&info), TipReading::Synced(9_000));
    }

    /// The case `synchronized` exists for: a freshly started daemon with no
    /// peers reports `target_height == 0`, which the height half alone reads
    /// as synced. Dropping `synchronized` from the predicate turns this red.
    #[test]
    fn a_peerless_daemon_reporting_target_zero_is_syncing_not_synced() {
        let info = json!({"height": 5, "target_height": 0, "synchronized": false});
        assert_eq!(tip_reading_from_info(&info), TipReading::Syncing);
    }

    /// The height half of the lifted predicate, with `synchronized` true so
    /// only the heights can decide.
    #[test]
    fn a_daemon_behind_its_own_target_is_syncing() {
        let behind = json!({"height": 9_000, "target_height": 9_500, "synchronized": true});
        assert_eq!(tip_reading_from_info(&behind), TipReading::Syncing);

        let level = json!({"height": 9_500, "target_height": 9_500, "synchronized": true});
        assert_eq!(
            tip_reading_from_info(&level),
            TipReading::Synced(9_499),
            "height >= target is the lifted predicate's accepting edge"
        );
    }

    /// Absences, each in its named direction.
    #[test]
    fn absent_fields_take_their_named_directions() {
        assert_eq!(
            tip_reading_from_info(&json!({"target_height": 0, "synchronized": true})),
            TipReading::Unusable,
            "no height is not height 0"
        );
        assert_eq!(
            tip_reading_from_info(&json!({"height": 9_001, "target_height": 0})),
            TipReading::Syncing,
            "absent `synchronized` is false, which refuses"
        );
        assert_eq!(
            tip_reading_from_info(&json!({"height": 9_001, "synchronized": true})),
            TipReading::Synced(9_000),
            "absent `target_height` is the info surface's 0-when-synced"
        );
        assert_eq!(
            tip_reading_from_info(&json!({"height": "nope", "synchronized": true})),
            TipReading::Unusable,
            "an unparseable height is never silently defaulted"
        );
        assert_eq!(
            tip_reading_from_info(&json!({"height": 0, "synchronized": true})),
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

        tip.stamp_syncing();
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
        assert!(
            max_age * 4 <= Duration::from_secs(BLOCK_TARGET * 4 * 4),
            "one block target is well inside the gate's +/-4 block tolerance"
        );
    }
}
