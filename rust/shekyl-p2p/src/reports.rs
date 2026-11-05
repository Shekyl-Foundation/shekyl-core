// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network's periodic log lines: the engine's lateness per owner class,
//! and the connections admission refused before any handshake. Each is a
//! housekeeping owner on the timing engine (brief §2, rule 7: every wake is
//! an engine owner), served by a task on the transport runtime; it ends when
//! the engine closes or the runtime stops.

use shekyl_timing_engine::{Clock, Handle, MonotonicClock, OwnerClass, OwnerHandle, Tick};
use shekyl_transport_layer::Sockets;

/// A minute, in the engine's nanosecond ticks.
const EVERY_NANOS: u64 = 60_000_000_000;

/// A housekeeping owner for the report `what`, or `None` (logged) when the
/// engine refuses one.
fn owner(engine: &Handle<MonotonicClock>, what: &str) -> Option<OwnerHandle<MonotonicClock>> {
    match engine.register(OwnerClass::Housekeeping) {
        Ok(owner) => Some(owner),
        Err(err) => {
            tracing::error!("the {what} report could not start ({err:?}); it is not logged");
            None
        }
    }
}

/// Arm `owner` a minute from now and wait for the wake. `false` when the
/// engine has closed.
async fn next_minute(owner: &OwnerHandle<MonotonicClock>) -> bool {
    let at = Tick::new(owner.clock().now().get().saturating_add(EVERY_NANOS));
    owner.arm(at).is_ok() && owner.wait_wake_async().await.is_ok()
}

/// Report each owner class's lateness once a minute, at debug. The
/// engine's answer is a blocking receive, so each report runs on the
/// blocking pool. The task ends when the engine closes or the runtime
/// stops.
pub(crate) fn spawn_lateness_report(
    runtime: &tokio::runtime::Handle,
    engine: Handle<MonotonicClock>,
) {
    let Some(owner) = owner(&engine, "lateness") else {
        return;
    };
    drop(runtime.spawn(async move {
        while next_minute(&owner).await {
            let engine = engine.clone();
            match tokio::task::spawn_blocking(move || report_lateness(&engine)).await {
                Ok(true) => {}
                Ok(false) | Err(_) => return,
            }
        }
    }));
}

/// Name the connections refused before any handshake, once a minute and
/// only when there were some: one line per refused connection is what a
/// flood turns into a flood of the log (Rick, 2026-10-30).
///
/// The socket table counted them at the decision
/// ([`Sockets::take_accept_refusals`]). A node at its ceiling refuses
/// connections in ordinary service, so that minute is reported at info. A
/// minute in which the accept rate (D10.3) refused anything is a warning:
/// connections arrived faster than the protocol serves.
pub(crate) fn spawn_refusal_report(
    runtime: &tokio::runtime::Handle,
    engine: &Handle<MonotonicClock>,
    sockets: Sockets,
) {
    let Some(owner) = owner(engine, "refusal") else {
        return;
    };
    drop(runtime.spawn(async move {
        while next_minute(&owner).await {
            let refusals = sockets.take_accept_refusals();
            if !refusals.any() {
                continue;
            }
            if refusals.over_rate() > 0 {
                tracing::warn!(
                    over_host_rate = refusals.over_host_rate,
                    over_connector_rate = refusals.over_connector_rate,
                    inbound_closed = refusals.inbound_closed,
                    full_or_banned = refusals.full_or_banned,
                    "connections arrived faster than the protocol's accept rate in the last \
                     minute and were closed before any handshake; this node keeps serving its \
                     other peers"
                );
            } else {
                tracing::info!(
                    inbound_closed = refusals.inbound_closed,
                    full_or_banned = refusals.full_or_banned,
                    "connections were refused before any handshake in the last minute: the \
                     inbound limit was reached or closed, or the peer is banned"
                );
            }
        }
    }));
}

/// One lateness report. `false` when the engine has closed.
fn report_lateness(engine: &Handle<MonotonicClock>) -> bool {
    for class in OwnerClass::ALL {
        let Ok(totals) = engine.lateness(class) else {
            return false;
        };
        if totals.fires == 0 && totals.home_reports == 0 {
            continue;
        }
        tracing::debug!(
            class = ?class,
            fires = totals.fires,
            max_wake_delay_ns = totals.max_wake_delay,
            wakes_late_1ms = totals.wakes_at_least(1_000_000),
            wakes_late_100ms = totals.wakes_at_least(100_000_000),
            home_reports = totals.home_reports,
            max_home_delay_ns = totals.max_home_delay,
            homes_late_1ms = totals.homes_at_least(1_000_000),
            homes_late_100ms = totals.homes_at_least(100_000_000),
            replaced_wakes = totals.replaced_wakes,
            wake_histogram_ns = %pow2_histogram(&totals.wake_buckets),
            home_histogram_ns = %pow2_histogram(&totals.home_buckets),
            "engine lateness"
        );
    }
    true
}

/// A power-of-two histogram as one log field: `2^i:n` for each bucket that
/// counted, bucket `i` holding values in `[2^i, 2^(i+1))` nanoseconds
/// (`shekyl_timing_engine::ClassLateness`'s buckets and
/// `shekyl_capped_stream::WriteStall`'s share the shape), `none` when
/// nothing counted. The distribution is what the relay-timing register
/// reads (`DAEMON_RELAY_PRIVACY.md` §97): the maximum and two thresholds
/// said whether a tail existed, not its shape.
pub(crate) fn pow2_histogram(buckets: &[u64]) -> String {
    let mut out = String::new();
    for (i, n) in buckets.iter().enumerate().filter(|(_, n)| **n > 0) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("2^{i}:{n}"));
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

#[cfg(test)]
mod pow2_histogram_tests {
    use super::pow2_histogram;

    #[test]
    fn only_counted_buckets_are_named_and_an_empty_histogram_says_so() {
        let mut buckets = [0u64; 64];
        buckets[13] = 7;
        buckets[20] = 1;
        assert_eq!(pow2_histogram(&buckets), "2^13:7 2^20:1");
        assert_eq!(pow2_histogram(&[0u64; 64]), "none");
    }
}
