// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network's periodic log lines: the engine's lateness per owner class,
//! and the connections admission refused before any handshake. Both run as
//! tasks on the transport runtime and end when it stops.

use std::time::Duration;

use shekyl_timing_engine::{Handle, MonotonicClock, OwnerClass};
use shekyl_transport_layer::Sockets;

const EVERY: Duration = Duration::from_secs(60);

/// Report each owner class's lateness once a minute, at debug. The
/// engine's answer is a blocking receive, so each report runs on the
/// blocking pool. The task ends when the engine closes or the runtime
/// stops.
pub(crate) fn spawn_lateness_report(
    runtime: &tokio::runtime::Handle,
    engine: Handle<MonotonicClock>,
) {
    drop(runtime.spawn(async move {
        let mut every = tokio::time::interval_at(tokio::time::Instant::now() + EVERY, EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
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
pub(crate) fn spawn_refusal_report(runtime: &tokio::runtime::Handle, sockets: Sockets) {
    drop(runtime.spawn(async move {
        let mut every = tokio::time::interval_at(tokio::time::Instant::now() + EVERY, EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
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
            "engine lateness"
        );
    }
    true
}
