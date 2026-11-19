// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's pure pieces. The owner on live sessions is `tests/owner.rs`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use super::actor::tick_of;
use super::carrier::{CarrierCmd, CarrierTask};
use super::connection_id;
use crate::carrier::Carrier;
use crate::noise_queue::NoiseQueues;
use shekyl_draw_rng::SplitMix64;
use shekyl_p2p_session::SocketId;
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_timing_engine::{EngineService, ManualClock, OwnerClass, Tick};
use tokio::sync::mpsc;

#[test]
fn a_socket_id_names_a_connection_without_colliding_with_local() {
    let a = connection_id(SocketId::from_ffi(1).expect("one is an id"));
    let b = connection_id(SocketId::from_ffi(2).expect("two is an id"));
    assert_ne!(a, b);
    assert_ne!(a, ConnectionId::from_bytes([0; 16]), "nil is this node");
    assert_eq!(
        a.as_bytes()[..8],
        1u64.to_le_bytes(),
        "the socket id is the first eight bytes, little-endian"
    );
    assert!(a.as_bytes()[8..].iter().all(|b| *b == 0));
}

#[test]
fn the_same_socket_id_names_the_same_connection() {
    let id = SocketId::from_ffi(0x0102_0304_0506_0708).expect("an id");
    assert_eq!(connection_id(id), connection_id(id));
}

/// A waker that records that it was woken.
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

/// How long the wake-order test waits for the timing engine to deliver a
/// wake it was told is due. A bound on a broken engine, not a pacing.
const DELIVERY_BOUND: Duration = Duration::from_secs(30);

/// How many times the wake-order test repeats. An unbiased `select!`
/// serves the wake first half the time, so one round would pass it one
/// time in two; this many pass it one time in 2^32.
const WAKE_ORDER_ROUNDS: u64 = 32;

/// **The carrier serves a due window before its inbox** (the review of
/// #1431, Rick 2026-11-18). With a wake delivered and a command queued, the
/// turn takes the wake: a burst of commands cannot delay a window.
///
/// The queued command is `Stop`, so the order shows in what the turn
/// returns: the wake first keeps the task running, the inbox first ends it.
/// The wake is known delivered before the command is queued, because the
/// pending turn's waker fired while the inbox was empty.
///
/// Red edits: drop `biased` from the turn's `select!` (some round ends the
/// task), or put the inbox arm first (the first round does).
#[test]
fn the_carrier_serves_a_due_window_before_its_inbox() {
    const CHANNELS: usize = 2;
    const WINDOW_BUDGET: usize = 1;
    for round in 0..WAKE_ORDER_ROUNDS {
        let clock = ManualClock::new(Tick::new(0));
        let engine = EngineService::start(clock.clone());
        let timing = engine.handle();
        let nudge = timing
            .register(OwnerClass::Housekeeping)
            .expect("the nudge registers");
        let mut rng = SplitMix64::new(round);
        let carrier = Carrier::new(CHANNELS, 0, &mut rng);
        let first = carrier.deadline().expect("a channel is armed");
        let (commands, inbox) = mpsc::unbounded_channel();
        let (to_owner, _owner_inbox) = mpsc::unbounded_channel();
        let mut task = CarrierTask {
            carrier,
            queues: NoiseQueues::new(CHANNELS, vec![0; 8], WINDOW_BUDGET).expect("a queue"),
            sessions: HashMap::new(),
            rng: Box::new(rng),
            owner: timing
                .register(OwnerClass::Carrier)
                .expect("the carrier registers"),
            inbox,
            to_owner,
        };
        task.arm();

        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        {
            let mut turn = std::pin::pin!(task.turn());
            assert!(
                turn.as_mut().poll(&mut cx).is_pending(),
                "fixture: nothing is due and the inbox is empty"
            );

            // The window comes due, and the engine delivers its wake.
            clock.set(tick_of(first));
            nudge.clear().expect("the engine is open");
            let by = Instant::now() + DELIVERY_BOUND;
            while !flag.0.load(Ordering::Acquire) {
                assert!(Instant::now() < by, "the engine never delivered the wake");
                std::thread::yield_now();
            }

            // Now a command is queued behind the delivered wake.
            commands.send(CarrierCmd::Stop).expect("the task is alive");
            assert_eq!(
                turn.as_mut().poll(&mut cx),
                Poll::Ready(true),
                "round {round}: the queued command was served before the due window"
            );
        }
        assert!(
            task.carrier.deadline() > Some(first),
            "the wake was served: its channel is armed again"
        );
        // The command was not lost: the next turn takes it.
        let mut turn = std::pin::pin!(task.turn());
        assert_eq!(turn.as_mut().poll(&mut cx), Poll::Ready(false));
    }
}
