// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A bootstrap stranded by a clock jump (the VM clock run of 2026-10-30;
//! Rick, 2026-10-30): respawn only on Tor's reported jump, followed by a
//! bound in which neither the percent nor `traffic/read` moved.

use std::time::Duration;

use super::super::super::posture::{Cause, Shown};
use super::super::{duration_ns, Core, Input, Step};
use super::{managed, policy, takes_down};

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

fn sample(core: &mut Core, at: u64, percent: u8, read: u64) -> Step {
    core.on(
        Input::DirectorySample {
            progress: Some(percent),
            socks: None,
            read: Some(read),
        },
        at,
    )
}

fn bootstrapping() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core
}

/// The stranded run's shape: the jump, one percent after it, then nothing
/// for the bound. The fault comes at the first sample a full bound after
/// the later of the jump, the percent's move and the bytes' move, and not
/// one sample before. Clearing the jump at the next percent, or not holding
/// it at all, fails this.
#[test]
fn a_reported_jump_then_a_still_bound_starts_tor_again() {
    let mut core = bootstrapping();
    sample(&mut core, secs(5), 14, 1_000);
    core.on(Input::ClockJumped, secs(10));
    // Tor moves one percent after the jump, then stops; no byte arrives.
    sample(&mut core, secs(15), 15, 2_000);
    let mut at = secs(20);
    while at < secs(15) + secs(300) {
        let step = sample(&mut core, at, 15, 2_000);
        assert!(!takes_down(&step));
        assert_eq!(
            core.status().respawn_count,
            0,
            "still inside the bound at {at}"
        );
        at += secs(5);
    }
    sample(&mut core, secs(15) + secs(300), 15, 2_000);
    let status = core.status();
    assert_eq!(status.respawn_count, 1, "started again");
    assert_eq!(status.cause, Cause::StrandedAfterClockJump);
    assert_eq!(status.shown, Shown::Restarting);
}

/// A slow directory mirror with no jump is not a fault, however long the
/// percent holds and whatever the bytes do (Rick, 2026-10-19). A jump
/// followed by bytes that keep arriving is not one either: that is a slow
/// mirror after a jump. Respawning on the stall alone fails this.
#[test]
fn a_stall_without_a_jump_or_with_bytes_arriving_is_not_a_fault() {
    let mut core = bootstrapping();
    for i in 1..=200 {
        sample(&mut core, secs(5 * i), 40, 10_000);
    }
    assert_eq!(
        core.status().respawn_count,
        0,
        "no jump: a stall is not a fault"
    );

    let mut core = bootstrapping();
    sample(&mut core, secs(5), 40, 10_000);
    core.on(Input::ClockJumped, secs(6));
    for i in 2..=200 {
        sample(&mut core, secs(5 * i), 40, 10_000 + i * 50_000);
    }
    assert_eq!(
        core.status().respawn_count,
        0,
        "bytes arriving: a slow mirror after the jump"
    );
}
