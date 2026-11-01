// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clock named from the consensus, no republish while it cannot help,
//! and the republish backoff (`TOR_SUPERVISOR.md` §4.2, §4.5; Rick,
//! 2026-11-01).
//!
//! Every wall time and `valid-after` here is a value the test passes, as
//! the driver does; the core's own time is the test's, in nanoseconds.

use super::super::super::posture::{render, Cause, Inbound, InboundCause};
use super::super::{Action, Core, Input, RoundEnd, Step};
use super::probe::{arrival, count, probes, published, republishes, run_timed, secs, uploaded};
use super::{managed, policy};

/// The consensus of 2026-11-01 00:00:00 UTC, the one Tor held through the
/// clock VM run.
const VALID_AFTER: u64 = 1_793_491_200;

/// A day: how far the VM run set the clock back.
const DAY: u64 = 86_400;

fn clock(valid_after: u64, wall: u64) -> Input {
    Input::ConsensusClock { valid_after, wall }
}

fn round_end(end: RoundEnd, uploads: u32, refused: u32) -> Input {
    Input::UploadRoundEnded {
        end,
        uploads,
        refused,
        draw: 0,
    }
}

fn overdues(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::DescriptorOverdue))
}

fn checks(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::CheckDirectories))
}

/// Every action taken while serving deadlines up to `at`, each liveness
/// sample answered with a full bootstrap and, when `wall_at` gives one, the
/// consensus clock read at that sample, as the driver reads it.
fn serve(core: &mut Core, at: u64, wall_at: impl Fn(u64) -> Option<(u64, u64)>) -> Step {
    let mut actions = Vec::new();
    let mut served = None;
    while let Some(due) = core.deadline().filter(|due| *due <= at) {
        assert_ne!(served, Some(due), "the deadline at {due} did not move");
        served = Some(due);
        let step = core.on_deadline(due);
        let sampled = step.actions.contains(&Action::Sample);
        actions.extend(step.actions);
        if sampled {
            let folded = core.on(
                Input::DirectorySample {
                    progress: Some(100),
                    socks: None,
                    read: None,
                },
                due,
            );
            actions.extend(folded.actions);
            if let Some((valid_after, wall)) = wall_at(due) {
                actions.extend(core.on(clock(valid_after, wall), due).actions);
            }
        }
    }
    Step {
        actions,
        deadline: core.deadline(),
    }
}

/// A published core whose round began and ended at 0 and whose probe
/// arrived: Reachable, with the descriptor's lifetime counting from 0.
fn reachable() -> Core {
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    core.on(uploaded(0), secs(5));
    let (probe_at, step) = run_timed(&mut core, secs(20));
    assert_eq!(probes(&step), 1, "the round's probe");
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    core.on(arrival(probe_at, probe_at + secs(1)), probe_at + secs(1));
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    core
}

/// **Named while Running, and cleared** (Rick, 2026-11-01). A wall time a
/// day behind `valid-after` names the clock in the ruling's words, with N
/// the lower bound read; outbound and `OwnTx` are untouched. A later sample
/// further behind updates N. The first sample inside the tolerance clears
/// it, and the facet is unknown again until a probe. Fails if
/// `consensus_clock` does not set `clock_behind` (no sentence), or never
/// takes it back (the clock stays named).
#[test]
fn the_clock_is_named_while_running_and_clears() {
    let mut core = published();
    let before = core.status();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(5));
    let named = core.status();
    assert_eq!(
        named.clock_behind,
        Some(std::time::Duration::from_secs(DAY))
    );
    assert_eq!(
        named.inbound,
        Inbound::Unreachable {
            cause: InboundCause::ClockBehind,
            since: secs(5),
        }
    );
    assert_eq!(named.cause, Cause::None, "outbound is untouched");
    assert_eq!(named.own_tx, before.own_tx, "OwnTx is untouched");
    assert!(
        render(&named).contains(
            "This computer's clock is at least 1 d 0 h behind the Tor network's. Others may not be able to reach this node. Check this computer's date and time."
        ),
        "{}",
        render(&named)
    );
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY - 3_600), secs(6));
    assert_eq!(
        core.status().clock_behind,
        Some(std::time::Duration::from_secs(DAY + 3_600)),
        "N is the latest reading"
    );
    core.on(clock(VALID_AFTER, VALID_AFTER - 200), secs(7));
    let cleared = core.status();
    assert_eq!(cleared.clock_behind, None);
    assert_eq!(cleared.inbound, Inbound::Publishing);
    assert!(!render(&cleared).contains("clock"));
}

/// **Named while Bootstrapping too**; before Tor runs, the reading is
/// ignored. Fails if `consensus_clock` reads only Running.
#[test]
fn the_clock_is_named_while_bootstrapping() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), 0);
    assert_eq!(core.status().clock_behind, None, "no Tor yet");
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: None,
            read: None,
        },
        0,
    );
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(1));
    assert_eq!(
        core.status().clock_behind,
        Some(std::time::Duration::from_secs(DAY))
    );
}

/// **Only behind, and only past the tolerance** (§10 `TSR-M13`, 360 s).
/// A clock 360 s behind is inside it: a correct clock can hold a consensus
/// the authorities' distribution delay before its `valid-after`, and Tor's
/// own notice allows 60 s on top. A clock ahead is never named: a consensus
/// older than the clock is a node that was offline. Fails if the comparison
/// is `>=` (360 named), or takes the absolute difference (ahead named).
#[test]
fn only_a_clock_behind_past_the_tolerance_is_named() {
    let mut core = published();
    core.on(clock(VALID_AFTER, VALID_AFTER - 360), secs(1));
    assert_eq!(core.status().clock_behind, None, "inside the tolerance");
    core.on(clock(VALID_AFTER, VALID_AFTER - 361), secs(2));
    assert_eq!(
        core.status().clock_behind,
        Some(std::time::Duration::from_secs(361))
    );
    core.on(clock(VALID_AFTER, VALID_AFTER), secs(3));
    core.on(clock(VALID_AFTER, VALID_AFTER + DAY), secs(4));
    assert_eq!(core.status().clock_behind, None, "ahead is not named");
}

/// **No republish while the clock is named** (Rick, 2026-11-01): not the
/// overdue rule's, not a round's probe (none is scheduled, so the two-miss
/// rule cannot run), and not a direct ask. Fails if `republish` drops
/// `republish_cannot_help`, if `trigger` schedules a probe under the clock,
/// or if `on_overdue_deadline` republishes (the VM run's first republish,
/// at the lifetime).
#[test]
fn no_republish_while_the_clock_is_named() {
    let mut core = reachable();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(30));
    core.on(Input::UploadRoundStarted, secs(40));
    core.on(Input::FirstUploaded { draw: 0 }, secs(40));
    let ended = core.on(uploaded(0), secs(45));
    assert_eq!(checks(&ended), 0, "no probe's check under the clock");
    let behind = |_| Some((VALID_AFTER, VALID_AFTER - DAY));
    let served = serve(&mut core, secs(40 + 4 * 3_600), behind);
    assert_eq!(probes(&served), 0, "no probe");
    assert_eq!(republishes(&served), 0, "no republish");
    assert_eq!(overdues(&served), 0, "the overdue rule stands down");
    assert_eq!(core.republish(secs(40 + 4 * 3_600)), []);
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::ClockBehind,
            ..
        }
    ));
}

/// **No republish under a majority of refusals; exactly half is not
/// one.** The VM run's rounds: 7 of 8 refused per descriptor, 14 of 16. The
/// facet names it in its own words, and the overdue rule stands down. A
/// round with 8 of 16 refused is accepted: the facet is unknown again and
/// the round's probe judges it. Fails if the majority test is `>=` (8 of 16
/// refused), if `round_ended` republishes or probes a refused round, or if
/// `uploads_accepted` leaves the cause standing.
#[test]
fn no_republish_under_a_majority_of_refusals() {
    let mut core = reachable();
    let refused = core.on(round_end(RoundEnd::Uploaded, 16, 14), secs(30));
    assert_eq!(republishes(&refused), 0);
    assert_eq!(checks(&refused), 0, "no probe for a refused round");
    let status = core.status();
    assert_eq!(
        status.inbound,
        Inbound::Unreachable {
            cause: InboundCause::UploadsRefused,
            since: secs(30),
        }
    );
    assert!(
        render(&status).contains(
            "The Tor network is not accepting this node's address right now. Others may not be able to reach this node."
        ),
        "{}",
        render(&status)
    );
    let served = serve(&mut core, secs(4 * 3_600), |_| None);
    assert_eq!(republishes(&served), 0, "no republish");
    assert_eq!(overdues(&served), 0, "the overdue rule stands down");
    let half = core.on(round_end(RoundEnd::Uploaded, 16, 8), secs(4 * 3_600 + 1));
    assert_eq!(core.status().inbound, Inbound::Publishing);
    assert_eq!(checks(&half), 1, "an accepted round's probe judges");
}

/// **The backoff doubles, caps at three hours, and resets on a confirmed
/// Reachable** (§10 `TSR-M14`: base 300 s). A republish waits for its own
/// judgment: a second ask before it is owed, and nothing is due. Each failed
/// judgment holds the next for the wait, then doubles it. Fails if
/// `republish_failed` stops doubling (300 s every time), loses the cap
/// (19 200 s at the seventh), or `judge` stops calling
/// `republish_confirmed` (the wait after a Reachable stays at the cap).
#[test]
fn the_republish_backoff_doubles_caps_and_resets_on_reachable() {
    let mut core = published();
    let mut at = secs(1_000);
    assert_eq!(core.republish(at), [Action::RepublishOnion]);
    core.on(Input::OnionPublished, at);
    assert_eq!(core.republish(at + 1), [], "waits for its own judgment");
    assert_eq!(core.republish.due(), None, "nothing is due before it");
    let mut waits = Vec::new();
    for _ in 0..8 {
        core.republish_failed(at);
        assert_eq!(core.republish(at), [], "held");
        let due = core.republish.due().expect("the owed republish is due");
        waits.push((due - at) / secs(1));
        assert_eq!(core.republish(due - 1), [], "still held");
        assert_eq!(republishes(&core.on_deadline(due)), 1, "runs when due");
        core.on(Input::OnionPublished, due);
        at = due;
    }
    assert_eq!(
        waits,
        [300, 600, 1_200, 2_400, 4_800, 9_600, 10_800, 10_800]
    );
    // A confirmed Reachable: the republish's round, and its probe arriving.
    core.on(uploaded(0), at);
    let (probe_at, step) = run_timed(&mut core, at + secs(60));
    assert_eq!(probes(&step), 1);
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    core.on(arrival(probe_at, probe_at + secs(1)), probe_at + secs(1));
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    let next = probe_at + secs(10);
    assert_eq!(core.republish(next), [Action::RepublishOnion]);
    core.republish_failed(next);
    core.republish(next);
    assert_eq!(
        core.republish.due(),
        Some(next + secs(300)),
        "back to the base"
    );
}

/// **The 2026-11-01 VM run, replayed** (`shekyl-dev`
/// `data/tsr-acceptance/2026-11-01-linux-vm-clock/`): the node Reachable at
/// 00:44:34Z, the guest clock set back a day at 00:46:14Z, Tor holding the
/// 00:00Z consensus throughout, no upload round after 00:42 (the old rule's
/// overdue republish fired at 03:42, the first of 36). Replayed to 06:16Z:
/// the clock is named at the first sample after the jump, the clock line is
/// the facet's sentence, and nothing is republished, probed, or called
/// overdue. Fails if `consensus_clock` stops comparing (the overdue
/// republish returns at 03:42).
#[test]
fn the_clock_runs_sequence_gives_the_clock_line_and_no_republish() {
    // Core time 0 is 00:42:00Z, the round's upload.
    let start = VALID_AFTER + 42 * 60;
    let jumped = secs(4 * 60 + 14);
    let end = secs(5 * 3_600 + 34 * 60);
    let mut core = reachable();
    let wall = move |now: u64| {
        let real = start + now / secs(1);
        Some((VALID_AFTER, if now >= jumped { real - DAY } else { real }))
    };
    let before = serve(&mut core, jumped - 1, wall);
    assert_eq!(core.status().clock_behind, None, "a correct clock first");
    assert_eq!(republishes(&before), 0);
    let mut named_at = None;
    let mut after = Vec::new();
    let mut at = jumped;
    while at < end {
        at += secs(1);
        let step = serve(&mut core, at, wall);
        after.extend(step.actions);
        if named_at.is_none() && core.status().clock_behind.is_some() {
            named_at = Some(at);
        }
    }
    let named_at = named_at.expect("the clock is named");
    let sample = super::super::duration_ns(policy().alive_every);
    assert!(
        named_at - jumped <= sample,
        "named within one liveness sample: {} s",
        (named_at - jumped) / secs(1)
    );
    let after = Step {
        actions: after,
        deadline: None,
    };
    assert_eq!(republishes(&after), 0, "no republish");
    assert_eq!(probes(&after), 0, "no probe");
    assert_eq!(overdues(&after), 0, "the overdue rule stands down");
    // 06:16Z on the clock: 00:00Z the day before plus 6 h 16 min, so
    // 17 h 44 min behind.
    let text = render(&core.status());
    assert!(
        text.contains("This computer's clock is at least 17 h 44 min behind the Tor network's."),
        "{text}"
    );
}

/// **A new Tor keeps a named clock.** A respawned Tor numbers its uploads
/// from the same clock, so the facet stays on the clock's line instead of
/// going back to "publishing". Fails if `enter_running` resets the facet
/// whatever the clock (`clock_behind.is_none()` dropped from its test).
#[test]
fn a_new_tor_keeps_a_named_clock() {
    let mut core = published();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(1));
    core.on(Input::ControlEnded, secs(2));
    let due = core.deadline().expect("the respawn wait");
    let step = core.on_deadline(due);
    assert!(
        step.actions.contains(&Action::CheckPin),
        "{:?}",
        step.actions
    );
    core.on(Input::PinAccepted, due);
    core.on(Input::Spawned, due);
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some("127.0.0.1:9150".parse().expect("socks")),
            read: None,
        },
        due,
    );
    core.on(Input::BootstrapComplete, due);
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::ClockBehind,
            ..
        }
    ));
    assert!(render(&core.status()).contains("This computer's clock is at least"));
}

/// **A clock jump asks no probe while the clock is named**: the run of
/// 2026-11-01 17:11Z logged "probing" right after the clock was named,
/// though the probe's own gate then dropped it. Fails if `jump_probe` asks
/// whatever the clock.
#[test]
fn a_clock_jump_asks_no_probe_while_the_clock_is_named() {
    let mut core = reachable();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(30));
    let jumped = core.on(Input::ClockJumped, secs(31));
    assert!(
        !jumped.actions.contains(&Action::ProbeAfterJump),
        "{:?}",
        jumped.actions
    );
}
