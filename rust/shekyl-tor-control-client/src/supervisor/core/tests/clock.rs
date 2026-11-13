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

use super::super::super::posture::{Cause, Inbound, InboundCause};
use super::super::{Action, Core, Input, RoundTally, Step};
use super::probe::{arrival, count, probes, published, republishes, run_timed, secs, uploaded};
use super::{managed, policy, replied};
use super::{said, said_of};

/// The consensus of 2026-11-01 00:00:00 UTC, the one Tor held through the
/// clock VM run.
const VALID_AFTER: u64 = 1_793_491_200;

/// A day: how far the VM run set the clock back.
const DAY: u64 = 86_400;

fn clock(valid_after: u64, wall: u64) -> Input {
    Input::ConsensusClock { valid_after, wall }
}

fn behind(seconds: u64) -> InboundCause {
    InboundCause::ClockBehind {
        behind: std::time::Duration::from_secs(seconds),
    }
}

/// `uploaded` reached a directory, `refused` of the `begun` uploads were
/// refused. The VM run's rounds are 2 of 16 accepted and 14 refused.
fn round_tally(uploaded: u32, refused: u32, begun: u32) -> Input {
    Input::UploadRoundEnded {
        tally: RoundTally {
            uploaded,
            refused,
            begun,
        },
        draw: 0,
    }
}

fn overdues(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::DescriptorOverdue))
}

fn checks(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::CheckDirectories))
}

/// Answer each sample `actions` sent, as the driver answers it: a full
/// bootstrap, the consensus clock read at that sample when `wall` gives
/// one, and then [`Input::Replied`]. A request queued behind the sample is
/// sent by that `Replied`; its actions join `actions`.
fn answer_samples(core: &mut Core, at: u64, actions: &mut Vec<Action>, wall: Option<(u64, u64)>) {
    let mut sampled = actions.contains(&Action::Sample);
    while sampled {
        let folded = core.on(
            Input::DirectorySample {
                progress: Some(100),
                socks: None,
                read: None,
            },
            at,
        );
        actions.extend(folded.actions);
        if let Some((valid_after, wall)) = wall {
            actions.extend(core.on(clock(valid_after, wall), at).actions);
        }
        let next = replied(core, at);
        sampled = next.actions.contains(&Action::Sample);
        actions.extend(next.actions);
    }
}

/// `step`, with the sample it sent answered ([`answer_samples`], no clock
/// read): the actions of the `Replied` that sends what was queued behind
/// it join the step's.
fn sample_answered(core: &mut Core, step: Step, at: u64) -> Step {
    let mut actions = step.actions;
    answer_samples(core, at, &mut actions, None);
    Step {
        actions,
        deadline: core.deadline(),
    }
}

/// The republish in flight is answered: its `DEL_ONION`, then the
/// `ADD_ONION` that follows, published.
fn republish_answered(core: &mut Core, at: u64) {
    let deleted = replied(core, at);
    assert!(
        deleted.actions.contains(&Action::AddOnion),
        "the add follows the delete: {deleted:?}"
    );
    core.on(Input::OnionPublished, at);
    replied(core, at);
}

/// Every action taken while serving deadlines up to `at`, each liveness
/// sample answered ([`answer_samples`]) with a full bootstrap and, when
/// `wall_at` gives one, the consensus clock read at that sample, as the
/// driver reads it.
fn serve(core: &mut Core, at: u64, wall_at: impl Fn(u64) -> Option<(u64, u64)>) -> Step {
    let mut actions = Vec::new();
    let mut served = None;
    while let Some(due) = core.deadline().filter(|due| *due <= at) {
        assert_ne!(served, Some(due), "the deadline at {due} did not move");
        served = Some(due);
        let mut step = core.on_deadline(due).actions;
        answer_samples(core, due, &mut step, wall_at(due));
        actions.extend(step);
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
            cause: behind(DAY),
            since: secs(5),
        }
    );
    assert_eq!(named.cause, Cause::None, "outbound is untouched");
    assert_eq!(named.own_tx, before.own_tx, "OwnTx is untouched");
    assert!(
        said_of(&named).contains(
            "This computer's clock is at least 1 d 0 h behind the Tor network's. Others may not be able to reach this node. Check this computer's date and time."
        ),
        "{}",
        said_of(&named)
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
    assert!(
        matches!(cleared.inbound, Inbound::Publishing { .. }),
        "{:?}",
        cleared.inbound
    );
    assert!(!said_of(&cleared).contains("clock"));
}

/// **Named while Bootstrapping too**; before Tor runs, the reading is
/// ignored. Fails if `consensus_clock` reads only Running.
#[test]
fn the_clock_is_named_while_bootstrapping() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), 0);
    assert_eq!(core.status().clock_behind, None, "no Tor yet");
    core.on(Input::accepted(), 0);
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
            cause: InboundCause::ClockBehind { .. },
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
    let refused = core.on(round_tally(2, 14, 16), secs(30));
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
        said_of(&status).contains(
            "The Tor network is not accepting this node's address right now. Others may not be able to reach this node."
        ),
        "{}",
        said_of(&status)
    );
    let served = serve(&mut core, secs(4 * 3_600), |_| None);
    assert_eq!(republishes(&served), 0, "no republish");
    assert_eq!(overdues(&served), 0, "the overdue rule stands down");
    let half = core.on(round_tally(8, 8, 16), secs(4 * 3_600 + 1));
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
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
        // The liveness sample this deadline also asks goes first; the
        // republish is sent when it is answered.
        let step = core.on_deadline(due);
        let step = sample_answered(&mut core, step, due);
        assert_eq!(republishes(&step), 1, "runs when due");
        republish_answered(&mut core, due);
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
    let text = said(&core);
    assert!(
        text.contains("This computer's clock is at least 17 h 44 min behind the Tor network's."),
        "{text}"
    );
}

/// **A new Tor keeps a named clock.** A respawned Tor numbers its uploads
/// from the same clock, so the facet stays on the clock's line instead of
/// going back to "publishing". Fails if `enter_running` resets the facet
/// whatever the clock (`clock_is_behind` dropped from its test).
#[test]
fn a_new_tor_keeps_a_named_clock() {
    let mut core = published();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(1));
    let ended = core.on(Input::ControlEnded, secs(2));
    // The ended Tor is reaped off the loop before the next launch.
    assert!(ended.actions.contains(&Action::Reap), "{:?}", ended.actions);
    replied(&mut core, secs(2));
    let due = core.deadline().expect("the respawn wait");
    let step = core.on_deadline(due);
    assert!(
        step.actions.contains(&Action::CheckPin),
        "{:?}",
        step.actions
    );
    core.on(Input::accepted(), due);
    core.on(Input::Spawned, due);
    // The launch, then the subscription; its `Replied` sends the first
    // sample, answered as the driver answers it.
    replied(&mut core, due);
    replied(&mut core, due);
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some("127.0.0.1:9150".parse().expect("socks")),
            read: None,
        },
        due,
    );
    replied(&mut core, due);
    let running = core.on(Input::BootstrapComplete, due);
    assert!(
        running.actions.contains(&Action::RepublishOnion),
        "a new Tor still publishes"
    );
    assert!(
        core.action_stands(&Action::RepublishOnion),
        "that first publish is not a republish the clock can withhold"
    );
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::ClockBehind { .. },
            ..
        }
    ));
    assert!(said(&core).contains("This computer's clock is at least"));
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

/// **Standing down does not postpone the overdue check.** A clock named for
/// longer than a lifetime leaves the anchor where the last upload put it.
/// The first sample inside the tolerance makes the check due at once, and
/// it republishes then. Fails if `on_overdue_deadline` moves
/// `lifetime_from` while a republish cannot help: the next check would wait
/// another lifetime.
#[test]
fn a_named_clock_does_not_postpone_the_overdue_check() {
    let mut core = reachable();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(30));
    let behind_wall = |_| Some((VALID_AFTER, VALID_AFTER - DAY));
    let served = serve(&mut core, secs(4 * 3_600), behind_wall);
    assert_eq!(overdues(&served), 0, "the check stands down");
    let clear_at = secs(4 * 3_600 + 10);
    core.on(clock(VALID_AFTER, VALID_AFTER), clear_at);
    let due = core.deadline().expect("due once a republish can help");
    assert!(
        due <= clear_at,
        "the anchor was not moved: due at {due}, cleared at {clear_at}"
    );
    let step = core.on_deadline(clear_at);
    let step = sample_answered(&mut core, step, clear_at);
    assert_eq!(overdues(&step), 1, "the check that came due while named");
    assert_eq!(republishes(&step), 1);
}

/// **The liveness sample is ahead of a republish the same deadline queues.**
/// The sample is sent and the republish waits behind it. Folding a clock
/// that sample names withholds the republish at its turn, when the sample's
/// `Replied` comes: it is never sent, and the lifetime is put back. Fails if
/// `on_deadline` queues `RepublishOnion` first (the driver would publish
/// before it could know), if the queue sends a republish that no longer
/// stands, or if `republish_withheld` keeps the anchor the send moved.
#[test]
fn a_sample_names_the_clock_before_the_republish_it_queues() {
    let mut core = reachable();
    let anchor = core
        .lifetime_from
        .expect("the upload numbered the descriptor");
    let due = anchor + super::super::duration_ns(policy().descriptor_lifetime);
    core.alive_at = Some(due);
    let step = core.on_deadline(due);
    assert!(
        step.actions.contains(&Action::Sample),
        "the liveness sample is sent: {step:?}"
    );
    assert_eq!(
        republishes(&step),
        0,
        "the republish waits behind the sample: {step:?}"
    );
    assert_eq!(overdues(&step), 1, "the overdue check asked the republish");
    assert!(core.action_stands(&Action::RepublishOnion));
    assert_eq!(
        core.lifetime_from,
        Some(due),
        "the hand-over starts its lifetime"
    );
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), due);
    assert!(
        !core.action_stands(&Action::RepublishOnion),
        "a named clock withholds the send already handed over"
    );
    let number = core.in_flight().expect("the sample is in flight");
    let turn = core.on(Input::Replied { number }, due);
    assert!(
        !turn
            .actions
            .iter()
            .any(|action| matches!(action, Action::RepublishOnion | Action::AddOnion)),
        "the republish is withheld at its turn, not sent: {turn:?}"
    );
    assert_eq!(core.in_flight(), None, "nothing was sent in its place");
    assert_eq!(core.lifetime_from, Some(anchor), "the anchor is put back");
    assert!(!core.service_republish);
    assert!(!core.republish_is_judging(), "the send was not published");
    assert_eq!(core.republish(due), [], "a named clock does not send it");
    core.on(clock(VALID_AFTER, VALID_AFTER), due);
    let again = core.deadline().expect("the restored anchor is due");
    assert!(
        again <= due,
        "the anchor was put back, not started again: due at {again}"
    );
}

/// **A hold that expires while a republish cannot help stays owed.** The
/// deadline is hidden, and it is not cleared. Once the clock clears, that
/// same instant sends. Fails if `on_republish_deadline` clears `until`
/// while standing down: the owed republish would never run.
#[test]
fn a_republish_held_while_suppressed_stays_owed() {
    let mut core = reachable();
    let at = secs(100);
    assert_eq!(core.republish(at), [Action::RepublishOnion]);
    core.on(Input::OnionPublished, at);
    core.republish_failed(at);
    assert_eq!(core.republish(at), [], "held");
    let due = core.republish.due().expect("the owed republish");
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), at + 1);
    assert_eq!(
        core.republish_due(),
        None,
        "hidden while the clock is named"
    );
    let served = core.on_deadline(due + secs(1));
    let served = sample_answered(&mut core, served, due + secs(1));
    assert_eq!(republishes(&served), 0, "the past hold does not spin");
    assert_eq!(core.republish.due(), Some(due), "the hold was not cleared");
    core.on(clock(VALID_AFTER, VALID_AFTER), due + secs(2));
    assert_eq!(core.republish_due(), Some(due));
    let step = core.on_deadline(due + secs(2));
    let step = sample_answered(&mut core, step, due + secs(2));
    assert_eq!(republishes(&step), 1, "it runs once a republish can help");
}

/// **A republish's lifetime starts when it is handed over**, not at the
/// previous upload's remainder, and a descriptor that was never uploaded
/// still starts one. Fails if `republish` leaves `lifetime_from` where it
/// was: the no-round timeout would be the old descriptor's, or none.
#[test]
fn a_republish_counts_its_lifetime_from_the_send() {
    let lifetime = super::super::duration_ns(policy().descriptor_lifetime);
    let mut core = published();
    assert_eq!(core.lifetime_from, None);
    let at = secs(50);
    assert_eq!(core.republish(at), [Action::RepublishOnion]);
    assert_eq!(core.overdue_due(), Some(at + lifetime));

    let mut core = reachable();
    assert_eq!(core.lifetime_from, Some(0));
    let at = secs(100);
    assert_eq!(core.republish(at), [Action::RepublishOnion]);
    assert_eq!(
        core.overdue_due(),
        Some(at + lifetime),
        "not the previous upload's remainder"
    );
}

/// **A probe already in hand is cancelled when the republish is handed
/// over**, so that probe cannot confirm it. An idle probe adds no cancel.
/// Fails if `republish` leaves the dial running.
#[test]
fn a_republish_cancels_the_probe_in_hand() {
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    core.on(uploaded(0), secs(5));
    let (probe_at, step) = run_timed(&mut core, secs(20));
    assert_eq!(probes(&step), 1);
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    assert_eq!(
        core.republish(probe_at + 1),
        [Action::CancelProbe, Action::RepublishOnion]
    );
}

/// **Naming the clock drops a probe already in hand.** Its dial is
/// cancelled, and a directory check queued beside it no longer stands.
/// Fails if `consensus_clock` leaves the probe to judge the copy a
/// republish cannot replace.
#[test]
fn a_named_clock_drops_the_probe_in_hand() {
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    core.on(uploaded(0), secs(5));
    let (probe_at, step) = run_timed(&mut core, secs(20));
    assert_eq!(probes(&step), 1);
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    let named = core.on(clock(VALID_AFTER, VALID_AFTER - DAY), probe_at + 1);
    assert!(
        named.actions.contains(&Action::CancelProbe),
        "the probe in hand is dropped: {named:?}"
    );
    assert!(!core.action_stands(&Action::Probe));
    assert!(!core.action_stands(&Action::CheckDirectories));
}

/// **A round's wait that runs out while standing down does not spend the
/// round's one probe.** The round's end, once the clock has cleared,
/// schedules it. Fails if `on_round_deadline` sets `triggered` when
/// `trigger` scheduled nothing.
#[test]
fn a_round_wait_while_suppressed_can_still_schedule() {
    let mut core = reachable();
    core.on(clock(VALID_AFTER, VALID_AFTER - DAY), secs(30));
    core.on(Input::UploadRoundStarted, secs(40));
    core.on(Input::FirstUploaded { draw: 0 }, secs(40));
    let wait_end = secs(40) + super::super::duration_ns(policy().round_wait);
    let waited = core.on_deadline(wait_end);
    let waited = sample_answered(&mut core, waited, wait_end);
    assert_eq!(checks(&waited), 0, "standing down schedules nothing");
    let clear = secs(40) + super::super::duration_ns(policy().round_wait) + secs(1);
    core.on(clock(VALID_AFTER, VALID_AFTER), clear);
    let ended = core.on(uploaded(0), clear);
    assert_eq!(
        checks(&ended),
        1,
        "the round's end still schedules its probe"
    );
}

/// **A jump probe does not confirm a republish waiting on its own round.**
/// It can still find the onion reachable. The round's own probe does
/// confirm it (the backoff test). Fails if `judge` calls
/// `republish_confirmed` for every Reachable.
#[test]
fn a_jump_probe_does_not_confirm_a_republish_waiting_on_its_round() {
    let mut core = published();
    let at = secs(1_000);
    assert_eq!(core.republish(at), [Action::RepublishOnion]);
    core.on(Input::OnionPublished, at);
    assert!(core.republish_is_judging());
    let jumped = core.on(Input::ClockJumped, at + 1);
    assert!(
        jumped.actions.contains(&Action::Sample),
        "the jump's sample is sent: {jumped:?}"
    );
    assert!(
        !jumped.actions.contains(&Action::ProbeAfterJump),
        "the draw waits for the sample: {jumped:?}"
    );
    let drawn = replied(&mut core, at + 1);
    assert!(
        drawn.actions.contains(&Action::ProbeAfterJump),
        "the draw follows the sample: {drawn:?}"
    );
    core.on(Input::JumpProbeDrawn { draw: 0 }, at + 1);
    let (probe_at, step) = run_timed(&mut core, at + secs(20));
    assert_eq!(probes(&step), 1, "the jump probe");
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    core.on(arrival(probe_at, probe_at + secs(1)), probe_at + secs(1));
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    assert!(core.republish_is_judging(), "the wait stands");
    assert_eq!(
        core.republish(probe_at + secs(2)),
        [],
        "the jump probe does not reset the backoff"
    );
}

/// **A round in which no upload succeeded leaves refused uploads standing.**
/// It is not a round of uploads, so it does not clear the cause and it does
/// not republish. Fails if `round_ended` clears `uploads_refused` whenever
/// the round was not a majority refusal.
#[test]
fn a_round_with_no_upload_leaves_refused_uploads_standing() {
    let mut core = reachable();
    core.on(round_tally(2, 14, 16), secs(30));
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::UploadsRefused,
            ..
        }
    ));
    core.on(Input::UploadRoundStarted, secs(40));
    let ended = core.on(round_tally(0, 0, 16), secs(50));
    assert_eq!(republishes(&ended), 0);
    assert!(
        matches!(
            core.status().inbound,
            Inbound::Unreachable {
                cause: InboundCause::UploadsRefused,
                ..
            }
        ),
        "a round with no upload is not a round of uploads: {:?}",
        core.status().inbound
    );
}
