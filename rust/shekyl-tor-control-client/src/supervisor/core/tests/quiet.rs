// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet line and Tor's sampled network view (`TSR-Q14`).
//!
//! Dial replies are display. Tor's own statements name the cause.

use std::time::Duration;

use super::super::super::posture::{Cause, Shown, TorQuiet};
use super::super::{duration_ns, Action, Core, DialTally, Input, Step, TorCensus};
use super::{announces, managed, policy, reach_usable, replied, socks, spawns, takes_down};
use super::{said, said_of};
use crate::control::{NetworkView, Reported};

/// A tally of `unopened` failed Tor dials since the `opened`-th opened one,
/// the latest of them launched at `began`, and no sign of life. The census
/// is one seat held since the clock's origin, so the unanswered span is
/// the quiet stretch.
fn dials(opened: u64, unopened: u32, began: Option<u64>) -> Input {
    lived(opened, unopened, None, began)
}

/// [`dials`], with the judge's last sign of life at `life`.
fn lived(opened: u64, unopened: u32, life: Option<u64>, began: Option<u64>) -> Input {
    tally(
        opened,
        unopened,
        life,
        began,
        TorCensus::Held { seats: 1, since: 0 },
    )
}

fn tally(
    opened: u64,
    unopened: u32,
    life: Option<u64>,
    began: Option<u64>,
    census: TorCensus,
) -> Input {
    Input::DialEvidence(DialTally {
        opened,
        unopened,
        last_sign_of_life: life,
        failed_attempt_began: began,
        census,
    })
}

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

/// A sampled view. Unknown is not a negative.
fn tor_says(liveness: Reported, circuits: Reported) -> Input {
    Input::NetworkView(NetworkView { liveness, circuits })
}

/// Run every deadline up to and including `until`, answering each liveness
/// sample as a Tor that has not reported its network, so nothing but the
/// evidence under test can move the core, and then with
/// [`Input::Replied`]. Returns every step taken, the `Replied` steps among
/// them: a request queued behind a sample is sent there.
fn run_until(core: &mut Core, until: u64) -> Vec<Step> {
    let mut steps = Vec::new();
    while let Some(due) = core.deadline().filter(|due| *due <= until) {
        let step = core.on_deadline(due);
        let mut sampled = step.actions.contains(&Action::Sample);
        steps.push(step);
        while sampled {
            steps.push(core.on(tor_says(Reported::Unknown, Reported::Unknown), due));
            let next = replied(core, due);
            sampled = next.actions.contains(&Action::Sample);
            steps.push(next);
        }
    }
    steps
}

fn faults(steps: &[Step]) -> bool {
    steps.iter().any(|step| {
        spawns(step)
            || takes_down(step)
            || step
                .actions
                .iter()
                .any(|action| matches!(action, Action::CheckPin))
    })
}

fn says_progress(steps: &[Step]) -> usize {
    steps
        .iter()
        .flat_map(|step| &step.actions)
        .filter(|action| matches!(action, Action::SayProgress))
        .count()
}

/// `TSR-Q14` (Rick, 2026-10-25): this node's own dial replies are never a
/// link verdict. Ten minutes of failed Tor dials, with no session held and
/// Tor saying nothing about its network, is a neutral line said once, and
/// no cause, no announcement, no respawn. A planted onion answers `0x01` at
/// will and a blackholing one `0x06` (shekyl-dev
/// `data/tsr-acceptance/2026-10-25-socks-reply-sources`), so a cause from
/// dials would let anyone make the node tell its operator it cannot reach
/// Tor. Routing the tally to a cause fails the first half; dropping it
/// fails the line. Every deadline runs; all 150 samples are answered.
#[test]
fn ten_minutes_of_failed_dials_are_a_neutral_line_never_a_cause() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let mut steps = Vec::new();
    let mut unopened = 0;
    let mut at = 0;
    while at < duration_ns(Duration::from_secs(600)) {
        at += duration_ns(Duration::from_secs(5));
        steps.extend(run_until(&mut core, at));
        unopened += 1;
        steps.push(core.on(dials(0, unopened, Some(at)), at));
    }
    let samples = steps
        .iter()
        .filter(|step| step.actions.contains(&Action::Sample))
        .count();
    // One liveness sample per `alive_every` while Running: 600 s / 4 s.
    assert_eq!(samples, 150, "the liveness samples ran");
    assert!(!faults(&steps), "no respawn, no takedown, no pin check");
    assert_eq!(
        steps.iter().map(announces).sum::<usize>(),
        0,
        "nothing announced"
    );
    assert_eq!(says_progress(&steps), 1, "the line is said once");
    let status = core.status();
    assert_eq!(status.cause, Cause::None);
    assert_eq!(status.shown, Shown::Usable);
    assert_eq!(status.respawn_count, 0);
    assert!(status.tor_quiet.is_some());
    let text = said_of(&status);
    assert!(
        text.contains("Peers are known; none has answered through Tor for"),
        "{text}"
    );
    assert!(!text.contains("cannot reach"), "{text}");
}

/// **The line runs from the judge's last sign of life**
/// (`DIALER_OUTAGE_EVIDENCE.md` §6): a byte a session received, or a stream
/// that opened, starts the span again; with a Tor dial launched after it
/// and failed, the line stands `quiet_after` later and not before. The
/// testnet case, two live seeds talking while four dead ones are redialed,
/// is a byte every timed sync, so no line. Reading the opened count instead
/// of the judge's instant fails the byte half.
#[test]
fn the_line_runs_from_the_judges_last_sign_of_life() {
    let after = duration_ns(policy().quiet_after);
    for (opened, life) in [(0, secs(30)), (1, secs(40))] {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        reach_usable(&mut core);
        core.on(dials(0, 1, Some(secs(1))), secs(1));
        core.on(lived(opened, 0, Some(life), Some(secs(1))), life);
        let failed = Some(life + secs(1));
        core.on(lived(opened, 1, Some(life), failed), life + secs(1));
        core.on(lived(opened, 1, Some(life), failed), life + after - 1);
        assert_eq!(core.status().tor_quiet, None, "{opened}: inside the span");
        let step = core.on(lived(opened, 1, Some(life), failed), life + after);
        assert_eq!(says_progress(&[step]), 1, "{opened}: said once");
        assert_eq!(
            core.status().tor_quiet,
            Some(TorQuiet::Unanswered(policy().quiet_after))
        );
    }
}

/// **No dial launched since the last sign of life and failed, no line**:
/// the line states the fact the dialer acted on, so a span with no such
/// failure says nothing however long it is. A failure launched before the
/// sign of life is not one, even when the tally carrying both arrives
/// after the byte (the cell keeps only the latest tally). Reading "some
/// dial failed, ever", or dating the failure when its tally arrived, fails
/// this.
#[test]
fn the_line_needs_a_dial_launched_since_the_last_sign_of_life() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let after = duration_ns(policy().quiet_after);
    let life = secs(20);
    core.on(dials(0, 1, Some(secs(10))), secs(10));
    core.on(lived(0, 1, Some(life), Some(secs(10))), secs(21));
    core.on(lived(0, 1, Some(life), Some(secs(10))), life + 2 * after);
    assert_eq!(
        core.status().tor_quiet,
        None,
        "the failure was launched before the byte"
    );
    let late = life + 2 * after + 1;
    let step = core.on(lived(0, 2, Some(life), Some(late)), late);
    assert_eq!(says_progress(&[step]), 1, "a dial launched since failed");
    assert!(core.status().tor_quiet.is_some());
}

/// **The sentence says what the judge observed**, neutral and with no fix
/// (`TSR-Q14`): peers are known, and none has answered through Tor for the
/// span (Rick, 2026-11-10). A sentence that names a cause or offers a fix
/// fails this.
#[test]
fn the_quiet_sentence_says_what_the_judge_observed() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(dials(0, 1, Some(secs(1))), secs(1));
    core.on(dials(0, 2, Some(secs(70))), secs(80));
    let text = said(&core);
    assert!(
        text.contains("Peers are known; none has answered through Tor for 1 min 20 s."),
        "{text}"
    );
    assert!(!text.contains("cannot reach"), "{text}");
}

/// Bring `core` to Running at `at`, after failures and life from before.
fn running_at(core: &mut Core, at: u64) {
    core.on(Input::PinAccepted, at);
    core.on(Input::Spawned, at);
    // Launch, subscription, and the sample `Spawned` queued. The progress
    // line is not said from behind a request the test has already treated
    // as finished.
    replied(core, at);
    replied(core, at);
    replied(core, at);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
        },
        at,
    );
    replied(core, at);
    core.on(Input::BootstrapComplete, at);
    // The onion's delete, then its add.
    replied(core, at);
    core.on(Input::OnionPublished, at);
    replied(core, at);
    core.on(Input::RouteInstalled, at);
}

/// **A failure launched before a respawn's Running raises nothing**
/// (`DIALER_OUTAGE_EVIDENCE.md` §6.1). Dials sent to the Tor that ended run
/// out their window after the new one reaches Running; they did not test
/// it. Dating the failure when it was counted, or starting the stretch at
/// the last sign of life alone, makes the line stand at once.
#[test]
fn a_failure_launched_before_a_respawns_running_raises_nothing() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let at = secs(100);
    core.on(lived(0, 9, Some(secs(50)), Some(secs(60))), at);
    running_at(&mut core, at);
    let after = duration_ns(policy().quiet_after);
    core.on(lived(0, 10, Some(secs(50)), Some(at - 1)), at + 1);
    core.on(lived(0, 11, Some(secs(50)), Some(at - 1)), at + 2 * after);
    assert_eq!(
        core.status().tor_quiet,
        None,
        "launched before Running, counted after it"
    );
}

/// **A failure launched after the stretch began still counts** (§6.1): one
/// dial sent to the new Tor and failed stands the line once the span has
/// elapsed. Filtering every failure that arrives after Running by anything
/// other than its launch fails this.
#[test]
fn a_failure_launched_inside_the_stretch_counts() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let at = secs(100);
    core.on(lived(0, 9, Some(secs(50)), Some(secs(60))), at);
    running_at(&mut core, at);
    let after = duration_ns(policy().quiet_after);
    core.on(lived(0, 10, Some(secs(50)), Some(at)), at + 1);
    let step = core.on(lived(0, 10, Some(secs(50)), Some(at)), at + after);
    assert_eq!(says_progress(&[step]), 1);
    assert!(core.status().tor_quiet.is_some());
}

/// **A failure launched before a wake raises nothing** (§6.1). A wake
/// starts the stretch again; a dial launched before the machine slept
/// fails after it, and did not test the link since the wake. Leaving the
/// stretch where the sleep found it fails this.
#[test]
fn a_failure_launched_before_a_wake_raises_nothing() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let after = duration_ns(policy().quiet_after);
    let woke = secs(50);
    let resumed = core.on(
        Input::Resumed {
            late_by: Duration::from_secs(600),
        },
        woke,
    );
    // The wake's sample is in flight. The quiet line waits until it is
    // answered, so a later dial is not said from behind it.
    if resumed.actions.contains(&Action::Sample) {
        replied(&mut core, woke);
    }
    core.on(dials(0, 1, Some(woke - 1)), woke + 1);
    core.on(dials(0, 2, Some(woke - 1)), woke + 2 * after);
    assert_eq!(core.status().tor_quiet, None, "launched before the wake");
    let step = core.on(dials(0, 3, Some(woke + 2 * after)), woke + 2 * after);
    assert_eq!(says_progress(&[step]), 1, "one launched after it counts");
}

/// **An old dial's success still counts** (§6.1): only failures are
/// filtered by launch. A stream that opens is a sign of life whenever its
/// dial was launched, and it starts the stretch again. Filtering successes
/// by launch too makes the line stand here.
#[test]
fn an_old_dials_success_still_counts() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let at = secs(100);
    running_at(&mut core, at);
    let after = duration_ns(policy().quiet_after);
    let failed = Some(at + 1);
    core.on(dials(0, 1, failed), at + 1);
    // A dial launched before Running opens its stream at `opened`.
    let opened = at + secs(50);
    core.on(lived(1, 0, Some(opened), failed), opened);
    core.on(lived(1, 0, Some(opened), failed), at + after + 1);
    assert_eq!(core.status().tor_quiet, None, "the open is life");
}

/// Tor's own view (`TSR-Q14`) governs even when Tor sends no event: its
/// liveness verdict `down` names the blocked link at once; both affirmative
/// answers clear it at once. Unknown says nothing, and neither does "no
/// circuit established", which is display only. During a bootstrap no
/// circuit is built yet, and a view folded then is not a statement.
/// *Changed by the VM clock findings (2026-10-30):* "no circuit" named the
/// blocked link, and after a resume, when Tor drops its circuits on
/// purpose, that was a false alarm.
#[test]
fn tors_sampled_view_names_and_clears_a_blocked_link_only_while_running() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let step = core.on(tor_says(Reported::Yes, Reported::No), 1);
    assert_eq!(announces(&step), 0);
    assert_eq!(
        core.status().cause,
        Cause::None,
        "bootstrapping: no circuit yet"
    );

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    assert_eq!(
        announces(&core.on(tor_says(Reported::Unknown, Reported::Unknown), 1)),
        0
    );
    let step = core.on(tor_says(Reported::No, Reported::Unknown), 2);
    assert_eq!(announces(&step), 1, "said at once");
    assert_eq!(core.status().cause, Cause::ExternalBlocked);
    assert_eq!(core.status().shown, Shown::Degraded);
    assert_eq!(
        announces(&core.on(tor_says(Reported::Yes, Reported::Unknown), 3)),
        0
    );
    assert_eq!(core.status().cause, Cause::ExternalBlocked, "a circuit too");
    let step = core.on(tor_says(Reported::Yes, Reported::Yes), 4);
    assert_eq!(announces(&step), 1, "the recovery is said at once");
    assert_eq!(core.status().cause, Cause::None);
    let step = core.on(tor_says(Reported::Yes, Reported::No), 5);
    assert_eq!(announces(&step), 0);
    assert_eq!(
        core.status().cause,
        Cause::None,
        "no circuit is not Tor saying its network is down"
    );
}

/// **After a resume, no circuit is not a block** (the VM suspend of
/// 2026-10-30). Tor drops its circuits on a clock jump and says so; the
/// sample after it reads `circuit-established=0` with liveness up. That
/// named the blocked link and said "cannot reach the Tor network" for the
/// seconds Tor took to rebuild. Reading "no circuit" as "blocked" again
/// fails this.
#[test]
fn the_sample_after_a_clock_jump_names_no_block() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::ClockJumped, 10);
    let step = core.on(tor_says(Reported::Yes, Reported::No), 11);
    assert_eq!(announces(&step), 0, "nothing is said");
    assert_eq!(core.status().cause, Cause::None);
    assert!(!said(&core).contains("cannot reach"));
    core.on(tor_says(Reported::Yes, Reported::Yes), 18);
    assert_eq!(core.status().cause, Cause::None);
}

/// "Process only when the control connection also fails" (Rick): a blocked
/// link does not stop a control failure from being a process fault.
#[test]
fn a_blocked_link_still_respawns_when_the_control_connection_fails() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::ExternalBlocked, 1);
    core.on(Input::ControlEnded, 2);
    assert!(matches!(core.status().cause, Cause::Died { .. }));
    assert_eq!(core.status().shown, Shown::Restarting);
    let due = core.deadline().expect("the respawn wait");
    let during = core.on_deadline(due);
    assert!(
        !during.actions.contains(&Action::CheckPin),
        "the pin waits for the reap: {during:?}"
    );
    let step = replied(&mut core, due);
    assert!(
        step.actions.contains(&Action::CheckPin),
        "{:?}",
        step.actions
    );
}

/// Tor saying it reaches its network clears what is about reaching the
/// network, which nothing did while Tor ran: a blocked link and an
/// unreachable directory. The open-file limit and a clock report are not
/// the network and keep their own evidence.
#[test]
fn tor_reaching_its_network_clears_the_network_causes_only() {
    for named in [Input::ExternalBlocked, Input::DirectoryUnreachable] {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        reach_usable(&mut core);
        core.on(named, 1);
        assert_eq!(core.status().shown, Shown::Degraded);
        let step = core.on(Input::ExternalCleared, 2);
        assert_eq!(announces(&step), 1, "the recovery is said at once");
        assert_eq!(core.status().cause, Cause::None);
        assert_eq!(core.status().shown, Shown::Usable);
    }
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::TooManyFiles { open: 1024 }, 3);
    let step = core.on(Input::ExternalCleared, 4);
    assert_eq!(announces(&step), 0);
    assert_eq!(core.status().cause, Cause::TooManyFiles { open: 1024 });
}

/// The line reads whether dials failed, never how many (the dialer lane's
/// #1190 keeps up to five Tor dials in flight): five failures landing at
/// once leave the posture exactly where one does, and the count reaches no
/// one, since Status carries only the stretch.
#[test]
fn the_line_reads_whether_dials_failed_not_how_many() {
    let late = duration_ns(policy().quiet_after) + 1;
    let mut seen = Vec::new();
    for unopened in [1, 5] {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        reach_usable(&mut core);
        let step = core.on(dials(0, unopened, Some(late)), late);
        seen.push((says_progress(&[step]), core.status()));
    }
    assert_eq!(
        seen[0], seen[1],
        "one failure and five are the same posture"
    );
    assert!(seen[0].1.tor_quiet.is_some());
}

/// A tally whose census is `census`, with `unopened` failed Tor dials, the
/// latest launched at `began`.
fn held(census: TorCensus, unopened: u32, began: Option<u64>) -> Input {
    tally(0, unopened, None, began, census)
}

/// **No peers known yet is its own line** (Rick, 2026-11-10). With the
/// dialer holding no Tor address there is nothing to dial, so no dial
/// fails; the line still stands at `quiet_after`, says so, once, and names
/// no cause. Fails if the line still needs a failed dial (nothing is said
/// at all), or if it says a peer did not answer.
#[test]
fn no_peers_known_yet_is_said_once() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let mut steps = vec![core.on(held(TorCensus::Empty, 0, None), secs(1))];
    steps.extend(run_until(&mut core, secs(120)));
    assert_eq!(says_progress(&steps), 1, "said once");
    assert_eq!(steps.iter().map(announces).sum::<usize>(), 0);
    let status = core.status();
    assert_eq!(status.tor_quiet, Some(TorQuiet::NoPeersKnown));
    assert_eq!(status.cause, Cause::None);
    let text = said_of(&status);
    assert!(text.contains("No peers are known yet."), "{text}");
    assert!(!text.contains("answered"), "{text}");
}

/// **Before the dialer's first census, nothing is said**, including when a
/// dial has failed. A pending census is not an empty one, and a failed
/// dial is not a census. Reading pending as empty says "no peers"; reading
/// it as peers known says "none has answered".
#[test]
fn no_census_yet_says_nothing() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let mut steps = vec![core.on(held(TorCensus::Pending, 0, None), secs(1))];
    let failed = Some(secs(2));
    steps.push(core.on(held(TorCensus::Pending, 1, failed), secs(2)));
    steps.extend(run_until(&mut core, secs(120)));
    assert_eq!(says_progress(&steps), 0);
    assert_eq!(core.status().tor_quiet, None);
    let text = said(&core);
    assert!(!text.contains("Peers are known"), "{text}");
    assert!(!text.contains("No peers are known"), "{text}");
}

/// **Peers learned, then none answering, is said again, once, and the
/// span starts when the run did.** The empty stretch is not time peers
/// were silent. The same fact evaluated again is not said. A return to an
/// empty census is said once more. Fails if a standing line swallows the
/// change, if every evaluation says it, or if the spoken span includes the
/// time before the dialer held anyone.
#[test]
fn peers_learned_and_unanswered_switch_the_line_once() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let after = duration_ns(policy().quiet_after);
    let mut steps = vec![core.on(held(TorCensus::Empty, 0, None), secs(1))];
    steps.extend(run_until(&mut core, secs(60)));
    assert_eq!(says_progress(&steps), 1, "no peers known yet");
    steps.clear();

    let learned = secs(61);
    let held_run = TorCensus::Held {
        seats: 6,
        since: learned,
    };
    steps.push(core.on(held(held_run, 1, Some(learned)), learned + secs(1)));
    steps.extend(run_until(&mut core, learned + after - 1));
    assert_eq!(
        says_progress(&steps),
        0,
        "one second of peers is not the empty stretch"
    );
    assert_eq!(core.status().tor_quiet, None);

    let due = learned + after;
    let step = core.on(held(held_run, 1, Some(learned)), due);
    assert!(
        step.actions.contains(&Action::SayProgress),
        "peers known, none answering"
    );
    assert_eq!(
        core.status().tor_quiet,
        Some(TorQuiet::Unanswered(policy().quiet_after)),
        "the span is the run, not the empty stretch"
    );
    steps.push(step);
    steps.extend(run_until(&mut core, due + secs(30)));
    steps.push(core.on(held(held_run, 9, Some(due)), due + secs(30)));
    assert_eq!(says_progress(&steps), 1, "the same fact is not said again");

    steps.clear();
    steps.push(core.on(held(TorCensus::Empty, 9, Some(due)), due + secs(31)));
    assert_eq!(says_progress(&steps), 1, "empty again is a new fact");
    assert_eq!(core.status().tor_quiet, Some(TorQuiet::NoPeersKnown));
}
