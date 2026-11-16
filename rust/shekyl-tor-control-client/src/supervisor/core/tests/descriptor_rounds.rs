// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Each descriptor's rounds in the core (`TOR_SUPERVISOR.md` §4.5; Rick,
//! 2026-11-15).
//!
//! The service's two descriptors upload on their own clocks, so the core
//! keeps one open round per descriptor: two rounds bring one probe, the
//! probe's list waits until both are `Policy::round_wait` old, a refusal of
//! one descriptor is not cleared by the other's accepted round, and a round
//! is counted stuck, or forgotten, on its own.

use super::super::super::posture::{Inbound, InboundCause};
use super::super::{Action, Input, RoundTally, Step};
use super::directories::{drive, fetched, ours, sent};
use super::probe::{probes, published, secs};
use super::{D0, D1};
use crate::control::DescriptorKey;

fn started(descriptor: DescriptorKey) -> Input {
    Input::UploadRoundStarted { descriptor }
}

fn first_uploaded(descriptor: DescriptorKey) -> Input {
    Input::FirstUploaded {
        descriptor,
        draw: 0,
    }
}

fn ended(descriptor: DescriptorKey, uploaded: u32, refused: u32, begun: u32) -> Input {
    Input::UploadRoundEnded {
        descriptor,
        tally: RoundTally {
            uploaded,
            refused,
            begun,
        },
        draw: 0,
    }
}

fn refused(core: &super::super::Core) -> bool {
    matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::UploadsRefused,
            ..
        }
    )
}

fn stuck(step: &Step) -> Vec<DescriptorKey> {
    step.actions
        .iter()
        .filter_map(|action| match action {
            Action::RoundStuck { descriptor } => Some(*descriptor),
            _ => None,
        })
        .collect()
}

/// **Two rounds close together bring one probe, and its list waits for
/// both** (the brief's B1). The current descriptor's round ends at 10 s and
/// schedules the probe for 25 s; the next descriptor's round began at 5 s
/// and is still open then, so the probe waits until it is 60 s old, at 65 s.
/// That round ends at 30 s and schedules nothing more: the probe in hand is
/// its one probe. One list is drawn, as the probe goes out. Fails if
/// `on_probe_deadline` sends the probe at 25 s, or a second round's end
/// schedules a second probe (a second list, which `drive` refuses).
#[test]
fn two_rounds_close_together_bring_one_probe_whose_list_waits_for_both() {
    let mut core = published();
    core.on(started(D0), 0);
    core.on(first_uploaded(D0), secs(2));
    core.on(started(D1), secs(5));
    core.on(ended(D0, 8, 0, 8), secs(10));
    let mut list = Some(sent(1..=8, "cur", 0));
    let before = drive(&mut core, secs(19), &mut list, &ours());
    assert_eq!(probes(&before), 0);
    core.on(first_uploaded(D1), secs(20));
    let held = drive(&mut core, secs(29), &mut list, &ours());
    assert_eq!(
        probes(&held),
        0,
        "held: the next descriptor's round is young"
    );
    core.on(ended(D1, 8, 0, 8), secs(30));
    let still = drive(&mut core, secs(64), &mut list, &ours());
    assert_eq!(probes(&still), 0, "the wait counts from the round's start");
    assert!(list.is_some(), "no list drawn before the probe goes out");
    let out = drive(&mut core, secs(65), &mut list, &ours());
    assert_eq!(probes(&out), 1, "the one probe, at 65 s");
    assert!(list.is_none());
    assert_eq!(fetched(&out).len(), 8);
    let after = drive(&mut core, secs(200), &mut list, &ours());
    assert_eq!(probes(&after), 0, "no second probe");
}

/// **One descriptor's refused round stands through the other's accepted
/// one** (the brief's B; Rick, 2026-11-15: a refused majority in either
/// descriptor's round is clock evidence). Only a round of the refused
/// descriptor that is accepted clears it. Fails if `uploads_accepted`
/// clears the refusal whatever the descriptor.
#[test]
fn a_refusal_of_one_descriptor_stands_through_the_others_acceptance() {
    let mut core = published();
    core.on(ended(D0, 1, 7, 8), secs(10));
    assert!(refused(&core));
    core.on(ended(D1, 8, 0, 8), secs(20));
    assert!(
        refused(&core),
        "the other descriptor's acceptance clears nothing"
    );
    core.on(ended(D0, 8, 0, 8), secs(30));
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
}

/// **A descriptor dropped after its refused round ended takes that refusal
/// with it.** The round is already closed, so there is no track to drop
/// and nothing to judge. The key will not be accepted again, including
/// when the same blinded id is seen under a new key. The sibling's
/// refusal stays. Fails if `round_forgotten` keeps the descriptor's
/// refusal, or if clearing one key clears the set.
#[test]
fn a_dropped_descriptors_closed_refusal_leaves_with_it() {
    let mut core = published();
    core.on(ended(D0, 1, 7, 8), secs(10));
    core.on(ended(D1, 1, 7, 8), secs(20));
    let forgot = core.on(Input::UploadRoundForgotten { descriptor: D0 }, secs(30));
    assert_eq!(probes(&forgot), 0, "a closed round is not judged again");
    assert!(
        refused(&core),
        "the sibling's refusal stands: {:?}",
        core.status().inbound
    );
    core.on(Input::UploadRoundForgotten { descriptor: D1 }, secs(40));
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "the last retired descriptor takes the facet with it: {:?}",
        core.status().inbound
    );
}

/// **A forgotten round is neither a success nor a failure.** Tor freed the
/// descriptor at a rotation: its open round is dropped without a probe or a
/// judgment, and its refusal no longer stands. With no round open, the
/// overdue rule counts again. Fails if `round_forgotten` judges the round,
/// or leaves its track or its refusal.
#[test]
fn a_forgotten_round_is_neither_a_success_nor_a_failure() {
    let mut core = published();
    core.on(ended(D0, 1, 7, 8), secs(10));
    core.on(started(D0), secs(20));
    core.on(first_uploaded(D0), secs(21));
    assert!(core.overdue_due().is_none(), "a round is open");
    let forgot = core.on(Input::UploadRoundForgotten { descriptor: D0 }, secs(22));
    assert_eq!(probes(&forgot), 0);
    assert!(core.rounds.is_empty());
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "the freed descriptor's refusal no longer stands: {:?}",
        core.status().inbound
    );
    assert!(
        core.overdue_due().is_some(),
        "the overdue rule counts again"
    );
}

/// **Each descriptor's round is counted stuck on its own age.** The current
/// descriptor's round opened at 0, the next one's at 100 s; each is said
/// stuck at its own 300 s, naming its descriptor, so the driver ends that
/// round only. Fails if `on_round_deadline` counts one shared round.
#[test]
fn each_round_is_counted_stuck_on_its_own_age() {
    let mut core = published();
    core.on(started(D0), 0);
    core.on(started(D1), secs(100));
    let early = drive(&mut core, secs(299), &mut None, &ours());
    assert!(stuck(&early).is_empty());
    let first = drive(&mut core, secs(300), &mut None, &ours());
    assert_eq!(stuck(&first), [D0]);
    let second = drive(&mut core, secs(400), &mut None, &ours());
    assert_eq!(stuck(&second), [D1]);
    assert_eq!(core.status().stuck_upload_rounds, 2);
}
