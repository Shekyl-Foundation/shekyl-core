// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one renderer against every state it can be handed (`TSR-Q13`).
//!
//! A sentence that says Tor carries the node's traffic and a sentence that
//! says Tor cannot carry it must never stand together (the VM suspend of
//! 2026-10-30 rendered "Tor is carrying this node's traffic. This machine
//! cannot reach the Tor network.").

use super::super::super::posture::{render, Cause, OwnTx, Shown, Space, Status};
use super::held_status;

/// Every cause kind, one detail each. The match below makes a new variant
/// a compile error here until it is added.
fn every_cause() -> Vec<Cause> {
    let all = vec![
        Cause::None,
        Cause::BundleMissing,
        Cause::PinRefused,
        Cause::Unavailable,
        Cause::FailedStart,
        Cause::Died { exit_code: Some(1) },
        Cause::DirectoryUnusable {
            path: std::path::PathBuf::from("/var/lib/shekyl"),
            space: Some(Space {
                available: 0,
                needed: 1,
            }),
        },
        Cause::ExternalBlocked,
        Cause::DirectoryUnreachable,
        Cause::ClockSkew { seconds: -259_200 },
        Cause::TooManyFiles { open: 1024 },
        Cause::ReplyLate,
        Cause::DangerousVersion,
        Cause::OnionRefused,
        Cause::StrandedAfterClockJump,
    ];
    for cause in &all {
        match cause {
            Cause::None
            | Cause::BundleMissing
            | Cause::PinRefused
            | Cause::Unavailable
            | Cause::FailedStart
            | Cause::Died { .. }
            | Cause::DirectoryUnusable { .. }
            | Cause::ExternalBlocked
            | Cause::DirectoryUnreachable
            | Cause::ClockSkew { .. }
            | Cause::TooManyFiles { .. }
            | Cause::ReplyLate
            | Cause::DangerousVersion
            | Cause::OnionRefused
            | Cause::StrandedAfterClockJump => {}
        }
    }
    all
}

const EVERY_SHOWN: [Shown; 5] = [
    Shown::Restarting,
    Shown::RestartingHeld,
    Shown::Bootstrapping,
    Shown::Usable,
    Shown::Degraded,
];

const EVERY_OWN_TX: [OwnTx; 4] = [
    OwnTx::AddressHiding,
    OwnTx::Held,
    OwnTx::ClearnetOnly,
    OwnTx::Offline,
];

/// "Tor is carrying this node's traffic" is said only while the link shows
/// usable, or degraded on its inbound side alone, whatever the relay's
/// verdict: beside every other shown state and every cause it would
/// contradict what follows. Saying it from the verdict alone, as before,
/// fails this for every pair of a fault or network cause with an
/// address-hiding origin.
#[test]
fn no_rendering_says_tor_carries_traffic_beside_a_cause_that_says_it_cannot() {
    let mut rendered = 0;
    for cause in every_cause() {
        for shown in EVERY_SHOWN {
            for own_tx in EVERY_OWN_TX {
                let status = Status {
                    cause: cause.clone(),
                    shown,
                    own_tx,
                    ..held_status()
                };
                let text = render(&status);
                rendered += 1;
                let carries = text.contains("Tor is carrying this node's traffic");
                let allowed =
                    shown == Shown::Usable || (shown == Shown::Degraded && cause == Cause::None);
                assert!(
                    !carries || allowed,
                    "{cause:?} / {shown:?} / {own_tx:?}: {text}"
                );
                if own_tx == OwnTx::AddressHiding && !allowed {
                    assert!(
                        text.contains("Connections already open through Tor still carry"),
                        "{cause:?} / {shown:?}: {text}"
                    );
                }
            }
        }
    }
    assert_eq!(rendered, 15 * 5 * 4);
}
