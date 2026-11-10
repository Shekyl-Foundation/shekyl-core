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

use super::super::super::posture::{
    render, Carriage, Cause, OwnTx, ReportedSkew, Shown, Space, Status,
};
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
        Cause::ClockSkew {
            skew: ReportedSkew::Measured(-259_200),
        },
        Cause::CertificatesOutOfDate,
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
            | Cause::CertificatesOutOfDate
            | Cause::TooManyFiles { .. }
            | Cause::ReplyLate
            | Cause::DangerousVersion
            | Cause::OnionRefused
            | Cause::StrandedAfterClockJump => {}
        }
    }
    all
}

const EVERY_CARRIAGE: [Carriage; 3] = [Carriage::Carries, Carriage::OpenOnly, Carriage::Gone];

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

/// The traffic sentences follow [`Carriage`], the core's reading of the
/// link, and nothing else: whatever the projection and the cause, "Tor is
/// carrying this node's traffic" is said only while the link carries, open
/// connections are said to carry only while the Tor holding them runs, and
/// a held node waits for Tor only while the link does not carry. Which
/// causes leave the link carrying is the core's
/// (`a_version_warning_beside_an_unreachable_onion_leaves_the_link_carrying`,
/// `a_dead_tor_carries_nothing_while_the_verdict_lags`). Deriving a sentence
/// from the shown state or the cause again fails this for a pair it reads
/// differently.
#[test]
fn the_traffic_sentences_follow_the_carriage_whatever_the_cause_and_shown_state() {
    let mut rendered = 0;
    for cause in every_cause() {
        for shown in EVERY_SHOWN {
            for carriage in EVERY_CARRIAGE {
                for own_tx in EVERY_OWN_TX {
                    let status = Status {
                        cause: cause.clone(),
                        shown,
                        carriage,
                        own_tx,
                        ..held_status()
                    };
                    let text = render(&status);
                    rendered += 1;
                    let at = format!("{cause:?} / {shown:?} / {carriage:?} / {own_tx:?}: {text}");
                    let hiding = own_tx == OwnTx::AddressHiding;
                    assert_eq!(
                        text.contains("Tor is carrying this node's traffic"),
                        hiding && carriage == Carriage::Carries,
                        "{at}"
                    );
                    assert_eq!(
                        text.contains("Connections already open through Tor still carry"),
                        hiding && carriage == Carriage::OpenOnly,
                        "{at}"
                    );
                    let held = own_tx == OwnTx::Held || (hiding && carriage == Carriage::Gone);
                    assert_eq!(text.contains("holding its own transactions"), held, "{at}");
                    assert_eq!(
                        text.contains("waiting for Tor"),
                        held && carriage != Carriage::Carries,
                        "{at}"
                    );
                }
            }
        }
    }
    assert_eq!(rendered, 16 * 5 * 3 * 4);
}

/// Tor's process ends while the relay still holds an address-hiding
/// verdict: the sessions over the dead Tor close only after the relay sees
/// them go. Until then the line says the node is held and claims nothing
/// for connections the dead Tor held. Rendering the open-connections
/// sentence from the lagging verdict fails this.
#[test]
fn a_dead_tor_carries_nothing_while_the_verdict_lags() {
    let (mut core, _) = super::Core::start(super::policy(), super::managed(true), 0);
    super::reach_usable(&mut core);
    core.on(super::carrying(), 0);
    assert_eq!(core.status().own_tx, OwnTx::AddressHiding);
    let step = core.on(
        super::Input::ProcessEnded { exit_code: Some(9) },
        5_000_000_000,
    );
    assert!(super::takes_down(&step));
    let status = core.status();
    assert_eq!(status.shown, Shown::Restarting);
    assert_eq!(status.own_tx, OwnTx::AddressHiding, "the verdict lags");
    let text = render(&status);
    assert!(!text.contains("carry"), "{text}");
    assert!(text.contains("holding its own transactions"), "{text}");
}
