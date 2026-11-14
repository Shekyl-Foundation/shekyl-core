// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The supervisor where Tor is not this node's to run: `tor = off`, or an
//! operator's Tor (Rick, 2026-11-10: the status actor exists under every
//! setting). It answers the status from the relay's verdict and the
//! sessions, and never launches, checks a pin or announces.

use super::super::super::posture::{Connectors, OriginVerdict, OwnTx, Sessions, TorSetting};
use super::super::{Core, DialTally, Input, TorCensus};
use super::policy;

fn unmanaged(tor: TorSetting) -> Connectors {
    Connectors {
        tor,
        clearnet_on: true,
    }
}

/// **A Tor this node does not run is never launched.** Under `tor = off`
/// and an operator's Tor the core starts with nothing to do and no
/// deadline, and the verdict, the sessions and the dialer's tally fold
/// without an action: no pin check, no spawn, no posture line. Fails if
/// `start` checks the pin whatever the setting, or `say` announces a Tor
/// the node does not run.
#[test]
fn a_tor_this_node_does_not_run_is_never_launched() {
    for tor in [TorSetting::Off, TorSetting::Operator] {
        let (mut core, step) = Core::start(policy(), unmanaged(tor), 0);
        assert!(step.actions.is_empty(), "{tor:?}: {step:?}");
        assert_eq!(step.deadline, None, "{tor:?}");
        for input in [
            Input::AddressHidingOrigin(OriginVerdict::Routable),
            Input::Sessions(Sessions {
                clearnet: 2,
                tor: 3,
            }),
            Input::DialEvidence(DialTally {
                opened: 1,
                unopened: 0,
                last_sign_of_life: Some(1),
                failed_attempt_began: None,
                census: TorCensus::Held { seats: 1, since: 0 },
            }),
            Input::AddressHidingOrigin(OriginVerdict::Absent),
        ] {
            let step = core.on(input, 1);
            assert!(step.actions.is_empty(), "{tor:?}: {step:?}");
            assert_eq!(step.deadline, None, "{tor:?}");
        }
    }
}

/// **Its status carries the verdict and the sessions.** An operator's Tor
/// whose session hides this node's address and routes its origin reads
/// health and address-hiding; with clearnet the node syncs over both. Fails
/// if the unmanaged core does not fold what the network publishes.
#[test]
fn an_operators_tor_status_carries_the_verdict_and_the_sessions() {
    let (mut core, _) = Core::start(policy(), unmanaged(TorSetting::Operator), 0);
    core.on(Input::AddressHidingOrigin(OriginVerdict::Routable), 1);
    core.on(
        Input::Sessions(Sessions {
            clearnet: 2,
            tor: 3,
        }),
        1,
    );
    let status = core.status();
    assert!(status.health);
    assert_eq!(status.own_tx, OwnTx::AddressHiding);
    assert!(status.sync.tor && status.sync.clearnet, "{:?}", status.sync);
}

/// **An unmanaged supervisor's status never carries an install cause.**
/// A Tor this node does not run has no pin and no launch. Were a pin or
/// launch answer folded anyway, the core would show `unavailable` or a
/// refused pin, with the install fixes, against a Tor the operator runs;
/// it folds none of them, and the status keeps no cause and offers no fix.
/// Fails if the unmanaged core folds a launch's answer.
#[test]
fn an_unmanaged_status_never_carries_an_install_cause() {
    use super::super::super::posture::{Cause, Space};
    for tor in [TorSetting::Off, TorSetting::Operator] {
        let (mut core, _) = Core::start(policy(), unmanaged(tor), 0);
        for input in [
            Input::PinRefused,
            Input::BundleMissing,
            Input::Unavailable,
            Input::DirectoryUnusable {
                space: Some(Space {
                    available: 1,
                    needed: 2,
                }),
            },
            Input::accepted(),
            Input::Spawned,
            Input::SpawnFailed,
        ] {
            let named = format!("{tor:?} {input:?}");
            let step = core.on(input, 1);
            assert!(step.actions.is_empty(), "{named}: {step:?}");
            let status = core.status();
            assert_eq!(status.cause, Cause::None, "{named}");
            assert!(status.fixes.is_empty(), "{named}: {:?}", status.fixes);
        }
    }
}
