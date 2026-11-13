// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire shape and its renderer (`docs/design/TOR_STATUS_CRATE.md` §6).

use std::collections::HashSet;
use std::mem::discriminant;

use crate::*;

/// A managed Tor bootstrapping with nothing wrong.
fn managed() -> TorStatus {
    TorStatus {
        posture: Posture {
            tor: TorSetting::Managed,
            clearnet: Clearnet::Off,
        },
        origination: Origination::Connecting,
        sync_connector: vec![],
        tor_quiet: None,
        tor: Some(ManagedTor {
            state: TorState::Bootstrapping,
            cause: None,
            age: 12,
            respawn_count: 0,
            progress: Some(30),
            flagged: false,
            fix: vec![],
            onion: None,
            bootstrap: None,
            carriage: Carriage::Gone,
        }),
    }
}

fn with_tor(change: impl FnOnce(&mut ManagedTor)) -> TorStatus {
    let mut status = managed();
    change(status.tor.as_mut().expect("managed"));
    status
}

fn unknown(tag: &str) -> String {
    tag.to_owned()
}

// Exhaustive matches: a variant added without a sample below does not
// compile, and the sample lists are checked to cover every arm.

fn cause_arm(cause: &TorCause) -> u8 {
    match cause {
        TorCause::OutboundBlocked => 0,
        TorCause::DirectoryUnreachable => 1,
        TorCause::ClockSkew(_) => 2,
        TorCause::DescriptorLimit(_) => 3,
        TorCause::Exited(_) => 4,
        TorCause::Unanswered => 5,
        TorCause::LaunchFailed => 6,
        TorCause::InstallDefect => 7,
        TorCause::Missing => 8,
        TorCause::Unavailable => 9,
        TorCause::Unusable(_) => 10,
        TorCause::OnionRefused => 11,
        TorCause::Stranded => 12,
        TorCause::Unknown { .. } => 13,
    }
}

fn causes() -> Vec<TorCause> {
    vec![
        TorCause::OutboundBlocked,
        TorCause::DirectoryUnreachable,
        TorCause::ClockSkew(None),
        TorCause::ClockSkew(Some(Skew::Measured(-259_201))),
        TorCause::ClockSkew(Some(Skew::Minimum(7_200))),
        TorCause::ClockSkew(Some(Skew::Unknown {
            tag: unknown("estimated"),
        })),
        TorCause::DescriptorLimit(4_096),
        TorCause::Exited(Some(1)),
        TorCause::Exited(None),
        TorCause::Unanswered,
        TorCause::LaunchFailed,
        TorCause::InstallDefect,
        TorCause::Missing,
        TorCause::Unavailable,
        TorCause::Unusable(None),
        TorCause::Unusable(Some(Unusable::Exhausted {
            free: 1_000_000,
            needed: 70_000_000,
        })),
        TorCause::Unusable(Some(Unusable::Unwritable)),
        TorCause::Unusable(Some(Unusable::Unknown {
            tag: unknown("read-only"),
        })),
        TorCause::OnionRefused,
        TorCause::Stranded,
        TorCause::Unknown {
            tag: unknown("melted"),
        },
    ]
}

fn onion_cause_arm(cause: &OnionCause) -> u8 {
    match cause {
        OnionCause::ProbeMissed => 0,
        OnionCause::UploadsRefused => 1,
        OnionCause::DescriptorMissing => 2,
        OnionCause::ClockBehind(_) => 3,
        OnionCause::Unknown { .. } => 4,
    }
}

fn onion_causes() -> Vec<OnionCause> {
    vec![
        OnionCause::ProbeMissed,
        OnionCause::UploadsRefused,
        OnionCause::DescriptorMissing,
        OnionCause::ClockBehind(3_600),
        OnionCause::Unknown {
            tag: unknown("blinded"),
        },
    ]
}

fn quiet_arm(quiet: &TorQuiet) -> u8 {
    match quiet {
        TorQuiet::Empty => 0,
        TorQuiet::Failing { .. } => 1,
        TorQuiet::Unknown { .. } => 2,
    }
}

fn quiets() -> Vec<TorQuiet> {
    vec![
        TorQuiet::Empty,
        TorQuiet::Failing { age: 130 },
        TorQuiet::Unknown {
            tag: unknown("muted"),
        },
    ]
}

/// Every keyword set's known variants and one unknown.
fn with_unknown<T>(known: Vec<T>, unknown: T) -> Vec<T> {
    let mut all = known;
    all.push(unknown);
    all
}

/// A status for every variant of every set on the wire.
fn table() -> Vec<TorStatus> {
    let mut table = Vec::new();
    for tor in with_unknown(
        TorSetting::known(),
        TorSetting::Unknown {
            tag: unknown("bridge"),
        },
    ) {
        let mut status = managed();
        status.posture.tor = tor;
        table.push(status);
    }
    for clearnet in with_unknown(
        Clearnet::known(),
        Clearnet::Unknown {
            tag: unknown("lan"),
        },
    ) {
        let mut status = managed();
        status.posture.clearnet = clearnet;
        table.push(status);
    }
    for origination in with_unknown(
        Origination::known(),
        Origination::Unknown {
            tag: unknown("mixnet"),
        },
    ) {
        let mut status = managed();
        status.origination = origination;
        table.push(status);
    }
    for connector in with_unknown(
        Connector::known(),
        Connector::Unknown {
            tag: unknown("i2p"),
        },
    ) {
        let mut status = managed();
        status.sync_connector = vec![connector];
        table.push(status);
    }
    for quiet in quiets() {
        let mut status = managed();
        status.tor_quiet = Some(quiet);
        if let Some(tor) = status.tor.as_mut() {
            tor.state = TorState::Usable;
            tor.progress = None;
        }
        table.push(status);
    }
    for state in with_unknown(
        TorState::known(),
        TorState::Unknown {
            tag: unknown("dormant"),
        },
    ) {
        table.push(with_tor(|tor| tor.state = state));
    }
    for cause in causes() {
        table.push(with_tor(|tor| tor.cause = Some(cause)));
    }
    for fix in with_unknown(
        Fix::known(),
        Fix::Unknown {
            tag: unknown("reinstall"),
        },
    ) {
        table.push(with_tor(|tor| {
            tor.cause = Some(TorCause::Missing);
            tor.fix = vec![fix];
        }));
    }
    for carriage in with_unknown(
        Carriage::known(),
        Carriage::Unknown {
            tag: unknown("partial"),
        },
    ) {
        let carriage_status = with_tor(|tor| tor.carriage = carriage);
        table.push(carriage_status);
    }
    for state in with_unknown(
        OnionState::known(),
        OnionState::Unknown {
            tag: unknown("hidden"),
        },
    ) {
        table.push(with_tor(|tor| {
            tor.onion = Some(Onion {
                state,
                age: 40,
                cause: None,
            });
        }));
    }
    for cause in onion_causes() {
        table.push(with_tor(|tor| {
            tor.onion = Some(Onion {
                state: OnionState::Unreachable,
                age: 40,
                cause: Some(cause),
            });
        }));
    }
    for pace in with_unknown(
        Pace::known(),
        Pace::Unknown {
            tag: unknown("racing"),
        },
    ) {
        for download in [None, Some(0), Some(48_000)] {
            table.push(with_tor(|tor| {
                tor.bootstrap = Some(Bootstrap {
                    pace: pace.clone(),
                    unchanged: 75,
                    download,
                    window: 30,
                });
            }));
        }
    }
    table.push(TorStatus {
        tor: None,
        posture: Posture {
            tor: TorSetting::Operator,
            clearnet: Clearnet::On,
        },
        origination: Origination::AddressHiding,
        sync_connector: vec![Connector::Clearnet, Connector::Tor],
        tor_quiet: None,
    });
    table
}

/// **The table covers every arm.** Fails when a sample list leaves out a
/// variant the exhaustive matches above name.
#[test]
fn the_table_covers_every_arm() {
    let table = table();
    let seen = |arms: &dyn Fn(&TorStatus) -> Option<u8>| -> HashSet<u8> {
        table.iter().filter_map(arms).collect()
    };
    let causes = seen(&|s| s.tor.as_ref()?.cause.as_ref().map(cause_arm));
    assert_eq!(causes.len(), 14, "{causes:?}");
    let onion = seen(&|s| {
        s.tor
            .as_ref()?
            .onion
            .as_ref()?
            .cause
            .as_ref()
            .map(onion_cause_arm)
    });
    assert_eq!(onion.len(), 5, "{onion:?}");
    let quiet = seen(&|s| s.tor_quiet.as_ref().map(quiet_arm));
    assert_eq!(quiet.len(), 3, "{quiet:?}");
    let skews: HashSet<_> = causes_of(&table)
        .filter_map(|cause| match cause {
            TorCause::ClockSkew(Some(skew)) => Some(discriminant(skew)),
            _ => None,
        })
        .collect();
    assert_eq!(skews.len(), 3);
    let unusable: HashSet<_> = causes_of(&table)
        .filter_map(|cause| match cause {
            TorCause::Unusable(Some(kind)) => Some(discriminant(kind)),
            _ => None,
        })
        .collect();
    assert_eq!(unusable.len(), 3);
}

fn causes_of(table: &[TorStatus]) -> impl Iterator<Item = &TorCause> {
    table
        .iter()
        .filter_map(|status| status.tor.as_ref()?.cause.as_ref())
}

/// **Round trip:** every status in the table encodes, decodes to itself,
/// and renders the same before and after. Fails if an encoder and its
/// decoder disagree on any keyword or payload.
#[test]
fn every_status_round_trips() {
    for status in table() {
        let wire = serde_json::to_string(&status).expect("encodes");
        let back: TorStatus = serde_json::from_str(&wire).expect("decodes");
        assert_eq!(back, status, "{wire}");
        assert_eq!(
            render(&back, Some("/data/tor")),
            render(&status, Some("/data/tor")),
            "{wire}"
        );
    }
}

/// **The wire is §23's shape:** one-key objects, null for no cause, ages as
/// integers. Fails if a payload is encoded under another key or nesting.
#[test]
fn the_wire_is_the_ruled_shape() {
    let status = with_tor(|tor| {
        tor.cause = Some(TorCause::ClockSkew(Some(Skew::Measured(-5))));
        tor.onion = Some(Onion {
            state: OnionState::Unreachable,
            age: 40,
            cause: Some(OnionCause::ClockBehind(3_600)),
        });
    });
    let value = serde_json::to_value(&status).expect("encodes");
    assert_eq!(value["posture"]["tor"], "managed");
    assert_eq!(value["origination"], "connecting");
    assert_eq!(value["tor"]["cause"]["clock-skew"]["measured"], -5);
    assert_eq!(value["tor"]["onion"]["cause"]["clock-behind"], 3_600);
    assert_eq!(value["tor"]["age"], 12);
    assert!(value["tor_quiet"].is_null());
    let quiet = serde_json::to_value(TorQuiet::Failing { age: 130 }).expect("encodes");
    assert_eq!(quiet, serde_json::json!({"failing": {"age": 130}}));
    let empty = serde_json::to_value(TorQuiet::Empty).expect("encodes");
    assert_eq!(empty, serde_json::json!({"empty": null}));
    let hold = serde_json::to_value(TorCause::Unusable(Some(Unusable::Exhausted {
        free: 1,
        needed: 2,
    })))
    .expect("encodes");
    assert_eq!(
        hold,
        serde_json::json!({"unusable": {"exhausted": {"free": 1, "needed": 2}}})
    );
    let certificates = serde_json::to_value(TorCause::ClockSkew(None)).expect("encodes");
    assert_eq!(certificates, serde_json::json!({"clock-skew": null}));
    // The refused file stays in the daemon's log (Rick, 2026-11-12).
    let defect = serde_json::to_value(TorCause::InstallDefect).expect("encodes");
    assert_eq!(defect, serde_json::json!({"install-defect": null}));
}

/// **An unknown keyword decodes, in every set, and the rest of the reply is
/// intact.** Each line plants one keyword this build does not know; the
/// reply decodes, the planted value is `Unknown` with its tag, the other
/// fields read as encoded, and the line says the update sentence. Fails if
/// a decoder refuses an unknown keyword, which would fail the whole reply.
#[test]
fn an_unknown_keyword_decodes_and_says_so() {
    let base = serde_json::to_value(managed()).expect("encodes");
    let plants: [(&str, serde_json::Value); 9] = [
        ("/posture/clearnet", serde_json::json!("lan")),
        ("/origination", serde_json::json!("mixnet")),
        ("/sync_connector", serde_json::json!(["i2p"])),
        ("/tor_quiet", serde_json::json!({"muted": null})),
        ("/tor/state", serde_json::json!("dormant")),
        ("/tor/cause", serde_json::json!({"melted": {"heat": 9}})),
        ("/tor/carriage", serde_json::json!("partial")),
        (
            "/tor/onion",
            serde_json::json!({"state": "unreachable", "age": 4, "cause": {"blinded": 1}}),
        ),
        (
            "/tor/bootstrap",
            serde_json::json!({"pace": "racing", "unchanged": 1, "download": null, "window": 30}),
        ),
    ];
    for (pointer, planted) in plants {
        let mut value = base.clone();
        *value.pointer_mut(pointer).expect("the field") = planted;
        let status: TorStatus = serde_json::from_value(value).unwrap_or_else(|error| {
            panic!("{pointer}: an unknown keyword failed the reply: {error}")
        });
        assert_eq!(
            status.tor.as_ref().map(|tor| tor.respawn_count),
            Some(0),
            "{pointer}: the rest of the reply"
        );
        let line = render(&status, None);
        assert!(line.contains(UNKNOWN_SENTENCE), "{pointer}: {line}");
        assert_eq!(
            line.matches(UNKNOWN_SENTENCE).count(),
            1,
            "{pointer}: {line}"
        );
    }
    let mut value = base;
    *value.pointer_mut("/tor/cause").expect("cause") = serde_json::json!({"melted": null});
    let status: TorStatus = serde_json::from_value(value).expect("decodes");
    assert_eq!(
        status.tor.and_then(|tor| tor.cause),
        Some(TorCause::Unknown {
            tag: "melted".to_owned()
        })
    );
}

/// **A cause carries one key.** Two keys are refused: the variant is the
/// one key (IG-Q70). Fails if a second key is read as detail.
#[test]
fn a_cause_with_two_keys_is_refused() {
    let two = serde_json::json!({"missing": null, "unavailable": null});
    assert!(serde_json::from_value::<TorCause>(two).is_err());
}

/// **An unknown origination fails closed** (Rick, 2026-11-12). A reply
/// carrying an origination keyword this build does not know never reads as
/// address-hiding through the accessors a send decision uses, whatever the
/// posture. Fails if an unknown keyword is read as hiding.
#[test]
fn an_unknown_origination_never_reads_as_address_hiding() {
    let mut status = managed();
    status.origination = serde_json::from_value(serde_json::json!("mixnet")).expect("decodes");
    for tor in TorSetting::known() {
        status.posture.tor = tor;
        assert!(!status.own_tx_hides_address(), "{:?}", status.posture);
    }
}

/// **An unknown posture fails closed** (Rick, 2026-11-12): with
/// `origination` address-hiding, a `posture.tor` or `posture.clearnet` this
/// build does not know, or Tor `off`, does not read as hiding, and the reply
/// renders the update sentence. Fails if the send decision trusts the
/// origination alone, or reads either half of the posture as known.
#[test]
fn an_unknown_posture_never_reads_as_address_hiding() {
    let mut status = managed();
    status.origination = Origination::AddressHiding;
    assert!(status.own_tx_hides_address());
    status.posture.tor = serde_json::from_value(serde_json::json!("bridge")).expect("decodes");
    assert!(!status.own_tx_hides_address());
    assert!(render(&status, None).contains(UNKNOWN_SENTENCE));
    status.posture.tor = TorSetting::Off;
    assert!(!status.own_tx_hides_address());
    for tor in [TorSetting::Managed, TorSetting::Operator] {
        status.posture.tor = tor;
        status.posture.clearnet =
            serde_json::from_value(serde_json::json!("relay-only")).expect("decodes");
        assert!(!status.own_tx_hides_address(), "{:?}", status.posture);
        assert!(render(&status, None).contains(UNKNOWN_SENTENCE));
    }
}

/// **An operator's Tor speaks from origination alone, with no fix** (Rick,
/// 2026-11-12). With no managed Tor, address-hiding says Tor carries the
/// traffic; connecting says the node waits and holds; nothing offers a
/// managed fix. Fails if the renderer needs a managed object to speak.
#[test]
fn an_operators_tor_speaks_from_origination_alone() {
    let mut status = TorStatus {
        posture: Posture {
            tor: TorSetting::Operator,
            clearnet: Clearnet::Off,
        },
        origination: Origination::AddressHiding,
        sync_connector: vec![Connector::Tor],
        tor_quiet: None,
        tor: None,
    };
    assert_eq!(
        render(&status, None),
        "Tor is carrying this node's traffic."
    );
    status.origination = Origination::Connecting;
    let line = render(&status, None);
    assert!(
        line.starts_with("This node is waiting for Tor and holding"),
        "{line}"
    );
    assert!(!line.contains("Restore the bundled Tor"), "{line}");
    status.origination = Origination::Rebuilding;
    assert!(render(&status, None).starts_with("This node is holding its own transactions."));
}

/// **A null percent is never printed** (Rick, 2026-11-12; RK-D23: 0 is a
/// sample). The renderer speaks the bootstrap exactly when `progress` is on
/// the wire, whatever the state says. Fails if the renderer keeps its own
/// rule for when the bootstrap is spoken, or prints a missing percent as 0%.
#[test]
fn a_bootstrap_with_no_percent_prints_none() {
    let status = with_tor(|tor| {
        tor.state = TorState::Bootstrapping;
        tor.progress = None;
    });
    let line = render(&status, None);
    assert!(!line.contains('%'), "{line}");
    assert!(!line.contains("fetching the network directory"), "{line}");

    let impaired = with_tor(|tor| {
        tor.state = TorState::Impaired;
        tor.progress = Some(0);
    });
    let line = render(&impaired, None);
    assert!(
        line.contains("fetching the network directory (0%)"),
        "{line}"
    );
}

/// **The data directory is named only when the caller passes it** (Rick,
/// 2026-11-12: only a caller holding `config`). Fails if the renderer names
/// a path the caller did not give, or drops one it did.
#[test]
fn the_data_directory_is_named_only_when_given() {
    let status = with_tor(|tor| {
        tor.state = TorState::Waiting;
        tor.cause = Some(TorCause::Unusable(Some(Unusable::Exhausted {
            free: 1_000_000,
            needed: 70_000_000,
        })));
    });
    let named = render(&status, Some("/var/lib/shekyl/tor"));
    assert!(
        named.contains(
            "Tor's data directory /var/lib/shekyl/tor has 1.0 MB free and Tor needs 70.0 MB."
        ),
        "{named}"
    );
    let unnamed = render(&status, None);
    assert!(
        unnamed.contains("Tor's data directory has 1.0 MB free"),
        "{unnamed}"
    );
    assert!(names_data_dir(&status));
    assert!(!names_data_dir(&managed()));
}
