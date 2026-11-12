// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one renderer (`TSR-Q13`): the daemon's log line, `shekyl-cli` and the
//! GUI all say what this says, from the wire shape alone.
//!
//! Clauses in order: what the node does with its traffic; the named cause,
//! or else the quiet line; the clock; the onion; the bootstrap; the fixes;
//! and, once, that the node reported something this version does not know.

use crate::{
    Bootstrap, Carriage, Clearnet, Connector, Fix, ManagedTor, OnionCause, OnionState, Origination,
    Pace, Skew, TorCause, TorQuiet, TorSetting, TorStatus, Unusable,
};

/// Said once when the reply carries a keyword this build does not know
/// (rule 82): the rest is read as usual.
pub const UNKNOWN_SENTENCE: &str =
    "The node reports a Tor condition this version does not know. Update this program.";

const CHECK: &str = "Check this computer's date and time.";

/// The status in words. `data_dir` is Tor's data directory, named only by a
/// caller that holds the `config` grant (IG-Q97); the daemon's own log
/// always passes it.
#[must_use]
pub fn render(status: &TorStatus, data_dir: Option<&str>) -> String {
    // The posture is not spoken, but a keyword in it this build does not
    // know is still said, as every other is.
    let mut unknown = matches!(status.posture.tor, TorSetting::Unknown { .. })
        || matches!(status.posture.clearnet, Clearnet::Unknown { .. });
    let tor = status.tor.as_ref();
    let mut text = behaviour(status, &mut unknown);
    if let Some(cause) = tor.and_then(|tor| named_cause(tor, data_dir, &mut unknown)) {
        append(&mut text, &cause);
    } else if let Some(quiet) = quiet_sentence(status, &mut unknown) {
        append(&mut text, &quiet);
    }
    if let Some(clock) = tor.and_then(|tor| clock_sentence(tor, &mut unknown)) {
        append(&mut text, &clock);
    }
    if let Some(onion) = tor.and_then(|tor| onion_sentence(tor, &mut unknown)) {
        append(&mut text, &onion);
    }
    // The bootstrap is spoken exactly when `progress` is on the wire: the
    // snapshot alone decides when that is (Rick, 2026-11-12).
    if let Some((tor, progress)) = tor.and_then(|tor| tor.progress.map(|progress| (tor, progress)))
    {
        append(&mut text, &bootstrap_sentence(tor, progress, &mut unknown));
    }
    if let Some(tor) = tor.filter(|tor| !tor.fix.is_empty()) {
        append(&mut text, &fixes_sentence(&tor.fix, &mut unknown));
    }
    if unknown || status.has_unknown() {
        append(&mut text, UNKNOWN_SENTENCE);
    }
    text
}

fn append(text: &mut String, sentence: &str) {
    if !text.is_empty() {
        text.push(' ');
    }
    text.push_str(sentence);
}

/// What the node does with its traffic. Under a managed Tor the carriage
/// picks the sentence: the verdict lags a Tor that ended until the relay
/// sees its sessions close. Under an operator's Tor the origination alone
/// says it (Rick, 2026-11-12).
fn behaviour(status: &TorStatus, unknown: &mut bool) -> String {
    let carriage = status.tor.as_ref().map(|tor| &tor.carriage);
    match (&status.origination, carriage) {
        (Origination::AddressHiding, Some(Carriage::Carries) | None) => {
            "Tor is carrying this node's traffic.".to_owned()
        }
        (Origination::AddressHiding, Some(Carriage::OpenOnly)) => {
            "Connections already open through Tor still carry this node's traffic.".to_owned()
        }
        (Origination::AddressHiding, Some(Carriage::Gone)) => {
            held_sentence(false, &status.sync_connector, unknown)
        }
        (Origination::Connecting | Origination::Rebuilding, Some(carriage)) => {
            if let Carriage::Unknown { .. } = carriage {
                *unknown = true;
            }
            held_sentence(*carriage == Carriage::Carries, &status.sync_connector, unknown)
        }
        // An operator's Tor: a session that hides the address exists while
        // the origin pin is rebuilt; none does while it connects.
        (Origination::Connecting, None) => held_sentence(false, &status.sync_connector, unknown),
        (Origination::Rebuilding, None) => held_sentence(true, &status.sync_connector, unknown),
        (Origination::ClearnetOnly, _) => "This node is syncing and sending over the open network. Until the encrypted link is in place, that network is unencrypted.".to_owned(),
        (Origination::Offline, _) => "This node is offline.".to_owned(),
        (Origination::AddressHiding, Some(Carriage::Unknown { .. }))
        | (Origination::Unknown { .. }, _) => {
            *unknown = true;
            String::new()
        }
    }
}

/// The held sentence. The node is "waiting for Tor" only while the link is
/// not up; a held origin beside a usable link is holding, not waiting.
fn held_sentence(tor_up: bool, sync: &[Connector], unknown: &mut bool) -> String {
    let over_tor = sync.contains(&Connector::Tor);
    let over_clearnet = sync.contains(&Connector::Clearnet);
    if sync
        .iter()
        .any(|connector| matches!(connector, Connector::Unknown { .. }))
    {
        *unknown = true;
    }
    let syncing = match (over_tor, over_clearnet) {
        (true, true) => "It is syncing over Tor and clearnet.",
        (true, false) => "It is syncing over Tor.",
        (false, true) => "It is syncing over clearnet.",
        (false, false) => "It is not syncing.",
    };
    if tor_up {
        format!("This node is holding its own transactions. {syncing}")
    } else {
        format!("This node is waiting for Tor and holding its own transactions. {syncing}")
    }
}

/// What a refused pin means for a node not yet started: the configuration
/// check speaks it after the pin's cause (`INPUT_GRAMMAR.md` IG-Q59). Under
/// TB-2 it starts all the same, holds its own transactions, and syncs over
/// clearnet only when clearnet is on.
#[must_use]
pub fn held_at_start_sentence(clearnet_on: bool) -> String {
    let syncing = if clearnet_on {
        "It will sync over clearnet."
    } else {
        "It will not sync until Tor is up."
    };
    format!("When it starts, this node will wait for Tor and hold its own transactions. {syncing}")
}

/// The words for an install cause: a missing Tor, a refused pin, or no
/// managed Tor on this platform. The daemon's pin warning speaks these too.
/// `None` for every other cause.
#[must_use]
pub fn install_sentence(cause: &TorCause) -> Option<&'static str> {
    match cause {
        TorCause::Missing => Some("No Tor was found beside the daemon."),
        TorCause::InstallDefect => {
            Some("The Tor that was found failed its check, so it was not started.")
        }
        TorCause::Unavailable => Some("This release has no Tor for this platform yet."),
        _ => None,
    }
}

/// The named cause. The clock's causes are the clock clause's; the version
/// flag speaks when no cause does.
fn named_cause(tor: &ManagedTor, data_dir: Option<&str>, unknown: &mut bool) -> Option<String> {
    let Some(cause) = &tor.cause else {
        return tor
            .flagged
            .then(|| "Upgrade Shekyl when a release updates the bundled Tor.".to_owned());
    };
    Some(match cause {
        TorCause::ClockSkew(_) => return None,
        TorCause::Missing | TorCause::InstallDefect | TorCause::Unavailable => {
            install_sentence(cause)?.to_owned()
        }
        TorCause::LaunchFailed => "Tor did not start.".to_owned(),
        TorCause::Exited(code) => died_sentence(tor.respawn_count, *code),
        TorCause::Unusable(kind) => unusable_sentence(kind.as_ref(), data_dir, unknown),
        // Clock first: a wrong clock also stops every handshake, Tor may name
        // nothing more specific than the handshake, and the date takes the
        // operator ten seconds to check.
        TorCause::OutboundBlocked | TorCause::DirectoryUnreachable => {
            "This machine cannot reach the Tor network. Check this computer's date and time, then the firewall or the network.".to_owned()
        }
        TorCause::DescriptorLimit(open) => {
            format!("Tor reached the open-file limit ({open} open). Raise the limit.")
        }
        TorCause::Unanswered => "Tor stopped answering and is being started again.".to_owned(),
        TorCause::OnionRefused => {
            "Tor refused to publish this node's address again and is being started again."
                .to_owned()
        }
        TorCause::Stranded => {
            "Tor stopped making progress after this computer's clock changed, and is being started again."
                .to_owned()
        }
        TorCause::Unknown { .. } => {
            *unknown = true;
            return None;
        }
    })
}

fn unusable_sentence(
    kind: Option<&Unusable>,
    data_dir: Option<&str>,
    unknown: &mut bool,
) -> String {
    let named = data_dir.map_or_else(String::new, |path| format!(" {path}"));
    match kind {
        Some(Unusable::Exhausted { free, needed }) => format!(
            "Tor's data directory{named} has {} free and Tor needs {}. Free space there.",
            spoken_bytes(*free),
            spoken_bytes(*needed)
        ),
        Some(Unusable::Unknown { .. }) => {
            *unknown = true;
            format!("Tor's data directory{named} could not be used.")
        }
        Some(Unusable::Unwritable) | None => {
            format!("Tor's data directory{named} could not be used.")
        }
    }
}

fn died_sentence(count: u32, exit_code: Option<i32>) -> String {
    if count <= 1 {
        return "Tor stopped and is being started again.".to_owned();
    }
    match exit_code {
        Some(code) => format!(
            "Tor has stopped {count} times. The last exit code was {code}. It is being started again."
        ),
        None => format!("Tor has stopped {count} times and is being started again."),
    }
}

/// The quiet line, said only when the bootstrap line is not.
fn quiet_sentence(status: &TorStatus, unknown: &mut bool) -> Option<String> {
    if let Some(TorQuiet::Unknown { .. }) = status.tor_quiet {
        *unknown = true;
    }
    if status
        .tor
        .as_ref()
        .is_some_and(|tor| tor.progress.is_some())
    {
        return None;
    }
    Some(match status.tor_quiet.as_ref()? {
        TorQuiet::Empty => "No peers are known yet.".to_owned(),
        TorQuiet::Failing { age } => format!(
            "Peers are known; none has answered through Tor for {}.",
            spoken_duration(*age)
        ),
        TorQuiet::Unknown { .. } => {
            *unknown = true;
            return None;
        }
    })
}

/// The clock clause: Tor's figure, else the consensus check's lower bound,
/// else Tor's word that relays' certificates read as out of date.
fn clock_sentence(tor: &ManagedTor, unknown: &mut bool) -> Option<String> {
    if let Some(TorCause::ClockSkew(Some(Skew::Unknown { .. }))) = &tor.cause {
        *unknown = true;
    }
    let behind = tor.onion.as_ref().and_then(|onion| match onion.cause {
        Some(OnionCause::ClockBehind(seconds)) => Some(seconds),
        _ => None,
    });
    match &tor.cause {
        Some(TorCause::ClockSkew(Some(skew @ (Skew::Measured(_) | Skew::Minimum(_))))) => {
            Some(reported(skew, behind.is_some()))
        }
        _ if behind.is_some() => behind.map(lower_bound),
        Some(TorCause::ClockSkew(None)) => Some(format!(
            "Tor reports that this computer's date or time looks wrong, so it cannot connect. {CHECK}"
        )),
        _ => None,
    }
}

/// Tor's figure. The reachability clause is the consensus check's.
fn reported(skew: &Skew, consensus_behind: bool) -> String {
    let (seconds, bound) = match skew {
        Skew::Measured(seconds) => (*seconds, ""),
        Skew::Minimum(seconds) => (*seconds, "at least "),
        Skew::Unknown { .. } => (0, ""),
    };
    let span = spoken_span(seconds.unsigned_abs());
    let direction = if seconds < 0 { "behind" } else { "ahead of" };
    let reach = if consensus_behind {
        " Others may not be able to reach this node."
    } else {
        ""
    };
    format!("This computer's clock is {bound}{span} {direction} the Tor network's.{reach} {CHECK}")
}

/// The consensus check's lower bound. It only sees a clock behind.
fn lower_bound(behind: u64) -> String {
    let span = spoken_span(behind);
    format!(
        "This computer's clock is at least {span} behind the Tor network's. Others may not be able to reach this node. {CHECK}"
    )
}

/// The onion's clause, when it is down. The clock's is the clock clause.
fn onion_sentence(tor: &ManagedTor, unknown: &mut bool) -> Option<String> {
    let onion = tor.onion.as_ref()?;
    match (&onion.state, &onion.cause) {
        (OnionState::Unreachable, Some(OnionCause::ProbeMissed | OnionCause::DescriptorMissing)) => Some(
            "Peers cannot reach this node through Tor right now. Its address is being published again."
                .to_owned(),
        ),
        (OnionState::Unreachable, Some(OnionCause::UploadsRefused)) => Some(
            "The Tor network is not accepting this node's address right now. Others may not be able to reach this node."
                .to_owned(),
        ),
        (OnionState::Unknown { .. }, _) | (_, Some(OnionCause::Unknown { .. })) => {
            *unknown = true;
            None
        }
        _ => None,
    }
}

/// The bootstrap line: the percent, and how it is going. `progress` is a
/// sample, never a stand-in for a missing one (RK-D23).
fn bootstrap_sentence(tor: &ManagedTor, progress: u8, unknown: &mut bool) -> String {
    let fetching = format!("Tor is fetching the network directory ({progress}%)");
    let Some(Bootstrap {
        pace,
        unchanged,
        download,
        window,
    }) = &tor.bootstrap
    else {
        return format!("{fetching}.");
    };
    let held = spoken_duration(*unchanged);
    let window = spoken_duration(*window);
    match (pace, download) {
        (Pace::Advancing, Some(bytes)) if *bytes > 0 => format!(
            "{fetching}. {} arrived in the last {window}.",
            spoken_bytes(*bytes)
        ),
        (Pace::Advancing, _) => format!("{fetching}."),
        (Pace::Slow, Some(bytes)) => format!(
            "{fetching}, unchanged for {held}. {} arrived in the last {window}; a slow directory mirror can hold this for minutes.",
            spoken_bytes(*bytes)
        ),
        (Pace::Stalled, _) => {
            format!("{fetching}, unchanged for {held}. Nothing arrived in the last {window}.")
        }
        (Pace::Slow, None) | (Pace::Held, _) => format!("{fetching}, unchanged for {held}."),
        (Pace::Unknown { .. }, _) => {
            *unknown = true;
            format!("{fetching}.")
        }
    }
}

fn fixes_sentence(fixes: &[Fix], unknown: &mut bool) -> String {
    let mut parts = Vec::new();
    for fix in fixes {
        parts.push(match fix {
            Fix::RestoreManaged => "Restore the bundled Tor, or name one that passes its check.",
            Fix::Operator => "Or use a Tor you run yourself.",
            Fix::ClearnetOn => "Or turn clearnet on and keep Tor managed.",
            Fix::ClearnetOnly => {
                "Or turn Tor off and send over the open network. Until the encrypted link is in place, that network is unencrypted."
            }
            Fix::Unknown { .. } => {
                *unknown = true;
                continue;
            }
        });
    }
    parts.join(" ")
}

/// A duration, as the log says it.
fn spoken_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds} s")
    } else {
        format!("{} min {} s", seconds / 60, seconds % 60)
    }
}

/// A span that can run to days, at the precision the clock line needs.
fn spoken_span(seconds: u64) -> String {
    if seconds >= 86_400 {
        format!("{} d {} h", seconds / 86_400, seconds % 86_400 / 3_600)
    } else if seconds >= 3_600 {
        format!("{} h {} min", seconds / 3_600, seconds % 3_600 / 60)
    } else {
        spoken_duration(seconds)
    }
}

fn spoken_bytes(bytes: u64) -> String {
    // CLIPPY: a display figure; a byte count below 2^52 is exact in f64.
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes < 1_000 {
        format!("{bytes} bytes")
    } else if bytes < 1_000_000 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{:.1} MB", value / 1e6)
    }
}
