// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one stop owner (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 6 and step 9).
//!
//! Every trigger reaches one latch: the operating system's stop triggers
//! through [`own`], which forwards the first of them from
//! `shekyl_process::stop` (the triggers every Shekyl program takes; a
//! second stop exits at once there); the RPC's `daemon_stop`
//! (`shekyl-cli daemon stop`) through [`request_stop`]; a task the node
//! owns ending on its own, through [`fatal`]; and the Tor supervisor
//! ending on its own, through [`tor_ended`]. A task's own end makes the
//! exit a failure. A wait is [`stop_requested`], which answers at once
//! when the latch is already set, so a trigger that arrives between two
//! waits (the managed Tor's bootstrap sits between the RPC start and step
//! 8) is kept, not dropped.
//!
//! The latch is per daemon start: [`own`] clears it and retires the
//! previous start. A request made before this start, and a signal the
//! replaced arm already read, do not stop the daemon they were not meant for.

use std::fmt;
use std::sync::Mutex;

use shekyl_node::NodeEnd;

use crate::tor::SupervisorEnd;
use shekyl_process::stop::{FirstStop, Inherited, Stops, Trigger};
use tokio::sync::Notify;

/// Why the daemon stops. The report matches the variant: an operator's
/// stop is announced, and [`Self::Fatal`] is an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// The operating system's stop trigger: a service manager's or a
    /// terminal's ordinary way to stop the daemon.
    Signal(Trigger),
    /// The RPC's `daemon_stop`, which `shekyl-cli daemon stop` posts.
    Requested,
    /// The owner's socket, or its directory, went from under the running
    /// daemon: the session that started it ended (`RPC_CHANNEL.md` §7.1).
    RendezvousGone,
    /// The process that started this daemon closed its owning connection,
    /// or died (`INPUT_GRAMMAR.md` IG-Q106).
    OwningConnectionClosed,
    /// A task the node owns ended on its own ([`shekyl_node::Node::ended`]).
    Fatal(NodeEnd),
    /// The Tor supervisor, which the daemon starts beside the node, ended
    /// on its own ([`crate::tor::Supervisor::ended`]).
    TorEnded(SupervisorEnd),
}

impl StopCause {
    /// Whether this stop makes the exit a failure: a task's own end, not an
    /// operator's stop.
    #[must_use]
    pub fn fails_the_exit(&self) -> bool {
        match self {
            Self::Fatal(_) | Self::TorEnded(_) => true,
            Self::Signal(_)
            | Self::Requested
            | Self::RendezvousGone
            | Self::OwningConnectionClosed => false,
        }
    }
}

impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(trigger) => f.write_str(trigger.name()),
            Self::Requested => f.write_str("the RPC's daemon_stop"),
            Self::RendezvousGone => f.write_str("the owner's socket going"),
            Self::OwningConnectionClosed => {
                f.write_str("the process that started this daemon closing its owning connection")
            }
            Self::Fatal(end) => write!(f, "{end}"),
            Self::TorEnded(end) => write!(f, "{end}"),
        }
    }
}

/// One daemon start's latch. `generation` advances in [`own`]; a signal
/// publishes only when it still names the start that armed it.
struct Latch {
    generation: u64,
    cause: Option<StopCause>,
}

/// The latched cause, and which start it belongs to.
static STOP: Mutex<Latch> = Mutex::new(Latch {
    generation: 0,
    cause: None,
});
/// Woken when [`STOP`]'s cause is set.
static STOPPED: Notify = Notify::const_new();

fn lock_stop() -> std::sync::MutexGuard<'static, Latch> {
    STOP.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn latch(cause: StopCause) {
    let mut stop = lock_stop();
    if stop.cause.is_none() {
        stop.cause = Some(cause);
        drop(stop);
        STOPPED.notify_waiters();
    }
}

/// A signal from the arm [`own`] installed at `generation`. A later `own`
/// has moved on, and the signal is not this start's.
fn latch_signal(generation: u64, trigger: Trigger) {
    let mut stop = lock_stop();
    if stop.generation != generation || stop.cause.is_some() {
        return;
    }
    stop.cause = Some(StopCause::Signal(trigger));
    drop(stop);
    STOPPED.notify_waiters();
}

fn latched() -> Option<StopCause> {
    lock_stop().cause.clone()
}

/// The daemon's own request: the RPC's `daemon_stop`.
pub fn request_stop() {
    latch(StopCause::Requested);
}

/// The owner's socket went: a run-as-me daemon stops when its session
/// ends (`RPC_CHANNEL.md` §7.1). A clean stop.
pub fn rendezvous_gone() {
    latch(StopCause::RendezvousGone);
}

/// The process that started this daemon closed its owning connection or
/// died (IG-Q106). A clean stop: the daemon's life was that process's.
pub fn owning_connection_closed() {
    latch(StopCause::OwningConnectionClosed);
}

/// A task the node owns ended on its own, as `end` says.
///
/// Every waiter sees [`StopCause::Fatal`]. A stop already latched keeps
/// its own cause. The waiter that observes a fatal cause makes the exit
/// a failure, as does the arm that reads the node's end directly.
pub fn fatal(end: NodeEnd) {
    latch(StopCause::Fatal(end));
}

/// The Tor supervisor ended on its own, as `end` says. Latched as
/// [`fatal`] latches a node task's end.
pub fn tor_ended(end: SupervisorEnd) {
    latch(StopCause::TorEnded(end));
}

/// The program's name in the lines the start says about its stops.
const PROGRAM: &str = "shekyld";

/// Said in place of the platform's line when the node was started holding
/// an owning connection (IG-Q106): the program that started it is how it
/// is stopped, and it has no console or window of its own to stop it from
/// (Rick, 2026-11-17).
const STARTED_BY_LINE: &str =
    "The program that started shekyld stops it: shekyld stops when that program \
     closes its connection to it or exits.";

/// The IG-14 line `inherited` owes, if it owes one (`shekyl_process::stop`:
/// Unix owes it when `SIGINT` was ignored, Windows on every start). A node
/// `started_by` a program holding its owning connection owes the same
/// lines, naming that program as its stop in place of Ctrl-Break, the
/// window, SIGTERM or the service stop: such a node has no console or
/// window, and its starter is how it stops.
#[must_use]
pub fn notice(inherited: Inherited, started_by: bool) -> Option<String> {
    owed(inherited.line(PROGRAM), started_by)
}

/// The platform's `line`, or [`STARTED_BY_LINE`] in its place when the node
/// was `started_by` a program holding its owning connection.
fn owed(line: Option<String>, started_by: bool) -> Option<String> {
    line.map(|line| {
        if started_by {
            STARTED_BY_LINE.to_owned()
        } else {
            line
        }
    })
}

/// Arm the operating system's stop triggers for this start, and forward the
/// first of them to the latch on `handle`. Clears the latch. The generation
/// advances before the new arm is installed, so a forwarder that already
/// took a trigger from the previous arm cannot publish it here. `inherited`
/// is [`Inherited::at_start`], read before anything installed a handler.
///
/// # Errors
/// The operating system refused a trigger's stream.
pub fn own(handle: &tokio::runtime::Handle, inherited: Inherited) -> std::io::Result<()> {
    let generation = {
        let mut stop = lock_stop();
        stop.generation = stop.generation.wrapping_add(1);
        stop.cause = None;
        stop.generation
    };
    let mut stops = Stops::arm(inherited)?;
    handle.spawn(async move {
        if let FirstStop::Stop(trigger) = stops.first().await {
            latch_signal(generation, trigger);
        }
    });
    Ok(())
}

/// Resolves when a stop has been requested, with its cause; at once when
/// one already has.
pub async fn stop_requested() -> StopCause {
    loop {
        let notified = STOPPED.notified();
        tokio::pin!(notified);
        // Enabled before the check, so a latch set between the check and
        // the await still wakes this wait.
        notified.as_mut().enable();
        if let Some(cause) = latched() {
            return cause;
        }
        // The latch is set before the wake. It reads clear here only if a
        // start's `own` cleared it in between, which is not a stop: wait
        // again rather than name a cause nobody gave.
        notified.await;
    }
}

/// Process-wide dispositions the daemon runs with.
pub fn install_dispositions() {
    // A peer that closes its socket mid-write must be an `EPIPE` on that
    // write, never a signal that ends the daemon.
    #[cfg(unix)]
    shekyl_process::platform::ignore_sigpipe();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// The reason the owner is one latch: a request made while no wait is
    /// in flight is answered by the next wait, at once; and a request made
    /// before the owner existed is not this daemon's. One test, in order:
    /// the latch is process-wide.
    #[test]
    fn a_request_between_waits_is_kept_and_a_stale_one_is_cleared() {
        // The run tests latch the same owner: one at a time.
        let _serial = crate::run::hold_process_table();
        let rt = runtime();
        request_stop();
        own(rt.handle(), Inherited::none()).expect("own");
        let waited = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), stop_requested()).await
        });
        assert!(
            waited.is_err(),
            "no request after own(): the wait must not resolve"
        );

        request_stop();
        let cause = rt.block_on(stop_requested());
        assert_eq!(cause, StopCause::Requested);
        // Still latched: a second wait answers the same way.
        assert_eq!(rt.block_on(stop_requested()), cause);
    }

    fn one_trigger() -> Trigger {
        #[cfg(unix)]
        {
            Trigger::Terminate
        }
        #[cfg(windows)]
        {
            Trigger::CtrlBreak
        }
    }

    /// A signal read for the previous start does not latch after [`own`]
    /// retires it, and a signal for this start does. Red edit: `latch_signal`
    /// ignores the generation (the next start stops on the previous arm's
    /// trigger).
    #[test]
    fn a_signal_from_a_replaced_start_does_not_latch() {
        let _serial = crate::run::hold_process_table();
        let rt = runtime();
        own(rt.handle(), Inherited::none()).expect("own");
        let generation = lock_stop().generation;
        latch_signal(generation.wrapping_sub(1), one_trigger());
        let waited = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), stop_requested()).await
        });
        assert!(
            waited.is_err(),
            "a signal from the replaced start latched: {waited:?}"
        );

        latch_signal(generation, one_trigger());
        assert_eq!(
            rt.block_on(stop_requested()),
            StopCause::Signal(one_trigger())
        );
        // The next start does not inherit this one.
        own(rt.handle(), Inherited::none()).expect("own");
        let waited = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), stop_requested()).await
        });
        assert!(waited.is_err(), "own() left the previous signal latched");
    }

    /// **A node started by a program holding its owning connection names
    /// that program as its stop** (Rick, 2026-11-17): never Ctrl-Break, a
    /// window, SIGTERM or the service stop, which it has none of; and a
    /// node that owes no line owes none for its starter either. Red edit:
    /// `owed` ignores `started_by` (a GUI's node tells its standard error
    /// to close a window it does not have).
    #[test]
    fn a_node_started_by_a_program_names_that_program_as_its_stop() {
        let platform = "Ctrl-C is off because the program that started shekyld asked for it.";
        assert_eq!(
            owed(Some(platform.to_owned()), false).as_deref(),
            Some(platform)
        );
        assert_eq!(owed(None, true), None);
        let line = owed(Some(platform.to_owned()), true).expect("the line is still owed");
        assert_eq!(line, STARTED_BY_LINE);
        assert!(
            line.starts_with("The program that started shekyld"),
            "{line}"
        );
        for gone in ["Ctrl-Break", "window", "SIGTERM", "service"] {
            assert!(!line.contains(gone), "{gone}: {line}");
        }
        #[cfg(unix)]
        assert_eq!(notice(Inherited::none(), true), None);
        #[cfg(windows)]
        assert_eq!(
            notice(Inherited::none(), true).as_deref(),
            Some(STARTED_BY_LINE)
        );
    }
}
