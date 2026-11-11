// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one stop owner (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 6 and step 9).
//!
//! Every trigger reaches one latch: the POSIX signals and every Windows
//! console event through [`own`], which holds the operating system's
//! streams for the process's life on the signal runtime; the RPC's
//! `stop_daemon` (`shekyl-cli daemon stop`) through [`request_stop`]; and a part
//! the daemon cannot run without ending, chain sync's owner, through
//! [`fatal`], whose stop also makes the exit a failure. A wait is
//! [`stop_requested`], which answers at once when the latch is already
//! set, so a trigger that arrives between two waits (the managed Tor's
//! bootstrap sits between the RPC start and step 8) is kept, not dropped:
//! a stream that exists only while a wait is in flight would lose it.
//!
//! The latch is per daemon start: [`own`] clears it, so a request made
//! before the owner existed does not stop the daemon it was not meant for.
//!
//! [`InheritedInterrupt`] is what the start can know about an inherited
//! request to ignore the interrupt, read before any handler. On Unix an
//! ignored `SIGINT` is not given a stream, so the disposition stays
//! `SIG_IGN`.

use std::fmt;
use std::sync::Mutex;

use shekyl_node::NodeEnd;
use tokio::sync::Notify;

/// A stop trigger the operating system delivers, by its platform name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    #[cfg(unix)]
    Interrupt,
    #[cfg(unix)]
    Terminate,
    #[cfg(windows)]
    CtrlC,
    #[cfg(windows)]
    CtrlBreak,
    #[cfg(windows)]
    WindowClose,
    #[cfg(windows)]
    Logoff,
    #[cfg(windows)]
    Shutdown,
}

impl Signal {
    fn name(self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Interrupt => "SIGINT",
            #[cfg(unix)]
            Self::Terminate => "SIGTERM",
            #[cfg(windows)]
            Self::CtrlC => "Ctrl-C",
            #[cfg(windows)]
            Self::CtrlBreak => "Ctrl-Break",
            #[cfg(windows)]
            Self::WindowClose => "window close",
            #[cfg(windows)]
            Self::Logoff => "logoff",
            #[cfg(windows)]
            Self::Shutdown => "shutdown",
        }
    }
}

/// Why the daemon stops. The report matches the variant: an operator's
/// stop is announced, and [`Self::Fatal`] is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// The operating system's stop trigger: a service manager's or a
    /// terminal's ordinary way to stop the daemon.
    Signal(Signal),
    /// The RPC's `stop_daemon`, which `shekyl-cli daemon stop` posts.
    Requested,
    /// A task the node owns ended on its own ([`shekyl_node::Node::ended`]).
    Fatal(NodeEnd),
}

impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(signal) => f.write_str(signal.name()),
            Self::Requested => f.write_str("the RPC's stop_daemon"),
            Self::Fatal(end) => write!(f, "{end}"),
        }
    }
}

/// The cause of the stop, once one has arrived.
static STOP: Mutex<Option<StopCause>> = Mutex::new(None);
/// Woken when `STOP` is set.
static STOPPED: Notify = Notify::const_new();

fn latch(cause: StopCause) {
    let mut stop = STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if stop.is_none() {
        *stop = Some(cause);
        drop(stop);
        STOPPED.notify_waiters();
    }
}

fn latched() -> Option<StopCause> {
    *STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The daemon's own request: the RPC's `stop_daemon`.
pub fn request_stop() {
    latch(StopCause::Requested);
}

/// A task the node owns ended on its own, as `end` says.
///
/// Every waiter sees [`StopCause::Fatal`]. A stop already latched keeps
/// its own cause. The waiter that observes a fatal cause makes the exit
/// a failure, as does the arm that reads the node's end directly.
pub fn fatal(end: NodeEnd) {
    latch(StopCause::Fatal(end));
}

/// What the start can know about an inherited request to ignore the
/// interrupt, fixed before this process installs a handler.
///
/// On Unix the request is `SIGINT` already being `SIG_IGN`: a
/// non-interactive background list sets that, and so does `trap "" INT`.
/// An interactive `&` does not, and `nohup` ignores `SIGHUP` rather than
/// `SIGINT`. On Windows the request is the inherited ignore-Ctrl-C
/// attribute, which has no documented read. `start /b` does not set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InheritedInterrupt {
    /// `SIGINT` was not `SIG_IGN`. The node opens its stream, and `SIGINT`
    /// stops it.
    #[cfg(unix)]
    Owned,
    /// `SIGINT` was `SIG_IGN`. The node opens no `SIGINT` stream, so the
    /// disposition stays ignored.
    #[cfg(unix)]
    Ignored,
    /// The inherited ignore-Ctrl-C attribute cannot be read. The node opens
    /// every console handler. Windows delivers Ctrl-C only when the
    /// attribute is clear, and installing a handler does not clear it.
    #[cfg(windows)]
    Unreadable,
}

/// Said when Unix leaves an inherited `SIG_IGN` in place (IG-14).
#[cfg(unix)]
const IGNORED_LINE: &str =
    "Ctrl-C is off because the program that started this node asked for it. \
     Stop it with SIGTERM or the service stop.";

/// Said on every Windows start: the stops that work whether or not the
/// unreadable attribute is set (IG-14).
#[cfg(windows)]
const UNREADABLE_LINE: &str =
    "Stop this node with Ctrl-Break or by closing its window. Ctrl-C stops it \
     too, unless the program that started it asked for Ctrl-C to be ignored, \
     which Windows does not let this node read.";

impl InheritedInterrupt {
    /// The observation, before anything in the node installs a handler.
    #[must_use]
    pub fn at_start() -> Self {
        #[cfg(unix)]
        {
            if shekyl_process::interrupt::sigint_is_ignored() {
                Self::Ignored
            } else {
                Self::Owned
            }
        }
        #[cfg(windows)]
        {
            Self::Unreadable
        }
    }

    /// The IG-14 line this observation owes, if it owes one.
    ///
    /// Unix owes a line only when `SIGINT` was ignored. Windows owes its
    /// line on every start, because the attribute cannot be read.
    #[must_use]
    pub fn line(self) -> Option<&'static str> {
        match self {
            #[cfg(unix)]
            Self::Owned => None,
            #[cfg(unix)]
            Self::Ignored => Some(IGNORED_LINE),
            #[cfg(windows)]
            Self::Unreadable => Some(UNREADABLE_LINE),
        }
    }

    /// What tests pass to [`own`] when the test is not about an inherited
    /// ignore. On Unix the node takes `SIGINT`. On Windows the attribute
    /// stays unreadable.
    #[cfg(test)]
    pub(crate) fn ordinary() -> Self {
        #[cfg(unix)]
        {
            Self::Owned
        }
        #[cfg(windows)]
        {
            Self::Unreadable
        }
    }
}

/// Install the owner of the operating system's stop triggers on `handle`:
/// the streams are opened here, so a platform that refuses one refuses the
/// start, and held by a task for the process's life. Clears the latch.
/// `interrupt` is [`InheritedInterrupt::at_start`].
///
/// # Errors
/// The operating system refused a stream.
pub fn own(handle: &tokio::runtime::Handle, interrupt: InheritedInterrupt) -> std::io::Result<()> {
    *STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    match interrupt {
        #[cfg(unix)]
        InheritedInterrupt::Owned | InheritedInterrupt::Ignored => install_posix(handle, interrupt),
        #[cfg(windows)]
        InheritedInterrupt::Unreadable => install_console(handle),
    }
}

/// `SIGTERM`, and `SIGINT` when `interrupt` is [`InheritedInterrupt::Owned`].
///
/// An [`InheritedInterrupt::Ignored`] arm completes with `None` at once.
/// `select` disables an arm whose pattern missed, so the task waits on
/// `SIGTERM` only and the `SIG_IGN` disposition is never replaced.
#[cfg(unix)]
fn install_posix(
    handle: &tokio::runtime::Handle,
    interrupt: InheritedInterrupt,
) -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut sigint, mut sigterm) = handle.block_on(async {
        let sigint = match interrupt {
            InheritedInterrupt::Owned => Some(signal(SignalKind::interrupt())?),
            InheritedInterrupt::Ignored => None,
        };
        Ok::<_, std::io::Error>((sigint, signal(SignalKind::terminate())?))
    })?;
    handle.spawn(async move {
        tokio::select! {
            Some(()) = sigint_stop(&mut sigint) => latch(StopCause::Signal(Signal::Interrupt)),
            _ = sigterm.recv() => latch(StopCause::Signal(Signal::Terminate)),
        }
    });
    Ok(())
}

/// `Some` when `sigint` was opened and then fired. `None` at once when it
/// was not opened, which disables the caller's `select` arm.
#[cfg(unix)]
async fn sigint_stop(sigint: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    let stream = sigint.as_mut()?;
    stream.recv().await;
    Some(())
}

/// Every Windows console event. The inherited ignore-Ctrl-C attribute is
/// [`InheritedInterrupt::Unreadable`]; opening `ctrl_c` does not clear it,
/// and Windows withholds Ctrl-C while it is set.
#[cfg(windows)]
fn install_console(handle: &tokio::runtime::Handle) -> std::io::Result<()> {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};
    let (mut c, mut brk, mut close, mut logoff, mut shutdown) = handle.block_on(async {
        Ok::<_, std::io::Error>((
            ctrl_c()?,
            ctrl_break()?,
            ctrl_close()?,
            ctrl_logoff()?,
            ctrl_shutdown()?,
        ))
    })?;
    handle.spawn(async move {
        tokio::select! {
            _ = c.recv() => latch(StopCause::Signal(Signal::CtrlC)),
            _ = brk.recv() => latch(StopCause::Signal(Signal::CtrlBreak)),
            _ = close.recv() => latch(StopCause::Signal(Signal::WindowClose)),
            _ = logoff.recv() => latch(StopCause::Signal(Signal::Logoff)),
            _ = shutdown.recv() => latch(StopCause::Signal(Signal::Shutdown)),
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
        own(rt.handle(), InheritedInterrupt::ordinary()).expect("own");
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

    /// What the start says about an interrupt. On Unix only an ignored
    /// `SIGINT` is said, with the stop that works; on Windows the attribute
    /// cannot be read, so every start names the stops that always work.
    /// Red edits: say nothing on Windows, or say the Unix line when the node
    /// takes `SIGINT`.
    #[test]
    fn the_start_names_the_stops_that_work() {
        #[cfg(unix)]
        {
            assert_eq!(InheritedInterrupt::Owned.line(), None);
            let line = InheritedInterrupt::Ignored
                .line()
                .expect("an ignored SIGINT is said");
            assert!(
                line.contains("Ctrl-C is off") && line.contains("SIGTERM"),
                "{line}"
            );
        }
        #[cfg(windows)]
        {
            let line = InheritedInterrupt::Unreadable
                .line()
                .expect("every Windows start names its stops");
            assert!(
                line.contains("Ctrl-Break") && line.contains("closing its window"),
                "{line}"
            );
        }
    }
}
