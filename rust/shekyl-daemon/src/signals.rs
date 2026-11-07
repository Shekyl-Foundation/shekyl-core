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

use std::fmt;
use std::sync::Mutex;

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

/// Why the daemon stops. An operator's stop and a forced one are different
/// kinds, so the line that reports them can tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// The operating system's stop trigger: a service manager's or a
    /// terminal's ordinary way to stop the daemon.
    Signal(Signal),
    /// The RPC's `stop_daemon`, which `shekyl-cli daemon stop` posts.
    Requested,
    /// A part the daemon cannot run without ended, with this cause.
    Fatal(&'static str),
}

impl StopCause {
    /// Whether the operator asked for this stop. An asked-for stop is the
    /// daemon doing what it was told, announced rather than logged as a
    /// fault (IG-14; alpha.11 bug hunt, a SIGTERM logged at WARN); a forced
    /// one is an error.
    #[must_use]
    pub fn asked_for(self) -> bool {
        !matches!(self, Self::Fatal(_))
    }
}

impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(signal) => f.write_str(signal.name()),
            Self::Requested => f.write_str("the RPC's stop_daemon"),
            Self::Fatal(cause) => f.write_str(cause),
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

/// A part the daemon cannot run without has ended, with `cause`: chain
/// sync's owner ending on its own. Every waiter sees the stop with this
/// cause. The caller makes the exit a failure; a stop already latched
/// keeps its own cause.
pub fn fatal(cause: &'static str) {
    latch(StopCause::Fatal(cause));
}

/// Install the owner of the operating system's stop triggers on `handle`:
/// the streams are opened here, so a platform that refuses one refuses the
/// start, and held by a task for the process's life. Clears the latch.
///
/// # Errors
/// The operating system refused a stream.
pub fn own(handle: &tokio::runtime::Handle) -> std::io::Result<()> {
    *STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (mut interrupt, mut terminate) = handle.block_on(async {
            Ok::<_, std::io::Error>((
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
            ))
        })?;
        handle.spawn(async move {
            tokio::select! {
                _ = interrupt.recv() => latch(StopCause::Signal(Signal::Interrupt)),
                _ = terminate.recv() => latch(StopCause::Signal(Signal::Terminate)),
            }
        });
    }
    #[cfg(windows)]
    {
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
    }
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
        own(rt.handle()).expect("own");
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
}
