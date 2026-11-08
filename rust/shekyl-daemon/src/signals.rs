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

use shekyl_node::EndCause;
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
    /// Chain sync's owner ended on its own.
    Fatal(EndCause),
}

impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(signal) => f.write_str(signal.name()),
            Self::Requested => f.write_str("the RPC's stop_daemon"),
            Self::Fatal(cause) => f.write_str(cause.text()),
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

/// Chain sync's owner ended on its own, with `cause`.
///
/// Every waiter sees [`StopCause::Fatal`]. A stop already latched keeps
/// its own cause. The waiter that observes a fatal cause makes the exit
/// a failure, as does the arm that reads the owner's failed end directly.
pub fn fatal(cause: EndCause) {
    latch(StopCause::Fatal(cause));
}

/// What the program that started this node asked of an interrupt (Rick,
/// 2026-11-08: honour an inherited ignore on every platform, and say so).
///
/// A parent that starts a program in the background asks it to ignore an
/// interrupt, so that one typed at the parent's terminal leaves it alone. The
/// node keeps that request and says which stops work instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrupt {
    /// The node owns the interrupt: `SIGINT` or Ctrl-C stops it.
    Owned,
    /// `SIGINT` was ignored when the node started. The node leaves it
    /// ignored and does not open its stream.
    #[cfg(unix)]
    IgnoredByParent,
}

impl Interrupt {
    /// The request, read before anything in the node installs a handler.
    /// On Windows it cannot be read: the inherited "ignore Ctrl-C"
    /// attribute has no documented getter, so the node owns Ctrl-C and
    /// Windows delivers it or not.
    #[must_use]
    pub fn at_start() -> Self {
        #[cfg(unix)]
        if shekyl_process::interrupt::interrupt_ignored_at_start() {
            return Self::IgnoredByParent;
        }
        Self::Owned
    }

    /// The line the start announces about it (IG-14). On Unix, only when
    /// the parent asked for the interrupt to be ignored. On Windows always:
    /// the node cannot tell, so it names the stops that work either way.
    #[must_use]
    pub fn announcement(self) -> Option<&'static str> {
        #[cfg(unix)]
        {
            match self {
                Self::Owned => None,
                Self::IgnoredByParent => Some(
                    "Ctrl-C is off because the program that started this node asked for it. \
                     Stop it with SIGTERM or the service stop.",
                ),
            }
        }
        #[cfg(windows)]
        {
            let Self::Owned = self;
            Some(
                "Stop this node with Ctrl-Break or by closing its window. Ctrl-C stops it \
                 too, unless the program that started it asked for Ctrl-C to be ignored, \
                 which Windows does not let this node read.",
            )
        }
    }
}

/// Install the owner of the operating system's stop triggers on `handle`:
/// the streams are opened here, so a platform that refuses one refuses the
/// start, and held by a task for the process's life. Clears the latch.
/// `interrupt` is [`Interrupt::at_start`]: on Unix an interrupt the parent
/// asked to ignore gets no stream, so its disposition stays `SIG_IGN`.
///
/// # Errors
/// The operating system refused a stream.
pub fn own(handle: &tokio::runtime::Handle, interrupt: Interrupt) -> std::io::Result<()> {
    *STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (interrupt, mut terminate) = handle.block_on(async {
            let interrupt = match interrupt {
                Interrupt::Owned => Some(signal(SignalKind::interrupt())?),
                Interrupt::IgnoredByParent => None,
            };
            Ok::<_, std::io::Error>((interrupt, signal(SignalKind::terminate())?))
        })?;
        handle.spawn(async move {
            let interrupted = async {
                match interrupt {
                    Some(mut stream) => stream.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = interrupted => latch(StopCause::Signal(Signal::Interrupt)),
                _ = terminate.recv() => latch(StopCause::Signal(Signal::Terminate)),
            }
        });
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let Interrupt::Owned = interrupt;
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
        own(rt.handle(), Interrupt::Owned).expect("own");
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
    /// `SIGINT` is said, with the stop that works; on Windows the request
    /// cannot be read, so every start names the stops that always work.
    /// Red edits: say nothing on Windows, or say the Unix line when the node
    /// owns `SIGINT`.
    #[test]
    fn the_start_names_the_stops_that_work() {
        #[cfg(unix)]
        {
            assert_eq!(Interrupt::Owned.announcement(), None);
            let line = Interrupt::IgnoredByParent
                .announcement()
                .expect("an ignored SIGINT is said");
            assert!(
                line.contains("Ctrl-C is off") && line.contains("SIGTERM"),
                "{line}"
            );
        }
        #[cfg(windows)]
        {
            let line = Interrupt::Owned
                .announcement()
                .expect("every Windows start names its stops");
            assert!(
                line.contains("Ctrl-Break") && line.contains("closing its window"),
                "{line}"
            );
        }
    }
}
