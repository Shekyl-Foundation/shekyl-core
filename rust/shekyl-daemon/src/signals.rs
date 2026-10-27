// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one stop owner (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 6 and step 9).
//!
//! Every trigger reaches one latch: the POSIX signals and every Windows
//! console event through [`own`], which holds the operating system's
//! streams for the process's life on the signal runtime; the console's
//! `exit` and the RPC's `stop_daemon` through [`request_stop`]. A wait is
//! [`stop_requested`], which answers at once when the latch is already
//! set, so a trigger that arrives between two waits (the managed Tor's
//! bootstrap sits between the RPC start and step 8) is kept, not dropped:
//! a stream that exists only while a wait is in flight would lose it.
//!
//! The latch is per daemon start: [`own`] clears it, so a request made
//! before the owner existed does not stop the daemon it was not meant for.

use std::sync::Mutex;

use tokio::sync::Notify;

/// The cause of the stop, once one has arrived.
static STOP: Mutex<Option<&'static str>> = Mutex::new(None);
/// Woken when `STOP` is set.
static STOPPED: Notify = Notify::const_new();

fn latch(cause: &'static str) {
    let mut stop = STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if stop.is_none() {
        *stop = Some(cause);
        drop(stop);
        STOPPED.notify_waiters();
    }
}

fn latched() -> Option<&'static str> {
    *STOP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The daemon's own request: the console's `exit`, the RPC's `stop_daemon`.
pub fn request_stop() {
    latch("the daemon's own request (console or RPC)");
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
                _ = interrupt.recv() => latch("SIGINT"),
                _ = terminate.recv() => latch("SIGTERM"),
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
                _ = c.recv() => latch("Ctrl-C"),
                _ = brk.recv() => latch("Ctrl-Break"),
                _ = close.recv() => latch("window close"),
                _ = logoff.recv() => latch("logoff"),
                _ = shutdown.recv() => latch("shutdown"),
            }
        });
    }
    Ok(())
}

/// Resolves when a stop has been requested, with its cause; at once when
/// one already has.
pub async fn stop_requested() -> &'static str {
    let notified = STOPPED.notified();
    tokio::pin!(notified);
    // Enabled before the check, so a latch set between the check and the
    // await still wakes this wait.
    notified.as_mut().enable();
    if let Some(cause) = latched() {
        return cause;
    }
    notified.await;
    latched().unwrap_or("a stop")
}

/// Process-wide dispositions the daemon runs with.
pub fn install_dispositions() {
    // A peer that closes its socket mid-write must be an `EPIPE` on that
    // write, never a signal that ends the daemon.
    #[cfg(unix)]
    shekyl_ffi::platform::ignore_sigpipe();
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
        assert_eq!(cause, "the daemon's own request (console or RPC)");
        // Still latched: a second wait answers the same way.
        assert_eq!(rt.block_on(stop_requested()), cause);
    }
}
