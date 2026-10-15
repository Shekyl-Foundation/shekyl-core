// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one signal owner (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 9, DC-F13):
//! every stop trigger feeds one stop path. On Unix, `SIGINT` and `SIGTERM`;
//! on Windows, every console event: Ctrl-C, Ctrl-Break, window close,
//! logoff and shutdown; on both, the remnant's request
//! ([`crate::entry::shekyl_daemon_request_stop`]: the console's `exit` and
//! the RPC's `stop_daemon`). `SIGPIPE` is ignored once at start.

use tokio::sync::Notify;

/// The remnant's request. `notify_one` stores a permit when no one waits,
/// so a request that lands before the owner waits is still observed.
static REQUEST: Notify = Notify::const_new();

/// Records a stop request from the remnant.
pub fn request_stop() {
    REQUEST.notify_one();
}

/// Resolves when a stop is requested, naming what requested it.
///
/// # Errors
/// The operating system refused to deliver one of the signals.
#[cfg(unix)]
pub async fn stop_requested() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = interrupt.recv() => Ok("SIGINT"),
        _ = terminate.recv() => Ok("SIGTERM"),
        () = REQUEST.notified() => Ok("the daemon's own request (console or RPC)"),
    }
}

/// Resolves when a stop is requested, naming what requested it.
///
/// # Errors
/// The operating system refused to register one of the handlers.
#[cfg(windows)]
pub async fn stop_requested() -> std::io::Result<&'static str> {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};
    let mut c = ctrl_c()?;
    let mut brk = ctrl_break()?;
    let mut close = ctrl_close()?;
    let mut logoff = ctrl_logoff()?;
    let mut shutdown = ctrl_shutdown()?;
    tokio::select! {
        _ = c.recv() => Ok("Ctrl-C"),
        _ = brk.recv() => Ok("Ctrl-Break"),
        _ = close.recv() => Ok("window close"),
        _ = logoff.recv() => Ok("logoff"),
        _ = shutdown.recv() => Ok("shutdown"),
        () = REQUEST.notified() => Ok("the daemon's own request (console or RPC)"),
    }
}

/// The process-wide dispositions set once at start.
pub fn install_dispositions() {
    #[cfg(unix)]
    shekyl_ffi::platform::ignore_sigpipe();
}
