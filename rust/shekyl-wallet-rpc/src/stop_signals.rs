// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Process stop signals for the wallet RPC server.
//!
//! The first signal asks the server to stop. The serve task closes the
//! open wallet. A second signal exits at once. When the host's main
//! thread is not waiting on the server, the process also exits once the
//! wallet is closed.

use std::sync::Arc;

use tracing::{info, warn};

use crate::server::AppState;

/// What the watcher does once the wallet is closed.
#[derive(Clone, Copy)]
pub(crate) enum AfterClose {
    /// Nothing: the host's own serve call returns.
    Return,
    /// End the process. For a host whose main thread is not waiting on
    /// the server (`shekyl-cli`).
    Exit,
}

/// The process's stop signals, registered once.
struct StopSignals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hup: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    ctrl_break: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    logoff: tokio::signal::windows::CtrlLogoff,
    #[cfg(windows)]
    shutdown: tokio::signal::windows::CtrlShutdown,
}

impl StopSignals {
    fn register() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self {
                term: signal(SignalKind::terminate())?,
                int: signal(SignalKind::interrupt())?,
                hup: signal(SignalKind::hangup())?,
            })
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows;
            Ok(Self {
                ctrl_c: windows::ctrl_c()?,
                ctrl_break: windows::ctrl_break()?,
                // Close, logoff and shutdown end the process when the
                // handler returns; tokio parks the handler thread instead,
                // so the wallet closes inside the system's grace period.
                close: windows::ctrl_close()?,
                logoff: windows::ctrl_logoff()?,
                shutdown: windows::ctrl_shutdown()?,
            })
        }
    }

    /// The next stop signal's name.
    async fn next(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.term.recv() => "SIGTERM",
                _ = self.int.recv() => "SIGINT",
                _ = self.hup.recv() => "SIGHUP",
            }
        }
        #[cfg(windows)]
        {
            tokio::select! {
                _ = self.ctrl_c.recv() => "ctrl-c",
                _ = self.ctrl_break.recv() => "ctrl-break",
                _ = self.close.recv() => "console close",
                _ = self.logoff.recv() => "logoff",
                _ = self.shutdown.recv() => "system shutdown",
            }
        }
    }
}

/// Watch the process's stop signals for `state`'s server.
///
/// The first signal requests shutdown. The serve task closes the open
/// wallet. A second signal exits at once. With [`AfterClose::Exit`] the
/// process also exits once the wallet is closed.
///
/// # Errors
///
/// The signal handlers could not be registered.
pub(crate) fn watch(state: Arc<AppState>, after: AfterClose) -> std::io::Result<()> {
    let mut signals = StopSignals::register()?;
    tokio::spawn(async move {
        let first = signals.next().await;
        info!(
            signal = first,
            "stopping: closing the open wallet; a second signal exits at once"
        );
        state.shutdown.notify_one();
        match after {
            AfterClose::Return => {
                let second = signals.next().await;
                warn!(signal = second, "second stop signal: exiting at once");
                std::process::exit(130);
            }
            AfterClose::Exit => {
                tokio::select! {
                    () = state.closed.notified() => std::process::exit(130),
                    second = signals.next() => {
                        warn!(signal = second, "second stop signal: exiting at once");
                        std::process::exit(130);
                    }
                }
            }
        }
    });
    Ok(())
}
