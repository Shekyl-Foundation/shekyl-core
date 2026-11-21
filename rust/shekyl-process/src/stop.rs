// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stop triggers every Shekyl program takes: `shekyld`,
//! `shekyl-wallet-rpc`, `shekyl-cli` and `shekyl-rpc-tunnel`
//! (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 9; Rick, 2026-11-20).
//!
//! - **Unix:** `SIGTERM`, `SIGINT` and `SIGHUP`. **Windows:** every console
//!   event (Ctrl-C, Ctrl-Break, the window's close, logoff and shutdown).
//!   The first is a clean stop: the program closes what it holds and exits.
//! - **A second stop exits at once** with [`EXIT_SECOND_STOP`] and no
//!   cleanup, whichever trigger it is (Rick, 2026-10-14, restated
//!   2026-11-20). Every program is safe to kill: its next start takes over
//!   or clears what a kill left.
//! - **An inherited ignore is kept** ([`Inherited`], read before any handler
//!   is installed). On Unix an ignored `SIGINT` is not taken and the start
//!   says so once (IG-14); an ignored `SIGHUP` (`nohup`) is not taken and
//!   nothing is said. Windows has no read of the inherited ignore-Ctrl-C
//!   attribute, so a Windows start names the stops that always work.
//!
//! [`Stops::arm`] opens the streams on a thread of their own, with a
//! runtime of their own, for the process's life. A program's runtimes can
//! end, and a second stop must still exit at once: the program's runtime
//! shuts down before its last steps (the lock's release, the log's flush),
//! and a stream nobody polls neither exits nor lets Windows end the
//! process with the status ruled. The first stop waits in [`Stops`] until
//! the program asks for it, so one that arrives before the program's
//! first wait is kept.

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use tokio::sync::watch;

/// The exit status of a second stop: 128 plus `SIGINT`, the status a
/// shell gives a program its interrupt ended.
pub const EXIT_SECOND_STOP: i32 = 130;

/// A stop trigger the operating system delivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// `SIGINT`: Ctrl-C in the program's terminal.
    #[cfg(unix)]
    Interrupt,
    /// `SIGTERM`: a service manager's stop.
    #[cfg(unix)]
    Terminate,
    /// `SIGHUP`: the program's terminal closed.
    #[cfg(unix)]
    Hangup,
    /// Ctrl-C in the program's console.
    #[cfg(windows)]
    CtrlC,
    /// Ctrl-Break in the program's console.
    #[cfg(windows)]
    CtrlBreak,
    /// The program's console window closed.
    #[cfg(windows)]
    WindowClose,
    /// The user logged off.
    #[cfg(windows)]
    Logoff,
    /// The system is shutting down.
    #[cfg(windows)]
    Shutdown,
}

impl Trigger {
    /// The trigger's name, as the programs report it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Interrupt => "SIGINT",
            #[cfg(unix)]
            Self::Terminate => "SIGTERM",
            #[cfg(unix)]
            Self::Hangup => "SIGHUP",
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

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the start can know about inherited requests to ignore a stop,
/// fixed before this process installs a handler.
///
/// On Unix the requests are `SIG_IGN` dispositions. A non-interactive
/// background list (`sh -c 'p &'`) and `trap "" INT` ignore `SIGINT`;
/// `nohup` ignores `SIGHUP`. An interactive `&` sets neither. On Windows
/// the request is the inherited ignore-Ctrl-C attribute, which has no
/// documented read; `start /b` does not set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inherited {
    /// `SIGINT` was `SIG_IGN`: it is not taken, and the start says so.
    #[cfg(unix)]
    interrupt_ignored: bool,
    /// `SIGHUP` was `SIG_IGN`: it is not taken, and nothing is said.
    #[cfg(unix)]
    hangup_ignored: bool,
}

impl Inherited {
    /// The observation, before anything in the process installs a handler.
    #[must_use]
    pub fn at_start() -> Self {
        #[cfg(unix)]
        {
            Self {
                interrupt_ignored: is_ignored(libc::SIGINT),
                hangup_ignored: is_ignored(libc::SIGHUP),
            }
        }
        #[cfg(windows)]
        {
            Self {}
        }
    }

    /// No inherited ignore: every trigger is taken. For tests that are not
    /// about an inherited ignore.
    #[must_use]
    pub fn none() -> Self {
        #[cfg(unix)]
        {
            Self {
                interrupt_ignored: false,
                hangup_ignored: false,
            }
        }
        #[cfg(windows)]
        {
            Self {}
        }
    }

    /// The IG-14 line this start owes, naming `program`, if it owes one.
    ///
    /// Unix owes a line only when `SIGINT` was ignored. Windows owes its
    /// line on every start, because the attribute cannot be read.
    #[must_use]
    pub fn line(self, program: &str) -> Option<String> {
        #[cfg(unix)]
        {
            self.observed_line(program)
        }
        #[cfg(windows)]
        {
            Some(format!(
                "Stop {program} with Ctrl-Break or by closing its window. Ctrl-C stops it \
                 too, unless the program that started it asked for Ctrl-C to be ignored, \
                 which Windows does not let {program} read."
            ))
        }
    }

    /// The line for an ignore this start observed: Unix's, never Windows'
    /// every-start line. For an interactive program, whose console is the
    /// operator's own (`shekyl-cli`; Rick, 2026-11-20).
    #[must_use]
    pub fn observed_line(self, program: &str) -> Option<String> {
        #[cfg(unix)]
        {
            self.interrupt_ignored.then(|| {
                format!(
                    "Ctrl-C is off because the program that started {program} asked for it. \
                     Stop it with SIGTERM or the service stop."
                )
            })
        }
        #[cfg(windows)]
        {
            let _ = program;
            None
        }
    }
}

/// `true` when `signal`'s disposition is `SIG_IGN` at the time of the call.
/// A failed read is `false`, so the signal is taken.
#[cfg(unix)]
fn is_ignored(signal: libc::c_int) -> bool {
    // SAFETY: `sigaction` with a null new action only reads the current
    // disposition into `current`, a local of the type it writes; a zeroed
    // `sigaction` is a valid value of that plain C struct.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `signal` is one of the valid numbers this module
    // passes.
    let read = unsafe { libc::sigaction(signal, std::ptr::null(), &raw mut current) };
    read == 0 && current.sa_sigaction == libc::SIG_IGN
}

/// The armed stops, as one program start sees them. Cloned handles see the
/// same first stop.
#[derive(Clone, Debug)]
pub struct Stops {
    first: watch::Receiver<Option<Trigger>>,
}

/// One arm's first stop. The owner sends the first trigger here, and exits
/// at once on a trigger that finds one already sent.
type Arm = Arc<watch::Sender<Option<Trigger>>>;

/// The arm the owner reports to: the latest [`Stops::arm`]'s.
static CURRENT: Mutex<Option<Arm>> = Mutex::new(None);

/// Whether the owner thread opened its streams: `Err` holds the kind and
/// words of the refusal, for every later arm to return.
static OWNER: OnceLock<Result<(), (io::ErrorKind, String)>> = OnceLock::new();

impl Stops {
    /// Take the stop triggers `inherited` allows, for the process's life.
    ///
    /// The first call opens the streams on the owner's thread; a platform
    /// that refuses one refuses this call and every later one. A later call
    /// (a test that starts a program twice in one process) starts a fresh
    /// arm on the same streams: a stop before it is not this start's, and
    /// `inherited` is the first call's.
    ///
    /// # Errors
    /// The operating system refused a stream, or the owner's thread or
    /// runtime could not start.
    pub fn arm(inherited: Inherited) -> io::Result<Self> {
        let (sender, first) = watch::channel(None);
        *CURRENT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(sender));
        OWNER
            .get_or_init(|| start_owner(inherited).map_err(|e| (e.kind(), e.to_string())))
            .clone()
            .map_err(|(kind, words)| io::Error::new(kind, words))?;
        Ok(Self { first })
    }

    /// The first stop, at once when it has already arrived.
    pub async fn first(&mut self) -> Trigger {
        loop {
            if let Some(trigger) = *self.first.borrow_and_update() {
                return trigger;
            }
            if self.first.changed().await.is_err() {
                // A later arm replaced this one: no stop of this start's
                // can arrive any more.
                std::future::pending::<()>().await;
            }
        }
    }

    /// The first stop, if it has arrived.
    #[must_use]
    pub fn arrived(&self) -> Option<Trigger> {
        *self.first.borrow()
    }
}

/// A trigger, from the owner's thread: the first stop of the current arm,
/// or a second stop, which exits at once.
fn deliver(trigger: Trigger) {
    let arm = CURRENT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some(arm) = arm else {
        return;
    };
    if arm.borrow().is_some() {
        exit_at_once();
    }
    arm.send_replace(Some(trigger));
}

/// Ends this process now, with [`EXIT_SECOND_STOP`], running nothing: no
/// destructor, no exit handler, no flush. Every program is safe to kill.
fn exit_at_once() -> ! {
    #[cfg(unix)]
    {
        // SAFETY: `_exit` ends the process; it reads and writes no memory
        // of ours and does not return.
        unsafe { libc::_exit(EXIT_SECOND_STOP) }
    }
    #[cfg(windows)]
    {
        crate::harden::end_process(EXIT_SECOND_STOP);
        // `TerminateProcess` on the calling process does not return.
        std::process::abort()
    }
}

/// Starts the owner's thread and waits until its streams are open.
fn start_owner(inherited: Inherited) -> io::Result<()> {
    let (opened, opening) = std::sync::mpsc::sync_channel::<io::Result<()>>(1);
    std::thread::Builder::new()
        .name("shekyl-stops".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    drop(opened.send(Err(e)));
                    return;
                }
            };
            runtime.block_on(async move {
                let mut streams = match Streams::open(inherited) {
                    Ok(streams) => streams,
                    Err(e) => {
                        drop(opened.send(Err(e)));
                        return;
                    }
                };
                drop(opened.send(Ok(())));
                loop {
                    deliver(streams.next().await);
                }
            });
        })?;
    opening
        .recv()
        .map_err(|_| io::Error::other("the stop owner ended before it opened its streams"))?
}

/// The open streams. On Unix an inherited ignore leaves its stream unopened,
/// so its disposition stays `SIG_IGN`.
#[cfg(unix)]
struct Streams {
    terminate: tokio::signal::unix::Signal,
    interrupt: Option<tokio::signal::unix::Signal>,
    hangup: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
impl Streams {
    fn open(inherited: Inherited) -> io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        let taken = |ignored: bool, kind: SignalKind| -> io::Result<_> {
            if ignored {
                Ok(None)
            } else {
                signal(kind).map(Some)
            }
        };
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: taken(inherited.interrupt_ignored, SignalKind::interrupt())?,
            hangup: taken(inherited.hangup_ignored, SignalKind::hangup())?,
        })
    }

    /// The next trigger. An unopened stream's arm is disabled.
    async fn next(&mut self) -> Trigger {
        tokio::select! {
            _ = self.terminate.recv() => Trigger::Terminate,
            Some(()) = fired(self.interrupt.as_mut()) => Trigger::Interrupt,
            Some(()) = fired(self.hangup.as_mut()) => Trigger::Hangup,
        }
    }
}

/// `Some` when `stream` was opened and then fired; `None` at once when it
/// was not opened, which disables the caller's `select` arm.
#[cfg(unix)]
async fn fired(stream: Option<&mut tokio::signal::unix::Signal>) -> Option<()> {
    stream?.recv().await
}

/// Every console event. Opening `ctrl_c` does not clear the inherited
/// ignore-Ctrl-C attribute, and Windows withholds Ctrl-C while it is set.
/// The window's close, logoff and shutdown end the process when the handler
/// returns; tokio parks the handler's thread instead, so the program's
/// clean stop runs inside the system's grace period.
#[cfg(windows)]
struct Streams {
    ctrl_c: tokio::signal::windows::CtrlC,
    ctrl_break: tokio::signal::windows::CtrlBreak,
    close: tokio::signal::windows::CtrlClose,
    logoff: tokio::signal::windows::CtrlLogoff,
    shutdown: tokio::signal::windows::CtrlShutdown,
}

#[cfg(windows)]
impl Streams {
    fn open(_inherited: Inherited) -> io::Result<Self> {
        use tokio::signal::windows;
        Ok(Self {
            ctrl_c: windows::ctrl_c()?,
            ctrl_break: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            logoff: windows::ctrl_logoff()?,
            shutdown: windows::ctrl_shutdown()?,
        })
    }

    async fn next(&mut self) -> Trigger {
        tokio::select! {
            _ = self.ctrl_c.recv() => Trigger::CtrlC,
            _ = self.ctrl_break.recv() => Trigger::CtrlBreak,
            _ = self.close.recv() => Trigger::WindowClose,
            _ = self.logoff.recv() => Trigger::Logoff,
            _ = self.shutdown.recv() => Trigger::Shutdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a start says about an interrupt. On Unix only an ignored
    /// `SIGINT` is said, naming the program and the stop that works; an
    /// ignored `SIGHUP` alone says nothing. On Windows every start names
    /// the stops that always work, except where the operator's own console
    /// is the program's. Red edits: say the Unix line when `SIGINT` is
    /// taken, say a line for `nohup`, or drop the program's name.
    #[test]
    fn the_start_names_the_program_and_the_stops_that_work() {
        assert_eq!(Inherited::none().observed_line("shekyld"), None);
        #[cfg(unix)]
        {
            assert_eq!(Inherited::none().line("shekyld"), None);
            let nohup = Inherited {
                interrupt_ignored: false,
                hangup_ignored: true,
            };
            assert_eq!(nohup.line("shekyld"), None, "nohup is not announced");
            let background = Inherited {
                interrupt_ignored: true,
                hangup_ignored: false,
            };
            let line = background
                .line("shekyl-wallet-rpc")
                .expect("an ignored SIGINT is said");
            assert_eq!(
                line,
                "Ctrl-C is off because the program that started shekyl-wallet-rpc asked for \
                 it. Stop it with SIGTERM or the service stop."
            );
            assert_eq!(background.observed_line("shekyl-wallet-rpc"), Some(line));
        }
        #[cfg(windows)]
        {
            let line = Inherited::none()
                .line("shekyl-rpc-tunnel")
                .expect("every Windows start names its stops");
            assert!(
                line.starts_with(
                    "Stop shekyl-rpc-tunnel with Ctrl-Break or by closing its window."
                ) && line.ends_with("which Windows does not let shekyl-rpc-tunnel read."),
                "{line}"
            );
        }
    }

    /// The names the programs report, one per trigger.
    #[test]
    fn every_trigger_has_its_name() {
        #[cfg(unix)]
        let all = [
            (Trigger::Interrupt, "SIGINT"),
            (Trigger::Terminate, "SIGTERM"),
            (Trigger::Hangup, "SIGHUP"),
        ];
        #[cfg(windows)]
        let all = [
            (Trigger::CtrlC, "Ctrl-C"),
            (Trigger::CtrlBreak, "Ctrl-Break"),
            (Trigger::WindowClose, "window close"),
            (Trigger::Logoff, "logoff"),
            (Trigger::Shutdown, "shutdown"),
        ];
        for (trigger, name) in all {
            assert_eq!(trigger.to_string(), name);
        }
    }
}
