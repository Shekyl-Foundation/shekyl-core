// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stop rules on Unix (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 9; Rick,
//! 2026-11-20), judged from outside a child that arms the stops:
//!
//! - the first stop of any kind ends the child's wait, and one that came
//!   before the wait is kept;
//! - a second stop exits at once with
//!   [`EXIT_SECOND_STOP`](shekyl_process::stop::EXIT_SECOND_STOP), while the
//!   child is still in its stop, and a `SIGHUP` never counts as one;
//! - an inherited ignore of `SIGINT` is kept and said; one of `SIGHUP` is
//!   kept and not said.
//!
//! Each test re-executes this binary on itself alone, in a child mode, and
//! signals only that child: the test binary never arms the stops, so no
//! signal can end it. The child sets its inherited dispositions between
//! fork and exec. Its lines arrive on standard output; the second stop is
//! sent only after the child has said its first, so the two are never one
//! delivery.
//!
//! `SHEKYL_STOP_CHILD` is this harness's re-exec marker, read by the test
//! binary alone; no shipped binary reads it (IG-13).

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use shekyl_process::stop::{FirstStop, Inherited, Stops, EXIT_SECOND_STOP};

const CHILD_MARKER: &str = "SHEKYL_STOP_CHILD";

/// The name the child's notice gives.
const PROGRAM: &str = "stop-child";

/// The child waits for its first stop, says it, and returns.
const ONCE: &str = "once";
/// As [`ONCE`], but it waits this long after arming before it asks.
const LATE: &str = "late";
/// As [`ONCE`], but after its first stop it holds, as a program's clean
/// stop does, for [`HOLD`].
const HOLDING: &str = "holding";

const LATE_BY: Duration = Duration::from_millis(500);
const HOLD: Duration = Duration::from_secs(30);
/// How long a child may take to say a line or to end.
const WITHIN: Duration = Duration::from_secs(10);
/// How long an ignored signal must leave the child waiting.
const IGNORED_HOLDS: Duration = Duration::from_secs(1);

/// In the re-executed child: arm, say so, wait for the first stop, say it.
/// `true` when this process is the child.
fn run_child_if_asked() -> bool {
    let Ok(mode) = std::env::var(CHILD_MARKER) else {
        return false;
    };
    // The test harness has printed `test <name> ... ` with no newline: end
    // that line, so each line the child says is its own.
    println!();
    let inherited = Inherited::at_start();
    if let Some(line) = inherited.line(PROGRAM) {
        println!("said: {line}");
    }
    let mut stops = Stops::arm(inherited).expect("the stops arm");
    println!("armed");
    if mode == LATE {
        std::thread::sleep(LATE_BY);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let FirstStop::Stop(first) = runtime.block_on(stops.first()) else {
        panic!("the arm was replaced");
    };
    println!("first: {first}");
    if mode == HOLDING {
        std::thread::sleep(HOLD);
        println!("held");
    }
    true
}

/// A child of this binary on `test`, in `mode`, with each of `ignored`
/// set to `SIG_IGN` and every other stop signal to `SIG_DFL`.
struct StopChild {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl StopChild {
    fn start(test: &str, mode: &str, ignored: &'static [libc::c_int]) -> Self {
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", test, "--nocapture", "--test-threads", "1"])
            .env(CHILD_MARKER, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // SAFETY: the closure runs between fork and exec and calls only
        // `signal`, which is async-signal-safe, plus the errno read on
        // failure. It sets this child's stop dispositions and no other
        // state.
        unsafe {
            command.pre_exec(move || {
                for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                    let disposition = if ignored.contains(&signal) {
                        libc::SIG_IGN
                    } else {
                        libc::SIG_DFL
                    };
                    if libc::signal(signal, disposition) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child =
            shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the child starts");
        let stdout = child.stdout.take().expect("piped stdout");
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if send.send(line).is_err() {
                    return;
                }
            }
        });
        let mut started = Self {
            child,
            lines,
            seen: Vec::new(),
        };
        started.expect_line("armed");
        started
    }

    /// Waits for a line that is `line`, or panics with what was seen.
    fn expect_line(&mut self, line: &str) {
        let deadline = std::time::Instant::now() + WITHIN;
        while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(got) => {
                    let found = got == line;
                    self.seen.push(got);
                    if found {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        panic!("the child did not say {line:?}; it said {:?}", self.seen);
    }

    /// Every line said so far, without waiting.
    fn said(&mut self) -> &[String] {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        &self.seen
    }

    fn signal(&self, signal: libc::c_int) {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid");
        // SAFETY: `kill` reads no memory of ours; the pid is this test's
        // own child, not yet reaped.
        let sent = unsafe { libc::kill(pid, signal) };
        assert_eq!(sent, 0, "kill: {}", std::io::Error::last_os_error());
    }

    /// The child's exit code, once it ends within [`WITHIN`].
    fn exit_code(&mut self) -> i32 {
        let deadline = std::time::Instant::now() + WITHIN;
        loop {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                return status
                    .code()
                    .unwrap_or_else(|| panic!("the child ended by a signal: {status}"));
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the child did not end; it said {:?}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn still_waiting(&mut self) -> bool {
        self.child.try_wait().expect("the child's state").is_none()
    }
}

impl Drop for StopChild {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

fn name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        libc::SIGHUP => "SIGHUP",
        _ => unreachable!("not a stop signal"),
    }
}

/// **A second stop exits at once with 130**, while the first stop is still
/// running (Rick, 2026-10-14, restated 2026-11-20): `SIGINT` or `SIGTERM`
/// after a first stop of any kind, `SIGHUP` included. The child
/// holds after its first stop as a program's clean stop does; the second
/// ends it with the ruled status, not the hold's end. Red edit: `deliver`
/// sends the second trigger instead of exiting (the child holds and the
/// wait times out).
#[test]
fn a_second_stop_exits_at_once_with_130() {
    const TEST: &str = "a_second_stop_exits_at_once_with_130";
    if run_child_if_asked() {
        return;
    }
    for (first, second) in [
        (libc::SIGTERM, libc::SIGTERM),
        (libc::SIGINT, libc::SIGTERM),
        (libc::SIGTERM, libc::SIGINT),
        (libc::SIGHUP, libc::SIGTERM),
        (libc::SIGHUP, libc::SIGINT),
    ] {
        let mut child = StopChild::start(TEST, HOLDING, &[]);
        child.signal(first);
        child.expect_line(&format!("first: {}", name(first)));
        child.signal(second);
        assert_eq!(
            child.exit_code(),
            EXIT_SECOND_STOP,
            "{} then {}: {:?}",
            name(first),
            name(second),
            child.said()
        );
        assert!(
            !child.said().iter().any(|line| line == "held"),
            "the second stop waited for the first to finish"
        );
    }
}

/// **A `SIGHUP` never counts as the second stop** (Rick, 2026-11-21): a
/// closing terminal under bash sends two hangups, the kernel's and the
/// shell's, and the escape-at-once is for a person pressing Ctrl-C again.
/// After a first `SIGTERM` or `SIGHUP`, two more hangups leave the child in
/// its stop; a `SIGINT` then still exits at once with 130, so the hold is
/// the hangups' doing, not a stop that cannot be ended. Red edit: let
/// `SIGHUP` count (`counts_as_a_second_stop` true for it; the child exits
/// 130 on the first hangup).
#[test]
fn a_sighup_never_counts_as_the_second_stop() {
    const TEST: &str = "a_sighup_never_counts_as_the_second_stop";
    if run_child_if_asked() {
        return;
    }
    for first in [libc::SIGTERM, libc::SIGHUP] {
        let mut child = StopChild::start(TEST, HOLDING, &[]);
        child.signal(first);
        child.expect_line(&format!("first: {}", name(first)));
        child.signal(libc::SIGHUP);
        child.signal(libc::SIGHUP);
        std::thread::sleep(IGNORED_HOLDS);
        assert!(
            child.still_waiting(),
            "{} then two SIGHUPs ended it: {:?}",
            name(first),
            child.said()
        );
        child.signal(libc::SIGINT);
        assert_eq!(
            child.exit_code(),
            EXIT_SECOND_STOP,
            "{} then SIGHUP twice then SIGINT: {:?}",
            name(first),
            child.said()
        );
    }
}

/// **The first stop of each kind is the one the wait returns, and the
/// child ends on its own terms**: status 0, not the signal's death.
#[test]
fn the_first_stop_of_each_kind_ends_the_wait() {
    const TEST: &str = "the_first_stop_of_each_kind_ends_the_wait";
    if run_child_if_asked() {
        return;
    }
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        let mut child = StopChild::start(TEST, ONCE, &[]);
        child.signal(signal);
        child.expect_line(&format!("first: {}", name(signal)));
        assert_eq!(child.exit_code(), 0, "{}", name(signal));
    }
}

/// **A stop that arrives before the program's first wait is kept**: the
/// streams are open from the arm, and the wait answers at once. Red edit:
/// open the streams in `first` (the child dies by the signal before it
/// waits).
#[test]
fn a_stop_before_the_first_wait_is_kept() {
    const TEST: &str = "a_stop_before_the_first_wait_is_kept";
    if run_child_if_asked() {
        return;
    }
    let mut child = StopChild::start(TEST, LATE, &[]);
    child.signal(libc::SIGTERM);
    child.expect_line("first: SIGTERM");
    assert_eq!(child.exit_code(), 0);
}

/// **An inherited `SIGINT` ignore is kept, and said once** (IG-14): the
/// start names the program and the stop that works, `SIGINT` leaves the
/// child waiting, and `SIGTERM` still stops it. The subject is shown by
/// [`the_first_stop_of_each_kind_ends_the_wait`]: without the ignore,
/// `SIGINT` stops the same child. Red edit: open the `SIGINT` stream
/// whatever the disposition.
#[test]
fn an_inherited_sigint_ignore_is_kept_and_said() {
    const TEST: &str = "an_inherited_sigint_ignore_is_kept_and_said";
    if run_child_if_asked() {
        return;
    }
    let mut child = StopChild::start(TEST, ONCE, &[libc::SIGINT]);
    let notice = Inherited::none().line(PROGRAM);
    assert_eq!(notice, None, "the control: no ignore, no line");
    assert!(
        child.said().iter().any(|line| line
            == "said: Ctrl-C is off because the program that started stop-child asked for it. \
                Stop it with SIGTERM or the service stop."),
        "the start did not say Ctrl-C is off: {:?}",
        child.said()
    );
    child.signal(libc::SIGINT);
    std::thread::sleep(IGNORED_HOLDS);
    assert!(
        child.still_waiting(),
        "SIGINT stopped it: {:?}",
        child.said()
    );
    assert!(!child.said().iter().any(|line| line.starts_with("first:")));
    child.signal(libc::SIGTERM);
    child.expect_line("first: SIGTERM");
    assert_eq!(child.exit_code(), 0);
}

/// **An inherited `SIGHUP` ignore (`nohup`) is kept, and not said**: the
/// start says nothing, `SIGHUP` leaves the child waiting, and `SIGTERM`
/// still stops it. Red edits: open the `SIGHUP` stream whatever the
/// disposition, or announce it.
#[test]
fn an_inherited_sighup_ignore_is_kept_silently() {
    const TEST: &str = "an_inherited_sighup_ignore_is_kept_silently";
    if run_child_if_asked() {
        return;
    }
    let mut child = StopChild::start(TEST, ONCE, &[libc::SIGHUP]);
    child.signal(libc::SIGHUP);
    std::thread::sleep(IGNORED_HOLDS);
    assert!(
        child.still_waiting(),
        "SIGHUP stopped it: {:?}",
        child.said()
    );
    child.signal(libc::SIGTERM);
    child.expect_line("first: SIGTERM");
    assert_eq!(child.exit_code(), 0);
    assert!(
        !child.said().iter().any(|line| line.starts_with("said:")),
        "nohup was announced: {:?}",
        child.said()
    );
}
