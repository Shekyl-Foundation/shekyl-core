// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Killing a managed Tor from outside, for the live tests.
//!
//! The crash the supervisors exist for is a Tor that ends with no stop, no
//! control-connection close and no handle. The live tests deliver it the way
//! a platform's own tools would. They name the Tor by its command line, which
//! carries the test's unique data directory, and kill that process only:
//! the program is `tor` (on Windows, `tor.exe`), and the command line
//! contains the directory as text. On Unix that is `pkill -9 -f`. `pkill`
//! compiles an extended regular expression, so the directory is escaped and
//! the program is anchored. On Windows a CIM query uses `String.Contains`,
//! and `Stop-Process -Force` is `TerminateProcess`. The child's handle is
//! not used: a kill through it would be the supervisor's own act, not a
//! crash.
//!
//! Both tools report "nothing was killed" as exit status [`NOTHING_MATCHED`].
//! Any other failure is a broken pattern or a tool error, and panics: a live
//! test must not read that as "the Tor was not there".
//!
//! Test-only: compiled under `cfg(test)` or the `unpinned-tor-for-tests`
//! feature, which only dev-dependency edges enable
//! (`scripts/ci/check_test_only_features.py`).

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, ExitStatus};

#[cfg(unix)]
use crate::inherit;
use crate::spawn_lock;

/// `pkill` exit 1, and the Windows script's `exit 1`: nothing was killed.
const NOTHING_MATCHED: i32 = 1;

/// Extended-regex metacharacters. `pkill -f` compiles `REG_EXTENDED` on
/// Linux and on macOS. A data directory is text, so each of these is escaped.
#[cfg(unix)]
const REGEX_METACHARACTERS: &str = r"\.^$*+?()[]{}|";

/// Exit status `TerminateProcess` receives from .NET `Process.Kill`, which
/// is what `Stop-Process -Force` calls. `ExitStatus::code` returns that
/// `DWORD` as `i32`.
#[cfg(windows)]
const TERMINATED_BY_FORCE: i32 = -1;

/// Kill every Tor whose command line contains `needle`, from outside.
/// `true` when at least one was found and killed.
///
/// # Panics
///
/// When `needle` is not UTF-8, the platform's tool does not start, or the
/// tool fails for a reason other than [`NOTHING_MATCHED`].
#[must_use]
pub fn kill_tor_named_by(needle: &Path) -> bool {
    let needle = needle.to_str().expect("a UTF-8 path names the Tor");
    let status =
        spawn_lock::status(&mut kill_command(needle)).expect("the platform's kill tool starts");
    killed(status)
}

/// What a reap reports for a process killed by [`kill_tor_named_by`].
///
/// A Unix signal has no exit code. Windows `Stop-Process -Force` records
/// the `TerminateProcess` status, `-1`.
#[must_use]
#[cfg(unix)]
pub const fn reaped_exit_code() -> Option<i32> {
    None
}

/// What a reap reports for a process killed by [`kill_tor_named_by`].
///
/// A Unix signal has no exit code. Windows `Stop-Process -Force` records
/// [`TERMINATED_BY_FORCE`].
#[must_use]
#[cfg(windows)]
pub const fn reaped_exit_code() -> Option<i32> {
    Some(TERMINATED_BY_FORCE)
}

/// `true` when the tool killed a process. A tool that failed outright panics,
/// so "nothing matched" cannot hide a broken pattern.
fn killed(status: ExitStatus) -> bool {
    if status.success() {
        return true;
    }
    assert_eq!(
        status.code(),
        Some(NOTHING_MATCHED),
        "the kill tool failed ({status}), rather than reporting that nothing was killed"
    );
    false
}

/// A command whose child inherits standard input, output and error only.
///
/// On Windows a child inherits only handles this process has marked
/// inheritable, and the spawn lock covers the one it marks for Tor. On Unix
/// the close-on-exec marks happen in the child (`DAEMON_CONFIG_CUTOVER.md`
/// §2.10).
fn child_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let stdio_only = inherit::StdioOnly::prepare();
        // SAFETY: the closure runs in the child between `fork` and `exec`,
        // and [`inherit::StdioOnly::apply`] is async-signal-safe.
        unsafe {
            command.pre_exec(move || stdio_only.apply());
        }
    }
    command
}

/// `pkill -9 -f` with [`tor_pattern`]. `pkill` does not match itself.
#[cfg(unix)]
fn kill_command(needle: &str) -> Command {
    let mut command = child_command("pkill");
    command.args(["-9", "-f"]).arg(tor_pattern(needle));
    command
}

/// The extended regular expression `pkill -f` reads.
///
/// The same predicate Windows applies with `Name = 'tor.exe'` and
/// `String.Contains`: the program is a file named `tor`, and the command
/// line contains `needle` as text. The managed launch runs Tor by its
/// absolute path (`launch.rs`), so the command line starts with `…/tor `
/// and the data directory is a later argument. The program's path may not
/// contain a space: a later argument ending in `/tor` would otherwise stand
/// in for the program. A Tor at such a path is not found, and the caller's
/// "Tor was killed" check fails.
#[cfg(unix)]
fn tor_pattern(needle: &str) -> String {
    let mut literal = String::with_capacity(needle.len() * 2);
    for c in needle.chars() {
        if REGEX_METACHARACTERS.contains(c) {
            literal.push('\\');
        }
        literal.push(c);
    }
    format!("^([^ ]*/)?tor .*{literal}")
}

/// Every `tor.exe` whose command line contains the needle, stopped with
/// `-Force`. `Contains` matches the text literally: `-like` would read `[`
/// and `]` in a path as a pattern. The needle travels in the environment, so
/// no quoting of the path reaches the script. Exit [`NOTHING_MATCHED`] when
/// none was found. A `Stop-Process` failure exits 2, which is not that
/// status, so the caller panics instead of reporting that nothing was killed.
#[cfg(windows)]
fn kill_command(needle: &str) -> Command {
    const SCRIPT: &str = "$needle = $env:SHEKYL_KILL_TOR_NAMED_BY; \
        $found = @(Get-CimInstance Win32_Process -Filter \"Name = 'tor.exe'\" | \
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($needle) }); \
        if ($found.Count -eq 0) { exit 1 }; \
        try { \
            $found | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } \
        } catch { exit 2 }; \
        exit 0";
    let mut command = child_command("powershell");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("SHEKYL_KILL_TOR_NAMED_BY", needle);
    command
}

#[cfg(test)]
mod tests {
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    /// The stand-in outlives the test unless it is killed.
    const STAND_IN_LIFETIME: Duration = Duration::from_secs(60);
    /// After the kill tool has returned, a process it signalled is gone
    /// within this long. A survivor is still running at the end of it.
    const KILL_VISIBLE: Duration = Duration::from_millis(500);
    /// How often a stand-in is polled while [`KILL_VISIBLE`] runs.
    const KILL_POLL: Duration = Duration::from_millis(50);
    /// How many times a copied program is started again while another
    /// process still holds it for writing (`ETXTBSY`).
    const COPY_BUSY_TRIES: u32 = 50;
    /// Pause between those starts.
    const COPY_BUSY_PAUSE: Duration = Duration::from_millis(20);

    /// A needle no process carries finds nothing, and says so.
    ///
    /// The name contains `.` and an unclosed `[`, both extended-regex
    /// metacharacters. Unescaped, `pkill -f` rejects the pattern and the
    /// helper panics, so a helper that hands the path to `pkill` raw cannot
    /// pass. Red edit: return `true` whatever the tool reports, and every
    /// live test's "the managed tor was killed" check passes with nothing
    /// killed.
    #[test]
    fn a_needle_no_tor_carries_kills_nothing() {
        let unused = tempfile::tempdir().unwrap();
        let needle = unused.path().join("no.tor[was-ever-started-here");
        assert!(!kill_tor_named_by(&needle));
    }

    /// A process that is not Tor, kept alive until it is dropped.
    struct StandIn {
        child: Child,
    }

    impl Drop for StandIn {
        fn drop(&mut self) {
            // The stand-in may already have exited. That error is the end
            // of the test, not a failure of it.
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }

    impl StandIn {
        /// Still running for [`KILL_VISIBLE`] after the kill tool returned.
        fn survived(mut self) -> bool {
            let deadline = Instant::now() + KILL_VISIBLE;
            while Instant::now() < deadline {
                if self
                    .child
                    .try_wait()
                    .expect("the stand-in's state")
                    .is_some()
                {
                    return false;
                }
                std::thread::sleep(KILL_POLL);
            }
            true
        }
    }

    /// A process that waits out [`STAND_IN_LIFETIME`], started as `program`
    /// with `marker` on its command line.
    ///
    /// Unix: `program -c 'sleep N; :' marker`. The `:` keeps the shell from
    /// replacing itself with `sleep`, which would take the marker off the
    /// command line. Windows: `program /c "ping … & rem marker"`, `cmd.exe`.
    fn stand_in(program: &Path, marker: &Path) -> StandIn {
        let mut command = child_command(program);
        #[cfg(unix)]
        command
            .arg("-c")
            .arg(format!("sleep {}; :", STAND_IN_LIFETIME.as_secs()))
            .arg(marker);
        #[cfg(windows)]
        {
            // `ping -n` counts the first echo, so one more than the lifetime
            // in seconds is what lasts about that long.
            let echoes = STAND_IN_LIFETIME.as_secs() + 1;
            let marker = marker.to_str().expect("a UTF-8 path names the stand-in");
            let script = format!("ping -n {echoes} 127.0.0.1 >nul & rem {marker}");
            command.args(["/c", &script]);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        StandIn {
            child: spawn_stand_in(&mut command),
        }
    }

    /// Start `command`, again while the program is busy.
    ///
    /// A copied binary can be open for write for a moment: another test's
    /// child still holds the copy, or `codesign` has just written it. Unix
    /// refuses `exec` with `ETXTBSY` until that descriptor closes.
    fn spawn_stand_in(command: &mut Command) -> Child {
        for _ in 0..COPY_BUSY_TRIES {
            match spawn_lock::spawn(command) {
                Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(COPY_BUSY_PAUSE);
                }
                started => return started.expect("the stand-in starts"),
            }
        }
        panic!(
            "the copied program stayed busy for {} ms",
            u128::from(COPY_BUSY_TRIES) * COPY_BUSY_PAUSE.as_millis()
        );
    }

    /// macOS kills a copied system binary at exec (status 137). An ad-hoc
    /// signature makes the copy a program of its own.
    #[cfg(target_os = "macos")]
    fn sign_ad_hoc(program: &Path) {
        let mut command = child_command("codesign");
        command
            .args(["-f", "-s", "-"])
            .arg(program)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(
            spawn_lock::status(&mut command)
                .expect("codesign starts")
                .success(),
            "the copy is signed ad hoc"
        );
    }

    /// A shell that runs as itself: `/bin/zsh` on macOS, whose `/bin/sh`
    /// starts another shell in its place; `/bin/sh` on the other Unixes;
    /// `cmd.exe` on Windows.
    fn shell() -> std::path::PathBuf {
        #[cfg(target_os = "macos")]
        let shell = std::path::PathBuf::from("/bin/zsh");
        #[cfg(all(unix, not(target_os = "macos")))]
        let shell = std::path::PathBuf::from("/bin/sh");
        #[cfg(windows)]
        let shell =
            std::path::PathBuf::from(std::env::var_os("ComSpec").expect("ComSpec names cmd.exe"));
        shell
    }

    /// A process that is not Tor survives, though its command line carries
    /// the needle. Red edit: drop the program from the match (Unix: match
    /// the needle anywhere; Windows: drop `Name = 'tor.exe'`), and the shell
    /// is killed.
    #[test]
    fn a_process_that_is_not_tor_survives() {
        let dir = tempfile::tempdir().unwrap();
        let needle = dir.path().join("data");
        let bystander = stand_in(&shell(), &needle);
        assert!(!kill_tor_named_by(&needle), "nothing named tor carries it");
        assert!(bystander.survived(), "the shell was not killed");
    }

    /// The needle is text, not a pattern. A Tor whose command line differs
    /// from it only where the needle has a `.` survives, and a Tor carrying
    /// the needle itself is killed. The Tor is a copy of the system shell
    /// named `tor`, signed ad hoc on macOS. Red edit: pass the needle to
    /// `pkill` unescaped, and the first Tor is killed.
    #[test]
    fn the_needle_is_text_not_a_pattern() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let tor = dir.path().join("tor");
        #[cfg(windows)]
        let tor = dir.path().join("tor.exe");
        std::fs::copy(shell(), &tor).expect("a copy of the shell named tor");
        #[cfg(target_os = "macos")]
        sign_ad_hoc(&tor);
        let needle = dir.path().join("data.dir");
        let near_miss = stand_in(&tor, &dir.path().join("dataXdir"));
        assert!(
            !kill_tor_named_by(&needle),
            "no tor carries the needle as text"
        );
        assert!(near_miss.survived(), "the near miss was not killed");
        let carrier = stand_in(&tor, &needle);
        assert!(
            kill_tor_named_by(&needle),
            "the tor carrying the needle is found"
        );
        assert!(!carrier.survived(), "and killed");
    }
}
