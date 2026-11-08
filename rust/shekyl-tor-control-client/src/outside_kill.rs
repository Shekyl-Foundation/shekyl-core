// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Killing a managed Tor from outside, for the live tests.
//!
//! The crash the supervisors exist for is a Tor that ends with no stop, no
//! control-connection close and no handle. The live tests deliver it the way
//! a platform's own tools would: they name the Tor by its command line, which
//! carries the test's unique data directory, and kill it. On Unix that is
//! `pkill -9 -f`; on Windows a CIM query by command line and
//! `Stop-Process -Force`, which is `TerminateProcess`. The child's handle is
//! not used: a kill through it would be the supervisor's own act, not a
//! crash.
//!
//! Test-only: compiled under `cfg(test)` or the `unpinned-tor-for-tests`
//! feature, which only dev-dependency edges enable
//! (`scripts/ci/check_test_only_features.py`).

use std::path::Path;
use std::process::Command;

use crate::{inherit, spawn_lock};

/// Kill every Tor whose command line contains `needle`, from outside. `true`
/// when at least one was found and killed.
///
/// # Panics
///
/// When `needle` is not UTF-8, or the platform's tool does not start.
#[must_use]
pub fn kill_tor_named_by(needle: &Path) -> bool {
    let needle = needle.to_str().expect("a UTF-8 path names the Tor");
    let status =
        spawn_lock::status(&mut kill_command(needle)).expect("the platform's kill tool starts");
    status.success()
}

/// `pkill -9 -f`: SIGKILL to every process whose full command line matches
/// [`tor_pattern`]. `pkill` does not match itself. Like every spawn in a
/// crate that launches a managed tor, its child inherits standard input,
/// output and error only (`DAEMON_CONFIG_CUTOVER.md` §2.10).
#[cfg(unix)]
fn kill_command(needle: &str) -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new("pkill");
    command.args(["-9", "-f"]).arg(tor_pattern(needle));
    let stdio_only = inherit::StdioOnly::prepare();
    // SAFETY: the closure runs in the child between `fork` and `exec`, and
    // [`inherit::StdioOnly::apply`] is async-signal-safe.
    unsafe {
        command.pre_exec(move || stdio_only.apply());
    }
    command
}

/// The extended regular expression `pkill -f` reads, matching what Windows
/// matches: a process whose program is a file named `tor`, and whose command
/// line contains `needle` as text. The managed launch runs tor by its
/// absolute path, so the command line starts with `…/tor ` (`launch.rs`).
/// Every character of the needle that the expression grammar reads is
/// escaped: a temporary directory's `.` would otherwise match any character.
/// The program's path may not contain a space, so that a later argument
/// ending in `/tor` cannot stand in for the program. A tor at such a path is
/// not found, and the caller's "tor was killed" check fails loudly.
#[cfg(unix)]
fn tor_pattern(needle: &str) -> String {
    let mut literal = String::with_capacity(needle.len() * 2);
    for c in needle.chars() {
        if "\\.[](){}*+?|^$".contains(c) {
            literal.push('\\');
        }
        literal.push(c);
    }
    format!("^([^ ]*/)?tor .*{literal}")
}

/// Every `tor.exe` whose command line contains the needle, stopped with
/// `-Force`. `Contains` matches the text literally: `-like` would read `[`
/// and `]` in a path as a pattern. The needle travels in the environment, so
/// no quoting of the path reaches the script. Exit 1 when none was found. A
/// child here inherits only the handles marked inheritable
/// (`inherit::stdio_only` is a no-op on Windows).
#[cfg(windows)]
fn kill_command(needle: &str) -> Command {
    const SCRIPT: &str = "$needle = $env:SHEKYL_KILL_TOR_NAMED_BY; \
        $found = @(Get-CimInstance Win32_Process -Filter \"Name = 'tor.exe'\" | \
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($needle) }); \
        if ($found.Count -eq 0) { exit 1 }; \
        $found | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }; \
        exit 0";
    let mut command = Command::new("powershell");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("SHEKYL_KILL_TOR_NAMED_BY", needle);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A needle no process carries finds nothing, and says so. Red edit:
    /// return `true` whatever the tool reports, and every live test's
    /// "the managed tor was killed" check passes with nothing killed.
    #[test]
    fn a_needle_no_tor_carries_kills_nothing() {
        let unused = tempfile::tempdir().unwrap();
        let needle = unused.path().join("no-tor-was-ever-started-here");
        assert!(!kill_tor_named_by(&needle));
    }

    /// A process that waits 60 s, started as `program` with `marker` on its
    /// command line. Unix: `program -c 'sleep 60; :' marker`, a shell; the
    /// `:` keeps the shell from replacing itself with `sleep`, which would
    /// take the marker off the command line. Windows:
    /// `program /c "ping -n 60 127.0.0.1 >nul & rem marker"`, `cmd.exe`.
    fn waiter(program: &Path, marker: &Path) -> std::process::Child {
        let mut command = Command::new(program);
        #[cfg(unix)]
        command.args(["-c", "sleep 60; :"]).arg(marker);
        #[cfg(windows)]
        command.args([
            "/c",
            &format!("ping -n 60 127.0.0.1 >nul & rem {}", marker.display()),
        ]);
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // A copied program can be busy for a moment: another test's fork may
        // hold the copy's write descriptor until that child execs.
        for _ in 0..50 {
            match command.spawn() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                started => return started.expect("the waiter starts"),
            }
        }
        panic!("the copied program stayed busy for a second");
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

    /// Whether `child` is still running after up to 5 s for an exit already
    /// sent, then end it.
    fn alive_then_reaped(mut child: std::process::Child) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut alive = true;
        while std::time::Instant::now() < deadline {
            if child.try_wait().expect("the waiter's state").is_some() {
                alive = false;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Ending a child that has already exited is not an error here.
        drop(child.kill());
        drop(child.wait());
        alive
    }

    /// A process that is not Tor survives, though its command line carries
    /// the needle. Red edit: drop the program from the match (Unix: match
    /// the needle anywhere; Windows: drop `Name = 'tor.exe'`), and the shell
    /// is killed.
    #[test]
    fn a_process_that_is_not_tor_survives() {
        let dir = tempfile::tempdir().unwrap();
        let needle = dir.path().join("data");
        let bystander = waiter(&shell(), &needle);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!kill_tor_named_by(&needle), "nothing named tor carries it");
        assert!(alive_then_reaped(bystander), "the shell was not killed");
    }

    /// The needle is text, not a pattern: a Tor whose command line differs
    /// from it only where the needle has a `.` survives, and a Tor carrying
    /// the needle itself is killed. The Tor is a copy of the system shell
    /// named `tor`. Red edit: pass the needle to `pkill` unescaped, and the
    /// first Tor is killed.
    #[test]
    fn the_needle_is_text_not_a_pattern() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let tor = dir.path().join("tor");
        #[cfg(windows)]
        let tor = dir.path().join("tor.exe");
        std::fs::copy(shell(), &tor).expect("a copy of the shell named tor");
        let needle = dir.path().join("data.dir");
        let near_miss = waiter(&tor, &dir.path().join("dataXdir"));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !kill_tor_named_by(&needle),
            "no tor carries the needle as text"
        );
        assert!(alive_then_reaped(near_miss), "the near miss was not killed");
        let carrier = waiter(&tor, &needle);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            kill_tor_named_by(&needle),
            "the tor carrying the needle is found"
        );
        assert!(!alive_then_reaped(carrier), "and killed");
    }
}
