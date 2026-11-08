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

/// `pkill -9 -f`: SIGKILL to every process whose full command line matches.
/// `pkill` does not match itself. Like every spawn in a crate that launches a
/// managed tor, its child inherits standard input, output and error only
/// (`DAEMON_CONFIG_CUTOVER.md` §2.10).
#[cfg(unix)]
fn kill_command(needle: &str) -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new("pkill");
    command.args(["-9", "-f", needle]);
    let stdio_only = inherit::StdioOnly::prepare();
    // SAFETY: the closure runs in the child between `fork` and `exec`, and
    // [`inherit::StdioOnly::apply`] is async-signal-safe.
    unsafe {
        command.pre_exec(move || stdio_only.apply());
    }
    command
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
}
