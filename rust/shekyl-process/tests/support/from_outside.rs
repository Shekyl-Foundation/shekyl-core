// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Observing a running binary's process hardening (rule 35, DC-Q21) from
//! outside it, for the binaries' own tests (`shekyl-cli`,
//! `shekyl-wallet-rpc`; included by `#[path]`).
//!
//! Every child starts through [`RAISE_THEN_EXEC`]: a shell raises the soft
//! core limit to the hard one and then becomes the program, so the program
//! starts with a core limit to remove. Each test first runs a **control**:
//! this test binary itself, re-executed in control mode
//! ([`run_as_control_if_asked`]), started the same way and never hardened.
//! The control must show what the hardened binary must not, or the test
//! fails as having no subject (rule 47).
//!
//! What each arm observes, and so proves:
//!
//! - **Linux.** `/proc/<pid>/limits`, the core row: the control reads
//!   non-zero, the binary `0`/`0`.
//! - **FreeBSD.** `procstat -l <pid>`, the `coredumpsize` row, read the same
//!   way; and `truss -p <pid>` from the same account, which attaches to the
//!   control and is refused for the binary (`procctl(PROC_TRACE_CTL)`). The
//!   control's attach needs `security.bsd.unprivileged_proc_debug=1`; with it
//!   off, the refusal would be the system's, so the control fails first.
//! - **macOS.** No tool reads another process's limit, so the arm observes
//!   the effect: `SIGABRT` to the control writes the core `kern.corefile`
//!   names, and `SIGABRT` to the binary writes none. It needs
//!   `kern.coredump=1` and a core directory this account can write; without
//!   either the control writes nothing and the test fails saying so. Every
//!   core it finds is deleted.
//!
//! Windows has no core limit; its dump control is the fault filter, checked
//! for `shekyld` by `shekyl-process`'s `dc_q21_a_fault_ends_with_its_code.rs`.
//! No arm here covers it.

#![allow(dead_code)] // each including test uses part of the surface

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

/// Raises the soft core limit to the hard one, then becomes `$0`.
pub const RAISE_THEN_EXEC: &str = r#"ulimit -Sc "$(ulimit -Hc)" && exec "$0" "$@""#;

/// The environment variable that puts this test binary in control mode.
const CONTROL_MARKER: &str = "SHEKYL_HARDENING_CONTROL";

/// The line a control prints once it runs.
const READY: &str = "control ready";

/// A command that starts `program` through [`RAISE_THEN_EXEC`].
pub fn raised(program: &str) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", RAISE_THEN_EXEC, program]);
    command
}

/// In the re-executed control: says it runs, then waits to be ended. The
/// caller's test returns at once when this returns `false`.
pub fn run_as_control_if_asked() -> bool {
    if std::env::var_os(CONTROL_MARKER).is_none() {
        return false;
    }
    println!("{READY}");
    std::thread::sleep(std::time::Duration::from_secs(120));
    true
}

/// Starts the control (this test binary, on `test` alone, in control mode,
/// through the raising shell) and waits for its line.
fn start_control(test: &str) -> Child {
    let exe = std::env::current_exe().expect("this test binary");
    let mut control = raised(exe.to_str().expect("a UTF-8 test binary path"))
        .args(["--exact", test, "--nocapture"])
        .env(CONTROL_MARKER, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the control");
    let stdout = control.stdout.take().expect("piped stdout");
    let ready = BufReader::new(stdout)
        .lines()
        .map(|line| line.expect("read the control's output"))
        .any(|line| line == READY);
    assert!(ready, "the control ended without saying it runs");
    control
}

fn end(mut child: Child) {
    child.kill().expect("end the child");
    child.wait().expect("reap the child");
}

/// The control, observed: the property the binary must lack is present.
pub fn assert_the_control_shows_the_subject(test: &str) {
    let control = start_control(test);
    os::assert_unhardened(control);
}

/// The binary, observed: no core limit (Linux, FreeBSD), no tracer
/// (FreeBSD), no core on `SIGABRT` (macOS). On macOS this ends `child`.
pub fn assert_hardened(child: &mut Child) {
    os::assert_hardened(child);
}

#[cfg(target_os = "linux")]
mod os {
    use super::{end, Child};

    /// `/proc/<pid>/limits`' core row, soft and hard, as spelled there.
    fn core_limit(pid: u32) -> (String, String) {
        const ROW: &str = "Max core file size";
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/limits: {e}"));
        let row = limits
            .lines()
            .find(|line| line.starts_with(ROW))
            .unwrap_or_else(|| panic!("no core row in /proc/{pid}/limits:\n{limits}"));
        let mut columns = row[ROW.len()..].split_whitespace();
        let soft = columns.next().expect("soft column").to_owned();
        let hard = columns.next().expect("hard column").to_owned();
        (soft, hard)
    }

    pub fn assert_unhardened(control: Child) {
        let limit = core_limit(control.id());
        end(control);
        assert!(
            limit.0 != "0" && limit.1 != "0",
            "the control's core limit is {limit:?}: this host gives no core \
             limit to remove, so the check would pass for nothing"
        );
    }

    pub fn assert_hardened(child: &mut Child) {
        assert_eq!(
            core_limit(child.id()),
            ("0".to_owned(), "0".to_owned()),
            "the binary runs with a core limit"
        );
    }
}

#[cfg(target_os = "freebsd")]
mod os {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::{end, Child};

    /// `procstat -l`'s `coredumpsize` row, soft and hard: `infinity`, or a
    /// number with its unit (`0 B`).
    fn core_limit(pid: u32) -> (String, String) {
        let out = Command::new("procstat")
            .args(["-l", &pid.to_string()])
            .output()
            .expect("run procstat");
        let text = String::from_utf8_lossy(&out.stdout);
        let row = text
            .lines()
            .find(|line| line.split_whitespace().nth(2) == Some("coredumpsize"))
            .unwrap_or_else(|| panic!("no coredumpsize row from procstat -l {pid}:\n{text}"));
        let mut values = Vec::new();
        let mut tokens = row.split_whitespace().skip(3).peekable();
        while let Some(token) = tokens.next() {
            if token == "infinity" {
                values.push(token.to_owned());
            } else {
                let unit = tokens.next().unwrap_or("");
                values.push(format!("{token} {unit}").trim().to_owned());
            }
        }
        assert_eq!(values.len(), 2, "soft and hard in: {row}");
        (values[0].clone(), values[1].clone())
    }

    /// `truss -p <pid>` from this account: `Ok` while it stays attached for
    /// `window`, `Err(stderr)` if it ends first.
    fn truss_attaches(pid: u32, window: Duration) -> (Child, Result<(), String>) {
        let mut truss = Command::new("truss")
            .args(["-o", "/dev/null", "-p", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run truss");
        let start = Instant::now();
        while start.elapsed() < window {
            if let Some(status) = truss.try_wait().expect("poll truss") {
                let mut stderr = String::new();
                if let Some(mut pipe) = truss.stderr.take() {
                    std::io::Read::read_to_string(&mut pipe, &mut stderr).expect("truss stderr");
                }
                return (truss, Err(format!("{status}: {}", stderr.trim())));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        (truss, Ok(()))
    }

    fn sysctl(name: &str) -> String {
        let out = Command::new("sysctl")
            .args(["-n", name])
            .output()
            .expect("run sysctl");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    pub fn assert_unhardened(control: Child) {
        let limit = core_limit(control.id());
        let (mut truss, attached) = truss_attaches(control.id(), Duration::from_secs(2));
        // truss first: ended by SIGKILL it detaches. A tracee killed under
        // an attached truss makes truss abort and leave a core.
        drop(truss.kill());
        truss.wait().expect("reap truss");
        end(control);
        assert!(
            !limit.0.starts_with("0 ") && !limit.1.starts_with("0 "),
            "the control's core limit is {limit:?}: this host gives no core \
             limit to remove, so the check would pass for nothing"
        );
        assert!(
            attached.is_ok(),
            "truss could not attach to the unhardened control ({attached:?}; \
             security.bsd.unprivileged_proc_debug = {}): a refusal of the \
             binary would be the system's, not its own",
            sysctl("security.bsd.unprivileged_proc_debug")
        );
    }

    pub fn assert_hardened(child: &mut Child) {
        let limit = core_limit(child.id());
        let (mut truss, attached) = truss_attaches(child.id(), Duration::from_secs(5));
        if attached.is_ok() {
            drop(truss.kill());
        }
        truss.wait().expect("reap truss");
        assert_eq!(
            limit,
            ("0 B".to_owned(), "0 B".to_owned()),
            "the binary runs with a core limit"
        );
        match attached {
            Ok(()) => panic!("truss attached to the hardened binary"),
            Err(why) => assert!(
                why.contains("Operation not permitted"),
                "truss ended for another reason than a refusal: {why}"
            ),
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{end, Child};

    fn sysctl(name: &str) -> String {
        let out = Command::new("sysctl")
            .args(["-n", name])
            .output()
            .expect("run sysctl");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Where the kernel writes `pid`'s core: `kern.corefile` with `%P`
    /// filled. A pattern with another token is refused by name.
    fn core_path(pid: u32) -> PathBuf {
        let pattern = sysctl("kern.corefile");
        let path = pattern.replace("%P", &pid.to_string());
        assert!(
            pattern.contains("%P") && !path.contains('%'),
            "kern.corefile is {pattern:?}: this check reads only a pattern \
             whose one token is %P"
        );
        PathBuf::from(path)
    }

    /// Ends `pid` by `SIGABRT` and reaps it.
    fn abort(child: &mut Child) {
        let status = Command::new("kill")
            .args(["-ABRT", &child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -ABRT {} failed", child.id());
        child.wait().expect("reap the child");
    }

    /// Removes the core at `path` and says whether there was one.
    fn take_core(path: &Path) -> bool {
        let there = path.exists();
        if there {
            std::fs::remove_file(path)
                .unwrap_or_else(|e| panic!("remove the core {}: {e}", path.display()));
        }
        there
    }

    fn describe_directory(path: &Path) -> String {
        let dir = path.parent().unwrap_or(Path::new("/"));
        match Command::new("ls").arg("-ld").arg(dir).output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
            Err(e) => format!("{}: {e}", dir.display()),
        }
    }

    pub fn assert_unhardened(mut control: Child) {
        let coredump = sysctl("kern.coredump");
        if coredump != "1" {
            end(control);
            panic!(
                "kern.coredump is {coredump:?}: this Mac writes no core for \
                 anything, so the check would pass for nothing"
            );
        }
        let path = core_path(control.id());
        abort(&mut control);
        assert!(
            take_core(&path),
            "SIGABRT to the unhardened control left no core at {}; the core \
             directory must be writable by this account ({}), or the check \
             would pass for nothing",
            path.display(),
            describe_directory(&path)
        );
    }

    pub fn assert_hardened(child: &mut Child) {
        let path = core_path(child.id());
        abort(child);
        assert!(
            !take_core(&path),
            "SIGABRT to the hardened binary wrote a core at {} (removed)",
            path.display()
        );
    }
}
