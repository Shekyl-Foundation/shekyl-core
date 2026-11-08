// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI hardens its process before it reads an argument (rule 35,
//! `DAEMON_CONFIG_CUTOVER.md` DC-Q21): the core limit is zero, soft and
//! hard, read from outside the running binary.
//!
//! The check is Linux's: it reads `/proc/<pid>/limits`, which stays
//! readable by the same account after `PR_SET_DUMPABLE` makes the
//! directory root-owned. Other Unixes run the same `harden_process`, whose
//! read-back is `shekyl-process`'s unit test; this file does not prove them.
//!
//! **The subject.** A shell raises the soft limit to the hard one and then
//! `exec`s the child, so the child starts with a core limit to remove. A
//! control child started the same way must read non-zero, or the host gives
//! nothing to remove and the check fails as having no subject (rule 47).
//!
//! **What turns this red.** `main` without its first statement: the binary
//! then runs with the limits the shell gave it.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Raises the soft core limit to the hard one, then becomes `$0`.
const RAISE_THEN_EXEC: &str = r#"ulimit -Sc "$(ulimit -Hc)" && exec "$0" "$@""#;

/// The core limit of `pid`, soft and hard, as `/proc/<pid>/limits` spells
/// them (`0`, a byte count, or `unlimited`).
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

/// Reads one line of the child's standard output: the child has run past
/// the point the caller waits for.
fn first_line(child: &mut Child) -> String {
    let stdout = child.stdout.take().expect("piped stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the child's first line");
    line
}

/// The subject: a child started through the same shell reads a non-zero
/// core limit on both bounds.
fn assert_the_shell_gives_a_core_limit() {
    let mut control = Command::new("sh")
        .args([
            "-c",
            r#"ulimit -Sc "$(ulimit -Hc)" && echo ready && exec sleep 60"#,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the control child");
    let ready = first_line(&mut control);
    let limit = core_limit(control.id());
    control.kill().expect("end the control child");
    control.wait().expect("reap the control child");
    assert_eq!(ready.trim(), "ready", "the control child did not start");
    assert!(
        limit.0 != "0" && limit.1 != "0",
        "the control child's core limit is {limit:?}: this host gives no core \
         limit to remove, so the check below would pass for nothing"
    );
}

fn stderr_of(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A running `shekyl-cli` reads a zero core limit, soft and hard, from
/// outside. The child answers `version` first, so it is past `main`'s
/// first statement when the limit is read.
#[test]
fn a_running_cli_has_no_core_limit() {
    assert_the_shell_gives_a_core_limit();

    let dir = tempfile::tempdir().expect("tempdir");
    let wallets = dir.path().join("wallets");
    let stderr_path = dir.path().join("stderr");
    let mut child = Command::new("sh")
        .args(["-c", RAISE_THEN_EXEC, env!("CARGO_BIN_EXE_shekyl-cli")])
        .args(["--network", "stagenet", "--daemon-address", "127.0.0.1:1"])
        .arg("--wallet-dir")
        .arg(&wallets)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
        .spawn()
        .expect("spawn shekyl-cli");
    let mut stdin = child.stdin.take().expect("piped stdin");
    writeln!(stdin, "version").expect("write a command");
    let answer = first_line(&mut child);
    let limit = core_limit(child.id());
    drop(stdin);
    let status = child.wait().expect("reap shekyl-cli");

    assert!(
        answer.starts_with("shekyl-cli "),
        "shekyl-cli did not answer `version` (status {status}); stderr:\n{}",
        stderr_of(&stderr_path)
    );
    assert_eq!(
        limit,
        ("0".to_owned(), "0".to_owned()),
        "shekyl-cli runs with a core limit"
    );
    assert!(
        status.success(),
        "shekyl-cli did not end cleanly at the end of its input: {status}; stderr:\n{}",
        stderr_of(&stderr_path)
    );
}
