// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet RPC server hardens its process before it reads an argument
//! (rule 35, `DAEMON_CONFIG_CUTOVER.md` DC-Q21): the core limit is zero,
//! soft and hard, read from outside the running binary.
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
//! **What turns this red.** `main` without its first statement: the server
//! then runs with the limits the shell gave it.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Raises the soft core limit to the hard one, then becomes `$0`.
const RAISE_THEN_EXEC: &str = r#"ulimit -Sc "$(ulimit -Hc)" && exec "$0" "$@""#;

/// How long the server has to bind its socket.
const BIND_DEADLINE: Duration = Duration::from_secs(60);

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
    let mut ready = String::new();
    BufReader::new(control.stdout.take().expect("piped stdout"))
        .read_line(&mut ready)
        .expect("read the control child's line");
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

/// A running `shekyl-wallet-rpc` reads a zero core limit, soft and hard,
/// from outside. The limit is read once its socket is bound, so the server
/// is past `main`'s first statement.
#[test]
fn a_running_wallet_rpc_has_no_core_limit() {
    assert_the_shell_gives_a_core_limit();

    let dir = tempfile::tempdir().expect("tempdir");
    let wallets = dir.path().join("wallets");
    std::fs::create_dir(&wallets).expect("wallet dir");
    let socket = dir.path().join("rpc.sock");
    let stderr_path = dir.path().join("stderr");
    let mut child = Command::new("sh")
        .args([
            "-c",
            RAISE_THEN_EXEC,
            env!("CARGO_BIN_EXE_shekyl-wallet-rpc"),
        ])
        .args(["--network", "stagenet", "--disable-rpc-login"])
        .arg(format!("--rpc-bind=uds://{}", socket.display()))
        .arg("--wallet-dir")
        .arg(&wallets)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
        .spawn()
        .expect("spawn shekyl-wallet-rpc");

    let start = Instant::now();
    while !socket.exists() {
        if let Some(status) = child.try_wait().expect("poll shekyl-wallet-rpc") {
            panic!(
                "shekyl-wallet-rpc ended before binding ({status}); stderr:\n{}",
                stderr_of(&stderr_path)
            );
        }
        if start.elapsed() > BIND_DEADLINE {
            child.kill().expect("end shekyl-wallet-rpc");
            child.wait().expect("reap shekyl-wallet-rpc");
            panic!(
                "shekyl-wallet-rpc did not bind {} within {BIND_DEADLINE:?}; stderr:\n{}",
                socket.display(),
                stderr_of(&stderr_path)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let limit = core_limit(child.id());
    child.kill().expect("end shekyl-wallet-rpc");
    child.wait().expect("reap shekyl-wallet-rpc");

    assert_eq!(
        limit,
        ("0".to_owned(), "0".to_owned()),
        "shekyl-wallet-rpc runs with a core limit"
    );
}
