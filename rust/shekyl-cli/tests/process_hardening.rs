// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI hardens its process before it reads an argument (rule 35,
//! `DAEMON_CONFIG_CUTOVER.md` DC-Q21), observed from outside the running
//! binary against an unhardened control: on Linux and FreeBSD the core limit
//! reads `0` on both bounds, on FreeBSD a same-account `truss -p` is refused
//! too, and on macOS `SIGABRT` writes no core. Which OS proves what, and what
//! each arm needs of the host, is `shekyl-process`'s
//! `tests/support/from_outside.rs`. Windows is not covered here.
//!
//! **What turns this red.** `main` without its first statement: the binary
//! then runs with the core limit the shell gave it.

#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]

#[path = "../../shekyl-process/tests/support/from_outside.rs"]
mod from_outside;

use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;

const NAME: &str = "a_running_cli_is_hardened";

/// A running `shekyl-cli`, observed from outside. The child answers
/// `version` first, so it is past `main`'s first statement when it is read.
#[test]
fn a_running_cli_is_hardened() {
    if from_outside::run_as_control_if_asked() {
        return;
    }
    from_outside::assert_the_control_shows_the_subject(NAME);

    let dir = tempfile::tempdir().expect("tempdir");
    let wallets = dir.path().join("wallets");
    let stderr_path = dir.path().join("stderr");
    let mut child = from_outside::raised(env!("CARGO_BIN_EXE_shekyl-cli"))
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
    let mut answer = String::new();
    BufReader::new(child.stdout.take().expect("piped stdout"))
        .read_line(&mut answer)
        .expect("read the answer");
    assert!(
        answer.starts_with("shekyl-cli "),
        "shekyl-cli did not answer `version`; stderr:\n{}",
        std::fs::read_to_string(&stderr_path).unwrap_or_default()
    );

    from_outside::assert_hardened(&mut child);
    drop(stdin);
    let status = child.wait().expect("reap shekyl-cli");
    // On macOS the check ended it by SIGABRT.
    if cfg!(not(target_os = "macos")) {
        assert!(
            status.success(),
            "shekyl-cli did not end cleanly at the end of its input: {status}; stderr:\n{}",
            std::fs::read_to_string(&stderr_path).unwrap_or_default()
        );
    }
}
