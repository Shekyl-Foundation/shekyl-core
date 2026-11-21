// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI's in-process wallet server listens on a socket in a private
//! directory it makes (`shekyl-rpc-<pid>-<n>`, under `XDG_RUNTIME_DIR`, else
//! the temp directory), and removes that directory when the CLI ends. On
//! FreeBSD every run left it behind, the socket still in it, and nothing said
//! so (2026-11-21).
//!
//! This test kills nothing: the CLI answers `version`, reads the end of its
//! input and ends on its own. Both places the directory can be made are
//! pointed at this test's own directory, so the check sees this run alone.
//!
//! **What turns this red.** `InProcessHandle::shutdown` not removing the
//! directory, or the CLI ending without calling it.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// The directory's name begins with this (`private_socket_dir`).
const PRIVATE_DIR_PREFIX: &str = "shekyl-rpc-";

#[test]
fn a_cli_that_ends_at_its_input_leaves_no_socket_directory() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let wallets = scratch.path().join("wallets");
    let stderr_path = scratch.path().join("stderr");
    let listing = || -> Vec<String> {
        std::fs::read_dir(&runtime)
            .expect("list the runtime dir")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|n| n.starts_with(PRIVATE_DIR_PREFIX))
            .collect()
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"))
        .args(["--network", "stagenet", "--daemon-address", "127.0.0.1:1"])
        .arg("--wallet-dir")
        .arg(&wallets)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("TMPDIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
        .spawn()
        .expect("spawn shekyl-cli");
    let stderr_of = || std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let mut stdin = child.stdin.take().expect("piped stdin");
    writeln!(stdin, "version").expect("write a command");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut answer = String::new();
    stdout.read_line(&mut answer).expect("read the answer");
    assert!(
        answer.starts_with("shekyl-cli "),
        "shekyl-cli did not answer `version`; stderr:\n{}",
        stderr_of()
    );
    // The server is up and its directory is there: the check below has a
    // subject (rule 47).
    assert_eq!(
        listing().len(),
        1,
        "the running CLI's socket directory is not under the test's runtime dir: {:?}",
        listing()
    );

    drop(stdin);
    std::io::copy(&mut stdout, &mut std::io::sink()).expect("drain the CLI's output");
    let status = child.wait().expect("reap shekyl-cli");
    assert!(
        status.success(),
        "shekyl-cli did not end cleanly at the end of its input: {status}; stderr:\n{}",
        stderr_of()
    );
    assert!(
        listing().is_empty(),
        "the CLI left its socket directory behind: {:?}; stderr:\n{}",
        listing(),
        stderr_of()
    );
}
