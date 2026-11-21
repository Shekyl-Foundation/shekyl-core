// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--tor-file` naming no file on this machine refuses the CLI's start with
//! its remedy, before the self-hosted server starts; it is never replaced by
//! discovery (`INPUT_GRAMMAR.md` IG-Q41, as the daemon's; Rick, 2026-11-21).

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn a_tor_file_naming_no_file_refuses_the_cli_start_with_its_remedy() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let missing = scratch.path().join("no-such-tor");
    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"))
        .args(["--network", "stagenet", "--daemon-address", "127.0.0.1:1"])
        .arg("--wallet-dir")
        .arg(scratch.path().join("wallets"))
        .arg("--tor-file")
        .arg(&missing)
        .env("XDG_RUNTIME_DIR", scratch.path())
        .env("TMPDIR", scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shekyl-cli");
    // The pipe may already refuse this if the CLI has ended.
    drop(writeln!(
        child.stdin.take().expect("piped stdin"),
        "version"
    ));
    let out = child.wait_with_output().expect("wait for shekyl-cli");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the start was not refused: {said}");
    assert!(said.contains(&missing.display().to_string()), "{said}");
    assert!(said.contains("point it at the Tor binary here"), "{said}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("shekyl-cli "),
        "the CLI answered a command, so its session started: {said}"
    );
}
