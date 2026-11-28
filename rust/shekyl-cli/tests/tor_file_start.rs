// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--tor-file` naming no file on this machine refuses the CLI's start with
//! its remedy, before the self-hosted server starts; it is never replaced by
//! discovery (`INPUT_GRAMMAR.md` IG-Q41, as the daemon's; Rick, 2026-11-21).
//! A relative one is refused too, before it is looked for (IG-6).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

mod common;

/// Start the CLI with `--tor-file tor_file` and return what it said, having
/// asserted that it refused before its session started.
fn refused_start(scratch: &Path, tor_file: &Path) -> String {
    let config = common::offline_channel_config();
    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"))
        .arg("--config-file")
        .arg(config.path())
        .args(["--network", "stagenet", "--daemon-endpoint", "127.0.0.1:1"])
        .arg("--wallet-dir")
        .arg(scratch.join("wallets"))
        .arg("--tor-file")
        .arg(tor_file)
        .env("XDG_RUNTIME_DIR", scratch)
        .env("TMPDIR", scratch)
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
    assert!(said.contains(&tor_file.display().to_string()), "{said}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("shekyl-cli "),
        "the CLI answered a command, so its session started: {said}"
    );
    said
}

#[test]
fn a_tor_file_naming_no_file_refuses_the_cli_start_with_its_remedy() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let said = refused_start(scratch.path(), &scratch.path().join("no-such-tor"));
    assert!(said.contains("point it at the Tor binary here"), "{said}");
}

/// A relative `--tor-file` is refused before it is looked for, even naming a
/// file from the working directory (IG-6: a `path` is absolute). The test
/// runs in the crate's directory, where `Cargo.toml` is a file.
#[test]
fn a_relative_tor_file_refuses_the_cli_start() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let relative = Path::new("Cargo.toml");
    assert!(relative.is_file(), "the test runs in the crate's directory");
    let said = refused_start(scratch.path(), relative);
    assert!(said.contains("is not an absolute path"), "{said}");
}
