// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--tor-file` naming no file on this machine refuses the wallet server's
//! start with its remedy: it binds nothing and is never handed discovery in
//! its place (`INPUT_GRAMMAR.md` IG-Q41, as the daemon's; Rick, 2026-11-21).
//! A relative one is refused too, before it is looked for (IG-6).

#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};

/// Start the server with `--tor-file tor_file` and return what it said,
/// having asserted that it refused and bound nothing.
fn refused_start(scratch: &Path, tor_file: &Path) -> String {
    let wallets = scratch.join("wallets");
    std::fs::create_dir(&wallets).expect("wallet dir");
    let socket = scratch.join("s");
    let out = Command::new(env!("CARGO_BIN_EXE_shekyl-wallet-rpc"))
        .args(["--network", "stagenet", "--disable-rpc-login"])
        .arg(format!("--rpc-bind=uds://{}", socket.display()))
        .arg("--wallet-dir")
        .arg(&wallets)
        .arg("--tor-file")
        .arg(tor_file)
        .stdin(Stdio::null())
        .output()
        .expect("run shekyl-wallet-rpc");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the start was not refused: {said}");
    assert!(said.contains(&tor_file.display().to_string()), "{said}");
    assert!(!socket.exists(), "the server bound its socket: {said}");
    said
}

#[test]
fn a_tor_file_naming_no_file_refuses_the_server_start_with_its_remedy() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let said = refused_start(scratch.path(), &scratch.path().join("no-such-tor"));
    assert!(said.contains("point it at the Tor binary here"), "{said}");
}

/// A relative `--tor-file` is refused before it is looked for, even naming a
/// file from the working directory (IG-6: a `path` is absolute). The test
/// runs in the crate's directory, where `Cargo.toml` is a file.
#[test]
fn a_relative_tor_file_refuses_the_server_start() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let relative = Path::new("Cargo.toml");
    assert!(relative.is_file(), "the test runs in the crate's directory");
    let said = refused_start(scratch.path(), relative);
    assert!(said.contains("is not an absolute path"), "{said}");
}
