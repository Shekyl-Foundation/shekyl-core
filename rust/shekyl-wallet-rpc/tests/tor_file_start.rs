// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--tor-file` naming no file on this machine refuses the wallet server's
//! start with its remedy: it binds nothing and is never handed discovery in
//! its place (`INPUT_GRAMMAR.md` IG-Q41, as the daemon's; Rick, 2026-11-21).

#![cfg(unix)]

use std::process::{Command, Stdio};

#[test]
fn a_tor_file_naming_no_file_refuses_the_server_start_with_its_remedy() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let missing = scratch.path().join("no-such-tor");
    let wallets = scratch.path().join("wallets");
    std::fs::create_dir(&wallets).expect("wallet dir");
    let socket = scratch.path().join("s");
    let out = Command::new(env!("CARGO_BIN_EXE_shekyl-wallet-rpc"))
        .args(["--network", "stagenet", "--disable-rpc-login"])
        .arg(format!("--rpc-bind=uds://{}", socket.display()))
        .arg("--wallet-dir")
        .arg(&wallets)
        .arg("--tor-file")
        .arg(&missing)
        .stdin(Stdio::null())
        .output()
        .expect("run shekyl-wallet-rpc");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the start was not refused: {said}");
    assert!(said.contains(&missing.display().to_string()), "{said}");
    assert!(said.contains("point it at the Tor binary here"), "{said}");
    assert!(!socket.exists(), "the server bound its socket: {said}");
}
