// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI half of RT-W7 on the built binary: a `--daemon-address` that is
//! not loopback puts the §1 operator statement on stderr before the command
//! runs; the loopback default says nothing. The edit that turns the first
//! test red is deleting the `disclose_network_posture` call in
//! `run_scripted`.

use std::process::{Command, Output};

/// Run a scripted `create` that fails before any daemon call: the password
/// file does not exist, so the run ends after the session is built (and the
/// disclosure made) and before anything is dialed. `203.0.113.7` is
/// TEST-NET-3 — it is never dialed here, so its unroutability never matters.
fn create_with(daemon_address: Option<&str>) -> Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"));
    cmd.arg("--engine-dir")
        .arg(dir.path())
        .arg("--network")
        .arg("stagenet");
    if let Some(address) = daemon_address {
        cmd.arg("--daemon-address").arg(address);
    }
    cmd.arg("create")
        .arg("w")
        .arg("--seed-out")
        .arg(dir.path().join("seed"))
        .arg("--password-file")
        .arg(dir.path().join("missing"));
    cmd.output().expect("spawn shekyl-cli")
}

#[test]
fn a_non_loopback_daemon_address_is_said_on_stderr() {
    let out = create_with(Some("203.0.113.7:11029"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the missing password file ends the run: {stderr}"
    );
    assert!(stderr.contains("operates that daemon"), "{stderr}");
    assert!(stderr.contains("203.0.113.7"), "{stderr}");
    assert!(stderr.contains("no proxy is configured"), "{stderr}");
}

#[test]
fn the_loopback_default_says_nothing() {
    let out = create_with(None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(!stderr.contains("operates that daemon"), "{stderr}");
    assert!(!stderr.contains("is not loopback"), "{stderr}");
}
