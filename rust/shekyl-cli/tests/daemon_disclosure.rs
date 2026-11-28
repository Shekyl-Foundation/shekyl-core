// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI half of RT-W7 on the built binary: a `daemon-endpoint` that is
//! not loopback puts the §1 operator statement on stderr before the command
//! runs; the loopback default says nothing. The edit that turns the first
//! test red is deleting the `disclose_network_posture` call in
//! `run_session`.

use std::process::{Command, Output};

mod common;

/// Run a file-backed `wallet create` that fails before any daemon call: the password
/// file does not exist, so the run ends after the session is built (and the
/// disclosure made) and before anything is dialed. `203.0.113.7` is
/// TEST-NET-3 — it is never dialed here, so its unroutability never matters.
fn create_with(daemon_address: Option<&str>) -> Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = common::empty_config();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"));
    cmd.arg("--config-file")
        .arg(config.path())
        .arg("--wallet-dir")
        .arg(dir.path())
        .arg("--network")
        .arg("stagenet");
    if let Some(address) = daemon_address {
        let key = shekyl_rpc_channel::handshake::StaticKeypair::generate().unwrap();
        let mut bytes = key.public().x25519().to_vec();
        bytes.extend_from_slice(key.public().mlkem_ek());
        let bundle = dir.path().join("bundle");
        std::fs::write(&bundle, shekyl_rpc_transport::channel::bundle_text(&bytes)).unwrap();
        cmd.arg("--daemon-endpoint")
            .arg(address)
            .arg("--daemon-bundle-file")
            .arg(bundle);
    }
    cmd.arg("--wallet-password-file")
        .arg(dir.path().join("missing"))
        .args(["wallet", "create", "w", "--mnemonic-file"])
        .arg(dir.path().join("seed"));
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
