// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet RPC server hardens its process before it reads an argument
//! (rule 35, `DAEMON_CONFIG_CUTOVER.md` DC-Q21), observed from outside the
//! running binary against an unhardened control: on Linux and FreeBSD the
//! core limit reads `0` on both bounds, on FreeBSD a same-account `truss -p`
//! is refused too, and on macOS `SIGABRT` writes no core. Which OS proves
//! what, and what each arm needs of the host, is `shekyl-process`'s
//! `tests/support/from_outside.rs`. Windows is not covered here.
//!
//! **What turns this red.** `main` without its first statement: the server
//! then runs with the core limit the shell gave it.

#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]

#[path = "../../shekyl-process/tests/support/from_outside.rs"]
mod from_outside;

use std::process::Stdio;
use std::time::{Duration, Instant};

const NAME: &str = "a_running_wallet_rpc_is_hardened";

/// How long the server has to bind its socket.
const BIND_DEADLINE: Duration = Duration::from_secs(60);

/// A running `shekyl-wallet-rpc`, observed from outside once its socket is
/// bound, so it is past `main`'s first statement.
#[test]
fn a_running_wallet_rpc_is_hardened() {
    if from_outside::run_as_control_if_asked() {
        return;
    }
    from_outside::assert_the_control_shows_the_subject(NAME);

    let dir = tempfile::tempdir().expect("tempdir");
    let wallets = dir.path().join("wallets");
    std::fs::create_dir(&wallets).expect("wallet dir");
    // A short name: a socket path must fit `sun_path` (104 bytes on macOS
    // and FreeBSD), and the temp directory's own path is long on macOS.
    let socket = dir.path().join("s");
    let stderr_path = dir.path().join("stderr");
    let stderr_of = || std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let mut child = from_outside::raised(env!("CARGO_BIN_EXE_shekyl-wallet-rpc"))
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
                stderr_of()
            );
        }
        if start.elapsed() > BIND_DEADLINE {
            child.kill().expect("end shekyl-wallet-rpc");
            child.wait().expect("reap shekyl-wallet-rpc");
            panic!(
                "shekyl-wallet-rpc did not bind {} within {BIND_DEADLINE:?}; stderr:\n{}",
                socket.display(),
                stderr_of()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    from_outside::assert_hardened(&mut child);
    // macOS's check already ended it; ending a reaped child is a no-op.
    child.kill().expect("end shekyl-wallet-rpc");
    child.wait().expect("reap shekyl-wallet-rpc");
}
