// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A start waits while another process holds the socket's directory.
//!
//! This test starts a child process, so it has a test binary of its own. On
//! macOS a socket is close-on-exec only just after it is created, so a child
//! spawned beside the listener unit tests could inherit one of their sockets
//! and keep it listening, and a closed socket would then answer a probe. No
//! other test in this binary holds a socket.
#![cfg(unix)]

use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use shekyl_rpc_transport::listen::{
    bind_owner_only_socket, OwnerSocketRefusal, SOCKET_PROBE_BOUND,
};

/// How often the parent looks for the other process's hold.
const READY_POLL: Duration = Duration::from_millis(10);

/// A directory only this account can enter, as the bind requires.
fn owner_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 700");
    dir
}

/// The other process reads this and holds that directory. A test reads
/// it; the listeners do not.
const OTHER_START_DIR: &str = "SHEKYL_TEST_HOLD_SOCKET_DIRECTORY";

/// How long the other process holds the directory: well past the probe,
/// so the parent observes the wait rather than a release.
const OTHER_START_HOLD: Duration = Duration::from_secs(30);

/// How long the parent waits for that process to take the lock.
const OTHER_START_READY: Duration = Duration::from_secs(5);

/// The file the other process writes once it holds the directory.
const HELD: &str = "held";

/// Stops the other start when this test ends, however it ends.
struct StopTheOtherStart(Option<std::process::Child>);

impl Drop for StopTheOtherStart {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            if child.kill().is_ok() {
                let _status = child.wait();
            }
        }
    }
}

/// Hold `dir` and say so, then wait. The parent is another process: on
/// FreeBSD and macOS a second lock in this process would be granted.
fn hold_for_the_parent(dir: &str) {
    let held = std::fs::File::open(dir).expect("the directory");
    held.lock().expect("the other start's hold");
    std::fs::write(Path::new(dir).join(HELD), b"1").expect("ready");
    std::thread::sleep(OTHER_START_HOLD);
}

/// A start waits while another process holds the socket's directory, and
/// past [`SOCKET_PROBE_BOUND`] refuses with nothing bound, so a socket
/// bound and not yet listening is never probed as a stopped server's.
/// Once that process is gone, the bind goes ahead. Red edit: drop the
/// hold, or take it in this process (FreeBSD and macOS grant it).
#[test]
fn a_start_waits_for_another_start_on_the_same_directory() {
    if let Ok(dir) = std::env::var(OTHER_START_DIR) {
        hold_for_the_parent(&dir);
        return;
    }
    let dir = owner_only_dir();
    let path = dir.path().join("s.sock");
    let child = std::process::Command::new(std::env::current_exe().expect("this test"))
        .arg("--exact")
        .arg("a_start_waits_for_another_start_on_the_same_directory")
        .arg("--test-threads")
        .arg("1")
        .env(OTHER_START_DIR, dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the other start");
    let mut other = StopTheOtherStart(Some(child));
    let ready = dir.path().join(HELD);
    let deadline = Instant::now() + OTHER_START_READY;
    while !ready.exists() {
        let child = other.0.as_mut().expect("the other start");
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = other
                    .0
                    .take()
                    .expect("the other start")
                    .wait_with_output()
                    .expect("the other start's output");
                panic!(
                    "the other start exited before holding the directory\n{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(READY_POLL),
            Ok(None) => panic!("the other start never took the directory"),
            Err(error) => panic!("the other start: {error}"),
        }
    }
    let started = Instant::now();
    let refused = bind_owner_only_socket(&path).expect_err("another start holds it");
    assert!(
        started.elapsed() >= SOCKET_PROBE_BOUND,
        "it waited out the bound"
    );
    assert!(
        matches!(&refused, OwnerSocketRefusal::Socket(e) if e.kind() == ErrorKind::WouldBlock),
        "{refused:?}"
    );
    assert!(!path.exists(), "nothing was bound");
    let child = other.0.as_mut().expect("the other start");
    child.kill().expect("stop the other start");
    child.wait().expect("the other start ended");
    bind_owner_only_socket(&path).expect("bound once the other start is done");
}
