// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node honours an interrupt its parent asked it to ignore, and says so
//! (Rick, 2026-11-08). A parent starts a program in the background with
//! `SIGINT` ignored so that an interrupt typed at its terminal leaves the
//! program alone; the node keeps that, announces that Ctrl-C is off and how
//! to stop it, and still stops on `SIGTERM`. With no such request, `SIGINT`
//! stops it as before.
//!
//! Each test starts a whole daemon in a child process, offline on regtest:
//! this test binary run again as [`the_daemon_child`], which runs the start
//! sequence (`shekyl_daemon::run::main`). A disposition is process-wide and
//! inherited across `exec`, so only a child shows what a parent's request
//! does. The ignored disposition comes from `sh`'s `trap "" INT` before the
//! `exec`, as a shell's background job gets it.

#![cfg(unix)]

use std::ffi::OsString;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use shekyl_daemon_config::Platform;

/// The child's working directory. Set only by the tests below.
const CHILD_DIR: &str = "SHEKYL_TEST_INTERRUPT_CHILD_DIR";
/// The child's admin RPC port: its bind is the sign that the stop owner is
/// installed, because the start owns the stop triggers before the RPC starts.
const CHILD_PORT: &str = "SHEKYL_TEST_INTERRUPT_CHILD_PORT";

/// The line the start announces when `SIGINT` was ignored.
const SHIELD_LINE: &str = "Ctrl-C is off because the program that started this node asked for it. \
                           Stop it with SIGTERM or the service stop.";

/// The daemon the tests below start. It runs only as their child: without
/// [`CHILD_DIR`] it returns at once.
#[test]
#[ignore = "the daemon the interrupt tests start, as their child"]
fn the_daemon_child() {
    let (Some(dir), Some(port)) = (std::env::var_os(CHILD_DIR), std::env::var_os(CHILD_PORT))
    else {
        return;
    };
    let dir = PathBuf::from(dir);
    let port = port.into_string().expect("a port number");
    let args: Vec<OsString> = [
        "shekyld",
        "--network",
        "regtest",
        "--clearnet",
        "off",
        "--tor",
        "off",
        "--rpc-admin-listen",
        &format!("127.0.0.1:{port}"),
        "--data-dir",
        dir.join("data").to_str().expect("a UTF-8 path"),
        "--log-file",
        dir.join("shekyld.log").to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let status = shekyl_daemon::run::main(
        &args,
        &Platform {
            home: Some(dir),
            program_data: None,
        },
    );
    std::process::exit(status);
}

/// A daemon child, its directory and its port.
struct Node {
    child: Child,
    dir: tempfile::TempDir,
    port: u16,
}

impl Node {
    /// Start [`the_daemon_child`], with `SIGINT` ignored at its start when
    /// `ignored`, and return once its RPC answers.
    fn start(ignored: bool) -> Self {
        let dir = tempfile::tempdir().expect("a directory");
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("a free port")
            .port();
        let me = std::env::current_exe().expect("this test binary");
        let mut command = if ignored {
            let mut sh = Command::new("/bin/sh");
            sh.args(["-c", r#"trap "" INT; exec "$0" "$@""#]).arg(&me);
            sh
        } else {
            Command::new(&me)
        };
        command
            .args(["--exact", "the_daemon_child", "--ignored", "--nocapture"])
            .env(CHILD_DIR, dir.path())
            .env(CHILD_PORT, port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = shekyl_tor_control_client::spawn_lock::with(|| command.spawn())
            .expect("the daemon child starts");
        let mut node = Self { child, dir, port };
        node.wait_for_rpc();
        node
    }

    fn wait_for_rpc(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                panic!(
                    "the daemon ended before its RPC answered: {status}\n{}",
                    self.log()
                );
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the daemon's RPC did not answer in 120 s\n{}", self.log());
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("shekyld.log")).unwrap_or_default()
    }

    /// Send `signal` (`INT` or `TERM`) with `kill`.
    fn send(&self, signal: &str) {
        let pid = self.child.id().to_string();
        let mut kill = Command::new("kill");
        kill.args([&format!("-{signal}"), pid.as_str()]);
        let status = shekyl_tor_control_client::spawn_lock::status(&mut kill).expect("kill starts");
        assert!(status.success(), "kill -{signal} {pid}: {status}");
    }

    /// The exit status, if the daemon ends within `within`.
    fn ended_within(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

/// **`SIGINT` ignored at start:** the node announces that Ctrl-C is off and
/// how to stop it, a `SIGINT` does not stop it, and `SIGTERM` stops it
/// cleanly. Red edits: open the `SIGINT` stream whatever the parent asked
/// (the node stops on `SIGINT`), or drop the announcement (no line).
#[test]
fn an_interrupt_the_parent_ignored_does_not_stop_the_node() {
    let mut node = Node::start(true);
    let log = node.log();
    assert!(log.lines().any(|line| line == SHIELD_LINE), "{log}");
    node.send("INT");
    assert_eq!(
        node.ended_within(Duration::from_secs(3)),
        None,
        "SIGINT stopped a node whose parent asked it to ignore SIGINT\n{}",
        node.log()
    );
    node.send("TERM");
    let status = node
        .ended_within(Duration::from_secs(60))
        .unwrap_or_else(|| panic!("SIGTERM did not stop the node\n{}", node.log()));
    assert!(status.success(), "{status}\n{}", node.log());
    let log = node.log();
    assert!(
        log.lines().any(|line| line == "stop requested by SIGTERM"),
        "{log}"
    );
}

/// **No request:** `SIGINT` stops the node cleanly, and nothing is said
/// about Ctrl-C. Red edit: never open the `SIGINT` stream (the node does
/// not stop), or announce the line whatever the parent asked.
#[test]
fn an_interrupt_with_no_request_stops_the_node() {
    let mut node = Node::start(false);
    let log = node.log();
    assert!(!log.contains("Ctrl-C is off"), "{log}");
    node.send("INT");
    let status = node
        .ended_within(Duration::from_secs(60))
        .unwrap_or_else(|| panic!("SIGINT did not stop the node\n{}", node.log()));
    assert!(status.success(), "{status}\n{}", node.log());
    let log = node.log();
    assert!(
        log.lines().any(|line| line == "stop requested by SIGINT"),
        "{log}"
    );
}
