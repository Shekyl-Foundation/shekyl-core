// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node keeps `SIGINT` ignored when that is the disposition at start,
//! and says so.
//!
//! The disposition is `SIG_IGN` for a non-interactive background list
//! (`sh -c 'shekyld &'`) and for `trap "" INT`. An interactive `&` does not
//! set it: job control leaves the disposition alone and the terminal signals
//! the foreground process group. `nohup` ignores `SIGHUP`, not `SIGINT`.
//!
//! Each test re-executes itself. Between fork and exec it sets `SIGINT` to
//! `SIG_IGN` or `SIG_DFL`, so the child inherits the arm's disposition and
//! not this process's. The child runs `shekyl_daemon::run::main`. The
//! announcement is queued, so the test waits until the line is in the log
//! before it signals, and it judges the absence of the line only after the
//! child has exited and flushed.

#![cfg(unix)]

use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use shekyl_daemon_config::Platform;

/// The child's working directory. Set only when this binary is the child.
const CHILD_DIR: &str = "SHEKYL_TEST_INTERRUPT_CHILD_DIR";
/// The child's admin RPC port. Its bind is the sign that the stop owner is
/// installed: the start owns the stop triggers before the RPC listens.
const CHILD_PORT: &str = "SHEKYL_TEST_INTERRUPT_CHILD_PORT";

/// The line the start announces when `SIGINT` was `SIG_IGN`.
const IGNORED_LINE: &str =
    "Ctrl-C is off because the program that started this node asked for it. \
     Stop it with SIGTERM or the service stop.";

/// How long the RPC may take to listen.
const RPC_READY: Duration = Duration::from_secs(120);
/// How long a queued announcement may take to reach the log after the RPC
/// is up.
const LINE_ON_DISK: Duration = Duration::from_secs(10);
/// How long an ignored `SIGINT` must leave the node running.
const IGNORED_HOLDS: Duration = Duration::from_secs(3);
/// How long a real stop may take.
const STOP_ARRIVES: Duration = Duration::from_secs(60);
/// Spacing of the readiness polls.
const POLL: Duration = Duration::from_millis(50);

/// Run the daemon and exit with its status when this process is the child.
/// A parent call, with neither variable set, returns.
fn run_child_if_requested() {
    let (Some(dir), Some(port)) = (std::env::var_os(CHILD_DIR), std::env::var_os(CHILD_PORT))
    else {
        return;
    };
    let dir = PathBuf::from(dir);
    let port = port.into_string().expect("a port number");
    let listen = format!("127.0.0.1:{port}");
    let data_dir = dir.join("data");
    let log_file = dir.join("shekyld.log");
    let mut args: Vec<std::ffi::OsString> = [
        "shekyld",
        "--network",
        "regtest",
        "--clearnet",
        "off",
        "--tor",
        "off",
        "--rpc-admin-listen",
        listen.as_str(),
        "--data-dir",
        data_dir.to_str().expect("a UTF-8 path"),
        "--log-file",
        log_file.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    // A harness names a private directory for the owner's socket, so this
    // daemon never meets another test's at the default rendezvous
    // (`RPC_CHANNEL.md` §7.1).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let socket_dir = dir.join("s");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&socket_dir)
            .expect("a socket directory");
        args.push("--rpc-socket-dir".into());
        args.push(socket_dir.into_os_string());
    }
    let status = shekyl_daemon::run::main(
        &args,
        &Platform {
            home: Some(dir),
            program_data: None,
            session_dir: None,
            service_rendezvous: None,
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
    /// Start this test binary again as `test_name`, with `SIGINT` set to
    /// `SIG_IGN` when `ignored` and to `SIG_DFL` otherwise. Returns once
    /// the RPC accepts a connection.
    fn start(test_name: &str, ignored: bool) -> Self {
        let dir = tempfile::tempdir().expect("a directory");
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free port")
            .port();
        let stderr = File::create(dir.path().join("stderr")).expect("the stderr file");
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_DIR, dir.path())
            .env(CHILD_PORT, port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        // SAFETY: the closure runs between fork and exec and calls only
        // `signal`, which is async-signal-safe, plus the errno read on
        // failure. It sets this child's `SIGINT` and no other state.
        unsafe {
            command.pre_exec(move || {
                let disposition = if ignored {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                };
                if libc::signal(libc::SIGINT, disposition) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child =
            shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the daemon child starts");
        let mut node = Self { child, dir, port };
        node.wait_for_rpc();
        node
    }

    fn wait_for_rpc(&mut self) {
        let deadline = Instant::now() + RPC_READY;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                panic!(
                    "the daemon ended before its RPC answered: {status}\n{}",
                    self.evidence()
                );
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(POLL);
        }
        panic!(
            "the daemon's RPC did not answer in {} s\n{}",
            RPC_READY.as_secs(),
            self.evidence()
        );
    }

    /// Wait until `line` is a whole log line, or the deadline passes.
    /// The announcement is queued; the RPC being up does not mean the
    /// writer has reached the file yet.
    fn wait_for_line(&mut self, line: &str) -> bool {
        let deadline = Instant::now() + LINE_ON_DISK;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                panic!(
                    "the daemon ended while the log was unread: {status}\n{}",
                    self.evidence()
                );
            }
            if self.log().lines().any(|entry| entry == line) {
                return true;
            }
            std::thread::sleep(POLL);
        }
        false
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("shekyld.log")).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("stderr")).unwrap_or_default()
    }

    fn evidence(&self) -> String {
        format!("log:\n{}\nstderr:\n{}", self.log(), self.stderr())
    }

    /// Send `signal` (`INT` or `TERM`) with `kill`.
    fn send(&self, signal: &str) {
        let pid = self.child.id().to_string();
        let mut kill = Command::new("kill");
        kill.args([&format!("-{signal}"), pid.as_str()]);
        let status = shekyl_spawn::spawn_lock::status(&mut kill).expect("kill starts");
        assert!(status.success(), "kill -{signal} {pid}: {status}");
    }

    /// The exit status, if the daemon ends within `within`.
    fn ended_within(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                return Some(status);
            }
            std::thread::sleep(POLL);
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

/// **`SIGINT` is `SIG_IGN` at start:** the node announces that Ctrl-C is off
/// and how to stop it, a `SIGINT` does not stop it, and `SIGTERM` stops it
/// cleanly. Red edits: open the `SIGINT` stream whatever the disposition
/// was (the node stops on `SIGINT`), or drop the announcement (no line).
#[test]
fn an_interrupt_the_parent_ignored_does_not_stop_the_node() {
    const NAME: &str = "an_interrupt_the_parent_ignored_does_not_stop_the_node";
    run_child_if_requested();
    let mut node = Node::start(NAME, true);
    assert!(
        node.wait_for_line(IGNORED_LINE),
        "the ignored-SIGINT line was not in the log within {} s\n{}",
        LINE_ON_DISK.as_secs(),
        node.evidence()
    );
    node.send("INT");
    assert_eq!(
        node.ended_within(IGNORED_HOLDS),
        None,
        "SIGINT stopped a node whose SIGINT was SIG_IGN\n{}",
        node.evidence()
    );
    node.send("TERM");
    let status = node
        .ended_within(STOP_ARRIVES)
        .unwrap_or_else(|| panic!("SIGTERM did not stop the node\n{}", node.evidence()));
    assert!(status.success(), "{status}\n{}", node.evidence());
    let log = node.log();
    assert!(
        log.lines().any(|line| line == "stop requested by SIGTERM"),
        "{}",
        node.evidence()
    );
}

/// **`SIGINT` is `SIG_DFL` at start:** `SIGINT` stops the node cleanly, and
/// the ignored-SIGINT line is absent from the flushed log. Red edit: never
/// open the `SIGINT` stream (the node does not stop), or announce the line
/// on this arm.
#[test]
fn an_interrupt_with_no_request_stops_the_node() {
    const NAME: &str = "an_interrupt_with_no_request_stops_the_node";
    run_child_if_requested();
    let mut node = Node::start(NAME, false);
    node.send("INT");
    let status = node
        .ended_within(STOP_ARRIVES)
        .unwrap_or_else(|| panic!("SIGINT did not stop the node\n{}", node.evidence()));
    assert!(status.success(), "{status}\n{}", node.evidence());
    let log = node.log();
    assert!(
        log.lines().any(|line| line == "stop requested by SIGINT"),
        "{}",
        node.evidence()
    );
    assert!(
        !log.lines().any(|line| line == IGNORED_LINE),
        "a default SIGINT announced that Ctrl-C was off\n{}",
        node.evidence()
    );
}
