// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's socket on a running daemon (`docs/design/RPC_CHANNEL.md`
//! RT-15, RT-16, §7.1).
//!
//! A daemon run as its user serves that user on a socket in a private
//! directory, at the host administrator's authority. Its life is the
//! socket's: when the socket goes, the daemon stops cleanly. A clean stop
//! removes the socket. A second daemon of the same account, network and
//! instance refuses to start while the first answers.
//!
//! Each test re-executes this binary as the daemon child, which runs
//! `shekyl_daemon::run::main` with a private `--rpc-socket-dir`, as every
//! harness does.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use shekyl_daemon_config::Platform;

/// The child's working directory. Set only when this binary is a child.
const CHILD_DIR: &str = "SHEKYL_TEST_OWNER_SOCKET_CHILD_DIR";
/// The child's data directory's name under its working directory, so a
/// second daemon can share the socket directory and not the data.
const CHILD_DATA: &str = "SHEKYL_TEST_OWNER_SOCKET_CHILD_DATA";

/// How long the owner's socket may take to answer.
const READY: Duration = Duration::from_secs(120);
/// How long a stop may take.
const STOP_ARRIVES: Duration = Duration::from_secs(60);
/// Spacing of the polls.
const POLL: Duration = Duration::from_millis(50);

/// Run the daemon and exit with its status when this process is a child.
fn run_child_if_requested() {
    let (Some(dir), Some(data)) = (std::env::var_os(CHILD_DIR), std::env::var_os(CHILD_DATA))
    else {
        return;
    };
    let dir = PathBuf::from(dir);
    let data_dir = dir.join(data);
    let log_file = data_dir.join("shekyld.log");
    let socket_dir = dir.join("socket");
    let args: Vec<std::ffi::OsString> = [
        "shekyld",
        "--network",
        "regtest",
        "--clearnet",
        "off",
        "--tor",
        "off",
        "--rpc-admin-listen",
        "none",
        "--rpc-socket-dir",
        socket_dir.to_str().expect("a UTF-8 path"),
        "--data-dir",
        data_dir.to_str().expect("a UTF-8 path"),
        "--log-file",
        log_file.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let status = shekyl_daemon::run::main(
        &args,
        &Platform {
            home: Some(dir),
            program_data: None,
            session_dir: None,
        },
    );
    std::process::exit(status);
}

/// A daemon child and its directory.
struct Node {
    child: Child,
    dir: PathBuf,
    data: &'static str,
}

/// A working directory with its private socket directory, as a harness
/// makes it.
fn workdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.path().join("socket"))
        .expect("the socket directory");
    dir
}

impl Node {
    /// Start this test binary again as `test_name`, the daemon child, in
    /// `dir` with the data directory `data`.
    fn spawn(test_name: &str, dir: &Path, data: &'static str) -> Self {
        std::fs::create_dir_all(dir.join(data)).expect("the data directory");
        let stderr = File::create(dir.join(format!("{data}.stderr"))).expect("the stderr file");
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_DIR, dir)
            .env(CHILD_DATA, data)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        let child = shekyl_tor_control_client::spawn_lock::with(|| command.spawn())
            .expect("the daemon child starts");
        Self {
            child,
            dir: dir.to_path_buf(),
            data,
        }
    }

    /// The one socket in the socket directory, once the daemon answers on
    /// it with a JSON-RPC reply.
    fn wait_for_owner(&mut self) -> PathBuf {
        let deadline = Instant::now() + READY;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                panic!(
                    "the daemon ended before its owner's socket answered: {status}\n{}",
                    self.evidence()
                );
            }
            if let Some(path) = self.socket() {
                if let Some(reply) = post(&path, "version") {
                    assert!(reply.contains("\"result\""), "{reply}");
                    return path;
                }
            }
            std::thread::sleep(POLL);
        }
        panic!(
            "the owner's socket did not answer in {} s\n{}",
            READY.as_secs(),
            self.evidence()
        );
    }

    fn socket(&self) -> Option<PathBuf> {
        std::fs::read_dir(self.dir.join("socket"))
            .ok()?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("shekyl-") && n.ends_with(".sock"))
            })
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join(self.data).join("shekyld.log")).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join(format!("{}.stderr", self.data))).unwrap_or_default()
    }

    fn evidence(&self) -> String {
        format!("log:\n{}\nstderr:\n{}", self.log(), self.stderr())
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

    fn terminate(&self) {
        let pid = self.child.id().to_string();
        let mut kill = Command::new("kill");
        kill.args(["-TERM", pid.as_str()]);
        let status = shekyl_tor_control_client::spawn_lock::status(&mut kill).expect("kill starts");
        assert!(status.success(), "kill -TERM {pid}: {status}");
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

/// One JSON-RPC call over the owner's socket; the reply's body, or `None`
/// while nothing serves it.
fn post(path: &Path, method: &str) -> Option<String> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
    let request = format!(
        "POST /json_rpc HTTP/1.1\r\nHost: owner\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).ok()?;
    let (head, body) = reply.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 200").then(|| body.to_owned())
}

/// **The owner is the host's administrator, and the daemon's life is its
/// socket's.** Over the socket, a host-only read is answered, not refused
/// as host-only. Removing the socket stops the daemon cleanly (exit 0),
/// and it says why. Red edit: start the RPC with no owner's socket, and
/// nothing answers in the socket directory.
#[test]
fn removing_the_owners_socket_stops_the_daemon_cleanly() {
    const NAME: &str = "removing_the_owners_socket_stops_the_daemon_cleanly";
    run_child_if_requested();
    let dir = workdir();
    let mut node = Node::spawn(NAME, dir.path(), "data");
    let socket = node.wait_for_owner();
    let host_only = post(&socket, "relay_stats").expect("a reply");
    assert!(
        !host_only.contains("grant.host-only"),
        "the owner was refused a host-only read: {host_only}"
    );
    std::fs::remove_file(&socket).expect("remove the socket");
    let status = node
        .ended_within(STOP_ARRIVES)
        .unwrap_or_else(|| panic!("the daemon kept running\n{}", node.evidence()));
    assert!(status.success(), "{status}\n{}", node.evidence());
    assert!(
        node.log()
            .contains("stop requested by the owner's socket going"),
        "{}",
        node.evidence()
    );
}

/// **A clean stop removes the socket, and a second daemon of the same
/// account, network and instance is refused while the first answers.** The
/// second has its own data directory, so it is the socket that refuses it,
/// not the data directory's lock. Red edit: keep the rendezvous on stop,
/// and the socket is still there after the first daemon exits.
#[test]
fn a_second_daemon_is_refused_and_a_clean_stop_removes_the_socket() {
    const NAME: &str = "a_second_daemon_is_refused_and_a_clean_stop_removes_the_socket";
    run_child_if_requested();
    let dir = workdir();
    let mut first = Node::spawn(NAME, dir.path(), "first");
    let socket = first.wait_for_owner();

    let mut second = Node::spawn(NAME, dir.path(), "second");
    let status = second
        .ended_within(STOP_ARRIVES)
        .unwrap_or_else(|| panic!("the second daemon kept running\n{}", second.evidence()));
    assert_eq!(status.code(), Some(2), "{}", second.evidence());
    assert!(
        second.stderr().contains("config.socket.running"),
        "{}",
        second.evidence()
    );
    assert!(socket.exists(), "the first daemon's socket was not touched");

    first.terminate();
    let status = first
        .ended_within(STOP_ARRIVES)
        .unwrap_or_else(|| panic!("the daemon kept running\n{}", first.evidence()));
    assert!(status.success(), "{status}\n{}", first.evidence());
    assert!(!socket.exists(), "a clean stop removes the owner's socket");
}
