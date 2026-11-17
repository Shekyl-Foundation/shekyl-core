// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's machine-wide rendezvous (`RPC_CHANNEL.md` §7.1; Rick,
//! 2026-11-14): published only when the service listens on the channel, and
//! found and dialled by a client as the record names it.
//!
//! Each test re-executes this binary as the daemon child, which runs
//! `shekyl_daemon::run::main` with `--service`. Its platform names the
//! test's own directories: the service root's parent (the data home is
//! `shekyl` in it, made 0700 here as the service manager makes it) and the
//! service's rendezvous directory. A service never runs as root, so on a
//! root runner the start's refusal is what is checked.

#![cfg(unix)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use shekyl_daemon_config::{Network, Platform};
use shekyl_rpc_channel::handshake::{StaticKeypair, StaticPublic};
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_rendezvous::ServiceRecord;
use shekyl_rpc_transport::channel::{ChannelDaemon, ChannelTarget, Leg};

const CHILD_DIR: &str = "SHEKYL_TEST_SERVICE_CHILD_DIR";
const CHILD_LISTEN: &str = "SHEKYL_TEST_SERVICE_CHILD_LISTEN";
const CHILD_ADMIN: &str = "SHEKYL_TEST_SERVICE_CHILD_ADMIN";

const READY: Duration = Duration::from_secs(120);
const STOP_ARRIVES: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(50);

fn run_child_if_requested() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let listen = std::env::var(CHILD_LISTEN).expect("the channel listener");
    let admin = std::env::var(CHILD_ADMIN).expect("the admin listener");
    let log = dir.join("shekyld.log");
    let args: Vec<std::ffi::OsString> = [
        "shekyld",
        "--network",
        "regtest",
        "--service",
        "--clearnet",
        "off",
        "--tor",
        "off",
        "--rpc-admin-listen",
        &admin,
        "--rpc-listen",
        &listen,
        "--log-file",
        log.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let status = shekyl_daemon::run::main_loading(
        &args,
        &Platform {
            home: Some(dir.clone()),
            service_parent: Some(dir.clone()),
            session_dir: None,
            service_rendezvous: Some(dir.join("run")),
        },
        shekyl_daemon_config::load_default_file_unread,
    );
    std::process::exit(status);
}

/// The test's directory, laid out as an installer lays out a service's:
/// the data home 0700, the rendezvous directory 0755.
fn workdir() -> tempfile::TempDir {
    use std::os::unix::fs::DirBuilderExt;
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.path().join("shekyl"))
        .expect("the data home");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(dir.path().join("run"))
        .expect("the rendezvous directory");
    dir
}

struct Service {
    child: Child,
    dir: PathBuf,
}

impl Service {
    fn spawn(test: &str, dir: &Path, listen: &str, admin: &str) -> Self {
        let stderr = File::create(dir.join("stderr")).expect("the stderr file");
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", test, "--nocapture"])
            .env(CHILD_DIR, dir)
            .env(CHILD_LISTEN, listen)
            .env(CHILD_ADMIN, admin)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        let child = shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the daemon child");
        Self {
            child,
            dir: dir.to_path_buf(),
        }
    }

    fn evidence(&self) -> String {
        format!(
            "stderr:\n{}\nlog:\n{}",
            std::fs::read_to_string(self.dir.join("stderr")).unwrap_or_default(),
            std::fs::read_to_string(self.dir.join("shekyld.log")).unwrap_or_default()
        )
    }

    /// The published record, once it is there whole.
    fn wait_for_record(&mut self) -> PathBuf {
        let deadline = Instant::now() + READY;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                panic!("the service ended: {status}\n{}", self.evidence());
            }
            if let Some(record) = records(&self.dir.join("run")).into_iter().next() {
                return record;
            }
            std::thread::sleep(POLL);
        }
        panic!(
            "no rendezvous in {} s\n{}",
            READY.as_secs(),
            self.evidence()
        );
    }

    /// Ask for a clean stop (`SIGTERM`) and wait for it.
    fn stop(&mut self) -> ExitStatus {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid");
        // SAFETY: signals this test's own child.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let deadline = Instant::now() + STOP_ARRIVES;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                return status;
            }
            std::thread::sleep(POLL);
        }
        panic!("the service did not stop\n{}", self.evidence());
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

/// The finished records in `dir`: `shekyl-<24 hex>`.
fn records(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .and_then(|n| n.strip_prefix("shekyl-"))
                        .is_some_and(|h| h.len() == 24 && h.bytes().all(|b| b.is_ascii_hexdigit()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A loopback port nothing listens on now: the grammar takes no port 0.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
        .port()
}

fn running_as_root() -> bool {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// On a root runner a service is refused before it starts, naming root.
fn refused_as_root(service: &mut Service) {
    let status = service.stop_or_end();
    assert_eq!(status.code(), Some(2), "{}", service.evidence());
    assert!(
        service.evidence().contains("runs as root"),
        "{}",
        service.evidence()
    );
}

impl Service {
    fn stop_or_end(&mut self) -> ExitStatus {
        let deadline = Instant::now() + STOP_ARRIVES;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                return status;
            }
            std::thread::sleep(POLL);
        }
        self.stop()
    }
}

/// One call over the channel on `leg`, as the console key read from
/// `console_file`, through RT-W11's production initiator: the reply's
/// envelope.
fn call_over_the_channel(
    leg: Leg,
    daemon: &StaticPublic,
    console_file: &Path,
    method: &str,
) -> serde_json::Value {
    let console =
        StaticKeypair::from_key_file(&std::fs::read(console_file).expect("the console key"))
            .expect("a key");
    let target = ChannelTarget::new(Network::Regtest.network_id(), daemon.clone(), console, leg);
    let channel = ChannelDaemon::connect(&target, GrantSet::ALL).expect("admitted");
    let body = serde_json::to_vec(
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}),
    )
    .unwrap();
    let reply = channel.post("json_rpc", body).expect("a reply");
    serde_json::from_slice(&reply).expect("JSON")
}

/// **A service that listens publishes its record, a client reaches it as
/// the record says, and a clean stop removes it.** The record names the
/// loopback channel address and the bundle; the console key, read from the
/// data directory, is admitted over that address, and over the console's
/// leg (RT-O37), the socket in the data directory, through RT-W11's
/// production initiator. Red edits: skip the publication in `run::start`,
/// and no record appears; bind no console leg in `run::start`, and its
/// socket is absent.
#[test]
fn a_listening_service_publishes_its_rendezvous_and_a_client_reaches_it() {
    const NAME: &str = "a_listening_service_publishes_its_rendezvous_and_a_client_reaches_it";
    run_child_if_requested();
    let dir = workdir();
    let listen = format!("127.0.0.1:{}", free_port());
    let mut service = Service::spawn(NAME, dir.path(), &listen, "none");
    if running_as_root() {
        refused_as_root(&mut service);
        return;
    }
    let record = service.wait_for_record();
    let bytes = std::fs::read(&record).expect("readable");
    let ServiceRecord {
        channel: addr,
        bundle,
    } = ServiceRecord::parse(&bytes).expect("a service record, as a client reads it");
    assert!(addr.ip().is_loopback(), "{addr}");
    let (x25519, mlkem) = bundle.split_at(32);
    let daemon = StaticPublic::from_parts(
        x25519.try_into().expect("32 bytes"),
        mlkem.try_into().expect("the encapsulation key"),
    )
    .expect("a bundle");
    let console_file = dir
        .path()
        .join("shekyl")
        .join("regtest")
        .join("rpc-console.key");
    let reply = call_over_the_channel(Leg::ip(addr, None), &daemon, &console_file, "version");
    assert!(
        reply["result"].is_object(),
        "{reply}\n{}",
        service.evidence()
    );

    // The console's leg (RT-O37): the socket in the data directory, the
    // service account's alone, serves the console key.
    let console_leg = console_file.with_file_name("rpc-console.sock");
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(&console_leg)
            .expect("the console's leg is bound")
            .permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o600);
    let reply = call_over_the_channel(
        Leg::Socket(console_leg.clone()),
        &daemon,
        &console_file,
        "version",
    );
    assert!(
        reply["result"].is_object(),
        "{reply}\n{}",
        service.evidence()
    );

    let status = service.stop();
    assert!(status.success(), "{status}\n{}", service.evidence());
    assert!(!record.exists(), "a clean stop removes the record");
    assert!(
        !console_leg.exists(),
        "a clean stop removes the console's leg"
    );
}

/// **A service that does not listen publishes nothing and says so** (Rick,
/// 2026-11-14). Red edit: publish whenever a service has a rendezvous
/// directory, and the start fails for want of a listener to name.
#[test]
fn a_service_without_rpc_listen_publishes_no_rendezvous() {
    const NAME: &str = "a_service_without_rpc_listen_publishes_no_rendezvous";
    run_child_if_requested();
    let dir = workdir();
    // A plaintext admin listener, so the test knows the service is up
    // (its stop owner installed) before it asks for the stop.
    let admin = format!("127.0.0.1:{}", free_port());
    let mut service = Service::spawn(NAME, dir.path(), "none", &admin);
    if running_as_root() {
        refused_as_root(&mut service);
        return;
    }
    let deadline = Instant::now() + READY;
    while std::net::TcpStream::connect(&admin).is_err() {
        assert!(Instant::now() < deadline, "{}", service.evidence());
        if let Some(status) = service.child.try_wait().unwrap() {
            panic!("the service ended: {status}\n{}", service.evidence());
        }
        std::thread::sleep(POLL);
    }
    assert!(
        service.evidence().contains("service rendezvous: none"),
        "{}",
        service.evidence()
    );
    assert!(records(&dir.path().join("run")).is_empty());
    let status = service.stop();
    assert!(status.success(), "{status}\n{}", service.evidence());
}
