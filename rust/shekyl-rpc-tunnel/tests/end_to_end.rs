// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-W11 end to end, against a real daemon (Rick, 2026-11-15): enroll,
//! dial, call, revoke, and a refused call after the revocation.
//!
//! A daemon runs in a child of this test binary, as `shekyl-daemon`'s own
//! tests run one, listening on the channel on loopback, with its owner's
//! leg in a private socket directory. The owner reads the node's bundle
//! (`rpc bundle show`) and enrolls an administrator's key with an `enroll`
//! ceiling; the administrator then runs `shekyl-cli`'s enrollment words (the
//! library) as a CLI on another host does: the node's bundle in a file and
//! its key file. The tunnel is this crate's binary. A consumer is a plain
//! HTTP client of the tunnel's loopback listener.
//!
//! The daemon is not a service: a service never runs as root, and CI runs
//! its tests as root. A service's console leg, the other way an
//! administrator reaches the node, is `shekyl-daemon`'s `service_rendezvous`
//! test, through the same initiator.
#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use shekyl_cli::enroll::{self, EnrollOptions, Remote};
use shekyl_cli::resolve::Enroll;
use shekyl_daemon_config::{Network, Platform};
use shekyl_rpc_client::wire;
use shekyl_rpc_rendezvous::Instance;
use shekyl_rpc_transport::channel::Leg;
use shekyl_rpc_transport::local::LocalTarget;
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::rpc::{CeilingWord, ClientCeiling};

const CHILD_DIR: &str = "SHEKYL_TEST_TUNNEL_CHILD_DIR";
const CHILD_LISTEN: &str = "SHEKYL_TEST_TUNNEL_CHILD_LISTEN";
const READY: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(50);

fn run_child_if_requested() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let listen = std::env::var(CHILD_LISTEN).expect("the channel listener");
    let data_dir = dir.join("data");
    let log = data_dir.join("shekyld.log");
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
        "--rpc-listen",
        &listen,
        "--data-dir",
        data_dir.to_str().expect("a UTF-8 path"),
        "--rpc-socket-dir",
        socket_dir(&dir).to_str().expect("a UTF-8 path"),
        "--log-file",
        log.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let status = shekyl_daemon::run::main(
        &args,
        &Platform {
            home: Some(dir),
            service_parent: None,
            session_dir: None,
            service_rendezvous: None,
        },
    );
    std::process::exit(status);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
        .port()
}

/// The private socket directory a harness names (`rpc-socket-dir`). Named
/// `s`: under macOS's per-user temporary directory a longer name leaves the
/// socket's path over the 104-byte limit.
fn socket_dir(dir: &Path) -> PathBuf {
    dir.join("s")
}

/// The test's directory and its socket directory, each 0700.
fn workdir() -> tempfile::TempDir {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("the test's directory");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(socket_dir(dir.path()))
        .expect("the socket directory");
    dir
}

/// A child process, killed if the test ends first.
struct Running {
    child: Child,
    what: &'static str,
    stderr: PathBuf,
}

impl Running {
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

fn spawn(what: &'static str, mut command: Command, stderr: PathBuf) -> Running {
    command
        .stdin(Stdio::null())
        .stderr(Stdio::from(File::create(&stderr).expect("the stderr file")));
    let child = shekyl_spawn::spawn_lock::with(|| command.spawn()).expect(what);
    Running {
        child,
        what,
        stderr,
    }
}

/// The owner's leg, once the daemon answers on it, and the node's bundle as
/// `rpc bundle show` prints it.
fn wait_for_owner(daemon: &mut Running, dir: &Path) -> (LocalTarget, String) {
    let owner = LocalTarget::test_override(
        Network::Regtest,
        &Instance::Default,
        Some(&socket_dir(dir)),
        None,
    );
    let deadline = Instant::now() + READY;
    while Instant::now() < deadline {
        if let Some(status) = daemon.child.try_wait().expect("the child") {
            panic!("the {} ended: {status}\n{}", daemon.what, daemon.stderr());
        }
        if let Ok(bundle) = owner.call::<wire::RpcBundleShow>(&NoParams) {
            let text = shekyl_rpc_transport::channel::bundle_text(&bundle.bundle.0);
            return (owner, text);
        }
        std::thread::sleep(POLL);
    }
    panic!("the owner's leg never answered\n{}", daemon.stderr());
}

/// One JSON-RPC call through the tunnel's loopback listener, as a plain
/// HTTP/1.1 consumer that closes after each request: the status and body.
fn consumer_call(listen: &str, method: &str) -> (u16, String) {
    try_consumer_call(listen, method).expect("the tunnel listens")
}

fn try_consumer_call(listen: &str, method: &str) -> std::io::Result<(u16, String)> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#);
    let mut tcp = std::net::TcpStream::connect(listen)?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    write!(
        tcp,
        "POST /json_rpc HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut reply = String::new();
    tcp.read_to_string(&mut reply)?;
    let status = reply
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = reply
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    Ok((status, body))
}

/// **Enroll, dial, call, revoke, and a refused call after the revocation**
/// (RT-W11, against a real daemon). An administrator the owner enrolled
/// enrolls the tunnel's key with `rpc client add` over the channel; the tunnel reports its grant and
/// serves a consumer's call; `rpc client remove` revokes it; the next call
/// is refused, the tunnel exits naming the revocation, and `rpc client
/// list` no longer lists it. A second tunnel ends cleanly on SIGTERM, as a
/// service manager stops one. Red edits: drop `changing.close` in
/// `Channel::client_remove`, and the tunnel keeps being served after the
/// revocation; make the pool report `NotEnrolled` after a held session
/// (`Pool::open_session`), and the refusal does not name the revocation
/// (the tunnel ends on it, and the next call finds no listener); drop the
/// `tracing::error!` in the tunnel's `main`, and its log does not name the
/// revocation. The
/// submission's padding is `shekyl-daemon-rpc`'s submission test.
#[test]
fn enroll_dial_call_revoke_and_a_refused_call_after() {
    const NAME: &str = "enroll_dial_call_revoke_and_a_refused_call_after";
    run_child_if_requested();
    let dir = workdir();
    let channel_listen = format!("127.0.0.1:{}", free_port());
    let mut daemon = {
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD_DIR, dir.path())
            .env(CHILD_LISTEN, &channel_listen)
            .stdout(Stdio::null());
        spawn("daemon", command, dir.path().join("daemon.stderr"))
    };
    let (owner, bundle) = wait_for_owner(&mut daemon, dir.path());
    let bundle_file = dir.path().join("node.bundle");
    std::fs::write(&bundle_file, bundle).unwrap();

    // The CLI as an administrator on another host: the bundle in a file,
    // its own key (`rpc key create`), which the owner enrolls to enroll.
    let cli = EnrollOptions {
        network: Network::Regtest,
        remote: Some(Remote {
            leg: Leg::ip(channel_listen.parse().expect("the channel listener"), None),
            bundle_file: bundle_file.clone(),
        }),
        key_file: Some(dir.path().join("admin.key")),
    };
    let admin = enroll::run(&cli, &Enroll::KeyCreate).expect("rpc key create");
    owner
        .call::<wire::RpcClientAdd>(&ClientCeiling {
            fingerprint: HashHex::from_hex(&admin).expect("a fingerprint"),
            ceiling: vec![CeilingWord::Enroll, CeilingWord::View],
        })
        .expect("the owner enrolls the administrator");

    // The tunnel's key.
    let tunnel = env!("CARGO_BIN_EXE_shekyl-rpc-tunnel");
    let key_file = dir.path().join("tunnel.key");
    let made = Command::new(tunnel)
        .args(["--network", "regtest", "--rpc-key-create", "--rpc-key-file"])
        .arg(&key_file)
        .output()
        .expect("rpc-key-create");
    assert!(made.status.success(), "{made:?}");
    let fingerprint = String::from_utf8(made.stdout).unwrap().trim().to_owned();
    assert_eq!(fingerprint.len(), 64, "{fingerprint}");

    // Enroll.
    enroll::run(
        &cli,
        &Enroll::ClientAdd {
            fingerprint: fingerprint.clone(),
            ceiling: vec![CeilingWord::View],
        },
    )
    .expect("rpc client add");
    let listed = enroll::run(&cli, &Enroll::ClientList).expect("rpc client list");
    assert!(listed.contains(&fingerprint), "{listed}");

    // Dial: the tunnel reports its grant and listens.
    let listen = format!("127.0.0.1:{}", free_port());
    let mut tunnel_run = {
        let mut command = Command::new(tunnel);
        command
            .args(["--network", "regtest", "--daemon-endpoint"])
            .arg(&channel_listen)
            .arg("--daemon-bundle-file")
            .arg(&bundle_file)
            .arg("--rpc-key-file")
            .arg(&key_file)
            .args(["--listen", &listen, "--log-file"])
            .arg(dir.path().join("tunnel.log"))
            .stdout(Stdio::piped());
        spawn("tunnel", command, dir.path().join("tunnel.stderr"))
    };
    let mut stdout = tunnel_run.child.stdout.take().expect("stdout");
    let mut said = String::new();
    let deadline = Instant::now() + READY;
    while !said.contains("Listening on") {
        assert!(Instant::now() < deadline, "{said}\n{}", tunnel_run.stderr());
        let mut buf = [0u8; 256];
        let n = stdout.read(&mut buf).expect("the tunnel's output");
        assert!(n > 0, "the tunnel ended: {said}\n{}", tunnel_run.stderr());
        said.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    let view: Vec<&str> = shekyl_rpc_grants::Preset::View
        .grants()
        .iter()
        .map(shekyl_rpc_grants::Grant::name)
        .collect();
    let view = view.join(", ");
    assert!(
        said.contains(&format!(
            "Connected with {view}; this client is enrolled for at most {view}."
        )),
        "the tunnel reports the grant it received and its ceiling: {said}"
    );

    // Call.
    let (status, body) = consumer_call(&listen, "version");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"result\""), "{body}");

    // A service manager's stop: a second tunnel, as the unit and the rc.d
    // script stop one, ends cleanly on SIGTERM sent the moment it says it
    // listens, and removes its socket.
    let second_socket = socket_dir(dir.path()).join("t2.sock");
    let mut second = {
        let mut command = Command::new(tunnel);
        command
            .args(["--network", "regtest", "--daemon-endpoint"])
            .arg(&channel_listen)
            .arg("--daemon-bundle-file")
            .arg(&bundle_file)
            .arg("--rpc-key-file")
            .arg(&key_file)
            .arg("--listen-socket-file")
            .arg(&second_socket)
            .arg("--log-file")
            .arg(dir.path().join("tunnel2.log"))
            .stdout(Stdio::piped());
        spawn("second tunnel", command, dir.path().join("tunnel2.stderr"))
    };
    let mut out = second.child.stdout.take().expect("stdout");
    let mut said2 = String::new();
    while !said2.contains("Listening on") {
        let mut buf = [0u8; 256];
        let n = out.read(&mut buf).expect("the second tunnel's output");
        assert!(
            n > 0,
            "the second tunnel ended: {said2}\n{}",
            second.stderr()
        );
        said2.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    let killed = Command::new("kill")
        .args(["-TERM", &second.child.id().to_string()])
        .status()
        .expect("kill");
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    let stopped = loop {
        if let Some(status) = second.child.try_wait().expect("the second tunnel") {
            break status;
        }
        assert!(Instant::now() < deadline, "SIGTERM did not stop the tunnel");
        std::thread::sleep(POLL);
    };
    assert!(stopped.success(), "a SIGTERM is a clean stop: {stopped}");
    assert!(
        !second_socket.exists(),
        "a clean stop removes the socket {}",
        second_socket.display()
    );

    // Revoke.
    enroll::run(
        &cli,
        &Enroll::ClientRemove {
            fingerprint: fingerprint.clone(),
        },
    )
    .expect("rpc client remove");

    // The revocation ends the tunnel. A call that meets it is answered
    // with the node's reason. A tunnel with no further call ends the same
    // way, from the pool's keeper, once the daemon has closed the session.
    let deadline = Instant::now() + READY;
    let refused = loop {
        if tunnel_run.child.try_wait().expect("the tunnel").is_some() {
            break None;
        }
        match try_consumer_call(&listen, "version") {
            Ok((status, body)) if status == 502 && body.contains("revoked") => break Some(body),
            Ok((status, body)) => {
                assert!(
                    Instant::now() < deadline,
                    "the tunnel kept being served after the revocation: {status} {body}"
                );
            }
            Err(_) => {
                assert!(
                    Instant::now() < deadline,
                    "the tunnel neither answered the revocation nor ended"
                );
            }
        }
        std::thread::sleep(POLL);
    };
    if let Some(refused) = refused {
        assert_eq!(refused, "The node revoked this client's enrollment.");
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let ended = loop {
        if let Some(status) = tunnel_run.child.try_wait().expect("the tunnel") {
            break status;
        }
        assert!(Instant::now() < deadline, "the tunnel did not end");
        std::thread::sleep(POLL);
    };
    assert!(!ended.success(), "{ended}");
    assert!(
        tunnel_run
            .stderr()
            .contains("The node revoked this client's enrollment."),
        "{}",
        tunnel_run.stderr()
    );
    let log = std::fs::read_to_string(dir.path().join("tunnel.log")).unwrap_or_default();
    assert!(
        log.contains("The node revoked this client's enrollment."),
        "the tunnel's log names the revocation at its default level: {log}"
    );
    let listed = enroll::run(&cli, &Enroll::ClientList).expect("rpc client list");
    assert!(!listed.contains(&fingerprint), "{listed}");
}
