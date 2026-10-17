// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon carries its SOCKS username and password on the dial
//! (`DAEMON_CONFIG_CUTOVER.md` DC-Q7; Rick, 2026-10-17): a live regtest
//! `shekyld` dials through a SOCKS5 proxy that takes only RFC 1929
//! username/password, presents the configured pair, and tunnels its
//! connection through it. A pair the proxy refuses is named to the
//! operator by the rows that fix it, and the daemon keeps running.
//!
//! The pair is file-only, so each test writes the daemon's configuration
//! file, readable by its owner alone. Unix only: the file's mode is the
//! POSIX check. Every test here is `#[ignore]`d and needs `SHEKYLD_BIN`.

#![cfg(unix)]

mod live_daemon;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use live_daemon::{free_port, rpc_ok};

const USERNAME: &[u8] = b"shekyl-operator";
const PASSWORD: &[u8] = b"proxy-password";
/// How long a test waits for the dialer to reach the proxy.
const DIAL_WITHIN: Duration = Duration::from_secs(90);
/// A valid v3 onion (`shekyl-onion-v3`'s fixture); the proxy answers for it.
const ONION: &str = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";

/// Where a CONNECT asked to go.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Destination {
    Ip(SocketAddr),
    Name(String, u16),
}

/// What one connection to the proxy did.
#[derive(Clone, Debug, Default)]
struct Seen {
    /// The methods the greeting offered.
    methods: Vec<u8>,
    /// The username and password presented.
    pair: Option<(Vec<u8>, Vec<u8>)>,
    /// The CONNECT's destination, when the exchange got that far.
    destination: Option<Destination>,
    /// Bytes the daemon sent through the tunnel.
    tunneled: usize,
}

/// A SOCKS5 proxy that offers only username/password and accepts the
/// pair when `accept` holds. Each connection is recorded.
struct AuthProxy {
    at: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl AuthProxy {
    fn start(accept: bool) -> Self {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind the proxy");
        let at = listener.local_addr().expect("proxy address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let record = Arc::clone(&record);
                std::thread::spawn(move || {
                    let mut seen = Seen::default();
                    drop(serve(stream, accept, &mut seen));
                    record.lock().expect("record").push(seen);
                });
            }
        });
        Self { at, seen }
    }

    /// The first connection that `done` says is complete, within
    /// [`DIAL_WITHIN`].
    fn wait_for(&self, done: impl Fn(&Seen) -> bool) -> Seen {
        let deadline = Instant::now() + DIAL_WITHIN;
        loop {
            if let Some(found) = self.seen.lock().expect("record").iter().find(|s| done(s)) {
                return found.clone();
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not reach the proxy within {DIAL_WITHIN:?}: {:?}",
                self.seen.lock().expect("record")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// One RFC 1928 / RFC 1929 exchange, then the tunnel's first bytes.
fn serve(mut stream: TcpStream, accept: bool, seen: &mut Seen) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods)?;
    seen.methods.clone_from(&methods);
    if head[0] != 5 || !methods.contains(&2) {
        stream.write_all(&[5, 0xFF])?;
        return Ok(());
    }
    stream.write_all(&[5, 2])?;
    let mut version = [0u8; 2];
    stream.read_exact(&mut version)?;
    let mut username = vec![0u8; usize::from(version[1])];
    stream.read_exact(&mut username)?;
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen)?;
    let mut password = vec![0u8; usize::from(plen[0])];
    stream.read_exact(&mut password)?;
    let matched = username == USERNAME && password == PASSWORD;
    seen.pair = Some((username, password));
    if !(accept && matched) {
        stream.write_all(&[1, 1])?;
        return Ok(());
    }
    stream.write_all(&[1, 0])?;
    let mut request = [0u8; 4];
    stream.read_exact(&mut request)?;
    let destination = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip)?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port)?;
            Destination::Ip(SocketAddr::from((ip, u16::from_be_bytes(port))))
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name)?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port)?;
            Destination::Name(
                String::from_utf8_lossy(&name).into_owned(),
                u16::from_be_bytes(port),
            )
        }
        other => panic!("an address type this test does not expect: {other}"),
    };
    seen.destination = Some(destination);
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let mut first = [0u8; 64];
    seen.tunneled = stream.read(&mut first)?;
    Ok(())
}

/// A regtest daemon started with `args` and the configuration file `toml`.
struct Daemon {
    child: Child,
    data_dir: PathBuf,
    rpc_port: u16,
}

impl Daemon {
    fn start(test: &str, args: &[String], toml: &str) -> Self {
        let bin = PathBuf::from(std::env::var_os("SHEKYLD_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYLD_BIN not set. Build the daemon and run e.g. \
                 SHEKYLD_BIN=/abs/path/build/bin/shekyld cargo test -p shekyl-levin \
                 --test socks_credentials -- --ignored --nocapture ({test})"
            )
        }));
        let rpc_port = free_port();
        let data_dir = owner_only_base().join(format!("shekyl-{test}-{rpc_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        // Owner-only: the daemon refuses a configuration file whose directory
        // its group or others can write.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&data_dir)
            .expect("create data dir");
        let config = data_dir.join("shekyld.toml");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)
            .and_then(|mut file| file.write_all(toml.as_bytes()))
            .expect("the configuration file, owner-only");
        let log = std::fs::File::create(data_dir.join("daemon.log")).expect("daemon log");
        let child = Command::new(&bin)
            .args([
                "--network",
                "regtest",
                "--dev-difficulty",
                "1",
                "--rpc-admin-listen",
                &format!("127.0.0.1:{rpc_port}"),
                "--data-dir",
                data_dir.to_str().expect("utf8 data dir"),
                "--log-file",
                &data_dir.join("shekyld.log").display().to_string(),
                "--log-level",
                "warn",
                "--config-file",
                config.to_str().expect("utf8 config path"),
            ])
            .args(args)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));
        let mut daemon = Self {
            child,
            data_dir,
            rpc_port,
        };
        daemon.await_rpc();
        daemon
    }

    fn await_rpc(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("daemon exited early ({status}):\n{}", self.output());
            }
            if rpc_ok(self.rpc_port) {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("daemon never answered its RPC:\n{}", self.output());
    }

    fn output(&self) -> String {
        std::fs::read_to_string(self.data_dir.join("daemon.log")).unwrap_or_default()
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(self.data_dir.join("shekyld.log")).unwrap_or_default()
    }

    fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

/// A directory whose every ancestor only root or this account can write:
/// the daemon refuses a configuration file anywhere else (`file.rs`; a
/// sticky world-writable `/tmp` included). The runtime directory, then the
/// home directory.
fn owner_only_base() -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    let probe = std::env::temp_dir().join(format!("shekyl-uid-probe-{}", std::process::id()));
    std::fs::write(&probe, b"").expect("the uid probe");
    let me = std::fs::metadata(&probe).expect("the uid probe").uid();
    drop(std::fs::remove_file(&probe));
    let safe = |dir: &std::path::Path| {
        dir.ancestors().all(|a| {
            std::fs::metadata(a)
                .map(|m| (m.uid() == 0 || m.uid() == me) && m.mode() & 0o022 == 0)
                .unwrap_or(false)
        })
    };
    ["XDG_RUNTIME_DIR", "HOME"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .find(|dir| dir.is_absolute() && safe(dir))
        .expect("neither $XDG_RUNTIME_DIR nor $HOME is writable by root and this account alone")
}

fn pair_toml(option: &str) -> String {
    format!(
        "{option}-username = \"{}\"\n{option}-password = \"{}\"\n",
        String::from_utf8_lossy(USERNAME),
        String::from_utf8_lossy(PASSWORD)
    )
}

fn clearnet_args(proxy: SocketAddr, peer: SocketAddr) -> Vec<String> {
    vec![
        "--tor".into(),
        "off".into(),
        "--clearnet-listen".into(),
        format!("127.0.0.1:{}", free_port()),
        "--clearnet-socks".into(),
        proxy.to_string(),
        "--p2p-closed-peer".into(),
        peer.to_string(),
    ]
}

/// The clearnet dial offers only username/password, presents the
/// configured pair, and tunnels to the peer through the proxy.
#[test]
#[ignore = "live: requires SHEKYLD_BIN; spawns a daemon behind a SOCKS5 proxy"]
fn the_clearnet_dial_presents_its_pair_and_tunnels_through_the_proxy() {
    let proxy = AuthProxy::start(true);
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let _daemon = Daemon::start(
        "socks-clearnet",
        &clearnet_args(proxy.at, peer),
        &pair_toml("clearnet-socks"),
    );
    let seen = proxy.wait_for(|s| s.tunneled > 0);
    assert_eq!(seen.methods, [2], "username/password only, never no-auth");
    assert_eq!(
        seen.pair,
        Some((USERNAME.to_vec(), PASSWORD.to_vec())),
        "the configured pair"
    );
    assert_eq!(seen.destination, Some(Destination::Ip(peer)));
}

/// A pair the proxy refuses is named by the rows that fix it, and the
/// daemon keeps running (rule 82).
#[test]
#[ignore = "live: requires SHEKYLD_BIN; spawns a daemon behind a SOCKS5 proxy"]
fn a_refused_pair_names_its_rows_and_the_daemon_keeps_running() {
    const NAMED: &str = "refused this node's username and password";
    let proxy = AuthProxy::start(false);
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let mut daemon = Daemon::start(
        "socks-refused",
        &clearnet_args(proxy.at, peer),
        &pair_toml("clearnet-socks"),
    );
    let seen = proxy.wait_for(|s| s.pair.is_some());
    assert_eq!(seen.destination, None, "no CONNECT after a refused pair");
    let deadline = Instant::now() + DIAL_WITHIN;
    while !daemon.log_text().contains(NAMED) {
        assert!(
            Instant::now() < deadline,
            "the refusal was not named in the log:\n{}",
            daemon.log_text()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let log = daemon.log_text();
    let line = log.lines().find(|l| l.contains(NAMED)).expect("the line");
    assert!(
        line.contains("`clearnet-socks-username` and `clearnet-socks-password`"),
        "{line}"
    );
    assert!(
        !log.contains(&String::from_utf8_lossy(PASSWORD).into_owned()),
        "the password never reaches the log"
    );
    assert!(daemon.running(), "a refused pair does not stop the daemon");
}

/// The operator's Tor: the onion dial presents the pair to the operator's
/// SOCKS port and asks it for the onion by name.
#[test]
#[ignore = "live: requires SHEKYLD_BIN; spawns a daemon behind a SOCKS5 proxy"]
fn the_operator_tor_dial_presents_its_pair() {
    let proxy = AuthProxy::start(true);
    let _daemon = Daemon::start(
        "socks-tor",
        &[
            "--clearnet".into(),
            "off".into(),
            "--tor".into(),
            "operator".into(),
            "--tor-socks".into(),
            proxy.at.to_string(),
            "--p2p-closed-peer".into(),
            format!("{ONION}:18080"),
        ],
        &pair_toml("tor-socks"),
    );
    let seen = proxy.wait_for(|s| s.destination.is_some());
    assert_eq!(seen.methods, [2], "username/password only");
    assert_eq!(seen.pair, Some((USERNAME.to_vec(), PASSWORD.to_vec())));
    assert_eq!(
        seen.destination,
        Some(Destination::Name(ONION.to_owned(), 18080)),
        "the onion, by name, through the operator's proxy"
    );
}
