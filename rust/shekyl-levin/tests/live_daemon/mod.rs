// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A live regtest `shekyld` and a simulated inbound peer, shared by the
//! live tests of this crate (`inbound_cost_bench`, `refused_inbound`).
//! Every test here is `#[ignore]`d and needs `SHEKYLD_BIN`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_levin::{
    invoke, response, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, PortableMap,
    Received, SupportFlags, SupportFlagsRequest, SupportFlagsResponse, COMMAND_HANDSHAKE,
    COMMAND_REQUEST_SUPPORT_FLAGS,
};

pub struct Daemon {
    pub child: Child,
    pub data_dir: PathBuf,
    pub p2p_port: u16,
    pub rpc_port: u16,
}

impl Daemon {
    /// Spawn the daemon on a fresh data directory, clearnet listener and
    /// admin listener on loopback, Tor off, and wait until it answers.
    pub fn start(test: &str) -> Self {
        Self::start_with(test, None, "warn")
    }

    /// [`Self::start`], with the child's soft descriptor limit lowered to
    /// `descriptor_limit` (Unix: `ulimit -n` in the shell that execs the
    /// daemon, so nothing but the child is limited) and the log level given.
    pub fn start_with(test: &str, descriptor_limit: Option<u64>, log_level: &str) -> Self {
        let bin = PathBuf::from(std::env::var_os("SHEKYLD_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYLD_BIN not set. Build the daemon and run e.g. \
                 SHEKYLD_BIN=/abs/path/build/bin/shekyld cargo test -p shekyl-levin \
                 --test {test} -- --ignored --nocapture"
            )
        }));
        let rpc_port = free_port();
        let p2p_port = free_port();
        let data_dir = std::env::temp_dir().join(format!("shekyl-{test}-{p2p_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let log = std::fs::File::create(data_dir.join("daemon.log")).expect("daemon log");
        // Regtest has no seeds and the test names no peer, so every connection
        // counted here is INBOUND and ours; the outbound degree is a protocol
        // constant (`out-peers` is a rejected row). Regtest's default is the
        // managed Tor; `--tor off` keeps this rig clearnet-only
        // (DAEMON_CONFIG_CUTOVER.md §5.1).
        let args = [
            "--network",
            "regtest",
            "--tor",
            "off",
            "--dev-difficulty",
            "1",
            "--clearnet-listen",
            &format!("127.0.0.1:{p2p_port}"),
            "--rpc-admin-listen",
            &format!("127.0.0.1:{rpc_port}"),
            "--data-dir",
            data_dir.to_str().expect("utf8 data dir"),
            "--log-file",
            &data_dir.join("shekyld.log").display().to_string(),
            "--log-level",
            log_level,
        ];
        let mut command = match descriptor_limit {
            None => {
                let mut c = Command::new(&bin);
                c.args(args);
                c
            }
            Some(limit) => {
                // The limit is the child's alone: a shell lowers its own soft
                // limit and execs the daemon in its place.
                let mut c = Command::new("sh");
                c.arg("-c")
                    .arg("ulimit -n \"$1\" || exit 97; shift; exec \"$@\"")
                    .arg("sh")
                    .arg(limit.to_string())
                    .arg(&bin)
                    .args(args);
                c
            }
        };
        let child = command
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));
        let mut d = Self {
            child,
            data_dir,
            p2p_port,
            rpc_port,
        };
        d.await_ready();
        d
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The daemon's own log file (not the captured stdout).
    pub fn log_text(&self) -> String {
        std::fs::read_to_string(self.data_dir.join("shekyld.log")).unwrap_or_default()
    }

    fn await_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                let out =
                    std::fs::read_to_string(self.data_dir.join("daemon.log")).unwrap_or_default();
                let tail: Vec<&str> = out.lines().rev().take(20).collect();
                panic!(
                    "daemon exited early ({status}); last lines:\n{}",
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                );
            }
            if rpc_ok(self.rpc_port) && TcpStream::connect(("127.0.0.1", self.p2p_port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("daemon never became ready");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    l.local_addr().expect("addr").port()
}

pub fn rpc_ok(rpc_port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", rpc_port)) else {
        return false;
    };
    drop(s.set_read_timeout(Some(Duration::from_secs(2))));
    let body = r#"{"jsonrpc":"2.0","id":"0","method":"get_info"}"#;
    let req = format!(
        "POST /json_rpc HTTP/1.1\r\nHost: 127.0.0.1:{rpc_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).is_ok() && String::from_utf8_lossy(&buf).contains("\"height\"")
}

/// FAKECHAIN (`--network regtest`) derives its id from fakechain's genesis pin.
pub fn regtest_network_id() -> shekyl_p2p_transport::NetworkId {
    shekyl_p2p_transport::network_id_from_genesis(&shekyl_rpc_types::genesis_hash_for(
        shekyl_rpc_types::DaemonNetwork::Fakechain,
    ))
}

/// What a simulated peer's socket did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerOutcome {
    /// The handshake was answered; the peer stayed until told to stop.
    Admitted,
    /// The daemon closed the socket before answering the handshake.
    Closed,
    /// The peer could not connect, or the socket failed otherwise.
    Failed,
}

/// Completes a handshake, then services the socket until told to stop.
///
/// The servicing thread is not incidental: an unanswered `COMMAND_TIMED_SYNC`
/// gets the peer dropped, and a dropped peer costs nothing — it would measure
/// as a free connection and understate every figure in the table.
///
/// `shook` is set the moment the handshake is answered, so a caller can
/// wait for admission without joining the thread.
pub fn spawn_peer(
    p2p_port: u16,
    stop: Arc<AtomicBool>,
    shook: Arc<AtomicBool>,
) -> std::thread::JoinHandle<PeerOutcome> {
    std::thread::spawn(move || {
        let Ok(stream) = TcpStream::connect(("127.0.0.1", p2p_port)) else {
            return PeerOutcome::Failed;
        };
        drop(stream.set_read_timeout(Some(Duration::from_millis(500))));
        drop(stream.set_write_timeout(Some(Duration::from_secs(10))));
        drop(stream.set_nodelay(true));
        let mut s = stream;
        let mut reader = BucketReader::new();
        let req = HandshakeRequest {
            node_data: BasicNodeData {
                network_id: regtest_network_id(),
                support_flags: SupportFlags::ADVERTISED,
            },
            payload_data: CoreSyncData {
                current_height: 1,
                cumulative_difficulty: 0,
                cumulative_difficulty_top64: 0,
                top_id: [0u8; 32],
            },
            nonce: [0x42; 32],
        };
        let Ok(payload) = req.store() else {
            return PeerOutcome::Failed;
        };
        if s.write_all(&invoke(COMMAND_HANDSHAKE, &payload)).is_err() {
            return PeerOutcome::Failed;
        }
        let mut buf = [0u8; 8192];
        let outcome = |shaken: bool| {
            if shaken {
                PeerOutcome::Admitted
            } else {
                PeerOutcome::Closed
            }
        };
        while !stop.load(Ordering::Relaxed) {
            loop {
                match reader.next_message() {
                    Ok(Some(Received::Response { command, .. }))
                        if command == COMMAND_HANDSHAKE =>
                    {
                        shook.store(true, Ordering::SeqCst);
                    }
                    Ok(Some(Received::Request { command, payload }))
                        if command == COMMAND_REQUEST_SUPPORT_FLAGS =>
                    {
                        if SupportFlagsRequest::load(&payload).is_ok() {
                            if let Ok(b) = (SupportFlagsResponse {
                                support_flags: SupportFlags::ADVERTISED,
                            })
                            .store()
                            {
                                drop(s.write_all(&response(COMMAND_REQUEST_SUPPORT_FLAGS, &b)));
                            }
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return outcome(shook.load(Ordering::SeqCst)),
                }
            }
            match s.read(&mut buf) {
                Ok(0) => return outcome(shook.load(Ordering::SeqCst)),
                Ok(n) => {
                    if reader.feed(&buf[..n]).is_err() {
                        return outcome(shook.load(Ordering::SeqCst));
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => return outcome(shook.load(Ordering::SeqCst)),
            }
        }
        outcome(shook.load(Ordering::SeqCst))
    })
}
