// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live Rust Levin client ↔ C++ `shekyld` (`LV2_PORTABLE_STORAGE.md` §12 step 4).
//!
//! Proves the LV-2b maps round-trip on the real wire. Does **not** rewire
//! daemon emit/recv (that is LV-3). `#[ignore]`d: requires `SHEKYLD_BIN`.
//! Default `cargo test -p shekyl-levin` must not spawn a daemon.
//!
//! ```bash
//! SHEKYLD_BIN=/path/to/build/bin/shekyld \
//!   cargo test -p shekyl-levin --test dual_stack -- --ignored --nocapture
//! ```
//!
//! `--offline` skips the p2p bind (`net_node.inl`); this harness uses
//! `--p2p-bind-ip 127.0.0.1` plus `--out-peers 0`. `--regtest` (FAKECHAIN)
//! speaks mainnet `NETWORK_ID` (`cryptonote_config.h` `get_config`).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use shekyl_levin::{
    invoke, response, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest,
    HandshakeResponse, NetworkAddress, PortableMap, Received, SupportFlagsRequest,
    SupportFlagsResponse, TimedSyncRequest, TimedSyncResponse, COMMAND_HANDSHAKE,
    COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, DEFAULT_MAX_PACKET_SIZE,
};

/// `config::NETWORK_ID` — FAKECHAIN (`--regtest`) uses mainnet id.
const MAINNET_NETWORK_ID: [u8; 16] = [
    0x55, 0x6C, 0xA9, 0x70, 0x8F, 0xF9, 0x1F, 0x7A, 0x40, 0x69, 0xDA, 0xF3, 0xFC, 0x55, 0xBB, 0xBD,
];

/// `P2P_SUPPORT_FLAGS` (`FLUFFY_BLOCKS | ZSTD_COMPRESSION`).
const P2P_SUPPORT_FLAGS: u32 = 0x01 | 0x02;

/// C++ p2p command handlers return `1` on success (`net_node.inl`
/// `handle_handshake` / `handle_ping`). `LEVIN_OK` (0) is the protocol
/// layer, not the command-handler return.
const COMMAND_OK: i32 = 1;

struct Daemon {
    child: Child,
    data_dir: PathBuf,
    p2p_port: u16,
    rpc_port: u16,
}

impl Daemon {
    fn start() -> Self {
        let bin = match std::env::var_os("SHEKYLD_BIN") {
            Some(p) => PathBuf::from(p),
            None => panic!(
                "SHEKYLD_BIN not set. Build the daemon and run e.g. \
                 SHEKYLD_BIN=/abs/path/build/bin/shekyld cargo test -p shekyl-levin \
                 --test dual_stack -- --ignored"
            ),
        };
        let rpc_port = free_port();
        let p2p_port = free_port();
        let data_dir = std::env::temp_dir().join(format!("shekyl-lv2b-dual-{p2p_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("create data dir");

        let log = std::fs::File::create(data_dir.join("daemon.log")).expect("daemon log");
        let child = Command::new(&bin)
            .args([
                "--regtest",
                "--non-interactive",
                "--no-igd",
                "--out-peers",
                "0",
                "--fixed-difficulty",
                "1",
                "--p2p-bind-ip",
                "127.0.0.1",
                "--p2p-bind-port",
                &p2p_port.to_string(),
                "--rpc-bind-ip",
                "127.0.0.1",
                "--rpc-bind-port",
                &rpc_port.to_string(),
                "--data-dir",
                data_dir.to_str().expect("utf8 data dir"),
                "--log-level",
                "0",
            ])
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));

        let mut daemon = Self {
            child,
            data_dir,
            p2p_port,
            rpc_port,
        };
        daemon.await_ready();
        daemon
    }

    fn log_path(&self) -> PathBuf {
        self.data_dir.join("daemon.log")
    }

    fn await_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last_err = String::new();
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "daemon exited early ({status}) before RPC became ready; log tail:\n{}",
                    log_tail(&self.log_path())
                );
            }
            match get_info(self.rpc_port) {
                Ok(_) => {
                    wait_tcp(self.p2p_port, deadline);
                    return;
                }
                Err(e) => last_err = e,
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!(
            "daemon RPC never became ready (rpc {}, p2p {}) after 60s: {last_err}; log tail:\n{}",
            self.rpc_port,
            self.p2p_port,
            log_tail(&self.log_path())
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local_addr").port()
}

fn wait_tcp(p2p_port: u16, deadline: Instant) {
    let addr = SocketAddr::from(([127, 0, 0, 1], p2p_port));
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("p2p port {p2p_port} never accepted a TCP connect");
}

fn log_tail(log_path: &Path) -> String {
    std::fs::read_to_string(log_path)
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(20);
            lines[start..].join("\n")
        })
        .unwrap_or_else(|e| format!("(daemon log unreadable: {e})"))
}

struct ChainTip {
    height: u64,
    top_id: [u8; 32],
}

fn get_info(rpc_port: u16) -> Result<ChainTip, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", rpc_port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let body = r#"{"jsonrpc":"2.0","id":"0","method":"get_info"}"#;
    let req = format!(
        "POST /json_rpc HTTP/1.1\r\nHost: 127.0.0.1:{rpc_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let json = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    let height = json_u64(json, "height").ok_or_else(|| format!("no height in {json}"))?;
    let top_id =
        json_hex32(json, "top_block_hash").ok_or_else(|| format!("no top_block_hash in {json}"))?;
    Ok(ChainTip { height, top_id })
}

/// The raw `gray_list` slice of `/get_peer_list` — string matching is all
/// the pin needs, and it keeps the harness free of a JSON dependency.
fn get_gray_list(rpc_port: u16) -> Result<String, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", rpc_port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let req = format!(
        "POST /get_peer_list HTTP/1.1\r\nHost: 127.0.0.1:{rpc_port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let json = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    let start = json
        .find("\"gray_list\"")
        .ok_or_else(|| format!("no gray_list in {json}"))?;
    let end = json[start..]
        .find("\"white_list\"")
        .map(|o| start + o)
        .unwrap_or(json.len());
    Ok(json[start..end].to_owned())
}

fn json_u64(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = body.split(&needle).nth(1)?;
    rest.trim_start()
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn json_hex32(body: &str, key: &str) -> Option<[u8; 32]> {
    let needle = format!("\"{key}\":\"");
    let rest = body.split(&needle).nth(1)?;
    let hex = rest.get(..64)?;
    decode_hex32(hex)
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = from_hex(chunk[0])?;
        let lo = from_hex(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

struct Session {
    stream: TcpStream,
    reader: BucketReader,
    log_path: PathBuf,
}

impl Session {
    fn connect(p2p_port: u16, log_path: PathBuf) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", p2p_port)).unwrap_or_else(|e| {
            panic!(
                "connect p2p {p2p_port}: {e}; log tail:\n{}",
                log_tail(&log_path)
            )
        });
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .expect("write timeout");
        stream.set_nodelay(true).expect("nodelay");
        Self {
            stream,
            reader: BucketReader::new(),
            log_path,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.stream
            .write_all(bytes)
            .unwrap_or_else(|e| panic!("write: {e}; log tail:\n{}", log_tail(&self.log_path)));
    }

    fn invoke_map<T: PortableMap>(&mut self, command: u32, body: &T) -> (i32, Vec<u8>) {
        let payload = body.store().expect("store");
        self.send(&invoke(command, &payload));
        self.recv_response(command)
    }

    fn recv_response(&mut self, want: u32) -> (i32, Vec<u8>) {
        loop {
            match self.next_message() {
                Received::Response {
                    command,
                    return_code,
                    payload,
                } if command == want => return (return_code, payload),
                Received::Request { command, payload }
                    if command == COMMAND_REQUEST_SUPPORT_FLAGS =>
                {
                    SupportFlagsRequest::load(&payload).expect("support-flags request");
                    let body = SupportFlagsResponse {
                        support_flags: P2P_SUPPORT_FLAGS,
                    }
                    .store()
                    .expect("store support-flags");
                    self.send(&response(COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_OK, &body));
                }
                Received::Notification { command, .. } => {
                    // Fresh regtest may still emit cryptonote notifies; maps
                    // under test here are the invoke/response commands.
                    let _ = command;
                }
                other => panic!(
                    "unexpected {other:?} waiting for response {want}; log tail:\n{}",
                    log_tail(&self.log_path)
                ),
            }
        }
    }

    fn next_message(&mut self) -> Received {
        let mut buf = [0u8; 8192];
        loop {
            match self.reader.next_message() {
                Ok(Some(msg)) => return msg,
                Ok(None) => {}
                Err(e) => panic!(
                    "BucketReader: {e:?}; log tail:\n{}",
                    log_tail(&self.log_path)
                ),
            }
            let n = self
                .stream
                .read(&mut buf)
                .unwrap_or_else(|e| panic!("read: {e}; log tail:\n{}", log_tail(&self.log_path)));
            if n == 0 {
                panic!(
                    "peer closed while waiting for a Levin bucket; log tail:\n{}",
                    log_tail(&self.log_path)
                );
            }
            self.reader
                .feed(&buf[..n])
                .unwrap_or_else(|e| panic!("feed: {e:?}; log tail:\n{}", log_tail(&self.log_path)));
        }
    }
}

/// A fixed client nonce: the daemon must treat it as any other value — it
/// only ever matches a nonce the DAEMON itself put in flight, and this
/// client is not the daemon.
const CLIENT_NONCE: [u8; 32] = [0x42; 32];

#[ignore = "LV-2b dual-stack: requires SHEKYLD_BIN; spawns a live daemon"]
#[test]
fn rust_client_handshakes_with_shekyld() {
    let daemon = Daemon::start();
    let tip = get_info(daemon.rpc_port).expect("get_info after ready");

    let mut session = Session::connect(daemon.p2p_port, daemon.log_path());
    // The Q1 pin, live and cross-stack: advertise a LYING host half with a
    // real port. The daemon must record socket-host:advertised-port in GRAY
    // and never the advertised host — an announcement proves nothing.
    let advertised_port: u16 = 28_099;
    let req = HandshakeRequest {
        node_data: BasicNodeData {
            network_id: MAINNET_NETWORK_ID,
            address: NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(9, 9, 9, 9),
                port: advertised_port,
            },
            support_flags: P2P_SUPPORT_FLAGS,
        },
        payload_data: CoreSyncData {
            current_height: tip.height,
            cumulative_difficulty: 0,
            cumulative_difficulty_top64: 0,
            top_id: tip.top_id,
            top_version: 0,
            pruning_seed: 0,
        },
        nonce: CLIENT_NONCE,
    };
    let (rc, payload) = session.invoke_map(COMMAND_HANDSHAKE, &req);
    assert_eq!(rc, COMMAND_OK, "handshake return_code");
    let hs = HandshakeResponse::load(&payload).expect("decode handshake response");
    assert_eq!(hs.node_data.network_id, MAINNET_NETWORK_ID);
    assert_eq!(hs.payload_data.current_height, tip.height);
    assert_eq!(hs.payload_data.top_id, tip.top_id);

    session.reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);

    let gray = get_gray_list(daemon.rpc_port).expect("get_peer_list after handshake");
    assert!(
        gray.contains("127.0.0.1") && gray.contains(&advertised_port.to_string()),
        "gray list must hold socket-host + advertised port, got {gray}"
    );
    assert!(
        !gray.contains("9.9.9.9"),
        "the advertised host must never be recorded, got {gray}"
    );

    let (rc, payload) = session.invoke_map(
        COMMAND_TIMED_SYNC,
        &TimedSyncRequest {
            payload_data: req.payload_data.clone(),
        },
    );
    assert_eq!(rc, COMMAND_OK, "timed-sync return_code");
    let ts = TimedSyncResponse::load(&payload).expect("decode timed-sync");
    assert_eq!(ts.payload_data.top_id, tip.top_id);
    assert_eq!(ts.payload_data.current_height, tip.height);

    let (rc, payload) = session.invoke_map(COMMAND_REQUEST_SUPPORT_FLAGS, &SupportFlagsRequest);
    assert_eq!(rc, COMMAND_OK, "support-flags return_code");
    let flags = SupportFlagsResponse::load(&payload).expect("decode support-flags");
    assert_eq!(flags.support_flags, P2P_SUPPORT_FLAGS);
}
