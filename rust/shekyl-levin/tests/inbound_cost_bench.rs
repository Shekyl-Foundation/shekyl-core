// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one INBOUND connection costs a node — the rig for `--in-peers`'
//! shipped default (`PWD-I7`, rule 76).
//!
//! The per-host inbound cap was deleted 2026-09-22, which left the total
//! ceiling as the only inbound bound — and that ceiling resolves to
//! `UINT32_MAX` at the shipped default, so it never fires. Its replacement is
//! a **measurement**, not a ruling: the target property is descriptors and
//! memory, which are directly observable, so nothing here is a judgement call.
//!
//! **This is the instrument, not the answer.** It prints a table; the value
//! that ships is derived from a run ON THE FLOOR DEVICE (rule 76 item 4:
//! values and increments for the floor are measured on it, never
//! extrapolated). Rule 76 also expects the floor to move, and every constant
//! provisioned against it to be re-derived — which is why this lands as a
//! re-runnable bench rather than as a number in a commit message.
//!
//! **Two arms** (`DAEMON_RELAY_PRIVACY.md` §80.4, rule 76 item 3): run it on
//! the floor device and on a development machine, and record the ratio.
//! Cross-machine ratios are measured, never assumed.
//!
//! ```bash
//! SHEKYLD_BIN=/abs/path/build/bin/shekyld \
//!   cargo test -p shekyl-levin --test inbound_cost_bench -- --ignored --nocapture
//! ```
//!
//! Three costs, because the ceiling is bounded by whichever binds first:
//!
//!   * **`VmRSS`** — steady-state resident set, the term a ceiling is usually
//!     derived against.
//!   * **`VmHWM`** — peak resident set since start. Q12-R14 measured daemon
//!     startup at roughly twice steady state, so the binding constraint may be
//!     a transient rather than the plateau, and a ceiling derived from `VmRSS`
//!     alone would be derived against the wrong number.
//!   * **open descriptors** — one socket per inbound connection, against
//!     `RLIMIT_NOFILE`. This is a configuration bound rather than a hardware
//!     one, so it is reported separately and never folded into the memory
//!     figure.
//!
//! Each simulated peer completes a real `COMMAND_HANDSHAKE` and then services
//! its socket, because a connection the daemon has dropped costs nothing and
//! would measure as a free peer.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_levin::{
    invoke, response, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, NetworkAddress,
    PortableMap, Received, SupportFlags, SupportFlagsRequest, SupportFlagsResponse,
    COMMAND_HANDSHAKE, COMMAND_REQUEST_SUPPORT_FLAGS,
};

/// `config::NETWORK_ID` — FAKECHAIN (`--regtest`) uses the mainnet id.
const MAINNET_NETWORK_ID: [u8; 16] = [
    0x55, 0x6C, 0xA9, 0x70, 0x8F, 0xF9, 0x1F, 0x7A, 0x40, 0x69, 0xDA, 0xF3, 0xFC, 0x55, 0xBB, 0xBD,
];

/// Inbound counts to sample. The first is the baseline; every later row's
/// marginal cost is taken against its predecessor, so a non-linear term shows
/// up as a drifting per-connection figure rather than hiding in an average.
const STEPS: &[usize] = &[0, 16, 32, 64, 128];

// ---------------------------------------------------------------------------
// Process sampling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Sample {
    rss_kib: u64,
    hwm_kib: u64,
    /// Exact open-descriptor count, or `None` when `/proc/<pid>/fd` is not
    /// readable. **Never zero as a stand-in for unknown**: reading `fd/`
    /// needs `PTRACE_MODE_READ`, which a hardened `/proc` or a sandbox
    /// refuses even for one's own child, and a silent `0` there would report
    /// "descriptors are free" when the truth is "not measured".
    fds: Option<usize>,
    /// Allocated fd-table slots from `status`, which needs no ptrace. A
    /// power-of-two ceiling rather than a count, so it bounds `fds` from
    /// above and is the fallback when the exact count is unavailable.
    fd_slots: u64,
}

fn sample(pid: u32) -> Sample {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    let field = |name: &str| -> u64 {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(std::iter::Iterator::count)
        .ok();
    Sample {
        rss_kib: field("VmRSS:"),
        hwm_kib: field("VmHWM:"),
        fds,
        fd_slots: field("FDSize:"),
    }
}

// ---------------------------------------------------------------------------
// Daemon under measurement
// ---------------------------------------------------------------------------

struct Daemon {
    child: Child,
    data_dir: PathBuf,
    p2p_port: u16,
    rpc_port: u16,
}

impl Daemon {
    fn start() -> Self {
        let bin = PathBuf::from(std::env::var_os("SHEKYLD_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYLD_BIN not set. Build the daemon and run e.g. \
                 SHEKYLD_BIN=/abs/path/build/bin/shekyld cargo test -p shekyl-levin \
                 --test inbound_cost_bench -- --ignored --nocapture"
            )
        }));
        let rpc_port = free_port();
        let p2p_port = free_port();
        let data_dir = std::env::temp_dir().join(format!("shekyl-inbound-cost-{p2p_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let log = std::fs::File::create(data_dir.join("daemon.log")).expect("daemon log");

        // `--out-peers 0` so every connection counted here is INBOUND and ours.
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

        let mut d = Self {
            child,
            data_dir,
            p2p_port,
            rpc_port,
        };
        d.await_ready();
        d
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn await_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("daemon exited early ({status})");
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

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    l.local_addr().expect("addr").port()
}

fn rpc_ok(rpc_port: u16) -> bool {
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

// ---------------------------------------------------------------------------
// A simulated inbound peer
// ---------------------------------------------------------------------------

/// Completes a handshake, then services the socket until told to stop.
///
/// The servicing thread is not incidental: an unanswered `COMMAND_TIMED_SYNC`
/// gets the peer dropped, and a dropped peer costs nothing — it would measure
/// as a free connection and understate every figure in the table.
fn spawn_peer(
    p2p_port: u16,
    advertised_port: u16,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let Ok(stream) = TcpStream::connect(("127.0.0.1", p2p_port)) else {
            return false;
        };
        drop(stream.set_read_timeout(Some(Duration::from_millis(500))));
        drop(stream.set_write_timeout(Some(Duration::from_secs(10))));
        drop(stream.set_nodelay(true));
        let mut s = stream;
        let mut reader = BucketReader::new();

        let req = HandshakeRequest {
            node_data: BasicNodeData {
                network_id: MAINNET_NETWORK_ID,
                address: NetworkAddress::Ipv4 {
                    ip: Ipv4Addr::new(9, 9, 9, 9),
                    port: advertised_port,
                },
                support_flags: SupportFlags::ADVERTISED,
            },
            payload_data: CoreSyncData {
                current_height: 1,
                cumulative_difficulty: 0,
                cumulative_difficulty_top64: 0,
                top_id: [0u8; 32],
                top_version: 0,
            },
            nonce: [0x42; 32],
        };
        let Ok(payload) = req.store() else {
            return false;
        };
        if s.write_all(&invoke(COMMAND_HANDSHAKE, &payload)).is_err() {
            return false;
        }

        let mut buf = [0u8; 8192];
        let mut shook = false;
        while !stop.load(Ordering::Relaxed) {
            loop {
                match reader.next_message() {
                    Ok(Some(Received::Response { command, .. }))
                        if command == COMMAND_HANDSHAKE =>
                    {
                        shook = true;
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
                    Err(_) => return shook,
                }
            }
            match s.read(&mut buf) {
                Ok(0) => return shook,
                Ok(n) => {
                    if reader.feed(&buf[..n]).is_err() {
                        return shook;
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => return shook,
            }
        }
        shook
    })
}

// ---------------------------------------------------------------------------
// The bench
// ---------------------------------------------------------------------------

#[ignore = "measurement rig: requires SHEKYLD_BIN; spawns a live daemon and many sockets"]
#[test]
fn inbound_connection_cost_table() {
    let daemon = Daemon::start();
    let pid = daemon.pid();

    // Let the daemon settle before the baseline: a sample taken while startup
    // allocation is still in flight attributes startup cost to connection 1.
    std::thread::sleep(Duration::from_secs(5));

    println!("\n=== inbound connection cost — {} ===", host_label());
    println!(
        "SHEKYLD_BIN={:?}",
        std::env::var("SHEKYLD_BIN").unwrap_or_default()
    );
    println!(
        "{:>6}  {:>6}  {:>10}  {:>10}  {:>8}  {:>8}   {:>14}",
        "n_req", "live", "VmRSS KiB", "VmHWM KiB", "fds", "fd_slots", "marg RSS KiB"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    let mut prev: Option<(usize, Sample)> = None;

    for &n in STEPS {
        while handles.len() < n {
            let port = 30_000u16.wrapping_add(u16::try_from(handles.len()).unwrap_or(0));
            handles.push(spawn_peer(daemon.p2p_port, port, Arc::clone(&stop)));
            std::thread::sleep(Duration::from_millis(25));
        }
        // Settle: buffers allocate on use, not on accept.
        std::thread::sleep(Duration::from_secs(10));

        // Count peers still connected. The table's `n_req` is what was
        // LAUNCHED; a peer the daemon dropped costs nothing, so dividing by
        // `n_req` would understate the per-connection figure. Marginals are
        // taken against `live`.
        let live = handles.iter().filter(|h| !h.is_finished()).count();
        let s_now = sample(pid);
        let mr = match prev {
            Some((plive, ps)) if live > plive => {
                let dn = i64::try_from(live - plive).unwrap_or(1).max(1);
                let d_rss = i64::try_from(s_now.rss_kib).unwrap_or(0)
                    - i64::try_from(ps.rss_kib).unwrap_or(0);
                tenths(d_rss * 10 / dn)
            }
            _ => "-".into(),
        };
        println!(
            "{n:>6}  {live:>6}  {:>10}  {:>10}  {:>8}  {:>8}   {:>14}",
            s_now.rss_kib,
            s_now.hwm_kib,
            s_now
                .fds
                .map_or_else(|| "n/a".to_string(), |v| v.to_string()),
            s_now.fd_slots,
            mr
        );
        prev = Some((live, s_now));
    }

    stop.store(true, Ordering::Relaxed);
    println!(
        "\nfds `n/a` means /proc/<pid>/fd was not readable -- it needs\n\
         PTRACE_MODE_READ, which a hardened /proc or a sandbox refuses even\n\
         for one's own child. It is NOT zero; fd_slots (FDSize, no ptrace\n\
         required) is the readable upper bound in that case."
    );
    println!(
        "NOTE: VmHWM is the peak since start. If it exceeds the final VmRSS by\n\
         more than the table's total growth, the binding constraint is STARTUP,\n\
         not steady state, and the ceiling must be derived against the peak.\n\
         Record BOTH arms (floor device and dev machine) and the ratio: rule 76\n\
         item 3 — cross-machine ratios are measured, never assumed.\n"
    );
}

/// Render tenths of a unit without a float cast (`x` is value * 10).
fn tenths(x: i64) -> String {
    format!("{}.{}", x / 10, (x % 10).abs())
}

fn host_label() -> String {
    let model = std::fs::read_to_string("/proc/device-tree/model")
        .map(|s| s.trim_end_matches('\0').trim().to_string())
        .unwrap_or_default();
    if model.is_empty() {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
            })
            .unwrap_or_else(|| "unknown".into())
    } else {
        model
    }
}
