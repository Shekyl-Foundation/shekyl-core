// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-T2 daemon-observability measurement harness (Round-0).
//!
//! The archival firewall serves N per-`P` block-fetch streams from **one**
//! daemon. Before the wallet-side `PBlockSource` design freezes, we must know
//! *what that leaks* — the success metric is observability, never blocks/sec
//! (`docs/design/ARCHIVAL_BOND_2D2_SP_T2_FETCH.md`, DQ-T2.5). This harness
//! quantifies four things against a live `shekyld --regtest`:
//!
//! - **M-enum** — is the concurrent per-`P` connection count observable, and
//!   *where*? Confirms the count lives in the **host TCP table**
//!   (`/proc/net/tcp`), an OS-level residual *below* the RPC layer, and that
//!   the Rust/Axum RPC surface neither caps N (the dead epee `per_private_ip`
//!   default) nor exposes a connection-count field.
//! - **M-timing** — the cross-persona timing coupling on **both** read paths:
//!   the lock-taking JSON `get_block` (`m_blockchain_lock`) and the lock-free
//!   `get_blocks_by_height.bin` (`get_block_from_height`, MVCC, no lock). The
//!   load-bearing output is the **coupling-magnitude distribution** — how far a
//!   probe persona's latency shifts under N contending personas, in absolute
//!   time — and the **delta** between paths, which isolates the lock.
//! - **M-consistency** — the correctness gate on the "serve lock-free" rung: a
//!   latency-only harness would greenlight it without testing what makes it
//!   *safe*. Under a concurrent writer (`generateblocks` + `pop_blocks`
//!   churning the tip), the lock-free path must return, for the *same stable
//!   height*, the **same block** the locked path does — i.e. it must not expose
//!   a consistency window the lock closes. Tip-race reads are additionally
//!   checked for internal validity (they parse and their coinbase height
//!   matches the request), not cross-path equality (a legitimately-replaced tip
//!   block is not a torn read).
//! - **M-substitute** — dissolving `m_blockchain_lock` must not silently mint a
//!   *new* shared-resource channel one layer up; the lock-free path is measured
//!   under N-persona contention (the M-timing lock-free column), so a substitute
//!   coupling (shared thread-pool queuing, a reused reader) cannot hide.
//!
//! Round-0 ran 2026-07-02 (envelope: regtest ~2 s/block coinbase-only chain,
//! tip 41, N ≤ 16 on an 8c/16t box). Results + the settled disposition — rung 1
//! (single-height lock-free read) adopted as correct-by-construction; local
//! timing subsumed by the enumeration residual; remote-daemon channels recorded
//! as discouraged-posture residuals — live in the design doc's DQ-T2.5. These
//! measurements are architectural characterization, not a live-channel
//! assessment.
//!
//! All tests are `#[ignore]`d and require `SHEKYLD_BIN`; run e.g.
//! `SHEKYLD_BIN=/abs/build/bin/shekyld cargo test -p shekyl-engine-core \
//!  daemon_observability -- --ignored --nocapture --test-threads=1`.
//! Reporting is via `eprintln!` (the measurement *is* the output); nothing here
//! logs a secret — heights and latencies on a throwaway regtest chain only.

// Whole-file test module (declared `#[cfg(test)] mod` in the parent). The inner
// gate self-declares this as test code so the "no debug macros in production
// Rust" CI lint's file-scan keys on it and allows the `eprintln!` measurement
// output — the same pattern `regtest_e2e.rs` uses.
#![cfg(test)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use shekyl_rpc_client::Rpc;
use shekyl_rpc_transport::SimpleRequestRpc;
use shekyl_wire::Block;

use super::regtest_e2e::RegtestDaemon;

// ---------------------------------------------------------------------------
// EPEE (portable storage) — hand-rolled, mirroring the `get_o_indexes.bin`
// codec in `shekyl-rpc-client` (there is no epee crate). We only need the two
// shapes `get_blocks_by_height.bin` uses: a request `{ heights: [u64] }` and a
// response `{ blocks: [ { block: <blob>, .. }, .. ], .. }`.
// ---------------------------------------------------------------------------

/// EPEE stream header: an 8-byte magic + a 1-byte format version.
const EPEE_HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

// EPEE scalar type tags (the low 6 bits; bit 0x80 flags an array-of-that-type).
const T_INT64: u8 = 1;
const T_INT32: u8 = 2;
const T_INT16: u8 = 3;
const T_INT8: u8 = 4;
const T_UINT64: u8 = 5;
const T_UINT32: u8 = 6;
const T_UINT16: u8 = 7;
const T_UINT8: u8 = 8;
const T_DOUBLE: u8 = 9;
const T_STRING: u8 = 10;
const T_BOOL: u8 = 11;
const T_OBJECT: u8 = 12;
const ARRAY_FLAG: u8 = 0x80;

/// Max object-nesting depth the decoder will follow before erroring. The real
/// `get_blocks_by_height.bin` response nests ~2 levels (top section → `blocks`
/// array → block object); this bounds the `walk_section`→`read_scalar`→
/// `walk_section` recursion so a malformed/adversarial response returns `Err`
/// rather than overflowing the stack (keeps the decoder panic-free as documented).
const MAX_EPEE_DEPTH: usize = 32;

/// Append an EPEE varint: the 2 LSBs encode the byte-width (0→1, 1→2, 2→4,
/// 3→8), the value occupies the remaining bits. Inverse of the reader's
/// `read_epee_vi`.
// Each narrowing cast is guarded by the branch's range check (`v <= 0x3F`
// etc.), so truncation is impossible by construction.
#[allow(clippy::cast_possible_truncation)]
fn write_epee_vi(out: &mut Vec<u8>, v: u64) {
    if v <= 0x3F {
        out.push((v as u8) << 2);
    } else if v <= 0x3FFF {
        out.extend_from_slice(&(((v as u16) << 2) | 1).to_le_bytes());
    } else if v <= 0x3FFF_FFFF {
        out.extend_from_slice(&(((v as u32) << 2) | 2).to_le_bytes());
    } else {
        out.extend_from_slice(&((v << 2) | 3).to_le_bytes());
    }
}

/// Serialize the `get_blocks_by_height.bin` request `{ heights: [u64] }`.
fn build_get_blocks_by_height_req(heights: &[u64]) -> Vec<u8> {
    let mut r = EPEE_HEADER.to_vec();
    write_epee_vi(&mut r, 1); // one top-level field
    r.push(7); // name length
    r.extend_from_slice(b"heights");
    r.push(ARRAY_FLAG | T_UINT64);
    write_epee_vi(&mut r, heights.len() as u64);
    for &h in heights {
        r.extend_from_slice(&h.to_le_bytes());
    }
    r
}

/// A minimal forward cursor over an EPEE blob.
struct Epee<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Epee<'a> {
    fn new(b: &'a [u8]) -> Result<Self, String> {
        if b.len() < EPEE_HEADER.len() || &b[..EPEE_HEADER.len()] != EPEE_HEADER {
            return Err("bad EPEE header".into());
        }
        Ok(Epee {
            b,
            pos: EPEE_HEADER.len(),
        })
    }

    fn byte(&mut self) -> Result<u8, String> {
        let x = *self.b.get(self.pos).ok_or("EPEE truncated")?;
        self.pos += 1;
        Ok(x)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("EPEE length overflow")?;
        let s = self.b.get(self.pos..end).ok_or("EPEE truncated")?;
        self.pos = end;
        Ok(s)
    }

    fn vi(&mut self) -> Result<u64, String> {
        let start = self.byte()?;
        let len = 1usize << (start & 0b11);
        let mut v = u64::from(start >> 2);
        for i in 1..len {
            v |= u64::from(self.byte()?) << (((i - 1) * 8) + 6);
        }
        Ok(v)
    }

    /// Walk one object (section): a field count, then `name/type/value` triples.
    /// Every `block` string value encountered anywhere in the tree is pushed to
    /// `blocks` — the only such field in this response is the one we want, and
    /// string *values* (block/tx blobs) are read opaquely, never re-parsed for
    /// field names, so a blob byte-pattern can't be mistaken for a key.
    fn walk_section(&mut self, blocks: &mut Vec<Vec<u8>>, depth: usize) -> Result<(), String> {
        if depth > MAX_EPEE_DEPTH {
            return Err("EPEE nesting exceeds MAX_EPEE_DEPTH".into());
        }
        let fields = self.vi()?;
        for _ in 0..fields {
            let name_len = self.byte()? as usize;
            let name = self.take(name_len)?.to_vec();
            let ty = self.byte()?;
            self.read_value(ty, &name, blocks, depth)?;
        }
        Ok(())
    }

    fn read_value(
        &mut self,
        ty: u8,
        name: &[u8],
        blocks: &mut Vec<Vec<u8>>,
        depth: usize,
    ) -> Result<(), String> {
        if ty & ARRAY_FLAG != 0 {
            let count = self.vi()?;
            for _ in 0..count {
                self.read_scalar(ty & !ARRAY_FLAG, name, blocks, depth)?;
            }
        } else {
            self.read_scalar(ty, name, blocks, depth)?;
        }
        Ok(())
    }

    fn read_scalar(
        &mut self,
        base: u8,
        name: &[u8],
        blocks: &mut Vec<Vec<u8>>,
        depth: usize,
    ) -> Result<(), String> {
        match base {
            T_STRING => {
                let len = usize::try_from(self.vi()?).map_err(|_| "EPEE string too long")?;
                let bytes = self.take(len)?;
                if name == b"block" {
                    blocks.push(bytes.to_vec());
                }
            }
            T_OBJECT => self.walk_section(blocks, depth + 1)?,
            T_BOOL | T_UINT8 | T_INT8 => {
                self.take(1)?;
            }
            T_UINT16 | T_INT16 => {
                self.take(2)?;
            }
            T_UINT32 | T_INT32 => {
                self.take(4)?;
            }
            T_UINT64 | T_INT64 | T_DOUBLE => {
                self.take(8)?;
            }
            other => return Err(format!("unhandled EPEE type {other}")),
        }
        Ok(())
    }
}

/// Decode a `get_blocks_by_height.bin` response into its raw block blobs, in
/// order.
fn decode_block_blobs(resp: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut e = Epee::new(resp)?;
    let mut blocks = Vec::new();
    e.walk_section(&mut blocks, 0)?;
    Ok(blocks)
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------

/// The two block-read paths under study, distinguished only by their daemon
/// lock behavior.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReadPath {
    /// JSON-RPC `get_block` — enters `m_blockchain_lock` (`get_block_by_hash`).
    Locked,
    /// `get_blocks_by_height.bin` single-height — bare LMDB `get_block_from_height`.
    LockFree,
}

impl ReadPath {
    fn label(self) -> &'static str {
        match self {
            ReadPath::Locked => "get_block (LOCKED)",
            ReadPath::LockFree => ".bin       (lock-free)",
        }
    }
}

/// One client, one path, one height — return the raw block bytes (`None` if the
/// daemon has no block at that height, e.g. it was just popped).
async fn fetch_block(
    rpc: &SimpleRequestRpc,
    path: ReadPath,
    h: u64,
) -> Result<Option<Vec<u8>>, String> {
    match path {
        ReadPath::Locked => {
            let v: Value = rpc
                .json_rpc_call("get_block", Some(json!({ "height": h })))
                .await
                .map_err(|e| format!("{e:?}"))?;
            match v.get("blob").and_then(Value::as_str) {
                Some(hexs) => Ok(Some(hex::decode(hexs).map_err(|_| "blob not hex")?)),
                None => Ok(None),
            }
        }
        ReadPath::LockFree => {
            let req = build_get_blocks_by_height_req(&[h]);
            let resp = rpc
                .bin_call("get_blocks_by_height.bin", req)
                .await
                .map_err(|e| format!("{e:?}"))?;
            Ok(decode_block_blobs(&resp)?.into_iter().next())
        }
    }
}

/// Open an independent client — a distinct `reqwest` pool ⇒ a distinct TCP
/// connection, mirroring the per-`P` isolation posture (never a shared clone).
async fn open_client(port: u16) -> SimpleRequestRpc {
    SimpleRequestRpc::new(format!("http://127.0.0.1:{port}"))
        .await
        .expect("construct per-persona rpc client")
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Nearest-rank percentile (`numer/denom`, e.g. `90/100`) over already-sorted
/// latency samples (µs). Integer arithmetic — no float casts.
fn percentile(sorted: &[u64], numer: usize, denom: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() - 1) * numer / denom;
    sorted[idx]
}

// ---------------------------------------------------------------------------
// Chain bootstrap
// ---------------------------------------------------------------------------

/// Create a throwaway wallet against the daemon and return its encoded primary
/// address (the coinbase target `generateblocks` requires). The wallet file is
/// ephemeral — only the address string outlives this call.
async fn new_wallet_address(port: u16) -> String {
    use super::lifecycle::{CapabilityInput, Credentials, EngineCreateParams};
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_address::Network;
    use shekyl_crypto_pq::account::{SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::wallet_envelope::KdfParams;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_engine_prefs::WalletPrefs;

    let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{port}"))
        .await
        .expect("wallet rpc");
    let daemon_client = DaemonClient::new(rpc);

    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let seed = [0x11u8; MASTER_SEED_BYTES];
    let creds = Credentials::password_only(b"spt2-observability");
    let params = EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: Network::Mainnet,
        capability: CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };
    let wallet = Engine::<SoloSigner>::create(params, daemon_client).expect("create wallet");
    wallet
        .primary_address()
        .encode()
        .expect("encode wallet address")
}

/// Spawn a regtest daemon and mine `blocks` blocks; returns the daemon, the
/// coinbase address (reused by the M-consistency writer), and the resulting tip.
async fn boot_and_mine(blocks: u64) -> (RegtestDaemon, String, u64) {
    let daemon = RegtestDaemon::start().await;
    let address = new_wallet_address(daemon.rpc_port()).await;
    daemon.generate_blocks(blocks, &address).await;
    let tip = daemon.height().await;
    (daemon, address, tip)
}

// ---------------------------------------------------------------------------
// M-enum
// ---------------------------------------------------------------------------

/// Parse the trailing `:PORT` (hex) of a `/proc/net/tcp` address column.
fn hex_port(addr: &str) -> Option<u16> {
    let p = addr.rsplit(':').next()?;
    u16::from_str_radix(p, 16).ok()
}

/// Count ESTABLISHED loopback sockets touching `port`, from both `/proc/net/tcp`
/// and `tcp6`. Returns `(client_side, daemon_side)`: sockets whose *remote* port
/// is `port` are the N client→daemon connections the daemon serves; sockets
/// whose *local* port is `port` are the daemon's accepted ends.
fn count_established(port: u16) -> (usize, usize) {
    let mut client_side = 0;
    let mut daemon_side = 0;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[3] != "01" {
                continue; // 01 == TCP_ESTABLISHED
            }
            if hex_port(f[2]) == Some(port) {
                client_side += 1;
            }
            if hex_port(f[1]) == Some(port) {
                daemon_side += 1;
            }
        }
    }
    (client_side, daemon_side)
}

/// **M-enum.** Open more concurrent per-`P` clients than the (dead) epee
/// `per_private_ip=25` cap, keep them active, and confirm: (1) every client
/// connects — N is *not* capped by the Axum layer; (2) the connection count is
/// observable in the host TCP table; (3) `get_info` carries no field that
/// reveals it. The leak is an OS-level residual below our RPC layer.
async fn measure_enum(port: u16) {
    const N: usize = 30; // > the dead per_private_ip=25 default

    // N independent clients, each looping get_info to hold its connection open.
    let stop = Arc::new(AtomicBool::new(false));
    let ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..N {
        let rpc = open_client(port).await;
        let stop = stop.clone();
        let ok = ok.clone();
        handles.push(tokio::spawn(async move {
            let mut succeeded = false;
            while !stop.load(Ordering::Relaxed) {
                if rpc.json_rpc_call::<Value>("get_info", None).await.is_ok() {
                    if !succeeded {
                        succeeded = true;
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    // Let all clients establish, then sample the host TCP table.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let proc_available = std::path::Path::new("/proc/net/tcp").exists();
    let (client_side, daemon_side) = count_established(port);
    let connected = ok.load(Ordering::Relaxed);

    // Is the count exposed by the RPC surface? (grounding says no.)
    let probe = open_client(port).await;
    let info: Value = probe
        .json_rpc_call("get_info", None)
        .await
        .expect("get_info");
    let rpc_conn_field = info.get("rpc_connections_count").and_then(Value::as_u64);

    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.await.expect("harness task panicked");
    }

    eprintln!("\n=== M-enum: per-P connection enumeration ===");
    eprintln!("clients opened .............. {N}");
    eprintln!("clients that connected ...... {connected}  (cap would truncate this)");
    eprintln!("host TCP table, client-side . {client_side} ESTABLISHED → :{port}");
    eprintln!("host TCP table, daemon-side . {daemon_side} ESTABLISHED  :{port} → *");
    eprintln!(
        "get_info.rpc_connections_count {}",
        match rpc_conn_field {
            Some(v) => format!("= {v}  (does NOT reflect the {N} Axum connections)"),
            None => "absent".to_string(),
        }
    );
    eprintln!("→ N is not capped by the RPC layer; the count is an OS-level (TCP-table)");
    eprintln!("  residual BELOW the RPC surface — confirms DQ-T2.5 #1.\n");

    // Not capped: the dead epee `per_private_ip=25` default must not gate N. A
    // lower bound (not `== N`) — `connected` is sampled at a fixed instant, so a
    // slow box may not have landed the last client's first get_info yet; the
    // property is "well past the dead 25-cap", not an exact count.
    assert!(
        connected > 25,
        "the Axum layer must not cap N at the dead epee per_private_ip=25 \
         (only {connected} of {N} connected)"
    );
    // The TCP-table observability check is Linux-/proc-specific; skip it where
    // /proc is unavailable (macOS/BSD/containers without procfs) rather than
    // failing the whole harness on a portability gap.
    if proc_available {
        assert!(
            client_side >= N / 2,
            "the concurrent connection count must be observable in the host TCP \
             table (saw {client_side} of {N})"
        );
    } else {
        eprintln!("  (/proc/net/tcp unavailable — TCP-table observability check skipped)");
    }
    assert!(
        rpc_conn_field.unwrap_or(0) < N as u64,
        "the RPC surface must NOT expose the concurrent per-P connection count \
         (rpc_connections_count = {rpc_conn_field:?})"
    );
}

// ---------------------------------------------------------------------------
// M-timing + M-substitute
// ---------------------------------------------------------------------------

/// A contending persona: hammer `path` across the height range until stopped.
async fn run_contender(
    rpc: SimpleRequestRpc,
    path: ReadPath,
    tip: u64,
    stop: Arc<AtomicBool>,
    seed: u64,
) {
    let span = tip.max(1);
    let mut i = seed;
    while !stop.load(Ordering::Relaxed) {
        fetch_block(&rpc, path, i % span).await.ok();
        i = i.wrapping_add(1);
    }
}

/// Collect `samples` sequential probe latencies (µs) on `path`, cycling heights.
async fn probe_latencies(
    rpc: &SimpleRequestRpc,
    path: ReadPath,
    tip: u64,
    samples: usize,
) -> Vec<u64> {
    let span = tip.max(1);
    let mut lat = Vec::with_capacity(samples);
    for k in 0..samples {
        let h = (k as u64) % span;
        let t0 = Instant::now();
        let ok = fetch_block(rpc, path, h).await.is_ok();
        let elapsed = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
        // Only successful reads enter the coupling distribution — an error
        // round-trip (a fast 5xx / a slow timeout) is not the block-read latency
        // this measurement characterizes, and folding it in would corrupt the
        // p50/p90/p99 the harness exists to produce.
        if ok {
            lat.push(elapsed);
        }
    }
    lat
}

/// Sweep contender counts, returning `(contenders, p50, p90, p99)` µs rows for
/// `path`. The probe is a single dedicated client; contenders are independent
/// clients (distinct connections).
async fn coupling_sweep(port: u16, path: ReadPath, tip: u64) -> Vec<(usize, u64, u64, u64)> {
    const LEVELS: [usize; 6] = [0, 1, 2, 4, 8, 16];
    const SAMPLES: usize = 200;

    let probe = open_client(port).await;
    // Warm the LMDB page cache so we measure lock coupling, not cold I/O.
    let _ = probe_latencies(&probe, path, tip, 64).await;

    let mut rows = Vec::new();
    for &c in &LEVELS {
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for j in 0..c {
            let rpc = open_client(port).await;
            let stop = stop.clone();
            handles.push(tokio::spawn(run_contender(
                rpc,
                path,
                tip,
                stop,
                (j as u64) * 97 + 1,
            )));
        }
        tokio::time::sleep(Duration::from_millis(250)).await; // let contenders ramp
        let mut lat = probe_latencies(&probe, path, tip, SAMPLES).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.await.expect("harness task panicked");
        }
        lat.sort_unstable();
        rows.push((
            c,
            percentile(&lat, 50, 100),
            percentile(&lat, 90, 100),
            percentile(&lat, 99, 100),
        ));
    }
    rows
}

fn report_sweep(path: ReadPath, rows: &[(usize, u64, u64, u64)]) {
    eprintln!("  {}", path.label());
    eprintln!("    contenders   p50(µs)   p90(µs)   p99(µs)");
    for &(c, p50, p90, p99) in rows {
        eprintln!("    {c:>9}   {p50:>7}   {p90:>7}   {p99:>7}");
    }
    let base_p90 = rows.first().map(|r| r.2).unwrap_or(0);
    let max_p90 = rows.last().map(|r| r.2).unwrap_or(0);
    let n = rows.last().map(|r| r.0).unwrap_or(1).max(1) as u64;
    eprintln!(
        "    coupling: p90 {base_p90}µs → {max_p90}µs over 0→{n} contenders  \
         (~{}µs per contender)",
        (max_p90.saturating_sub(base_p90)) / n
    );
}

/// **M-timing + M-substitute.** The cross-persona coupling on both paths. What
/// decides the disposition is each path's *coupling slope* (its own p90 latency
/// shift from 0→N contenders, each path its own C=0 baseline) — NOT the absolute
/// latency gap between paths, which folds in JSON-vs-epee codec/handler cost the
/// lock never caused. The lock-isolated coupling is `slope_locked −
/// slope_lockfree`; the lock-free slope alone is the M-substitute check (coupling
/// that survives the dissolved lock).
async fn measure_timing(port: u16, tip: u64) {
    let locked = coupling_sweep(port, ReadPath::Locked, tip).await;
    let lockfree = coupling_sweep(port, ReadPath::LockFree, tip).await;

    eprintln!("\n=== M-timing: cross-persona coupling (tip {tip}) ===");
    report_sweep(ReadPath::Locked, &locked);
    report_sweep(ReadPath::LockFree, &lockfree);

    // Coupling SLOPE per path = p90 shift from 0→max contenders, each path its
    // own C=0 baseline. The delta between the two slopes cancels JSON-vs-epee
    // codec/handler cost and isolates the m_blockchain_lock contribution — the
    // number the disposition turns on. The absolute cross-path latency gap is
    // NOT that number and is deliberately not reported as one.
    let lock_slope = locked
        .last()
        .unwrap()
        .2
        .saturating_sub(locked.first().unwrap().2);
    let free_slope = lockfree
        .last()
        .unwrap()
        .2
        .saturating_sub(lockfree.first().unwrap().2);
    eprintln!("\n  coupling SLOPE (p90 shift 0→16 contenders; each path its own C=0 baseline):");
    eprintln!("    LOCKED   get_block : {lock_slope}µs");
    eprintln!(
        "    lock-free .bin     : {free_slope}µs   (M-substitute: coupling left after the lock)"
    );
    eprintln!(
        "  lock-ISOLATED coupling = slope_locked − slope_lockfree = {}µs",
        lock_slope.saturating_sub(free_slope)
    );
    eprintln!("  → architectural characterization, not a live-channel assessment: both paths are");
    eprintln!("    ~flat below CPU saturation; the signal is the N≈cores cliff, where the locked");
    eprintln!("    path amplifies ~4× more. Disposition: design doc DQ-T2.5 (rung 1 adopted as");
    eprintln!("    correct-by-construction; local timing is subsumed by enumeration).\n");

    // Round-0 asserts only that the harness produced a full sweep on both paths;
    // the magnitude is a measurement to record, not a pass/fail threshold.
    assert_eq!(locked.len(), 6);
    assert_eq!(lockfree.len(), 6);
}

// ---------------------------------------------------------------------------
// M-consistency
// ---------------------------------------------------------------------------

/// **M-consistency** — the correctness gate on rung 1, under a *forced and
/// measured* writer window. A green diff means nothing unless the write window
/// was provably open during the reads, so a per-critical-section commit counter
/// is sampled around every tip read: `raced` is the count of reads a writer
/// commit landed *during* — the denominator that turns "0 torn in one quiet run"
/// into "0 torn across K reads with W provably racing a commit."
///
/// Three probes run concurrently with a tip-churning writer:
/// - **stable-height soundness:** for an unchanging deep height the two paths
///   must return identical bytes (a decode/soundness check, not the window test).
/// - **forced-window single-height validity (the rung-1 mechanism):** tip reads
///   on the lock-free path — each block whole and at the height asked for, even
///   when it raced a commit. Single-height LMDB reads are atomic, so this is
///   *expected* to hold; the point is to hold it under a proven-open window.
/// - **multi-height straddle probe (the AVOIDED hazard, finding-b):** a `.bin`
///   batch spanning the churn zone must be an internally-linked chain segment
///   (`previous == prev.hash()`); a broken link is a straddle — the multi-read
///   incoherence the lock closes and rung-1 sidesteps by reading one height per
///   call. Characterized, never asserted: its presence *confirms* why rung-1
///   avoids batches; its absence under a proven-open window is also informative.
async fn measure_consistency(daemon: Arc<RegtestDaemon>, address: String, tip: u64) {
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    const CHURN_DEPTH: u64 = 2; // pop+regen the top blocks
    const STABLE: [u64; 5] = [5, 10, 15, 20, 25];
    const READERS: usize = 4;
    const READ_SECS: u64 = 40; // duration-bound so reads span many commits
    const BATCH_SPAN: u64 = 5; // multi-height straddle-probe width

    assert!(
        tip > STABLE.iter().copied().max().unwrap() + CHURN_DEPTH + 5,
        "need a stable zone below the churn tip"
    );

    let port = daemon.rpc_port();
    let stop = Arc::new(AtomicBool::new(false));
    // Bumped once per writer critical section (pop, then generate); a reader that
    // sees it change across a read provably raced a commit.
    let commits = Arc::new(AtomicU64::new(0));

    let churn = {
        let daemon = daemon.clone();
        let stop = stop.clone();
        let commits = commits.clone();
        tokio::spawn(async move {
            let mut cycles = 0u64;
            while !stop.load(Ordering::Relaxed) {
                daemon.pop_blocks(CHURN_DEPTH).await;
                commits.fetch_add(1, Ordering::Relaxed);
                daemon.generate_blocks(CHURN_DEPTH, &address).await;
                commits.fetch_add(1, Ordering::Relaxed);
                cycles += 1;
            }
            cycles
        })
    };

    let stable_reads = Arc::new(AtomicUsize::new(0));
    let mismatches = Arc::new(AtomicUsize::new(0));
    let tip_reads = Arc::new(AtomicUsize::new(0));
    let tip_present = Arc::new(AtomicUsize::new(0));
    let raced = Arc::new(AtomicUsize::new(0));
    let torn = Arc::new(AtomicUsize::new(0));
    let batch_reads = Arc::new(AtomicUsize::new(0));
    let batch_raced = Arc::new(AtomicUsize::new(0));
    let straddles = Arc::new(AtomicUsize::new(0));

    let mut readers = Vec::new();
    for _ in 0..READERS {
        let rpc = open_client(port).await;
        let commits = commits.clone();
        let stable_reads = stable_reads.clone();
        let mismatches = mismatches.clone();
        let tip_reads = tip_reads.clone();
        let tip_present = tip_present.clone();
        let raced = raced.clone();
        let torn = torn.clone();
        let batch_reads = batch_reads.clone();
        let batch_raced = batch_raced.clone();
        let straddles = straddles.clone();
        readers.push(tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_secs(READ_SECS);
            while Instant::now() < deadline {
                // (a) stable-height soundness: unchanging height, bytes must match.
                for &h in &STABLE {
                    let a = fetch_block(&rpc, ReadPath::Locked, h).await;
                    let b = fetch_block(&rpc, ReadPath::LockFree, h).await;
                    stable_reads.fetch_add(1, Ordering::Relaxed);
                    match (a, b) {
                        (Ok(Some(x)), Ok(Some(y))) if x == y => {}
                        (Ok(Some(_)), Ok(Some(_))) => {
                            mismatches.fetch_add(1, Ordering::Relaxed);
                        }
                        (Ok(x), Ok(y)) if x.is_none() || y.is_none() => {
                            mismatches.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
                // (b) forced-window single-height tip validity: bracket each read
                // with the commit counter to prove the write window was open.
                // `tip` is the block COUNT, so the max height is `tip-1` (reading
                // `tip` always misses); the lower heights are always present, so
                // the reads run concurrently with the writer even as the top few
                // blink in and out under the churn.
                let max_h = tip.saturating_sub(1);
                for d in 0..=(CHURN_DEPTH + 1) {
                    let h = max_h.saturating_sub(d);
                    let c0 = commits.load(Ordering::Relaxed);
                    let r = fetch_block(&rpc, ReadPath::LockFree, h).await;
                    let c1 = commits.load(Ordering::Relaxed);
                    tip_reads.fetch_add(1, Ordering::Relaxed);
                    if c1 != c0 {
                        raced.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Ok(Some(bytes)) = r {
                        tip_present.fetch_add(1, Ordering::Relaxed);
                        match Block::from_bytes(&bytes) {
                            Ok(blk) if blk.number() == Some(h) => {}
                            _ => {
                                torn.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                // (c) multi-height straddle probe: a batch over the churn zone
                // must be an internally-linked chain segment.
                let base = max_h.saturating_sub(BATCH_SPAN - 1);
                let heights: Vec<u64> = (base..=max_h).collect();
                let c0 = commits.load(Ordering::Relaxed);
                let resp = rpc
                    .bin_call(
                        "get_blocks_by_height.bin",
                        build_get_blocks_by_height_req(&heights),
                    )
                    .await;
                let c1 = commits.load(Ordering::Relaxed);
                batch_reads.fetch_add(1, Ordering::Relaxed);
                if c1 != c0 {
                    batch_raced.fetch_add(1, Ordering::Relaxed);
                }
                if let Ok(bytes) = resp {
                    if let Ok(blobs) = decode_block_blobs(&bytes) {
                        // Parse each returned blob. A blob that fails to parse is
                        // itself a batch anomaly (a torn/malformed block) — count
                        // it, do NOT silently drop it: dropping both hides a real
                        // straddle and manufactures a phantom one by making the
                        // surviving blocks look adjacent when they aren't.
                        let mut parsed: Vec<Block> = Vec::with_capacity(blobs.len());
                        for b in &blobs {
                            match Block::from_bytes(b) {
                                Ok(blk) => parsed.push(blk),
                                Err(_) => {
                                    straddles.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        // Compare linkage only between blocks whose heights are
                        // *actually* consecutive (keyed on `number()`), so an
                        // absent height in the batch cannot fake a broken link.
                        for w in parsed.windows(2) {
                            if let (Some(h0), Some(h1)) = (w[0].number(), w[1].number()) {
                                if h1 == h0 + 1 && w[1].header.previous != w[0].hash() {
                                    straddles.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }
        }));
    }

    for r in readers {
        r.await.expect("harness reader task panicked");
    }
    stop.store(true, Ordering::Relaxed);
    // Surface a churn-writer failure honestly. `generate_blocks`/`pop_blocks`
    // .expect()-panic on a transient RPC error; swallowing that panic into
    // cycles=0 would fail the `cycles > 0` invariant below with a misleading
    // "writer never churned" message when the writer *did* churn and then hit a
    // hiccup. (Deeper fix — non-panicking churn under contention — is a
    // harness-hardening follow-up.)
    let cycles = churn
        .await
        .expect("M-consistency churn writer panicked (transient RPC error during churn?)");

    let commits = commits.load(Ordering::Relaxed);
    let stable_reads = stable_reads.load(Ordering::Relaxed);
    let mismatches = mismatches.load(Ordering::Relaxed);
    let tip_reads = tip_reads.load(Ordering::Relaxed);
    let tip_present = tip_present.load(Ordering::Relaxed);
    let raced = raced.load(Ordering::Relaxed);
    let torn = torn.load(Ordering::Relaxed);
    let batch_reads = batch_reads.load(Ordering::Relaxed);
    let batch_raced = batch_raced.load(Ordering::Relaxed);
    let straddles = straddles.load(Ordering::Relaxed);

    eprintln!("\n=== M-consistency: lock-free vs locked under a FORCED writer window ===");
    eprintln!(
        "conditions: {READERS} readers × {READ_SECS}s, churn pop+regen {CHURN_DEPTH} @ tip {tip}"
    );
    eprintln!("writer cycles / commits ............. {cycles} / {commits}");
    eprintln!(
        "stable-height path pairs (==) ....... {stable_reads}, mismatches {mismatches}  (want 0)"
    );
    eprintln!("tip reads ........................... {tip_reads}  ({tip_present} present)");
    eprintln!("  ├─ raced a concurrent commit ...... {raced}   ← single-height window (rare: reads are atomic)");
    eprintln!("  └─ torn / mis-height .............. {torn}   (want 0)");
    eprintln!(
        "multi-height batch probe ............ {batch_reads} reads, {batch_raced} raced a commit ← straddle window"
    );
    eprintln!("  └─ straddles (finding-b) .......... {straddles}  (0 expected — see below)");
    let window_forced = raced + batch_raced;
    if torn == 0 && mismatches == 0 && window_forced > 0 {
        eprintln!(
            "→ single-height reads (atomic by LMDB construction) stayed whole and matched the"
        );
        eprintln!("  locked path across {tip_present} present reads, under a window forced open {window_forced}×");
        eprintln!("  ({raced} single + {batch_raced} batch). The multi-height straddle (finding-b) was NOT");
        eprintln!(
            "  observed and CANNOT be forced by pop+regenerate: top-down pop + bottom-up regen"
        );
        eprintln!(
            "  never presents an inconsistent adjacent pair, so a real competing-chain reorg"
        );
        eprintln!(
            "  (not stageable via generateblocks) is needed to force it. Rung-1 confirms the"
        );
        eprintln!("  single-height mechanism; the straddle stays source-established + avoided by");
        eprintln!("  construction (one height per call).\n");
    } else if window_forced == 0 {
        eprintln!(
            "→ INCONCLUSIVE: no read provably raced a commit — window not forced; re-run with"
        );
        eprintln!("  faster churn / longer reads before trusting the 0-torn result.\n");
    } else {
        eprintln!("→ DIVERGENCE under load: the lock guards consistency the bare read drops.\n");
    }

    assert_eq!(
        mismatches, 0,
        "stable-height blocks diverged across paths under writer contention"
    );
    assert_eq!(
        torn, 0,
        "lock-free path returned a torn/mis-height block under writer contention"
    );
    assert!(
        cycles > 0,
        "writer must have churned the tip during the reads"
    );
    assert!(
        tip_present > 0,
        "no tip read returned a present block — check the height targets"
    );
    assert!(
        window_forced > 0,
        "no read provably raced a writer commit — the window never opened, so a \
         0-torn/0-straddle result is not a pass"
    );
}

// ---------------------------------------------------------------------------
// Round-0 driver
// ---------------------------------------------------------------------------

/// SP-T2 Round-0: one daemon, one chain, all measurements in sequence
/// (M-enum → M-timing/M-substitute → M-consistency). Consolidated so the ~2s/
/// block mine is paid once rather than per measurement. M-consistency runs last
/// because it churns the tip.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "SP-T2 observability: requires SHEKYLD_BIN; spawns a live daemon"]
async fn daemon_observability_round0() {
    // ~2s/block on this rig; keep the single generateblocks call well under the
    // RPC client's 180s timeout while leaving a stable zone below the churn tip.
    const MINE: u64 = 40;

    let (daemon, address, tip) = boot_and_mine(MINE).await;
    let port = daemon.rpc_port();
    eprintln!("\n######## SP-T2 daemon observability (Round-0) — tip {tip} ########");

    measure_enum(port).await;
    measure_timing(port, tip).await;

    let daemon = Arc::new(daemon);
    measure_consistency(daemon, address, tip).await;
}
