// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `BA-T5` floor probe: what serving archival shards costs the minimum
//! supported device, as wall clock and CPU.
//!
//! Ignored by default. It is a measurement instrument, not a test: it
//! asserts only that responses are whole, and prints tab-separated rows.
//! Run one mode at a time, in release. `BAT5_STORE` names a directory the
//! probe may create things under; it writes, and deletes, only its own
//! child `ba-t5-store` there:
//!
//! ```text
//! BAT5_STORE=/scratch BAT5_MODE=phase BAT5_LABEL=A.1 \
//!   cargo test --release --locked -p shekyl-p-serve \
//!   --test ba_t5_floor_probe -- --ignored --nocapture
//! ```
//!
//! The endpoint is the production one, `PServeEndpoint` with the test
//! signer, over loopback. What it serves is of two kinds, and only one is
//! production's:
//!
//! * **`full-store`** is the production path end to end: an on-disk
//!   `LeafStore` with one frozen, pinned segment behind
//!   `StoreShardProvider`. A frozen segment is always a full one, so this
//!   is also the smallest frame production can serve.
//! * **`one-leaf`, `eighth` and `full-memory`** are synthetic bodies from
//!   memory. The first two are sizes production cannot serve today; they
//!   are projections, there to show how cost moves with size. The third
//!   is a full segment without the store's read path.
//!
//! The probe uses only public API that is the same before and after the
//! delivery-digest fold moved to the blocking pool, so one source builds
//! against both arms.
//!
//! The endpoint and a wake-lateness task run on one runtime with four
//! workers; the requesters run on another. A lateness sample is how late a
//! 1 ms sleep woke on the endpoint's runtime, which is what a connection's
//! task waits when a worker thread is held by something that does not
//! yield.
//!
//! Rows (first column is the row kind):
//!
//! ```text
//! OBS      label mode size in_flight micros bytes
//! PHASE    label size phase micros          (phase: read | hash | sign)
//! LATE     label mode size in_flight n p50_us p90_us p99_us p999_us max_us
//! BLOCK    label mode size in_flight n wall_ms cpu_ms served
//! ABANDON  label size provider n cpu_us_per_request loopback_bytes_per_request served_delta
//! ```
//!
//! `BAT5_MODE`: `phase`, `load`, `cold`, `abandon`, `sustain`, `idle`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_archival_retention::pass_anchor::{pass_request_header_bytes, PASS_ANCHOR_DEPTH_BLOCKS};
use shekyl_archival_retention::pass_delivery_digest;
use shekyl_curve_tree::serving_route::encode_request_header;
use shekyl_curve_tree::{
    leaves_per_segment, BlockHeight, Gindex, LeafEntry, LeafStore, OutputIdentity, ServingReader,
    TargetKind,
};
use shekyl_p_serve::{
    PServeEndpoint, PassKey, PassSigner, ProviderError, ShardBody, ShardProvider,
    StoreShardProvider, TestKeySigner, REQUEST_HEADER_NAME, SIGNATURE_ENVELOPE_LEN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};

const OWN_HEIGHT: u64 = 20_000;
const ANCHOR_HEIGHT: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const LEAF_BYTES: usize = 128;
/// The serve loop's chunk size. Private to the crate; restated here only
/// to read the isolated `read` phase at the size the endpoint reads at.
const CHUNK_BYTES: usize = 64 * 1024;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn env_usize(name: &str, default: usize) -> usize {
    env(name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn segment_entries() -> Vec<LeafEntry> {
    (0..leaves_per_segment())
        .map(|i| {
            let gindex = as_u64(i);
            let mut leaf = [1u8; LEAF_BYTES];
            leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
            LeafEntry {
                gindex: Gindex::from_raw(gindex),
                maturity: BlockHeight::from_raw(0),
                creation_height: BlockHeight::from_raw(0),
                leaf,
                identity: OutputIdentity {
                    output_key: shekyl_curve_tree::OneTimePubkey::from_bytes([1u8; 32]),
                    commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes([2u8; 32])),
                    cm: [3u8; 32],
                    target: TargetKind::TaggedKey,
                },
            }
        })
        .collect()
}

/// Shard 0 from the on-disk store, shard 1 and 2 from memory at one leaf
/// and an eighth of a segment, shard 3 a full segment from memory. A
/// frozen segment is always full, so the two smaller sizes cannot come
/// from the store; shard 3 exists so a full segment can be compared with
/// and without the store's read path.
struct Shards {
    store: StoreShardProvider,
    one_leaf: Arc<[u8]>,
    eighth: Arc<[u8]>,
    full: Arc<[u8]>,
}

impl ShardProvider for Shards {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        match shard_id {
            0 => self.store.shard_bytes(0),
            1 => Ok(ShardBody::flat(Arc::clone(&self.one_leaf))),
            2 => Ok(ShardBody::flat(Arc::clone(&self.eighth))),
            3 => Ok(ShardBody::flat(Arc::clone(&self.full))),
            _ => Ok(None),
        }
    }
}

fn synthetic(len: usize) -> Arc<[u8]> {
    let mut state = 0x9e37_79b9_u32;
    let bytes: Vec<u8> = (0..len)
        .map(|_| {
            state = state.wrapping_mul(2_654_435_761).wrapping_add(1);
            state.to_le_bytes()[2]
        })
        .collect();
    Arc::from(bytes.into_boxed_slice())
}

/// A request nonce: `fill` everywhere, with `counter` in its first bytes,
/// so no two requests of a block share one.
fn nonce(fill: u8, counter: usize) -> [u8; 32] {
    let mut nonce = [fill; 32];
    nonce[..8].copy_from_slice(&u64::try_from(counter).expect("a count").to_le_bytes());
    nonce
}

fn as_u64(count: usize) -> u64 {
    u64::try_from(count).expect("a count")
}

fn size_of(shard_id: u64) -> (&'static str, usize) {
    match shard_id {
        0 => ("full-store", leaves_per_segment() * LEAF_BYTES),
        1 => ("one-leaf", LEAF_BYTES),
        2 => ("eighth", leaves_per_segment() / 8 * LEAF_BYTES),
        _ => ("full-memory", leaves_per_segment() * LEAF_BYTES),
    }
}

fn request_head(shard_id: u64, nonce: [u8; 32]) -> Vec<u8> {
    let header = encode_request_header(&pass_request_header_bytes(
        &nonce,
        BlockHeight::from_raw(ANCHOR_HEIGHT),
        &[0xc3; 32],
    ));
    format!("GET /shard/{shard_id} HTTP/1.1\r\nhost: x\r\n{REQUEST_HEADER_NAME}: {header}\r\n\r\n")
        .into_bytes()
}

async fn fetch(addr: SocketAddr, shard_id: u64, nonce: [u8; 32]) -> usize {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(&request_head(shard_id, nonce))
        .await
        .expect("write request");
    let mut out = Vec::with_capacity(size_of(shard_id).1 + 8192);
    s.read_to_end(&mut out).await.expect("read response");
    out.len()
}

/// Send a valid head, read the status line and nothing more, close.
async fn abandon(addr: SocketAddr, shard_id: u64, nonce: [u8; 32]) {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(&request_head(shard_id, nonce))
        .await
        .expect("write request");
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while !seen.ends_with(b"\r\n") {
        let n = s.read(&mut byte).await.expect("read status line");
        assert!(n > 0, "closed before the status line");
        seen.push(byte[0]);
    }
    drop(s);
}

/// CPU time of this whole process, in microseconds: every thread's
/// on-CPU nanoseconds from the scheduler's own accounting.
fn cpu_micros() -> u64 {
    let mut nanos = 0u64;
    for entry in std::fs::read_dir("/proc/self/task").expect("tasks") {
        let path = entry.expect("task").path().join("schedstat");
        if let Ok(text) = std::fs::read_to_string(path) {
            nanos += text
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    nanos / 1_000
}

/// Bytes transmitted on the loopback interface since boot. The probe is
/// the only loopback traffic of any size during a block (the device is
/// held under a quiet claim), so a difference is the bytes the endpoint
/// put on the wire plus the requests and TCP's own headers. The per-process
/// `wchar` counter does not see socket sends, which is why this is used.
fn loopback_bytes() -> u64 {
    std::fs::read_to_string("/sys/class/net/lo/statistics/tx_bytes")
        .expect("lo tx_bytes")
        .trim()
        .parse()
        .expect("a number")
}

fn percentile(sorted: &[u64], per_mille: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) * per_mille) / 1000]
}

/// The endpoint's side: its runtime, the endpoint, and the lateness task.
struct Served {
    runtime: Runtime,
    endpoint: PServeEndpoint,
    signer: Arc<TestKeySigner>,
    provider: Arc<Shards>,
    lateness: Arc<Mutex<Vec<u64>>>,
    sampling: Arc<AtomicBool>,
}

impl Served {
    fn start() -> Self {
        let parent = env("BAT5_STORE").expect("BAT5_STORE = a directory to keep the store under");
        // The probe's own child, so that deleting it between blocks can
        // never take anything else in the directory with it.
        let dir = format!("{parent}/ba-t5-store");
        let store_file = format!("{dir}/leaves.redb");
        // `BAT5_REUSE`: open the store a previous invocation left, without
        // writing it again. A cold block needs this: a store written by
        // this process is in the store's own in-process cache whatever the
        // kernel has dropped, so only a fresh process over an existing
        // file reads from the disk.
        let reuse = env("BAT5_REUSE").is_some() && std::path::Path::new(&store_file).exists();
        if !reuse {
            // The store an earlier block left may or may not be there.
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).expect("mkdir");
        }
        let store = Arc::new(LeafStore::open(&store_file).expect("open store"));
        if !reuse {
            store
                .append_block_deltas(&segment_entries(), &[], &[], BlockHeight::from_raw(10_000))
                .expect("append and freeze segment 0");
            store.pin_serve_set(&[0]).expect("pin");
        }
        let provider = Arc::new(Shards {
            store: StoreShardProvider::new(ServingReader::new(Arc::clone(&store))),
            one_leaf: synthetic(size_of(1).1),
            eighth: synthetic(size_of(2).1),
            full: synthetic(size_of(3).1),
        });
        if !reuse {
            store.prune_frozen(&[]).expect("prune");
        }

        let runtime = Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("endpoint runtime");
        let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
        let endpoint = runtime
            .block_on(PServeEndpoint::bind(
                Arc::clone(&provider) as Arc<dyn ShardProvider>,
                Arc::clone(&signer) as Arc<dyn PassSigner>,
            ))
            .expect("bind");

        let lateness = Arc::new(Mutex::new(Vec::new()));
        let sampling = Arc::new(AtomicBool::new(false));
        let (samples, on) = (Arc::clone(&lateness), Arc::clone(&sampling));
        runtime.spawn(async move {
            let period = Duration::from_millis(1);
            loop {
                // Idle when nothing is sampling, so the task's own wake-ups
                // are not charged to a block that measures CPU.
                if !on.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                let asked = Instant::now();
                tokio::time::sleep(period).await;
                let late = asked.elapsed().saturating_sub(period);
                if on.load(Ordering::Relaxed) {
                    samples
                        .lock()
                        .expect("lateness")
                        .push(u64::try_from(late.as_micros()).unwrap_or(u64::MAX));
                }
            }
        });
        Self {
            runtime,
            endpoint,
            signer,
            provider,
            lateness,
            sampling,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.endpoint.addr()
    }

    fn sample(&self, on: bool) {
        if on {
            self.lateness.lock().expect("lateness").clear();
        }
        self.sampling.store(on, Ordering::Relaxed);
    }

    fn print_lateness(&self, label: &str, mode: &str, size: &str, in_flight: usize) {
        let mut v = std::mem::take(&mut *self.lateness.lock().expect("lateness"));
        v.sort_unstable();
        println!(
            "LATE\t{label}\t{mode}\t{size}\t{in_flight}\t{}\t{}\t{}\t{}\t{}\t{}",
            v.len(),
            percentile(&v, 500),
            percentile(&v, 900),
            percentile(&v, 990),
            percentile(&v, 999),
            v.last().copied().unwrap_or(0),
        );
    }
}

fn requesters() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("requester runtime")
}

/// One timed block: which shard, how many fetches, how many at once.
#[derive(Clone, Copy)]
struct Block<'a> {
    label: &'a str,
    mode: &'a str,
    shard_id: u64,
    in_flight: usize,
    n: usize,
    warm_up: usize,
}

/// `n` whole fetches of one shard at `in_flight`, timed each, with
/// lateness sampled across the block.
fn timed_block(served: &Served, clients: &Runtime, block: Block<'_>) {
    let Block {
        label,
        mode,
        shard_id,
        in_flight,
        n,
        warm_up,
    } = block;
    let addr = served.addr();
    let (size, payload) = size_of(shard_id);
    let whole = payload + SIGNATURE_ENVELOPE_LEN;
    clients.block_on(async {
        for i in 0..warm_up {
            let got = fetch(addr, shard_id, nonce(0x11, i)).await;
            assert!(got > whole, "short response: {got}");
        }
    });
    let served_before = served.endpoint.served_count();
    served.sample(true);
    let cpu0 = cpu_micros();
    let t0 = Instant::now();
    clients.block_on(async {
        let mut k = 0usize;
        while k < n {
            let batch = in_flight.min(n - k);
            let mut joins = Vec::new();
            for b in 0..batch {
                let nonce = nonce(0x5a, k + b);
                joins.push(tokio::spawn(async move {
                    let s = Instant::now();
                    let got = fetch(addr, shard_id, nonce).await;
                    (s.elapsed().as_micros(), got)
                }));
            }
            for j in joins {
                let (us, got) = j.await.expect("join");
                assert!(got > whole, "short response: {got}");
                println!("OBS\t{label}\t{mode}\t{size}\t{in_flight}\t{us}\t{got}");
            }
            k += batch;
        }
    });
    let wall_ms = t0.elapsed().as_millis();
    let cpu_ms = (cpu_micros() - cpu0) / 1_000;
    served.sample(false);
    println!(
        "BLOCK\t{label}\t{mode}\t{size}\t{in_flight}\t{n}\t{wall_ms}\t{cpu_ms}\t{}",
        served.endpoint.served_count() - served_before
    );
    served.print_lateness(label, mode, size, in_flight);
}

/// The three costs a response is made of, each alone, on this thread:
/// reading the shard at the serve loop's chunk size, the delivery digest
/// over the framed bytes, and one countersignature.
fn isolated_phases(served: &Served, label: &str, n: usize) {
    for shard_id in [1u64, 2, 0] {
        let (size, payload) = size_of(shard_id);
        let mut framed = Vec::with_capacity(payload + 16);
        for _ in 0..n {
            let t = Instant::now();
            let mut body = served
                .provider
                .shard_bytes(shard_id)
                .expect("open")
                .expect("held");
            framed.clear();
            while let Some(chunk) = body.next_chunk(CHUNK_BYTES).expect("read") {
                framed.extend_from_slice(&chunk);
            }
            println!("PHASE\t{label}\t{size}\tread\t{}", t.elapsed().as_micros());
            assert_eq!(framed.len(), payload);
        }
        for i in 0..n {
            let t = Instant::now();
            let digest = pass_delivery_digest(&nonce(0x22, i), &framed);
            println!("PHASE\t{label}\t{size}\thash\t{}", t.elapsed().as_micros());
            assert_ne!(digest, [0u8; 32]);
        }
    }
    for i in 0..n {
        let mut message = [0x33u8; 112];
        message[..32].copy_from_slice(&nonce(0x33, i));
        let t = Instant::now();
        let signature = served.signer.sign_pass(&message).expect("sign");
        println!("PHASE\t{label}\tany\tsign\t{}", t.elapsed().as_micros());
        drop(signature);
    }
}

#[test]
#[ignore = "BA-T5 floor probe: a measurement, run by hand with BAT5_MODE set"]
fn ba_t5_floor_probe() {
    let mode = env("BAT5_MODE").expect("BAT5_MODE");
    let label = env("BAT5_LABEL").unwrap_or_default();
    let served = Served::start();
    let clients = requesters();
    let addr = served.addr();

    match mode.as_str() {
        // One in flight at three sizes, and the phases alone.
        "phase" => {
            let n = env_usize("BAT5_N", 50);
            for shard_id in [0u64, 2, 1] {
                timed_block(
                    &served,
                    &clients,
                    Block {
                        label: &label,
                        mode: "phase",
                        shard_id,
                        in_flight: 1,
                        n,
                        warm_up: 5,
                    },
                );
            }
            isolated_phases(&served, &label, env_usize("BAT5_PHASE_N", 25));
        }
        // Eight in flight, full segment from the store: throughput and
        // executor wake lateness.
        "load" => {
            let n = env_usize("BAT5_N", 128);
            let in_flight = env_usize("BAT5_IN_FLIGHT", 8);
            timed_block(
                &served,
                &clients,
                Block {
                    label: &label,
                    mode: "load",
                    shard_id: 0,
                    in_flight,
                    n,
                    warm_up: 5,
                },
            );
        }
        // One whole fetch, first thing this process does. Run with
        // `BAT5_REUSE` over a store whose pages the caller has just dropped
        // from the page cache, it is a read from the disk.
        "cold" => {
            let whole = size_of(0).1 + SIGNATURE_ENVELOPE_LEN;
            let t = Instant::now();
            let got = clients.block_on(fetch(addr, 0, nonce(0x44, 0)));
            assert!(got > whole, "short response: {got}");
            println!(
                "OBS\t{label}\tcold\tfull-store\t1\t{}\t{got}",
                t.elapsed().as_micros()
            );
        }
        // A requester that reads the status line and closes. CPU and bytes
        // written per abandoned request, at the smallest frame and at a
        // full segment; and the same requester against a shard that is not
        // held, as the cost of a request that serves nothing.
        "abandon" => {
            let n = env_usize("BAT5_N", 200);
            for (shard_id, provider) in [(9u64, "none"), (1, "memory"), (3, "memory"), (0, "store")]
            {
                let size = if shard_id == 9 {
                    "not-held"
                } else {
                    size_of(shard_id).0
                };
                // Settle: let the endpoint finish whatever came before.
                std::thread::sleep(Duration::from_millis(500));
                let served_before = served.endpoint.served_count();
                let (cpu0, w0) = (cpu_micros(), loopback_bytes());
                clients.block_on(async {
                    for i in 0..n {
                        abandon(addr, shard_id, nonce(0xa5, i)).await;
                        // Let the endpoint notice the close before the next.
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                });
                std::thread::sleep(Duration::from_millis(500));
                let (cpu, written) = (cpu_micros() - cpu0, loopback_bytes() - w0);
                println!(
                    "ABANDON\t{label}\t{size}\t{provider}\t{n}\t{}\t{}\t{}",
                    cpu / as_u64(n),
                    written / as_u64(n),
                    served.endpoint.served_count() - served_before
                );
            }
        }
        // A steady rate for a long time: one whole fetch every period,
        // each timed, lateness summarised per minute.
        "sustain" => {
            let seconds = env_usize("BAT5_SECONDS", 3600);
            let period = Duration::from_millis(as_u64(env_usize("BAT5_PERIOD_MS", 2000)));
            let whole = size_of(0).1 + SIGNATURE_ENVELOPE_LEN;
            let start = Instant::now();
            let cpu0 = cpu_micros();
            let mut i = 0usize;
            let mut minute = 0u64;
            served.sample(true);
            while start.elapsed() < Duration::from_secs(as_u64(seconds)) {
                let due = start + period * u32::try_from(i).expect("a fetch count");
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    std::thread::sleep(wait);
                }
                let t = Instant::now();
                let got = clients.block_on(fetch(addr, 0, nonce(0x77, i)));
                assert!(got > whole, "short response: {got}");
                println!(
                    "OBS\t{label}\tsustain\tfull-store\t1\t{}\t{got}",
                    t.elapsed().as_micros()
                );
                i += 1;
                if start.elapsed().as_secs() / 60 > minute {
                    minute = start.elapsed().as_secs() / 60;
                    served.sampling.store(false, Ordering::Relaxed);
                    served.print_lateness(
                        &format!("{label}.m{minute}"),
                        "sustain",
                        "full-store",
                        1,
                    );
                    served.sample(true);
                }
            }
            served.sample(false);
            println!(
                "BLOCK\t{label}\tsustain\tfull-store\t1\t{i}\t{}\t{}\t{}",
                start.elapsed().as_millis(),
                (cpu_micros() - cpu0) / 1_000,
                served.endpoint.served_count()
            );
        }
        // Nothing served: what the lateness task reads on an idle endpoint.
        "idle" => {
            served.sample(true);
            std::thread::sleep(Duration::from_secs(as_u64(env_usize("BAT5_SECONDS", 10))));
            served.sample(false);
            served.print_lateness(&label, "idle", "none", 0);
        }
        other => panic!("unknown BAT5_MODE {other:?}"),
    }
    drop(served.runtime);
}
