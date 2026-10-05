# `SF-D8` v3 serve cost on the floor device, 2026-10-05

What the pass countersignature's delivery digest costs `P` per response on a
Pi 4. PR #954 made `P` read a shard twice and digest it on both reads
(`ARCHIVAL_SHARD_FETCH.md` `SF-D8`); PR #961 folded both reads through one
`FramedDigest`. This prices that against the serve path as it was before.

## Reading

One full segment, 3,326,976 B of payload (3,330,449 B on the wire with head,
frame and signature). Per-response time from connect to end of stream.

Run 2, three arms in one window (15:55:26Z – 16:06:57Z):

| Arm | Tree | 1 in flight: median / mean / p95 (n = 200) | CPU per response | 8 in flight: median (n = 128) | 8 in flight: responses per second |
| --- | --- | --- | --- | --- | --- |
| before | `b5d563a2fe` (parent of the #954 merge) | 24.8 / 25.6 / 32.8 ms | 30–36 ms | 90.9 ms | 74–84 |
| #954 | `cd51261ab2` | 104.2 / 104.3 / 109.7 ms | 112–113 ms | 201.3 ms | 37–38 |
| #961 | `b5e7dbfed5` | 103.1 / 103.5 / 108.3 ms | 110–113 ms | 200.2 ms | 37–38 |

- **Cost per response: 78 ms** (103.1 − 24.8, medians, one in flight), all of
  it CPU. #961 did not move it.
- Run 1 (11:51:10Z – 11:58:46Z, the first two arms only) read 22.9 ms and
  103.5 ms, a difference of 81 ms.
- The digest alone over one framed segment: 23.9 ms median (n = 50, run 1,
  range 23.8 – 24.2). The serve path computes it twice. The remaining 30 ms or
  so was not separately timed; the second store read is part of it.
- Against `U1b`'s reads of the same object over Tor from the same device
  (`u1b_floor_device_20261002.tsv`, 608 completed at 1×: median 14.8 s, fastest
  6.5 s), 78 ms is 0.5 % of the median read and 1.2 % of the fastest.

## What ran

The production serving path: an on-disk `LeafStore` with one frozen, pinned
segment, `StoreShardProvider`, `PServeEndpoint` with the test signer,
answering `GET /shard/0` over loopback. The reader counts bytes and checks
the length; it verifies nothing, so its own cost is the same in every arm. One
probe source, built with `cargo test --release --locked` against each tree on
the device (rustc 1.94.0, aarch64). It uses nothing #954 or #961 changed.

Each block opens a fresh store, discards 5 fetches, then times 50 at one in
flight or 64 at eight in flight. Arms alternate within a round: four rounds at
one in flight, then two at eight. Every block exited 0. Board temperature
53 – 62 °C across both runs; run 1 started straight after its builds, run 2
after a five-minute pause.

The shape, the reading above and the void conditions were written into the run
scripts on the device before each run's first observation. There is no
threshold: this prices a change and is not a verdict on `W`.

## What this does not cover

- **A cold page cache.** The store is written seconds before it is read, and
  the device gives no way to drop caches without root. Both reads of a shard
  were served from memory. A `P` whose shard is not cached pays the first
  read from disk in either tree; whether its second read is still cached
  depends on memory pressure this run did not apply.
- **Tor.** Loopback only. The comparison against `U1b` above sets this cost
  beside a Tor read; it does not measure the two together.
- **A daemon beside it.** Nothing else ran on the device.
- **`U1b` reading B.** The 18,229 pairs per epoch figure was not re-measured.

## Files

- `sfd8_serve_cost_floor_device_run1_20261005.tsv`
  (sha256 `d052f51420812df365599d597335ef6dc67f62fff1ba50968a0e4ebb9ba82fb7`)
- `sfd8_serve_cost_floor_device_run2_20261005.tsv`
  (sha256 `77985e2ef7688616606bf1c4921a89641ae714847c6830d580086945b8f4b43d`)

Rows: `OBS`, arm.round, in flight, microseconds, bytes received.
`BLOCK`, arm.round, in flight, fetches, wall ms, CPU ticks (10 ms each, the
whole process after warm-up), responses served including warm-up.
`DIGEST`, microseconds, first digest byte. Arm labels in the files: `old` is
"before", `new` is #954, `cur` is #961.

## The probe

Placed in `rust/shekyl-p-serve/tests/` of each tree for the build, and not
committed there. `SFD8_STORE` names a scratch directory.

```rust
// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Throwaway timing probe (not committed): the production serving path —
//! on-disk `LeafStore` → `StoreShardProvider` → `PServeEndpoint` → loopback —
//! serving one full segment, timed per fetch. Same source builds against the
//! tree before and after the SF-D8 v3 change; it reads bytes and checks only
//! the length, so it depends on nothing that change touched.
#![allow(clippy::all, clippy::pedantic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use shekyl_archival_retention::pass_anchor::{pass_request_header_bytes, PASS_ANCHOR_DEPTH_BLOCKS};
use shekyl_curve_tree::serving_route::encode_request_header;
use shekyl_curve_tree::{
    leaves_per_segment, BlockHeight, Gindex, LeafEntry, LeafStore, OutputIdentity, ServingReader,
    TargetKind,
};
use shekyl_p_serve::{
    PServeEndpoint, PassSigner, StoreShardProvider, TestKeySigner, REQUEST_HEADER_NAME,
    SIGNATURE_ENVELOPE_LEN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const OWN_HEIGHT: u64 = 20_000;
const ANCHOR_HEIGHT: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

fn segment_entries() -> Vec<LeafEntry> {
    (0..leaves_per_segment())
        .map(|i| {
            let gindex = i as u64;
            let mut leaf = [1u8; 128];
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

async fn fetch(addr: SocketAddr, nonce: [u8; 32]) -> usize {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let header = encode_request_header(&pass_request_header_bytes(
        &nonce,
        BlockHeight::from_raw(ANCHOR_HEIGHT),
        &[0xc3; 32],
    ));
    s.write_all(
        format!("GET /shard/0 HTTP/1.1\r\nhost: x\r\n{REQUEST_HEADER_NAME}: {header}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .expect("write request");
    let mut out = Vec::with_capacity(3_400_000);
    s.read_to_end(&mut out).await.expect("read response");
    out.len()
}

/// utime + stime of this process, in clock ticks.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("stat");
    let rest = &stat[stat.rfind(')').expect("comm") + 2..];
    let f: Vec<&str> = rest.split(' ').collect();
    f[11].parse::<u64>().expect("utime") + f[12].parse::<u64>().expect("stime")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cost_probe() {
    let dir = std::env::var("SFD8_STORE").expect("SFD8_STORE = a fresh directory for the store");
    let n: usize = std::env::var("SFD8_N").ok().and_then(|v| v.parse().ok()).unwrap_or(50);
    let conc: usize = std::env::var("SFD8_CONC").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let label = std::env::var("SFD8_LABEL").unwrap_or_default();

    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let store = Arc::new(LeafStore::open(format!("{dir}/leaves.redb")).expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight::from_raw(10_000))
        .expect("append and freeze segment 0");
    store.pin_serve_set(&[0]).expect("pin");
    let provider = StoreShardProvider::new(ServingReader::new(Arc::clone(&store)));
    store.prune_frozen(&[]).expect("prune");

    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let ep = PServeEndpoint::bind(Arc::new(provider), signer as Arc<dyn PassSigner>)
        .await
        .expect("bind");
    let addr = ep.addr();

    let payload = leaves_per_segment() * 128;
    let mut expect_min = payload + SIGNATURE_ENVELOPE_LEN;
    // Warm-up, discarded: 5 fetches.
    for i in 0..5u8 {
        let got = fetch(addr, [i; 32]).await;
        assert!(got > expect_min, "short response: {got}");
        expect_min = expect_min.max(got - 1);
    }

    let c0 = cpu_ticks();
    let t0 = Instant::now();
    let mut k = 0u32;
    while (k as usize) < n {
        let batch = conc.min(n - k as usize);
        let started = Instant::now();
        let mut joins = Vec::new();
        for b in 0..batch {
            let mut nonce = [0x5a; 32];
            nonce[..4].copy_from_slice(&(k + b as u32).to_le_bytes());
            joins.push(tokio::spawn(async move {
                let s = Instant::now();
                let got = fetch(addr, nonce).await;
                (s.elapsed().as_micros(), got)
            }));
        }
        for j in joins {
            let (us, got) = j.await.expect("join");
            assert!(got > expect_min, "short response: {got}");
            println!("OBS\t{label}\t{conc}\t{us}\t{got}");
        }
        let _ = started;
        k += batch as u32;
    }
    let wall_ms = t0.elapsed().as_millis();
    let ticks = cpu_ticks() - c0;
    println!("BLOCK\t{label}\t{conc}\t{n}\t{wall_ms}\t{ticks}\t{}", ep.served_count());
}
```

The digest timing, built against the #954 tree only:

```rust
// Throwaway timing probe (not committed): the delivery digest alone over one
// framed full segment.
#![allow(clippy::all, clippy::pedantic)]
use std::time::Instant;

use shekyl_archival_retention::pass_delivery_digest;

#[test]
fn cost_digest() {
    let framed: Vec<u8> = (0..3_326_980u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    for i in 0..50u8 {
        let t = Instant::now();
        let d = pass_delivery_digest(&[i; 32], &framed);
        println!("DIGEST\t{}\t{}", t.elapsed().as_micros(), d[0]);
    }
}
```
