// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! libzstd level 1 against ruzstd `Fastest` on the Levin messages the relay
//! compresses (Rick, 2026-10-19): "Before the swap, measure on the Rust
//! path: ratio and throughput vs libzstd level 1 on real block/tx payloads,
//! Pi decode time for a full block."
//!
//! The corpus is `shekyl-engine-core`'s `zstd_corpus_capture` output. From
//! its blobs this builds the payloads the relay hands to
//! [`shekyl_levin::compress_payload`]:
//!
//! - `tx`: one `NOTIFY_NEW_TRANSACTIONS` per pool body (fluff, no padding:
//!   a padded notification is never compressed, `--pad-transactions`);
//! - `tx-batch`: every pool body in one notification;
//! - `compact`: one `NOTIFY_NEW_COMPACT_BLOCK` per block, bodies included;
//! - `compact-header`: the same with no bodies;
//! - `objects`: one `RESPONSE_GET_OBJECTS` per block, bodies included;
//! - `objects-batch`: every kept block in one response, as sync sends them.
//!
//! The libzstd arm is the production path (`compress_payload`,
//! `inflated_size`, `decompress_into`). The ruzstd arm is
//! `compress_to_vec(_, Fastest)` and `FrameDecoder::decode_all` into a
//! buffer sized from the declared content size, the same shape. ruzstd
//! 0.9.1 writes no `Frame_Content_Size` (its encoder hard-codes `None`), so
//! the receive guard would refuse every frame it makes; the `+fcs` column is
//! the frame with that field written in (RFC 8878 §3.1.1.1.1), and every
//! such frame is decoded by the production libzstd path as the oracle.
//!
//! Usage:
//!
//! ```text
//! cargo run --release -p shekyl-levin --example zstd_corpus_compare -- \
//!     compare <corpus> <report.tsv>
//! cargo run --release -p shekyl-levin --example zstd_corpus_compare -- \
//!     emit <corpus> <dir>      # the full block's frames, for the Pi
//! cargo run --release -p shekyl-levin --example zstd_corpus_compare -- \
//!     decode <dir>             # time both decoders on those frames
//! ```
//!
//! A measurement tool, not a test: it asserts what the numbers rest on
//! (every decode returns the input) and prints the numbers.

// Byte counts and nanosecond timings here stay far below 2^52, so the float
// conversions for ratios and rates lose nothing.
#![allow(clippy::cast_precision_loss)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ruzstd::decoding::FrameDecoder;
use ruzstd::encoding::{compress_to_vec, CompressionLevel};
use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_levin::{
    compress_payload, decompress_into, inflated_size, BasicNodeData, BlockCompleteEntry,
    CoreSyncData, HandshakeRequest, HandshakeResponse, NetworkAddress, NewCompactBlock,
    NewTransactions, PeerlistEntry, PortableMap, ResponseGetObjects, SupportFlags,
    TimedSyncRequest, TimedSyncResponse, TxBlobEntry, COMPRESSION_MIN_PAYLOAD,
    DECOMPRESSED_MAX_SIZE, HASH_SIZE,
};
use shekyl_peer_bounds::DISCLOSE_COUNT;

/// `0xFD2FB528`, little-endian on the wire.
const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// How long each timed operation runs, at least.
const BUDGET: Duration = Duration::from_millis(60);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("compare") if args.len() == 4 => compare(Path::new(&args[2]), Path::new(&args[3])),
        Some("emit") if args.len() == 4 => emit(Path::new(&args[2]), Path::new(&args[3])),
        Some("decode") if args.len() == 3 => decode(Path::new(&args[2])),
        Some("peers") if args.len() == 3 => peers(Path::new(&args[2])),
        _ => {
            eprintln!(
                "usage: zstd_corpus_compare compare <corpus> <report.tsv>\n\
                 \x20      zstd_corpus_compare emit <corpus> <dir>\n\
                 \x20      zstd_corpus_compare decode <dir>\n\
                 \x20      zstd_corpus_compare peers <report.tsv>"
            );
            std::process::exit(2);
        }
    }
}

/// One payload the relay would compress.
struct Payload {
    class: &'static str,
    name: String,
    bytes: Vec<u8>,
}

/// One payload's numbers.
struct Row {
    class: &'static str,
    name: String,
    input: usize,
    lib: usize,
    lib_sent: bool,
    ru: usize,
    ru_fcs: usize,
    ru_sent: bool,
    lib_c_ns: f64,
    ru_c_ns: f64,
    lib_d_ns: f64,
    ru_d_ns: f64,
    ru_d_lib_ns: f64,
}

fn compare(corpus: &Path, report: &Path) {
    let mut about = vec![format!("corpus: {}", corpus.display())];
    if let Ok(p) = std::fs::read_to_string(corpus.join("provenance")) {
        about.extend(p.lines().map(|line| format!("  {line}")));
    }
    run(&payloads(corpus), report, &about);
}

/// Measure `payloads`, write the TSV to `report`, print the summary.
fn run(payloads: &[Payload], report: &Path, about: &[String]) -> Vec<Row> {
    let mut rows = Vec::new();
    for p in payloads {
        rows.push(measure(p));
    }
    let mut tsv = String::from(
        "class\tname\tinput\tlibzstd1\tlib_sent\truzstd\truzstd_fcs\tru_sent\t\
         lib_compress_ns\tru_compress_ns\tlib_decode_ns\tru_decode_ns\tru_decode_libframe_ns\n",
    );
    for r in &rows {
        writeln!(
            tsv,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{:.0}",
            r.class,
            r.name,
            r.input,
            r.lib,
            r.lib_sent,
            r.ru,
            r.ru_fcs,
            r.ru_sent,
            r.lib_c_ns,
            r.ru_c_ns,
            r.lib_d_ns,
            r.ru_d_ns,
            r.ru_d_lib_ns
        )
        .expect("write to a String");
    }
    std::fs::write(report, tsv).expect("write the report");

    for line in about {
        println!("{line}");
    }
    println!(
        "\n{:<15} {:>4} {:>11} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "class",
        "n",
        "input B",
        "lib1 %",
        "ru %",
        "ru+fcs %",
        "sent l/r",
        "c lib",
        "c ru",
        "d lib",
        "d ru",
        "d ru(lib)"
    );
    println!(
        "{:<15} {:>4} {:>11} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "", "", "", "of input", "", "", "", "MB/s", "MB/s", "MB/s", "MB/s", "MB/s"
    );
    let mut classes: Vec<&str> = rows.iter().map(|r| r.class).collect();
    classes.dedup();
    for class in classes {
        let of: Vec<&Row> = rows.iter().filter(|r| r.class == class).collect();
        let input: usize = of.iter().map(|r| r.input).sum();
        let lib: usize = of.iter().map(|r| r.lib).sum();
        let ru: usize = of.iter().map(|r| r.ru).sum();
        let ru_fcs: usize = of.iter().map(|r| r.ru_fcs).sum();
        let lib_sent = of.iter().filter(|r| r.lib_sent).count();
        let ru_sent = of.iter().filter(|r| r.ru_sent).count();
        let mbps = |ns: f64| input as f64 / ns * 1e3;
        let sum = |f: fn(&Row) -> f64| of.iter().map(|r| f(r)).sum::<f64>();
        println!(
            "{:<15} {:>4} {:>11} {:>7.2}% {:>7.2}% {:>7.2}% {:>4}/{:<4} {:>9.0} {:>9.0} {:>9.0} {:>9.0} {:>9.0}",
            class,
            of.len(),
            input,
            pct(lib, input),
            pct(ru, input),
            pct(ru_fcs, input),
            lib_sent,
            ru_sent,
            mbps(sum(|r| r.lib_c_ns)),
            mbps(sum(|r| r.ru_c_ns)),
            mbps(sum(|r| r.lib_d_ns)),
            mbps(sum(|r| r.ru_d_ns)),
            mbps(sum(|r| r.ru_d_lib_ns)),
        );
    }
    let disagree: Vec<&Row> = rows.iter().filter(|r| r.lib_sent != r.ru_sent).collect();
    println!(
        "\npayloads where the send decision differs (libzstd sent vs ruzstd+fcs sent): {}",
        disagree.len()
    );
    for r in disagree {
        println!(
            "  {} {}: input {}, libzstd {} ({}), ruzstd+fcs {} ({})",
            r.class,
            r.name,
            r.input,
            r.lib,
            sent(r.lib_sent),
            r.ru_fcs,
            sent(r.ru_sent)
        );
    }
    println!(
        "\nevery decode checked against the input: libzstd(libzstd), libzstd(ruzstd+fcs), \
         ruzstd(ruzstd), ruzstd(libzstd); the production receive guard refused every raw \
         ruzstd frame ({} of {}).",
        rows.len(),
        rows.len()
    );
    println!("report: {}", report.display());
    rows
}

fn measure(p: &Payload) -> Row {
    let input = &p.bytes;
    // libzstd, through production: the decision and the frame it sends.
    let decided = compress_payload(input).expect("a corpus payload is under the plaintext bound");
    let lib_frame = zstd::bulk::compress(input, shekyl_levin::ZSTD_COMPRESSION_LEVEL)
        .expect("libzstd compresses");
    let lib_sent = decided.is_some();
    if let Some(sent_frame) = &decided {
        assert_eq!(sent_frame, &lib_frame, "{}: production frame", p.name);
    }
    // ruzstd Fastest, the frame as it comes and with the content size written.
    let ru_frame = ruzstd_compress(input);
    let ru_fcs_frame = with_content_size(&ru_frame, input.len() as u64);
    let ru_sent = input.len() >= COMPRESSION_MIN_PAYLOAD && ru_fcs_frame.len() < input.len();

    // The four decodes the numbers rest on, and the guard's refusal.
    assert_eq!(
        &lib_decode(&lib_frame),
        input,
        "{}: libzstd(libzstd)",
        p.name
    );
    assert_eq!(
        &lib_decode(&ru_fcs_frame),
        input,
        "{}: libzstd(ruzstd+fcs)",
        p.name
    );
    assert_eq!(
        &ru_decode(&ru_fcs_frame),
        input,
        "{}: ruzstd(ruzstd+fcs)",
        p.name
    );
    assert_eq!(&ru_decode(&lib_frame), input, "{}: ruzstd(libzstd)", p.name);
    assert!(
        inflated_size(&ru_frame, DECOMPRESSED_MAX_SIZE).is_err(),
        "{}: the receive guard accepted a frame with no content size",
        p.name
    );

    Row {
        class: p.class,
        name: p.name.clone(),
        input: input.len(),
        lib: lib_frame.len(),
        lib_sent,
        ru: ru_frame.len(),
        ru_fcs: ru_fcs_frame.len(),
        ru_sent,
        lib_c_ns: time(|| zstd::bulk::compress(input, 1).expect("libzstd compresses")),
        ru_c_ns: time(|| ruzstd_compress(input)),
        lib_d_ns: time(|| lib_decode(&lib_frame)),
        ru_d_ns: time(|| ru_decode(&ru_fcs_frame)),
        ru_d_lib_ns: time(|| ru_decode(&lib_frame)),
    }
}

fn ruzstd_compress(input: &[u8]) -> Vec<u8> {
    compress_to_vec(input, CompressionLevel::Fastest)
}

/// The production receive path: the declared-size guard, then the inflate.
fn lib_decode(frame: &[u8]) -> Vec<u8> {
    let size = inflated_size(frame, DECOMPRESSED_MAX_SIZE).expect("the guard reads a size");
    let mut out = vec![0u8; size];
    decompress_into(frame, &mut out).expect("libzstd inflates");
    out
}

/// ruzstd in the same shape: the declared size from its header read, a
/// buffer of that size, one `decode_all`. A frame with no size reads as 0
/// in ruzstd's API, indistinguishable from a declared 0.
fn ru_decode(frame: &[u8]) -> Vec<u8> {
    let mut decoder = FrameDecoder::new();
    decoder.init(frame).expect("ruzstd reads the frame header");
    let size = decoder.content_size();
    assert!(
        size > 0 && size <= DECOMPRESSED_MAX_SIZE,
        "a declared size in bounds"
    );
    let mut out = vec![0u8; usize::try_from(size).expect("bounded")];
    let written = decoder
        .decode_all(frame, &mut out)
        .expect("ruzstd inflates");
    assert_eq!(written, out.len(), "ruzstd wrote the declared size");
    out
}

/// Write `Frame_Content_Size` into a ruzstd frame header (RFC 8878
/// §3.1.1.1). ruzstd 0.9.1 writes the magic, a descriptor of 0 (no content
/// size, not single-segment, no checksum without the `hash` feature, no
/// dictionary) and one window byte; the size goes after the window byte,
/// in the smallest field that holds it.
fn with_content_size(frame: &[u8], size: u64) -> Vec<u8> {
    assert_eq!(frame[..4], MAGIC, "a zstd frame");
    assert_eq!(
        frame[4], 0,
        "ruzstd's descriptor: no size, checksum or dictionary"
    );
    let (flag, field): (u8, Vec<u8>) = if (256..=65_791).contains(&size) {
        (
            1,
            u16::try_from(size - 256)
                .expect("in range")
                .to_le_bytes()
                .to_vec(),
        )
    } else if let Ok(small) = u32::try_from(size) {
        (2, small.to_le_bytes().to_vec())
    } else {
        (3, size.to_le_bytes().to_vec())
    };
    let mut out = Vec::with_capacity(frame.len() + field.len());
    out.extend_from_slice(&frame[..4]);
    out.push(flag << 6);
    out.push(frame[5]);
    out.extend_from_slice(&field);
    out.extend_from_slice(&frame[6..]);
    out
}

/// The median of enough runs of `f` to fill [`BUDGET`], in nanoseconds.
fn time<T>(mut f: impl FnMut() -> T) -> f64 {
    for _ in 0..2 {
        std::hint::black_box(f());
    }
    let start = Instant::now();
    std::hint::black_box(f());
    let once = start.elapsed().max(Duration::from_nanos(1));
    let runs = (BUDGET.as_nanos() / once.as_nanos()).clamp(5, 5_000) as usize;
    let mut samples: Vec<u128> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            std::hint::black_box(f());
            t.elapsed().as_nanos()
        })
        .collect();
    samples.sort_unstable();
    samples[samples.len() / 2] as f64
}

fn pct(part: usize, whole: usize) -> f64 {
    part as f64 * 100.0 / whole as f64
}

fn sent(yes: bool) -> &'static str {
    if yes {
        "sent compressed"
    } else {
        "sent plain"
    }
}

/// A kept block: its blob and its bodies.
struct Kept {
    height: u64,
    block: Vec<u8>,
    txs: Vec<Vec<u8>>,
}

fn entry(k: &Kept, with_bodies: bool) -> BlockCompleteEntry {
    let txs: Vec<TxBlobEntry> = if with_bodies {
        k.txs
            .iter()
            .map(|blob| TxBlobEntry {
                blob: blob.clone(),
                prunable_hash: [0u8; HASH_SIZE],
            })
            .collect()
    } else {
        Vec::new()
    };
    let weight = k.block.len() + k.txs.iter().map(Vec::len).sum::<usize>();
    BlockCompleteEntry {
        pruned: false,
        block: k.block.clone(),
        block_weight: weight as u64,
        txs,
        attestation_witness: Vec::new(),
    }
}

fn kept_blocks(corpus: &Path) -> Vec<Kept> {
    let mut kept: Vec<Kept> = std::fs::read_dir(corpus.join("blocks"))
        .expect("the corpus's blocks")
        .map(|e| {
            let dir = e.expect("a block dir").path();
            let height = dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse().ok())
                .expect("a block dir is named by height");
            let mut txs: Vec<(usize, Vec<u8>)> = std::fs::read_dir(&dir)
                .expect("a block dir")
                .filter_map(|f| {
                    let path = f.expect("a block file").path();
                    let name = path.file_name()?.to_str()?.to_owned();
                    let i = name
                        .strip_prefix("tx_")?
                        .strip_suffix(".bin")?
                        .parse()
                        .ok()?;
                    Some((i, std::fs::read(&path).expect("a block tx")))
                })
                .collect();
            txs.sort_by_key(|(i, _)| *i);
            Kept {
                height,
                block: std::fs::read(dir.join("block.bin")).expect("block.bin"),
                txs: txs.into_iter().map(|(_, b)| b).collect(),
            }
        })
        .collect();
    kept.sort_by_key(|k| k.height);
    kept
}

fn pool(corpus: &Path) -> Vec<Vec<u8>> {
    let mut pool: Vec<(usize, Vec<u8>)> = std::fs::read_dir(corpus.join("pool"))
        .expect("the corpus's pool")
        .map(|e| {
            let path = e.expect("a pool file").path();
            let n = path
                .file_stem()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse().ok())
                .expect("a pool body is named by index");
            (n, std::fs::read(&path).expect("a pool body"))
        })
        .collect();
    pool.sort_by_key(|(n, _)| *n);
    pool.into_iter().map(|(_, b)| b).collect()
}

fn tip(kept: &[Kept]) -> u64 {
    kept.last().map_or(0, |k| k.height + 1)
}

fn payloads(corpus: &Path) -> Vec<Payload> {
    let pool = pool(corpus);
    let kept = kept_blocks(corpus);
    let height = tip(&kept);
    let mut out = Vec::new();
    let notify = |txs: Vec<Vec<u8>>| {
        NewTransactions {
            txs,
            padding: Vec::new(),
            dandelionpp_fluff: true,
        }
        .store()
        .expect("store a tx notification")
    };
    for (n, body) in pool.iter().enumerate() {
        out.push(Payload {
            class: "tx",
            name: format!("pool/{n}"),
            bytes: notify(vec![body.clone()]),
        });
    }
    out.push(Payload {
        class: "tx-batch",
        name: format!("pool/all-{}", pool.len()),
        bytes: notify(pool.clone()),
    });
    for (class, bodies) in [("compact", true), ("compact-header", false)] {
        for k in &kept {
            out.push(Payload {
                class,
                name: format!("block/{}", k.height),
                bytes: NewCompactBlock {
                    b: entry(k, bodies),
                    current_blockchain_height: height,
                }
                .store()
                .expect("store a compact block"),
            });
        }
    }
    for k in &kept {
        out.push(Payload {
            class: "objects",
            name: format!("block/{}", k.height),
            bytes: objects(&[k], height),
        });
    }
    let all: Vec<&Kept> = kept.iter().collect();
    out.push(Payload {
        class: "objects-batch",
        name: format!("blocks/all-{}", kept.len()),
        bytes: objects(&all, height),
    });
    out
}

fn objects(blocks: &[&Kept], height: u64) -> Vec<u8> {
    ResponseGetObjects {
        blocks: blocks.iter().map(|k| entry(k, true)).collect(),
        missed_ids: Vec::new(),
        current_blockchain_height: height,
    }
    .store()
    .expect("store a get-objects response")
}

/// The full block's `RESPONSE_GET_OBJECTS` payload and its two frames.
fn emit(corpus: &Path, dir: &Path) {
    let full: u64 = std::fs::read_to_string(corpus.join("full"))
        .expect("the corpus's full height")
        .trim()
        .parse()
        .expect("a height");
    let kept = kept_blocks(corpus);
    let block = kept
        .iter()
        .find(|k| k.height == full)
        .expect("the full block is kept");
    let payload = objects(&[block], tip(&kept));
    let lib = zstd::bulk::compress(&payload, 1).expect("libzstd compresses");
    let ru = with_content_size(&ruzstd_compress(&payload), payload.len() as u64);
    assert_eq!(lib_decode(&ru), payload);
    assert_eq!(ru_decode(&lib), payload);
    std::fs::create_dir_all(dir).expect("create the frame dir");
    let files: [(&str, &[u8]); 3] = [
        ("payload.bin", &payload),
        ("libzstd1.zst", &lib),
        ("ruzstd_fcs.zst", &ru),
    ];
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).expect("write a frame");
    }
    println!(
        "full block {full}: {} txs, payload {} B, libzstd1 {} B, ruzstd+fcs {} B -> {}",
        block.txs.len(),
        payload.len(),
        lib.len(),
        ru.len(),
        dir.display()
    );
}

/// A decode path: frame in, payload out.
type Decoder = fn(&[u8]) -> Vec<u8>;

/// Time both decoders on the frames `emit` wrote.
fn decode(dir: &Path) {
    let read = |name: &str| -> Vec<u8> {
        let path: PathBuf = dir.join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let payload = read("payload.bin");
    let lib = read("libzstd1.zst");
    let ru = read("ruzstd_fcs.zst");
    let cases: [(&str, &[u8], Decoder); 4] = [
        ("libzstd decodes the libzstd frame", &lib, lib_decode),
        ("ruzstd decodes the libzstd frame", &lib, ru_decode),
        ("libzstd decodes the ruzstd+fcs frame", &ru, lib_decode),
        ("ruzstd decodes the ruzstd+fcs frame", &ru, ru_decode),
    ];
    println!("payload {} B", payload.len());
    for (what, frame, f) in cases {
        assert_eq!(f(frame), payload, "{what}");
        let ns = time(|| f(frame));
        println!(
            "{what:<38} {:>10.1} us  {:>8.0} MB/s",
            ns / 1e3,
            payload.len() as f64 / ns * 1e3
        );
    }
}

/// The handshake and timed-sync payloads (Rick, 2026-10-19, on #1134:
/// "Measure the handshake and timed-sync peer lists with the same rig").
///
/// No corpus holds these: a regtest daemon has no peers. The values are
/// synthetic and the encoder is production's: a fixed-seed generator
/// draws the addresses, the node identifier, the nonce and the tip, and
/// every peer listens on testnet's default port (12021), which is the
/// most repetitive and so the most compressible case. Each list is full,
/// at [`DISCLOSE_COUNT`] entries, the most a message may carry.
fn peers(report: &Path) {
    let mut rng = SplitMix(0x5e1f_c0de_2026_1019);
    let node_data = BasicNodeData {
        network_id: rng.bytes(),
        support_flags: SupportFlags::ADVERTISED,
    };
    let sync = CoreSyncData {
        current_height: 21_011,
        cumulative_difficulty: 0x0000_0123_4567_89ab,
        cumulative_difficulty_top64: 0,
        top_id: rng.bytes(),
    };
    let mut out = vec![
        Payload {
            class: "handshake-req",
            name: "request".to_owned(),
            bytes: HandshakeRequest {
                node_data: node_data.clone(),
                payload_data: sync.clone(),
                nonce: rng.bytes(),
            }
            .store()
            .expect("store a handshake request"),
        },
        Payload {
            class: "timed-sync-req",
            name: "request".to_owned(),
            bytes: TimedSyncRequest {
                payload_data: sync.clone(),
            }
            .store()
            .expect("store a timed-sync request"),
        },
    ];
    for mix in ["ipv4", "ipv6", "tor", "mixed"] {
        let list: Vec<PeerlistEntry> = (0..DISCLOSE_COUNT)
            .map(|i| PeerlistEntry {
                adr: rng.address(match mix {
                    "mixed" => ["ipv4", "ipv6", "tor"][i % 3],
                    one => one,
                }),
            })
            .collect();
        out.push(Payload {
            class: "handshake-resp",
            name: format!("{mix}-{DISCLOSE_COUNT}"),
            bytes: HandshakeResponse {
                node_data: node_data.clone(),
                payload_data: sync.clone(),
                local_peerlist_new: list.clone(),
            }
            .store()
            .expect("store a handshake response"),
        });
        out.push(Payload {
            class: "timed-sync-resp",
            name: format!("{mix}-{DISCLOSE_COUNT}"),
            bytes: TimedSyncResponse {
                payload_data: sync.clone(),
                local_peerlist_new: list,
            }
            .store()
            .expect("store a timed-sync response"),
        });
    }
    out.sort_by_key(|p| p.class);
    let about = [format!(
        "synthetic handshake and timed-sync payloads: production encoder, fixed-seed values, \
         {DISCLOSE_COUNT} peers per list, every peer on port {TESTNET_P2P_PORT}"
    )];
    let rows = run(&out, report, &about);
    println!(
        "\n{:<16} {:<10} {:>7} {:>9} {:>12} {:>12}",
        "class", "list", "input B", "libzstd1", "ruzstd+fcs", "saved B"
    );
    for r in rows {
        let best = [(r.lib_sent, r.lib), (r.ru_sent, r.ru_fcs)]
            .into_iter()
            .filter(|(sent, _)| *sent)
            .map(|(_, len)| r.input - len)
            .max()
            .unwrap_or(0);
        println!(
            "{:<16} {:<10} {:>7} {:>9} {:>12} {:>12}",
            r.class, r.name, r.input, r.lib, r.ru_fcs, best
        );
    }
}

/// Testnet's default P2P port (`src/cryptonote_config.h`).
const TESTNET_P2P_PORT: u16 = 12021;

/// SplitMix64: a fixed-seed source for the synthetic values, so a rerun
/// measures the same bytes.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        out
    }

    /// A public-looking address of `family` on the default port. A Tor
    /// host is a v3-length name: 56 base32 characters and `.onion`.
    fn address(&mut self, family: &str) -> NetworkAddress {
        let port = TESTNET_P2P_PORT;
        match family {
            "ipv4" => {
                let [a, b, c, d] = self.bytes::<4>();
                NetworkAddress::Ipv4 {
                    ip: Ipv4Addr::new(a % 223 + 1, b, c, d),
                    port,
                }
            }
            "ipv6" => {
                let mut octets = self.bytes::<16>();
                octets[0] = 0x20 | (octets[0] & 0x0f);
                NetworkAddress::Ipv6 {
                    ip: Ipv6Addr::from(octets),
                    port,
                }
            }
            "tor" => {
                const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
                let mut host: String = (0..56)
                    .map(|_| char::from(BASE32[(self.next() % 32) as usize]))
                    .collect();
                host.push_str(".onion");
                NetworkAddress::Tor { host, port }
            }
            other => unreachable!("no address family {other}"),
        }
    }
}
