// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P6: what does a handshake cost on the floor device, each side?
//! (`docs/design/RPC_CHANNEL.md` §9; RT-W9 step 4.)
//!
//! The registration is `docs/benchmarks/rt_p6_handshake_cost_20261018.md`.
//! It fixes, before any registered run, what is timed, the counts, the
//! conditions recorded and what voids a run. Read it before changing this
//! file: a change here is a change to the registered method.
//!
//! # What is timed
//!
//! Three things, each a single call between two clock reads, on the wall
//! clock and on this thread's CPU clock (`CLOCK_THREAD_CPUTIME_ID`):
//!
//! 1. **Every step of a full handshake**, both roles in this one process:
//!    the client's `start`, `read_message2`, `write_message3`,
//!    `read_message4` and `into_directions` with the first record's seal;
//!    the daemon's `read_message1`, `write_message2`, `read_message3`,
//!    `write_message4` and `open_first_message`. The identities are made
//!    before the loop. The ephemeral keys each step draws are part of what
//!    it costs, as in production.
//! 2. **The daemon's `read_message1` on a stranger's message 1**, which is
//!    what a sender with no identity can make the daemon spend: a
//!    well-formed message 1 from an honest client, and 2,320 random bytes.
//!    Every message is made before its loop, into one array.
//! 3. **Sealing and opening one record** with `Direction` at each class
//!    RT-O6 ruled: 512, 16,384 and 65,535 bytes of plaintext. This is the
//!    AEAD's cost; `ClassedRecord`'s header byte and its protection do not
//!    exist until RT-W9 step 5 and are measured there. Every plaintext and
//!    ciphertext is made before its loop.
//!
//! # Output
//!
//! Raw samples, one row each, in `<out>/steps.tsv`, `<out>/message1.tsv`
//! and `<out>/records.tsv`; a summary on standard output. The derivations
//! the registration names are made from the files, not here.
//!
//! Run: `cargo run --release -p shekyl-rpc-channel --example
//! rt_p6_handshake_cost -- <out-dir> <dry|registered>`, pinned to one core
//! with `taskset`.

use std::path::PathBuf;
use std::time::Instant;

use rand_core::{OsRng, RngCore};
use shekyl_noise::Direction;
use shekyl_rpc_channel::handshake::{Client, Daemon, StaticKeypair, MESSAGE1_LEN, TRANSPORT_AD};
use shekyl_rpc_channel::NetworkId;

const NETWORK: NetworkId = [0x26; 16];

/// Message 3's and message 4's payloads. Their encoding is RT-W10's; both
/// are fixed-length (§6.2), and their length barely moves a symmetric
/// cipher's cost. Registered at 64 bytes each.
const PAYLOAD: [u8; 64] = [0x5a; 64];

/// The response classes RT-O6 ruled on 2026-10-18.
const CLASSES: [usize; 3] = [512, 16_384, 65_535];

struct Cell {
    warmup: usize,
    handshakes: usize,
    messages1: usize,
    records: usize,
}

const DRY: Cell = Cell {
    warmup: 5,
    handshakes: 50,
    messages1: 50,
    records: 50,
};

const REGISTERED: Cell = Cell {
    warmup: 200,
    handshakes: 10_000,
    messages1: 10_000,
    records: 10_000,
};

/// This thread's CPU time, in nanoseconds.
fn cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; the clock id is a constant
    // the kernel defines.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    assert_eq!(rc, 0, "the thread CPU clock is readable");
    u64::try_from(ts.tv_sec).expect("non-negative") * 1_000_000_000
        + u64::try_from(ts.tv_nsec).expect("non-negative")
}

/// Time one call: (wall ns, CPU ns, result).
fn timed<T>(f: impl FnOnce() -> T) -> (u64, u64, T) {
    let c0 = cpu_ns();
    let w0 = Instant::now();
    let out = f();
    let wall = w0.elapsed();
    let c1 = cpu_ns();
    (u64::try_from(wall.as_nanos()).expect("fits"), c1 - c0, out)
}

#[derive(Default)]
struct Rows(String);

impl Rows {
    fn push(&mut self, cols: &[&dyn std::fmt::Display]) {
        let line: Vec<String> = cols.iter().map(ToString::to_string).collect();
        self.0.push_str(&line.join("\t"));
        self.0.push('\n');
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (out, cell, name) = match args.as_slice() {
        [_, out, cell] if cell == "dry" => (PathBuf::from(out), DRY, "dry"),
        [_, out, cell] if cell == "registered" => (PathBuf::from(out), REGISTERED, "registered"),
        _ => {
            eprintln!("usage: rt_p6_handshake_cost <out-dir> <dry|registered>");
            std::process::exit(2);
        }
    };
    assert!(
        !out.exists(),
        "the output directory exists; a run never writes over another's"
    );
    std::fs::create_dir_all(&out).expect("create the output directory");

    let daemon_id = StaticKeypair::generate().expect("daemon identity");
    let client_id = StaticKeypair::generate().expect("client identity");

    // 1. Full handshakes.
    let mut steps = Rows::default();
    steps.push(&[&"iteration", &"side", &"step", &"wall_ns", &"cpu_ns"]);
    for i in 0..cell.warmup + cell.handshakes {
        let record = i >= cell.warmup;
        let mut row = |side: &str, step: &str, w: u64, c: u64| {
            if record {
                steps.push(&[&(i - cell.warmup), &side, &step, &w, &c]);
            }
        };
        let (w, c, r) = timed(|| Client::start(&NETWORK, &client_id, daemon_id.public()));
        let (client, m1) = r.expect("start");
        row("client", "start", w, c);
        let (w, c, r) = timed(|| Daemon::new(&NETWORK, &daemon_id).read_message1(&m1));
        let daemon = r.expect("read_message1");
        row("daemon", "read_message1", w, c);
        let (w, c, r) = timed(|| daemon.write_message2());
        let (daemon, m2) = r.expect("write_message2");
        row("daemon", "write_message2", w, c);
        let (w, c, r) = timed(|| client.read_message2(&m2));
        let client = r.expect("read_message2");
        row("client", "read_message2", w, c);
        let (w, c, r) = timed(|| client.write_message3(&PAYLOAD));
        let (client, m3) = r.expect("write_message3");
        row("client", "write_message3", w, c);
        let (w, c, r) = timed(|| daemon.read_message3(&m3));
        let daemon = r.expect("read_message3");
        row("daemon", "read_message3", w, c);
        let (w, c, r) = timed(|| daemon.write_message4(&PAYLOAD));
        let (pending, m4) = r.expect("write_message4");
        row("daemon", "write_message4", w, c);
        let (w, c, r) = timed(|| client.read_message4(&m4));
        let (client, _grant) = r.expect("read_message4");
        row("client", "read_message4", w, c);
        let (w, c, r) = timed(|| {
            let (mut send, recv) = client.into_directions();
            let (first, _) = send.seal(&PAYLOAD, TRANSPORT_AD).expect("seal");
            (send, recv, first)
        });
        let (_send, _recv, first) = r;
        row("client", "first_record", w, c);
        let (w, c, r) = timed(|| {
            pending.open_first_message(|recv: &mut Direction| {
                recv.open(&first, TRANSPORT_AD).map(|(p, _)| p)
            })
        });
        r.expect("the first record opens");
        row("daemon", "open_first_message", w, c);
    }
    std::fs::write(out.join("steps.tsv"), steps.0).expect("write steps.tsv");

    // 2. A stranger's message 1, made before the loop.
    let honest: Vec<Vec<u8>> = (0..cell.messages1)
        .map(|_| {
            Client::start(&NETWORK, &client_id, daemon_id.public())
                .expect("start")
                .1
        })
        .collect();
    let mut rng = OsRng;
    let garbage: Vec<Vec<u8>> = (0..cell.messages1)
        .map(|_| {
            let mut m = vec![0u8; MESSAGE1_LEN];
            rng.fill_bytes(&mut m);
            m
        })
        .collect();
    let mut m1 = Rows::default();
    m1.push(&[&"iteration", &"kind", &"accepted", &"wall_ns", &"cpu_ns"]);
    for (kind, set) in [("honest", &honest), ("random", &garbage)] {
        let mut accepted = 0usize;
        for (i, m) in set.iter().enumerate() {
            let (w, c, r) = timed(|| Daemon::new(&NETWORK, &daemon_id).read_message1(m));
            accepted += usize::from(r.is_ok());
            m1.push(&[&i, &kind, &r.is_ok(), &w, &c]);
        }
        // The registration's gate: each kind is what it says it is.
        let expected = if kind == "honest" { set.len() } else { 0 };
        assert_eq!(
            accepted, expected,
            "{kind} messages 1 accepted: the measurement is not of what it names"
        );
    }
    std::fs::write(out.join("message1.tsv"), m1.0).expect("write message1.tsv");

    // 3. One record at each class, made before the loop.
    let mut records = Rows::default();
    records.push(&[&"iteration", &"class", &"op", &"wall_ns", &"cpu_ns"]);
    for class in CLASSES {
        let (mut send, mut recv) = handshake_directions(&client_id, &daemon_id);
        let plaintexts: Vec<Vec<u8>> = (0..cell.records)
            .map(|_| {
                let mut p = vec![0u8; class];
                rng.fill_bytes(&mut p);
                p
            })
            .collect();
        let mut sealed = Vec::with_capacity(cell.records);
        for (i, p) in plaintexts.iter().enumerate() {
            let (w, c, r) = timed(|| send.seal(p, TRANSPORT_AD));
            sealed.push(r.expect("seal").0);
            records.push(&[&i, &class, &"seal", &w, &c]);
        }
        for (i, ct) in sealed.iter().enumerate() {
            let (w, c, r) = timed(|| recv.open(ct, TRANSPORT_AD));
            r.expect("open");
            records.push(&[&i, &class, &"open", &w, &c]);
        }
    }
    std::fs::write(out.join("records.tsv"), records.0).expect("write records.tsv");

    println!(
        "rt-p6 {name}: {} handshakes, {} messages 1 of each kind, {} records per class and op; files in {}",
        cell.handshakes,
        cell.messages1,
        cell.records,
        out.display()
    );
}

/// A client's sending direction and the daemon's receiving direction of one
/// completed handshake, for the record measurement.
fn handshake_directions(
    client_id: &StaticKeypair,
    daemon_id: &StaticKeypair,
) -> (Direction, Direction) {
    let (client, m1) = Client::start(&NETWORK, client_id, daemon_id.public()).expect("start");
    let daemon = Daemon::new(&NETWORK, daemon_id)
        .read_message1(&m1)
        .expect("read_message1");
    let (daemon, m2) = daemon.write_message2().expect("write_message2");
    let client = client.read_message2(&m2).expect("read_message2");
    let (client, m3) = client.write_message3(&PAYLOAD).expect("write_message3");
    let daemon = daemon.read_message3(&m3).expect("read_message3");
    let (pending, m4) = daemon.write_message4(&PAYLOAD).expect("write_message4");
    let (client, _) = client.read_message4(&m4).expect("read_message4");
    let (mut send, _client_recv) = client.into_directions();
    let (first, _) = send.seal(&PAYLOAD, TRANSPORT_AD).expect("seal");
    let (session, _) = pending
        .open_first_message(|recv: &mut Direction| recv.open(&first, TRANSPORT_AD).map(|(p, _)| p))
        .expect("first record");
    (send, session.recv)
}
