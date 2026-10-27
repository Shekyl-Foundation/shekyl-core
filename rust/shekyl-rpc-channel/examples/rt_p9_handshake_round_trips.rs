// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P9: how long does the channel's handshake take on a real network leg
//! to the floor device? (`docs/design/RPC_CHANNEL.md` §9.)
//!
//! The registration is `docs/benchmarks/rt_p9_handshake_round_trips_20261020.md`.
//! It fixes, before any registered run, the legs, the counts, what is timed
//! and how the message-1 deadline and the whole-handshake deadline are
//! derived from it. Read it before changing this file.
//!
//! # What runs
//!
//! The real `hybridXK` handshake, mac1 and the handshake budget included,
//! over one TCP connection per sample. Every message has a fixed length, so
//! the stream carries them back to back with no framing:
//!
//! 1. the client sends message 1 (2,336 bytes on the wire);
//! 2. the daemon replies with message 2 (2,320);
//! 3. the client sends message 3 (1,264 + 64-byte payload);
//! 4. the daemon replies with message 4 (1,120 + 64-byte payload);
//! 5. the client sends its first record (a 64-byte payload sealed);
//! 6. the daemon opens it, which authenticates the client, and replies with
//!    one sealed record, so the client sees the exchange end.
//!
//! The daemon side (`serve`) stamps each event against the instant its
//! `accept` returned: the clock a daemon's deadlines run on. It serves until
//! it is stopped, one connection at a time. The client numbers its samples
//! and carries the number in the first 8 bytes of its first record, so the
//! daemon's row of a completed sample names the client's row it pairs with;
//! a connection that fails before that record is the daemon's alone. The client side
//! (`client`) stamps each event against the instant it began to connect.
//! For the onion leg the client reaches the daemon through a SOCKS5 proxy,
//! with a different username per connection, so that Tor builds a fresh
//! circuit for each sample, as a client's first connection meets.
//!
//! Usage:
//!
//! ```text
//! rt_p9_handshake_round_trips serve  <listen addr> <bundle out file> <out dir>
//! rt_p9_handshake_round_trips client <leg> <host:port> <socks addr | direct> <bundle file> <out dir> <count>
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use shekyl_noise::RecvDirection;
use shekyl_rpc_channel::budget::HandshakeBudget;
use shekyl_rpc_channel::handshake::{
    Client, Daemon, Message1Admission, StaticKeypair, StaticPublic, MESSAGE1_WIRE_LEN,
    MESSAGE2_LEN, MESSAGE3_OVERHEAD, MESSAGE4_OVERHEAD, TAG_LEN, TRANSPORT_AD,
};
use shekyl_rpc_channel::{NetworkId, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};

/// Fixed network id. The bytes are not a deployed network.
const BENCH_NETWORK_ID: NetworkId = [0x29; 16];

/// Message 3's and message 4's payloads, and the first record's: 64 bytes,
/// as RT-P6 registered (RT-W10's encodings are fixed-length, §6.2).
const PAYLOAD: [u8; 64] = [0x5a; 64];

const MESSAGE3_LEN: usize = MESSAGE3_OVERHEAD + PAYLOAD.len();
const MESSAGE4_LEN: usize = MESSAGE4_OVERHEAD + PAYLOAD.len();
const RECORD_LEN: usize = PAYLOAD.len() + TAG_LEN;

/// A connection that has not finished within this is recorded as such and
/// closed. Far beyond any deadline the run could derive.
const SAMPLE_LIMIT: Duration = Duration::from_secs(120);

/// The client's pause between samples. The daemon role runs under the
/// ruled handshake budget (115 handshakes a second). Back to back on the
/// LAN a handshake takes about 5 ms, so one client would reconnect at about
/// 200 a second and, once the burst was spent, the budget would drop the
/// excess, as it is built to. 100 ms keeps one client at 10 a second.
const BETWEEN_SAMPLES: Duration = Duration::from_millis(100);

const SERVER_HEADER: &str =
    "accepted\tsample\tok\tmessage1_received_ns\tmessage2_sent_ns\tmessage3_received_ns\tmessage4_sent_ns\tfirst_record_opened_ns\treply_sent_ns";
const CLIENT_HEADER: &str = "sample\tleg\tok\tconnected_ns\tmessage1_sent_ns\tmessage2_received_ns\tmessage3_sent_ns\tmessage4_received_ns\tfirst_record_sent_ns\treply_received_ns";

fn ns(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 5 => serve(&args[2], &args[3], &args[4]),
        Some("client") if args.len() == 8 => {
            client(&args[2], &args[3], &args[4], &args[5], &args[6], &args[7])
        }
        _ => {
            eprintln!("usage: see the module documentation");
            ExitCode::from(2)
        }
    }
}

fn fresh_dir(out: &str) -> PathBuf {
    let out = PathBuf::from(out);
    assert!(
        !out.exists(),
        "the output directory exists; a run never writes over another's"
    );
    std::fs::create_dir_all(&out).expect("create the output directory");
    out
}

fn count(text: &str) -> usize {
    text.parse().expect("a count")
}

// ------------------------------------------------------------------ daemon

fn serve(listen: &str, bundle_out: &str, out: &str) -> ExitCode {
    let out = fresh_dir(out);
    let daemon_id = StaticKeypair::generate().expect("daemon identity");
    let public = daemon_id.public();
    std::fs::write(
        bundle_out,
        format!(
            "{}\n{}\n",
            hex::encode(public.x25519()),
            hex::encode(public.mlkem_ek())
        ),
    )
    .expect("write the bundle");
    // The ruled budget: the run measures a handshake under the daemon's own
    // admission. The client paces itself below it (`BETWEEN_SAMPLES`).
    let budget = HandshakeBudget::new(Instant::now());
    let listener = TcpListener::bind(listen).expect("bind");
    let mut rows = String::from(SERVER_HEADER);
    rows.push('\n');
    for accepted_count in 0u64.. {
        let (stream, _) = listener.accept().expect("accept");
        let accepted = Instant::now();
        let mut sample = None;
        let result = serve_one(stream, &daemon_id, &budget, accepted, &mut sample);
        let (ok, stamps) = match result {
            Ok(stamps) => (true, stamps),
            Err(stamps) => (false, stamps),
        };
        let cells: Vec<String> = stamps
            .iter()
            .map(|s| s.map_or_else(String::new, |v| v.to_string()))
            .collect();
        let sample = sample.map_or_else(String::new, |v| v.to_string());
        rows.push_str(&format!(
            "{accepted_count}\t{sample}\t{ok}\t{}\n",
            cells.join("\t")
        ));
        std::fs::write(out.join("server.tsv"), &rows).expect("write server.tsv");
    }
    ExitCode::SUCCESS
}

/// The first record's payload: the sample's number, then [`PAYLOAD`]'s bytes.
fn numbered(sample: u64) -> [u8; 64] {
    let mut payload = PAYLOAD;
    payload[..8].copy_from_slice(&sample.to_le_bytes());
    payload
}

type Stamps = [Option<u64>; 6];

fn serve_one(
    mut stream: TcpStream,
    daemon_id: &StaticKeypair,
    budget: &HandshakeBudget,
    accepted: Instant,
    sample: &mut Option<u64>,
) -> Result<Stamps, Stamps> {
    let mut stamps: Stamps = [None; 6];
    stream.set_read_timeout(Some(SAMPLE_LIMIT)).ok();
    stream.set_nodelay(true).ok();
    let mut m1 = vec![0u8; MESSAGE1_WIRE_LEN];
    stream.read_exact(&mut m1).map_err(|_| stamps)?;
    stamps[0] = Some(ns(accepted));
    // An admission continues the handshake. A budget refusal is a reply
    // this function sends, and then a sample that did not finish. A
    // refusal sends nothing.
    let daemon = match Daemon::new(&BENCH_NETWORK_ID, daemon_id).read_message1(
        &m1,
        budget,
        Instant::now(),
    ) {
        Ok(Message1Admission::Continue(daemon)) => daemon,
        Ok(Message1Admission::Busy(reply)) => {
            stream.write_all(&reply).map_err(|_| stamps)?;
            return Err(stamps);
        }
        Err(_) => return Err(stamps),
    };
    let (daemon, m2) = daemon.write_message2().map_err(|_| stamps)?;
    stream.write_all(&m2).map_err(|_| stamps)?;
    stamps[1] = Some(ns(accepted));
    let mut m3 = vec![0u8; MESSAGE3_LEN];
    stream.read_exact(&mut m3).map_err(|_| stamps)?;
    stamps[2] = Some(ns(accepted));
    let daemon = daemon.read_message3(&m3).map_err(|_| stamps)?;
    let (pending, m4) = daemon.write_message4(&PAYLOAD).map_err(|_| stamps)?;
    stream.write_all(&m4).map_err(|_| stamps)?;
    stamps[3] = Some(ns(accepted));
    let mut first = vec![0u8; RECORD_LEN];
    stream.read_exact(&mut first).map_err(|_| stamps)?;
    let (mut session, opened) = pending
        .open_first_message(|recv: &mut RecvDirection| {
            recv.open(&first, TRANSPORT_AD).map(|(p, _)| p)
        })
        .map_err(|_| stamps)?;
    stamps[4] = Some(ns(accepted));
    let number: [u8; 8] = opened
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .ok_or(stamps)?;
    *sample = Some(u64::from_le_bytes(number));
    let (reply, _) = session
        .send
        .seal(&PAYLOAD, TRANSPORT_AD)
        .map_err(|_| stamps)?;
    stream.write_all(&reply).map_err(|_| stamps)?;
    stamps[5] = Some(ns(accepted));
    Ok(stamps)
}

// ------------------------------------------------------------------ client

fn read_bundle(path: &str) -> StaticPublic {
    let text = std::fs::read_to_string(path).expect("read the bundle");
    let mut lines = text.lines();
    let x: [u8; X25519_PUBLIC_LEN] = hex::decode(lines.next().expect("x25519 line"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let ek: [u8; MLKEM768_EK_LEN] = hex::decode(lines.next().expect("ek line"))
        .expect("hex")
        .try_into()
        .expect("1,184 bytes");
    StaticPublic::from_parts(x, ek).expect("a valid bundle")
}

fn client(
    leg: &str,
    target: &str,
    socks: &str,
    bundle: &str,
    out: &str,
    samples: &str,
) -> ExitCode {
    let out = fresh_dir(out);
    let samples = count(samples);
    let daemon = read_bundle(bundle);
    let client_id = StaticKeypair::generate().expect("client identity");
    let mut rows = String::from(CLIENT_HEADER);
    rows.push('\n');
    for sample in 0..u64::try_from(samples).expect("a count") {
        if sample > 0 {
            std::thread::sleep(BETWEEN_SAMPLES);
        }
        let started = Instant::now();
        let (ok, stamps) = match client_one(target, socks, &client_id, &daemon, started, sample) {
            Ok(stamps) => (true, stamps),
            Err(stamps) => (false, stamps),
        };
        let cells: Vec<String> = stamps
            .iter()
            .map(|s| s.map_or_else(String::new, |v| v.to_string()))
            .collect();
        rows.push_str(&format!("{sample}\t{leg}\t{ok}\t{}\n", cells.join("\t")));
        std::fs::write(out.join("client.tsv"), &rows).expect("write client.tsv");
    }
    ExitCode::SUCCESS
}

type ClientStamps = [Option<u64>; 7];

fn client_one(
    target: &str,
    socks: &str,
    client_id: &StaticKeypair,
    daemon: &StaticPublic,
    started: Instant,
    sample: u64,
) -> Result<ClientStamps, ClientStamps> {
    let mut stamps: ClientStamps = [None; 7];
    let mut stream = if socks == "direct" {
        TcpStream::connect(target).map_err(|_| stamps)?
    } else {
        socks5_connect(socks, target).map_err(|_| stamps)?
    };
    stream.set_read_timeout(Some(SAMPLE_LIMIT)).ok();
    stream.set_nodelay(true).ok();
    stamps[0] = Some(ns(started));
    let (client, m1) = Client::start(&BENCH_NETWORK_ID, client_id, daemon).map_err(|_| stamps)?;
    stream.write_all(&m1).map_err(|_| stamps)?;
    stamps[1] = Some(ns(started));
    let mut m2 = vec![0u8; MESSAGE2_LEN];
    stream.read_exact(&mut m2).map_err(|_| stamps)?;
    stamps[2] = Some(ns(started));
    let client = client.read_message2(&m2).map_err(|_| stamps)?;
    let (client, m3) = client.write_message3(&PAYLOAD).map_err(|_| stamps)?;
    stream.write_all(&m3).map_err(|_| stamps)?;
    stamps[3] = Some(ns(started));
    let mut m4 = vec![0u8; MESSAGE4_LEN];
    stream.read_exact(&mut m4).map_err(|_| stamps)?;
    stamps[4] = Some(ns(started));
    let (client, _grant) = client.read_message4(&m4).map_err(|_| stamps)?;
    let (mut send, mut recv) = client.into_directions();
    let (first, _) = send
        .seal(&numbered(sample), TRANSPORT_AD)
        .map_err(|_| stamps)?;
    stream.write_all(&first).map_err(|_| stamps)?;
    stamps[5] = Some(ns(started));
    let mut reply = vec![0u8; RECORD_LEN];
    stream.read_exact(&mut reply).map_err(|_| stamps)?;
    recv.open(&reply, TRANSPORT_AD).map_err(|_| stamps)?;
    stamps[6] = Some(ns(started));
    Ok(stamps)
}

/// A SOCKS5 CONNECT to `target` (a host name and port) through `socks`, with
/// a fresh username so Tor isolates the stream on a circuit of its own.
fn socks5_connect(socks: &str, target: &str) -> std::io::Result<TcpStream> {
    let bad = |what: &str| std::io::Error::other(what.to_owned());
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| bad("target is host:port"))?;
    let port: u16 = port.parse().map_err(|_| bad("target port"))?;
    let mut s = TcpStream::connect(socks)?;
    s.set_read_timeout(Some(SAMPLE_LIMIT))?;
    // Offer username/password only: it is what isolates the circuit.
    s.write_all(&[5, 1, 2])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply != [5, 2] {
        return Err(bad("the proxy refused username authentication"));
    }
    let mut user = [0u8; 16];
    OsRng.fill_bytes(&mut user);
    let user = hex::encode(user);
    let mut auth = vec![1, u8::try_from(user.len()).map_err(|_| bad("user"))?];
    auth.extend_from_slice(user.as_bytes());
    auth.extend_from_slice(&[1, b'x']);
    s.write_all(&auth)?;
    s.read_exact(&mut reply)?;
    if reply != [1, 0] {
        return Err(bad("the proxy refused the credentials"));
    }
    let mut request = vec![
        5,
        1,
        0,
        3,
        u8::try_from(host.len()).map_err(|_| bad("host"))?,
    ];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0 {
        return Err(bad("the proxy could not connect"));
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            usize::from(len[0]) + 2
        }
        _ => return Err(bad("the proxy's reply has an unknown address type")),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip)?;
    Ok(s)
}
