// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P6: what a handshake costs on the floor device, each side.
//!
//! The registered method is
//! `docs/benchmarks/rt_p6_handshake_cost_20261018.md`. This binary writes
//! the raw samples that method names (`steps.tsv`, `message1.tsv`,
//! `records.tsv`). `scripts/bench/rt_p6_summary.py` is the statistics, and
//! it refuses a file that is not the registered shape. The step names below
//! are that script's `HANDSHAKE_STEPS`.
//!
//! Linux runs the measurement. Any other host exits without writing a run:
//! the registered clock is the Linux thread CPU clock, and the host is the
//! Pi 4. `cargo test` still builds the example everywhere.
//!
//! ```text
//! cargo run --release -p shekyl-rpc-channel --example rt_p6_handshake_cost -- <out-dir> <dry|registered>
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "rt-p6 measures the floor device, which is Linux (the Pi 4). This host is {}.",
            std::env::consts::OS
        );
        ExitCode::from(2)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fmt::Write;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use rand_core::{OsRng, RngCore};
    use shekyl_noise::Direction;
    use shekyl_rpc_channel::budget::HandshakeBudget;
    use shekyl_rpc_channel::handshake::{
        Client, Daemon, DaemonReadyForMessage2, HandshakeError, Message1Admission, StaticKeypair,
        MESSAGE1_LEN, MESSAGE1_WIRE_LEN, TAG_LEN, TRANSPORT_AD,
    };
    use shekyl_rpc_channel::NetworkId;

    /// Fixed network id. Every sample mixes the same prologue. The bytes
    /// are not a deployed network, and the cost does not depend on them.
    const BENCH_NETWORK_ID: NetworkId = [0x26; 16];

    /// Message 3 and message 4 payloads. RT-W10's encoding is fixed-length
    /// (§6.2). Registered at 64 bytes.
    const PAYLOAD_LEN: usize = 64;
    const PAYLOAD_BYTE: u8 = 0x5a;
    const PAYLOAD: [u8; PAYLOAD_LEN] = [PAYLOAD_BYTE; PAYLOAD_LEN];

    /// The response classes RT-O6 ruled on 2026-10-18.
    const RECORD_CLASSES: [usize; 3] = [512, 16_384, 65_535];

    /// Flips one byte of message 1's tag. The tag is the last [`TAG_LEN`]
    /// bytes, so the encapsulation key and the ciphertext still parse.
    const TAG_BYTE_FLIP: u8 = 0x01;

    const STEPS_FILE: &str = "steps.tsv";
    const MESSAGE1_FILE: &str = "message1.tsv";
    const RECORDS_FILE: &str = "records.tsv";

    const STEP_HEADER: &str = "iteration\tside\tstep\twall_ns\tcpu_ns";
    const MESSAGE1_HEADER: &str =
        "iteration\tkind\taccepted\tnew_wall_ns\tnew_cpu_ns\tread_wall_ns\tread_cpu_ns";
    const RECORD_HEADER: &str = "iteration\tclass\top\twall_ns\tcpu_ns";

    /// How many samples a cell records, and how many it discards first.
    #[derive(Clone, Copy)]
    struct Cell {
        name: &'static str,
        warmup: usize,
        handshakes: usize,
        messages1: usize,
        records: usize,
    }

    const DRY: Cell = Cell {
        name: "dry",
        warmup: 5,
        handshakes: 50,
        messages1: 50,
        records: 50,
    };

    const REGISTERED: Cell = Cell {
        name: "registered",
        warmup: 200,
        handshakes: 10_000,
        messages1: 10_000,
        records: 10_000,
    };

    /// One timed call of a full handshake. The side is part of the step, so
    /// a sample cannot name `read_message1` on the client.
    #[derive(Clone, Copy)]
    enum HandshakeStep {
        ClientStart,
        DaemonNew,
        DaemonReadMessage1,
        DaemonWriteMessage2,
        ClientReadMessage2,
        ClientWriteMessage3,
        DaemonReadMessage3,
        DaemonWriteMessage4,
        ClientReadMessage4,
        ClientFirstRecord,
        DaemonOpenFirstMessage,
    }

    impl HandshakeStep {
        const fn side(self) -> &'static str {
            match self {
                Self::ClientStart
                | Self::ClientReadMessage2
                | Self::ClientWriteMessage3
                | Self::ClientReadMessage4
                | Self::ClientFirstRecord => "client",
                Self::DaemonNew
                | Self::DaemonReadMessage1
                | Self::DaemonWriteMessage2
                | Self::DaemonReadMessage3
                | Self::DaemonWriteMessage4
                | Self::DaemonOpenFirstMessage => "daemon",
            }
        }

        const fn name(self) -> &'static str {
            match self {
                Self::ClientStart => "start",
                Self::DaemonNew => "new",
                Self::DaemonReadMessage1 => "read_message1",
                Self::DaemonWriteMessage2 => "write_message2",
                Self::ClientReadMessage2 => "read_message2",
                Self::ClientWriteMessage3 => "write_message3",
                Self::DaemonReadMessage3 => "read_message3",
                Self::DaemonWriteMessage4 => "write_message4",
                Self::ClientReadMessage4 => "read_message4",
                Self::ClientFirstRecord => "first_record",
                Self::DaemonOpenFirstMessage => "open_first_message",
            }
        }
    }

    /// The two message-1 bodies the amplification figure is taken from.
    /// Both pass the public parse. They differ by the tag.
    #[derive(Clone, Copy)]
    enum Message1Kind {
        Honest,
        TagFlipped,
        NoBundle,
    }

    impl Message1Kind {
        const fn name(self) -> &'static str {
            match self {
                Self::Honest => "honest",
                Self::TagFlipped => "tag_flipped",
                Self::NoBundle => "no_bundle",
            }
        }

        const fn accepted(self) -> bool {
            match self {
                Self::Honest => true,
                Self::TagFlipped | Self::NoBundle => false,
            }
        }
    }

    /// A budget that cannot run out during a run: the whole of a core, a
    /// day's burst. The run measures what an admitted message costs; how
    /// many are admitted is the budget's, and its tests cover it.
    fn unbounded() -> HandshakeBudget {
        HandshakeBudget::with_share(1_000, Duration::from_secs(86_400), Instant::now())
    }

    /// The measurement budget does not run out, so a read that is not a
    /// refusal has continued the handshake.
    fn expect_continue(read: Result<Message1Admission, HandshakeError>) -> DaemonReadyForMessage2 {
        match read.expect("read_message1") {
            Message1Admission::Continue(ready) => ready,
            Message1Admission::Busy(_) => panic!("the measurement budget does not run out"),
        }
    }

    fn continued(read: &Result<Message1Admission, HandshakeError>) -> bool {
        matches!(read, Ok(Message1Admission::Continue(_)))
    }

    #[derive(Clone, Copy)]
    enum RecordOp {
        Seal,
        Open,
    }

    impl RecordOp {
        const fn name(self) -> &'static str {
            match self {
                Self::Seal => "seal",
                Self::Open => "open",
            }
        }
    }

    struct PreparedMessage1 {
        kind: Message1Kind,
        bodies: Vec<Vec<u8>>,
    }

    /// This thread's CPU time, in nanoseconds.
    fn cpu_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid writable `timespec`. The clock id is the
        // Linux thread CPU clock, and the call does not retain `ts`.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
        assert_eq!(rc, 0, "the thread CPU clock is readable");
        let seconds = u64::try_from(ts.tv_sec).expect("the thread CPU clock is non-negative");
        let nanos = u64::try_from(ts.tv_nsec).expect("the thread CPU clock is non-negative");
        seconds * 1_000_000_000 + nanos
    }

    /// One timed call: wall time of the call, and this thread's CPU time
    /// across the call and the two wall-clock reads.
    #[derive(Copy, Clone)]
    struct Sample {
        wall_ns: u64,
        cpu_ns: u64,
    }

    /// Time one call. The CPU reading brackets the wall reading, so the CPU
    /// sample includes the two wall-clock reads and the wall sample does not
    /// include `clock_gettime`.
    fn timed<T>(call: impl FnOnce() -> T) -> (Sample, T) {
        let cpu_before = cpu_ns();
        let wall_before = Instant::now();
        let output = call();
        let wall = wall_before.elapsed();
        let cpu_after = cpu_ns();
        (
            Sample {
                wall_ns: u64::try_from(wall.as_nanos()).expect("a sample fits in u64 nanoseconds"),
                cpu_ns: cpu_after - cpu_before,
            },
            output,
        )
    }

    fn push_step(out: &mut String, iteration: usize, step: HandshakeStep, sample: Sample) {
        writeln!(
            out,
            "{iteration}\t{}\t{}\t{}\t{}",
            step.side(),
            step.name(),
            sample.wall_ns,
            sample.cpu_ns,
        )
        .expect("a step row");
    }

    fn push_message1(
        out: &mut String,
        iteration: usize,
        kind: Message1Kind,
        accepted: bool,
        new: Sample,
        read: Sample,
    ) {
        writeln!(
            out,
            "{iteration}\t{}\t{accepted}\t{}\t{}\t{}\t{}",
            kind.name(),
            new.wall_ns,
            new.cpu_ns,
            read.wall_ns,
            read.cpu_ns,
        )
        .expect("a message-1 row");
    }

    fn push_record(out: &mut String, iteration: usize, class: usize, op: RecordOp, sample: Sample) {
        writeln!(
            out,
            "{iteration}\t{class}\t{}\t{}\t{}",
            op.name(),
            sample.wall_ns,
            sample.cpu_ns,
        )
        .expect("a record row");
    }

    pub fn run() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        let (out, cell) = match args.as_slice() {
            [_, out, name] if name == "dry" => (PathBuf::from(out), DRY),
            [_, out, name] if name == "registered" => (PathBuf::from(out), REGISTERED),
            _ => {
                eprintln!("usage: rt_p6_handshake_cost <out-dir> <dry|registered>");
                return ExitCode::from(2);
            }
        };
        assert!(
            !out.exists(),
            "the output directory exists; a run never writes over another's"
        );
        std::fs::create_dir_all(&out).expect("create the output directory");

        let daemon_id = StaticKeypair::generate().expect("daemon identity");
        let client_id = StaticKeypair::generate().expect("client identity");
        let mut rng = OsRng;

        let steps = measure_handshakes(cell, &client_id, &daemon_id);
        let message1 = measure_message1(cell, &client_id, &daemon_id);
        let records = measure_records(cell, &client_id, &daemon_id, &mut rng);

        std::fs::write(out.join(STEPS_FILE), steps).expect("write steps.tsv");
        std::fs::write(out.join(MESSAGE1_FILE), message1).expect("write message1.tsv");
        std::fs::write(out.join(RECORDS_FILE), records).expect("write records.tsv");

        println!(
            "rt-p6 {}: {} handshakes, {} messages 1 of each kind, {} records per class and operation; files in {}",
            cell.name,
            cell.handshakes,
            cell.messages1,
            cell.records,
            out.display()
        );
        ExitCode::SUCCESS
    }

    fn measure_handshakes(
        cell: Cell,
        client_id: &StaticKeypair,
        daemon_id: &StaticKeypair,
    ) -> String {
        let budget = unbounded();
        let mut out = String::from(STEP_HEADER);
        out.push('\n');
        for i in 0..cell.warmup + cell.handshakes {
            // Warmup iterations have no recorded index. `checked_sub`
            // is `None` until `i` reaches `cell.warmup`.
            let recorded = i.checked_sub(cell.warmup);
            let mut row = |step, sample| {
                if let Some(iteration) = recorded {
                    push_step(&mut out, iteration, step, sample);
                }
            };

            let (sample, started) =
                timed(|| Client::start(&BENCH_NETWORK_ID, client_id, daemon_id.public()));
            let (client, message1) = started.expect("start");
            row(HandshakeStep::ClientStart, sample);

            let (sample, daemon) = timed(|| Daemon::new(&BENCH_NETWORK_ID, daemon_id));
            row(HandshakeStep::DaemonNew, sample);

            let now = Instant::now();
            let (sample, read) = timed(|| daemon.read_message1(&message1, &budget, now));
            let daemon = expect_continue(read);
            row(HandshakeStep::DaemonReadMessage1, sample);

            let (sample, written) = timed(|| daemon.write_message2());
            let (daemon, message2) = written.expect("write_message2");
            row(HandshakeStep::DaemonWriteMessage2, sample);

            let (sample, read) = timed(|| client.read_message2(&message2));
            let client = read.expect("read_message2");
            row(HandshakeStep::ClientReadMessage2, sample);

            let (sample, written) = timed(|| client.write_message3(&PAYLOAD));
            let (client, message3) = written.expect("write_message3");
            row(HandshakeStep::ClientWriteMessage3, sample);

            let (sample, read) = timed(|| daemon.read_message3(&message3));
            let daemon = read.expect("read_message3");
            row(HandshakeStep::DaemonReadMessage3, sample);

            let (sample, written) = timed(|| daemon.write_message4(&PAYLOAD));
            let (pending, message4) = written.expect("write_message4");
            row(HandshakeStep::DaemonWriteMessage4, sample);

            let (sample, read) = timed(|| client.read_message4(&message4));
            let (client, _grant) = read.expect("read_message4");
            row(HandshakeStep::ClientReadMessage4, sample);

            let (sample, sealed) = timed(|| {
                let (mut send, recv) = client.into_directions();
                send.seal(&PAYLOAD, TRANSPORT_AD)
                    .map(|(first, _epoch)| (send, recv, first))
            });
            let (_send, _recv, first) = sealed.expect("the first record seals");
            row(HandshakeStep::ClientFirstRecord, sample);

            let (sample, opened) = timed(|| {
                pending.open_first_message(|recv: &mut Direction| {
                    recv.open(&first, TRANSPORT_AD)
                        .map(|(plaintext, _epoch)| plaintext)
                })
            });
            opened.expect("the first record opens");
            row(HandshakeStep::DaemonOpenFirstMessage, sample);
        }
        out
    }

    fn measure_message1(
        cell: Cell,
        client_id: &StaticKeypair,
        daemon_id: &StaticKeypair,
    ) -> String {
        let prepared = prepare_message1(client_id, daemon_id, cell.messages1);
        let budget = unbounded();
        let mut out = String::from(MESSAGE1_HEADER);
        out.push('\n');
        for set in &prepared {
            warm_message1(daemon_id, &set.bodies, cell.warmup);
            let mut accepted = 0usize;
            for (i, body) in set.bodies.iter().enumerate() {
                let (new, daemon) = timed(|| Daemon::new(&BENCH_NETWORK_ID, daemon_id));
                let now = Instant::now();
                let (read, result) = timed(|| daemon.read_message1(body, &budget, now));
                accepted += usize::from(continued(&result));
                push_message1(&mut out, i, set.kind, continued(&result), new, read);
            }
            let expect = usize::from(set.kind.accepted()) * set.bodies.len();
            assert_eq!(
                accepted,
                expect,
                "{} messages 1: the measurement is not of what it names",
                set.kind.name()
            );
        }
        out
    }

    /// Honest message 1s from `Client::start`; the same bytes with one tag
    /// byte flipped and the mac1 made again, as a sender holding the bundle
    /// can; and the honest bytes with one mac1 byte flipped, as a sender
    /// without the bundle sends. All are built before any timed read.
    fn prepare_message1(
        client_id: &StaticKeypair,
        daemon_id: &StaticKeypair,
        count: usize,
    ) -> [PreparedMessage1; 3] {
        let honest: Vec<Vec<u8>> = (0..count)
            .map(|_| {
                Client::start(&BENCH_NETWORK_ID, client_id, daemon_id.public())
                    .expect("start")
                    .1
            })
            .collect();
        let tag_flipped = honest
            .iter()
            .map(|message| flip_tag(message, daemon_id))
            .collect();
        let no_bundle = honest.iter().map(|message| flip_mac1(message)).collect();
        [
            PreparedMessage1 {
                kind: Message1Kind::Honest,
                bodies: honest,
            },
            PreparedMessage1 {
                kind: Message1Kind::TagFlipped,
                bodies: tag_flipped,
            },
            PreparedMessage1 {
                kind: Message1Kind::NoBundle,
                bodies: no_bundle,
            },
        ]
    }

    fn flip_tag(message: &[u8], daemon_id: &StaticKeypair) -> Vec<u8> {
        assert_eq!(
            message.len(),
            MESSAGE1_WIRE_LEN,
            "message 1 has a fixed length"
        );
        let mut body = message.to_vec();
        // The Noise message's tag is its last TAG_LEN bytes. One flipped
        // byte still parses as a key and a ciphertext, and the tag check
        // fails after the decapsulation and the X25519 Diffie-Hellman. The
        // mac1 is made again over the changed bytes, so the message passes
        // mac1 and reaches them.
        let tag_start = MESSAGE1_LEN - TAG_LEN;
        body[tag_start + TAG_LEN - 1] ^= TAG_BYTE_FLIP;
        let mac1 = daemon_id.public().mac1(&body[..MESSAGE1_LEN]);
        body[MESSAGE1_LEN..].copy_from_slice(&mac1);
        body
    }

    /// The honest bytes with the mac1's last byte flipped: refused at mac1,
    /// before either long-term key.
    fn flip_mac1(message: &[u8]) -> Vec<u8> {
        assert_eq!(
            message.len(),
            MESSAGE1_WIRE_LEN,
            "message 1 has a fixed length"
        );
        let mut body = message.to_vec();
        body[MESSAGE1_WIRE_LEN - 1] ^= TAG_BYTE_FLIP;
        body
    }

    /// Warm the read on its own budget, so the mac1s it presents are not
    /// the ones the timed loop admits. A shared window would make the timed
    /// read of those bytes a replay.
    fn warm_message1(daemon_id: &StaticKeypair, bodies: &[Vec<u8>], warmup: usize) {
        let budget = unbounded();
        for body in bodies.iter().take(warmup) {
            let daemon = Daemon::new(&BENCH_NETWORK_ID, daemon_id);
            let read = daemon.read_message1(body, &budget, Instant::now());
            let _read = std::hint::black_box(read);
        }
    }

    fn measure_records(
        cell: Cell,
        client_id: &StaticKeypair,
        daemon_id: &StaticKeypair,
        rng: &mut OsRng,
    ) -> String {
        let mut out = String::from(RECORD_HEADER);
        out.push('\n');
        for class in RECORD_CLASSES {
            warm_records(client_id, daemon_id, class, cell.warmup, rng);
            let (mut send, mut recv) = handshake_directions(client_id, daemon_id);
            let mut plaintext = vec![0u8; class];
            rng.fill_bytes(&mut plaintext);
            let mut sealed = Vec::with_capacity(cell.records);
            for i in 0..cell.records {
                let (sample, result) = timed(|| send.seal(&plaintext, TRANSPORT_AD));
                sealed.push(result.expect("seal").0);
                push_record(&mut out, i, class, RecordOp::Seal, sample);
            }
            for (i, ciphertext) in sealed.iter().enumerate() {
                let (sample, result) = timed(|| recv.open(ciphertext, TRANSPORT_AD));
                let (opened, _epoch) = result.expect("open");
                let _opened = std::hint::black_box(opened);
                push_record(&mut out, i, class, RecordOp::Open, sample);
            }
        }
        out
    }

    /// Seals and opens at `class` on a session that is then dropped, so the
    /// timed session is the first recorded nonce and the length has already
    /// been through the cipher.
    fn warm_records(
        client_id: &StaticKeypair,
        daemon_id: &StaticKeypair,
        class: usize,
        warmup: usize,
        rng: &mut OsRng,
    ) {
        if warmup == 0 {
            return;
        }
        let (mut send, mut recv) = handshake_directions(client_id, daemon_id);
        let mut plaintext = vec![0u8; class];
        rng.fill_bytes(&mut plaintext);
        for _ in 0..warmup {
            let (ciphertext, _epoch) = send.seal(&plaintext, TRANSPORT_AD).expect("warmup seal");
            let (opened, _epoch) = recv.open(&ciphertext, TRANSPORT_AD).expect("warmup open");
            let _opened = std::hint::black_box(opened);
        }
    }

    /// The client's sending direction and the daemon's receiving direction
    /// after the handshake's authenticating record. The first recorded nonce
    /// is therefore 1.
    fn handshake_directions(
        client_id: &StaticKeypair,
        daemon_id: &StaticKeypair,
    ) -> (Direction, Direction) {
        let (client, message1) =
            Client::start(&BENCH_NETWORK_ID, client_id, daemon_id.public()).expect("start");
        let daemon = expect_continue(Daemon::new(&BENCH_NETWORK_ID, daemon_id).read_message1(
            &message1,
            &unbounded(),
            Instant::now(),
        ));
        let (daemon, message2) = daemon.write_message2().expect("write_message2");
        let client = client.read_message2(&message2).expect("read_message2");
        let (client, message3) = client.write_message3(&PAYLOAD).expect("write_message3");
        let daemon = daemon.read_message3(&message3).expect("read_message3");
        let (pending, message4) = daemon.write_message4(&PAYLOAD).expect("write_message4");
        let (client, _) = client.read_message4(&message4).expect("read_message4");
        let (mut send, _client_recv) = client.into_directions();
        let (first, _) = send.seal(&PAYLOAD, TRANSPORT_AD).expect("seal");
        let (session, _) = pending
            .open_first_message(|recv: &mut Direction| {
                recv.open(&first, TRANSPORT_AD)
                    .map(|(plaintext, _epoch)| plaintext)
            })
            .expect("first record");
        (send, session.recv)
    }
}
