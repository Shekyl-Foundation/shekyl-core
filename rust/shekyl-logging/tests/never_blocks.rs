// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Logging never blocks (Rick, 2026-10-14). A sink whose writes stall for
//! 10 s, while a timing-engine owner and a loopback session run and log on
//! every step: the wakes and the session's round trips stay on time, and
//! once the sink catches up it carries one line saying how many lines were
//! dropped. *Records-was:* the stderr layer wrote synchronously, and a
//! stalled stderr held every logging thread for as long as it stalled
//! (18 s on one responder in the PR-3 measurement), its P2P transport
//! workers among them.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_logging::{Config, __test_only_init_with_stderr};
use shekyl_timing_engine::{Clock, EngineService, MonotonicClock, OwnerClass, Tick};
use tracing::Level;

/// How long the sink stalls: every write that starts inside the window waits
/// until the window ends.
const STALL: Duration = Duration::from_secs(10);
/// Small, so the queue fills and drops inside the stall.
const QUEUE_LINES: usize = 16;
/// What "on time" means here. A blocked logger would show the whole stall.
const ON_TIME: Duration = Duration::from_millis(500);

/// A sink that stalls every write until `until`, then records what it gets.
struct StallingSink {
    until: Instant,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Write for StallingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let now = Instant::now();
        if now < self.until {
            thread::sleep(self.until - now);
        }
        self.written.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_stalled_sink_delays_no_wake_and_no_session_and_reports_its_drops() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let start = Instant::now();
    let sink = StallingSink {
        until: start + STALL,
        written: Arc::clone(&written),
    };
    let guard = __test_only_init_with_stderr(Config::stderr_only(Level::DEBUG), sink, QUEUE_LINES)
        .expect("init");

    // A timing-engine owner: arm 20 ms ahead, wait, log, repeat, through the
    // stall and past it.
    let engine = EngineService::start(MonotonicClock::new());
    let handle = engine.handle();
    let wakes = thread::spawn(move || {
        let owner = handle.register(OwnerClass::Transport).expect("owner");
        let mut worst = Duration::ZERO;
        let mut count = 0u32;
        while start.elapsed() < STALL + Duration::from_secs(1) {
            let deadline = Tick::new(owner.clock().now().get() + 20_000_000);
            owner.arm(deadline).expect("arm");
            let wake = owner.wait_wake().expect("wake");
            let late = Duration::from_nanos(
                owner
                    .clock()
                    .now()
                    .get()
                    .saturating_sub(wake.deadline.get()),
            );
            worst = worst.max(late);
            count += 1;
            tracing::debug!(count, late = ?late, "wake");
        }
        (count, worst)
    });

    // A loopback session: the server echoes and logs, the client measures
    // each round trip and logs.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 8];
        while stream.read_exact(&mut buf).is_ok() {
            tracing::debug!(bytes = buf.len(), "echo");
            if stream.write_all(&buf).is_err() {
                break;
            }
        }
    });
    let mut client = TcpStream::connect(address).expect("connect");
    let mut worst_rtt = Duration::ZERO;
    let mut round_trips = 0u32;
    while start.elapsed() < STALL + Duration::from_secs(1) {
        let sent = Instant::now();
        client.write_all(&[7u8; 8]).expect("send");
        let mut back = [0u8; 8];
        client.read_exact(&mut back).expect("echo");
        let rtt = sent.elapsed();
        worst_rtt = worst_rtt.max(rtt);
        round_trips += 1;
        tracing::debug!(rtt = ?rtt, "round trip");
        thread::sleep(Duration::from_millis(20));
    }
    drop(client);
    server.join().expect("server");
    let (wake_count, worst_wake) = wakes.join().expect("wakes");

    assert!(wake_count > 100, "the owner kept waking: {wake_count}");
    assert!(
        worst_wake < ON_TIME,
        "a wake was {worst_wake:?} late while the sink stalled"
    );
    assert!(round_trips > 100, "the session kept running: {round_trips}");
    assert!(
        worst_rtt < ON_TIME,
        "a round trip took {worst_rtt:?} while the sink stalled"
    );

    // Dropping the guard flushes the queue: the sink has caught up.
    drop(guard);
    let text = String::from_utf8_lossy(&written.lock().expect("sink")).into_owned();
    assert!(
        text.contains("lines dropped since"),
        "the sink carries the drop report once it catches up"
    );
}
