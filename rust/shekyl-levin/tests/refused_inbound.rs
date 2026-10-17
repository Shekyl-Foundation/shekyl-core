// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The refused-inbound gate (`DAEMON_CONFIG_CUTOVER.md` §5.2; Rick,
//! 2026-10-14): the inbound safety bound is the process's descriptor
//! headroom and nothing else — no option, no development lever (PWD-B1,
//! IG-Q40). The daemon is started with a lowered soft descriptor limit on
//! the child alone; it derives its inbound ceiling from that limit and logs
//! it; this test fills the ceiling with admitted peers and asserts that the
//! next inbound connection is refused — closed by the daemon before its
//! handshake is answered — while the admitted ones stay.
//!
//! Unix only: Windows has no per-process descriptor limit, and the daemon's
//! ceiling there is unbounded by design (PWD-B1). `#[ignore]`d: requires
//! `SHEKYLD_BIN`, and run by `scripts/ci/run_live_daemon_gates.sh`.

#![cfg(unix)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod live_daemon;
use live_daemon::{spawn_peer, Daemon, PeerOutcome};

/// The child's soft descriptor limit. Low enough that the derived ceiling
/// is a few dozen peers, high enough that the daemon starts (its store,
/// logs, listeners and the reservation its Rust `main()` records).
const DESCRIPTOR_LIMIT: u64 = 160;

/// The ceiling the daemon logged at bind, `Bounded(n)`.
fn logged_ceiling(daemon: &Daemon) -> Option<u32> {
    let text = daemon.log_text();
    let line = text
        .lines()
        .find(|l| l.contains("the inbound ceiling the seam binds with"))?;
    let start = line.find("Bounded(")? + "Bounded(".len();
    let end = line[start..].find(')')? + start;
    line[start..end].parse().ok()
}

fn wait_until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

#[ignore = "refused-inbound gate: requires SHEKYLD_BIN; spawns a live daemon under a lowered descriptor limit"]
#[test]
fn the_inbound_ceiling_derived_from_the_descriptor_limit_refuses_the_next_peer() {
    let daemon = Daemon::start_with("refused_inbound", Some(DESCRIPTOR_LIMIT), "info");

    // The subject (rule 47): the daemon derived a bounded ceiling from the
    // limit this test imposed, and said so.
    let ceiling = wait_until(Duration::from_secs(30), || {
        logged_ceiling(&daemon).is_some()
    })
    .then(|| logged_ceiling(&daemon))
    .flatten()
    .unwrap_or_else(|| {
        panic!(
            "the daemon did not log a bounded inbound ceiling under a soft limit of \
                 {DESCRIPTOR_LIMIT}; log:\n{}",
            daemon.log_text()
        )
    });
    eprintln!("inbound ceiling under a soft descriptor limit of {DESCRIPTOR_LIMIT}: {ceiling}");
    assert!(
        (1..=512).contains(&ceiling),
        "a ceiling of {ceiling} under a limit of {DESCRIPTOR_LIMIT} is not the derivation \
         (headroom = limit - held - reserved)"
    );

    // Fill it: `ceiling` peers, each admitted (its handshake answered).
    let stop = Arc::new(AtomicBool::new(false));
    let mut peers = Vec::new();
    for _ in 0..ceiling {
        let shook = Arc::new(AtomicBool::new(false));
        peers.push((
            spawn_peer(daemon.p2p_port, Arc::clone(&stop), Arc::clone(&shook)),
            shook,
        ));
        std::thread::sleep(Duration::from_millis(10));
    }
    let all_admitted = wait_until(Duration::from_secs(60), || {
        peers.iter().all(|(_, shook)| shook.load(Ordering::SeqCst))
    });
    let admitted = peers
        .iter()
        .filter(|(_, shook)| shook.load(Ordering::SeqCst))
        .count();
    assert!(
        all_admitted,
        "every peer up to the ceiling must be admitted: {admitted} of {ceiling} were; log:\n{}",
        daemon.log_text()
    );

    // The next one is refused: the daemon closes it before answering the
    // handshake. Observed as the peer's socket ending without a handshake
    // response, within a bound a slow accept loop cannot reach.
    let extra_shook = Arc::new(AtomicBool::new(false));
    let extra = spawn_peer(daemon.p2p_port, Arc::clone(&stop), Arc::clone(&extra_shook));
    let finished = wait_until(Duration::from_secs(20), || extra.is_finished());
    assert!(
        finished && !extra_shook.load(Ordering::SeqCst),
        "the peer past the ceiling must be refused, not admitted (finished: {finished}, \
         handshake answered: {}); log:\n{}",
        extra_shook.load(Ordering::SeqCst),
        daemon.log_text()
    );
    let outcome = extra.join().expect("extra peer thread");
    assert_eq!(
        outcome,
        PeerOutcome::Closed,
        "the refusal is a close, not a failure to connect"
    );

    // The admitted peers were not displaced to make room.
    let still_admitted = peers.iter().filter(|(h, _)| !h.is_finished()).count();
    assert_eq!(
        still_admitted,
        usize::try_from(ceiling).expect("ceiling fits"),
        "the admitted peers stay while the extra one is refused"
    );

    stop.store(true, Ordering::Relaxed);
    for (handle, _) in peers {
        assert_eq!(handle.join().expect("peer thread"), PeerOutcome::Admitted);
    }
}
