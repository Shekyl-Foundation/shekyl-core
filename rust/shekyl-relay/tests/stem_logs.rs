// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The log never records a stem's transactions or its successor, at any
//! level or category (`RPC_CHANNEL.md` §6.4, RT-O27, RT-O9.3): the log sits
//! on disk, and a runtime option may raise its level. Its own binary, so the
//! process-wide subscriber below sees every event the relay's threads emit,
//! at TRACE.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use shekyl_transport_layer::{CloseCause, CloseKind, DialEnd, DialFailure, Reached, Retry};
use support::{
    blob, carrier_rig, discard_the_carrier, id_of, new_transactions, Build, Rig, SETTLE, STEP,
};

/// Every event this process emits, as text.
fn captured() -> Arc<Mutex<Vec<u8>>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    Arc::clone(LOG.get_or_init(|| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || Sink(Arc::clone(&sink)))
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("the one subscriber");
        log
    }))
}

struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("the log").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// **A stem's transactions and successor are never logged.** A stem goes to
/// its successor, then a second stem's write fails and it falls back to
/// fluff; every event at TRACE is captured. No line names either
/// transaction, and no line about a stem names the successor (a fluff may
/// name the peers it reaches). The test first sees the stem's own event, so
/// an empty log cannot pass. Red edits: put `?peer` back on "a reshape stem
/// was written", `?destination` on "a stem was forwarded" or
/// `tx = ?pending.tx` on the carrier's discard, and this fails.
#[test]
fn the_log_never_names_a_stems_transactions_or_its_successor() {
    let log = captured();
    let rig = Rig::build(Build::default());
    let mut successor = rig.outbound(1);
    let sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(1)], false));
    let batch = rig.read_batch(&mut successor);
    assert!(!batch.dandelionpp_fluff, "fixture: a stem epoch, routed");

    successor.writer_fails(DialEnd::new(
        DialFailure::local(Retry::Again, Reached::StreamOpened),
        CloseCause::new(CloseKind::IoError),
    ));
    sender.inject_blocking(new_transactions(vec![blob(2)], false));
    support::wait_until("the fallback showed it", || {
        rig.pool.shown().contains(&id_of(&blob(2)))
    });
    thread::sleep(SETTLE);

    let text = String::from_utf8(log.lock().expect("the log").clone()).expect("UTF-8");
    assert!(
        text.contains("a stem was forwarded"),
        "the capture saw the stem's own event:\n{text}"
    );
    for tag in [1, 2] {
        let tx = format!("{:?}", id_of(&blob(tag)));
        assert!(
            !text.contains(&tx),
            "the log names a stem's transaction:\n{text}"
        );
    }
    let named = format!("{:?}", shekyl_relay::owner::connection_id(successor.id));
    for line in text.lines().filter(|line| line.contains("stem")) {
        assert!(
            !line.contains(&named),
            "a stem line names its successor: {line}"
        );
    }
    drop(sender);
}

/// The log as text, so far.
fn text(log: &Mutex<Vec<u8>>) -> String {
    String::from_utf8(log.lock().expect("the log").clone()).expect("UTF-8")
}

/// **The carrier's discarded stem and the embargo's reshape stem are logged
/// without their transactions or successors too.** A stem the carrier
/// holds is discarded when its sessions go, and fluffs; a stem whose
/// embargo fires with no re-arrival is re-stemmed to the alternate
/// successor. The test first sees both events. Red edits: put
/// `tx = ?pending.tx` back on the discard's line, or `?peer` on "a reshape
/// stem was written", and this fails.
#[test]
fn the_carrier_discard_and_the_reshape_name_nothing_either() {
    let log = captured();

    let rig = carrier_rig();
    let first = rig.outbound(1);
    let second = rig.outbound(2);
    let sender = rig.inbound(1);
    let named: Vec<String> = [first.id, second.id]
        .iter()
        .map(|id| format!("{:?}", shekyl_relay::owner::connection_id(*id)))
        .collect();
    sender.inject_blocking(new_transactions(vec![blob(7)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    discard_the_carrier(&rig, vec![first, second]);
    drop(sender);

    let rig = Rig::build(Build::default());
    let mut one = rig.outbound(1);
    let mut two = rig.outbound(2);
    let sender = rig.inbound(1);
    let mut named = named;
    named.extend(
        [one.id, two.id]
            .iter()
            .map(|id| format!("{:?}", shekyl_relay::owner::connection_id(*id))),
    );
    sender.inject_blocking(new_transactions(vec![blob(8)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    // Drain whichever successor took the stem, then let the embargo fire.
    thread::sleep(SETTLE);
    drop(rig.batches(&mut one));
    drop(rig.batches(&mut two));
    rig.drive(STEP, 200, || text(&log).contains("a reshape stem was"));
    drop(sender);

    let text = text(&log);
    assert!(
        text.contains("the carrier discarded a forwarded stem"),
        "the capture saw the carrier's discard:\n{text}"
    );
    assert!(
        text.contains("a reshape stem was"),
        "the capture saw the embargo's reshape:\n{text}"
    );
    for tag in [7, 8] {
        let tx = format!("{:?}", id_of(&blob(tag)));
        assert!(
            !text.contains(&tx),
            "the log names a stem's transaction:\n{text}"
        );
    }
    for line in text.lines().filter(|line| line.contains("stem")) {
        for successor in &named {
            assert!(
                !line.contains(successor),
                "a stem line names its successor: {line}"
            );
        }
    }
}
