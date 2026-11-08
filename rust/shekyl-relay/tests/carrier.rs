// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay owner with the covert carrier on (`noise: true`): a stem
//! rides fixed-size windows on its stem slot's channel instead of the
//! ordinary wire, and the owner learns what became of it only from the
//! carrier's verdict (`DAEMON_RELAY_PRIVACY.md` §42, §92.5c; COVER §3.1).
//!
//! These are the carrier cases `tests/unit_tests/levin.cpp` held before the
//! C++ host was deleted, re-asserted against `owner::actor`'s dispatch and
//! verdict paths through the owner's own surfaces: what the far side of
//! each session reads, what the pool is told (`shown`), and the published
//! stem observations (`stem_in_flight`).
//!
//! The rig's clock is manual. A carrier window goes out only when the
//! clock moves (each channel every 3.3–6.7 s), so "the carrier took it" is
//! recognised the way the C++ cases recognised it: nothing reaches any
//! wire, nothing is shown, nothing is observed — until the clock moves.

mod support;

use std::thread;
use std::time::Duration;

use shekyl_levin::NewTransactions;
use shekyl_p2p_session::harness::Wire;
use shekyl_transport_layer::{CloseCause, CloseKind, DialEnd, DialFailure, Reached, Retry};
use support::{blob, id_of, new_transactions, Build, Rig, SEND_CAP, SETTLE};

/// One second: shorter than the carrier's fastest cadence, so a drive in
/// these steps sees every window a channel emits.
const STEP: Duration = Duration::from_secs(1);

fn carrier_rig() -> Rig {
    carrier_rig_from(Build::default())
}

fn carrier_rig_from(build: Build) -> Rig {
    let rig = Rig::build(Build {
        noise: true,
        ..build
    });
    support::wait_until("fixture: the zone must run the carrier", || {
        rig.relay.snapshot().noise
    });
    rig
}

/// Every 2002 the wires read, in wire order.
fn read_all(rig: &Rig, wires: &mut [&mut Wire]) -> Vec<NewTransactions> {
    wires
        .iter_mut()
        .flat_map(|wire| rig.batches(wire))
        .collect()
}

/// Past the first epoch's end (600 s plus up to 30 s of jitter, from a
/// clock at 1 ms): the roll that rebuilds the stem slots from the
/// sessions that are left.
const PAST_THE_FIRST_EPOCH: Duration = Duration::from_secs(640);

/// A blob the carrier cannot take: its 2002 frames to more than
/// `MAX_FRAGMENTS` (5) windows of 20,480 bytes, which the carrier refuses.
fn oversize(tag: u8) -> Vec<u8> {
    vec![tag; 110_000]
}

/// Close every outbound session, then roll the epoch with none left. A
/// close alone does not unbind a channel: the slot keeps the dead peer
/// until the map is rebuilt, and only a due tick on an empty slot clears
/// the channel's queue, reporting each message it held as discarded.
fn discard_the_carrier(rig: &Rig, outbound: Vec<Wire>) {
    for mut wire in outbound {
        let id = wire.id;
        wire.peer_closes();
        rig.wait_closed(id);
        drop(wire);
    }
    // The owner hears the closes after the board does.
    thread::sleep(SETTLE);
    rig.advance(PAST_THE_FIRST_EPOCH);
    thread::sleep(SETTLE);
    // Each channel is due within 6.7 s of the roll, one per wake.
    rig.drive(STEP, 15, || false);
    thread::sleep(SETTLE);
}

/// The batches that carry `blob`.
fn carrying(batches: &[NewTransactions], blob: &[u8]) -> usize {
    batches
        .iter()
        .filter(|batch| batch.txs.iter().any(|tx| tx == blob))
        .count()
}

/// The carrier took the stem: no wire read it, the pool was told nothing,
/// and no stem observation is armed. An ordinary stem would have been on a
/// successor's wire already, armed; a fluff would have been shown.
fn assert_the_carrier_holds_it(rig: &Rig, wires: &mut [&mut Wire]) {
    thread::sleep(SETTLE);
    let early = read_all(rig, wires);
    assert!(
        early.is_empty(),
        "the stem went out before the clock moved, so it took the ordinary \
         wire rather than the carrier: {early:?}"
    );
    assert!(
        rig.pool.shown().is_empty(),
        "an enqueue is not a send: the pool is told nothing yet"
    );
    assert_eq!(
        rig.relay.snapshot().stem_in_flight,
        0,
        "an enqueue arms no stem observation; the verdict does"
    );
}

/// **A real transaction rides the carrier, and the stem is recorded only
/// when its last window has gone out.** (Replaces the C++
/// `a_real_transaction_rides_the_carrier_and_records_on_arrival`.)
///
/// Before the clock moves nothing is on any wire and nothing is armed:
/// the enqueue is not a send. Once the channel emits, exactly one 2002
/// carrying the transaction reaches a successor, flagged stem, and the
/// verdict's `record_stem` arms the observation. The pool is not told: a
/// stem is shown only when its embargo resolves.
///
/// What edit reds this: delete the `record_stem` call in `apply_verdict`'s
/// sent arm (nothing is ever observed), or send the carrier's share on the
/// ordinary wire (the first assertion sees it before the clock moves).
#[test]
fn a_real_transaction_rides_the_carrier_and_is_recorded_when_its_window_goes_out() {
    let rig = carrier_rig();
    let mut first = rig.outbound(1);
    let mut second = rig.outbound(2);
    let sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(3)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    assert_the_carrier_holds_it(&rig, &mut [&mut first, &mut second]);

    let recorded = rig.drive(STEP, 30, || rig.relay.snapshot().stem_in_flight == 1);
    assert!(
        recorded,
        "the carrier never recorded the stem: either no window carrying it \
         went out, or its verdict did not reach `record_stem`"
    );
    let carried = read_all(&rig, &mut [&mut first, &mut second]);
    assert_eq!(
        carrying(&carried, &blob(3)),
        1,
        "exactly one emission carries the transaction: zero means only cover \
         went out while the stem was recorded, two means it was sent twice: \
         {carried:?}"
    );
    let batch = carried
        .iter()
        .find(|batch| batch.txs == vec![blob(3)])
        .expect("the carried batch is the transaction alone");
    assert!(!batch.dandelionpp_fluff, "a carried stem is flagged stem");
    assert!(
        rig.pool.shown().is_empty(),
        "a carried stem is not shown until its embargo resolves"
    );
    drop(sender);
}

/// **An originated transaction the carrier discards is held, not shown.**
/// (Replaces the C++ `a_discarded_origin_is_left_unrelayed_for_the_short_grid`.)
///
/// An origin the carrier dropped was never sent. Showing or fluffing it
/// would publish this node's own transaction from its own address, and
/// recording it would buy it the long origin retry for a send that never
/// happened (§92.5c). It is held instead, and re-planned: the moment an
/// outbound session appears it leaves on the ordinary wire as a stem,
/// before the clock moves (the carrier would need the clock).
///
/// What edit reds this: drop the `pending.local` arm of `apply_verdict`,
/// so a discarded origin takes the forwarded stem's fluff fallback (it is
/// shown); or drop the `hold_origin` call (the new session never gets it).
#[test]
fn a_discarded_origin_is_held_unshown_and_leaves_on_the_next_outbound_session() {
    // The watch starts synchronised, with no change for the owner to see:
    // the zone's planner of held origins must read it from the start, or
    // the held origin waits at AwaitSync for good.
    let rig = carrier_rig_from(Build::default());
    let mut first = rig.outbound(1);
    let mut second = rig.outbound(2);
    let tx = id_of(&blob(4));
    rig.pool.hold(tx);
    assert!(rig.relay.relay_local(tx, blob(4)), "the owner took it");
    assert_the_carrier_holds_it(&rig, &mut [&mut first, &mut second]);

    discard_the_carrier(&rig, vec![first, second]);
    assert!(
        rig.pool.shown().is_empty(),
        "an originated transaction the carrier discarded was shown: the \
         discard took the fluff fallback, which publishes this node's own \
         transaction for a send that never happened"
    );
    assert_eq!(rig.relay.snapshot().stem_in_flight, 0);

    // Read without moving the clock: the carrier cannot have sent it.
    let mut fresh = rig.outbound(3);
    let batch = support::batch_of(rig.read_within(&mut fresh, SETTLE).expect(
        "the discarded origin was not held: a new outbound session should \
         take it at once as an ordinary stem, and nothing came",
    ));
    assert_eq!(
        batch.txs,
        vec![blob(4)],
        "the held origin leaves on the first outbound session it gets"
    );
    assert!(!batch.dandelionpp_fluff, "an origin stems");
    assert!(rig.pool.shown().is_empty(), "a stem is not shown");
}

/// **A forwarded stem the carrier discards falls back to fluff.**
/// (Replaces the C++ `a_discarded_forwarded_stem_falls_back_to_fluff`.)
///
/// A relayed transaction is not this node's, and the carrier's discard
/// leaves nobody else to move it on: without the fallback it is stranded
/// in this node's pool. It is shown, and the next fluff release carries it
/// to the peers other than its source.
///
/// What edit reds this: drop `fluff_and_record` from `apply_verdict`'s
/// discard arm (nothing is shown and nothing is fluffed).
#[test]
fn a_discarded_forwarded_stem_falls_back_to_fluff() {
    let rig = carrier_rig();
    let mut first = rig.outbound(1);
    let mut second = rig.outbound(2);
    let sender = rig.inbound(1);
    let mut bystander = rig.inbound(2);
    sender.inject_blocking(new_transactions(vec![blob(6)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    assert_the_carrier_holds_it(&rig, &mut [&mut first, &mut second]);

    discard_the_carrier(&rig, vec![first, second]);
    assert_eq!(
        rig.pool.shown(),
        vec![id_of(&blob(6))],
        "a forwarded stem the carrier discarded must be shown and fluffed; \
         otherwise nothing ever moves it on and it is stranded until it \
         expires from the pool"
    );
    let batch = rig.read_batch_within(&mut bystander, 10);
    assert!(batch.dandelionpp_fluff, "the fallback is a fluff");
    assert_eq!(batch.txs, vec![blob(6)]);
    drop(sender);
}

/// **A transaction the carrier already holds is not handed over twice.**
/// (Replaces the C++ `a_transaction_already_in_the_carrier_is_not_enqueued_twice`.)
///
/// The pool re-offers an origin on its own schedule, which is shorter
/// than a channel's backlog may take to drain. A second offer while the
/// first is still queued must neither take the ordinary wire nor ride the
/// carrier a second time: two copies would be two stems, two successors
/// charged, for one transaction.
///
/// The carrier is drained for long enough that a second copy queued
/// behind the first would have gone out too, before anything is counted.
///
/// What edit reds this: drop the `carrier_pending` scan in `dispatch`.
#[test]
fn a_transaction_already_in_the_carrier_is_not_enqueued_twice() {
    let rig = carrier_rig();
    let mut first = rig.outbound(1);
    let mut second = rig.outbound(2);
    let tx = id_of(&blob(5));
    rig.pool.hold(tx);
    assert!(rig.relay.relay_local(tx, blob(5)));
    assert_the_carrier_holds_it(&rig, &mut [&mut first, &mut second]);

    assert!(
        rig.relay.relay_local(tx, blob(5)),
        "the owner took the re-offer"
    );
    assert_the_carrier_holds_it(&rig, &mut [&mut first, &mut second]);

    rig.drive(STEP, 40, || false);
    let carried = read_all(&rig, &mut [&mut first, &mut second]);
    assert_eq!(
        carrying(&carried, &blob(5)),
        1,
        "the carrier sent the transaction {} time(s): a second copy rode it, \
         which stems one transaction twice",
        carrying(&carried, &blob(5))
    );
    assert_eq!(rig.relay.snapshot().stem_in_flight, 1);
}

/// **A batch the carrier can only partly take splits: the refused half
/// alone takes the ordinary stem, the taken half alone rides the carrier.**
/// (Replaces the C++ `a_batch_the_carrier_partly_refuses_splits_without_double_counting`,
/// its stem half.)
///
/// The refusal is by size, the realistic one: a transaction over five
/// windows cannot be carried. The ordinary wire must carry only that one;
/// sending the whole batch there would put the carried transaction on the
/// clear wire as well, and record it before any window of it went out.
///
/// The rig's send cap is raised so the oversize stem is written rather
/// than closing the session; the failed-write half is the next case.
///
/// What edit reds this: send the whole batch after the carrier loop in
/// `dispatch` (replace `to_send = refused` with the original batch).
#[test]
fn a_batch_the_carrier_partly_refuses_stems_only_the_refused_half() {
    let rig = carrier_rig_from(Build {
        send_cap: 1 << 20,
        ..Build::default()
    });
    let mut first = rig.outbound(1);
    let mut second = rig.outbound(2);
    let sender = rig.inbound(1);
    let large = oversize(2);
    sender.inject_blocking(new_transactions(vec![blob(1), large.clone()], false));
    support::wait_until("both blobs were admitted", || rig.pool.admits().len() == 2);
    thread::sleep(SETTLE);

    let ordinary = read_all(&rig, &mut [&mut first, &mut second]);
    assert_eq!(
        ordinary.len(),
        1,
        "one ordinary stem, for the refused half: {} batch(es)",
        ordinary.len()
    );
    assert!(
        ordinary[0].txs == vec![large.clone()],
        "the ordinary stem carried {} transaction(s); the carrier took the \
         small one, so only the oversize one belongs on the clear wire",
        ordinary[0].txs.len()
    );
    assert!(!ordinary[0].dandelionpp_fluff);
    assert_eq!(
        rig.relay.snapshot().stem_in_flight,
        1,
        "only the ordinary stem is observed at send time"
    );

    let carried = rig.drive(STEP, 30, || rig.relay.snapshot().stem_in_flight == 2);
    assert!(carried, "the carrier never completed the small transaction");
    let late = read_all(&rig, &mut [&mut first, &mut second]);
    assert_eq!(
        carrying(&late, &blob(1)),
        1,
        "the small one rode the carrier once"
    );
    assert_eq!(carrying(&late, &large), 0, "the oversize one went out once");
    assert!(rig.pool.shown().is_empty());
    drop(sender);
}

/// **When the refused half's stem fails, the fluff fallback carries only
/// the refused half.** (Replaces the C++
/// `a_batch_the_carrier_partly_refuses_splits_without_double_counting`,
/// its fluff half.)
///
/// At the harness's 64 KiB send cap the oversize stem's write is refused,
/// every retry with it, and the batch falls through to fluff. The
/// transaction the carrier holds must stay out of that fluff: its verdict
/// is what resolves it, and fluffing it too would send it twice and
/// publish it while it is still being carried.
///
/// What edit reds this: as for the stem half — the whole batch reaches the
/// fallback and the carried transaction is shown.
#[test]
fn a_split_batch_whose_stem_fails_fluffs_only_the_refused_half() {
    let rig = carrier_rig();
    assert!(
        oversize(2).len() > SEND_CAP,
        "fixture: the write is refused"
    );
    let _first = rig.outbound(1);
    let _second = rig.outbound(2);
    let sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(1), oversize(2)], false));
    support::wait_until("both blobs were admitted", || rig.pool.admits().len() == 2);
    support::wait_until("the fallback showed what it fluffed", || {
        !rig.pool.shown().is_empty()
    });
    thread::sleep(SETTLE);
    assert_eq!(
        rig.pool.shown(),
        vec![id_of(&oversize(2))],
        "the fluff fallback took the transaction the carrier holds as well \
         as the one it refused"
    );
    drop(sender);
}

/// **A verdict for a transaction the pool has dropped records nothing.**
/// (Replaces the C++ `a_verdict_for_a_transaction_the_pool_dropped_records_nothing`.)
///
/// The carrier can send a transaction up to an epoch after it took it,
/// and a block may take the transaction out of the pool meanwhile. Arming
/// an observation for it then charges the successor a silence when no
/// re-arrival comes, which a mined transaction never produces: a wrong
/// tally entry, not a missing one.
///
/// The window still goes out (the carrier cannot be recalled), which is
/// what proves the verdict arrived and was refused.
///
/// What edit reds this: drop the `pool.holds` gate in `apply_verdict`.
#[test]
fn a_verdict_for_a_transaction_the_pool_dropped_records_nothing() {
    let rig = carrier_rig();
    let mut first = rig.outbound(1);
    let mut second = rig.outbound(2);
    let sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(7)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    assert_the_carrier_holds_it(&rig, &mut [&mut first, &mut second]);

    // Mined while the carrier still holds it.
    rig.pool.forget(&id_of(&blob(7)));

    let mut carried = Vec::new();
    let sent = rig.drive(STEP, 30, || {
        carried.extend(read_all(&rig, &mut [&mut first, &mut second]));
        carrying(&carried, &blob(7)) != 0
    });
    assert!(sent, "the carrier never sent it, so no verdict was reached");
    thread::sleep(SETTLE);
    assert_eq!(
        rig.relay.snapshot().stem_in_flight,
        0,
        "an observation was armed for a transaction the pool no longer \
         holds: it expires as a silence and charges a successor that did \
         nothing wrong"
    );
    assert!(rig.pool.shown().is_empty(), "nothing to show it against");
    drop(sender);
}

/// **A stem whose write fails is not recorded as stemmed; it fluffs.**
/// (Replaces the C++ `a_failed_stem_is_not_recorded_as_relayed`, which ran
/// with the carrier off, as this does.)
///
/// First a stem goes out and is observed, so the failure below is known
/// to be a stem epoch's, on a routed successor. Then the successor's
/// writer fails: the stem's write is refused, the retry with it, and the
/// transaction takes the fluff fallback. An observation armed for it would
/// charge the successor for a send that never happened.
///
/// What edit reds this: record the stem in `dispatch` whatever `send_stem`
/// returned.
#[test]
fn a_failed_stem_is_not_recorded_and_falls_back_to_fluff() {
    let rig = Rig::build(Build::default());
    let mut successor = rig.outbound(1);
    let sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(1)], false));
    let batch = rig.read_batch(&mut successor);
    assert_eq!(batch.txs, vec![blob(1)]);
    assert!(!batch.dandelionpp_fluff, "fixture: a stem epoch, routed");
    support::wait_until("the stem is observed", || {
        rig.relay.snapshot().stem_in_flight == 1
    });

    successor.writer_fails(DialEnd::new(
        DialFailure::local(Retry::Again, Reached::StreamOpened),
        CloseCause::new(CloseKind::IoError),
    ));
    sender.inject_blocking(new_transactions(vec![blob(2)], false));
    support::wait_until("the fallback showed it", || {
        rig.pool.shown().contains(&id_of(&blob(2)))
    });
    thread::sleep(SETTLE);
    assert_eq!(
        rig.relay.snapshot().stem_in_flight,
        1,
        "a stem that never reached the wire was observed as sent"
    );
    assert_eq!(rig.pool.shown(), vec![id_of(&blob(2))]);
    drop(sender);
}
