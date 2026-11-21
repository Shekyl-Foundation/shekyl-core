// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The embargo and its reshape (`DAEMON_RELAY_PRIVACY.md` §12, §14.7; RX-2,
//! Rick 2026-10-29; once sent, an own transaction is a relayed one, Rick
//! 2026-11-18). Each test names the edit that turns it red.

#![cfg(test)]

use std::ops::ControlFlow;

use shekyl_draw_rng::SplitMix64;
use shekyl_relay_privacy::conformance::RecoveryBudget;
use shekyl_relay_privacy::params::{origin_retry_one_in, DandelionParams};
use shekyl_relay_privacy::schedule::{EmbargoTimer, PeerDirection};

use super::*;
use crate::driver::{Driver, Effect};
use crate::stem_watch::TxId;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

fn tx(byte: u8) -> (TxId, TxBlob) {
    (
        TxId::from_bytes([byte; 32]),
        TxBlob::from(&[byte, 0xAB, 0xCD][..]),
    )
}

/// A clearnet zone in a stem epoch with outbound sessions on `peers`.
fn stem_zone(peers: &[u8], rng: &mut SplitMix64) -> Relay {
    for _ in 0..10_000 {
        let mut z = Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Clearnet],
            0,
            rng,
        )
        .unwrap();
        if z.is_fluffing() {
            continue;
        }
        for peer in peers {
            z.on_session_established(
                id(*peer),
                PeerDirection::Outbound,
                ConnectorId::Clearnet,
                rng,
            );
        }
        return z;
    }
    panic!("no stem epoch in 10k draws");
}

/// Plan this node's own transaction and record its stem, as the C++ does
/// after a successful send. Returns the successor.
fn originate(z: &mut Relay, sent: &(TxId, TxBlob), rng: &mut SplitMix64) -> ConnectionId {
    z.set_node_sync(NodeSync::Synchronised, 0);
    let RelayPlan::Stem(successor) = z.plan_relay(None, true, NodeSync::Synchronised, rng) else {
        panic!("the origin has a stem");
    };
    z.record_stem(std::slice::from_ref(sent), successor, None, 0, rng);
    successor
}

/// The overdue budget is status only: two fires of the shared timer, each
/// at the 1-in-10 confidence, over the longest transit. Nothing is sent on
/// it. The waits a test gives a fire are the same timer's quantiles: 1 in
/// 1000 for a fire that must come, 1 in 10 for one that must not.
/// Red edit: derive any of them from a timer of its own. The reshape
/// budget's mean and its 1-in-100 deadline are a different clock.
#[test]
fn the_overdue_budget_is_two_fires_of_the_shared_timer() {
    /// The longest-transit timer's 1-in-10 quantile at the shipped terms
    /// (`DAEMON_RELAY_PRIVACY.md` §92.5c item 3).
    const PER_FIRE_SECS: u32 = 1_176;
    let params = DandelionParams::adopted_for_transit_ms(longest_transit());
    let timer = EmbargoTimer::adopted(&params);
    let fires = u32::try_from(params.graph.stem_count()).expect("stem count fits u32");
    let retry_cap = fires.checked_sub(1).expect("at least one fire");
    let recovery = RecoveryBudget::for_cap(&timer, retry_cap);
    assert_eq!(recovery.cycles, fires);
    let per_fire = timer.judge_failed_after_secs(origin_retry_one_in());
    assert_eq!(per_fire, PER_FIRE_SECS);
    let budget_ms = u64::from(per_fire) * 1_000 * u64::from(recovery.cycles);
    assert_eq!(origin_publication_budget_ms(), budget_ms);
    assert_ne!(u64::from(recovery.mean_secs) * 1_000, budget_ms);
    assert_ne!(u64::from(recovery.failed_secs) * 1_000, budget_ms);
    assert_eq!(
        embargo_fire_wait_secs(),
        timer.judge_failed_after_secs(super::embargo::FIRE_WAIT_MISS_ONE_IN)
    );
    assert_eq!(embargo_quiet_wait_secs(), per_fire);
    assert!(
        embargo_fire_wait_secs() > embargo_quiet_wait_secs(),
        "a fire that must come is waited for longer than one that must not"
    );
}

/// **Once sent, this node's own transaction gets the reaction a relayed one
/// gets** (Rick, 2026-11-18): the same timer and the same two steps. A stem
/// peer that drops every stem from a node and watches what the node does
/// must not be able to sort the node's own transactions from the ones it
/// relays.
///
/// Over a thousand seeds, one zone stems its own transaction and its twin stems a
/// relayed one, each recorded and fired with a generator of the same seed.
/// The first deadline, the reshape, the second deadline and the broadcast
/// are the same. Red edit: any branch on `source` in `record_stem` or
/// `fire_embargoes`: a fixed interval for the origin, at the first send or
/// at the reshape (the deadlines differ), or planning the origin again
/// where a relayed stem is broadcast (the reactions differ).
#[test]
fn a_dropped_stem_gets_one_reaction_own_or_relayed() {
    #[derive(Debug, PartialEq)]
    struct Reaction {
        first_fire: Millis,
        restems: usize,
        second_fire: Millis,
        published: usize,
        left: usize,
    }
    let run = |seed: u64, own: bool| {
        let mut rng = SplitMix64::new(0xD0 + seed);
        let mut z = stem_zone(&[1, 2], &mut rng);
        z.on_session_established(
            id(9),
            PeerDirection::Inbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
        z.set_node_sync(NodeSync::Synchronised, 0);
        let source = (!own).then_some(id(9));
        let RelayPlan::Stem(successor) =
            z.plan_relay(source, own, NodeSync::Synchronised, &mut rng)
        else {
            panic!("a stem epoch stems");
        };
        let sent = tx(40);
        // Fresh generators of one seed, so only the code path can differ.
        z.record_stem(
            std::slice::from_ref(&sent),
            successor,
            source,
            0,
            &mut SplitMix64::new(seed),
        );
        let first_fire = z.stem_observation_deadline().expect("armed");
        let first = z.fire_embargoes(first_fire, &mut SplitMix64::new(seed ^ 0x55));
        assert!(
            z.stem_observation_deadline().is_none(),
            "the fire asks for the reshape; the write arms it"
        );
        z.commit_stem(
            &first.stems[0],
            first_fire,
            &mut SplitMix64::new(seed ^ 0x55),
        );
        let second_fire = z.stem_observation_deadline().expect("the write armed it");
        let second = z.fire_embargoes(second_fire, &mut SplitMix64::new(seed ^ 0xAA));
        assert!(first.published.is_empty() && second.stems.is_empty());
        Reaction {
            first_fire,
            restems: first.stems.len(),
            second_fire,
            published: second.published.len(),
            left: z.relay_state_len(),
        }
    };
    /// Seeds walked. Enough that the printed means sit within a few
    /// percent of the timer's (an exponential's mean over n draws has a
    /// relative error of 1/sqrt(n)).
    const SEEDS: u64 = 1_024;
    let (mut to_reshape, mut to_broadcast) = (0_u64, 0_u64);
    for seed in 0..SEEDS {
        let own = run(seed, true);
        assert_eq!(own, run(seed, false), "seed {seed}");
        assert_eq!(
            (own.restems, own.published, own.left),
            (1, 1, 0),
            "seed {seed}"
        );
        to_reshape += own.first_fire;
        to_broadcast += own.second_fire;
    }
    // The failure path's times, for the record: a stem dropped at its first
    // hop, on the clearnet connector.
    println!(
        "dropped at the first hop, {SEEDS} seeds, own and relayed alike: mean {} s to the \
         reshape, mean {} s to the broadcast",
        to_reshape / SEEDS / 1_000,
        to_broadcast / SEEDS / 1_000
    );
}

/// The judgment is a function of an arm time and the clock at the read.
/// The zone's map stores the arm. One millisecond inside the budget is
/// held; the budget itself is overdue. The single-tx query is that
/// function on the map.
#[test]
fn an_origin_is_judged_when_it_is_read() {
    let budget = origin_publication_budget_ms();
    assert_eq!(
        OriginPublication::judge(0, budget - 1),
        OriginPublication::Held
    );
    assert_eq!(
        OriginPublication::judge(0, budget),
        OriginPublication::HeldOverdue
    );
    let armed_at = 40_000;
    assert_eq!(
        OriginPublication::judge(armed_at, armed_at + budget - 1),
        OriginPublication::Held
    );

    let mut rng = SplitMix64::new(0xB1);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(11);
    originate(&mut z, &sent, &mut rng);
    let armed = z.origin_armed();
    let at = armed.get(&sent.0).copied().expect("the origin is armed");
    for now in [at, at + budget - 1, at + budget] {
        assert_eq!(
            z.origin_publication(&sent.0, now),
            Some(OriginPublication::judge(at, now)),
            "now {now}"
        );
    }
    assert_eq!(
        armed.get(&sent.0).copied(),
        Some(at),
        "the map keeps the arm time after the late read"
    );
}

/// The daemon judges an origin hold on its own clock. One millisecond
/// inside the budget is held; the budget itself, with the hold still
/// there, is overdue. A relay position is not an origin. Once its fires have
/// run and it is broadcast, the transaction is no longer held.
#[test]
fn the_daemon_judges_an_origin_hold_against_its_own_budget() {
    let mut rng = SplitMix64::new(0xB0);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(7);
    let successor = originate(&mut z, &sent, &mut rng);
    let budget = origin_publication_budget_ms();

    assert_eq!(
        z.origin_publication(&sent.0, budget - 1),
        Some(OriginPublication::Held)
    );
    // The fire has not run. The hold is still here, and the clock is due.
    assert_eq!(
        z.origin_publication(&sent.0, budget),
        Some(OriginPublication::HeldOverdue)
    );

    let relayed = tx(8);
    z.record_stem(
        std::slice::from_ref(&relayed),
        successor,
        Some(id(1)),
        0,
        &mut rng,
    );
    assert_eq!(
        z.origin_publication(&relayed.0, budget),
        None,
        "a relay position is not this node's origin"
    );

    let mut fired = stem_zone(&[1, 2], &mut rng);
    let broadcast = tx(9);
    originate(&mut fired, &broadcast, &mut rng);
    let first = fired.stem_observation_deadline().expect("armed");
    let reshape = fired.fire_embargoes(first, &mut rng);
    assert!(
        fired.stem_observation_deadline().is_none(),
        "the fire asks for the reshape; the write arms it"
    );
    for stem in &reshape.stems {
        fired.commit_stem(stem, first, &mut rng);
    }
    let second_at = fired
        .stem_observation_deadline()
        .expect("armed by the write");
    let second = fired.fire_embargoes(second_at, &mut rng);
    assert_eq!(second.published, vec![broadcast.0]);
    assert_eq!(
        fired.origin_publication(&broadcast.0, budget),
        None,
        "the last fire broadcasts, so the hold is gone"
    );

    let mut waiting = stem_zone(&[1, 2], &mut rng);
    let unsent = tx(10);
    waiting.hold_origin(std::slice::from_ref(&unsent), 0);
    assert_eq!(
        waiting.origin_publication(&unsent.0, budget - 1),
        Some(OriginPublication::Held)
    );
    assert_eq!(
        waiting.origin_publication(&unsent.0, budget),
        Some(OriginPublication::HeldOverdue)
    );
}

/// §12.2 at the origin: its first fire re-stems once to its alternate, the
/// other live slot, on the shared timer's draw; its second fire fluffs to
/// every session and publishes, as for a relayed stem. Red edits: fluff on
/// every fire (the C++ behaviour §14 rejected) fails the first-fire
/// assertion; plan the origin again at the second fails the publication.
#[test]
fn an_own_transaction_re_stems_once_to_its_alternate_then_is_broadcast() {
    let mut rng = SplitMix64::new(0xE1);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(7);
    let successor = originate(&mut z, &sent, &mut rng);
    let alternate = z.alternate_of(&sent.0).expect("two slots: an alternate");
    assert_ne!(alternate, successor);

    let fire = z.stem_observation_deadline().expect("armed");
    let early = z.fire_embargoes(fire - 1, &mut rng);
    assert!(
        early.stems.is_empty() && early.published.is_empty(),
        "nothing fires before the deadline"
    );

    let first = z.fire_embargoes(fire, &mut rng);
    assert_eq!(
        first.stems,
        vec![StemWork {
            peer: alternate,
            tx: sent.0,
            blob: TxBlob::clone(&sent.1),
            source: None,
        }],
        "the first fire re-stems to the alternate"
    );
    assert!(
        first.published.is_empty(),
        "the first fire does not publish"
    );
    assert!(
        z.stem_observation_deadline().is_none(),
        "the fire asks for the reshape; the write arms it"
    );
    z.commit_stem(&first.stems[0], fire, &mut rng);

    let second_at = z.stem_observation_deadline().expect("armed by the write");
    let second = z.fire_embargoes(second_at, &mut rng);
    assert!(second.stems.is_empty(), "the cap is one re-stem");
    assert_eq!(second.published, vec![sent.0], "the second fire publishes");
    for peer in [successor, alternate] {
        assert_eq!(
            z.peer(&peer).expect("connected").queued,
            [TxBlob::clone(&sent.1)],
            "the last resort fluffs to every session"
        );
    }
    assert_eq!(
        z.relay_state_len(),
        0,
        "a fluffed transaction leaves no state"
    );
}

/// W3b: with no live alternate the first fire ends the stem phase, for this
/// node's own transaction as for a relayed one: fluffed to every session
/// but its source, and published. Red edit: re-stem to the successor itself
/// when there is no alternate.
#[test]
fn no_live_alternate_ends_the_stem_at_the_first_fire() {
    let mut rng = SplitMix64::new(0xE2);
    let mut z = stem_zone(&[1], &mut rng);
    let sent = tx(8);
    originate(&mut z, &sent, &mut rng);
    assert_eq!(z.alternate_of(&sent.0), None, "one slot: no alternate");
    let fire = z.stem_observation_deadline().expect("armed");
    let fired = z.fire_embargoes(fire, &mut rng);
    assert!(fired.stems.is_empty());
    assert_eq!(
        fired.published,
        vec![sent.0],
        "broadcast, as a relayed stem is"
    );
    assert!(!z.holds_unsent(&sent.0));

    let mut relay = stem_zone(&[1], &mut rng);
    relay.on_session_established(
        id(9),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let forwarded = tx(18);
    let RelayPlan::Stem(successor) =
        relay.plan_relay(Some(id(9)), false, NodeSync::Synchronised, &mut rng)
    else {
        panic!("a stem epoch stems");
    };
    relay.record_stem(
        std::slice::from_ref(&forwarded),
        successor,
        Some(id(9)),
        0,
        &mut rng,
    );
    let fired = relay.fire_embargoes(Millis::MAX / 2, &mut rng);
    assert!(fired.stems.is_empty());
    assert_eq!(fired.published, vec![forwarded.0], "published");
    assert_eq!(
        relay.peer(&successor).expect("connected").queued,
        [TxBlob::clone(&forwarded.1)],
        "fluffed to the sessions other than its source"
    );
    assert!(
        relay.peer(&id(9)).expect("connected").queued.is_empty(),
        "not back to its source"
    );
    assert_eq!(relay.relay_state_len(), 0);
}

/// §12.2 is position-blind: a relay that forwarded a stem re-stems to its
/// own alternate when its embargo fires, at its connector's draw. Red edit:
/// arm the embargo for the origin only.
#[test]
fn a_relay_position_re_stems_to_its_own_alternate() {
    let mut rng = SplitMix64::new(0xE3);
    let mut z = stem_zone(&[1, 2], &mut rng);
    z.on_session_established(
        id(9),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let sent = tx(9);
    let RelayPlan::Stem(successor) =
        z.plan_relay(Some(id(9)), false, NodeSync::Synchronised, &mut rng)
    else {
        panic!("a stem epoch stems");
    };
    z.record_stem(
        std::slice::from_ref(&sent),
        successor,
        Some(id(9)),
        0,
        &mut rng,
    );
    let alternate = z.alternate_of(&sent.0).expect("an alternate");

    let fired = z.fire_embargoes(Millis::MAX / 2, &mut rng);
    assert_eq!(
        fired.stems,
        vec![StemWork {
            peer: alternate,
            tx: sent.0,
            blob: TxBlob::clone(&sent.1),
            source: Some(id(9)),
        }]
    );
    assert_ne!(alternate, id(9), "never back to the source");
}

/// §92.5c item 1: an arrival from somewhere other than the successor disarms
/// the embargo, and no fire follows; the charged successor's echo disarms
/// nothing (F-10). Red edit: drop the disarm from `record_arrival`.
#[test]
fn circulation_disarms_and_an_echo_does_not() {
    let mut rng = SplitMix64::new(0xE4);
    let mut z = stem_zone(&[1, 2, 3], &mut rng);
    let sent = tx(10);
    let successor = originate(&mut z, &sent, &mut rng);

    assert!(
        z.record_arrival(&[sent.0], Some(successor)).is_empty(),
        "the successor's echo resolves nothing"
    );
    let other = [1, 2, 3]
        .map(id)
        .into_iter()
        .find(|peer| *peer != successor)
        .expect("three peers");
    assert_eq!(
        z.record_arrival(&[sent.0], Some(other)),
        vec![sent.0],
        "an arrival from elsewhere circulates"
    );
    let fired = z.fire_embargoes(Millis::MAX / 2, &mut rng);
    assert!(
        fired.stems.is_empty() && fired.published.is_empty(),
        "a disarmed embargo never fires"
    );
    assert_eq!(z.relay_state_len(), 0);
}

/// W3c: churn that refills a slot within the epoch does not hand the
/// reshape a fresh draw. The alternate is the one captured at the first
/// stem; when it has left, the fire ends the stem phase rather than
/// re-stemming to the refill.
/// Red edit: read the alternate from the live slots at fire.
#[test]
fn a_churn_refill_does_not_change_the_alternate() {
    let mut rng = SplitMix64::new(0xE5);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(11);
    originate(&mut z, &sent, &mut rng);
    let alternate = z.alternate_of(&sent.0).expect("an alternate");

    z.on_connection_close(&alternate);
    z.on_session_established(
        id(3),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        z.alternate_of(&sent.0),
        Some(alternate),
        "the captured alternate is not re-read"
    );

    let fire = z.stem_observation_deadline().expect("armed");
    let fired = z.fire_embargoes(fire, &mut rng);
    assert!(
        fired.stems.iter().all(|stem| stem.peer != id(3)),
        "the refill is never the reshape's target"
    );
    assert_eq!(
        fired.published,
        vec![sent.0],
        "a gone alternate is the W3b fallback"
    );
}

/// RX-2 and the AwaitSync hold: an unsynchronised origin is held, not shown
/// and not fluffed, and sent once the node turns synchronised, with its
/// embargo armed. Red edit: drop `unsent_due_now` from `set_node_sync`.
#[test]
fn an_unsynchronised_origin_is_held_and_sent_once_synchronised() {
    let mut rng = SplitMix64::new(0xE6);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(12);
    z.hold_origin(std::slice::from_ref(&sent), 0);
    assert!(z.holds_unsent(&sent.0));

    let waiting = z.due_unsent(NEVER_SENT_RETRY_MS, &mut rng);
    assert!(
        waiting.stems.is_empty() && waiting.published.is_empty(),
        "unsynchronised: held, neither sent nor published"
    );
    assert!(z.holds_unsent(&sent.0));

    z.set_node_sync(NodeSync::Synchronised, NEVER_SENT_RETRY_MS + 1);
    let now = NEVER_SENT_RETRY_MS + 1;
    let sent_now = z.due_unsent(now, &mut rng);
    assert_eq!(
        sent_now.stems.len(),
        1,
        "planned at the sync turn, not a grid later"
    );
    assert_eq!(sent_now.stems[0].blob, sent.1);
    assert!(z.holds_unsent(&sent.0), "unsent until the write lands");
    assert_eq!(
        z.stem_observations_in_flight(),
        0,
        "the plan does not arm the embargo"
    );
    let again = z.due_unsent(now, &mut rng);
    assert!(again.stems.is_empty(), "a handed stem is not planned twice");
    let stem = &sent_now.stems[0];
    z.record_stem(
        &[(stem.tx, TxBlob::clone(&stem.blob))],
        stem.peer,
        stem.source,
        now,
        &mut rng,
    );
    assert!(!z.holds_unsent(&sent.0));
    assert_eq!(
        z.stem_observations_in_flight(),
        1,
        "the write armed its embargo"
    );
}

/// RX-2: a node whose connectors hide its address holds its own
/// transaction while no address-hiding session exists: not sent, not
/// published. It goes out on the own edge once one is established. Red
/// edits: fluff on `NoOwnEdge`, or drop the session-established wake.
#[test]
fn no_own_edge_holds_until_an_own_edge_appears() {
    let mut rng = SplitMix64::new(0xE7);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.rebuild_stems(&mut rng);
    z.set_node_sync(NodeSync::Synchronised, 0);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoOwnEdge,
        "fixture: no address-hiding session"
    );
    let sent = tx(13);
    z.hold_origin(std::slice::from_ref(&sent), 0);
    let held = z.due_unsent(NEVER_SENT_RETRY_MS, &mut rng);
    assert!(
        held.stems.is_empty() && held.published.is_empty(),
        "NoOwnEdge never fluffs and never publishes"
    );
    assert!(
        z.peer(&id(1)).expect("connected").queued.is_empty(),
        "nothing queued on the clear link"
    );

    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    let out = z.due_unsent(NEVER_SENT_RETRY_MS + 1, &mut rng);
    assert_eq!(
        out.stems.iter().map(|stem| stem.peer).collect::<Vec<_>>(),
        vec![id(2)],
        "the own edge carries it, at the session's wake"
    );
    assert!(out.published.is_empty());
}

/// The state is bounded by the pool: a departure leaves nothing. Red edit:
/// make `release` a no-op.
#[test]
fn a_departed_entry_leaves_no_relay_state() {
    let mut rng = SplitMix64::new(0xE8);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let stemmed = tx(14);
    let unsent = tx(15);
    originate(&mut z, &stemmed, &mut rng);
    z.hold_origin(std::slice::from_ref(&unsent), 0);
    assert_eq!(z.relay_state_len(), 2);

    z.release(&stemmed.0);
    z.release(&unsent.0);
    assert_eq!(z.relay_state_len(), 0);
    let fired = z.fire_embargoes(Millis::MAX / 2, &mut rng);
    assert!(
        fired.stems.is_empty() && fired.published.is_empty(),
        "a released transaction never fires"
    );
}

/// §12.2 item 5: the driver's reshape effect carries the transaction's own
/// bytes and nothing else, and a relayed stem's last fire names the
/// transaction for the pool. Red edit: append a retry count to the blob.
#[test]
fn the_wire_carries_only_the_transaction() {
    let mut rng = SplitMix64::new(0xE9);
    let mut z = stem_zone(&[1, 2], &mut rng);
    z.on_session_established(
        id(9),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let sent = tx(16);
    let RelayPlan::Stem(successor) =
        z.plan_relay(Some(id(9)), false, NodeSync::Synchronised, &mut rng)
    else {
        panic!("a stem epoch stems");
    };
    z.record_stem(
        std::slice::from_ref(&sent),
        successor,
        Some(id(9)),
        0,
        &mut rng,
    );
    let alternate = z.alternate_of(&sent.0).expect("an alternate");
    let mut d = Driver::new(z);

    let fire = d.zone().stem_observation_deadline().expect("armed");
    let first = d.poll(fire, &mut rng);
    let stems: Vec<_> = first
        .iter()
        .filter_map(|effect| match effect {
            Effect::Stem { stem } => Some(StemWork::clone(stem)),
            _ => None,
        })
        .collect();
    assert_eq!(
        stems,
        vec![StemWork {
            peer: alternate,
            tx: sent.0,
            blob: TxBlob::clone(&sent.1),
            source: Some(id(9)),
        }]
    );
    assert_eq!(
        stems[0].blob.as_ref(),
        sent.1.as_ref(),
        "byte for byte the transaction"
    );
    assert!(
        d.zone().stem_observation_deadline().is_none(),
        "the poll asks for the reshape; the write arms it"
    );
    d.zone_mut().commit_stem(&stems[0], fire, &mut rng);

    let second_fire = d
        .zone()
        .stem_observation_deadline()
        .expect("armed by the write");
    let second = d.poll(second_fire, &mut rng);
    assert!(
        second
            .iter()
            .any(|effect| matches!(effect, Effect::Published { txs } if txs == &vec![sent.0])),
        "the last resort names the transaction for the pool"
    );
}

/// Drive `z` to its first fire and return the reshape it asks for, not yet
/// written.
fn first_reshape(z: &mut Relay, rng: &mut SplitMix64) -> (StemWork, Millis) {
    let fire = z.stem_observation_deadline().expect("armed");
    let mut fired = z.fire_embargoes(fire, rng);
    assert_eq!(fired.stems.len(), 1, "the first fire asks for one reshape");
    (fired.stems.remove(0), fire)
}

/// **A reshape whose write missed gets one more embargo, then is broadcast,
/// own or relayed.** The fire asks for the reshape and arms nothing. The
/// caller reports the miss, the zone draws one embargo on the alternate, and
/// that fire ends the stem phase: the one re-stem was spent on the attempt.
/// With the alternate gone the miss cannot be armed and says so, so the
/// caller ends the phase at once and nothing is left waiting on a wake that
/// never comes. Red edits: arm the reshape in `fire_embargoes` (the
/// not-armed assertion); clear `restemmed` on a miss (a second reshape); or
/// branch on `source` in `reject_stem` (own and relayed differ).
#[test]
fn a_missed_reshape_is_armed_once_and_its_next_fire_broadcasts() {
    let run = |own: bool| {
        let mut rng = SplitMix64::new(0xEA);
        let mut z = stem_zone(&[1, 2], &mut rng);
        z.on_session_established(
            id(9),
            PeerDirection::Inbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
        z.set_node_sync(NodeSync::Synchronised, 0);
        let source = (!own).then_some(id(9));
        let RelayPlan::Stem(successor) =
            z.plan_relay(source, own, NodeSync::Synchronised, &mut rng)
        else {
            panic!("a stem epoch stems");
        };
        let sent = tx(41);
        z.record_stem(
            std::slice::from_ref(&sent),
            successor,
            source,
            0,
            &mut SplitMix64::new(1),
        );
        let (stem, fire) = first_reshape(&mut z, &mut rng);
        assert!(
            !z.holds_unsent(&sent.0),
            "sent once: no longer a first send"
        );
        assert!(
            z.stem_observation_deadline().is_none(),
            "the fire arms nothing"
        );
        assert_eq!(
            z.reject_stem(&stem, fire, &mut SplitMix64::new(2)),
            ControlFlow::Continue(()),
            "the alternate is connected: the miss stays armed"
        );
        let last = z
            .stem_observation_deadline()
            .expect("the miss armed one embargo");
        let ended = z.fire_embargoes(last, &mut rng);
        assert!(ended.stems.is_empty(), "the one re-stem is spent");
        assert_eq!(ended.published, vec![sent.0], "the next fire broadcasts");
        assert_eq!(z.relay_state_len(), 0);
        last - fire
    };
    assert_eq!(run(true), run(false), "one embargo, own or relayed");

    let mut rng = SplitMix64::new(0xEB);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(42);
    originate(&mut z, &sent, &mut rng);
    let (stem, fire) = first_reshape(&mut z, &mut rng);
    z.on_connection_close(&stem.peer);
    assert_eq!(
        z.reject_stem(&stem, fire, &mut rng),
        ControlFlow::Break(()),
        "a gone alternate carries no embargo: the caller ends the phase"
    );
    assert_eq!(z.relay_state_len(), 0, "the row is released with the break");
    assert!(z.stem_observation_deadline().is_none());
}

/// **A missed stem the zone has no row for is released, not adopted.**
/// Stem effects come only from unsent rows and held rows, so this is a
/// transaction the pool dropped between the ask and the write, or a caller
/// that kept a stem too long. The zone answers `Break` and writes no row:
/// the caller broadcasts. Red edit: hold whatever is not in the held rows
/// as unsent (a relayed transaction becomes this node's own, with no
/// source, and is planned again on the grid).
#[test]
fn a_missed_stem_with_no_row_is_released_and_never_adopted() {
    let mut rng = SplitMix64::new(0xED);
    let mut z = stem_zone(&[1, 2], &mut rng);
    z.set_node_sync(NodeSync::Synchronised, 0);
    let stray = tx(44);
    let stem = StemWork {
        peer: id(1),
        tx: stray.0,
        blob: TxBlob::clone(&stray.1),
        source: Some(id(2)),
    };

    assert_eq!(
        z.reject_stem(&stem, 0, &mut rng),
        ControlFlow::Break(()),
        "no row: the caller broadcasts"
    );
    assert!(!z.holds_unsent(&stray.0), "not adopted as an own origin");
    assert_eq!(z.relay_state_len(), 0, "no row is written");
    assert_eq!(z.stem_observations_in_flight(), 0, "no embargo is armed");
    assert_eq!(z.unsent_deadline(), None, "nothing is planned on the grid");
}

/// **A held origin's first send that misses stays unsent.** `due_unsent`
/// hands the stem out and arms nothing; with no record the row is still
/// unsent, not planned again before the grid, and planned again at it.
/// Red edits: record the stem in `due_unsent` (the transaction counts as
/// sent though no byte left, and reacts as a sent one); or leave `due`
/// where it was (every poll sends it again).
#[test]
fn a_first_send_that_misses_stays_unsent_and_is_planned_again_on_the_grid() {
    let mut rng = SplitMix64::new(0xEC);
    let mut z = stem_zone(&[1, 2], &mut rng);
    z.set_node_sync(NodeSync::Synchronised, 0);
    let sent = tx(43);
    z.hold_origin(std::slice::from_ref(&sent), 0);

    let first = z.due_unsent(NEVER_SENT_RETRY_MS, &mut rng);
    assert_eq!(first.stems.len(), 1, "due at the grid");
    assert_eq!(first.stems[0].source, None);
    assert_eq!(
        z.reject_stem(&first.stems[0], NEVER_SENT_RETRY_MS, &mut rng),
        ControlFlow::Continue(()),
        "a missed first send stays with the zone"
    );
    assert!(z.holds_unsent(&sent.0), "still unsent: no byte left");
    assert_eq!(z.stem_observations_in_flight(), 0, "no embargo is armed");
    assert_eq!(
        z.unsent_deadline(),
        Some(2 * NEVER_SENT_RETRY_MS),
        "it waits one grid"
    );
    let early = z.due_unsent(2 * NEVER_SENT_RETRY_MS - 1, &mut rng);
    assert!(early.stems.is_empty() && early.published.is_empty());
    let again = z.due_unsent(2 * NEVER_SENT_RETRY_MS, &mut rng);
    assert_eq!(again.stems.len(), 1, "planned again at the grid");
    assert!(again.published.is_empty(), "never shown by a failed write");
}
