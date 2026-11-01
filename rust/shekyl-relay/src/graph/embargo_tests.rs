// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The embargo and its reshape (`DAEMON_RELAY_PRIVACY.md` §12, §14.7; RX-1
//! and RX-2, Rick 2026-10-29). Each test names the edit that turns it red.

use shekyl_draw_rng::SplitMix64;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::PeerDirection;

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

/// RX-1 and §12.2: the origin's first fire re-stems once to its alternate,
/// the other live slot, at the derived retry interval; its second fire
/// fluffs to every session and publishes. Red edits: fluff on every fire
/// (the C++ behaviour §14 rejected) fails the first-fire assertion; draw the
/// origin's deadline from the embargo timer fails the timing assertion.
#[test]
fn the_origin_re_stems_once_to_its_alternate_then_fluffs() {
    let mut rng = SplitMix64::new(0xE1);
    let mut z = stem_zone(&[1, 2], &mut rng);
    let sent = tx(7);
    let successor = originate(&mut z, &sent, &mut rng);
    let alternate = z.alternate_of(&sent.0).expect("two slots: an alternate");
    assert_ne!(alternate, successor);

    let retry = origin_retry_ms();
    let early = z.fire_embargoes(retry - 1, &mut rng);
    assert!(
        early.stems.is_empty() && early.published.is_empty(),
        "nothing fires before the retry interval"
    );

    let first = z.fire_embargoes(retry, &mut rng);
    assert_eq!(
        first.stems,
        vec![(alternate, TxBlob::clone(&sent.1))],
        "the first fire re-stems to the alternate, never fluffs"
    );
    assert!(
        first.published.is_empty(),
        "nothing is published on the first fire"
    );
    assert!(
        z.peer(&successor).expect("connected").queued.is_empty(),
        "no fluff was queued"
    );

    let second = z.fire_embargoes(2 * retry, &mut rng);
    assert!(second.stems.is_empty(), "the cap is one re-stem");
    assert_eq!(second.published, vec![sent.0], "the second fire publishes");
    for peer in [successor, alternate] {
        assert_eq!(
            z.peer(&peer).expect("connected").queued.as_slice(),
            std::slice::from_ref(&sent.1),
            "the last resort fluffs to every session"
        );
    }
    assert_eq!(
        z.relay_state_len(),
        0,
        "a fluffed transaction leaves no state"
    );
}

/// W3b: with no live alternate the first fire fluffs. Red edit: re-stem to
/// the successor itself when there is no alternate.
#[test]
fn no_live_alternate_fluffs_at_the_first_fire() {
    let mut rng = SplitMix64::new(0xE2);
    let mut z = stem_zone(&[1], &mut rng);
    let sent = tx(8);
    originate(&mut z, &sent, &mut rng);
    assert_eq!(z.alternate_of(&sent.0), None, "one slot: no alternate");

    let fired = z.fire_embargoes(origin_retry_ms(), &mut rng);
    assert!(fired.stems.is_empty());
    assert_eq!(fired.published, vec![sent.0]);
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
    assert_eq!(fired.stems, vec![(alternate, TxBlob::clone(&sent.1))]);
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
/// stem; when it has left, the fire fluffs rather than re-stemming to the
/// refill. Red edit: read the alternate from the live slots at fire.
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

    let fired = z.fire_embargoes(origin_retry_ms(), &mut rng);
    assert!(
        fired.stems.iter().all(|(peer, _)| *peer != id(3)),
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
    let sent_now = z.due_unsent(NEVER_SENT_RETRY_MS + 1, &mut rng);
    assert_eq!(
        sent_now.stems.len(),
        1,
        "sent at the sync turn, not a grid later"
    );
    assert_eq!(sent_now.stems[0].1, sent.1);
    assert!(!z.holds_unsent(&sent.0));
    assert_eq!(
        z.stem_observations_in_flight(),
        1,
        "the send armed its embargo"
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
        out.stems.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
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
/// bytes and nothing else, and the last resort's effect names the
/// transaction for the pool. Red edit: append a retry count to the blob.
#[test]
fn the_wire_carries_only_the_transaction() {
    let mut rng = SplitMix64::new(0xE9);
    let z = stem_zone(&[1, 2], &mut rng);
    let mut d = Driver::new(z);
    let sent = tx(16);
    originate(d.zone_mut(), &sent, &mut rng);
    let alternate = d.zone().alternate_of(&sent.0).expect("an alternate");

    let first = d.poll(origin_retry_ms(), &mut rng);
    let stems: Vec<_> = first
        .iter()
        .filter_map(|effect| match effect {
            Effect::Stem { peer, blobs } => Some((*peer, blobs.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(stems, vec![(alternate, vec![TxBlob::clone(&sent.1)])]);
    assert_eq!(
        stems[0].1[0].as_ref(),
        sent.1.as_ref(),
        "byte for byte the transaction"
    );

    let second = d.poll(2 * origin_retry_ms(), &mut rng);
    assert!(
        second
            .iter()
            .any(|effect| matches!(effect, Effect::Published { txs } if txs == &vec![sent.0])),
        "the last resort names the transaction for the pool"
    );
}
