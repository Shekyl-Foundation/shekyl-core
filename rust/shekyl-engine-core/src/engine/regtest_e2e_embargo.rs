// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The origin's embargo on two live walks: no alternate, and a successor
//! that drops so the origin re-stems.
//!
//! A `#[path]` child of the origin rig, so the stem/sink pair stays with
//! that rig and this file still sees the harness. The production
//! debug-macro lint treats a file as test code only when the file itself
//! carries this attribute.

#![cfg(test)]

use super::super::*;
use super::*;

/// RX-1 on two live daemons: the origin's only peer is the sink, so it has
/// no alternate, and its first embargo fire, at the derived retry interval
/// (1,148 s), fluffs as the last resort (W3b): the transaction is shown at
/// the origin and the next block mines it. Red on the flip binary before
/// the relay embargo landed: the origin's transaction stayed in its stem
/// phase for 600 s and nothing would ever have published it (2026-10-29,
/// the probe recorded in `DRS_X_STORE_FLIP.md`'s register).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): two live daemons and the origin's 1,148 s retry"]
async fn an_origin_with_no_alternate_fluffs_at_its_first_fire_and_is_mined() {
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    let seed = [0x5du8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let pair = StemSinkPair::start_for_seed(&seed).await;
    let origin = pair.origin();
    let (wallet, _tmp, address) = mainnet_wallet(origin.rpc_port(), 0x5d).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(origin, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    let amount = AtomicUnits::from_raw(unlocked_balance(&arc).await.to_raw() / 4);
    let txid = submit_transfer(
        origin,
        &arc,
        crate::engine::pending::TxDestination::Address(address),
        amount,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    let submitted = Instant::now();
    assert_eq!(
        pair.stem_held(txid).await,
        StemHold::Stem,
        "fixture: the origin stems its own transaction to the sink"
    );

    // The origin's retry interval at the shipped terms, pinned in
    // `shekyl-ffi`'s `dandelionpp_ffi` tests to `shekyl_relay::origin_retry_secs`;
    // this crate does not depend on the relay.
    const ORIGIN_RETRY_SECS: u64 = 1_148;
    let retry = Duration::from_secs(ORIGIN_RETRY_SECS);
    let shown_by = submitted + retry + Duration::from_secs(120);
    let mut state = pair.stem_held(txid).await;
    while state == StemHold::Stem && Instant::now() < shown_by {
        tokio::time::sleep(Duration::from_secs(2)).await;
        state = pair.stem_held(txid).await;
    }
    let waited = submitted.elapsed();
    eprintln!("the origin's transaction was {state:?} after {waited:?}");
    assert_eq!(
        state,
        StemHold::Broadcast,
        "the first fire with no alternate fluffs and the origin shows it"
    );
    assert!(
        waited + Duration::from_secs(5) >= retry,
        "it was published at the retry interval, not before: {waited:?} against {retry:?}"
    );

    let height = assert_tx_confirmed(origin, txid).await;
    eprintln!("mined at height {height}");
}

/// RX-1 and §12.2 at the origin, against an adversary that lives in the
/// test (Rick, 2026-10-29). The origin dials two simulated peers, which
/// take its two outbound stem slots and swallow every stem; a third
/// simulated peer dials in. Every assertion is on the origin, which is all
/// production code:
///
/// - its first stem goes to one slot, and at its first embargo fire, the
///   derived retry interval later, it re-stems to the other, as a stem;
/// - when the transaction comes back from a peer other than the one it was
///   re-stemmed to, it disarms and shows it;
/// - it never fluffs: no peer hears the transaction as a fluff from the
///   origin through a full second interval, and the next block mines it.
///
/// Red under fluff on expiry (the C++ behaviour §14 rejected): the first
/// fire reaches every peer as a fluff, and the re-stem assertion fails.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): a live daemon, three simulated peers and two 1,148 s origin intervals"]
async fn an_origin_whose_successor_drops_re_stems_to_its_alternate_and_never_fluffs() {
    use super::super::peer::{Heard, TestPeer};
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    // The origin's retry interval at the shipped terms, pinned in
    // `shekyl-ffi`'s `dandelionpp_ffi` tests; this crate does not depend on
    // the relay.
    const ORIGIN_RETRY: Duration = Duration::from_secs(1_148);
    const SLACK: Duration = Duration::from_secs(120);

    let serial = serial_lock().lock_owned().await;
    let droppers = [
        TestPeer::listen(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        TestPeer::listen(std::net::Ipv4Addr::new(127, 0, 0, 2)),
    ];
    let origin_p2p =
        RegtestDaemon::free_port_excluding(&[droppers[0].addr.port(), droppers[1].addr.port()]);
    let seed = [0x5cu8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let origin = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial))
            .with_mine_address(mine_address_from_seed(
                &seed,
                shekyl_address::Network::Mainnet,
            ))
            .with_peering(Peering::Closed {
                p2p_port: origin_p2p,
                peers: [droppers[0].addr, droppers[1].addr],
            }),
    )
    .await;

    let linked_by = Instant::now() + Duration::from_secs(90);
    // A live session to each, not a past handshake: the dialer confirms
    // an address with a session it closes before it keeps one.
    while !(droppers[0].live() && droppers[1].live()) {
        assert!(
            Instant::now() < linked_by,
            "the origin never dialled both simulated peers; log tail:\n{}",
            origin.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let returner = TestPeer::dial(origin_p2p);
    let synced_by = Instant::now() + Duration::from_secs(60);
    loop {
        let synchronized = origin
            .rpc
            .json_rpc_call::<GetInfoResponse>("get_info", None)
            .await
            .expect("origin get_info")
            .health
            .synchronized;
        if synchronized && returner.live() {
            break;
        }
        assert!(
            Instant::now() < synced_by,
            "the origin never read itself synchronized with the returner linked (synchronized {synchronized}, returner {}); log tail:\n{}",
            returner.live(),
            origin.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let (wallet, _tmp, address) = mainnet_wallet(origin.rpc_port(), 0x5c).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(&origin, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    let amount = AtomicUnits::from_raw(unlocked_balance(&arc).await.to_raw() / 4);
    let txid = submit_transfer(
        &origin,
        &arc,
        crate::engine::pending::TxDestination::Address(address),
        amount,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    let submitted = Instant::now();

    let of = |peer: &TestPeer| -> Vec<Heard> {
        peer.heard()
            .into_iter()
            .filter(|heard| {
                heard.txs.iter().any(|blob| {
                    shekyl_wire::Transaction::from_bytes(blob)
                        .is_ok_and(|tx| tx.txid_parts().hash == txid)
                })
            })
            .collect()
    };
    let fluffed = |peers: &[&TestPeer]| -> bool {
        peers
            .iter()
            .any(|peer| of(peer).iter().any(|heard| heard.fluff))
    };
    let everyone = [&droppers[0], &droppers[1], &returner];
    // What each peer heard of the transaction, and whether its session is
    // up: the evidence a failure here prints.
    let report = |label: &str| -> String {
        let mut out = format!("{label}\n");
        for (name, peer) in [
            ("dropper 0", &droppers[0]),
            ("dropper 1", &droppers[1]),
            ("returner", &returner),
        ] {
            let heard: Vec<String> = of(peer)
                .iter()
                .map(|heard| {
                    format!(
                        "{:?} after submit, {}",
                        heard.at.saturating_duration_since(submitted),
                        if heard.fluff { "fluff" } else { "stem" }
                    )
                })
                .collect();
            out.push_str(&format!(
                "  {name}: session {}, heard {heard:?}\n",
                if peer.live() { "up" } else { "DOWN" }
            ));
        }
        out.push_str(&format!("origin log tail:\n{}", origin.log_tail()));
        out
    };

    // The first stem: one slot, as a stem, and nothing else.
    let stemmed_by = submitted + Duration::from_secs(30);
    let primary = loop {
        if let Some(index) = (0..2).find(|i| !of(&droppers[*i]).is_empty()) {
            break index;
        }
        assert!(
            Instant::now() < stemmed_by,
            "the origin stemmed to neither slot; log tail:\n{}",
            origin.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let alternate = 1 - primary;
    let first = of(&droppers[primary]);
    assert!(
        first.iter().all(|heard| !heard.fluff),
        "the first send is a stem"
    );
    assert!(
        of(&droppers[alternate]).is_empty() && of(&returner).is_empty(),
        "the first send reaches one slot only"
    );
    let first_at = first[0].at;

    // The first fire: the re-stem to the alternate, at the retry interval.
    let fired_by = first_at + ORIGIN_RETRY + SLACK;
    while of(&droppers[alternate]).is_empty() && Instant::now() < fired_by {
        assert!(
            !fluffed(&everyone),
            "{}",
            report("the origin fluffed before or at its first fire")
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let restem = of(&droppers[alternate]);
    assert_eq!(
        restem.len(),
        1,
        "{}",
        report("at the first fire the origin re-stems once to its alternate")
    );
    assert!(!restem[0].fluff, "the re-stem is a stem");
    let waited = restem[0].at.duration_since(first_at);
    eprintln!("re-stemmed to the alternate {waited:?} after the first stem");
    assert!(
        waited + Duration::from_secs(5) >= ORIGIN_RETRY,
        "the re-stem came at the retry interval, not before: {waited:?}"
    );
    assert!(!fluffed(&everyone), "the first fire does not fluff");

    // The transaction comes back from a peer other than the alternate.
    let blob = restem[0]
        .txs
        .iter()
        .find(|blob| {
            shekyl_wire::Transaction::from_bytes(blob).is_ok_and(|tx| tx.txid_parts().hash == txid)
        })
        .expect("the re-stem carried the transaction")
        .clone();
    returner.fluff(&blob);
    let shown_by = Instant::now() + Duration::from_secs(30);
    loop {
        let pool: PoolRelayResp = origin
            .rpc
            .rpc_call("get_transaction_pool", None::<serde_json::Value>)
            .await
            .expect("origin /get_transaction_pool");
        let wanted = hex::encode(txid.as_bytes());
        if pool
            .transactions
            .iter()
            .any(|entry| entry.id_hash == wanted && entry.relayed)
        {
            break;
        }
        assert!(
            Instant::now() < shown_by,
            "the origin did not disarm and show the transaction that came back"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Disarmed: no second fire, so no fluff, through a full interval.
    let quiet_until = first_at + 2 * ORIGIN_RETRY + SLACK;
    while Instant::now() < quiet_until {
        assert!(
            !fluffed(&everyone),
            "{}",
            report("a disarmed origin fluffed")
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert!(!fluffed(&everyone), "the origin never fluffs");
    assert_eq!(
        of(&droppers[primary]).len() + of(&droppers[alternate]).len(),
        2,
        "two stems in all: the first send and the one re-stem"
    );

    let height = assert_tx_confirmed(&origin, txid).await;
    eprintln!("mined at height {height}");
}
