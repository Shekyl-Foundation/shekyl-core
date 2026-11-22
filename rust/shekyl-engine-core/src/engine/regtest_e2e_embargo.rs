// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The origin's embargo on two live walks: no alternate, and a successor
//! that drops so the origin re-stems.
//!
//! The embargo is a floor plus a memoryless draw. Neither walk times the
//! floor or reads the origin "still in stem": both read what the origin
//! sent from its simulated peers' records.
//!
//! A `#[path]` child of the origin rig, so the stem/sink pair stays with
//! that rig and this file still sees the harness. The production
//! debug-macro lint treats a file as test code only when the file itself
//! carries this attribute.

#![cfg(test)]

use super::super::peer::{Heard, TestPeer};
use super::super::*;
use super::*;

/// How often a walk reads its peers' records while it waits for a send.
/// It is also the walk's reaction time to a re-stem, which is the gap the
/// second walk's one race lives in.
const POLL: Duration = Duration::from_millis(250);

/// How long after an embargo fire a fluff may still reach a peer. The
/// fire queues the fluff, and each peer's flush is its own Poisson draw:
/// mean 2.5 s toward an outbound peer and 5 s toward an inbound one
/// (`FLUFF_AVERAGE_OUT_QUARTER_SECS`, `FLUFF_AVERAGE_IN_QUARTER_SECS`),
/// 8.75 s at the inbound draw's 99.9th percentile. Over three times that.
const FLUFF_FLUSH_LIMIT: Duration = Duration::from_secs(30);

/// How long the origin may take to show a transaction it has broadcast
/// or seen come back: one RPC read after an event that has already
/// happened in the relay.
const SHOWN_LIMIT: Duration = Duration::from_secs(30);

/// What `peer` heard of `txid`, in the order its session delivered it.
fn heard_of(peer: &TestPeer, txid: TxHash) -> Vec<Heard> {
    peer.heard()
        .into_iter()
        .filter(|heard| {
            heard.txs.iter().any(|blob| {
                shekyl_wire::Transaction::from_bytes(blob)
                    .is_ok_and(|tx| tx.txid_parts().hash == txid)
            })
        })
        .collect()
}

/// Whether the origin shows `txid`: pooled and public.
async fn origin_shows(origin: &RegtestDaemon, txid: TxHash) -> bool {
    matches!(
        tx_slot(&origin.rpc, txid).await,
        Slot::Item(entry) if entry.pooled && entry.public.0 == Some(true)
    )
}

/// Wait until the origin shows `txid`, or fail with `what`.
async fn await_shown(origin: &RegtestDaemon, txid: TxHash, what: &str) {
    let shown_by = Instant::now() + SHOWN_LIMIT;
    while !origin_shows(origin, txid).await {
        assert!(
            Instant::now() < shown_by,
            "{what}; log tail:\n{}",
            origin.log_tail()
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Wait until `peers` hold sessions the origin keeps and the origin reads
/// itself synchronized. A live session, not a past handshake: the dialer
/// confirms an address with a session it closes before it keeps one.
async fn await_linked(origin: &RegtestDaemon, peers: &[&TestPeer]) {
    let linked_by = Instant::now() + Duration::from_secs(90);
    loop {
        let synchronized = origin.status().await.synchronized;
        let live: Vec<bool> = peers.iter().map(|peer| peer.live()).collect();
        if synchronized && live.iter().all(|up| *up) {
            return;
        }
        assert!(
            Instant::now() < linked_by,
            "the origin never held every simulated peer's session while synchronized \
             (synchronized {synchronized}, sessions up {live:?}); log tail:\n{}",
            origin.log_tail()
        );
        tokio::time::sleep(POLL).await;
    }
}

/// The origin and one simulated peer, its only successor, so it has no
/// alternate. Its first embargo fire, a draw of the shared timer (waited
/// for up to the relay's `embargo_fire_wait_secs`), fluffs as the last
/// resort (W3b): the transaction reaches the peer as a fluff, the origin
/// shows it, and the next block mines it.
///
/// **Everything is read from the peer's record of what the origin sent
/// it, in the order its session delivered it:** one stem, then a fluff.
/// That order does not depend on when the embargo fires. The embargo is
/// its floor plus a memoryless draw, so a fire a moment after the floor
/// is correct behaviour, and no assertion here reads the origin's state
/// to catch it "still in stem": that read would race the timer. This walk
/// has no race to tolerate and no retry.
///
/// What it does not see: how long the origin waited. A node that stemmed
/// and broadcast at once every time would pass. The unit tests
/// `a_dropped_stem_gets_one_reaction_own_or_relayed` and
/// `no_embargo_fires_before_a_stem_could_return` hold the draw and the
/// floor.
///
/// Red on a node that broadcasts its own transaction with no stem: the
/// peer's first record is a fluff. Red on the flip binary before the
/// relay embargo landed: the origin's transaction stayed in its stem
/// phase for 600 s and nothing would ever have published it (2026-10-29,
/// the probe recorded in `DRS_X_STORE_FLIP.md`'s register), so no fluff
/// comes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "embargo lane (run_live_daemon_gates.sh ARMED_EMBARGO): a live daemon, one simulated peer and one embargo fire"]
async fn an_origin_with_no_alternate_fluffs_at_its_first_fire_and_is_mined() {
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    /// Past the fire's own wait: the fluff's flush and the walk's poll.
    const SLACK: Duration = Duration::from_secs(120);

    let serial = serial_lock().lock_owned().await;
    let successor = TestPeer::listen(std::net::Ipv4Addr::LOCALHOST);
    let origin_p2p = RegtestDaemon::free_port_excluding(&[successor.addr.port()]);
    let seed = [0x5du8; shekyl_crypto_pq::account::SEED_BYTES];
    let origin = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial))
            .with_mine_address(mine_address_from_seed(
                &seed,
                shekyl_address::Network::Regtest,
            ))
            .with_peering(Peering::Linked {
                p2p_port: origin_p2p,
                peer_p2p_port: successor.addr.port(),
            }),
    )
    .await;
    await_linked(&origin, &[&successor]).await;

    let (wallet, _tmp, address) = mainnet_wallet(origin.rpc_port(), 0x5d).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(&origin, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    let amount = AtomicUnits::from_raw(spendable_balance(&arc).await.to_raw() / 4);
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
    let report = |label: &str| -> String {
        let heard: Vec<String> = heard_of(&successor, txid)
            .iter()
            .map(|heard| {
                format!(
                    "{:?} after submit, {}",
                    heard.at.saturating_duration_since(submitted),
                    if heard.fluff { "fluff" } else { "stem" }
                )
            })
            .collect();
        format!(
            "{label}\n  successor: session {}, heard {heard:?}\norigin log tail:\n{}",
            if successor.live() { "up" } else { "DOWN" },
            origin.log_tail()
        )
    };

    // The first send. Whatever the embargo drew, the record keeps it.
    let stemmed_by = submitted + Duration::from_secs(30);
    while heard_of(&successor, txid).is_empty() {
        assert!(
            Instant::now() < stemmed_by,
            "{}",
            report("the origin sent its own transaction nowhere")
        );
        tokio::time::sleep(POLL).await;
    }
    let first_at = heard_of(&successor, txid)[0].at;

    // The first fire: no alternate, so the fluff, on the timer's draw.
    let fluffed_by = first_at + embargo_fire_wait() + SLACK;
    while !heard_of(&successor, txid).iter().any(|heard| heard.fluff) {
        assert!(
            Instant::now() < fluffed_by,
            "{}",
            report("the origin's first fire, with no alternate, never fluffed")
        );
        tokio::time::sleep(POLL).await;
    }
    let record = heard_of(&successor, txid);
    assert!(
        !record[0].fluff,
        "{}",
        report("the origin's first send of its own transaction is a stem")
    );
    assert_eq!(
        record.iter().filter(|heard| !heard.fluff).count(),
        1,
        "{}",
        report("one stem: with no alternate there is no re-stem")
    );
    let fluff_at = record
        .iter()
        .find(|heard| heard.fluff)
        .expect("the wait above saw a fluff")
        .at;
    eprintln!(
        "fluffed {:?} after the stem",
        fluff_at.saturating_duration_since(first_at)
    );
    await_shown(
        &origin,
        txid,
        "the origin fluffed its transaction and does not show it",
    )
    .await;

    let height = assert_tx_confirmed(&origin, txid).await;
    eprintln!("mined at height {height}");
}

/// RX-1 and §12.2 at the origin, against an adversary that lives in the
/// test (Rick, 2026-10-29). The origin dials two simulated peers, which
/// take its two outbound stem slots and swallow every stem; a third
/// simulated peer dials in. Every assertion is on the origin, which is all
/// production code. What an attempt proves:
///
/// - each slot hears the transaction first as a stem, and hears one stem:
///   the first send to one slot and, after the first embargo fire, the
///   one re-stem to the other. The peer that dialled in hears no stem;
/// - when the transaction comes back from a peer other than the one it was
///   re-stemmed to, the origin disarms and shows it;
/// - disarmed, it does not fluff: no peer hears the transaction as a fluff
///   from the origin through the quiet wait (the timer's 1-in-10 quantile
///   over the longest transit), and the next block mines it.
///
/// **Nothing here times the embargo's floor.** The stems are read from
/// each peer's record, in the order its session delivered them, whenever
/// the fires came: a first fire at the floor is the same record as a late
/// one, and is not a race.
///
/// **One race is legal, and the walk names it.** The second embargo is
/// armed when the re-stem is written, and the walk can send the
/// transaction back only after it has seen the re-stem. A second fire
/// inside that gap is correct behaviour: the origin broadcasts, as it
/// must for a stem nobody returned. The walk detects it two ways. Before
/// it sends the return, the origin already shows the transaction, or a
/// peer has already heard a fluff. Or a fluff reaches a peer within
/// [`FLUFF_FLUSH_LIMIT`] of the return: the fire's queued fluff, flushed
/// after it. An attempt that raced asserts the legal outcome (the same
/// two stems, the transaction shown), mines the transaction, and the walk
/// tries again with a fresh one, `MAX_ATTEMPTS` times in all. A fluff
/// later than that limit is a disarmed origin fluffing, and fails at once.
///
/// **The race needs a slow walk, not a short draw.** The walk's sessions
/// are clearnet, whose adopted embargo is a 5.5 s floor plus a memoryless
/// draw of mean 194 s (`DAEMON_RELAY_PRIVACY.md` §100). The second embargo
/// cannot fire inside the floor, and the gap is one [`POLL`] and two
/// loopback round trips, a second or two. So the race is open only to a
/// walk that takes longer than the floor to send the return, on a host
/// that stalled it. The retry stays for that host.
///
/// **The retry does not let a broken disarm pass.** An attempt passes
/// only by staying quiet through the whole wait. An origin whose disarm
/// did nothing fires again at the timer's floor plus its draw: it lands
/// inside the tolerated window about one time in eight (30 s, less the
/// floor, against the draw's 194 s) and is retried, and otherwise fluffs
/// later and fails at once; it survives a whole quiet wait about one time
/// in 900 (`e^(-1314/194)`).
///
/// What it does not see: a node that sent both stems at once. The record
/// of a zero first draw is the same.
///
/// Red under fluff on expiry (the C++ behaviour §14 rejected): the first
/// fire reaches the other slot as a fluff, and "hears it first as a stem"
/// fails.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "embargo lane (run_live_daemon_gates.sh ARMED_EMBARGO): a live daemon, three simulated peers, one embargo fire and the quiet wait"]
async fn an_origin_whose_successor_drops_re_stems_to_its_alternate_and_never_fluffs() {
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    const SLACK: Duration = Duration::from_secs(120);
    /// Fresh transactions the walk may spend on the one legal race (the
    /// second fire beat the return). The doc comment derives the rate.
    const MAX_ATTEMPTS: u32 = 3;

    let serial = serial_lock().lock_owned().await;
    let droppers = [
        TestPeer::listen(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        TestPeer::listen(std::net::Ipv4Addr::new(127, 0, 0, 2)),
    ];
    let origin_p2p =
        RegtestDaemon::free_port_excluding(&[droppers[0].addr.port(), droppers[1].addr.port()]);
    let seed = [0x5cu8; shekyl_crypto_pq::account::SEED_BYTES];
    let origin = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial))
            .with_mine_address(mine_address_from_seed(
                &seed,
                shekyl_address::Network::Regtest,
            ))
            .with_peering(Peering::Closed {
                p2p_port: origin_p2p,
                peers: [droppers[0].addr, droppers[1].addr],
            }),
    )
    .await;
    await_linked(&origin, &[&droppers[0], &droppers[1]]).await;
    let returner = TestPeer::dial(origin_p2p);
    let everyone = [&droppers[0], &droppers[1], &returner];
    await_linked(&origin, &everyone).await;

    let (wallet, _tmp, address) = mainnet_wallet(origin.rpc_port(), 0x5c).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(&origin, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    for attempt in 1..=MAX_ATTEMPTS {
        assert!(
            everyone.iter().all(|peer| peer.live()),
            "attempt {attempt}: a simulated peer's session is down; log tail:\n{}",
            origin.log_tail()
        );
        let amount = AtomicUnits::from_raw(spendable_balance(&arc).await.to_raw() / 4);
        let txid = submit_transfer(
            &origin,
            &arc,
            crate::engine::pending::TxDestination::Address(address.clone()),
            amount,
            MINE_BATCH_BLOCKS,
            MAX_MINE_BATCHES,
        )
        .await;
        let submitted = Instant::now();

        let of = |peer: &TestPeer| heard_of(peer, txid);
        let stems = |peer: &TestPeer| of(peer).iter().filter(|heard| !heard.fluff).count();
        // The earliest fluff any peer heard, if one did.
        let first_fluff = || -> Option<Instant> {
            everyone
                .iter()
                .flat_map(|peer| of(peer))
                .filter(|heard| heard.fluff)
                .map(|heard| heard.at)
                .min()
        };
        // What each peer heard of the transaction, and whether its session
        // is up: the evidence a failure here prints.
        let report = |label: &str| -> String {
            let mut out = format!("attempt {attempt}: {label}\n");
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
        // The stem sequence, read from the records and from no clock: each
        // slot heard the transaction first as a stem and heard one stem,
        // and the peer that dialled in heard none.
        let assert_two_stems = |label: &str| {
            for dropper in &droppers {
                let record = of(dropper);
                assert!(
                    record.first().is_some_and(|heard| !heard.fluff),
                    "{}",
                    report(&format!("{label}: a slot did not hear it first as a stem"))
                );
                assert_eq!(
                    stems(dropper),
                    1,
                    "{}",
                    report(&format!("{label}: a slot hears one stem"))
                );
            }
            assert_eq!(
                stems(&returner),
                0,
                "{}",
                report(&format!("{label}: a peer that dialled in is no stem slot"))
            );
        };

        // The first send: a slot hears the transaction.
        let stemmed_by = submitted + Duration::from_secs(30);
        while droppers.iter().all(|dropper| of(dropper).is_empty()) {
            assert!(
                Instant::now() < stemmed_by,
                "{}",
                report("the origin stemmed to neither slot")
            );
            tokio::time::sleep(POLL).await;
        }
        // The first fire: the other slot hears it too, on the timer's draw.
        // No bound from below: the draw may be zero.
        let fired_by = Instant::now() + embargo_fire_wait() + SLACK;
        while droppers.iter().any(|dropper| of(dropper).is_empty()) {
            assert!(
                Instant::now() < fired_by,
                "{}",
                report("the origin's first fire never reached its alternate")
            );
            tokio::time::sleep(POLL).await;
        }
        assert_two_stems("at the first fire");
        let firsts = [of(&droppers[0])[0].clone(), of(&droppers[1])[0].clone()];
        let alternate = usize::from(firsts[1].at > firsts[0].at);
        let restem = &firsts[alternate];
        eprintln!(
            "attempt {attempt}: re-stemmed to the alternate {:?} after the first stem",
            restem
                .at
                .saturating_duration_since(firsts[1 - alternate].at)
        );

        // The legal race, seen before the return: the second fire has
        // already broadcast it.
        let mut raced = first_fluff().is_some() || origin_shows(&origin, txid).await;
        if !raced {
            // The transaction comes back from a peer other than the alternate.
            let blob = restem
                .txs
                .iter()
                .find(|blob| {
                    shekyl_wire::Transaction::from_bytes(blob)
                        .is_ok_and(|tx| tx.txid_parts().hash == txid)
                })
                .expect("the re-stem carried the transaction");
            returner.fluff(blob);
            let returned_at = Instant::now();
            await_shown(
                &origin,
                txid,
                "the origin did not disarm and show the transaction that came back",
            )
            .await;

            // Disarmed: no second fire, so no fluff, through the quiet wait.
            let quiet_until = restem.at + embargo_quiet_wait() + SLACK;
            while Instant::now() < quiet_until {
                if let Some(fluff_at) = first_fluff() {
                    // The same race, seen after the return: a fire inside
                    // the gap, its fluff flushed since. Later than a flush
                    // can be, it is a disarmed origin fluffing.
                    assert!(
                        fluff_at <= returned_at + FLUFF_FLUSH_LIMIT,
                        "{}",
                        report("a disarmed origin fluffed")
                    );
                    raced = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        assert_two_stems(if raced {
            "the second fire beat the return"
        } else {
            "through the quiet wait"
        });

        if raced {
            // The legal outcome of that race: broadcast after the one
            // re-stem, and shown. Mined out, so the next attempt's
            // transaction is alone in the pool.
            await_shown(
                &origin,
                txid,
                "the origin's second fire broadcast its transaction and it does not show it",
            )
            .await;
            eprintln!(
                "{}",
                report(
                    "the second embargo fired before the return could disarm it; \
                     trying a fresh transaction"
                )
            );
            assert_tx_confirmed(&origin, txid).await;
            refresh(&arc).await;
            continue;
        }

        assert!(
            first_fluff().is_none(),
            "{}",
            report("the origin never fluffs a transaction that came back")
        );
        let height = assert_tx_confirmed(&origin, txid).await;
        eprintln!("attempt {attempt}: mined at height {height}");
        return;
    }
    panic!(
        "the second embargo fired before the return on each of {MAX_ATTEMPTS} attempts: \
         at the timer's rate that is not a race; log tail:\n{}",
        origin.log_tail()
    );
}
