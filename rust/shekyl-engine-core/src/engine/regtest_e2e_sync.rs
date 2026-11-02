// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live sync walks: a chain longer than the door's window, fifteen spans,
//! and a dialing node handing its tip across a restart.
//!
//! A `#[path]` child of the regtest harness. The production debug-macro
//! lint treats a file as test code only when the file itself carries this
//! attribute.

#![cfg(test)]

use super::*;

/// A node syncs a chain longer than the ingest door's window from one peer.
///
/// The handler downloads spans ahead and hands each to the door; the door
/// seats a window of arrivals and connects them in its own time. Seen red
/// on 2026-10-30 (the flip's F-B run and the RPC column's regtest sync):
/// the first span connected, the rest were offered while the door had no
/// room, the handler read the gap between the tip and what it had handed
/// over as "nothing to download from this peer" and dropped it, and the
/// node stood at height 21 of 82 for thirty minutes. The joiner must reach
/// the source's tip, and the same tip.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; two daemons, ~2 min"]
async fn a_node_syncs_a_chain_longer_than_the_doors_window_from_a_peer() {
    sync_from_a_peer(100, [0x5au8; 64]).await;
}

/// A node syncs fifteen spans from one peer: more than the handler
/// downloads ahead (ten spans), so spans the door has been handed and has
/// not yet connected sit beside spans still arriving. Seen red on
/// 2026-10-30 at the end of the 762-block F-B sync on two hosts: a handed
/// span was removed from the queue before the door connected it, its
/// heights were requested again, the queue filled with overlapping spans,
/// and the node stood at 724 of 762 with the door reporting no room. The
/// five-span test above never runs ahead of its own downloads and cannot
/// see this.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; two daemons and 300 blocks, several min"]
async fn a_node_syncs_fifteen_spans_from_a_peer() {
    sync_from_a_peer(300, [0x5bu8; 64]).await;
}

/// The two-daemon sync walk: a source linked to a non-syncing sink mines
/// `blocks`; a joiner linked to the source must reach its tip, moving at
/// least every 120 s.
async fn sync_from_a_peer(blocks: u64, seed: [u8; 64]) {
    let serial = serial_lock().lock_owned().await;
    let source_p2p = RegtestDaemon::free_port();
    let sink_p2p = RegtestDaemon::free_port_excluding(&[source_p2p]);
    let joiner_p2p = RegtestDaemon::free_port_excluding(&[source_p2p, sink_p2p]);
    let address = mine_address_from_seed(&seed, shekyl_address::Network::Mainnet);
    let _sink = RegtestDaemon::spawn(RegtestSpawn::new(None).with_peering(Peering::Linked {
        p2p_port: sink_p2p,
        peer_p2p_port: source_p2p,
        sink: true,
    }))
    .await;
    let source = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial))
            .with_mine_address(address)
            .with_peering(Peering::Linked {
                p2p_port: source_p2p,
                peer_p2p_port: sink_p2p,
                sink: false,
            }),
    )
    .await;
    let linked = Instant::now() + Duration::from_secs(60);
    while try_generate_blocks(&source.rpc, 1).await.is_err() {
        assert!(
            Instant::now() < linked,
            "the source never read synced against its sink within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    source.generate_blocks(blocks - 1).await;
    let want = source.height().await;
    assert_eq!(want, blocks + 1, "the source mined its chain");
    let source_tip = source.last_block_hash().await;

    let joiner = RegtestDaemon::spawn(RegtestSpawn::new(None).with_peering(Peering::Linked {
        p2p_port: joiner_p2p,
        peer_p2p_port: source_p2p,
        sink: false,
    }))
    .await;
    const STALL: Duration = Duration::from_secs(120);
    const CAP: Duration = Duration::from_secs(1800);
    let started = Instant::now();
    let (mut last, mut moved) = (0u64, Instant::now());
    loop {
        let have = joiner.height().await;
        if have >= want {
            break;
        }
        if have != last {
            last = have;
            moved = Instant::now();
        }
        assert!(
            moved.elapsed() < STALL,
            "the joiner stands at height {have} of {want} and has not moved for {STALL:?}: \
             the sync stalled"
        );
        assert!(
            started.elapsed() < CAP,
            "the joiner is at height {have} of {want} after {CAP:?}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert_eq!(
        joiner.height().await,
        want,
        "the joiner reached the source's height"
    );
    assert_eq!(
        joiner.last_block_hash().await,
        source_tip,
        "the joiner reached the source's tip"
    );
}

/// **A node that dials carries its tip** (`DRS_X_STORE_FLIP.md` DX-Q2
/// item 5; the design review's M2): the connector publishes the tip once
/// at start and after every connect, the dialer's readiness reads that
/// publication (`NotReady::NoTip` until it exists), and the outbound
/// handshake's `current_height` is the block count it published. Before
/// the forwarder that carries the publication to the dialer, a Rust
/// daemon never dialed at all: readiness stayed `NoTip`.
///
/// Two daemons, each the other's one closed peer. `B` first, then `A`,
/// which links to `B` at genesis — a node is synchronized from a
/// handshake with a peer at its own height, and the miner posts no job
/// before that, so `A` could not mine alone. `A` mines `MINED` blocks,
/// then **restarts on its own data directory**: the new process has no
/// session, reads its tip from the store, publishes it once at start,
/// and dials `B`. `B`'s `get_connections` must then show an **incoming**
/// connection it did not have before the restart whose `height` is
/// `MINED + 1`, the block count `A` came back with. The connection id
/// is what makes it a fresh handshake rather than the old session's row
/// updated by sync; `incoming` is what makes it `A`'s dial rather than
/// `B`'s redial of `A`, whose handshake `A` only answers.
///
/// The designed red is the tip forwarder's revert: `A` still mines (`B`
/// dials it, which is `A`'s handshake), but the restarted `A` never dials
/// (`NoTip`), and `B` sees no new incoming connection inside the wait.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; two daemons and one restart"]
async fn a_dialing_node_hands_its_tip_to_the_peer_it_dials() {
    use std::collections::BTreeSet;

    const MINED: u64 = 20;
    const LINK_WAIT: Duration = Duration::from_secs(90);

    async fn incoming_on(daemon: &RegtestDaemon) -> Vec<shekyl_rpc_types::ConnectionInfo> {
        let reply: shekyl_rpc_types::P2pReply<shekyl_rpc_types::GetConnectionsResponse> = daemon
            .rpc
            .json_rpc_call("get_connections", None)
            .await
            .expect("get_connections");
        reply
            .into_running()
            .expect("a linked daemon's P2P runs; it must not report offline")
            .connections
            .into_iter()
            .filter(|c| c.incoming)
            .collect()
    }

    let serial = serial_lock().lock_owned().await;
    let port_a = RegtestDaemon::free_port();
    let port_b = RegtestDaemon::free_port_excluding(&[port_a]);
    let b = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial)).with_peering(Peering::Linked {
            p2p_port: port_b,
            peer_p2p_port: port_a,
            sink: false,
        }),
    )
    .await;
    let mut a = RegtestDaemon::spawn(RegtestSpawn::new(None).with_peering(Peering::Linked {
        p2p_port: port_a,
        peer_p2p_port: port_b,
        sink: false,
    }))
    .await;

    // Linked at genesis: `A` synchronized, so its miner posts a job. The
    // job follows the sync state by one follower pass, so the miner is
    // asked rather than the flag (`get_info` said synchronized while the
    // posting still read `no_view`, observed 2026-10-29): the one refusal
    // retried is the wire-pinned `mine.not_synced`.
    let deadline = Instant::now() + LINK_WAIT;
    loop {
        match try_generate_blocks(&a.rpc, 1).await {
            Ok(_) => break,
            Err(e) if format!("{e:?}").contains("mine.not_synced") && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => a.panic_with_log(
                "A's miner never posted a job (A never synchronized against B?)",
                format!("{e:?}; B's log tail:\n{}", b.log_tail()),
            ),
        }
    }
    a.generate_blocks(MINED - 1).await;
    assert_eq!(
        a.height().await,
        MINED + 1,
        "A mined {MINED} blocks on genesis"
    );
    let before: BTreeSet<String> = incoming_on(&b)
        .await
        .into_iter()
        .map(|c| c.connection_id)
        .collect();
    eprintln!(
        "A at block count {}; B holds {} incoming connection(s) before the restart",
        MINED + 1,
        before.len()
    );

    // The restarted `A` has no session and a stored tip; its first dial
    // is the proposition.
    a.restart_keeping_chain().await;
    let deadline = Instant::now() + LINK_WAIT;
    loop {
        let incoming = incoming_on(&b).await;
        let fresh: Vec<&shekyl_rpc_types::ConnectionInfo> = incoming
            .iter()
            .filter(|c| !before.contains(&c.connection_id))
            .collect();
        if let Some(c) = fresh.iter().find(|c| c.height == Some(MINED + 1)) {
            eprintln!(
                "B: fresh incoming connection {} from {} claims height {:?} — the restarted \
                 dialer handed B its tip",
                c.connection_id, c.address, c.height
            );
            break;
        }
        let seen = fresh
            .iter()
            .map(|c| format!("{} height {:?}", c.address, c.height))
            .collect::<Vec<_>>()
            .join(", ");
        if Instant::now() >= deadline {
            a.panic_with_log(
                "the restarted A never handed B its tip",
                format!(
                    "after {LINK_WAIT:?}: fresh incoming connections on B: [{seen}] (wanted one at \
                     height Some({})); B's log tail:\n{}",
                    MINED + 1,
                    b.log_tail()
                ),
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
