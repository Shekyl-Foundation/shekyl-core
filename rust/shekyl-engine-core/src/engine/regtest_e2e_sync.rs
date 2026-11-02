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

/// The two-daemon sync walk: a source linked to a sink that requests
/// nothing (`dev-sync off`) mines `blocks`; a joiner linked to the source
/// must reach its tip, moving at least every 120 s.
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
            "the source did not mine within 60 s (it is closed, so synced from open; \
             the wait covers its follower's first post and its sink's opening)"
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
/// which links to `B` at genesis. Each is closed (its peer list names the
/// other), so it is synced from open; when the other's session opens, the
/// opening resolves on its claim of the same chain (CS-Q2 step 8). `A`
/// mines `MINED` blocks,
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

    // `A` is closed, so it is synced; its miner posts a job one follower
    // pass after the state, so the miner is asked rather than the flag
    // (`get_info` said synchronized while the posting still read
    // `no_view`, observed 2026-10-29). The refusal retried is the
    // wire-pinned `mine.not_synced`, for the moment `B`'s session opens
    // and its claim has not yet arrived (the opening, CS-Q2 step 8).
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

/// **A CS-5 node and an alpha.11 node refuse each other cleanly** (CS-5
/// §6). The CS-5 node mines a short chain beside a CS-5 sink that requests
/// nothing; it is closed (its peer list names the sink), so it is synced
/// from open. The alpha.11 node then links to it. Alpha.11's sync asks with the retired
/// chain request (2006), which this node's ingress refuses as an
/// undefined command, and this node's owner asks nothing of a peer that
/// claims less. So alpha.11 never takes the chain, and neither daemon
/// faults: both stay up and answer RPC.
///
/// Dark in CI: it needs a released alpha.11 `shekyld` as well
/// (`SHEKYLD_ALPHA11_BIN`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CS-5 mixed version: requires SHEKYLD_BIN and SHEKYLD_ALPHA11_BIN; three daemons, ~2 min"]
async fn a_node_and_an_alpha_11_node_refuse_each_other_cleanly() {
    let alpha11 = std::env::var_os("SHEKYLD_ALPHA11_BIN")
        .map(std::path::PathBuf::from)
        .expect("SHEKYLD_ALPHA11_BIN names a released alpha.11 shekyld");
    let serial = serial_lock().lock_owned().await;
    let node_p2p = RegtestDaemon::free_port();
    let sink_p2p = RegtestDaemon::free_port_excluding(&[node_p2p]);
    let alpha_p2p = RegtestDaemon::free_port_excluding(&[node_p2p, sink_p2p]);
    let address = mine_address_from_seed(&[7u8; 64], shekyl_address::Network::Mainnet);
    let _sink = RegtestDaemon::spawn(RegtestSpawn::new(None).with_peering(Peering::Linked {
        p2p_port: sink_p2p,
        peer_p2p_port: node_p2p,
        sink: true,
    }))
    .await;
    let node = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial))
            .with_mine_address(address)
            .with_peering(Peering::Linked {
                p2p_port: node_p2p,
                peer_p2p_port: sink_p2p,
                sink: false,
            }),
    )
    .await;
    let linked = Instant::now() + Duration::from_secs(60);
    while try_generate_blocks(&node.rpc, 1).await.is_err() {
        assert!(
            Instant::now() < linked,
            "the node did not mine within 60 s (it is closed, so synced from open; \
             the wait covers its follower's first post and its sink's opening)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    node.generate_blocks(4).await;
    let want = node.height().await;
    let alpha = RegtestDaemon::spawn(RegtestSpawn::new(None).with_binary(alpha11).with_peering(
        Peering::Linked {
            p2p_port: alpha_p2p,
            peer_p2p_port: node_p2p,
            sink: false,
        },
    ))
    .await;
    // Long enough for alpha.11's sync to ask, be refused, and redial.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(node.height().await, want, "this node kept its own chain");
    assert!(
        alpha.height().await < want,
        "alpha.11 took this node's chain: a retired request was served"
    );
}

/// **An offline testnet node is synced at open, and mines** (CS-Q2 step 8,
/// Rick 2026-11-01). Both connectors off is the operator's declaration
/// that the node has no network to be behind: it reads `Synced` from open
/// on every network, and `generateblocks` drives the built-in miner at the
/// network's own difficulty (testnet has no fixed one; one block takes
/// real proof of work).
///
/// Red before the declaration was built: the node read `NoView` forever
/// and `generateblocks` was refused `mine.not_synced`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; one testnet daemon, real proof of work"]
async fn an_offline_testnet_node_is_synced_and_mines() {
    let daemon = RegtestDaemon::start_on_testnet().await;
    let info = daemon
        .rpc
        .json_rpc_call::<GetInfoResponse>("get_info", None)
        .await
        .expect("get_info");
    assert!(
        info.health.synchronized,
        "an offline node is not synchronized at open"
    );
    let before = daemon.height().await;
    // The follower posts its first job one pass after the state at open is
    // published, so the first answers can be `starting` or `not_synced`; a
    // node that is not synced stays refused past the window.
    let posted = Instant::now() + Duration::from_secs(60);
    let mined = loop {
        match try_generate_blocks(&daemon.rpc, 1).await {
            Ok(mined) => break mined,
            Err(e)
                if ["mine.starting", "mine.not_synced"]
                    .iter()
                    .any(|code| format!("{e:?}").contains(code))
                    && Instant::now() < posted =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => daemon.panic_with_log(
                "generateblocks on an offline testnet node",
                format!("{e:?}"),
            ),
        }
    };
    assert_eq!(mined.blocks.len(), 1, "{:?}", mined.blocks);
    assert_eq!(
        daemon.height().await,
        before + 1,
        "the mined block connected"
    );
}

/// **A closed node whose peer is down mines; when the peer arrives, its
/// opening runs; when it leaves, the node still mines** (CS-Q2 step 8,
/// Rick 2026-11-01). A closed peer list is the operator naming the node's
/// whole network, so with none of it up the node is `Synced` and mines
/// alone on its own tip. When its peer comes up the opening runs: the
/// peer claims less work, so it resolves at once, the node stays synced,
/// and the peer syncs the node's chain. When the peer leaves, none of the
/// node's network is up again, and it is synced.
///
/// Red before the declaration was built: when its last peer left, the
/// node published `NoView` and `generateblocks` was refused
/// `mine.not_synced`. A regtest node opened `Synced` then, by network, so
/// the first leg alone does not tell the two apart.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; two daemons"]
async fn a_closed_node_whose_peer_is_down_mines_and_opens_when_it_arrives() {
    const MINED: u64 = 5;
    let serial = serial_lock().lock_owned().await;
    let node_p2p = RegtestDaemon::free_port();
    let peer_p2p = RegtestDaemon::free_port_excluding(&[node_p2p]);
    let address = mine_address_from_seed(&[0x5f; 64], shekyl_address::Network::Mainnet);
    let node = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial))
            .with_mine_address(address)
            .with_peering(Peering::Linked {
                p2p_port: node_p2p,
                peer_p2p_port: peer_p2p,
                sink: false,
            }),
    )
    .await;
    // Nothing listens on the peer's port. The follower posts its first job
    // one pass after the state at open is published, so the first answers
    // can be `starting` or `not_synced`; a node that is not synced stays
    // refused past the window.
    let posted = Instant::now() + Duration::from_secs(60);
    loop {
        match try_generate_blocks(&node.rpc, MINED).await {
            Ok(_) => break,
            Err(e)
                if ["mine.starting", "mine.not_synced"]
                    .iter()
                    .any(|code| format!("{e:?}").contains(code))
                    && Instant::now() < posted =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => node.panic_with_log(
                "a closed node with its peer down did not mine",
                format!("{e:?}"),
            ),
        }
    }
    let want = node.height().await;
    assert_eq!(want, MINED + 1, "the node mined alone");
    let tip = node.last_block_hash().await;

    let peer = RegtestDaemon::spawn(RegtestSpawn::new(None).with_peering(Peering::Linked {
        p2p_port: peer_p2p,
        peer_p2p_port: node_p2p,
        sink: false,
    }))
    .await;
    let synced = Instant::now() + Duration::from_secs(300);
    while peer.height().await < want {
        assert!(
            Instant::now() < synced,
            "the arriving peer reached height {} of {want}",
            peer.height().await
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(
        peer.last_block_hash().await,
        tip,
        "the peer took the node's chain"
    );
    // The opening resolved on the lighter claim: the node is still synced
    // and still mines.
    let more = try_generate_blocks(&node.rpc, 1).await.unwrap_or_else(|e| {
        node.panic_with_log(
            "the node stopped mining when its peer arrived",
            format!("{e:?}"),
        )
    });
    assert_eq!(more.blocks.len(), 1);

    // The peer leaves. A closed node with none of its network up is synced
    // again, not `NoView`: it keeps mining.
    drop(peer);
    let left = Instant::now() + Duration::from_secs(60);
    loop {
        let reply: shekyl_rpc_types::P2pReply<shekyl_rpc_types::SyncInfoResponse> = node
            .rpc
            .json_rpc_call("sync_info", None)
            .await
            .expect("sync_info");
        let info = reply.into_running().expect("a linked daemon's P2P runs");
        if info.peers.is_empty() {
            break;
        }
        assert!(Instant::now() < left, "the peer's session never closed");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mined = Instant::now() + Duration::from_secs(60);
    loop {
        match try_generate_blocks(&node.rpc, 1).await {
            Ok(_) => break,
            Err(e)
                if ["mine.starting", "mine.not_synced"]
                    .iter()
                    .any(|code| format!("{e:?}").contains(code))
                    && Instant::now() < mined =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => node.panic_with_log(
                "a closed node whose peer left did not mine",
                format!("{e:?}"),
            ),
        }
    }
}
