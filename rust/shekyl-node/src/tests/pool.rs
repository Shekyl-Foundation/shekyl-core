// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A pool-file fault retires the pool.

use super::*;

/// A flush whose pool-file write faults retires the pool, for the
/// service too: the flush answers a store fault, the next pool read is
/// not ready, and mining status reports the pool retired (the review of
/// #1165, M5).
///
/// The retirement does not black out the chain (the landing's N1). The
/// node goes on following the chain, so the chain's reads answer:
///
/// - `daemon_status` answers with the pool's counts `null` and the
///   chain's members as ever;
/// - `tx_list` answers a chain id, and gives an id the chain does not
///   hold a `null` slot, not `{"missing": null}`: whether the pool holds
///   it has no answer;
/// - a key image's spend stays failed closed: a spend the pool may hold
///   is unknowable, and "unspent" is a double spend's first step.
///
/// Red edits: the bridge does not retire the pool; the surroundings do not
/// read the retirement; `pool_counts` refuses on retirement.
#[test]
fn a_flush_over_a_faulted_pool_file_retires_the_pool() {
    use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
    use shekyl_daemon_rpc::info::{daemon_status, Disclosure};
    use shekyl_daemon_rpc::info_facts::PoolScope;
    use shekyl_daemon_rpc::pool_methods::{txpool_flush, txpool_list};
    use shekyl_daemon_rpc::reads::tx_list;
    use shekyl_rpc_types::errors::ErrorClass;
    use shekyl_rpc_types::wire::shared::{Slot, SlotState};
    use shekyl_rpc_types::wire::tx::{FlushIds, TxListQuery};
    use shekyl_rpc_types::HashHex;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let pool = node.pool().expect("a pool");
    let planted = {
        let mut pool = pool.lock().expect("the pool");
        let txid = pool.plant(
            shekyl_chain_rules::harness::fixture::paying_fee(
                shekyl_chain_rules::harness::fixture::listed([7; 32]),
                1,
            ),
            PoolRecord {
                received: ReceivedHour::from_raw(1),
                public: true,
            },
        );
        pool.refuse_next_commit();
        txid
    };
    let handles = node.handles();
    let flushed = a_runtime().block_on(txpool_flush(
        &*handles.pool,
        &FlushIds {
            id: Some(vec![HashHex::from_bytes(planted.to_bytes())]),
        },
        PoolScope::WithUnbroadcast,
    ));
    let after = txpool_list(&*handles.pool, PoolScope::Broadcast);
    let spent = handles
        .chain
        .key_images_spent(&[shekyl_types::KeyImage::from_bytes([7; 32])]);
    let status = handles.mining.status();
    // The Tor read is the supervisor's, which a node test does not run: a
    // Tor-off node's answer, as the handler would pass it.
    let tor = shekyl_daemon_rpc::tor_facts::TorRead {
        hiding: false,
        status: Some(shekyl_tor_status::TorStatus {
            posture: shekyl_tor_status::Posture {
                tor: shekyl_tor_status::TorSetting::Off,
                clearnet: shekyl_tor_status::Clearnet::On,
            },
            origination: shekyl_tor_status::Origination::ClearnetOnly,
            sync_connector: vec![],
            tor_quiet: None,
            tor: None,
        }),
    };
    let info = daemon_status(&*handles.chain, &*handles.chain, Disclosure::FULL, 0, tor);
    // The genesis coinbase: an id the chain holds.
    let genesis = handles
        .chain
        .blocks_by_height(&[shekyl_types::BlockHeight::ZERO])
        .expect("the genesis block");
    let coinbase = shekyl_wire::Block::from_bytes(&genesis.blocks[0].block)
        .expect("a recorded block parses")
        .miner_transaction
        .txid_parts()
        .hash;
    let asked = |id: &shekyl_types::TxHash| HashHex::from_bytes(id.to_bytes());
    let txs = tx_list(
        &*handles.chain,
        &TxListQuery {
            id: vec![asked(&coinbase), asked(&planted)],
            prune: false,
        },
        true,
    );
    node.stop();
    assert_eq!(
        flushed.expect_err("the file faulted").class,
        ErrorClass::StoreFault
    );
    assert_eq!(after.expect_err("retired").class, ErrorClass::NotReady);
    assert_eq!(
        spent.expect_err("a key image's pool spend is unknowable: failed closed"),
        shekyl_daemon_rpc::chain_facts::FactsFault::NotReady
    );
    assert!(
        status.expect("status").pool_retired,
        "the service's pool is retired"
    );
    let info = info.unwrap_or_else(|_| panic!("daemon_status answers over a retired pool"));
    assert_eq!(
        info.txpool_count.shown().expect("the pool part is shown").0,
        None,
        "the pool's count has no answer"
    );
    assert_eq!(
        info.txpool_private_count.shown().map(|count| count.0),
        Some(None),
        "the host's count is shown with no answer"
    );
    assert_eq!(info.hash, HashHex::from_bytes(genesis_hash().to_bytes()));
    let txs = txs.unwrap_or_else(|_| panic!("tx_list answers over a retired pool"));
    assert_eq!(txs.len(), 2);
    assert!(
        matches!(&txs[0], Slot::Item(entry) if entry.id == asked(&coinbase)),
        "the chain's id is answered"
    );
    assert!(
        !matches!(&txs[1], Slot::State(SlotState::Missing(_))),
        "an unread pool misses nothing"
    );
    assert!(
        matches!(&txs[1], Slot::Unasked),
        "the pool's id has no answer"
    );
}

/// `tx_relay` on a running node with no network (clearnet and Tor off):
/// the host's re-offer answers the held entry and enters the stem entry
/// the node installed, which no longer holds it; a caller without the
/// host's view is not shown it and its re-offer reaches nothing (IG-Q89).
///
/// That the entry turns public is
/// `a_reoffer_through_the_offline_stem_entry_shows_the_entry`'s claim. Here
/// a listing cannot read it: showing the entry wakes the tip follower (Q9),
/// whose reconcile judges the pool against the chain and drops this
/// fixture, which the chain would refuse. A read after the re-offer races
/// that removal, and on a loaded runner the removal won (run 43719108962,
/// all three tries). What holds either way is that the entry is no longer
/// held: the pool's record is public, or gone by the reconcile its showing
/// woke. This node does not mine and the follower has no timer, so nothing
/// else wakes it, and an entry the stem left alone is still held.
///
/// Red edits: `tx_relay` gives a caller without the host's view the held
/// entry; `PoolBridge::relay` answers no id it offered; the node installs
/// a stem entry that does not show what it is offered.
#[test]
fn a_reoffer_enters_the_stem_entry_a_submission_takes() {
    use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
    use shekyl_daemon_rpc::info_facts::PoolScope;
    use shekyl_daemon_rpc::pool_methods::{tx_relay, txpool_list};
    use shekyl_rpc_types::wire::shared::{Slot, SlotState};
    use shekyl_rpc_types::wire::tx::RelayIds;
    use shekyl_rpc_types::HashHex;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let pool = node.pool().expect("a pool");
    let held = pool.lock().expect("the pool").plant(
        shekyl_chain_rules::harness::fixture::paying_fee(
            shekyl_chain_rules::harness::fixture::listed([7; 32]),
            1,
        ),
        PoolRecord {
            received: ReceivedHour::from_raw(1),
            public: false,
        },
    );
    let handles = node.handles();
    let id = HashHex::from_bytes(held.to_bytes());
    let public = |handles: &shekyl_daemon_rpc::handles::Handles| {
        txpool_list(&*handles.pool, PoolScope::Broadcast)
            .unwrap_or_else(|_| panic!("a listing"))
            .iter()
            .any(|entry| entry.id == id)
    };
    let before = public(&handles);
    let stranger = tx_relay(
        &*handles.pool,
        &RelayIds { id: vec![id] },
        PoolScope::Broadcast,
    );
    let after_stranger = public(&handles);
    let host = tx_relay(
        &*handles.pool,
        &RelayIds { id: vec![id] },
        PoolScope::WithUnbroadcast,
    );
    let after_host = pool.lock().expect("the pool").relay_view().record(&held);
    node.stop();
    assert!(!before, "a held entry is not public");
    assert_eq!(
        stranger.unwrap_or_else(|_| panic!("a stranger's re-offer answers")),
        vec![Slot::State(SlotState::Missing(
            shekyl_rpc_types::wire::shared::Null
        ))]
    );
    assert!(!after_stranger, "a stranger's re-offer reaches nothing");
    assert_eq!(
        host.unwrap_or_else(|_| panic!("the host's re-offer answers")),
        vec![Slot::Item(id)]
    );
    assert!(
        !matches!(after_host, Some(PoolRecord { public: false, .. })),
        "the node's stem entry no longer holds the re-offered entry: {after_host:?}"
    );
}

/// A held entry the host re-offers turns public at once on a node with no
/// network: `PoolBridge::relay` hands it to the offline stem entry, which
/// shows it through the pool door (RX-2). Before the re-offer the
/// broadcast listing lacks it, after it the listing holds it.
///
/// The bridge, the stem entry, the door and the pool are the running
/// node's own types over its own pool. The door's wake goes to a `Notify`
/// nothing waits on, so no follower pass judges the pool between the
/// re-offer and the read: the fixture is a transaction the chain would
/// refuse, and a reconcile drops it (see
/// `a_reoffer_enters_the_stem_entry_a_submission_takes`). The node's tip
/// does not move here, so nothing else wakes the follower.
///
/// Red edits: `PoolBridge::relay` collects the ids without offering them;
/// the offline stem entry does not show what it is offered.
#[test]
fn a_reoffer_through_the_offline_stem_entry_shows_the_entry() {
    use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
    use shekyl_daemon_rpc::info_facts::PoolScope;
    use shekyl_daemon_rpc::pool_methods::{tx_relay, txpool_list};
    use shekyl_rpc_types::wire::shared::Slot;
    use shekyl_rpc_types::wire::tx::RelayIds;
    use shekyl_rpc_types::HashHex;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let pool = node.pool().expect("a pool");
    let held = pool.lock().expect("the pool").plant(
        shekyl_chain_rules::harness::fixture::paying_fee(
            shekyl_chain_rules::harness::fixture::listed([7; 32]),
            1,
        ),
        PoolRecord {
            received: ReceivedHour::from_raw(1),
            public: false,
        },
    );
    let pool_slot: crate::pool_door::PoolSlot = Arc::new(Mutex::new(Some(Arc::clone(&pool))));
    let rules = ChainRules::new(
        Network::Regtest,
        None,
        shekyl_chain_rules::CappedEpoch::PRODUCTION,
    )
    .expect("rules");
    let door = Arc::new(crate::pool_door::NodePoolDoor::new(
        Arc::new(Mutex::new(None)),
        Arc::clone(&pool_slot),
        rules,
        shekyl_chain_rules::AdmissionPolicy::GENESIS,
        Arc::new(crate::pool_door::Departures::default()),
        Arc::new(tokio::sync::Notify::new()),
    ));
    let bridge = crate::facts::PoolBridge::new(
        pool_slot,
        shekyl_chain_ingest::service::PoolHealth::unwired(),
        Arc::new(|_: &[shekyl_types::TxHash]| {}),
        crate::open_network::offline_stem_entry(door),
    );
    let id = HashHex::from_bytes(held.to_bytes());
    let public = || {
        txpool_list(&bridge, PoolScope::Broadcast)
            .unwrap_or_else(|_| panic!("a listing"))
            .iter()
            .any(|entry| entry.id == id)
    };
    let before = public();
    let host = tx_relay(
        &bridge,
        &RelayIds { id: vec![id] },
        PoolScope::WithUnbroadcast,
    );
    let after = public();
    node.stop();
    assert!(!before, "a held entry is not public");
    assert_eq!(
        host.unwrap_or_else(|_| panic!("the host's re-offer answers")),
        vec![Slot::Item(id)]
    );
    assert!(
        after,
        "the offline stem entry shows the re-offered entry at once"
    );
}
