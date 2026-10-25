// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Handler tests for [`crate::info::get_info`].
//!
//! The double and the oracle vectors live here so the handler module stays
//! the gather. `FakeInfoFacts` counts reads, which is how a test says a
//! read was not made.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use shekyl_economics::TxVolume;
use shekyl_types::{BlockHash, ChainCount};
use shekyl_units::AtomicUnits;

use super::*;
use crate::info_facts::{
    InfoChainFacts, InfoPeersFacts, InfoStatusFacts, PeerFacts, PoolCounts, PoolState,
    SessionCounts,
};

/// The emitter's `tagged_hash`: byte i = (i*7 + tag) & 0xff.
fn tagged_hash(tag: u8) -> BlockHash {
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let i = u8::try_from(i).expect("32 fits u8");
        *byte = i.wrapping_mul(7).wrapping_add(tag);
    }
    BlockHash::from_bytes(bytes)
}

/// An [`InfoFacts`] double: stated answers, a fault per read, and a
/// count of how often each read was made. The counts are what let a
/// test say a read was **not** made.
pub(crate) struct FakeInfoFacts {
    pub(crate) chain: InfoChainFacts,
    pub(crate) pool_broadcast: u64,
    pub(crate) pool_unbroadcast: u64,
    /// When set, the double answers a host-axis read without the second
    /// count: a facts layer that did not do what it was asked.
    pub(crate) pool_drops_unbroadcast: bool,
    /// When set, the pool is retired: the node's pool file faulted.
    pub(crate) pool_retired: bool,
    pub(crate) store_size: u64,
    pub(crate) status: InfoStatusFacts,
    pub(crate) peers: PeerFacts,
    pub(crate) sessions: SessionCounts,
    pub(crate) sessions_fault: Option<FactsFault>,
    pub(crate) sessions_reads: AtomicUsize,
    pub(crate) chain_fault: Option<FactsFault>,
    pub(crate) pool_fault: Option<FactsFault>,
    pub(crate) store_size_fault: Option<FactsFault>,
    pub(crate) status_fault: Option<FactsFault>,
    pub(crate) peers_fault: Option<FactsFault>,
    pub(crate) status_reads: AtomicUsize,
    pub(crate) peers_reads: AtomicUsize,
    pub(crate) store_size_reads: AtomicUsize,
    pub(crate) pool_scopes: Mutex<Vec<PoolScope>>,
}

/// The facts of the emitter's `synced_facts()`
/// (the emitter that captured the `get_info_*_v1.json` vectors; it was
/// deleted with the C++ handler). The `_v2` files are those with the
/// target restated at 3.46, and the core target below is where their
/// value comes from.
pub(crate) fn synced_facts() -> FakeInfoFacts {
    FakeInfoFacts {
        chain: InfoChainFacts {
            chain_height: ChainCount::from_raw(1_234_567),
            top_hash: tagged_hash(1),
            difficulty: (7u128 << 64) + 123_456_789,
            cumulative_difficulty: (9u128 << 64) + 987_654_321,
            difficulty_target: 120,
            total_transactions: 1_300_000,
            block_weight_limit: 600_000,
            block_weight_median: 300_000,
            adjusted_time: 1_700_000_123,
            already_generated_coins: AtomicUnits::from_raw(1_444_065_674_085_133),
            total_burned: AtomicUnits::from_raw(4_200_000_000),
            tx_volume: TxVolume::window(6000, 100),
            core_target_height: Some(ChainCount::from_raw(1_234_567)),
            synchronized: true,
            busy_syncing: false,
            offline: false,
            following_degraded: false,
            protocol_version: 3,
        },
        // Twelve entries held: nine broadcast, three not yet.
        pool_broadcast: 9,
        pool_unbroadcast: 3,
        pool_drops_unbroadcast: false,
        pool_retired: false,
        store_size: 7 * 1024 * 1024 * 1024 + 1,
        status: InfoStatusFacts {
            start_time: 1_699_990_000,
            free_space: 123_456_789_012,
            alt_blocks_count: 3,
            version: "3.1.0-oracle".to_owned(),
        },
        peers: PeerFacts::Running(InfoPeersFacts {
            public_incoming_sockets: 13,
            public_outgoing_sockets: 10,
            tor_incoming_sockets: 4,
            tor_outgoing_sockets: 2,
            white_peerlist_size: 500,
            grey_peerlist_size: 2500,
        }),
        chain_fault: None,
        pool_fault: None,
        store_size_fault: None,
        status_fault: None,
        peers_fault: None,
        // Eight outbound and twelve inbound, all handshaken.
        sessions: SessionCounts {
            outbound: 8,
            inbound: 12,
        },
        sessions_fault: None,
        sessions_reads: AtomicUsize::new(0),
        status_reads: AtomicUsize::new(0),
        peers_reads: AtomicUsize::new(0),
        store_size_reads: AtomicUsize::new(0),
        pool_scopes: Mutex::new(Vec::new()),
    }
}

impl InfoFacts for FakeInfoFacts {
    fn chain(&self) -> Result<InfoChainFacts, FactsFault> {
        self.chain_fault.map_or_else(|| Ok(self.chain.clone()), Err)
    }

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolState<PoolCounts>, FactsFault> {
        self.pool_scopes.lock().expect("scopes").push(scope);
        if let Some(fault) = self.pool_fault {
            return Err(fault);
        }
        if self.pool_retired {
            return Ok(PoolState::Retired);
        }
        Ok(PoolState::Live(PoolCounts {
            broadcast: self.pool_broadcast,
            // Counted only when asked for, as the real read does.
            unbroadcast: (scope == PoolScope::WithUnbroadcast && !self.pool_drops_unbroadcast)
                .then_some(self.pool_unbroadcast),
        }))
    }

    fn store_size(&self) -> Result<u64, FactsFault> {
        self.store_size_reads.fetch_add(1, Ordering::Relaxed);
        self.store_size_fault.map_or(Ok(self.store_size), Err)
    }

    fn status(&self) -> Result<InfoStatusFacts, FactsFault> {
        self.status_reads.fetch_add(1, Ordering::Relaxed);
        self.status_fault
            .map_or_else(|| Ok(self.status.clone()), Err)
    }

    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        self.peers_reads.fetch_add(1, Ordering::Relaxed);
        self.peers_fault.map_or(Ok(self.peers), Err)
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        self.sessions_reads.fetch_add(1, Ordering::Relaxed);
        self.sessions_fault.map_or(Ok(self.sessions), Err)
    }
}

fn oracle(vector: &str) -> serde_json::Value {
    serde_json::from_str(vector).expect("the oracle vector is JSON")
}

fn ours(facts: &FakeInfoFacts, disclosure: Disclosure) -> serde_json::Value {
    // The C++ handler wrote `rpc_connections_count` 0; the transport
    // filled it afterwards. The vectors carry the 0.
    serde_json::to_value(get_info(facts, disclosure, 0).expect("get_info answers"))
        .expect("the reply serializes")
}

// ── Parity: the C++ handler's computation over the same facts ──────────
//
// The vectors live in `shekyl-rpc-types`. This file is `src/info/tests.rs`,
// so the include climbs out of `info/`, `src/`, and the crate. A test in
// `src/*.rs` climbs one level less.

#[test]
fn synced_reproduces_the_oracle_vector() {
    assert_eq!(
        ours(&synced_facts(), Disclosure::FULL),
        oracle(include_str!(
            "../../../shekyl-rpc-types/tests/vectors/rpc/get_info_synced_v8.json"
        ))
    );
}

/// **RK-D15: the target is the core's, synchronized or not, and `null`
/// when the core has none.** The four combinations, each read off the
/// wire. Until 3.46 the two synchronized rows wrote `0`, which is also
/// what the fourth row wrote, so a synchronized node and a node with
/// nobody to learn a target from were the same bytes.
#[test]
fn the_target_is_the_cores_and_null_when_it_has_none() {
    for (synchronized, core_target, on_the_wire) in [
        (true, Some(1_234_567), serde_json::json!(1_234_567)),
        (true, None, serde_json::Value::Null),
        (false, Some(1_300_000), serde_json::json!(1_300_000)),
        (false, None, serde_json::Value::Null),
    ] {
        let mut facts = synced_facts();
        facts.chain.synchronized = synchronized;
        facts.chain.core_target_height = core_target.map(ChainCount::from_raw);
        let reply = ours(&facts, Disclosure::FULL);
        assert_eq!(
            reply["target_height"], on_the_wire,
            "synchronized {synchronized}, core target {core_target:?}"
        );
        assert_eq!(reply["synchronized"], serde_json::json!(synchronized));
    }
}

#[test]
fn syncing_reproduces_the_oracle_vector() {
    let mut facts = synced_facts();
    facts.chain.synchronized = false;
    facts.chain.core_target_height = Some(ChainCount::from_raw(1_300_000));
    facts.chain.busy_syncing = true;
    facts.chain.following_degraded = true;
    assert_eq!(
        ours(&facts, Disclosure::FULL),
        oracle(include_str!(
            "../../../shekyl-rpc-types/tests/vectors/rpc/get_info_syncing_v7.json"
        ))
    );
}

#[test]
fn peerless_startup_reproduces_the_oracle_vector() {
    let mut facts = synced_facts();
    facts.chain.synchronized = false;
    facts.chain.core_target_height = None;
    facts.sessions = SessionCounts::NONE;
    let PeerFacts::Running(peers) = &mut facts.peers else {
        unreachable!("the fixture's P2P runs")
    };
    peers.public_incoming_sockets = 0;
    peers.public_outgoing_sockets = 0;
    peers.tor_incoming_sockets = 0;
    peers.tor_outgoing_sockets = 0;
    assert_eq!(
        ours(&facts, Disclosure::FULL),
        oracle(include_str!(
            "../../../shekyl-rpc-types/tests/vectors/rpc/get_info_peerless_startup_v8.json"
        ))
    );
}

/// **A daemon started offline reports the state, never a zero**
/// (Rick, 2026-10-14). The Peers part is `"p2p": "offline"` with no count,
/// Health's `offline` agrees, and the board is not read.
#[test]
fn offline_reproduces_the_offline_vector() {
    let mut facts = synced_facts();
    facts.chain.synchronized = false;
    facts.chain.core_target_height = None;
    facts.chain.offline = true;
    facts.peers = PeerFacts::Offline;
    facts.sessions_fault = Some(FactsFault::NullHandle);
    facts.peers = PeerFacts::Offline;
    assert_eq!(
        ours(&facts, Disclosure::FULL),
        oracle(include_str!(
            "../../../shekyl-rpc-types/tests/vectors/rpc/get_info_offline_v1.json"
        ))
    );
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 0);
}

/// The P2P state and the core's `offline` flag are one configuration read
/// twice. A reply where they disagree is refused, in both directions: the
/// handler does not pick one.
#[test]
fn a_p2p_state_that_disagrees_with_offline_refuses() {
    let mut off_but_online = synced_facts();
    off_but_online.peers = PeerFacts::Offline;
    assert!(matches!(
        get_info(&off_but_online, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    ));
    let mut running_but_offline = synced_facts();
    running_but_offline.chain.offline = true;
    assert!(matches!(
        get_info(&running_but_offline, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    ));
}

/// An online daemon with no peer lists is a fault, not a Peers part of
/// zeros: the facts layer's `NullHandle` refuses the reply.
#[test]
fn an_online_daemon_with_no_peer_lists_refuses() {
    let mut facts = synced_facts();
    facts.peers_fault = Some(FactsFault::NullHandle);
    assert!(matches!(
        get_info(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::NullHandle))
    ));
}

/// The same facts as the synced case, asked by a restricted caller:
/// no Status and no Peers, and the pool counted over the broadcast set.
#[test]
fn synced_restricted_reproduces_the_oracle_vector() {
    assert_eq!(
        ours(&synced_facts(), Disclosure::VIEW),
        oracle(include_str!(
            "../../../shekyl-rpc-types/tests/vectors/rpc/get_info_synced_restricted_v7.json"
        ))
    );
}

// ── RK-Q9: a store that contradicts itself ───────────────────────────────

/// **More burned than generated refuses `get_info`, and the refusal says
/// what contradicted what** (RK-Q9). The fault names the invariant and
/// carries its three operands: coins generated, total burned, and the chain
/// height of the snapshot they were read at. Every caller is refused.
///
/// Until 3.51 this state was answered with `burn_pct: 0` and a log line.
/// `0` % is a legitimate burn, so the reply said something true-looking
/// about a store that could not be trusted. The oracle vectors
/// `get_info_burn_refusal_v1`…`_v4` record that reply; no daemon sends it
/// now, and this test is what stands where their parity test stood.
#[test]
fn more_burned_than_generated_refuses_with_the_invariant_and_its_operands() {
    let mut facts = synced_facts();
    let generated = facts.chain.already_generated_coins;
    let burned = AtomicUnits::from_raw(generated.to_raw() + 1);
    facts.chain.total_burned = burned;

    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        let fault = get_info(&facts, disclosure, 0).expect_err("a contradiction is not answered");
        assert_eq!(
            fault,
            RpcFault::Store(StoreFault::SupplyInvariant {
                coins_generated: generated,
                total_burned: burned,
                chain_height: ChainCount::from_raw(1_234_567),
            }),
            "{disclosure:?}"
        );
    }

    // What the caller reads: the invariant, and each operand as a number.
    let text = StoreFault::SupplyInvariant {
        coins_generated: generated,
        total_burned: burned,
        chain_height: ChainCount::from_raw(1_234_567),
    }
    .to_string();
    assert!(text.contains("total_burned <= coins_generated"), "{text}");
    assert!(text.contains("1444065674085134"), "total burned: {text}");
    assert!(text.contains("1444065674085133"), "coins generated: {text}");
    assert!(
        text.contains("1234567"),
        "the snapshot's chain height: {text}"
    );
}

/// The boundary: burned equal to generated is a legitimate state (nothing
/// circulating), and is answered. One unit more is the refusal above.
#[test]
fn everything_burned_is_answered_and_one_unit_more_is_not() {
    let mut facts = synced_facts();
    facts.chain.total_burned = facts.chain.already_generated_coins;
    let reply = get_info(&facts, Disclosure::FULL, 0).expect("equal is not a contradiction");
    assert_eq!(
        reply.economics.total_burned,
        reply.economics.already_generated_coins
    );

    facts.chain.total_burned =
        AtomicUnits::from_raw(facts.chain.already_generated_coins.to_raw() + 1);
    assert!(matches!(
        get_info(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Store(StoreFault::SupplyInvariant { .. }))
    ));
}

/// A burn of zero is an answer and is written as `0`, a plain number. It
/// is never `null`, and it no longer doubles as "the computation refused".
#[test]
fn a_burn_of_zero_is_a_number_on_the_wire() {
    let mut facts = synced_facts();
    facts.chain.total_burned = AtomicUnits::from_raw(0);
    facts.chain.tx_volume = TxVolume::ZERO;
    let wire = ours(&facts, Disclosure::FULL);
    assert!(
        wire["burn_pct"].is_u64(),
        "burn_pct is a number: {}",
        wire["burn_pct"]
    );
}

// ── RK-D24: gathering by part ──────────────────────────────────────────

/// A restricted caller is not shown Status or Peers, so neither is read
/// on its behalf, and its pool count is asked for over the broadcast
/// set only. The store's size is a Status member and is not read
/// either.
#[test]
fn a_view_caller_costs_no_status_or_peers_read() {
    let facts = synced_facts();
    get_info(&facts, Disclosure::VIEW, 5).expect("a view caller is answered");
    assert_eq!(facts.status_reads.load(Ordering::Relaxed), 0);
    assert_eq!(facts.peers_reads.load(Ordering::Relaxed), 0);
    assert_eq!(facts.store_size_reads.load(Ordering::Relaxed), 0);
    assert_eq!(
        facts.sessions_reads.load(Ordering::Relaxed),
        1,
        "Health is shown to every caller, so its read is made for this one"
    );
    assert_eq!(
        *facts.pool_scopes.lock().expect("scopes"),
        vec![PoolScope::Broadcast],
        "the not-yet-broadcast count is host-only and is not made without the host axis"
    );
}

/// The host's administrator is shown everything, and each part is read
/// once.
#[test]
fn a_full_caller_reads_each_part_once() {
    let facts = synced_facts();
    get_info(&facts, Disclosure::FULL, 5).expect("a full caller is answered");
    assert_eq!(facts.status_reads.load(Ordering::Relaxed), 1);
    assert_eq!(facts.peers_reads.load(Ordering::Relaxed), 1);
    assert_eq!(facts.store_size_reads.load(Ordering::Relaxed), 1);
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        *facts.pool_scopes.lock().expect("scopes"),
        vec![PoolScope::WithUnbroadcast]
    );
}

/// The test RK-D24 requires. With the Status facts set to fail, a view
/// caller gets a full reply — the same one it gets when they succeed —
/// and a full caller gets the refusal. A failing volume query must not
/// refuse a caller who would never have been told the free space.
#[test]
fn failing_status_facts_refuse_a_full_caller_and_not_a_view_caller() {
    let healthy = ours(&synced_facts(), Disclosure::VIEW);

    let mut facts = synced_facts();
    facts.status_fault = Some(FactsFault::Internal);
    assert_eq!(
        ours(&facts, Disclosure::VIEW),
        healthy,
        "a view caller's reply must not depend on the Status facts at all"
    );
    assert_eq!(
        get_info(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Internal))
    );
}

/// The same for Peers.
#[test]
fn failing_peers_facts_refuse_a_full_caller_and_not_a_view_caller() {
    let healthy = ours(&synced_facts(), Disclosure::VIEW);

    let mut facts = synced_facts();
    facts.peers_fault = Some(FactsFault::Internal);
    assert_eq!(ours(&facts, Disclosure::VIEW), healthy);
    assert_eq!(
        get_info(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Internal))
    );
}

/// The store's size is a Status member, so its read follows Status:
/// with the size read failing, a view caller gets the same full reply it
/// gets when the read succeeds, and a full caller gets the refusal.
///
/// Until 3.48 this was the one exception to gathering by part. A
/// restricted reply carried the size rounded up, so it was read for
/// every caller and an unreadable store refused both. The stand-in is
/// gone, and the exception with it (RK-Q8).
#[test]
fn an_unreadable_store_size_refuses_a_full_caller_and_not_a_view_caller() {
    let healthy = ours(&synced_facts(), Disclosure::VIEW);

    let mut facts = synced_facts();
    facts.store_size_fault = Some(FactsFault::StoreUnreadable);
    assert_eq!(
        ours(&facts, Disclosure::VIEW),
        healthy,
        "a view caller's reply must not depend on the store's size at all"
    );
    assert_eq!(
        facts.store_size_reads.load(Ordering::Relaxed),
        0,
        "the size is not read for a caller who is not told it"
    );
    assert_eq!(
        get_info(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::StoreUnreadable))
    );
}

/// A fault in a read every caller needs refuses every caller.
#[test]
fn a_failing_chain_or_pool_read_refuses_every_caller() {
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        let mut facts = synced_facts();
        facts.chain_fault = Some(FactsFault::NotReady);
        assert_eq!(
            get_info(&facts, disclosure, 0),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );

        let mut facts = synced_facts();
        facts.pool_fault = Some(FactsFault::Internal);
        assert_eq!(
            get_info(&facts, disclosure, 0),
            Err(RpcFault::Facts(FactsFault::Internal))
        );
    }
}

// ── What the reply says ────────────────────────────────────────────────

/// The transport's connection count is a Status field: shown to a full
/// caller as given, and not to a view caller whatever it is.
#[test]
fn the_rpc_connection_count_is_shown_with_status_only() {
    let facts = synced_facts();
    let full = get_info(&facts, Disclosure::FULL, 17).unwrap();
    assert_eq!(full.node.shown().map(|n| n.rpc_connections_count), Some(17));
    let view = get_info(&facts, Disclosure::VIEW, 17).unwrap();
    assert_eq!(view.node, Hidden::Withheld, "no Status, so no count");
}

/// `following_degraded` is the store's flag, carried as it is in both
/// states and for both callers (C2-R1b F-1(a): monitoring must see a
/// node that is knowingly not following the heaviest chain).
#[test]
fn following_degraded_is_the_stores_flag_for_every_caller() {
    for degraded in [false, true] {
        let mut facts = synced_facts();
        facts.chain.following_degraded = degraded;
        for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
            assert_eq!(
                get_info(&facts, disclosure, 0)
                    .unwrap()
                    .health
                    .following_degraded,
                degraded
            );
        }
    }
}

/// `target` is the store's difficulty target as a value (RK-D9), not a
/// byte form: the reply carries what the facts carry.
#[test]
fn target_is_the_difficulty_target() {
    let mut facts = synced_facts();
    facts.chain.difficulty_target = 77;
    assert_eq!(
        get_info(&facts, Disclosure::FULL, 0).unwrap().chain.target,
        77
    );
}

/// `already_generated_coins` is the coins generated through the tip the
/// snapshot names, and `total_burned` is reported beside it, not netted
/// out of it.
#[test]
fn already_generated_coins_is_the_snapshots_and_is_not_netted() {
    let facts = synced_facts();
    let reply = get_info(&facts, Disclosure::VIEW, 0).unwrap();
    assert_eq!(
        reply.economics.already_generated_coins,
        AtomicUnits::from_raw(1_444_065_674_085_133)
    );
    assert_eq!(
        reply.economics.total_burned,
        AtomicUnits::from_raw(4_200_000_000)
    );
}

/// The listener's posture is what `restricted` reports.
#[test]
fn restricted_reports_the_listener() {
    let facts = synced_facts();
    assert!(
        get_info(&facts, Disclosure::from_listener(true), 0)
            .unwrap()
            .restricted
    );
    assert!(
        !get_info(&facts, Disclosure::from_listener(false), 0)
            .unwrap()
            .restricted
    );
    assert_eq!(Disclosure::from_listener(true), Disclosure::VIEW);
    assert_eq!(Disclosure::from_listener(false), Disclosure::FULL);
}

/// **A restricted reply withholds Status and Peers: the parts are
/// absent, and nothing stands in for them** (RK-Q8, RK-D23). Every key
/// of both parts is missing from the wire, the reply still decodes as
/// this build's type with both parts withheld, and everything else in
/// it is what the host's administrator is told.
///
/// Until 3.48 those keys were present and held values that meant "not
/// this value": zero counts, an empty version, `u64::MAX` of free
/// space, and the store's size rounded up to five gibibytes.
#[test]
fn a_restricted_reply_withholds_status_and_peers() {
    const STATUS_KEYS: [&str; 8] = [
        "start_time",
        "free_space",
        "database_size",
        "version",
        "outgoing_connections_count",
        "incoming_connections_count",
        "alt_blocks_count",
        "rpc_connections_count",
    ];
    const PEERS_KEYS: [&str; 6] = [
        "public_incoming_socket_count",
        "public_outgoing_socket_count",
        "tor_incoming_socket_count",
        "tor_outgoing_socket_count",
        "white_peerlist_size",
        "grey_peerlist_size",
    ];

    let facts = synced_facts();
    let view = get_info(&facts, Disclosure::VIEW, 17).expect("a view caller is answered");
    assert_eq!(view.node, Hidden::Withheld);
    assert_eq!(view.peers, Hidden::Withheld);

    let wire = serde_json::to_value(&view).expect("the reply serializes");
    let members = wire.as_object().expect("a reply is an object");
    for key in STATUS_KEYS.iter().chain(PEERS_KEYS.iter()) {
        assert!(
            !members.contains_key(*key),
            "`{key}` is not disclosed, so it is not on the wire"
        );
    }
    assert_eq!(
        serde_json::from_value::<GetInfoResponse>(wire.clone()).expect("it decodes"),
        view,
        "a reply without the two parts is this build's reply"
    );

    // Everything else is what a full caller is told, apart from the
    // posture flag and the host-only part.
    let mut full = serde_json::to_value(
        get_info(&facts, Disclosure::FULL, 17).expect("a full caller is answered"),
    )
    .expect("the reply serializes");
    let full_members = full.as_object_mut().expect("a reply is an object");
    for key in STATUS_KEYS.iter().chain(PEERS_KEYS.iter()).chain(&["p2p"]) {
        assert!(
            full_members.remove(*key).is_some(),
            "a full reply carries `{key}`"
        );
    }
    let mut view_rest = wire;
    for reply in [&mut full, &mut view_rest] {
        let members = reply.as_object_mut().expect("a reply is an object");
        members.remove("restricted");
        members.remove("tx_pool_unbroadcast_count");
    }
    assert_eq!(view_rest, full);
}

// ── RK-Q10: the pool's two counts ────────────────────────────────────────

/// **`tx_pool_size` is one quantity for every caller: the entries this node
/// has broadcast** (RK-Q10). The host's administrator and a restricted
/// caller read the same number from the same pool. Until 3.50 the first was
/// told twelve and the second nine, under one key.
#[test]
fn tx_pool_size_is_the_broadcast_count_for_every_caller() {
    let facts = synced_facts();
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        assert_eq!(
            get_info(&facts, disclosure, 0).unwrap().pool.tx_pool_size(),
            Some(9),
            "{disclosure:?}"
        );
    }

    // And it does not move with the entries that are not yet broadcast.
    let mut facts = synced_facts();
    facts.pool_unbroadcast = 1_000;
    assert_eq!(
        get_info(&facts, Disclosure::FULL, 0)
            .unwrap()
            .pool
            .tx_pool_size(),
        Some(9)
    );
}

/// **The count of entries not yet broadcast is the host's alone.** The
/// host's administrator is told it, in its own part. Any other caller's
/// reply does not carry the key, and the count is not made on its behalf:
/// the facts layer is asked for the broadcast count only.
///
/// A transaction on its stem is such an entry. That it exists says where a
/// transaction originated, which is what the stem phase hides.
#[test]
fn the_unbroadcast_count_is_told_to_the_host_and_not_counted_for_anyone_else() {
    let facts = synced_facts();
    let full = get_info(&facts, Disclosure::FULL, 0).expect("the host is answered");
    assert_eq!(
        full.host,
        Hidden::Shown(InfoHost {
            tx_pool_unbroadcast_count: Some(3)
        })
    );

    let facts = synced_facts();
    let view = get_info(&facts, Disclosure::VIEW, 0).expect("a view caller is answered");
    assert_eq!(view.host, Hidden::Withheld);
    let wire = serde_json::to_value(&view).expect("the reply serializes");
    assert!(
        !wire
            .as_object()
            .expect("a reply is an object")
            .contains_key("tx_pool_unbroadcast_count"),
        "a caller who is not the host is not told the key exists with a value"
    );
    assert_eq!(
        *facts.pool_scopes.lock().expect("scopes"),
        vec![PoolScope::Broadcast],
        "and the count is not made for it"
    );
}

/// A host with nothing unbroadcast is told `0`, which is a count. It is
/// not the absent key a non-host caller gets.
#[test]
fn a_host_with_nothing_unbroadcast_is_told_zero_not_nothing() {
    let mut facts = synced_facts();
    facts.pool_unbroadcast = 0;
    let wire = serde_json::to_value(get_info(&facts, Disclosure::FULL, 0).unwrap()).unwrap();
    assert_eq!(wire["tx_pool_unbroadcast_count"], 0);
}

/// A facts layer that is asked on the host axis and returns no second
/// count did not do what it was asked. That is a fault, and the host is
/// not told `0` or left without the part.
#[test]
fn a_host_read_that_returns_no_unbroadcast_count_is_a_fault() {
    let mut facts = synced_facts();
    facts.pool_drops_unbroadcast = true;
    assert_eq!(
        get_info(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    );
}

/// **A retired pool does not black out the reply.** The node retires its
/// pool when the pool's file faults and goes on following the chain, so
/// `get_info` answers: `pool_retired`, the pool's counts `null` (RK-D23:
/// no answer), and the chain's members as a live pool's reply carries
/// them. The host's part is shown with its count `null`; any other caller
/// is withheld the part as ever.
#[test]
fn a_retired_pool_answers_null_counts_and_the_chain() {
    let live = get_info(&synced_facts(), Disclosure::FULL, 0).expect("live");
    let mut facts = synced_facts();
    facts.pool_retired = true;
    let full = get_info(&facts, Disclosure::FULL, 0).expect("a retired pool is answered");
    assert_eq!(full.pool, InfoPool::Retired);
    assert_eq!(
        full.host,
        Hidden::Shown(InfoHost {
            tx_pool_unbroadcast_count: None
        })
    );
    assert_eq!(
        (&full.health, &full.chain, &full.economics, &full.node),
        (&live.health, &live.chain, &live.economics, &live.node),
        "the chain's members are what a live pool's reply carries"
    );
    let wire = serde_json::to_value(&full).expect("the reply serializes");
    assert_eq!(wire["pool_retired"], true);
    assert!(wire["tx_pool_size"].is_null(), "{wire}");
    assert!(wire["tx_pool_unbroadcast_count"].is_null(), "{wire}");
    assert_eq!(
        serde_json::from_value::<GetInfoResponse>(wire).expect("it decodes"),
        full,
        "and round-trips"
    );

    let mut facts = synced_facts();
    facts.pool_retired = true;
    let view = get_info(&facts, Disclosure::VIEW, 0).expect("a view caller is answered");
    assert_eq!(view.pool, InfoPool::Retired);
    assert_eq!(view.host, Hidden::Withheld);
    let wire = serde_json::to_value(&view).expect("the reply serializes");
    assert!(
        !wire
            .as_object()
            .expect("an object")
            .contains_key("tx_pool_unbroadcast_count"),
        "withheld stays absent, not null"
    );

    // A live reply carries no `pool_retired`: its shape is unchanged.
    let wire = serde_json::to_value(&live).expect("the reply serializes");
    assert!(!wire
        .as_object()
        .expect("an object")
        .contains_key("pool_retired"));
}

#[path = "peer_facts_tests.rs"]
mod peers;
