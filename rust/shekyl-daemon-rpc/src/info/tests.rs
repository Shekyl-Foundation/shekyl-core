// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Handler tests for [`crate::info::daemon_status`].
//!
//! The double lives here so the handler module stays the gather.
//! `FakeInfoFacts` counts reads, which is how a test says a read was not
//! made.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use shekyl_economics::TxVolume;
use shekyl_types::{BlockHash, ChainCount};
use shekyl_units::AtomicUnits;

use super::*;
use crate::info_facts::{
    InfoChainFacts, InfoStatusFacts, PeerFacts, PoolCounts, PoolState, SessionCounts,
};
use shekyl_rpc_types::nullable::Nullable;
use shekyl_rpc_types::wire::daemon::ConnectorCounts;

fn counts(inbound: u64, outbound: u64, white: u64, gray: u64) -> ConnectorCounts {
    ConnectorCounts {
        inbound_count: Count(inbound),
        outbound_count: Count(outbound),
        peer_white_count: Count(white),
        peer_gray_count: Count(gray),
    }
}

/// The fixture's connector map, every connector's sockets replaced: a node
/// whose lists are full and whose sockets read `inbound` and `outbound`.
pub(super) fn with_sockets(peers: &PeerFacts, inbound: u64, outbound: u64) -> PeerFacts {
    let PeerFacts::Running(map) = peers else {
        unreachable!("the fixture's P2P runs")
    };
    let swap = |row: &Option<ConnectorCounts>| {
        row.as_ref().map(|row| ConnectorCounts {
            inbound_count: Count(inbound),
            outbound_count: Count(outbound),
            ..row.clone()
        })
    };
    PeerFacts::Running(ConnectorMap {
        clearnet: swap(&map.clearnet),
        tor: swap(&map.tor),
    })
}

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

/// A synchronized online node, its pool holding nine public entries and
/// three not yet public.
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
            // Two caches: a window that spans a seed boundary.
            randomx_caches: 2,
        },
        peers: PeerFacts::Running(ConnectorMap {
            clearnet: Some(counts(13, 10, 500, 2500)),
            tor: Some(counts(4, 2, 40, 300)),
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
        self.peers_fault.map_or_else(|| Ok(self.peers.clone()), Err)
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        self.sessions_reads.fetch_add(1, Ordering::Relaxed);
        self.sessions_fault.map_or(Ok(self.sessions), Err)
    }
}

/// The reply as `daemon_status` answers `disclosure`, on a chain whose
/// writer is live.
pub(super) fn status(
    facts: &FakeInfoFacts,
    disclosure: Disclosure,
    rpc_connections: u64,
) -> Result<DaemonStatus, RpcFault> {
    daemon_status(
        facts,
        &crate::methods::tests::facts(true, 0),
        disclosure,
        rpc_connections,
        tor_read(disclosure),
    )
}

/// What the supervisor answers `disclosure`: `hiding`, and an operator's
/// Tor's status only for a caller shown Status, as the handler asks it.
pub(super) fn tor_read(disclosure: Disclosure) -> crate::tor_facts::TorRead {
    use shekyl_tor_status::{Clearnet, Connector, Origination, Posture, TorSetting, TorStatus};
    crate::tor_facts::TorRead {
        hiding: true,
        status: disclosure.status().then(|| TorStatus {
            posture: Posture {
                tor: TorSetting::Operator,
                clearnet: Clearnet::Off,
            },
            origination: Origination::AddressHiding,
            sync_connector: vec![Connector::Tor],
            tor_quiet: None,
            tor: None,
        }),
    }
}

pub(super) fn ours(facts: &FakeInfoFacts, disclosure: Disclosure) -> serde_json::Value {
    serde_json::to_value(status(facts, disclosure, 0).expect("daemon_status answers"))
        .expect("the reply serializes")
}

/// The keys the Status part carries.
const STATUS_KEYS: [&str; 15] = [
    "started",
    "disk_free",
    "data_size",
    "randomx_caches",
    "revision",
    "peer_outbound_count",
    "peer_inbound_count",
    "alt_count",
    "rpc_connections",
    "txpool_retired",
    "posture",
    "origination",
    "sync_connector",
    "tor_quiet",
    "tor",
];

// ── what a synchronized node is told ───────────────────────────────────

/// A synchronized node, asked by the host: every member in its 4.0 name and
/// kind. The tip and target are ordinals (IG-Q45); amounts are decimal
/// strings; the difficulties `0x` hex; the parts all shown. The edit that
/// turns this red is a member written as its 3.x count or number.
#[test]
fn a_synced_node_answers_every_member_in_its_kind() {
    let wire = ours(&synced_facts(), Disclosure::FULL);
    assert_eq!(wire["height"], 1_234_566);
    assert_eq!(wire["hash"], tagged_hash(1).to_string());
    assert_eq!(wire["target_height"], 1_234_566);
    assert_eq!(wire["synchronized"], true);
    assert_eq!(wire["syncing"], false);
    assert_eq!(wire["offline"], false);
    assert_eq!(wire["degraded"], false);
    assert_eq!(wire["peered"], true);
    assert_eq!(wire["writer"], serde_json::json!({"live": null}));
    assert_eq!(wire["protocol_version"], 3);
    assert_eq!(
        wire["difficulty"],
        format!("{:#x}", (7u128 << 64) + 123_456_789)
    );
    assert_eq!(wire["block_spacing"], 120);
    assert_eq!(
        wire["tx_count"],
        1_300_000 - 1_234_567,
        "coinbases excluded"
    );
    assert_eq!(wire["block_weight_max"], 600_000);
    assert_eq!(wire["emission"], "1444065674085133");
    assert_eq!(wire["burn_total"], "4200000000");
    assert_eq!(wire["txpool_count"], 9);
    assert_eq!(wire["txpool_private_count"], 3);
    assert_eq!(wire["started"], 1_699_990_000);
    assert_eq!(wire["disk_free"], 123_456_789_012_u64);
    assert_eq!(wire["data_size"], 7 * 1024 * 1024 * 1024 + 1_u64);
    assert_eq!(wire["randomx_caches"], 2, "the hasher's live caches");
    assert_eq!(wire["revision"], "3.1.0-oracle");
    assert_eq!(wire["peer_outbound_count"], 8);
    assert_eq!(wire["peer_inbound_count"], 12);
    assert_eq!(wire["alt_count"], 3);
    assert_eq!(wire["txpool_retired"], false);
    assert_eq!(wire["connector"]["clearnet"]["inbound_count"], 13);
    assert_eq!(wire["connector"]["tor"]["peer_gray_count"], 300);
    assert!(wire["grant"].as_array().expect("a list").len() > 3);
}

/// **The target is the core's, as a tip, synchronized or not, and `null`
/// when the core has none** (RK-D15, RK-D23).
#[test]
fn the_target_is_the_cores_and_null_when_it_has_none() {
    for (synchronized, core_target, on_the_wire) in [
        (true, Some(1_234_567), serde_json::json!(1_234_566)),
        (true, None, serde_json::Value::Null),
        (false, Some(1_300_000), serde_json::json!(1_299_999)),
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

/// A syncing, degraded node says both, and its other members are as ever.
#[test]
fn a_syncing_degraded_node_says_so() {
    let mut facts = synced_facts();
    facts.chain.synchronized = false;
    facts.chain.busy_syncing = true;
    facts.chain.following_degraded = true;
    let wire = ours(&facts, Disclosure::FULL);
    assert_eq!(
        (&wire["synchronized"], &wire["syncing"], &wire["degraded"]),
        (
            &serde_json::json!(false),
            &serde_json::json!(true),
            &serde_json::json!(true)
        )
    );
    assert_eq!(wire["height"], 1_234_566);
}

/// The store's writer halted on an invariant is in Health, for every
/// caller (IG-Q92).
#[test]
fn a_halted_writer_is_told_to_every_caller() {
    let mut chain = crate::methods::tests::facts(true, 0);
    chain.tip.as_mut().expect("a tip").halt = Some((shekyl_types::BlockHeight::from_raw(5), 3));
    let reply = daemon_status(
        &synced_facts(),
        &chain,
        Disclosure::VIEW,
        0,
        tor_read(Disclosure::VIEW),
    )
    .expect("answered");
    assert_eq!(
        serde_json::to_value(reply).unwrap()["writer"],
        serde_json::json!({"halted": {"height": 5, "invariant": 3}})
    );
}

/// **A daemon started offline reports the state, never a zero** (Rick,
/// 2026-10-14): `offline`, `peered: null`, Status's counts `null`, the
/// connector map empty, and the board is not read.
#[test]
fn an_offline_node_reports_the_state() {
    let mut facts = synced_facts();
    facts.chain.offline = true;
    facts.peers = PeerFacts::Offline;
    facts.sessions_fault = Some(FactsFault::Internal);
    let wire = ours(&facts, Disclosure::FULL);
    assert_eq!(wire["offline"], true);
    assert!(wire["peered"].is_null());
    assert!(wire["peer_outbound_count"].is_null());
    assert!(wire["peer_inbound_count"].is_null());
    assert_eq!(wire["connector"], serde_json::json!({}));
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 0);
}

/// The P2P state and the core's `offline` flag are one configuration read
/// twice. A reply where they disagree is refused, in both directions.
#[test]
fn a_p2p_state_that_disagrees_with_offline_refuses() {
    let mut off_but_online = synced_facts();
    off_but_online.peers = PeerFacts::Offline;
    assert!(matches!(
        status(&off_but_online, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    ));
    let mut running_but_offline = synced_facts();
    running_but_offline.chain.offline = true;
    assert!(matches!(
        status(&running_but_offline, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    ));
}

/// An online daemon whose peer facts cannot be read is a fault, not a
/// Peers part of zeros.
#[test]
fn an_online_daemon_whose_peer_facts_fail_refuses() {
    let mut facts = synced_facts();
    facts.peers_fault = Some(FactsFault::Internal);
    assert!(matches!(
        status(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Internal))
    ));
}

// ── RK-Q9: a store that contradicts itself ───────────────────────────────

/// **More burned than generated refuses `daemon_status` for every caller,
/// and the refusal says what contradicted what** (RK-Q9).
#[test]
fn more_burned_than_generated_refuses_with_the_invariant_and_its_operands() {
    let mut facts = synced_facts();
    let generated = facts.chain.already_generated_coins;
    let burned = AtomicUnits::from_raw(generated.to_raw() + 1);
    facts.chain.total_burned = burned;
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        assert_eq!(
            status(&facts, disclosure, 0).expect_err("a contradiction is not answered"),
            RpcFault::Store(StoreFault::SupplyInvariant {
                coins_generated: generated,
                total_burned: burned,
                chain_height: ChainCount::from_raw(1_234_567),
            }),
            "{disclosure:?}"
        );
    }
    let text = StoreFault::SupplyInvariant {
        coins_generated: generated,
        total_burned: burned,
        chain_height: ChainCount::from_raw(1_234_567),
    }
    .to_string();
    assert!(text.contains("total_burned <= coins_generated"), "{text}");
    assert!(text.contains("1444065674085134"), "{text}");
    assert!(text.contains("1444065674085133"), "{text}");
}

/// Burned equal to generated is answered; one unit more is refused.
#[test]
fn everything_burned_is_answered_and_one_unit_more_is_not() {
    let mut facts = synced_facts();
    facts.chain.total_burned = facts.chain.already_generated_coins;
    let reply = status(&facts, Disclosure::FULL, 0).expect("equal is not a contradiction");
    assert_eq!(reply.burn_total, reply.emission);
    facts.chain.total_burned =
        AtomicUnits::from_raw(facts.chain.already_generated_coins.to_raw() + 1);
    assert!(matches!(
        status(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Store(StoreFault::SupplyInvariant { .. }))
    ));
}

/// A burn of zero is an answer, written as the number `0`, never `null`.
#[test]
fn a_burn_of_zero_is_a_number_on_the_wire() {
    let mut facts = synced_facts();
    facts.chain.total_burned = AtomicUnits::from_raw(0);
    facts.chain.tx_volume = TxVolume::ZERO;
    assert!(ours(&facts, Disclosure::FULL)["burn"].is_u64());
}

// ── RK-D24: gathering by part ──────────────────────────────────────────

/// A view caller is not shown Status or Peers, so neither is read on its
/// behalf, and its pool count is asked over the public set only.
#[test]
fn a_view_caller_costs_no_status_or_peers_read() {
    let facts = synced_facts();
    status(&facts, Disclosure::VIEW, 5).expect("a view caller is answered");
    assert_eq!(facts.status_reads.load(Ordering::Relaxed), 0);
    assert_eq!(facts.peers_reads.load(Ordering::Relaxed), 0);
    assert_eq!(facts.store_size_reads.load(Ordering::Relaxed), 0);
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        *facts.pool_scopes.lock().expect("scopes"),
        vec![PoolScope::Broadcast]
    );
}

/// The host is shown everything, and each part is read once.
#[test]
fn a_full_caller_reads_each_part_once() {
    let facts = synced_facts();
    status(&facts, Disclosure::FULL, 5).expect("a full caller is answered");
    assert_eq!(facts.status_reads.load(Ordering::Relaxed), 1);
    assert_eq!(facts.peers_reads.load(Ordering::Relaxed), 1);
    assert_eq!(facts.store_size_reads.load(Ordering::Relaxed), 1);
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        *facts.pool_scopes.lock().expect("scopes"),
        vec![PoolScope::WithUnbroadcast]
    );
}

/// What breaks one part of the facts.
type Breaks = fn(&mut FakeInfoFacts);

/// With the Status facts, the Peers facts, or the store's size failing, a
/// view caller gets the reply it gets when they succeed, and a full caller
/// gets the refusal (RK-D24).
#[test]
fn a_failing_part_refuses_a_full_caller_and_not_a_view_caller() {
    let healthy = ours(&synced_facts(), Disclosure::VIEW);
    let cases: [(Breaks, FactsFault); 3] = [
        (
            |f| f.status_fault = Some(FactsFault::Internal),
            FactsFault::Internal,
        ),
        (
            |f| f.peers_fault = Some(FactsFault::Internal),
            FactsFault::Internal,
        ),
        (
            |f| f.store_size_fault = Some(FactsFault::StoreUnreadable),
            FactsFault::StoreUnreadable,
        ),
    ];
    for (arm, fault) in cases {
        let mut facts = synced_facts();
        arm(&mut facts);
        assert_eq!(ours(&facts, Disclosure::VIEW), healthy);
        assert_eq!(
            status(&facts, Disclosure::FULL, 0),
            Err(RpcFault::Facts(fault))
        );
    }
}

/// A fault in a read every caller needs refuses every caller.
#[test]
fn a_failing_chain_or_pool_read_refuses_every_caller() {
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        let mut facts = synced_facts();
        facts.chain_fault = Some(FactsFault::NotReady);
        assert_eq!(
            status(&facts, disclosure, 0),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );
        let mut facts = synced_facts();
        facts.pool_fault = Some(FactsFault::Internal);
        assert_eq!(
            status(&facts, disclosure, 0),
            Err(RpcFault::Facts(FactsFault::Internal))
        );
    }
}

// ── the parts on the wire (RK-D23) ─────────────────────────────────────

/// The transport's connection count is a Status member: shown to a full
/// caller as given, absent for a view caller.
#[test]
fn the_rpc_connection_count_is_shown_with_status_only() {
    let facts = synced_facts();
    let full = status(&facts, Disclosure::FULL, 17).unwrap();
    assert_eq!(full.rpc_connections, Withheld::Shown(Count(17)));
    let view = status(&facts, Disclosure::VIEW, 17).unwrap();
    assert!(view.rpc_connections.is_withheld());
}

/// `degraded` is the store's flag, for every caller (C2-R1b F-1(a)).
#[test]
fn degraded_is_the_stores_flag_for_every_caller() {
    for degraded in [false, true] {
        let mut facts = synced_facts();
        facts.chain.following_degraded = degraded;
        for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
            assert_eq!(status(&facts, disclosure, 0).unwrap().degraded, degraded);
        }
    }
}

/// `block_spacing` is the store's difficulty target as a duration (RK-D9).
#[test]
fn block_spacing_is_the_difficulty_target() {
    let mut facts = synced_facts();
    facts.chain.difficulty_target = 77;
    assert_eq!(
        status(&facts, Disclosure::FULL, 0).unwrap().block_spacing,
        shekyl_rpc_types::kinds::Withheld::Shown(Duration(77))
    );
}

/// The connection's grants are the reply's `grant` list: what the caller
/// may ask for, so a client reads its own posture rather than a flag.
#[test]
fn the_grant_list_is_the_callers_grants() {
    use crate::authority::Authority;
    let facts = synced_facts();
    let view = status(&facts, Authority::VIEW_LISTENER.disclosure(), 0).unwrap();
    assert!(view.grant.contains(&GrantName::Health));
    assert!(view.grant.contains(&GrantName::Submit));
    assert!(!view.grant.contains(&GrantName::Status));
    let full = status(&facts, Authority::admin_listener(false).disclosure(), 0).unwrap();
    assert!(full.grant.contains(&GrantName::Node));
    assert_eq!(
        Authority::admin_listener(false).disclosure(),
        Disclosure::FULL
    );
    let view = Authority::VIEW_LISTENER.disclosure();
    assert!(!view.status() && !view.peers() && !view.config() && !view.host());
}

/// **A view reply withholds Status, Peers and the host-only part: the keys
/// are absent, and nothing stands in for them** (RK-Q8, RK-D23). It decodes
/// as this build's type, and everything else in it is what the host is
/// told. The edit that turns this red is a part written with stand-ins.
#[test]
fn a_view_reply_withholds_status_peers_and_the_host_part() {
    let facts = synced_facts();
    let view = status(&facts, Disclosure::VIEW, 17).expect("a view caller is answered");
    let wire = serde_json::to_value(&view).expect("the reply serializes");
    let members = wire.as_object().expect("a reply is an object");
    for key in STATUS_KEYS
        .iter()
        .chain(&["connector", "txpool_private_count"])
    {
        assert!(!members.contains_key(*key), "`{key}` is not disclosed");
    }
    assert_eq!(
        serde_json::from_value::<DaemonStatus>(wire.clone()).expect("it decodes"),
        view
    );

    let mut full = serde_json::to_value(status(&facts, Disclosure::FULL, 17).unwrap()).unwrap();
    let full_members = full.as_object_mut().expect("an object");
    for key in STATUS_KEYS
        .iter()
        .chain(&["connector", "txpool_private_count"])
    {
        assert!(
            full_members.remove(*key).is_some(),
            "a full reply carries `{key}`"
        );
    }
    let mut view_rest = wire;
    for reply in [&mut full, &mut view_rest] {
        reply.as_object_mut().expect("an object").remove("grant");
    }
    assert_eq!(view_rest, full);
}

// ── RK-Q10: the pool's two counts ────────────────────────────────────────

/// **`txpool_count` is the public entries, for every caller** (RK-Q10), and
/// does not move with the entries not yet public.
#[test]
fn txpool_count_is_the_public_count_for_every_caller() {
    let facts = synced_facts();
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        assert_eq!(
            status(&facts, disclosure, 0).unwrap().txpool_count,
            shekyl_rpc_types::kinds::Withheld::Shown(Nullable(Some(Count(9)))),
            "{disclosure:?}"
        );
    }
    let mut facts = synced_facts();
    facts.pool_unbroadcast = 1_000;
    assert_eq!(
        status(&facts, Disclosure::FULL, 0).unwrap().txpool_count,
        shekyl_rpc_types::kinds::Withheld::Shown(Nullable(Some(Count(9))))
    );
}

/// **The count not yet public is the host's alone**: shown to the host,
/// absent for anyone else and not counted for them.
#[test]
fn the_private_count_is_told_to_the_host_and_not_counted_for_anyone_else() {
    let facts = synced_facts();
    let full = status(&facts, Disclosure::FULL, 0).expect("the host is answered");
    assert_eq!(
        full.txpool_private_count,
        Withheld::Shown(Nullable(Some(Count(3))))
    );
    let facts = synced_facts();
    let view = status(&facts, Disclosure::VIEW, 0).expect("a view caller is answered");
    assert!(view.txpool_private_count.is_withheld());
    assert_eq!(
        *facts.pool_scopes.lock().expect("scopes"),
        vec![PoolScope::Broadcast]
    );
}

/// A host with nothing private is told `0`, a count, not the absent key.
#[test]
fn a_host_with_nothing_private_is_told_zero_not_nothing() {
    let mut facts = synced_facts();
    facts.pool_unbroadcast = 0;
    assert_eq!(ours(&facts, Disclosure::FULL)["txpool_private_count"], 0);
}

/// A facts layer asked on the host axis that returns no second count is a
/// fault, not `0`.
#[test]
fn a_host_read_that_returns_no_private_count_is_a_fault() {
    let mut facts = synced_facts();
    facts.pool_drops_unbroadcast = true;
    assert_eq!(
        status(&facts, Disclosure::FULL, 0),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    );
}

/// **A retired pool does not black out the reply** (IG-Q74): the counts
/// `null` (no answer), `txpool_retired` in Status, and the chain's members
/// as a live pool's reply carries them; a view caller is withheld the host
/// part as ever.
#[test]
fn a_retired_pool_answers_null_counts_and_the_chain() {
    let live = ours(&synced_facts(), Disclosure::FULL);
    let mut facts = synced_facts();
    facts.pool_retired = true;
    let full = ours(&facts, Disclosure::FULL);
    assert!(full["txpool_count"].is_null(), "{full}");
    assert!(full["txpool_private_count"].is_null(), "{full}");
    assert_eq!(full["txpool_retired"], true);
    for key in ["height", "hash", "emission", "burn", "started"] {
        assert_eq!(full[key], live[key], "{key}");
    }
    let mut facts = synced_facts();
    facts.pool_retired = true;
    let view = ours(&facts, Disclosure::VIEW);
    assert!(view["txpool_count"].is_null());
    assert!(!view
        .as_object()
        .unwrap()
        .contains_key("txpool_private_count"));
}

#[path = "peer_facts_tests.rs"]
mod peers;

/// **`health` carries liveness only** (`RPC_CHANNEL.md` §6.1, Rick
/// 2026-11-12). A connection whose grant set holds `health` and nothing
/// else is told whether the node is usable now and the grants it holds:
/// no chain fact, no pool count, no part of this node. `chain` adds the
/// chain's part and `pool` the relayed count, each alone. The grant sets
/// are built from the type, not from a preset, so the test holds before
/// any custom ceiling exists. Red edit: put a chain field back in the
/// base fields.
#[test]
fn a_health_only_caller_is_told_liveness_and_nothing_more() {
    use shekyl_rpc_types::method::{Grant, GrantSet};
    let facts = synced_facts();
    let keys = |grants: &[Grant]| {
        let reply = status(&facts, Disclosure::of(GrantSet::of(grants), false), 0)
            .unwrap_or_else(|_| panic!("daemon_status answers {grants:?}"));
        let value = serde_json::to_value(reply).expect("a reply serializes");
        let mut keys: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    let liveness = [
        "degraded",
        "grant",
        "hash",
        "height",
        "hiding",
        "offline",
        "peered",
        "protocol_version",
        "synchronized",
        "syncing",
        "target_height",
        "writer",
    ];
    assert_eq!(keys(&[Grant::Health]), liveness, "health alone");
    let chain = [
        "block_spacing",
        "block_weight_max",
        "block_weight_median",
        "burn",
        "burn_total",
        "difficulty",
        "difficulty_cumulative",
        "emission",
        "emission_multiplier",
        "stake_share",
        "time_adjusted",
        "tx_count",
    ];
    let mut with_chain: Vec<&str> = liveness.iter().chain(&chain).copied().collect();
    with_chain.sort_unstable();
    assert_eq!(
        keys(&[Grant::Health, Grant::Chain]),
        with_chain,
        "chain adds its part"
    );
    let mut with_pool: Vec<&str> = liveness.to_vec();
    with_pool.push("txpool_count");
    with_pool.sort_unstable();
    assert_eq!(
        keys(&[Grant::Health, Grant::Pool]),
        with_pool,
        "pool adds its count"
    );
}
