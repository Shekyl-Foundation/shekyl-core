// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_info`, served natively (`docs/design/DAEMON_RPC_KV_GET_INFO.md`).
//!
//! Like [`crate::methods`], this is the method with no Axum, no FFI and no
//! JSON in it: facts in, a typed reply out.
//!
//! # Gathering by part
//!
//! The handler asks [`Disclosure`] which parts the caller is shown and reads
//! only those (RK-D24). Health, identity, chain, economics and the pool's
//! broadcast count are read for every caller. Status and Peers are read
//! only for a caller who is shown them, so a failure in one of those reads
//! — the volume that cannot be queried for its free space, say — cannot
//! refuse a caller who was never going to be told it.
//!
//! # Parity
//!
//! The method first answered exactly what the C++ handler it replaced
//! answered, and five oracle vectors captured from that handler's own
//! computation held it to that. Each later commit moves one thing off
//! parity, with a vector derived from its predecessor: the `target_height`
//! sentinel went first (RK-D15, 3.46). It still writes what the design
//! retires after that, each marked where it is written: the restricted
//! stand-ins, the clearnet-only connection counts and their subtraction, a
//! refused burn computation reported as zero, and a pool count whose
//! meaning depends on the caller.
//!
//! **One read is made for every caller that the rule above would withhold.**
//! A restricted reply carries `database_size` rounded up to 5 GiB — a
//! stand-in, but one derived from the real size. The caller receives it, so
//! it is read for that caller. It joins the not-read set when a restricted
//! reply stops carrying Status (RK-Q8).

use shekyl_economics::{project_at_tip, EconomicParams, TipOperands};
use shekyl_rpc_types::{
    GetInfoResponse, HashHex, Hidden, InfoChain, InfoEconomics, InfoHealth, InfoIdentity,
    InfoPeers, InfoPool, InfoStatus, RpcStatus,
};

use crate::info_facts::{InfoFacts, PoolScope};
use crate::methods::RpcFault;

/// What a caller is shown: which parts its grants select, and whether it is
/// the host's administrator.
///
/// Two axes, and the second is not a grant. Host-only data — on this reply,
/// the pool entries this node has not broadcast — is served to the host's
/// administrator and to no grant, `admin` included (`RPC_CHANNEL.md` §6.1,
/// RT-O9.3). Naming the axis here is what stops the channel's daemon slice
/// from reading "`admin`" as "may see unrelayed entries".
///
/// Today both axes are mapped from the one listener flag
/// ([`Self::from_listener`]). The RPC channel (RT-W10) maps a connection's
/// grant set and its host flag onto the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disclosure {
    /// The caller is shown the Status part.
    status: bool,
    /// The caller is shown the Peers part.
    peers: bool,
    /// The caller is the host's administrator.
    host: bool,
    /// The listener's posture, reported back as `restricted`. Transitional:
    /// it leaves with that field when the channel's handshake returns the
    /// grant instead.
    listener_restricted: bool,
}

impl Disclosure {
    /// The unrestricted listener: every part, and host. That listener binds
    /// loopback only, which is what stands in for a host identity until the
    /// channel exists.
    pub const FULL: Self = Self {
        status: true,
        peers: true,
        host: true,
        listener_restricted: false,
    };

    /// The restricted listener: the `view` parts, and not host.
    pub const VIEW: Self = Self {
        status: false,
        peers: false,
        host: false,
        listener_restricted: true,
    };

    /// The disclosure a listener's posture gives its callers.
    #[must_use]
    pub const fn from_listener(restricted: bool) -> Self {
        if restricted {
            Self::VIEW
        } else {
            Self::FULL
        }
    }
}

/// The quantum a restricted reply rounds the store's size up to.
const RESTRICTED_DATABASE_SIZE_QUANTUM: u64 = 5 * 1024 * 1024 * 1024;

/// `get_info` (REST `/get_info`, `/getinfo`; JSON-RPC `get_info`).
///
/// `rpc_connections` is this server's live connection count, which the
/// transport owns; it is a Status field and is ignored for a caller who is
/// not shown Status.
///
/// # Errors
///
/// [`RpcFault::Facts`] when a read made on this caller's behalf fails. A
/// read that is not made cannot.
pub fn get_info(
    facts: &dyn InfoFacts,
    disclosure: Disclosure,
    rpc_connections: u64,
) -> Result<GetInfoResponse, RpcFault> {
    let chain = facts.chain()?;
    let pool_count = facts.pool_count(if disclosure.host {
        PoolScope::All
    } else {
        PoolScope::Broadcast
    })?;
    // Read for every caller while a restricted reply carries it rounded:
    // see the module docs.
    let store_size = facts.store_size()?;

    let node = if disclosure.status {
        let status = facts.status()?;
        InfoStatus {
            start_time: status.start_time,
            free_space: status.free_space,
            database_size: store_size,
            version: status.version,
            outgoing_connections_count: status.public_outgoing_connections,
            // Parity: the clearnet total and its outbound count are two
            // reads of two stores with no common lock, subtracted unsigned,
            // as the C++ handler did. RK-Q3 replaces both with per-direction
            // counts from the one store.
            incoming_connections_count: status
                .public_connections
                .wrapping_sub(status.public_outgoing_connections),
            alt_blocks_count: status.alt_blocks_count,
            rpc_connections_count: rpc_connections,
        }
    } else {
        // Parity: the restricted stand-ins. A value that means "not this
        // value" in every member; RK-Q8 makes the part absent instead.
        InfoStatus {
            start_time: 0,
            free_space: u64::MAX,
            database_size: store_size
                .div_ceil(RESTRICTED_DATABASE_SIZE_QUANTUM)
                .saturating_mul(RESTRICTED_DATABASE_SIZE_QUANTUM),
            version: String::new(),
            outgoing_connections_count: 0,
            incoming_connections_count: 0,
            alt_blocks_count: 0,
            rpc_connections_count: 0,
        }
    };

    let peers = if disclosure.peers {
        let peers = facts.peers()?;
        InfoPeers {
            public_incoming_socket_count: peers.public_incoming_sockets,
            public_outgoing_socket_count: peers.public_outgoing_sockets,
            tor_incoming_socket_count: peers.tor_incoming_sockets,
            tor_outgoing_socket_count: peers.tor_outgoing_sockets,
            white_peerlist_size: peers.white_peerlist_size,
            grey_peerlist_size: peers.grey_peerlist_size,
        }
    } else {
        // Parity: stand-ins, as for Status.
        InfoPeers {
            public_incoming_socket_count: 0,
            public_outgoing_socket_count: 0,
            tor_incoming_socket_count: 0,
            tor_outgoing_socket_count: 0,
            white_peerlist_size: 0,
            grey_peerlist_size: 0,
        }
    };

    let height = chain.chain_height.to_raw();
    let tip = project_at_tip(
        &TipOperands {
            coins_generated: chain.already_generated_coins,
            total_burned: chain.total_burned,
            tx_volume: chain.tx_volume,
            chain_height: height,
        },
        &EconomicParams::default(),
    );
    // Parity: a refused burn computation is reported as zero, and logged.
    // `0` % is a legitimate burn, so RK-Q9 turns this into a store fault.
    let burn_pct = tip.burn_pct.unwrap_or_else(|violation| {
        tracing::error!(
            %violation,
            "get_info: the burn computation refused; reporting burn_pct 0"
        );
        0
    });

    Ok(GetInfoResponse {
        status: RpcStatus::ok(),
        health: InfoHealth {
            height,
            top_block_hash: HashHex::from_bytes(*chain.top_hash.as_bytes()),
            // The core's target as the core reports it, synchronized or
            // not, and `null` when it has none (RK-D15).
            target_height: chain
                .core_target_height
                .map(shekyl_types::ChainCount::to_raw)
                .into(),
            synchronized: chain.synchronized,
            busy_syncing: chain.busy_syncing,
            offline: chain.offline,
            following_degraded: chain.following_degraded,
        },
        identity: InfoIdentity {
            nettype: chain.nettype,
            protocol_version: chain.protocol_version,
        },
        chain: InfoChain {
            difficulty: chain.difficulty,
            cumulative_difficulty: chain.cumulative_difficulty,
            target: chain.difficulty_target,
            // Coinbases excluded: one per block. Unsigned, as the C++
            // handler computed it.
            tx_count: chain.total_transactions.wrapping_sub(height),
            block_weight_limit: chain.block_weight_limit,
            block_weight_median: chain.block_weight_median,
            adjusted_time: chain.adjusted_time,
        },
        economics: InfoEconomics {
            already_generated_coins: tip.coins_generated.to_raw(),
            release_multiplier: tip.release_multiplier,
            burn_pct,
            total_burned: tip.total_burned.to_raw(),
            staker_emission_share_effective: tip.staker_emission_share,
        },
        // Parity: one key, two quantities — the broadcast set for a caller
        // who is not host, every entry for one who is. RK-Q10 splits it.
        pool: InfoPool {
            tx_pool_size: pool_count,
        },
        node: Hidden::Shown(node),
        peers: Hidden::Shown(peers),
        restricted: disclosure.listener_restricted,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use shekyl_economics::TxVolume;
    use shekyl_rpc_types::DaemonNetwork;
    use shekyl_types::{BlockHash, ChainCount};
    use shekyl_units::AtomicUnits;

    use super::*;
    use crate::chain_facts::FactsFault;
    use crate::info_facts::{InfoChainFacts, InfoPeersFacts, InfoStatusFacts};

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
        pub(crate) pool_all: u64,
        pub(crate) pool_broadcast: u64,
        pub(crate) store_size: u64,
        pub(crate) status: InfoStatusFacts,
        pub(crate) peers: InfoPeersFacts,
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
                nettype: DaemonNetwork::Mainnet,
                protocol_version: 3,
            },
            pool_all: 12,
            pool_broadcast: 9,
            store_size: 7 * 1024 * 1024 * 1024 + 1,
            status: InfoStatusFacts {
                start_time: 1_699_990_000,
                free_space: 123_456_789_012,
                alt_blocks_count: 3,
                public_connections: 20,
                public_outgoing_connections: 8,
                version: "3.1.0-oracle".to_owned(),
            },
            peers: InfoPeersFacts {
                public_incoming_sockets: 13,
                public_outgoing_sockets: 10,
                tor_incoming_sockets: 4,
                tor_outgoing_sockets: 2,
                white_peerlist_size: 500,
                grey_peerlist_size: 2500,
            },
            chain_fault: None,
            pool_fault: None,
            store_size_fault: None,
            status_fault: None,
            peers_fault: None,
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

        fn pool_count(&self, scope: PoolScope) -> Result<u64, FactsFault> {
            self.pool_scopes.lock().expect("scopes").push(scope);
            if let Some(fault) = self.pool_fault {
                return Err(fault);
            }
            Ok(match scope {
                PoolScope::All => self.pool_all,
                PoolScope::Broadcast => self.pool_broadcast,
            })
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

        fn peers(&self) -> Result<InfoPeersFacts, FactsFault> {
            self.peers_reads.fetch_add(1, Ordering::Relaxed);
            self.peers_fault.map_or(Ok(self.peers), Err)
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

    #[test]
    fn synced_reproduces_the_oracle_vector() {
        assert_eq!(
            ours(&synced_facts(), Disclosure::FULL),
            oracle(include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_info_synced_v2.json"
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
                "../../shekyl-rpc-types/tests/vectors/rpc/get_info_syncing_v1.json"
            ))
        );
    }

    #[test]
    fn peerless_startup_reproduces_the_oracle_vector() {
        let mut facts = synced_facts();
        facts.chain.nettype = DaemonNetwork::Fakechain;
        facts.chain.synchronized = false;
        facts.chain.core_target_height = None;
        facts.status.public_connections = 0;
        facts.status.public_outgoing_connections = 0;
        facts.peers.public_incoming_sockets = 0;
        facts.peers.public_outgoing_sockets = 0;
        facts.peers.tor_incoming_sockets = 0;
        facts.peers.tor_outgoing_sockets = 0;
        assert_eq!(
            ours(&facts, Disclosure::FULL),
            oracle(include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_info_peerless_startup_v2.json"
            ))
        );
    }

    /// The same facts as the synced case, asked by a restricted caller:
    /// every stand-in, the pool counted over the broadcast set, and the
    /// store's size rounded up.
    #[test]
    fn synced_restricted_reproduces_the_oracle_vector() {
        assert_eq!(
            ours(&synced_facts(), Disclosure::VIEW),
            oracle(include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_info_synced_restricted_v2.json"
            ))
        );
    }

    #[test]
    fn burn_refusal_reproduces_the_oracle_vector() {
        let mut facts = synced_facts();
        facts.chain.total_burned =
            AtomicUnits::from_raw(facts.chain.already_generated_coins.to_raw() + 1);
        assert_eq!(
            ours(&facts, Disclosure::FULL),
            oracle(include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_info_burn_refusal_v2.json"
            ))
        );
    }

    // ── RK-D24: gathering by part ──────────────────────────────────────────

    /// A restricted caller is not shown Status or Peers, so neither is read
    /// on its behalf, and its pool count is asked for over the broadcast
    /// set only. The store's size is the one read it shares, because its
    /// reply still carries that, rounded.
    #[test]
    fn a_view_caller_costs_no_status_or_peers_read() {
        let facts = synced_facts();
        get_info(&facts, Disclosure::VIEW, 5).expect("a view caller is answered");
        assert_eq!(facts.status_reads.load(Ordering::Relaxed), 0);
        assert_eq!(facts.peers_reads.load(Ordering::Relaxed), 0);
        assert_eq!(facts.store_size_reads.load(Ordering::Relaxed), 1);
        assert_eq!(
            *facts.pool_scopes.lock().expect("scopes"),
            vec![PoolScope::Broadcast],
            "the unrelayed count is host-only and is not read without the host axis"
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
        assert_eq!(
            *facts.pool_scopes.lock().expect("scopes"),
            vec![PoolScope::All]
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

    /// The exception, pinned. While a restricted reply carries the store's
    /// size rounded, the size is read for every caller, so a store that
    /// cannot be read for its size refuses both. RK-Q8's commit flips the
    /// view half of this: a view reply with a failing size read is whole.
    #[test]
    fn an_unreadable_store_size_refuses_both_callers_while_parity_lasts() {
        let mut facts = synced_facts();
        facts.store_size_fault = Some(FactsFault::StoreUnreadable);
        for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
            assert_eq!(
                get_info(&facts, disclosure, 0),
                Err(RpcFault::Facts(FactsFault::StoreUnreadable)),
                "{disclosure:?}"
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
        assert_eq!(view.node.shown().map(|n| n.rpc_connections_count), Some(0));
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
            1_444_065_674_085_133
        );
        assert_eq!(reply.economics.total_burned, 4_200_000_000);
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

    /// The restricted size is rounded **up** to the quantum: a store exactly
    /// on a boundary stays there, one byte over goes to the next, and an
    /// empty store is zero.
    #[test]
    fn the_restricted_size_rounds_up_to_five_gibibytes() {
        const Q: u64 = RESTRICTED_DATABASE_SIZE_QUANTUM;
        for (size, shown) in [(0, 0), (1, Q), (Q, Q), (Q + 1, 2 * Q), (3 * Q - 1, 3 * Q)] {
            let mut facts = synced_facts();
            facts.store_size = size;
            let reply = get_info(&facts, Disclosure::VIEW, 0).unwrap();
            assert_eq!(
                reply.node.shown().map(|n| n.database_size),
                Some(shown),
                "a store of {size} bytes"
            );
        }
    }
}
