// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's wire at `CORE_RPC_VERSION` 4.0: every method, its request
//! and its reply, under `INPUT_GRAMMAR.md` Part C's names as Part F and
//! IG-Q94 amend them (`RPC_WIRE.md` RW-Q7, RW-Q8).
//!
//! [`TABLE`] is the method table. Each row's name is written once, in the
//! list below; a client names a method by its type, and dispatch matches
//! [`Id`]. The schema the grammar's walk gate reads is
//! [`crate::schema::render`] of [`TABLE`].
//!
//! Grants are `RPC_CHANNEL.md` §6.1's.

pub mod archival;
pub mod block;
pub mod chain;
pub mod daemon;
pub mod node;
pub mod p2p;
pub mod shared;
pub mod tx;

use crate::kinds::{Done, NoParams};
use crate::method::Policy;
use crate::nullable::Nullable;
use shared::{OrArchived, Slot};
use shekyl_rpc_grants::Grant::{
    Bans, Chain, Health, MiningControl, MiningWork, Node, Peers, Pool, Status, Submit,
};

const fn g(grant: shekyl_rpc_grants::Grant) -> Policy {
    Policy::Grant(grant)
}

crate::rpc_methods! {
    id Id; table TABLE;
    /// The version read (RW-Q6), under no grant.
    Version = "version": NoParams => chain::Version, Policy::Authenticated;
    /// The tip.
    ChainHeight = "chain_height": NoParams => chain::ChainHeight, g(Chain);
    /// One header, by a selector.
    BlockHeaderShow = "block_header_show": block::HeaderSelect => block::BlockHeader, g(Chain);
    /// Headers over a range, or by hash.
    BlockHeaderList = "block_header_list": block::HeaderRange => Vec<Slot<block::BlockHeader>>, g(Chain);
    /// One block, by a selector.
    BlockShow = "block_show": block::BlockShowSelect => block::Block, g(Chain);
    /// Blocks by height (RW-Q5).
    BlockList = "block_list": block::BlockListQuery => block::BlockList, g(Chain);
    /// One transaction.
    TxShow = "tx_show": tx::TxQuery => OrArchived<tx::TxEntry>, g(Chain);
    /// Transactions by id.
    TxList = "tx_list": tx::TxListQuery => tx::TxList, g(Chain);
    /// Whether key images are spent.
    ChainSpent = "chain_spent": chain::SpentQuery => Vec<chain::Spent>, g(Chain);
    /// The fee tiers.
    Fee = "fee": NoParams => chain::Fee, g(Chain);
    /// The coinbase sum over a range.
    ChainCoinbaseSum = "chain_coinbase_sum": chain::CoinbaseSumRange => chain::CoinbaseSum, g(Chain);
    /// The alternative chains.
    ChainAlt = "chain_alt": NoParams => Vec<chain::AltChain>, g(Status);
    /// The curve tree at a height.
    CurveShow = "curve_show": chain::CurveSelect => chain::Curve, g(Chain);
    /// A persona's emission claim source.
    ArchivalClaimShow = "archival_claim_show": archival::PersonaQuery => archival::ClaimSource, g(Chain);
    /// Holders per shard.
    ShardCoverage = "shard_coverage": NoParams => archival::Coverage, g(Chain);
    /// A closed shard's view. `node` until IG-Q90's permit; then `chain`.
    ShardFetch = "shard_fetch": archival::ShardId => archival::ShardView, g(Chain);
    /// The daemon's state, each part by its grant.
    DaemonStatus = "daemon_status": NoParams => daemon::DaemonStatus, g(Health);
    /// Chain sync's view.
    SyncStatus = "sync_status": NoParams => p2p::SyncStatus, g(Peers);
    /// The live connections.
    PeerConnections = "peer_connections": NoParams => Vec<p2p::Connection>, g(Peers);
    /// The peer lists.
    PeerList = "peer_list": p2p::PeerListQuery => Vec<p2p::PeerEntry>, g(Peers);
    /// P2P statistics.
    P2pStats = "p2p_stats": NoParams => p2p::P2pStats, g(Status);
    /// Set runtime options (IG-12).
    OptionSet = "option_set": node::OptionSet => Vec<node::OptionRow>, g(Node);
    /// Show options, each row under its own grant (RT-O24).
    OptionShow = "option_show": node::OptionShow => Vec<node::OptionRow>, g(Health);
    /// Stop the daemon.
    DaemonStop = "daemon_stop": NoParams => Done, g(Node);
    /// The pool's entries.
    TxpoolList = "txpool_list": NoParams => Vec<tx::PoolEntry>, g(Pool);
    /// The pool's statistics.
    TxpoolStats = "txpool_stats": NoParams => tx::TxpoolStats, g(Pool);
    /// Remove pool entries.
    TxpoolFlush = "txpool_flush": tx::FlushIds => tx::Acted, g(Node);
    /// Offer the node's own entries to the relay again.
    TxRelay = "tx_relay": tx::RelayIds => tx::Acted, g(Node);
    /// Submit a transaction.
    TxSubmit = "tx_submit": tx::TxBody => tx::Verdict, g(Submit);
    /// The posted job.
    BlockTemplate = "block_template": NoParams => block::BlockTemplate, g(MiningWork);
    /// Submit a block.
    BlockSubmit = "block_submit": block::BlockBody => block::BlockId, g(MiningWork);
    /// A block's proof-of-work hash.
    Pow = "pow": block::PowInput => block::Pow, g(MiningWork);
    /// Start the miner.
    MineStart = "mine_start": node::MineStart => Done, g(MiningControl);
    /// Stop the miner.
    MineStop = "mine_stop": NoParams => Done, g(MiningControl);
    /// The miner's status.
    MineStatus = "mine_status": NoParams => node::MineStatus, g(MiningControl);
    /// Ban a host.
    BanAdd = "ban_add": node::BanAdd => Done, g(Bans);
    /// Unban a host.
    BanRemove = "ban_remove": node::BanHost => Done, g(Bans);
    /// Every ban.
    BanList = "ban_list": NoParams => Vec<node::Ban>, g(Bans);
    /// One host's ban; `null` when it is not banned (§18).
    BanShow = "ban_show": node::BanHost => Nullable<node::Ban>, g(Bans);
    /// The relay's floor and stem tallies (host-only, RT-O9.3).
    RelayStats = "relay_stats": NoParams => p2p::RelayStats, Policy::HostOnly;
    /// Mine blocks (an armed lever, RT-O9.2).
    DevBlockGenerate = "dev_block_generate": block::GenerateCount => block::Generated, Policy::Armed;
    /// Pop blocks (an armed lever, RT-O9.2).
    DevChainPop = "dev_chain_pop": block::PopCount => block::Popped, Policy::Armed;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{kind_faults, names, NameKind};

    /// Part C's 42 methods, and no other (§17 as Part F and IG-Q94 amend
    /// it).
    #[test]
    fn the_table_is_the_42_methods() {
        assert_eq!(TABLE.len(), 42);
        assert_eq!(Id::ALL.len(), 42);
    }

    /// Every name in the table holds the kind its last term requires, and
    /// no reply carries an optional field.
    #[test]
    fn every_name_holds_its_kind() {
        let faults = kind_faults(TABLE);
        assert!(faults.is_empty(), "{faults:#?}");
    }

    /// Every method has at least its name in the schema, and the walk
    /// reaches its fields.
    #[test]
    fn the_schema_reaches_every_method() {
        let walked = names(TABLE);
        for row in TABLE {
            assert!(walked
                .iter()
                .any(|name| name.kind == NameKind::Method && name.name == row.name));
        }
        assert!(walked.len() > 300, "{} names", walked.len());
    }

    use crate::schema::{conforms, render, Schema};
    use std::path::PathBuf;

    const SCHEMA_FILE: &str = "rpc_wire_schema.tsv";

    fn generated(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/generated")
            .join(name)
    }

    /// The committed schema is the table's rendering. The grammar's walk
    /// gate reads that file (`scripts/ci/check_input_grammar_walk.py`), so
    /// a type renamed without regenerating it fails here. Red edit: rename
    /// a field of any wire type and run this without regenerating.
    #[test]
    fn the_committed_schema_is_the_tables() {
        let path = generated(SCHEMA_FILE);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is committed: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(
            committed,
            render(TABLE),
            "{} differs from the table's rendering; regenerate it",
            path.display()
        );
    }

    #[test]
    #[ignore = "writes docs/generated/; run on purpose after a wire change"]
    fn regenerate_rpc_wire_schema() {
        std::fs::write(generated(SCHEMA_FILE), render(TABLE)).expect("write schema");
    }
    use serde_json::{json, Value};

    /// Serde reads `doc` exactly when the schema admits it, and what serde
    /// writes back is the document again.
    fn agree<T: serde::Serialize + serde::de::DeserializeOwned + Schema>(doc: &Value) -> bool {
        let read = serde_json::from_value::<T>(doc.clone());
        let admitted = conforms(doc, &T::shape());
        assert_eq!(
            read.is_ok(),
            admitted.is_ok(),
            "serde {:?} schema {admitted:?}: {doc}",
            read.err()
        );
        if let Ok(value) = read {
            assert_eq!(&serde_json::to_value(value).unwrap(), doc);
            true
        } else {
            false
        }
    }

    fn hash(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// A selector is exactly one of `height`, `hash` or `tip`, beside its
    /// switches (IG-Q94). Red edit: let `Selector::one` take the first key
    /// given, and the two-key document is read.
    #[test]
    fn a_selector_agrees_with_its_schema() {
        use block::{BlockShowSelect, HeaderSelect};
        assert!(agree::<HeaderSelect>(&json!({"height": 7, "pow": false})));
        assert!(agree::<HeaderSelect>(
            &json!({"hash": hash(1), "pow": true})
        ));
        assert!(agree::<HeaderSelect>(&json!({"tip": null, "pow": false})));
        assert!(agree::<BlockShowSelect>(
            &json!({"tip": null, "pow": false, "prune": true})
        ));
        for bad in [
            json!({"pow": true}),
            json!({"height": 7, "tip": null, "pow": false}),
            json!({"tip": 0, "pow": false}),
            json!({"height": 7, "prune": true, "pow": false}),
            json!(null),
        ] {
            assert!(!agree::<HeaderSelect>(&bad), "{bad}");
        }
        assert!(!agree::<chain::CurveSelect>(&json!({"hash": hash(1)})));
        assert!(agree::<chain::CurveSelect>(&json!({"height": 3})));
    }

    /// A list slot is the item, `{"missing": null}`, `{"archived": …}`, or
    /// `null` (IG-Q73).
    #[test]
    fn a_slot_agrees_with_its_schema() {
        type S = Slot<crate::hash::HashHex>;
        assert!(agree::<S>(&json!(hash(2))));
        assert!(agree::<S>(&json!({"missing": null})));
        assert!(agree::<S>(
            &json!({"archived": {"id": hash(3), "shard": 9}})
        ));
        assert!(agree::<S>(&Value::Null));
        assert!(!agree::<S>(&json!({"missing": 1})));
        assert!(!agree::<S>(&json!("missing")));
        assert!(!agree::<S>(&json!({"lost": null})));
    }

    /// The verdict is tagged by `verdict`, and a rejection's cause is one
    /// key (IG-Q76, IG-Q86).
    #[test]
    fn a_verdict_agrees_with_its_schema() {
        use tx::Verdict;
        assert!(agree::<Verdict>(&json!({"verdict": "accepted"})));
        assert!(agree::<Verdict>(
            &json!({"verdict": "already-in-pool", "publication": "overdue"})
        ));
        assert!(agree::<Verdict>(
            &json!({"verdict": "already-in-chain", "mined_height": 5})
        ));
        assert!(agree::<Verdict>(
            &json!({"verdict": "rejected", "cause": {"fee-too-low": null}})
        ));
        assert!(agree::<Verdict>(
            &json!({"verdict": "rejected", "cause": {"consensus-rule": "CEN-J15"}})
        ));
        for bad in [
            json!({"verdict": "rejected", "cause": "fee-too-low"}),
            json!({"verdict": "already_in_pool", "publication": "held"}),
            json!({"verdict": "already-in-pool"}),
        ] {
            assert!(!agree::<Verdict>(&bad), "{bad}");
        }
    }

    /// The submission's skew rules (`DAEMON_SUBMIT_VERDICT.md` §2.3): an
    /// unknown cause reads as unrecognized; an unknown field in a known
    /// verdict is tolerated, though a daemon never writes one (the schema
    /// refuses it); an unknown verdict is a parse error. Red edit: make an
    /// unknown cause key an error in `Rejection`'s reader.
    #[test]
    fn the_submission_keeps_its_skew_rules() {
        use tx::{Rejection, Verdict};
        let unknown_cause =
            json!({"verdict": "rejected", "cause": {"a-cause-from-a-newer-daemon": 7}});
        assert_eq!(
            serde_json::from_value::<Verdict>(unknown_cause).unwrap(),
            Verdict::Rejected {
                cause: Rejection::Unrecognized
            }
        );
        let extra = json!({"verdict": "already-in-chain", "mined_height": 5, "row": "x"});
        assert!(serde_json::from_value::<Verdict>(extra.clone()).is_ok());
        assert!(conforms(&extra, &Verdict::shape()).is_err());
        assert!(serde_json::from_value::<Verdict>(json!({"verdict": "deferred"})).is_err());
        assert!(serde_json::to_value(Rejection::Unrecognized).is_err());
    }

    fn status(extra: &[(&str, Value)]) -> Value {
        let mut doc = json!({
            "height": 10, "hash": hash(4), "target_height": null, "synchronized": true,
            "syncing": false, "offline": false, "degraded": false, "peered": true,
            "writer": {"live": null}, "protocol_version": 1, "difficulty": "0x1",
            "difficulty_cumulative": "0x2", "block_spacing": 120, "tx_count": 3,
            "block_weight_max": 300000, "block_weight_median": 1000, "time_adjusted": 1700000000,
            "emission": "100", "emission_multiplier": 1000000, "burn": 0, "burn_total": "0",
            "stake_share": 0, "txpool_count": 0, "grant": ["health", "status"],
        });
        for (key, value) in extra {
            doc[*key] = value.clone();
        }
        doc
    }

    /// `daemon_status`'s parts are each present whole or absent whole.
    /// Red edit: drop the part check from `wire_parted!`, and the
    /// partly-present document is read.
    #[test]
    fn daemon_status_parts_are_whole_or_absent() {
        use daemon::DaemonStatus;
        assert!(agree::<DaemonStatus>(&status(&[])));
        let whole: Vec<(&str, Value)> = vec![
            ("started", json!(1)),
            ("disk_free", json!(2)),
            ("data_size", json!(3)),
            ("revision", json!("v")),
            ("peer_outbound_count", json!(4)),
            ("peer_inbound_count", Value::Null),
            ("alt_count", json!(0)),
            ("rpc_connections", json!(1)),
            ("txpool_retired", json!(false)),
        ];
        assert!(agree::<DaemonStatus>(&status(&whole)));
        assert!(!agree::<DaemonStatus>(&status(&whole[..3])));
        assert!(agree::<DaemonStatus>(&status(&[(
            "connector",
            json!({"tor": {
                "inbound_count": 1, "outbound_count": 2, "peer_white_count": 3, "peer_gray_count": 4
            }})
        )])));
        assert!(!agree::<DaemonStatus>(&status(&[(
            "connector",
            json!({"i2p": {}})
        )])));
        assert!(!agree::<DaemonStatus>(&status(&[
            ("txpool_private_count", json!(null)),
            ("extra", json!(1))
        ])));
    }
}
