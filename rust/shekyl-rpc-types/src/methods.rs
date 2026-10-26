// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one method table (`RPC_WIRE.md` RW-Q7).
//!
//! Every method the daemon serves is one row: its name and the aliases it
//! answers to, the surface it is served on, who may call it, and what one
//! request may cost. Dispatch's grant check reads the table; nothing else
//! lists a method's policy (RK-D6). A gate in `shekyl-daemon-rpc` checks
//! that every served method is a row and every row is served.
//!
//! **Who may call it** is [`Policy`] (`RPC_CHANNEL.md` §6.1, RT-O32): every
//! row is in exactly one grant, or in exactly one of the two classes that are
//! not grants (host-only data and the armed test levers). A row without a
//! policy does not compile, and a test checks every row against §6.1.
//!
//! **What it may cost** is [`Cost`] (§6.3). Two rows are marked unbounded
//! until RT-W10 step 2 sets their bounds, and a bounded caller is refused
//! them.
//!
//! One of RW-Q7's columns is not here yet, and says why: **request and reply
//! types.** A type is not a value; until the flip, the dispatch match is
//! where a name meets its types.
//!
//! The names are today's (`RPC_WIRE.md` RW-Q8: the rename lands after the
//! flip, at `CORE_RPC_VERSION` 4.0, as one edit of this table).

pub use shekyl_rpc_grants::{Grant, GrantSet, Preset};

/// Who may call a method (`RPC_CHANNEL.md` §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// A connection holding this grant.
    Grant(Grant),
    /// Host-only data (RT-O9.3): the host's administrator only, whatever a
    /// key's ceiling.
    HostOnly,
    /// An armed test lever (RT-O9.2): the host's administrator only, and only
    /// while the daemon runs with its armed-lever switch on.
    Armed,
    /// The JSON-RPC endpoint itself: it serves any connection, and each
    /// method on it carries its own policy.
    Endpoint,
}

/// What one request may cost (`RPC_CHANNEL.md` §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cost {
    /// Bounded by its handler, or cheap.
    Bounded,
    /// No bound is set yet: a bounded caller (every caller but the host's
    /// administrator) is refused it as over its resource bound. RT-W10
    /// step 2 sets the bound.
    Unbounded,
}

/// Where a method is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// A JSON-RPC method on `/json_rpc`.
    JsonRpc,
    /// A REST path of its own.
    Rest,
}

/// One row of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method {
    /// The method's name: a JSON-RPC method, or a REST path.
    pub name: &'static str,
    /// Other names it answers to, as the C++ tables carried them.
    pub aliases: &'static [&'static str],
    /// Where it is served.
    pub surface: Surface,
    /// Who may call it.
    pub policy: Policy,
    /// What one request may cost.
    pub cost: Cost,
}

impl Method {
    /// Whether `name` is this row's name or one of its aliases.
    #[must_use]
    pub fn answers_to(&self, name: &str) -> bool {
        self.name == name || self.aliases.contains(&name)
    }

    /// Every name this row answers to, its own first.
    pub fn names(&self) -> impl Iterator<Item = &'static str> {
        core::iter::once(self.name).chain(self.aliases.iter().copied())
    }

    /// Whether this row is an armed test lever.
    #[must_use]
    pub const fn armed(&self) -> bool {
        matches!(self.policy, Policy::Armed)
    }
}

const fn json(name: &'static str, aliases: &'static [&'static str], policy: Policy) -> Method {
    Method {
        name,
        aliases,
        surface: Surface::JsonRpc,
        policy,
        cost: Cost::Bounded,
    }
}

const fn rest(name: &'static str, aliases: &'static [&'static str], policy: Policy) -> Method {
    Method {
        name,
        aliases,
        surface: Surface::Rest,
        policy,
        cost: Cost::Bounded,
    }
}

const fn unbounded(method: Method) -> Method {
    Method {
        cost: Cost::Unbounded,
        ..method
    }
}

use Grant::{Bans, Chain, Health, MiningControl, MiningWork, Node, Peers, Pool, Status, Submit};
use Policy::{Armed, Endpoint, HostOnly};

const fn g(grant: Grant) -> Policy {
    Policy::Grant(grant)
}

/// The table.
pub const METHODS: &[Method] = &[
    // JSON-RPC, served natively in Rust.
    json("get_version", &[], g(Health)),
    json("get_block_count", &["getblockcount"], g(Chain)),
    json("on_get_block_hash", &["on_getblockhash"], g(Chain)),
    json(
        "get_block_header_by_height",
        &["getblockheaderbyheight"],
        g(Chain),
    ),
    json("get_block", &["getblock"], g(Chain)),
    json("sync_info", &[], g(Peers)),
    json("get_connections", &[], g(Peers)),
    json("get_last_block_header", &["getlastblockheader"], g(Chain)),
    json(
        "get_block_header_by_hash",
        &["getblockheaderbyhash"],
        g(Chain),
    ),
    json(
        "get_block_headers_range",
        &["getblockheadersrange"],
        g(Chain),
    ),
    json("get_fee_estimate", &[], g(Chain)),
    json("request_archival_shard", &[], g(Node)),
    json("option_set", &[], g(Node)),
    // Rows are each shown under the grant they name (RT-O24).
    json("option_show", &[], g(Health)),
    // Fields are each present under their grant (§6.1).
    json("get_info", &[], g(Health)),
    // JSON-RPC, served by the C++ table until the flip.
    json("submit_block", &["submitblock"], g(MiningWork)),
    // A computation service (RT-O9.4); its bound is RT-W10 step 2's.
    unbounded(json("calc_pow", &[], g(MiningWork))),
    json("get_block_template", &["getblocktemplate"], g(MiningWork)),
    json("get_miner_data", &[], g(MiningWork)),
    json("generateblocks", &[], Armed),
    // RT-O9.2 (`RPC_CHANNEL.md`, ruled 2026-10-09): a regtest lever. It
    // deletes at the flip (DX-Q3).
    json("inject_archival_serve_credit", &[], Armed),
    json("set_bans", &[], g(Bans)),
    json("get_bans", &[], g(Bans)),
    json("banned", &[], g(Bans)),
    json("flush_txpool", &[], g(Node)),
    // A public chain fact (RT-O9.4); its span bound is RT-W10 step 2's.
    unbounded(json("get_coinbase_tx_sum", &[], g(Chain))),
    json("get_alternate_chains", &[], g(Status)),
    json("relay_tx", &[], g(Node)),
    json("get_txpool_backlog", &[], g(Pool)),
    json("flush_cache", &[], g(Node)),
    json("get_curve_tree_info", &[], g(Chain)),
    json("get_curve_tree_checkpoint", &[], g(Chain)),
    json("get_archival_emission_claim_source", &[], g(Chain)),
    json("get_archival_shard_coverage", &[], g(Chain)),
    // REST.
    rest("/json_rpc", &[], Endpoint),
    rest("/get_height", &["/getheight"], g(Chain)),
    rest("/get_transactions", &["/gettransactions"], g(Chain)),
    rest("/get_alt_blocks_hashes", &[], g(Status)),
    rest("/is_key_image_spent", &[], g(Chain)),
    rest("/submit_transaction", &[], g(Submit)),
    rest("/get_transaction_pool", &[], g(Pool)),
    rest("/get_transaction_pool_hashes", &[], g(Pool)),
    rest("/get_transaction_pool_stats", &[], g(Pool)),
    rest("/get_info", &["/getinfo"], g(Health)),
    rest(
        "/get_blocks_by_height.bin",
        &["/getblocks_by_height.bin"],
        g(Chain),
    ),
    rest("/get_o_indexes.bin", &[], g(Chain)),
    rest("/get_stem_tallies", &[], HostOnly),
    rest("/start_mining", &[], g(MiningControl)),
    rest("/stop_mining", &[], g(MiningControl)),
    rest("/mining_status", &[], g(MiningControl)),
    rest("/save_bc", &[], g(Node)),
    rest("/get_peer_list", &[], g(Peers)),
    rest("/set_log_hash_rate", &[], g(MiningControl)),
    rest("/stop_daemon", &[], g(Node)),
    rest("/get_net_stats", &[], g(Status)),
    rest("/pop_blocks", &[], Armed),
];

/// The row for a JSON-RPC method `name`, by its name or an alias.
#[must_use]
pub fn json_rpc(name: &str) -> Option<&'static Method> {
    METHODS
        .iter()
        .find(|row| row.surface == Surface::JsonRpc && row.answers_to(name))
}

/// The row for a REST `path`, by its path or an alias.
#[must_use]
pub fn rest_path(path: &str) -> Option<&'static Method> {
    METHODS
        .iter()
        .find(|row| row.surface == Surface::Rest && row.answers_to(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name, alias or path answers to one row: two rows that share a name
    /// would make the grant depend on which one a lookup finds first.
    #[test]
    fn every_name_is_one_rows() {
        let mut seen = std::collections::BTreeSet::new();
        for row in METHODS {
            for name in row.names() {
                assert!(
                    seen.insert((row.surface == Surface::Rest, name)),
                    "{name} is in two rows"
                );
            }
        }
    }

    /// The armed levers are `generateblocks`, `pop_blocks` and
    /// `inject_archival_serve_credit` (§6.1, RT-O9.2), and nothing else is.
    #[test]
    fn the_armed_levers_are_the_three() {
        let armed: Vec<&str> = METHODS
            .iter()
            .filter(|row| row.armed())
            .map(|row| row.name)
            .collect();
        assert_eq!(
            armed,
            [
                "generateblocks",
                "inject_archival_serve_credit",
                "/pop_blocks"
            ]
        );
    }

    /// Every row's policy, written from `RPC_CHANNEL.md` §6.1's table, not
    /// from the table above: a row moved to another grant fails here, and a
    /// row added without being placed here fails the exactly-once check.
    #[test]
    fn every_row_is_in_exactly_the_policy_section_6_1_gives_it() {
        let section: &[(&[&str], Policy)] = &[
            (
                &[
                    "get_block_count",
                    "on_get_block_hash",
                    "get_block_header_by_height",
                    "get_block",
                    "get_last_block_header",
                    "get_block_header_by_hash",
                    "get_block_headers_range",
                    "get_fee_estimate",
                    "get_coinbase_tx_sum",
                    "get_curve_tree_info",
                    "get_curve_tree_checkpoint",
                    "get_archival_emission_claim_source",
                    "get_archival_shard_coverage",
                    "/get_height",
                    "/get_transactions",
                    "/is_key_image_spent",
                    "/get_blocks_by_height.bin",
                    "/get_o_indexes.bin",
                ],
                Policy::Grant(Grant::Chain),
            ),
            (
                &[
                    "get_txpool_backlog",
                    "/get_transaction_pool",
                    "/get_transaction_pool_hashes",
                    "/get_transaction_pool_stats",
                ],
                Policy::Grant(Grant::Pool),
            ),
            (
                &["get_version", "get_info", "/get_info", "option_show"],
                Policy::Grant(Grant::Health),
            ),
            (
                &[
                    "get_alternate_chains",
                    "/get_alt_blocks_hashes",
                    "/get_net_stats",
                ],
                Policy::Grant(Grant::Status),
            ),
            (
                &["sync_info", "get_connections", "/get_peer_list"],
                Policy::Grant(Grant::Peers),
            ),
            (&["/submit_transaction"], Policy::Grant(Grant::Submit)),
            (
                &[
                    "get_block_template",
                    "get_miner_data",
                    "submit_block",
                    "calc_pow",
                ],
                Policy::Grant(Grant::MiningWork),
            ),
            (
                &[
                    "/start_mining",
                    "/stop_mining",
                    "/mining_status",
                    "/set_log_hash_rate",
                ],
                Policy::Grant(Grant::MiningControl),
            ),
            (
                &["set_bans", "get_bans", "banned"],
                Policy::Grant(Grant::Bans),
            ),
            (
                &[
                    "/stop_daemon",
                    "/save_bc",
                    "flush_txpool",
                    "flush_cache",
                    "relay_tx",
                    "request_archival_shard",
                    "option_set",
                ],
                Policy::Grant(Grant::Node),
            ),
            (&["/get_stem_tallies"], Policy::HostOnly),
            (
                &[
                    "generateblocks",
                    "inject_archival_serve_credit",
                    "/pop_blocks",
                ],
                Policy::Armed,
            ),
            (&["/json_rpc"], Policy::Endpoint),
        ];
        let mut placed = std::collections::BTreeMap::new();
        for (names, policy) in section {
            for name in *names {
                assert!(
                    placed.insert(*name, *policy).is_none(),
                    "{name} is placed twice"
                );
            }
        }
        for row in METHODS {
            assert_eq!(
                placed.remove(row.name),
                Some(row.policy),
                "{} is not where §6.1 puts it",
                row.name
            );
        }
        assert!(placed.is_empty(), "placed but not in the table: {placed:?}");
    }

    /// The two rows whose bound is RT-W10 step 2's are the only unbounded
    /// ones (§6.3): a bounded caller is refused them until then.
    #[test]
    fn only_calc_pow_and_the_coinbase_sum_are_unbounded() {
        let unbounded: Vec<&str> = METHODS
            .iter()
            .filter(|row| row.cost == Cost::Unbounded)
            .map(|row| row.name)
            .collect();
        assert_eq!(unbounded, ["calc_pow", "get_coinbase_tx_sum"]);
    }

    #[test]
    fn a_lookup_finds_a_row_by_alias_on_its_own_surface_only() {
        assert_eq!(
            json_rpc("getblockcount").map(|row| row.name),
            Some("get_block_count")
        );
        assert_eq!(rest_path("/getinfo").map(|row| row.name), Some("/get_info"));
        assert!(json_rpc("/get_info").is_none());
        assert!(rest_path("get_info").is_none());
    }
}
