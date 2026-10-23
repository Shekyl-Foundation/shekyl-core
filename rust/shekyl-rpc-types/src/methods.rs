// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one method table (`RPC_WIRE.md` RW-Q7).
//!
//! Every method the daemon serves is one row: its name and the aliases it
//! answers to, the surface it is served on, who may call it, and whether it
//! is an armed lever. Dispatch's grant check reads the table; nothing else
//! lists a method's policy (RK-D6). A gate in `shekyl-daemon-rpc` checks
//! that every served method is a row and every row is served.
//!
//! Two of RW-Q7's columns are not here yet, and say why:
//!
//! - **Request and reply types.** A type is not a value; until the flip,
//!   the dispatch match is where a name meets its types.
//! - **The resource bound.** `RPC_CHANNEL.md` §6.3's per-request bounds are
//!   RT-W10's, and are not built.
//!
//! The names are today's (`RPC_WIRE.md` RW-Q8: the rename lands after the
//! flip, at `CORE_RPC_VERSION` 4.0, as one edit of this table).

/// Who may call a method: RW-Q7's grant column.
///
/// Before RT-W10's grants exist, a daemon has two listeners: the view
/// listener (restricted) and the host's own (unrestricted). `Any` is served
/// on both; `HostOnly` only on the host's (`RPC_CHANNEL.md` RT-O9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grant {
    /// Any connection, the view listener included.
    Any,
    /// The host administrator only.
    HostOnly,
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
    pub grant: Grant,
    /// An armed lever (RW-Q7; `DRS_X_STORE_FLIP.md` DX-Q3, Q8): refused,
    /// whatever the caller's grant, unless the daemon was started with the
    /// armed-lever switch on.
    pub armed: bool,
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
}

const fn json(name: &'static str, aliases: &'static [&'static str], grant: Grant) -> Method {
    Method {
        name,
        aliases,
        surface: Surface::JsonRpc,
        grant,
        armed: false,
    }
}

const fn rest(name: &'static str, aliases: &'static [&'static str], grant: Grant) -> Method {
    Method {
        name,
        aliases,
        surface: Surface::Rest,
        grant,
        armed: false,
    }
}

const fn armed(method: Method) -> Method {
    Method {
        armed: true,
        ..method
    }
}

use Grant::{Any, HostOnly};

/// The table.
pub const METHODS: &[Method] = &[
    // JSON-RPC, served natively in Rust.
    json("get_version", &[], Any),
    json("get_block_count", &["getblockcount"], Any),
    json("on_get_block_hash", &["on_getblockhash"], Any),
    json(
        "get_block_header_by_height",
        &["getblockheaderbyheight"],
        Any,
    ),
    json("get_block", &["getblock"], Any),
    json("sync_info", &[], HostOnly),
    json("get_connections", &[], HostOnly),
    json("get_last_block_header", &["getlastblockheader"], Any),
    json("get_block_header_by_hash", &["getblockheaderbyhash"], Any),
    json("get_block_headers_range", &["getblockheadersrange"], Any),
    json("get_fee_estimate", &[], Any),
    json("request_archival_shard", &[], HostOnly),
    json("option_set", &[], HostOnly),
    json("option_show", &[], Any),
    json("get_info", &[], Any),
    // JSON-RPC, served by the C++ table until the flip.
    json("submit_block", &["submitblock"], Any),
    json("calc_pow", &[], HostOnly),
    json("get_block_template", &["getblocktemplate"], Any),
    json("get_miner_data", &[], Any),
    armed(json("generateblocks", &[], HostOnly)),
    json("inject_archival_serve_credit", &[], Any),
    json("set_bans", &[], HostOnly),
    json("get_bans", &[], HostOnly),
    json("banned", &[], HostOnly),
    json("flush_txpool", &[], HostOnly),
    json("get_coinbase_tx_sum", &[], HostOnly),
    json("get_alternate_chains", &[], HostOnly),
    json("relay_tx", &[], HostOnly),
    json("get_txpool_backlog", &[], Any),
    json("flush_cache", &[], HostOnly),
    json("get_curve_tree_info", &[], Any),
    json("get_curve_tree_checkpoint", &[], Any),
    json("get_archival_emission_claim_source", &[], Any),
    json("get_archival_shard_coverage", &[], Any),
    // REST.
    rest("/json_rpc", &[], Any),
    rest("/get_height", &["/getheight"], Any),
    rest("/get_transactions", &["/gettransactions"], Any),
    rest("/get_alt_blocks_hashes", &[], Any),
    rest("/is_key_image_spent", &[], Any),
    rest("/submit_transaction", &[], Any),
    rest("/get_transaction_pool", &[], Any),
    rest("/get_transaction_pool_hashes", &[], Any),
    rest("/get_transaction_pool_stats", &[], Any),
    rest("/get_info", &["/getinfo"], Any),
    rest(
        "/get_blocks_by_height.bin",
        &["/getblocks_by_height.bin"],
        Any,
    ),
    rest("/get_o_indexes.bin", &[], Any),
    rest("/get_stem_tallies", &[], HostOnly),
    rest("/start_mining", &[], HostOnly),
    rest("/stop_mining", &[], HostOnly),
    rest("/mining_status", &[], HostOnly),
    rest("/save_bc", &[], HostOnly),
    rest("/get_peer_list", &[], HostOnly),
    rest("/set_log_hash_rate", &[], HostOnly),
    rest("/stop_daemon", &[], HostOnly),
    rest("/get_net_stats", &[], HostOnly),
    armed(rest("/pop_blocks", &[], HostOnly)),
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

    /// The armed levers are `generateblocks` and `pop_blocks`, and both are
    /// the host's: an armed lever is never served to a view connection,
    /// switch or no switch.
    #[test]
    fn the_armed_levers_are_the_hosts() {
        let armed: Vec<&str> = METHODS
            .iter()
            .filter(|row| row.armed)
            .map(|row| row.name)
            .collect();
        assert_eq!(armed, ["generateblocks", "/pop_blocks"]);
        assert!(METHODS
            .iter()
            .filter(|row| row.armed)
            .all(|row| row.grant == Grant::HostOnly));
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
