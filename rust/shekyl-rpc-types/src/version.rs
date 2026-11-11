// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's version (`RPC_WIRE.md` RW-Q6, RK-D25): the constants a
//! daemon reports in `version` and a client compares before it decodes
//! anything else, and the history of every change that moved them.

/// `CORE_RPC_VERSION_MAJOR`: 4 since the rename (RW-Q8). A major bump is a
/// wire no reader of the previous major decodes past the version read.
pub const CORE_RPC_VERSION_MAJOR: u32 = 4;
/// `CORE_RPC_VERSION_MINOR`. 3.57: `get_fee_estimate` takes no
/// parameters and answers `status` and `fees` alone. `grace_blocks` moved
/// no rung (FL-R26) and `quantization_mask` is a Rust constant the wallet
/// shares (`shekyl_economics::FEE_QUANTIZATION_MASK`). `get_version` gains
/// nothing. 3.54: `get_info` stops repeating the daemon's
/// network (RK-Q6). `nettype` and the booleans `mainnet`, `testnet` and
/// `stagenet` are gone from it; `get_version.nettype` is the one place a
/// daemon names its network. `get_version` gains nothing.
/// 3.53: `get_info`'s two amounts of coin,
/// `already_generated_coins` and `total_burned`, are decimal strings of
/// atomic units (RK-Q2): the wallet RPC's encoding, since a JSON number
/// loses integers above 2^53 in a JavaScript reader. Both stay required.
/// Other daemon methods still write amounts as numbers until their own
/// migration. `get_version` gains nothing.
/// 3.52: `get_info` stops repeating values under
/// second names (RK-Q1). `difficulty`, `difficulty_top64`,
/// `cumulative_difficulty`, `cumulative_difficulty_top64`, `block_size_limit`
/// and `block_size_median` are gone; `wide_difficulty`,
/// `wide_cumulative_difficulty`, `block_weight_limit` and
/// `block_weight_median` stay, the last two now always present. Block
/// headers keep their triple. `get_version` gains nothing.
/// 3.51: `get_info` refuses when the chain store
/// holds more burned than generated, with an error that names the invariant
/// and its operands (RK-Q9). It answered that state with `burn_pct: 0`.
/// No member of any reply moves. `get_version` gains nothing.
/// 3.50: `get_info`'s `tx_pool_size` is the pool
/// entries this node has broadcast, for every caller; the entries it holds
/// and has not yet broadcast are `tx_pool_unbroadcast_count`, a host-only
/// part (RK-Q10). `tx_pool_size` was the broadcast set for a restricted
/// caller and every entry for any other. `get_version` gains nothing.
/// 3.49: `get_info`'s two connection counts are
/// handshaken sessions on every connector, per direction, from one snapshot
/// of the seam board (RK-Q3), so `has_peers` is true exactly when they are
/// not both zero. They were clearnet-only, and the incoming one was a
/// total from one store minus an outbound count from another. A shown
/// Status with an empty `version` is refused. `get_version` gains nothing.
/// 3.48: a `get_info` reply to a caller who is not
/// shown Status or Peers omits those parts (RK-Q8). It carried them with
/// stand-in values: zero counts, an empty `version`, `free_space` of
/// `u64::MAX`, and `database_size` rounded up to 5 GiB. `get_version` gains
/// nothing. 3.47: `get_info` gains `has_peers`, a boolean
/// in Health that every caller is told (RK-D14): at least one handshaken
/// session on any connector. `get_info` refuses when the p2p hub is not up,
/// where it answered zero counts. `get_version` gains nothing. 3.46: `target_height` is the core's target, and
/// `null` when the core reports none, on `get_info`, `get_version` and
/// `sync_info` together (RK-D15, RK-Q7). `get_info` stops writing `0` for a
/// synchronized node; `get_version` stops omitting the member and
/// `sync_info` stops writing `0` when there is no target; and
/// `get_version.current_height` is always present. 3.45: `get_info` stops carrying `emission_era`
/// (RK-D21): there never was an emission era, and the field is deleted, not
/// ported. `get_version` gains nothing. 3.44: `get_version` drops `hard_forks` and the
/// `hard_fork_info` method is deleted — the block version is the constant 1,
/// so there is no schedule to report and no activation to query.
/// `get_version` loses that member and gains nothing else. 3.43:
/// `request_archival_shard` is served natively over the W-shard view
/// (`archival.rs`; `SHARD_VIEW_FETCH.md` `SV-D3`): the response gains
/// `archival_len` and `close_height`, and an open shard and an absent
/// skeleton answer with their own codes (-24, -25) rather than sharing the
/// miss's -22. `get_version` gains nothing. 3.42: `get_info` reports
/// `already_generated_coins`, the gross coins emitted through the tip.
/// `get_version` gains nothing. 3.41: `inject_archival_serve_credit` (regtest
/// only) returns its receipt — `height`, the tip's block **index** the row
/// was keyed at, read under the lock with the write; the chain-vector
/// capture replays the injection as a corpus event at exactly that height
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.8 item 3, `ARW-26` on index vs count).
/// `get_version` gains nothing. 3.40: `get_version` and `sync_info` report the
/// core's target height. `0` is a core-reported absence, not "synchronized"
/// — that overload made the two states indistinguishable. 3.39: every `get_transactions` entry gains
/// `archival_len`, the operand a client supplies beside `prunable_hash` to
/// rebuild a pruned body's txid, which now binds it (`SHT-Q2`). The txid of
/// every non-coinbase transaction changes with the same cutover, so a 3.38
/// peer disagrees about identities, not only about this member. 3.38:
/// `get_info` gains the four per-connector
/// socket counts, and `get_bans` / `banned` gain `permanent`. `get_version`
/// gains nothing. 3.37: `get_block_template` bounds `reserve_size`
/// to 8 and `extra_nonce` to 8 bytes — the coinbase `0x02` nonce is a fixed
/// 8-byte field under the closed coinbase grammar (`TX_EXTRA_RUST_CUTOVER.md`
/// TXE-Q6′), always reserved, so `reserved_offset` is always returned; a
/// larger request is refused with `CORE_RPC_ERROR_CODE_COINBASE_NONCE_BOUND`
/// (-23; the old 0..255 `TOO_BIG_RESERVE_SIZE` -3 is retired).
/// 3.36: `get_info` drops `tx_prune_height` — the
/// C++ tx-data prune whose watermark it reported is deleted (LMDB v15; the
/// uniform discard is S-PRUNE, which will report its own frontier when it
/// exists). 3.35: the stripe seed leaves `get_peer_list`,
/// `get_connections` and `sync_info.peers`, and the next-needed stripe
/// leaves `sync_info`; the `prune_blockchain` method is deleted (REJECTED in
/// the registry, `PDM-Q7`) — the stripe engine is gone, so every value was
/// 0 and the field was a gossiped self-asserted attribute (`PWD-I1`'s shape).
/// 3.34: `get_curve_tree_path` **removed** — a
/// per-output path query is spend-revealing (`PHASE_2A_SEND_PATH.md` §3.0.1),
/// had no production consumer, and paired each leaf with a different
/// output's `(O, C)` on any chain carrying a transaction (`SOK-10`, Q7 → A);
/// the wallet assembles paths locally. (#782 and #784 both minted 3.33 on
/// their branches and git merged the constant clean — the collision the
/// paragraph below warns about, caught on merge by the parity chain test.)
/// 3.33: `get_output_histogram` deleted — a
/// per-amount output-count query over caller-chosen unlock and recency
/// windows is a statistical disclosure surface with no consumer on a chain
/// without rings (`DRS_E1_SOUT_KI.md` SOK-Q3, ruled B; census U-7). 3.32:
/// `calc_pow` drops leftover `major_version` (RandomX-only longhash; the
/// C++ daemon RPC was then still live via `core_rpc_ffi`). 3.31: `get_archival_shard_coverage` and
/// `request_archival_shard` (`ARCHIVAL_SHARD_SELECTION_LIST.md` `SL-D`).
/// 3.30: `get_fee_estimate.fees` drops the dead
/// fourth slot — three priced tiers, one slot each (FL-R25; the RK-5 bridge
/// mirrored slot 1 for a `FeePriority::Elevated` caller that never existed).
/// 3.29: `get_version` gains the three identity-
/// tuple fields — `consensus_constants_digest`, `nettype`, `genesis_hash`
/// (`CLIENT_VERSION_CONSTANTS_VALIDATION.md` `VC-2`). 3.28 was the peer
/// identifier leaving every readout; 3.27 RK-5b's three header-method shape
/// changes; 3.26 `get_info.following_degraded`; 3.25 the RK-4c removals.
///
/// **Read from this tree at the moment this line is written, never carried
/// forward from a plan.** `chain.rs:59-70` records two branches taking 3.26
/// honestly and git merging them character-for-character, because `= 25` →
/// `= 26` is textually identical whoever writes it. 3.33 is the
/// `get_output_histogram` deletion on this branch; 3.34 the
/// `get_curve_tree_path` removal, chained after it on merge; 3.35 the
/// stripe-seed deletion; 3.36 the `tx_prune_height` deletion; 3.37 the
/// coinbase-nonce bound; 3.38 the per-connector socket counts and the
/// permanent-ban flag; 3.39 `get_transactions`' `archival_len`; 3.40
/// `get_version` and `sync_info` stop encoding synchronization as
/// `target_height = 0`; 3.41 the injector's `height` receipt; 3.42
/// `get_info.already_generated_coins`; 3.43 `request_archival_shard`
/// served natively over the W-shard view (`archival.rs`): the response
/// gains `archival_len` and `close_height`, and the open-shard and
/// skeleton-absent refusals get their own codes (`SHARD_VIEW_FETCH.md`
/// `SV-D3`, `SV-D5`, `SV-D9`); 3.44 `get_version` loses `hard_forks` and
/// `hard_fork_info` is deleted. Both branches had written 3.43; the
/// deletion is chained after the shard view, the same way 3.34 was
/// chained after 3.33. 3.45 the `get_info.emission_era` deletion, written
/// as 3.43 and chained twice, after each of those. 3.46 the nullable
/// target on `get_info`, `get_version` and `sync_info`. 3.47
/// `get_info.has_peers`. 3.48 a restricted `get_info` omits Status and
/// Peers. 3.49 its connection counts come from the seam board. 3.50 its pool
/// count is split by broadcast state. 3.51 it refuses on a broken supply
/// invariant. 3.52 its duplicate wire names retire. 3.53 its
/// amounts are decimal strings. 3.54 it stops repeating the network. 3.55
/// `get_peer_list` entries lose `last_seen`: the Rust peer lists carry no
/// clock, and the listing is read from them. 3.56 a daemon started offline
/// reports that state: `get_info`'s Peers part is `"p2p": "offline"` with
/// no count (and `"p2p": "running"` with its counts), and `get_peer_list`,
/// `get_connections` and `sync_info` answer `offline` alone.
/// 3.58: `option_set` and `option_show` (RT-O23…RT-O27); the JSON-RPC
/// error object gains `data`, and `-26` is a configuration refusal.
/// `/set_limit`, `/get_limit`, `/set_log_level` and `/set_log_categories`
/// are gone (`DAEMON_CONFIG_CUTOVER.md` §2.7), and `/start_mining` no longer
/// takes `do_background_mining` or `ignore_battery` (§4.2: background
/// mining's options and runtime arguments); `/mining_status` loses
/// `is_background_mining_enabled` and the four `bg_*` members with the
/// miner's background half.
/// 3.59: `get_connections` and `sync_info` rows lose `support_flags` with
/// the P2P support-flags word (`SHEKYL_P2P_PROTOCOL.md` PWD-T7): it had no
/// other source. A row from a 3.58 daemon carries the key, which this
/// version's `ConnectionInfo` refuses, so the identity check reports the
/// contract before a reply is decoded.
/// 3.60: a claim-source bond row names `is_support_complete_tree`. A 3.59
/// daemon still sends `is_foundation_complete_tree`, which this version
/// refuses. `get_version` gains nothing.
/// 3.61: a node whose pool is retired answers the chain's reads.
/// `get_info` carries `pool_retired: true` with `tx_pool_size` (and the
/// host's `tx_pool_unbroadcast_count`) `null`; `get_transactions` lists an
/// id the chain does not hold under `unavailable_tx`. A 3.60 reader decodes
/// `tx_pool_size` as a number and knows neither key. `get_version` gains
/// nothing.
/// 3.62: a refusal by grant is the JSON-RPC error object on every surface
/// (`RPC_WIRE.md` RW-Q3): class `OutsideTheGrant` (-32002) with its typed
/// diagnostic, where a gated JSON-RPC method was HTTP 403 with -32601 and a
/// gated REST path was a 404. A path or a name that is not a method stays
/// not found. The view listener refuses
/// `/get_alt_blocks_hashes` (`status`), and `calc_pow` and
/// `get_coinbase_tx_sum` are refused to a bounded caller as
/// `OverResourceBound` (-32003) until their bounds are set (RT-W10).
/// `get_version` gains nothing.
/// 3.63: the flip's client shapes (FLIP-Q4). `start_mining` takes
/// `{ threads }` and no address. `generateblocks` takes `{ count }`.
/// `get_block_template` takes no parameters. A retired pool's
/// `tx_pool_size` is null. `join_market_unsupported` leaves the
/// `send_raw_transaction` reject-cause set: the Rust daemon admits a
/// JoinMarket bond post, and no daemon authors the cause. `get_version`
/// gains nothing.
/// 3.64: a transaction's body has two forms and both bind (`SB-Q2`,
/// `PDM-Q10`). A `get_transactions` entry carries `pqc_auth_hash`
/// (nullable) beside `prunable_hash` and `archival_len`; under `prune` its
/// `pruned_as_hex` is the pruned segment only, never with `pqc_auths`
/// appended. A full body this node has discarded is listed under
/// `archived` as `{ tx_hash, shard }`, not failed. `split`,
/// `decode_as_json`, `prunable_as_hex`, `as_json` and `pruned` retire
/// (IG-Q55). `get_blocks_by_height.bin` takes `prune` and carries each
/// archived body as a per-slot state rather than failing the height.
/// `get_version` gains nothing.
/// 3.65: `mining_status.speed` is the hash count over its window of
/// complete seconds. A whole-hash quotient read `0` for a miner below
/// one hash a second. `get_version` gains nothing.
/// 3.66: a bounded connection over an inherited list cap, or asking for
/// `fill_pow_hash`, is `OverResourceBound` (-32003) with the bound named.
/// The four caps stay 1000, 1000, 100 and 5000. `calc_pow` and
/// `get_coinbase_tx_sum` stay refused to a bounded caller until their
/// costs are set. `get_version` gains nothing.
/// 3.67: `calc_pow` and `get_coinbase_tx_sum` are served to a bounded
/// caller. `calc_pow` hashes a blob no longer than the hashing-blob
/// format (`MAX_POW_BLOB_SIZE`) and pays one hash from the shared budget.
/// `fill_pow_hash` returns the hash recorded at validation and does not
/// pay; a bounded header read stays within the 1,000-header cap. A request
/// for more than one hash, or one hash while the budget is empty, is
/// `OverResourceBound`. A bounded `get_coinbase_tx_sum` waits for the one
/// coinbase-read permit. `get_version` gains nothing.
/// 3.68: chain sync's cutover (CS-5 §7). `sync_info` carries the sync
/// owner's view under its own names: `height`, `target_height` (now always
/// a count), `state`, `stalled`, and `peers[]` with `connection_id`,
/// `address`, `claimed_height`, `mode`, `header_request`, `body_requests`
/// and `rate`. `spans` and `overview`, which rendered the deleted block
/// queue, are gone, and a 3.67 reader refuses the reply. `get_connections`
/// takes `height` (the claim's count) and `state` (the session's mode, or
/// null) from the view. `get_version` gains nothing.
/// 3.69: `already_in_pool` carries a required `relay` (`held`,
/// `held_overdue`, `published`, or `untracked`), the owner tier's relay
/// state. The daemon judges `held_overdue` when that state is read, on
/// its own clock. A missing origin row is `untracked`. `get_version`
/// gains nothing.
/// 3.70: `get_info`'s Peers part reports one row per connector the daemon
/// runs, `connectors: [{connector, incoming_sockets, outgoing_sockets,
/// white_peerlist_size, gray_peerlist_size}]`, `clearnet` before `tor`.
/// A connector the daemon does not run has no row. The six flat keys
/// (`public_*`/`tor_*` socket counts, `white_peerlist_size`,
/// `grey_peerlist_size`) are gone; the list sizes they gave were the
/// clearnet lists alone, so a Tor-only node read `white 0`. A 3.69 reader
/// refuses the reply. `get_version` gains nothing.
///
/// 4.0: the rename (`RPC_WIRE.md` RW-Q8). Every method takes its
/// `INPUT_GRAMMAR.md` Part C path, as Part F and IG-Q94 amend it, and is
/// served as JSON-RPC on `/json_rpc` alone: no alias, no REST path, and
/// neither `.bin` method (RW-Q1, RW-Q2, RW-Q5). The envelope is strict
/// JSON-RPC 2.0 with named `params`. `status` leaves every reply, and every
/// failure is the error object with a class and a dotted diagnostic
/// (RW-Q3). Each value takes its kind's one encoding: amounts are decimal
/// atomic units, bodies base64, heights ordinals (RW-Q4, IG-Q45). The
/// version read is `version`, under no grant; its `version` key and value
/// are unchanged (RK-D25, RW-Q6). A 3.x reader of any 4.0 reply refuses it
/// after the version read reports the daemon newer. The method table and
/// its schema are `wire::TABLE` and `docs/generated/rpc_wire_schema.tsv`.
pub const CORE_RPC_VERSION_MINOR: u32 = 0;
/// `MAKE_CORE_RPC_VERSION(major, minor)` = `(major << 16) | minor`.
pub const CORE_RPC_VERSION: u32 = (CORE_RPC_VERSION_MAJOR << 16) | CORE_RPC_VERSION_MINOR;

/// `major.minor` from the packed constant, for operator-facing copy.
#[must_use]
pub fn core_rpc_version_string(packed: u32) -> String {
    format!("{}.{}", packed >> 16, packed & 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MAKE_CORE_RPC_VERSION(4, 0)` is `(4 << 16) | 0` = 262144. Each bump
    /// moves this pin; the packing does not change (RK-D25).
    #[test]
    fn core_rpc_version_packs_major_over_minor() {
        assert_eq!(CORE_RPC_VERSION, 262_144);
        assert_eq!(CORE_RPC_VERSION, (4 << 16) | 0);
        assert_eq!(CORE_RPC_VERSION_MAJOR, 4);
        assert_eq!(CORE_RPC_VERSION_MINOR, 0);
        assert_eq!(core_rpc_version_string(CORE_RPC_VERSION), "4.0");
        assert_eq!(core_rpc_version_string((3 << 16) | 70), "3.70");
    }
}
