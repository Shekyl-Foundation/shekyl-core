// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-tip and version methods — the RK-1 slice of the daemon RPC KV
//! cutover (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.1).
//!
//! These are the single Rust definitions of the wire types that
//! `COMMAND_RPC_GET_HEIGHT` and `COMMAND_RPC_GET_VERSION` used to carry in
//! C++. Field names are the wire names; `u64` serializes as a JSON number
//! (as epee did); hashes are lowercase hex strings; every C++
//! `KV_SERIALIZE_OPT(field, default)` is mirrored by
//! `#[serde(default, skip_serializing_if = …)]`, which is what makes a reply
//! byte-equal to the captured epee document — the reason is oracle parity, not
//! any client's tolerance.
//!
//! Unknown fields are **refused** (`deny_unknown_fields`). They were tolerated
//! on the grounds that "additive daemon-side evolution must not break an older
//! wallet", which is not a constraint this tree has: there is no network, and
//! every client ships with the daemon. What the tolerance did buy was a
//! *renamed* field arriving unnoticed while the name we look for defaults —
//! a wrong value that reads as a legitimate one. Refusing turns that into a
//! parse error at the boundary, the same way `deny_unknown_fields` on the
//! wallet-RPC params makes an unknown key `-32602` rather than a guess.
//!
//! Checked, not assumed: every captured vector still parses with the denial on,
//! so the types already model everything the daemon emits.
//!
//! **This is not a fix for silent defaults.** `#[serde(default)]` still lets an
//! *omitted* field become its zero value; denial only catches the extra or
//! renamed one. Auditing those defaults is its own pass (FOLLOWUPS).
//!
//! Parity against the captured epee output is pinned by
//! `tests/rpc_parity.rs` over `tests/vectors/rpc/` (RK-D4).

use serde::{Deserialize, Serialize};

use crate::consensus_digest::DaemonNetwork;
use crate::hash::HashHex;

/// `CORE_RPC_VERSION_MAJOR` — moved here from
/// `src/rpc/core_rpc_server_commands_defs.h` with `get_version`, its only
/// reader (RK-D8).
pub const CORE_RPC_VERSION_MAJOR: u32 = 3;
/// `CORE_RPC_VERSION_MINOR`. 3.36: `get_info` drops `tx_prune_height` — the
/// C++ tx-data prune whose watermark it reported is deleted (LMDB v15; the
/// uniform discard is S-PRUNE, which will report its own frontier when it
/// exists). 3.35: `pruning_seed` leaves `get_peer_list`,
/// `get_connections` and `sync_info.peers`, and `next_needed_pruning_seed`
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
/// `calc_pow` drops leftover `major_version` (RandomX-only longhash; C++
/// daemon RPC is still live via `core_rpc_ffi`). 3.31: `get_archival_shard_coverage` and
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
/// `pruning_seed` deletion; 3.36 the `tx_prune_height` deletion.
pub const CORE_RPC_VERSION_MINOR: u32 = 36;
/// `MAKE_CORE_RPC_VERSION(major, minor)` = `(major << 16) | minor`.
pub const CORE_RPC_VERSION: u32 = (CORE_RPC_VERSION_MAJOR << 16) | CORE_RPC_VERSION_MINOR;

/// `major.minor` from the packed constant, for operator-facing copy.
#[must_use]
pub fn core_rpc_version_string(packed: u32) -> String {
    format!("{}.{}", packed >> 16, packed & 0xffff)
}

/// The `status` string every daemon reply carries (`rpc_response_base`).
///
/// One type for the three values C++ spelled as three macros
/// (`CORE_RPC_STATUS_OK` / `BUSY` / `NOT MINING`) and for the free-text error
/// statuses handlers emit; clients branch on [`RpcStatus::is_ok`], never on a
/// string literal of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(transparent)]
pub struct RpcStatus(pub String);

impl RpcStatus {
    /// `"OK"`.
    pub const OK: &'static str = "OK";
    /// `"BUSY"` — the core is not ready to answer.
    pub const BUSY: &'static str = "BUSY";

    /// The success status.
    #[must_use]
    pub fn ok() -> Self {
        Self(Self::OK.to_owned())
    }

    /// Whether this reply succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.0 == Self::OK
    }
}

/// JSON-RPC error code for a malformed request (`CORE_RPC_ERROR_CODE_WRONG_PARAM`).
///
/// This and [`CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT`] are the codes a client
/// branches on, so they live with the wire types. `src/rpc/core_rpc_server_error_codes.h`
/// still spells them for the ~26 handlers that remain in C++; that header is
/// deleted at RK-X, leaving these as the only definition.
pub const CORE_RPC_ERROR_CODE_WRONG_PARAM: i64 = -1;
/// JSON-RPC error code for a height at or past the chain tip
/// (`CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT`).
pub const CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT: i64 = -2;

/// JSON-RPC error code for a request the restricted listener declines
/// (`CORE_RPC_ERROR_CODE_RESTRICTED`) — a cap exceeded, or a privileged field
/// asked for. **A refusal, never a silently emptied field**: the C++ answered
/// `fill_pow_hash` under restriction with an empty string and status OK,
/// reporting success about a question it had declined.
pub const CORE_RPC_ERROR_CODE_RESTRICTED: i64 = -19;
/// JSON-RPC error code for a daemon-side failure the method has a contract
/// for (`CORE_RPC_ERROR_CODE_INTERNAL_ERROR`) — e.g. a store that reports a
/// height it cannot produce the block for.
pub const CORE_RPC_ERROR_CODE_INTERNAL_ERROR: i64 = -5;

/// JSON-RPC error code for a node that is not synchronised
/// (`CORE_RPC_ERROR_CODE_CORE_BUSY`, `core_rpc_server_error_codes.h:41`).
///
/// **A refusal, where the C++ answered with a status and a zeroed payload.**
/// `CHECK_CORE_READY()` set `status = BUSY` and returned success, leaving the
/// reply's `block_header` default-constructed — so a client that read the
/// header without checking the status got a block at height 0 with a zero
/// hash. That is not hypothetical: `shekyl-rpc-client`'s
/// `get_hardfork_version` reads `block_header.major_version` straight
/// through, and against an unsynchronised C++ daemon it silently returned
/// version 0. Refusing is the ruling this slice already applied twice
/// (`pow_hash_or_refuse`, and `5b0c32f51`'s "loud, never the degrade arm"):
/// a method that declines to answer must not report success.
pub const CORE_RPC_ERROR_CODE_CORE_BUSY: i64 = -9;

/// JSON-RPC error code for an operator shard-fetch that did not produce a
/// body (`CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE`). Typed miss — not
/// `WRONG_PARAM`. The requested `shard_id` was well-formed; this node
/// does not currently hold the archive (pruned, or the scheduler returned
/// MISS).
pub const CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE: i64 = -22;

/// The REST error envelope a natively-served endpoint answers with when it
/// cannot produce its reply (HTTP 500): `status` is never `OK`, and `error`
/// names what failed (diagnostic text — RK-D8 scope — not contract). The
/// transport sends the body whatever the HTTP status, so a client that wants
/// the reason decodes this when the success type does not fit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestErrorEnvelope {
    pub status: RpcStatus,
    pub error: String,
}

/// Response of `GET|POST /get_height` (alias `/getheight`). The request body
/// is empty (and ignored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetHeightResponse {
    pub status: RpcStatus,
    /// Chain height: the top block's height **plus one** (a chain holding
    /// only the genesis block reports `1`).
    pub height: u64,
    /// The top block's hash.
    pub hash: HashHex,
}

/// Result of the `get_block_count` JSON-RPC method (alias `getblockcount`).
/// Params are ignored, as the C++ handler ignored its positional list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockCountResponse {
    pub status: RpcStatus,
    /// Chain height — the block *count*, i.e. top block height plus one.
    pub count: u64,
}

/// Positional params of `on_get_block_hash` (alias `on_getblockhash`):
/// exactly one height, e.g. `[1234]`.
///
/// The arity and element type are the deserializer's job, not a hand-written
/// parser's: `[u64; 1]` refuses `[]`, `[1,2]`, `["1"]` and `[-1]` structurally,
/// and each of those is the method's `WRONG_PARAM` refusal.
///
/// The reply has no type of its own — `on_get_block_hash` answers with a bare
/// JSON string (the block hash as 64 lowercase hex characters), not an object,
/// and carries no `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHashParams(pub [u64; 1]);

/// The daemon's block header — the wire's `block_header_response`, shared by
/// every header-bearing method (RK-3 serves `get_block_header_by_height`;
/// `get_block`, `get_last_block_header`, `…_by_hash` and `…_range` reuse this
/// type as they migrate).
///
/// The 128-bit difficulties are carried the way the C++ wire carried them:
/// the low 64 bits as a number, the whole value as `0x`-prefixed minimal
/// lowercase hex, and the top 64 bits separately — three fields, one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_hash: HashHex,
    pub nonce: u32,
    pub orphan_status: bool,
    pub height: u64,
    /// Distance from the tip: `chain_height - height - 1`.
    pub depth: u64,
    pub hash: HashHex,
    /// Low 64 bits of the block's difficulty.
    pub difficulty: u64,
    /// The whole 128-bit difficulty, `0x`-prefixed minimal lowercase hex.
    pub wide_difficulty: String,
    /// High 64 bits of the block's difficulty.
    pub difficulty_top64: u64,
    pub cumulative_difficulty: u64,
    pub wide_cumulative_difficulty: String,
    pub cumulative_difficulty_top64: u64,
    /// Sum of the miner transaction's outputs.
    pub reward: u64,
    /// Always equal to `block_weight`; kept because the wire carries both,
    /// and unlike `block_weight` it is not omitted at zero.
    pub block_size: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub block_weight: u64,
    pub num_txes: u64,
    /// `None` unless the request asked for it **and** the listener is
    /// unrestricted. epee renders that absence as `""`, not as a missing
    /// field — see [`empty_string_as_absent`](crate::hash::empty_string_as_absent).
    #[serde(with = "crate::hash::empty_string_as_absent")]
    pub pow_hash: Option<HashHex>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub long_term_weight: u64,
    pub miner_tx_hash: HashHex,
    pub curve_tree_root: HashHex,
    pub attestation_root: HashHex,
}

/// Params of `get_block` (alias `getblock`).
///
/// Two ways to name one block. A non-empty `hash` wins and `height` is
/// ignored; with `hash` empty the block at `height` is returned, and absent
/// params mean height 0 — epee's KV load left both fields at their defaults.
///
/// `hash` is a `String`, not a [`HashHex`](crate::HashHex), on purpose
/// (RK-D12): typed, serde would reject a malformed hash into this method's
/// generic params refusal, where the handler can instead answer the specific
/// "Failed to parse hex representation of block hash. Hex = …" that names
/// what the caller actually sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockRequest {
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub fill_pow_hash: bool,
}

/// Response of `get_block` (alias `getblock`).
///
/// `miner_tx_hash` repeats the header's field of the same name — wire
/// duplication, preserved; RK-W's to retire.
///
/// `json` is epee's rendering of the whole block, produced in C++ and passed
/// through untouched (RK-D11). It duplicates `blob`, which carries the same
/// block in the consensus encoding, and both retire together in RK-W.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockResponse {
    pub status: RpcStatus,
    pub block_header: BlockHeader,
    pub miner_tx_hash: HashHex,
    /// Omitted entirely for a block with no transactions: epee drops an
    /// empty sequence from the document even though this member is a plain
    /// `KV_SERIALIZE`, not an OPT one (pinned by the `no_txes` vector).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_hashes: Vec<HashHex>,
    /// The block in its consensus encoding, lowercase hex.
    pub blob: String,
    pub json: String,
}

/// Params of `get_block_header_by_height` (alias `getblockheaderbyheight`).
///
/// Both fields default, reproducing epee's KV load: a field absent from the
/// request was left at its default rather than refused, so `{}` asks for
/// height 0. Making *that* strict is a wire change and belongs to RK-W.
///
/// Only absence defaults, though. epee also swallowed a field of the wrong
/// type — `KV_SERIALIZE` discards the load's result — and answered
/// `{"height": "nope"}` with the genesis header; the server refuses that
/// instead (`daemon_rpc::methods::block_header_request`), which is where the
/// object-only rule lives too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHeaderByHeightRequest {
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub fill_pow_hash: bool,
}

/// Result of `get_block_header_by_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHeaderByHeightResponse {
    pub status: RpcStatus,
    pub block_header: BlockHeader,
}

/// One row of [`GetVersionResponse::hard_forks`]: the version that activates
/// at `height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardForkEntry {
    pub hf_version: u8,
    pub height: u64,
}

/// Result of the `get_version` JSON-RPC method (no params).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetVersionResponse {
    pub status: RpcStatus,
    /// [`CORE_RPC_VERSION`] of the answering daemon.
    pub version: u32,
    /// Whether the daemon is a release build (`SHEKYL_VERSION_IS_RELEASE`).
    pub release: bool,
    /// Current chain height. Omitted on the wire when `0`
    /// (`KV_SERIALIZE_OPT(current_height, 0)`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub current_height: u64,
    /// Height the daemon is syncing towards; `0` — and omitted — once
    /// synchronized (`KV_SERIALIZE_OPT(target_height, 0)`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub target_height: u64,
    /// The hard-fork schedule. Omitted on the wire when empty
    /// (`KV_SERIALIZE_OPT(hard_forks, {})`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hard_forks: Vec<HardForkEntry>,

    // The three identity-tuple fields (VC-2). Each is MANDATORY and strict:
    // no `default`, no `Option`, no catch-all variant (VC-D14). `get_version`
    // is the call a client makes *before* it trusts anything, so on a remote
    // arm these are attacker-controlled bytes and an omitted field silently
    // becoming a zero value would turn "these disagree" into "these agree" —
    // the one outcome the identity check exists to prevent. The three
    // `KV_SERIALIZE_OPT` fields above keep their defaults because the C++
    // side genuinely omits them and the oracle vectors depend on it; the rule
    // is per-field on the tuple, not a sweep of the struct.
    /// Digest of the daemon's consensus-constant authorities
    /// ([`crate::CONSENSUS_CONSTANTS_DIGEST`]) — the **rules** axis.
    ///
    /// [`HashHex`] rather than `String` (`VC-R16`): it is a SHA-256, so 32
    /// bytes rendered as 64 hex characters, and the type refuses any other
    /// length or a non-hex character at the deserializer, accepts either
    /// case, and re-emits lowercase. A `String` would false-mismatch on an
    /// uppercase rendering of the same bytes and would admit "not a digest
    /// at all" as a legal value.
    pub consensus_constants_digest: HashHex,
    /// The network this daemon runs — the **network** axis.
    ///
    /// An unrecognised value is a deserialization error, never a default: a
    /// daemon reporting a network this build does not know is a daemon this
    /// build cannot vouch for.
    pub nettype: DaemonNetwork,
    /// Hash of block 0 — the **genesis** axis.
    ///
    /// Carried here rather than read from `on_get_block_hash([0])`
    /// (`VC-R2`): two calls can straddle a restart or a proxy fronting two
    /// nodes, so a client would pair a version from one daemon with a
    /// genesis from another and accept a tuple that never simultaneously
    /// existed. One reply, one snapshot.
    pub genesis_hash: HashHex,
}

/// The `n` of a `STORE_INVARIANT_REGISTER.md` `SI-n` row — the register's
/// stable name for a store belt, as the wire carries it.
///
/// Deliberately **not** `shekyl-chain-store::StoreInvariant`
/// (`DAEMON_REDB_STORE.md` §3.6.2; PR #751 disposition): this crate is
/// consumed by every wallet, and embedding the store's enum would make each
/// of them link the redb-backed store to decode a tip; and that enum gains a
/// variant each time an increment builds a belt, while the register's
/// numbering is append-only. The operator resolves the number against the
/// register — the one public authority on what each row means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoreInvariantRow(pub u32);

/// Whether the daemon's chain-store writer is live or halted
/// (`DAEMON_REDB_STORE.md` §3.6.2) — the halt a wallet must be able to see
/// before it refreshes against a chain that has moved on without it.
///
/// Minted with S-CHAIN-W, the only producer of the `Halted` arm
/// (`shekyl-chain-store::ConnectState` is the store-side value). Carried on
/// the tip (`ChainTip.connect`) when the Rust store serves `get_info` —
/// the `CORE_RPC_VERSION` minor bump lands with that field, not with these
/// types: the daemon still serves LMDB at this pin, and a version moves when
/// a wire shape does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectState {
    /// Connects and pops are accepted.
    Live,
    /// A connect or pop hit a store invariant; the writer refuses until
    /// restart, reads stay open.
    Halted {
        /// The height the halting connect or pop was working at.
        at_height: u64,
        /// The belt that caught it.
        row: StoreInvariantRow,
    },
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero(v: &u64) -> bool {
    *v == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_state_serializes_as_a_tagged_state_with_the_register_row_number() {
        let live = serde_json::to_string(&ConnectState::Live).expect("json");
        assert_eq!(live, r#"{"state":"live"}"#);
        let halted = ConnectState::Halted {
            at_height: 4_200,
            row: StoreInvariantRow(6),
        };
        let json = serde_json::to_string(&halted).expect("json");
        assert_eq!(json, r#"{"state":"halted","at_height":4200,"row":6}"#);
        let back: ConnectState = serde_json::from_str(&json).expect("round trip");
        assert_eq!(back, halted);
    }

    #[test]
    fn core_rpc_version_packs_like_the_cpp_macro() {
        // MAKE_CORE_RPC_VERSION(3, 29) == 0x0003_001D == 196637 (3.29:
        // `get_version` gains the three identity-tuple fields, VC-2; 3.28
        // the peer identifier leaving every readout, PWD-I1; 3.27 RK-5b's
        // three header-method shape changes; 3.26
        // `get_info.following_degraded`, C2-R1b F-1(a); 3.25 the RK-4c
        // `txs_as_hex`/`txs_as_json` removal). Captured vectors are never
        // edited to follow a constant — each bump mints a sibling vector —
        // so `assert_version_parity` compares every other field against
        // them and this pins the constant itself.
        //
        // Four spellings, and the last two are why. The literal catches a
        // bump that forgot this test; the packing expression catches a bump
        // that edited the literal without the fields it is made of; and the
        // two component assertions catch what actually happened between 3.26
        // and 3.27 — **two branches wrote the same new value for different
        // reasons and git merged the line clean**, because a one-line change
        // from 25 to 26 is textually identical whoever makes it. The minor
        // number is not a lock.
        assert_eq!(CORE_RPC_VERSION, 196_644);
        assert_eq!(CORE_RPC_VERSION, (3 << 16) | 36);
        assert_eq!(CORE_RPC_VERSION_MAJOR, 3);
        assert_eq!(CORE_RPC_VERSION_MINOR, 36);
    }

    #[test]
    fn error_envelope_round_trips() {
        let e = RestErrorEnvelope {
            status: RpcStatus("ERROR".to_owned()),
            error: "chain facts unavailable".to_owned(),
        };
        let wire = serde_json::to_string(&e).unwrap();
        assert_eq!(
            wire,
            r#"{"status":"ERROR","error":"chain facts unavailable"}"#
        );
        let back: RestErrorEnvelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, e);
        assert!(!back.status.is_ok());
    }

    /// The params type is the arity/type check: every shape the C++ handler
    /// answered `WRONG_PARAM` for is a deserialize failure here, and a valid
    /// `[height]` is the height. Widening the type (to `Vec<u64>`, say) turns
    /// the refusal cases green — which is the edit this guards.
    #[test]
    fn block_hash_params_accept_one_height_and_nothing_else() {
        let ok: GetBlockHashParams = serde_json::from_str("[1234]").unwrap();
        assert_eq!(ok.0[0], 1234);
        for bad in ["[]", "[1,2]", r#"["1"]"#, "[-1]", "1234", "{}", "null"] {
            assert!(
                serde_json::from_str::<GetBlockHashParams>(bad).is_err(),
                "{bad} must not parse as one height"
            );
        }
    }

    /// Absent fields take their defaults, as epee's KV load did — `{}` is a
    /// request for height 0, not a refusal.
    #[test]
    fn header_request_fields_default_like_the_kv_load() {
        let empty: GetBlockHeaderByHeightRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, GetBlockHeaderByHeightRequest::default());
        let only_height: GetBlockHeaderByHeightRequest =
            serde_json::from_str(r#"{"height":9}"#).unwrap();
        assert_eq!(only_height.height, 9);
        assert!(!only_height.fill_pow_hash);
    }

    #[test]
    fn status_is_transparent_on_the_wire() {
        assert_eq!(serde_json::to_string(&RpcStatus::ok()).unwrap(), r#""OK""#);
        let busy: RpcStatus = serde_json::from_str(r#""BUSY""#).unwrap();
        assert!(!busy.is_ok());
        assert_eq!(busy.0, RpcStatus::BUSY);
    }
}
