// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RK-1 parity against the C++ oracle (`docs/design/DAEMON_RPC_KV_CUTOVER.md`
//! §3.5, RK-D4).
//!
//! `vectors/rpc/*_v1.json` are epee's `store_t_to_json` output over the C++
//! response structs built from fixed facts, captured before those structs
//! were deleted (see the README beside them). Each test builds the Rust type
//! from the **same** fixed facts and asserts that serializing it yields a
//! document **parsed-equal** to the vector — key order and whitespace are
//! epee's, not the contract's, but every key, value and
//! `KV_SERIALIZE_OPT` omission is. The reverse direction (the vector
//! deserializes into the type, and round-trips) is asserted too, which is
//! what an existing client parsing a Rust-served reply relies on.

use serde_json::Value;
use shekyl_rpc_types::{
    BlockHeader, ConnectionInfo, ConnectionState, GetBlockCountResponse,
    GetBlockHeaderByHeightResponse, GetBlockResponse, GetConnectionsResponse, GetHeightResponse,
    GetNetStatsResponse, GetPeerListRequest, GetPeerListResponse, GetTransactionsRequest,
    GetTransactionsResponse, GetVersionResponse, HardForkEntry, HashHex, IsKeyImageSpentRequest,
    IsKeyImageSpentResponse, KeyImageStatus, Peer, RpcStatus, SyncInfoPeer, SyncInfoResponse,
    SyncSpan, TxEntry, TxLocation, CORE_RPC_VERSION,
};

/// The emitter's stand-ins for the two strings C++ still produces (RK-D11).
const BLOB_HEX: &str = "0101a1b2c3d4e5f60708";
const BLOCK_JSON: &str = "{\n  \"major_version\": 1, \n  \"nonce\": 305419896\n}";

/// The populated header the `full` and `by_hash` block vectors share.
fn block_vector_header(orphan: bool, pow: Option<HashHex>) -> BlockHeader {
    BlockHeader {
        major_version: 1,
        minor_version: 2,
        timestamp: 1_700_000_000,
        prev_hash: tagged_hash(3),
        nonce: 305_419_896,
        orphan_status: orphan,
        height: 1_234_567,
        depth: 42,
        hash: tagged_hash(11),
        difficulty: 12345,
        wide_difficulty: "0x400000000000003039".to_owned(),
        difficulty_top64: 64,
        cumulative_difficulty: 99,
        wide_cumulative_difficulty: "0x800000000000000063".to_owned(),
        cumulative_difficulty_top64: 128,
        reward: 600_000_000_000,
        block_size: 98765,
        block_weight: 98765,
        num_txes: 2,
        pow_hash: pow,
        long_term_weight: 87654,
        miner_tx_hash: tagged_hash(31),
        curve_tree_root: tagged_hash(41),
        attestation_root: tagged_hash(53),
    }
}

/// The emitter's `tagged_hash`: byte i = (i*7 + tag) & 0xff.
fn tagged_hash(tag: u8) -> HashHex {
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let i = u8::try_from(i).expect("32 fits u8");
        *byte = i.wrapping_mul(7).wrapping_add(tag);
    }
    HashHex::from_bytes(bytes)
}

fn parsed(json: &str) -> Value {
    serde_json::from_str(json).expect("vector / output is JSON")
}

/// Parity for `get_version`, whose `version` field is the one value a vector
/// cannot track.
///
/// `CORE_RPC_VERSION` moves whenever a wire shape changes — RK-4c's removal of
/// `txs_as_hex` / `txs_as_json` took it to 3.25 — while these vectors are
/// epee's output from RK-1, and the emitter that produced them was deleted
/// with `get_version`'s C++ handler. A vector is never hand-edited, so the
/// moving field is named here instead: everything else is compared against the
/// oracle byte-for-byte, and `version` is asserted against the constant
/// directly. Silently normalising both sides would have hidden a wrong
/// constant; asserting it is what keeps the bump deliberate.
fn assert_version_parity(vector: &str, built: &GetVersionResponse) {
    assert_eq!(
        built.version, CORE_RPC_VERSION,
        "the built reply must carry the current constant"
    );
    let mut ours = parsed(&serde_json::to_string(built).expect("serialize"));
    let mut theirs = parsed(vector);
    let historical = theirs
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .expect("the oracle vector carries a version");
    assert!(
        u64::from(CORE_RPC_VERSION) >= historical,
        "CORE_RPC_VERSION must never go backwards: {CORE_RPC_VERSION} < {historical}"
    );
    ours.as_object_mut().expect("object").remove("version");
    theirs.as_object_mut().expect("object").remove("version");
    assert_eq!(
        ours, theirs,
        "every field but `version` must still match the epee oracle"
    );
    let back: GetVersionResponse =
        serde_json::from_str(vector).expect("the oracle vector deserializes");
    assert_eq!(back.hard_forks, built.hard_forks);
    assert_eq!(back.current_height, built.current_height);
}

fn assert_parity<T>(vector: &str, built: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let ours = serde_json::to_string(built).expect("serialize");
    assert_eq!(
        parsed(&ours),
        parsed(vector),
        "Rust output is not parsed-equal to the epee oracle vector"
    );
    let back: T = serde_json::from_str(vector).expect("the oracle vector deserializes");
    assert_eq!(
        &back, built,
        "the oracle vector does not deserialize to the built value"
    );
}

#[test]
fn get_height_matches_the_oracle() {
    let built = GetHeightResponse {
        status: RpcStatus::ok(),
        height: 1_234_567,
        hash: tagged_hash(3),
    };
    assert_parity(include_str!("vectors/rpc/get_height_v1.json"), &built);
}

#[test]
fn get_version_synced_matches_the_oracle() {
    let built = GetVersionResponse {
        status: RpcStatus::ok(),
        version: CORE_RPC_VERSION,
        release: false,
        current_height: 1_234_567,
        target_height: 0,
        hard_forks: vec![HardForkEntry {
            hf_version: 1,
            height: 0,
        }],
    };
    assert_version_parity(
        include_str!("vectors/rpc/get_version_synced_v1.json"),
        &built,
    );
    // The OPT omission is on the wire, not only in the parse.
    assert!(!serde_json::to_string(&built)
        .unwrap()
        .contains("target_height"));
}

#[test]
fn get_version_syncing_matches_the_oracle() {
    let built = GetVersionResponse {
        status: RpcStatus::ok(),
        version: CORE_RPC_VERSION,
        release: true,
        current_height: 1000,
        target_height: 2_000_000,
        hard_forks: vec![
            HardForkEntry {
                hf_version: 1,
                height: 0,
            },
            HardForkEntry {
                hf_version: 2,
                height: 5000,
            },
        ],
    };
    assert_version_parity(
        include_str!("vectors/rpc/get_version_syncing_v1.json"),
        &built,
    );
}

#[test]
fn get_version_all_defaults_matches_the_oracle() {
    let built = GetVersionResponse {
        status: RpcStatus::ok(),
        version: CORE_RPC_VERSION,
        release: false,
        current_height: 0,
        target_height: 0,
        hard_forks: vec![],
    };
    assert_version_parity(
        include_str!("vectors/rpc/get_version_all_defaults_v1.json"),
        &built,
    );
    let wire = serde_json::to_string(&built).unwrap();
    for omitted in ["current_height", "target_height", "hard_forks"] {
        assert!(
            !wire.contains(omitted),
            "{omitted} must be omitted when default"
        );
    }
}

#[test]
fn get_block_count_matches_the_oracle() {
    let built = GetBlockCountResponse {
        status: RpcStatus::ok(),
        count: 1_234_567,
    };
    assert_parity(include_str!("vectors/rpc/get_block_count_v1.json"), &built);
}

/// `on_get_block_hash` answers with a bare JSON string — no object, no
/// `status` — so the "type" is `String` and the vector is that document.
/// Wrapping the reply in an object turns this red.
#[test]
fn get_block_hash_matches_the_oracle() {
    let built = tagged_hash(3);
    assert_parity(include_str!("vectors/rpc/get_block_hash_v1.json"), &built);
    assert!(
        parsed(include_str!("vectors/rpc/get_block_hash_v1.json")).is_string(),
        "the reply document is a lone JSON string"
    );
}

/// The full header: every field populated, a difficulty above 2^64, a filled
/// pow hash. Parsed-equal to what epee emitted from the same facts.
#[test]
fn block_header_full_matches_the_oracle() {
    let built = GetBlockHeaderByHeightResponse {
        status: RpcStatus::ok(),
        block_header: BlockHeader {
            major_version: 1,
            minor_version: 2,
            timestamp: 1_700_000_000,
            prev_hash: tagged_hash(3),
            nonce: 305_419_896,
            orphan_status: true,
            height: 1_234_567,
            depth: 42,
            hash: tagged_hash(11),
            difficulty: 12345,
            wide_difficulty: "0x400000000000003039".to_owned(),
            difficulty_top64: 64,
            cumulative_difficulty: 99,
            wide_cumulative_difficulty: "0x800000000000000063".to_owned(),
            cumulative_difficulty_top64: 128,
            reward: 600_000_000_000,
            block_size: 98765,
            block_weight: 98765,
            num_txes: 7,
            pow_hash: Some(tagged_hash(23)),
            long_term_weight: 87654,
            miner_tx_hash: tagged_hash(31),
            curve_tree_root: tagged_hash(41),
            attestation_root: tagged_hash(53),
        },
    };
    assert_parity(
        include_str!("vectors/rpc/get_block_header_by_height_full_v1.json"),
        &built,
    );
}

/// The defaults case pins the OPT asymmetry: `block_weight` and
/// `long_term_weight` are omitted at zero while `block_size` — filled from the
/// same source but not OPT — stays, and `pow_hash` is an empty string rather
/// than absent.
#[test]
fn block_header_defaults_matches_the_oracle() {
    let built = GetBlockHeaderByHeightResponse {
        status: RpcStatus::ok(),
        block_header: BlockHeader {
            major_version: 1,
            minor_version: 1,
            timestamp: 1_500_000_000,
            prev_hash: HashHex::ZERO,
            nonce: 0,
            orphan_status: false,
            height: 0,
            depth: 0,
            hash: tagged_hash(11),
            difficulty: 1,
            wide_difficulty: "0x1".to_owned(),
            difficulty_top64: 0,
            cumulative_difficulty: 1,
            wide_cumulative_difficulty: "0x1".to_owned(),
            cumulative_difficulty_top64: 0,
            reward: 0,
            block_size: 0,
            block_weight: 0,
            num_txes: 0,
            pow_hash: None,
            long_term_weight: 0,
            miner_tx_hash: tagged_hash(31),
            curve_tree_root: HashHex::ZERO,
            attestation_root: HashHex::ZERO,
        },
    };
    assert_parity(
        include_str!("vectors/rpc/get_block_header_by_height_defaults_v1.json"),
        &built,
    );
    let wire = serde_json::to_string(&built).unwrap();
    assert!(!wire.contains("block_weight"), "omitted at zero");
    assert!(!wire.contains("long_term_weight"), "omitted at zero");
    assert!(wire.contains("\"block_size\":0"), "kept at zero");
    assert!(wire.contains("\"pow_hash\":\"\""), "empty, not absent");
}

/// Numbers stay numbers: a client that typed `height` as an integer keeps
/// working (epee never quoted integers on this surface).
#[test]
fn integers_are_json_numbers() {
    let v = parsed(include_str!("vectors/rpc/get_height_v1.json"));
    assert!(v["height"].is_u64());
    let v = parsed(include_str!("vectors/rpc/get_version_syncing_v1.json"));
    assert!(v["version"].is_u64());
    assert!(v["hard_forks"][0]["hf_version"].is_u64());
}

/// A whole block: transactions, a filled pow hash, and `orphan_status` set —
/// the by-hash lookup can return an alt block, so that flag is a real value
/// here where RK-3's header method had it constant.
#[test]
fn get_block_full_matches_the_oracle() {
    let built = GetBlockResponse {
        status: RpcStatus::ok(),
        block_header: block_vector_header(true, Some(tagged_hash(23))),
        miner_tx_hash: tagged_hash(31),
        tx_hashes: vec![tagged_hash(61), tagged_hash(67)],
        blob: BLOB_HEX.to_owned(),
        json: BLOCK_JSON.to_owned(),
    };
    assert_parity(include_str!("vectors/rpc/get_block_full_v1.json"), &built);
}

/// The same reply reached by hash rather than by height. The lookup mode is
/// a request concern; a divergence in the reply would show up here.
#[test]
fn get_block_by_hash_matches_the_oracle() {
    let built = GetBlockResponse {
        status: RpcStatus::ok(),
        block_header: block_vector_header(false, None),
        miner_tx_hash: tagged_hash(31),
        tx_hashes: vec![tagged_hash(61), tagged_hash(67)],
        blob: BLOB_HEX.to_owned(),
        json: BLOCK_JSON.to_owned(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_block_by_hash_v1.json"),
        &built,
    );
}

/// A block with no transactions. epee drops an empty sequence from the
/// document even for a plain `KV_SERIALIZE` member, so `tx_hashes` must be
/// absent rather than `[]` — removing the `skip_serializing_if` turns this
/// red, and nothing in the C++ declaration would have warned us.
#[test]
fn get_block_without_transactions_omits_the_list() {
    let built = GetBlockResponse {
        status: RpcStatus::ok(),
        block_header: BlockHeader {
            major_version: 1,
            minor_version: 1,
            timestamp: 1_500_000_000,
            prev_hash: HashHex::ZERO,
            nonce: 0,
            orphan_status: false,
            height: 0,
            depth: 0,
            hash: tagged_hash(11),
            difficulty: 1,
            wide_difficulty: "0x1".to_owned(),
            difficulty_top64: 0,
            cumulative_difficulty: 1,
            wide_cumulative_difficulty: "0x1".to_owned(),
            cumulative_difficulty_top64: 0,
            reward: 0,
            block_size: 0,
            block_weight: 0,
            num_txes: 0,
            pow_hash: None,
            long_term_weight: 0,
            miner_tx_hash: tagged_hash(31),
            curve_tree_root: HashHex::ZERO,
            attestation_root: HashHex::ZERO,
        },
        miner_tx_hash: tagged_hash(31),
        tx_hashes: Vec::new(),
        blob: BLOB_HEX.to_owned(),
        json: BLOCK_JSON.to_owned(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_block_no_txes_v1.json"),
        &built,
    );
    let wire = serde_json::to_string(&built).expect("serialize");
    assert!(
        !wire.contains("tx_hashes"),
        "an empty transaction list is dropped, not emitted as []: {wire}"
    );
}

// ─── RK-4c: the transaction read set ─────────────────────────────────────────

/// The emitter's `tagged_hex` — `tagged_hash` rendered the way a request
/// carries it, since both request types take hashes as strings (RK-D12).
fn tagged_hex(tag: u8) -> String {
    tagged_hash(tag).to_string()
}

#[test]
fn get_transactions_request_matches_the_oracle() {
    let built = GetTransactionsRequest {
        txs_hashes: vec![tagged_hex(1), tagged_hex(2)],
        decode_as_json: true,
        prune: true,
        split: true,
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_request_v1.json"),
        &built,
    );
}

#[test]
fn get_transactions_request_defaults_matches_the_oracle() {
    let built = GetTransactionsRequest {
        txs_hashes: vec![tagged_hex(3)],
        decode_as_json: false,
        prune: false,
        split: false,
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_request_defaults_v1.json"),
        &built,
    );
}

#[test]
fn get_transactions_chain_and_pool_matches_the_oracle() {
    // The vector that pins `entry`'s branch: one mined entry and one pooled
    // one, so both field sets are in the same document. The emitter set the
    // *other* arm's members on each entry to non-default values, so a mirror
    // that emitted them would not be parsed-equal here.
    let mined = TxEntry {
        tx_hash: tagged_hash(11),
        as_hex: "0011223344".to_owned(),
        pruned_as_hex: String::new(),
        prunable_as_hex: String::new(),
        prunable_hash: tagged_hash(12),
        as_json: String::new(),
        pruned: false,
        double_spend_seen: false,
        location: TxLocation::Mined {
            block_height: 1_234_567,
            confirmations: 89,
            block_timestamp: 1_750_000_000,
            output_indices: vec![7, 8, 4_294_967_296],
        },
    };
    let pooled = TxEntry {
        tx_hash: tagged_hash(21),
        as_hex: "aabbcc".to_owned(),
        pruned_as_hex: String::new(),
        prunable_as_hex: String::new(),
        prunable_hash: tagged_hash(22),
        as_json: String::new(),
        pruned: false,
        double_spend_seen: true,
        location: TxLocation::Pooled {
            relayed: true,
            received_timestamp: 1_750_000_123,
        },
    };
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: vec![mined, pooled],
        missed_tx: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_chain_and_pool_v2.json"),
        &built,
    );
}

#[test]
fn get_transactions_split_form_matches_the_oracle() {
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: vec![TxEntry {
            tx_hash: tagged_hash(31),
            as_hex: String::new(),
            pruned_as_hex: "0102030405".to_owned(),
            prunable_as_hex: "0607".to_owned(),
            prunable_hash: tagged_hash(32),
            as_json: String::new(),
            pruned: true,
            double_spend_seen: false,
            location: TxLocation::Mined {
                block_height: 100,
                confirmations: 1,
                block_timestamp: 1_750_000_001,
                // Empty inside the chain arm: dropped like every other empty
                // sequence, which is what the vector proves.
                output_indices: Vec::new(),
            },
        }],
        missed_tx: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_split_form_v2.json"),
        &built,
    );
}

#[test]
fn get_transactions_decoded_matches_the_oracle() {
    let as_json = "{\"version\": 2, \"unlock_time\": 0}".to_owned();
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: vec![TxEntry {
            tx_hash: tagged_hash(41),
            as_hex: "00".to_owned(),
            pruned_as_hex: String::new(),
            prunable_as_hex: String::new(),
            prunable_hash: tagged_hash(42),
            as_json,
            pruned: false,
            double_spend_seen: false,
            location: TxLocation::Mined {
                block_height: 7,
                confirmations: 3,
                block_timestamp: 1_750_000_007,
                output_indices: vec![0],
            },
        }],
        missed_tx: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_decoded_v2.json"),
        &built,
    );
}

#[test]
fn get_transactions_missed_matches_the_oracle() {
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: Vec::new(),
        missed_tx: vec![tagged_hash(51), tagged_hash(52)],
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_missed_v2.json"),
        &built,
    );
}

#[test]
fn get_transactions_refusal_matches_the_oracle() {
    let built = GetTransactionsResponse {
        status: RpcStatus("Too many transactions requested in restricted mode".to_owned()),
        txs: Vec::new(),
        missed_tx: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_refusal_v2.json"),
        &built,
    );
}

#[test]
fn is_key_image_spent_request_matches_the_oracle() {
    let built = IsKeyImageSpentRequest {
        key_images: vec![tagged_hex(61), tagged_hex(62), tagged_hex(63)],
    };
    assert_parity(
        include_str!("vectors/rpc/is_key_image_spent_request_v1.json"),
        &built,
    );
}

#[test]
fn is_key_image_spent_matches_the_oracle() {
    let built = IsKeyImageSpentResponse {
        status: RpcStatus::ok(),
        spent_status: vec![
            KeyImageStatus::Unspent,
            KeyImageStatus::SpentInBlockchain,
            KeyImageStatus::SpentInPool,
        ],
    };
    assert_parity(
        include_str!("vectors/rpc/is_key_image_spent_v1.json"),
        &built,
    );
}

#[test]
fn is_key_image_spent_empty_matches_the_oracle() {
    let built = IsKeyImageSpentResponse {
        status: RpcStatus::ok(),
        spent_status: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/is_key_image_spent_empty_v1.json"),
        &built,
    );
}

/// The `txs_as_hex` / `txs_as_json` retirement, asserted as a difference.
///
/// The `_v1` vectors are the shape the C++ served before rule 60 removed those
/// two members; `_v2` is what the same emitter produced after. Keeping both and
/// asserting the difference is what makes the deletion checkable: re-adding
/// either member to the Rust type fails the `_v2` parity tests above, and
/// changing anything *else* in the reply fails this one. A `_v2` file alone
/// would only say what the shape is now, not what was removed to get there.
///
/// Per-vector presence is not asserted, because it is not true: epee omits an
/// empty sequence, so `txs_as_json` appears only in the fixture that asked for
/// `decode_as_json`. What is asserted is that across the set each retired
/// member was actually exercised — otherwise this test could pass while
/// silently checking the removal of only one of them.
/// **`get_version`'s v2 differs from v1 by exactly the version constant.**
///
/// `CORE_RPC_VERSION` moved to Rust, so this field can no longer be
/// re-captured from C++ — which is precisely why the pair is asserted rather
/// than the v2 file trusted. `get_transactions` dropping two members is a wire
/// change, the constant records it (3.24 → 3.25), and this pins that the
/// recording touched nothing else in the reply.
/// **An unknown field on the read surface is refused, not ignored.**
///
/// The tolerance these types used to carry was justified by "additive
/// daemon-side evolution must not break an older wallet" — a constraint this
/// tree does not have, since there is no network and every client ships with
/// the daemon. What it bought instead was a *renamed* field arriving unnoticed
/// while the name we look for defaults, which is a wrong value wearing the
/// shape of a legitimate one.
///
/// The second half is the one that matters and the one a future edit is most
/// likely to undo: the same document **without** the stray field must still
/// parse, so this pins a refusal of the unknown rather than a refusal of
/// everything.
#[test]
fn an_unknown_field_is_refused_on_the_read_surface() {
    use shekyl_rpc_types::{GetHeightResponse, GetTransactionsResponse};

    let good = r#"{"status":"OK","height":7,"hash":"ab"}"#
        .replace("\"ab\"", &format!("\"{}\"", "ab".repeat(32)));
    serde_json::from_str::<GetHeightResponse>(&good).expect("the modelled document parses");

    let with_extra = good.replace("{\"status\"", "{\"heightt\":7,\"status\"");
    let err = serde_json::from_str::<GetHeightResponse>(&with_extra)
        .expect_err("a field this type does not model must be refused");
    assert!(
        format!("{err}").contains("unknown field"),
        "the refusal must name the unknown field: {err}"
    );

    // And on the transactions surface the wallet's proofs path reads.
    let txs = r#"{"status":"OK","txs":[],"missed_tx":[],"surprise":1}"#;
    assert!(
        serde_json::from_str::<GetTransactionsResponse>(txs).is_err(),
        "an unmodelled field must not be ignored on a reply that feeds proofs"
    );
}

/// **A request this tree sends omits its empty sequences, as epee does.**
///
/// The omission rule is the wire's, not the response types' — a client that
/// emits `"txs_hashes":[]` where epee emits nothing has diverged from the
/// captured shape just as surely as a server would. Both directions are
/// asserted, because `skip_serializing_if` silently does nothing if the field
/// is later given a non-`Vec` type or the attribute is dropped.
#[test]
fn request_sequences_are_omitted_when_empty_and_present_when_not() {
    use shekyl_rpc_types::{GetTransactionsRequest, IsKeyImageSpentRequest};

    let empty = serde_json::to_value(GetTransactionsRequest::default()).unwrap();
    assert!(
        empty.get("txs_hashes").is_none(),
        "an empty txs_hashes must be omitted, not emitted as []: {empty}"
    );
    let filled = serde_json::to_value(GetTransactionsRequest {
        txs_hashes: vec!["ab".repeat(32)],
        ..Default::default()
    })
    .unwrap();
    assert!(
        filled.get("txs_hashes").is_some(),
        "a non-empty txs_hashes must still be carried: {filled}"
    );

    let empty = serde_json::to_value(IsKeyImageSpentRequest::default()).unwrap();
    assert!(
        empty.get("key_images").is_none(),
        "an empty key_images must be omitted, not emitted as []: {empty}"
    );
    let filled = serde_json::to_value(IsKeyImageSpentRequest {
        key_images: vec!["cd".repeat(32)],
    })
    .unwrap();
    assert!(
        filled.get("key_images").is_some(),
        "a non-empty key_images must still be carried: {filled}"
    );
}

#[test]
fn get_version_v3_is_v2_with_only_the_version_bumped() {
    // The live pair tracks the LATEST bump (3.26, C2-R1b's
    // `following_degraded`); each earlier pair's record is the vector
    // files themselves plus git history — the previous instance of this
    // test compared v1 to v2 for the 3.25 bump.
    let mut before = parsed(include_str!("vectors/rpc/get_version_synced_v2.json"));
    let after = parsed(include_str!("vectors/rpc/get_version_synced_v3.json"));

    let old = before
        .as_object_mut()
        .expect("v2 vector is an object")
        .insert(
            "version".to_string(),
            serde_json::json!(shekyl_rpc_types::CORE_RPC_VERSION),
        )
        .expect("v2 carries a version");

    assert_ne!(
        old,
        serde_json::json!(shekyl_rpc_types::CORE_RPC_VERSION),
        "v2 already carries the current constant — the pair has nothing to record"
    );
    assert_eq!(
        before, after,
        "v3 must differ from v2 by exactly CORE_RPC_VERSION"
    );
}

#[test]
fn v2_is_v1_minus_exactly_the_two_retired_members() {
    const RETIRED: [&str; 2] = ["txs_as_hex", "txs_as_json"];
    let mut seen = [false; 2];
    for (v1, v2) in [
        (
            include_str!("vectors/rpc/get_transactions_chain_and_pool_v1.json"),
            include_str!("vectors/rpc/get_transactions_chain_and_pool_v2.json"),
        ),
        (
            include_str!("vectors/rpc/get_transactions_decoded_v1.json"),
            include_str!("vectors/rpc/get_transactions_decoded_v2.json"),
        ),
        (
            include_str!("vectors/rpc/get_transactions_split_form_v1.json"),
            include_str!("vectors/rpc/get_transactions_split_form_v2.json"),
        ),
    ] {
        let mut before = parsed(v1);
        let after = parsed(v2);
        let obj = before.as_object_mut().expect("v1 vector is an object");
        for (i, key) in RETIRED.iter().enumerate() {
            if obj.remove(*key).is_some() {
                seen[i] = true;
            }
        }
        assert_eq!(
            before, after,
            "v2 must differ from v1 by exactly the retired members"
        );
    }
    assert!(
        seen.iter().all(|s| *s),
        "each retired member must appear in at least one v1 vector, or its \
         removal is not actually being checked: {RETIRED:?} seen = {seen:?}"
    );
}

// ── RK-5a: the p2p seam ─────────────────────────────────────────────────────

/// The `connection_info` both `get_connections` and `sync_info` carry, built
/// from the same fixed facts the emitter used.
fn vector_connection() -> ConnectionInfo {
    ConnectionInfo {
        incoming: true,
        localhost: false,
        local_ip: true,
        address: "192.0.2.7:18080".to_owned(),
        host: "192.0.2.7".to_owned(),
        ip: "192.0.2.7".to_owned(),
        port: "18080".to_owned(),
        peer_id: "ee32594917a6a97e".to_owned(),
        recv_count: 405,
        recv_idle_time: 2,
        send_count: 338,
        send_idle_time: 3,
        state: ConnectionState::Normal,
        live_time: 4242,
        avg_download: 11,
        current_download: 12,
        avg_upload: 13,
        current_upload: 14,
        support_flags: 3,
        connection_id: "151c232a31383f464d545b626970777e".to_owned(),
        height: 1_234_567,
        pruning_seed: 384,
        address_type: 1,
    }
}

#[test]
fn get_net_stats_matches_the_oracle() {
    let built = GetNetStatsResponse {
        status: RpcStatus::ok(),
        start_time: 1_788_202_424,
        total_packets_in: 101,
        total_bytes_in: 202_020,
        total_packets_out: 303,
        total_bytes_out: 404_040,
    };
    assert_parity(include_str!("vectors/rpc/get_net_stats_v1.json"), &built);
}

#[test]
fn get_peer_list_request_matches_the_oracle() {
    let built = GetPeerListRequest {
        public_only: false,
        include_blocked: true,
    };
    assert_parity(
        include_str!("vectors/rpc/get_peer_list_request_v1.json"),
        &built,
    );
}

/// `public_only` is the one `OPT` default in this slice that is **true**, so
/// the defaults document is empty of members rather than carrying
/// `public_only: true`. A mirror that defaulted it to false would emit a key
/// the daemon never emitted and, worse, would ask for a different peerlist.
#[test]
fn get_peer_list_request_defaults_match_the_oracle() {
    let built = GetPeerListRequest::default();
    assert!(built.public_only, "the wire default is public-only");
    assert_parity(
        include_str!("vectors/rpc/get_peer_list_request_defaults_v1.json"),
        &built,
    );
    assert_eq!(
        parsed(include_str!(
            "vectors/rpc/get_peer_list_request_defaults_v1.json"
        ))
        .as_object()
        .expect("object")
        .len(),
        0,
        "both members are optional at their defaults"
    );
}

/// The three address arms in one document, and both `pruning_seed` states.
#[test]
fn get_peer_list_matches_the_oracle() {
    let built = GetPeerListResponse {
        status: RpcStatus::ok(),
        white_list: vec![
            // ipv4: `host` is the ip string the daemon rendered from `ip`.
            Peer {
                id: 0x1122_3344_5566_7788,
                host: "10.32.0.7".to_owned(),
                ip: 0x0700_200a,
                port: 18080,
                last_seen: 1_750_000_001,
                pruning_seed: 0,
            },
            // ipv6: `host` is the bare host, `ip` stays zero, and this is the
            // pruned entry — so `pruning_seed` appears here and nowhere else.
            Peer {
                id: 0x99aa_bbcc_ddee_ff00,
                host: "2001:db8::1".to_owned(),
                ip: 0,
                port: 18081,
                last_seen: 1_750_000_002,
                pruning_seed: 384,
            },
        ],
        gray_list: vec![Peer {
            id: 0x0102_0304_0506_0708,
            host: "abcdefghijklmnop.onion:18080".to_owned(),
            ip: 0,
            port: 0,
            last_seen: 1_750_000_003,
            pruning_seed: 0,
        }],
    };
    assert_parity(include_str!("vectors/rpc/get_peer_list_v1.json"), &built);

    // `ip` is a JSON *number* here. `get_connections` carries a field of the
    // same name that is a *string*, and the pair of assertions is what keeps
    // a future edit from unifying them.
    let doc = parsed(include_str!("vectors/rpc/get_peer_list_v1.json"));
    assert!(
        doc["white_list"][0]["ip"].is_number(),
        "peer.ip is a number"
    );
}

/// What an idle daemon answers: both sequences omitted, not `[]`.
#[test]
fn get_peer_list_empty_matches_the_oracle() {
    let built = GetPeerListResponse {
        status: RpcStatus::ok(),
        white_list: Vec::new(),
        gray_list: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_peer_list_empty_v1.json"),
        &built,
    );
    let doc = parsed(include_str!("vectors/rpc/get_peer_list_empty_v1.json"));
    let obj = doc.as_object().expect("object");
    assert!(!obj.contains_key("white_list") && !obj.contains_key("gray_list"));
}

#[test]
fn get_connections_matches_the_oracle() {
    let built = GetConnectionsResponse {
        status: RpcStatus::ok(),
        connections: vec![vector_connection()],
    };
    assert_parity(include_str!("vectors/rpc/get_connections_v1.json"), &built);

    let doc = parsed(include_str!("vectors/rpc/get_connections_v1.json"));
    let entry = doc["connections"][0].as_object().expect("object");
    // `ip` is a string here — the counterpart of the `peer.ip` assertion.
    assert!(entry["ip"].is_string(), "connection_info.ip is a string");
    // `ssl` is a C++ member with no `KV_SERIALIZE` row, so it never reached
    // the wire. The emitter set it **true** on the object it captured, which
    // is what makes this an assertion rather than a coincidence: had the
    // field been serialized, it would be here and non-default.
    assert!(
        !entry.contains_key("ssl"),
        "`ssl` was never on the wire and is not being reintroduced"
    );
}

#[test]
fn get_connections_empty_matches_the_oracle() {
    let built = GetConnectionsResponse {
        status: RpcStatus::ok(),
        connections: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_connections_empty_v1.json"),
        &built,
    );
}

#[test]
fn sync_info_matches_the_oracle() {
    let built = SyncInfoResponse {
        status: RpcStatus::ok(),
        height: 1_234_567,
        target_height: 1_234_600,
        next_needed_pruning_seed: 1,
        peers: vec![SyncInfoPeer {
            info: vector_connection(),
        }],
        spans: vec![SyncSpan {
            start_block_height: 1_234_570,
            nblocks: 20,
            connection_id: "151c232a31383f464d545b626970777e".to_owned(),
            rate: 4096,
            speed: 75,
            size: 81920,
            remote_address: "192.0.2.7:18080".to_owned(),
        }],
        overview: "[<...m_o]".to_owned(),
    };
    assert_parity(include_str!("vectors/rpc/sync_info_v1.json"), &built);

    // The nesting is the wire's: a `sync_info` peer wraps the connection
    // under `info`, where `get_connections` carries it directly.
    let doc = parsed(include_str!("vectors/rpc/sync_info_v1.json"));
    assert_eq!(
        doc["peers"][0].as_object().expect("object").len(),
        1,
        "a sync_info peer has exactly the one `info` member"
    );
    assert_eq!(
        doc["peers"][0]["info"],
        parsed(&serde_json::to_string(&vector_connection()).expect("serialize"))
    );
}

/// The idle case. `overview` is a **string** holding brackets, not an empty
/// array — the one field in this reply where the two are easy to confuse.
#[test]
fn sync_info_empty_matches_the_oracle() {
    let built = SyncInfoResponse {
        status: RpcStatus::ok(),
        height: 1,
        target_height: 0,
        next_needed_pruning_seed: 1,
        peers: Vec::new(),
        spans: Vec::new(),
        overview: "[]".to_owned(),
    };
    assert_parity(include_str!("vectors/rpc/sync_info_empty_v1.json"), &built);
    let doc = parsed(include_str!("vectors/rpc/sync_info_empty_v1.json"));
    assert!(doc["overview"].is_string(), "overview is a string");
    let obj = doc.as_object().expect("object");
    assert!(!obj.contains_key("peers") && !obj.contains_key("spans"));
}
