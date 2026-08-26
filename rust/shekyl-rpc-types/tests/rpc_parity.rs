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
    BlockHeader, GetBlockCountResponse, GetBlockHeaderByHeightResponse, GetBlockResponse,
    GetHeightResponse, GetTransactionsRequest, GetTransactionsResponse, GetVersionResponse,
    HardForkEntry, HashHex, IsKeyImageSpentRequest, IsKeyImageSpentResponse, KeyImageStatus,
    RpcStatus, TxEntry, TxLocation, CORE_RPC_VERSION,
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
    assert_parity(
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
    assert_parity(
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
    assert_parity(
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
        txs_as_hex: vec![mined.as_hex.clone(), pooled.as_hex.clone()],
        txs_as_json: Vec::new(),
        txs: vec![mined, pooled],
        missed_tx: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_chain_and_pool_v1.json"),
        &built,
    );
}

#[test]
fn get_transactions_split_form_matches_the_oracle() {
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs_as_hex: vec![String::new()],
        txs_as_json: Vec::new(),
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
        include_str!("vectors/rpc/get_transactions_split_form_v1.json"),
        &built,
    );
}

#[test]
fn get_transactions_decoded_matches_the_oracle() {
    let as_json = "{\"version\": 2, \"unlock_time\": 0}".to_owned();
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs_as_hex: vec!["00".to_owned()],
        txs_as_json: vec![as_json.clone()],
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
        include_str!("vectors/rpc/get_transactions_decoded_v1.json"),
        &built,
    );
}

#[test]
fn get_transactions_missed_matches_the_oracle() {
    let built = GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs_as_hex: Vec::new(),
        txs_as_json: Vec::new(),
        txs: Vec::new(),
        missed_tx: vec![tagged_hash(51), tagged_hash(52)],
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_missed_v1.json"),
        &built,
    );
}

#[test]
fn get_transactions_refusal_matches_the_oracle() {
    let built = GetTransactionsResponse {
        status: RpcStatus("Too many transactions requested in restricted mode".to_owned()),
        txs_as_hex: Vec::new(),
        txs_as_json: Vec::new(),
        txs: Vec::new(),
        missed_tx: Vec::new(),
    };
    assert_parity(
        include_str!("vectors/rpc/get_transactions_refusal_v1.json"),
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
