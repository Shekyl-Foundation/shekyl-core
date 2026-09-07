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
    GetBlockHeaderByHashResponse, GetBlockHeaderByHeightResponse, GetBlockHeadersRangeResponse,
    GetBlockResponse, GetConnectionsResponse, GetHeightResponse, GetLastBlockHeaderResponse,
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

/// Every JSON vector is LF, and stays LF.
///
/// **The CRLF fidelity requirement was retired deliberately, not lost.** The
/// `_v1` files are epee's output and cannot be recaptured once a slice
/// deletes the C++ that produced them, so their bytes were kept exact as a
/// matter of provenance. But `RK-D4` states that whitespace is not part of
/// the wire contract, the parity suite compares *parsed* values, and `RK-W`
/// will redesign this wire on purpose — so nothing read those bytes as bytes,
/// and the property had no consumer. A tool normalising them was caught in
/// review, restored, and guarded; the guard was then defending a distinction
/// the project had no use for. Ruled 2026-09-05: normalise, and say so.
///
/// What is worth guarding is the opposite direction. `.gitattributes` marks
/// this directory `-text`, which stops **git** rewriting EOL — necessary for
/// the `.bin` vectors, where bytes *are* the contract — and which therefore
/// also means git will not normalise a CRLF that a Windows editor introduces.
/// This keeps the directory from drifting back, and it needs no exception
/// list: all JSON here is LF, with no "except these four".
///
/// `.bin` vectors are untouched by this: they have no line endings, their
/// bytes are the contract, and their own harnesses compare them byte for
/// byte.
#[test]
fn json_vectors_are_lf() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/rpc");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("vectors/rpc exists") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .expect("file name")
            .to_str()
            .expect("utf-8 name")
            .to_owned();
        if !name.ends_with(".json") {
            continue;
        }
        seen += 1;
        let bytes = std::fs::read(&path).expect("readable vector");
        assert!(
            !bytes.windows(2).any(|w| w == b"\r\n"),
            "{name} carries CRLF. `.gitattributes` marks this directory \
             `-text` for the sake of the `.bin` vectors, so git will not \
             normalise this for you — the JSON vectors are LF by ruling \
             (2026-09-05), and an editor reintroduced it"
        );
    }
    // A gate must assert its own subject exists (rule 47): a moved directory
    // or a broken glob would otherwise pass by walking nothing.
    assert!(
        seen > 30,
        "walked only {seen} JSON vectors; the glob is wrong"
    );
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

/// The whole `get_version` vector chain, not just its newest pair.
///
/// **This used to pin one pair and was renamed at each bump**, on the
/// reasoning that "each earlier pair's record is the vector files themselves
/// plus git history". RK-5b's merge showed what that leaves unguarded: this
/// branch bumped `_v2` from 196633 to 196634 for a 3.26 it drafted, `dev`
/// independently minted `_v3` at 196634 for a *different* 3.26, and the merge
/// took both — leaving `_v2` and `_v3` carrying the same number with no test
/// able to see it, because a one-pair test overwrites the `version` field
/// before comparing. The chain is the subject; every link is now checked.
///
/// A bump adds a file and a row here. It does not rename this test.
#[test]
fn the_get_version_chain_differs_by_exactly_the_version_at_every_link() {
    // One row per bump, oldest first. Each is (the vector before the bump,
    // the vector after it).
    let links: [(&str, &str); 4] = [
        (
            include_str!("vectors/rpc/get_version_synced_v1.json"),
            include_str!("vectors/rpc/get_version_synced_v2.json"),
        ),
        (
            include_str!("vectors/rpc/get_version_synced_v2.json"),
            include_str!("vectors/rpc/get_version_synced_v3.json"),
        ),
        (
            include_str!("vectors/rpc/get_version_synced_v3.json"),
            include_str!("vectors/rpc/get_version_synced_v4.json"),
        ),
        (
            include_str!("vectors/rpc/get_version_synced_v4.json"),
            include_str!("vectors/rpc/get_version_synced_v5.json"),
        ),
    ];

    let version_of = |raw: &str| -> u64 {
        parsed(raw)
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .expect("every get_version vector carries a version")
    };

    let mut previous_after: Option<&str> = None;
    for (i, (before_raw, after_raw)) in links.iter().enumerate() {
        let (lo, hi) = (version_of(before_raw), version_of(after_raw));
        assert!(
            hi > lo,
            "link {i}: the version must increase across a bump ({lo} -> {hi})"
        );
        // **Contiguity is document identity, not an ordering.** The first
        // draft asserted `lo > previous_version`, which only says the
        // sequence increases — a chain with a vector left out of `links`
        // passes that happily, and a vector left out is exactly what this
        // test exists to catch. Each link's *before* must be the previous
        // link's *after*: the same document, not merely a larger number.
        if let Some(previous) = previous_after {
            assert_eq!(
                parsed(previous),
                parsed(before_raw),
                "link {i}: its `before` is not the previous link's `after` — \
                 a vector is missing from the chain"
            );
        }
        previous_after = Some(after_raw);

        // The pair differs by the version and by nothing else.
        let mut before = parsed(before_raw);
        before
            .as_object_mut()
            .expect("vector is an object")
            .insert("version".to_string(), serde_json::json!(hi));
        assert_eq!(
            before,
            parsed(after_raw),
            "link {i}: the newer vector must be the older one with only the \
             version changed"
        );
    }

    // And the head of the chain is what the daemon actually emits today. This
    // is the assertion that would have caught two branches claiming one
    // number: whichever landed second would find the head already taken.
    assert_eq!(
        version_of(links[links.len() - 1].1),
        u64::from(shekyl_rpc_types::CORE_RPC_VERSION),
        "the newest vector must carry the current CORE_RPC_VERSION"
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
                host: "10.32.0.7".to_owned(),
                ip: 0x0700_200a,
                port: 18080,
                last_seen: 1_750_000_001,
                pruning_seed: 0,
            },
            // ipv6: `host` is the bare host, `ip` stays zero, and this is the
            // pruned entry — so `pruning_seed` appears here and nowhere else.
            Peer {
                host: "2001:db8::1".to_owned(),
                ip: 0,
                port: 18081,
                last_seen: 1_750_000_002,
                pruning_seed: 384,
            },
        ],
        gray_list: vec![Peer {
            host: "abcdefghijklmnop.onion:18080".to_owned(),
            ip: 0,
            port: 0,
            last_seen: 1_750_000_003,
            pruning_seed: 0,
        }],
    };
    // _v2 = _v1 minus the identifier fields 3.28 removed (PWD-I1) — derived,
    // not recaptured: the C++ oracle for this method is gone (RK-5a), so the
    // chain's memory continues from the Rust emitter's own prior contract.
    assert_parity(include_str!("vectors/rpc/get_peer_list_v2.json"), &built);

    // `ip` is a JSON *number* here. `get_connections` carries a field of the
    // same name that is a *string*, and the pair of assertions is what keeps
    // a future edit from unifying them.
    let doc = parsed(include_str!("vectors/rpc/get_peer_list_v2.json"));
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
    assert_parity(include_str!("vectors/rpc/get_connections_v2.json"), &built);

    let doc = parsed(include_str!("vectors/rpc/get_connections_v2.json"));
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
    assert_parity(include_str!("vectors/rpc/sync_info_v2.json"), &built);

    // The nesting is the wire's: a `sync_info` peer wraps the connection
    // under `info`, where `get_connections` carries it directly.
    let doc = parsed(include_str!("vectors/rpc/sync_info_v2.json"));
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

// ── RK-5b: the header remainder, and four deliberate divergences ────────────
//
// **A green parity run here does NOT mean "Rust matches C++".** Three of these
// methods change shape at 3.27, so their `_v1` captures are the *before* half
// of a pair and the `_v2` files are what the daemon emits now. Each `_v2` is
// held honest by a delta test below that **re-derives it from `_v1`**, so a
// hand-edited `_v2` fails rather than passing as its own authority.
//
// The denominator, stated rather than implied. Compared against `_v1`
// directly: `get_last_block_header`, `get_block_headers_range` — those two do
// not diverge. Compared against `_v2` only, with the delta pinned separately:
// `get_block_header_by_hash` (request and response), `hard_fork_info`,
// `get_fee_estimate`. No field is excluded from an equality without its own
// positive assertion in one of the delta tests, which is the thing that makes
// "excluded" different from "forgotten".

fn vector_header_v(tag: u8, orphan: bool) -> BlockHeader {
    BlockHeader {
        orphan_status: orphan,
        hash: tagged_hash(tag),
        ..block_vector_header(orphan, None)
    }
}

#[test]
fn get_last_block_header_matches_the_oracle() {
    let built = GetLastBlockHeaderResponse {
        status: RpcStatus::ok(),
        block_header: vector_header_v(11, false),
    };
    assert_parity(
        include_str!("vectors/rpc/get_last_block_header_v1.json"),
        &built,
    );
}

#[test]
fn get_block_headers_range_matches_the_oracle() {
    let built = GetBlockHeadersRangeResponse {
        status: RpcStatus::ok(),
        headers: vec![vector_header_v(11, false), vector_header_v(12, false)],
    };
    assert_parity(
        include_str!("vectors/rpc/get_block_headers_range_v1.json"),
        &built,
    );
}

/// **Subtraction.** The request `_v2` is `_v1` minus exactly the singular
/// `hash`, and nothing else moves.
#[test]
fn by_hash_request_v2_is_v1_minus_exactly_the_singular_hash() {
    let mut derived = parsed(include_str!(
        "vectors/rpc/get_block_header_by_hash_request_v1.json"
    ));
    let removed = derived
        .as_object_mut()
        .expect("object")
        .remove("hash")
        .expect("`_v1` must carry the field `_v2` retires");
    assert!(
        removed.is_string(),
        "the retired field was the singular hash"
    );
    assert_eq!(
        derived,
        parsed(include_str!(
            "vectors/rpc/get_block_header_by_hash_request_v2.json"
        )),
        "the request `_v2` must differ from `_v1` by that field and nothing else"
    );
}

/// **Transform, not subtraction.** `block_headers` becomes per-element slots,
/// which no removal from `_v1` produces — so the delta is written as code:
/// slot *i* carries `_v1`'s header *i* and that header's own hash, and the
/// singular `block_header` the C++ always emitted goes.
#[test]
fn by_hash_v2_is_v1_reshaped_into_slots() {
    let v1 = parsed(include_str!("vectors/rpc/get_block_header_by_hash_v1.json"));
    let headers = v1["block_headers"].as_array().expect("array");
    let slots: Vec<Value> = headers
        .iter()
        .map(|h| serde_json::json!({ "hash": h["hash"], "block_header": h }))
        .collect();
    let derived = serde_json::json!({ "status": v1["status"], "block_headers": slots });
    assert_eq!(
        derived,
        parsed(include_str!("vectors/rpc/get_block_header_by_hash_v2.json")),
        "`_v2` must be `_v1` reshaped, not authored"
    );
    assert!(
        v1.get("block_header").is_some(),
        "`_v1` carried a singular header that `_v2` drops; if it did not, this \
         delta would be describing a field that never existed"
    );
}

/// The missing-slot vector is **derived** from the regular `_v2`, not
/// authored beside it.
///
/// **This test stated that invariant and did not hold its own vector to it.**
/// It checked the slot count, which slot was empty, and that the document
/// deserialized — so an edit to `status`, to either present header, to any
/// echoed hash, or to the missing slot's own hash all stayed green. A vector
/// nothing derives is a vector standing as its own authority, which is the
/// one thing the `_v2` discipline exists to prevent.
///
/// **The transform is insertion, not subtraction**, and writing it out is
/// what made that clear: the vector is the regular `_v2` *plus* a slot for
/// one more hash the chain does not hold. That extra hash is the one datum
/// no transform can produce from `_v2`, so it is named here — the same
/// "transform plus a named extension" shape the README records for
/// `by_hash_v2_is_v1_reshaped_into_slots`. Everything else must be untouched,
/// and the comparison is exact rather than field-by-field, so a field added
/// to `BlockHeaderSlot` later is covered without anyone remembering to.
#[test]
fn a_missing_slot_is_the_case_v1_could_not_express() {
    /// The hash the chain does not hold. Not derivable from `_v2` — it is
    /// the input that makes this case exist — so it is stated once, here.
    const ABSENT: &str = "c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1";

    let mut derived = parsed(include_str!("vectors/rpc/get_block_header_by_hash_v2.json"));
    let slots = derived["block_headers"]
        .as_array_mut()
        .expect("v2 carries slots");
    assert_eq!(
        slots.len(),
        2,
        "the transform inserts into a two-slot reply"
    );
    slots.insert(1, serde_json::json!({ "hash": ABSENT }));

    let authored = parsed(include_str!(
        "vectors/rpc/get_block_header_by_hash_missing_v2.json"
    ));
    assert_eq!(
        derived, authored,
        "the missing-slot vector must be `_v2` with exactly one absent-hash \
         slot inserted — anything else in it is unaccounted for"
    );

    // And the property the vector exists to record: a miss costs only its own
    // slot, which the all-or-nothing C++ could not have produced a vector for
    // at all.
    let round_trip: GetBlockHeaderByHashResponse =
        serde_json::from_value(authored).expect("the missing-slot shape parses");
    assert_eq!(round_trip.block_headers.len(), 3);
    assert!(round_trip.block_headers[1].block_header.is_none());
    assert!(
        round_trip.block_headers[0].block_header.is_some()
            && round_trip.block_headers[2].block_header.is_some()
    );
}

/// **Rename plus one addition.** `version` becomes `active_version`, and
/// `queried_version` is information `_v1` does not contain — the C++ never
/// reported what the caller asked about — so its value is asserted rather than
/// derived.
#[test]
fn hard_fork_v2_renames_version_and_adds_the_query() {
    let v1 = parsed(include_str!("vectors/rpc/hard_fork_info_v1.json"));
    let v2 = parsed(include_str!("vectors/rpc/hard_fork_info_v2.json"));

    let queried = v2["queried_version"].as_u64().expect("the added field");
    assert_eq!(
        v2["active_version"], v1["version"],
        "the old `version` is the ACTIVE one — that was the collision"
    );
    assert_ne!(
        queried,
        v1["version"].as_u64().expect("v1 version"),
        "the vector deliberately uses different numbers, so a reply that \
         confused the two would not pass by coincidence"
    );

    let mut derived = v1.clone();
    let obj = derived.as_object_mut().expect("object");
    let old = obj.remove("version").expect("v1 carries it");
    obj.insert("active_version".to_owned(), old);
    obj.insert("queried_version".to_owned(), queried.into());
    assert_eq!(
        derived, v2,
        "rename plus exactly one addition, nothing else"
    );
}

/// **Subtraction.** `fee` was `fees[0]` under a second name.
#[test]
fn fee_v2_is_v1_minus_exactly_the_redundant_scalar() {
    let v1 = parsed(include_str!("vectors/rpc/get_fee_estimate_v1.json"));
    assert_eq!(
        v1["fee"], v1["fees"][0],
        "the scalar was the first tier restated — which is why it goes"
    );
    let mut derived = v1;
    derived.as_object_mut().expect("object").remove("fee");
    assert_eq!(
        derived,
        parsed(include_str!("vectors/rpc/get_fee_estimate_v2.json")),
        "`_v2` differs by that field and nothing else"
    );
}
