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
    GetHeightResponse, GetVersionResponse, HardForkEntry, RpcStatus, CORE_RPC_VERSION,
};

fn parsed(json: &str) -> Value {
    serde_json::from_str(json).expect("vector / output is JSON")
}

/// The hash `rpc_oracle_vectors.cpp::patterned_hash` used: byte i = (i*7+3) & 0xff.
fn patterned_hash_hex() -> String {
    (0..32u32)
        .map(|i| format!("{:02x}", (i * 7 + 3) & 0xff))
        .collect()
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
        hash: patterned_hash_hex(),
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
