// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `MIN_BLOCK_WEIGHT` from `config/consensus_constants.json`.
//!
//! The key `block_weight_full_reward_zone_bytes` is the penalty-free zone.
//! `shekyl-economics` and `cmake/generate_consensus_constants.py` read the
//! same key. This crate cannot depend on economics (the wire format is
//! below it), so it reads the JSON itself — the same per-crate build
//! pattern as `shekyl-difficulty`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .expect("workspace/rust path expected")
        .parent()
        .expect("workspace root path expected")
        .join("config")
        .join("consensus_constants.json");

    println!("cargo:rerun-if-changed={}", config_path.display());

    let raw = fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", config_path.display()));
    let map: BTreeMap<String, serde_json::Value> = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", config_path.display()));
    let zone = map
        .get("block_weight_full_reward_zone_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing or invalid u64 key \"block_weight_full_reward_zone_bytes\" in {}",
                config_path.display()
            )
        });
    let zone_usize = usize::try_from(zone).unwrap_or_else(|_| {
        panic!(
            "block_weight_full_reward_zone_bytes {zone} does not fit usize ({})",
            config_path.display()
        )
    });

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    fs::write(
        out_dir.join("block_weight_generated.rs"),
        format!("const GENERATED_FULL_REWARD_ZONE_USIZE: usize = {zone_usize};\n"),
    )
    .expect("failed writing generated block-weight constant");
}
