// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emit `ARCHIVAL_BOND_FLOOR_ATOMIC` from `config/consensus_constants.json`
//! (same JSON authority as C++ / `shekyl-engine-core`; avoids a crate cycle).

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

    let floor = map
        .get("archival_bond_floor_atomic")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing archival_bond_floor_atomic in {}",
                config_path.display()
            )
        });

    let plateau_value = map
        .get("archival_reward_plateau_value_milli")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing archival_reward_plateau_value_milli in {}",
                config_path.display()
            )
        });

    let plateau_work = map
        .get("archival_reward_plateau_work_milli")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing archival_reward_plateau_work_milli in {}",
                config_path.display()
            )
        });

    let expected_plateau_work = plateau_value.checked_mul(2).unwrap_or_else(|| {
        panic!(
            "archival_reward_plateau_value_milli overflow in {}",
            config_path.display()
        )
    });
    if plateau_work != expected_plateau_work {
        panic!(
            "archival_reward_plateau_work_milli ({plateau_work}) must equal \
             2 * archival_reward_plateau_value_milli ({plateau_value}) in {}",
            config_path.display()
        );
    }

    let age_weight = map
        .get("archival_reward_age_weight_milli")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing archival_reward_age_weight_milli in {}",
                config_path.display()
            )
        });

    let max_claim_age_w = map
        .get("max_claim_age_w")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("missing max_claim_age_w in {}", config_path.display()));

    let archival_reorg_depth_blocks = map
        .get("archival_reorg_depth_blocks")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing archival_reorg_depth_blocks in {}",
                config_path.display()
            )
        });

    // M1 reward-gate cover threshold (ARCHIVAL_REWARD_GATE_M1.md §4 sentinel
    // mechanics). `k_cover_provisional` gates a compile-time refusal in
    // `src/k_cover.rs`; while provisional, the ONLY permitted value is 0 —
    // the gate-identity degenerate the G-9 KAT pins executably (pre-seal
    // behavior is exactly the pre-gate behavior, so the r_market/sigma store
    // paths stay exercised end-to-end until seal). This makes a
    // plausible-looking provisional K_COVER unrepresentable, not merely
    // discouraged; the shipping guard is the compile refusal in
    // src/k_cover.rs, never the sentinel value.
    let k_cover = map
        .get("k_cover")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("missing k_cover in {}", config_path.display()));

    let k_cover_provisional = map
        .get("k_cover_provisional")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| {
            panic!(
                "missing k_cover_provisional (bool) in {}",
                config_path.display()
            )
        });

    if k_cover_provisional && k_cover != 0 {
        panic!(
            "k_cover_provisional is true but k_cover ({k_cover}) is not the gate-identity \
             sentinel 0 in {}. A plausible-looking provisional K_COVER is the silent-ship \
             class ARCHIVAL_REWARD_GATE_M1.md §4 refuses: either seal the §14.4-derived \
             value (flip k_cover_provisional to false) or keep the sentinel.",
            config_path.display()
        );
    }
    if !k_cover_provisional && k_cover == 0 {
        panic!(
            "k_cover_provisional is false but k_cover is 0 (the gate never gates — no \
             cold-start refusal) in {}. Sealing requires the WI-4 §14.4-derived value >= 1, \
             not the sentinel with the flag flipped.",
            config_path.display()
        );
    }

    // Declare the cfg for `-D warnings` (unexpected_cfgs); emit it only while
    // provisional so the refusal in src/k_cover.rs compiles away entirely at seal.
    println!("cargo:rustc-check-cfg=cfg(k_cover_provisional)");
    if k_cover_provisional {
        println!("cargo:rustc-cfg=k_cover_provisional");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let out_file = out_dir.join("archival_bond_floor_generated.rs");
    let output = format!(
        "// @generated by build.rs from config/consensus_constants.json — do not edit.\n\
         pub const ARCHIVAL_BOND_FLOOR_ATOMIC: u64 = {floor};\n\
         pub const ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI: u64 = {plateau_value};\n\
         pub const ARCHIVAL_REWARD_PLATEAU_WORK_MILLI: u64 = {plateau_work};\n\
         pub const ARCHIVAL_REWARD_AGE_WEIGHT_MILLI: u64 = {age_weight};\n\
         pub const MAX_CLAIM_AGE_W: u64 = {max_claim_age_w};\n\
         pub const ARCHIVAL_REORG_DEPTH_BLOCKS: u64 = {archival_reorg_depth_blocks};\n"
    );
    fs::write(&out_file, output).expect("failed writing archival bond floor constant");

    let k_cover_file = out_dir.join("k_cover_generated.rs");
    let k_cover_output = format!(
        "// @generated by build.rs from config/consensus_constants.json — do not edit.\n\
         pub const K_COVER: u64 = {k_cover};\n\
         pub const K_COVER_PROVISIONAL: bool = {k_cover_provisional};\n"
    );
    fs::write(&k_cover_file, k_cover_output).expect("failed writing k_cover constants");
}
