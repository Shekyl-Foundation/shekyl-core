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

    let release_cooldown_epochs = map
        .get("release_cooldown_epochs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing release_cooldown_epochs in {}",
                config_path.display()
            )
        });

    // Block-span floor for archival derived-state survival before prune sweep
    // (ARCHIVAL_TIMING_CONSTANTS.md §1 / §2.3). Same JSON authority as W,
    // reorg depth, and release cooldown — the sim's timing-cluster coupling
    // harness imports this rather than mirroring a local literal.
    let retention_horizon_blocks = map
        .get("retention_horizon_blocks")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing retention_horizon_blocks in {}",
                config_path.display()
            )
        });

    // Per-shard retention-commitment horizon (gate-4 §4.4). Shape genesis-frozen;
    // numerics provisional (H2 plateau arm). Consumed by
    // shekyl-archival-retention::bond_duration (Rust-only at genesis); the C++
    // header emits the same values for parity.
    let bond_duration_base_epochs = map
        .get("bond_duration_base_epochs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing bond_duration_base_epochs in {}",
                config_path.display()
            )
        });

    let bond_duration_age_scale = map
        .get("bond_duration_age_scale")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "missing bond_duration_age_scale in {}",
                config_path.display()
            )
        });

    // Sliding-window m-of-n failure confirmation (ARCHIVAL_FAILURE_CONFIRMATION_PIN
    // §1). Shape genesis-frozen; numerics provisional at the Round-1 values,
    // re-pinned at the Round-2 stressnet — the bond_duration precedent.
    //
    // Read at the width they are EMITTED and crossed at (`u32`, the
    // shekyl_archival_failure_window_params accessor), so an out-of-range re-pin
    // names itself here instead of surfacing as an opaque "literal out of range"
    // in the generated file. Converting on read rather than bound-checking after
    // is what makes both values structurally in-range: a check on `n` alone would
    // bound `m` only transitively through `n >= m` below, so reordering or
    // dropping that check would silently un-bound `m`.
    let failure_window_param = |key: &str| -> u32 {
        let raw = map
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("missing {key} in {}", config_path.display()));
        u32::try_from(raw).unwrap_or_else(|_| {
            panic!(
                "{key} ({raw}) exceeds u32 in {} — the failure-window FFI accessor \
                 is u32-wide",
                config_path.display()
            )
        })
    };
    let failure_window_m = failure_window_param("archival_failure_window_m");
    let failure_window_n = failure_window_param("archival_failure_window_n");

    // Shape invariants, not tunables: `m == 0` would slash a `P` that never
    // missed, and `n < m` would make the threshold unreachable — a silently
    // disabled slash. Both are re-pin typos the Round-2 numerics pass could
    // introduce, so they fail the build here rather than at a stressnet.
    if failure_window_m == 0 {
        panic!(
            "archival_failure_window_m must be >= 1 in {} (m = 0 slashes a P that \
             never missed a baseline)",
            config_path.display()
        );
    }
    if failure_window_n < failure_window_m {
        panic!(
            "archival_failure_window_n ({failure_window_n}) must be >= \
             archival_failure_window_m ({failure_window_m}) in {} — an unreachable \
             threshold disables the slash silently",
            config_path.display()
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let out_file = out_dir.join("archival_bond_floor_generated.rs");
    let output = format!(
        "// @generated by build.rs from config/consensus_constants.json — do not edit.\n\
         pub const ARCHIVAL_BOND_FLOOR_ATOMIC: u64 = {floor};\n\
         pub const ARCHIVAL_REWARD_AGE_WEIGHT_MILLI: u64 = {age_weight};\n\
         pub const MAX_CLAIM_AGE_W: u64 = {max_claim_age_w};\n\
         pub const RELEASE_COOLDOWN_EPOCHS: u64 = {release_cooldown_epochs};\n\
         pub const ARCHIVAL_REORG_DEPTH_BLOCKS: u64 = {archival_reorg_depth_blocks};\n\
         pub const RETENTION_HORIZON_BLOCKS: u64 = {retention_horizon_blocks};\n\
         pub const BOND_DURATION_BASE_EPOCHS: u64 = {bond_duration_base_epochs};\n\
         pub const BOND_DURATION_AGE_SCALE: u64 = {bond_duration_age_scale};\n"
    );
    fs::write(&out_file, output).expect("failed writing generated archival consensus constants");

    // Own file, own consumer: src/failure_window.rs includes only these two, so
    // the failure-window module does not pull the whole bond-floor constant set
    // into its namespace (the segment_leaf_count precedent).
    let failure_window_file = out_dir.join("archival_failure_window_generated.rs");
    let failure_window_output = format!(
        "// @generated by build.rs from config/consensus_constants.json — do not edit.\n\
         pub const ARCHIVAL_FAILURE_WINDOW_M: u32 = {failure_window_m};\n\
         pub const ARCHIVAL_FAILURE_WINDOW_N: u32 = {failure_window_n};\n"
    );
    fs::write(&failure_window_file, failure_window_output)
        .expect("failed writing generated archival failure-window constants");

    // Segment geometry (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.2). Derived,
    // not tunable: src/segment_freeze.rs re-asserts the value against the
    // shekyl-fcmp width product at compile time, so this check is only the
    // JSON-side half of the pin.
    let segment_leaf_count = map
        .get("segment_leaf_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("missing segment_leaf_count in {}", config_path.display()));
    if segment_leaf_count == 0 {
        panic!(
            "segment_leaf_count must be positive in {} (level-2 subtree leaf count, \
             ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.2)",
            config_path.display()
        );
    }

    let segment_file = out_dir.join("segment_leaf_count_generated.rs");
    let segment_output = format!(
        "// @generated by build.rs from config/consensus_constants.json — do not edit.\n\
         pub const SEGMENT_LEAF_COUNT: u64 = {segment_leaf_count};\n"
    );
    fs::write(&segment_file, segment_output).expect("failed writing segment_leaf_count constant");
}
