use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

fn get_u64(map: &BTreeMap<String, serde_json::Value>, key: &str) -> u64 {
    map.get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("missing or invalid u64 key in economics config: {key}"))
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let config_dir = manifest_dir
        .parent()
        .expect("workspace/rust path expected")
        .parent()
        .expect("workspace root path expected")
        .join("config");

    let config_path = config_dir.join("economics_params.json");
    println!("cargo:rerun-if-changed={}", config_path.display());

    let raw = fs::read_to_string(&config_path).expect("failed to read economics_params.json");
    let map: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&raw).expect("invalid JSON in economics_params.json");

    // SHEKYL_DAA_TARGET_SECONDS is a consensus constant whose authority is
    // config/consensus_constants.json (the same JSON that drives the C++ header
    // generator and shekyl-difficulty/build.rs). Reading it here rather than
    // literal-coding it keeps the emission curve's DAA target from silently
    // drifting from consensus — the constant feeds tail_subsidy_per_block, so a mismatch would break C2a′ dual-leg equivalence.
    // Per the 2026-05-05 FFI constant-drift audit (Bug 3).
    let consensus_path = config_dir.join("consensus_constants.json");
    println!("cargo:rerun-if-changed={}", consensus_path.display());
    let consensus_raw =
        fs::read_to_string(&consensus_path).expect("failed to read consensus_constants.json");
    let consensus_map: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&consensus_raw).expect("invalid JSON in consensus_constants.json");
    let daa_target_seconds = get_u64(&consensus_map, "daa_target_seconds");
    let block_weight_surge_factor = get_u64(&consensus_map, "block_weight_short_term_surge_factor");
    // The block-weight limit's multiple of the effective median and the
    // long-term weight's clamp, both in SCALE units (ESR-16 completion).
    let block_weight_limit_multiple = get_u64(&consensus_map, "block_weight_limit_multiple_scaled");
    let block_weight_long_term_clamp =
        get_u64(&consensus_map, "block_weight_long_term_clamp_scaled");
    // The penalty-free block-weight zone: the same authority as the surge
    // factor (config/consensus_constants.json drives both the C++ header
    // generator and this). Until E6 slice 4 it was a hand-written C++ macro
    // with no Rust home, passed to `paid_block_reward` as an argument on every
    // call (CHAIN_RULES_SLICE_4.md §3.1 S8).
    let block_weight_full_reward_zone =
        get_u64(&consensus_map, "block_weight_full_reward_zone_bytes");
    // The two medians' windows (CEN-G6, CHAIN_RULES_SLICE_7.md Q6): the
    // long-term median's horizon and the short-term median's. Both were
    // C++-only `#define`s until slice 7; the C++ header is generated from
    // the same keys.
    let block_weight_long_term_window =
        get_u64(&consensus_map, "block_weight_long_term_window_blocks");
    let block_weight_short_term_window =
        get_u64(&consensus_map, "block_weight_short_term_window_blocks");
    assert!(
        block_weight_short_term_window > 0 && block_weight_long_term_window > 0,
        "consensus_constants.json: a block-weight median window must be at least one block"
    );

    // RelayPolicy's keys: their own file, outside every digest (ESR-16
    // completion, ruled 2026-10-29). Read only from it, so a relay key in
    // economics_params.json is not picked up here, and a consensus key in
    // relay_policy.json is never required by the economics set.
    let relay_path = config_dir.join("relay_policy.json");
    println!("cargo:rerun-if-changed={}", relay_path.display());
    let relay_raw = fs::read_to_string(&relay_path).expect("failed to read relay_policy.json");
    let relay: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&relay_raw).expect("invalid JSON in relay_policy.json");
    // The lookback, the slack and the decimals are read as u32 / usize.
    for key in [
        "relay_floor_lookback",
        "relay_admission_slack_bp",
        "fee_decimal_places",
    ] {
        assert!(
            u32::try_from(get_u64(&relay, key)).is_ok(),
            "relay_policy.json: {key} does not fit u32"
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let out_file = out_dir.join("params_generated.rs");

    let output = format!(
        "pub const GENERATED_BLOCK_WEIGHT_SURGE_FACTOR: u64 = {block_weight_surge_factor};\n\
         pub const GENERATED_BLOCK_WEIGHT_LIMIT_MULTIPLE: u64 = {block_weight_limit_multiple};\n\
         pub const GENERATED_BLOCK_WEIGHT_LONG_TERM_CLAMP: u64 = {block_weight_long_term_clamp};\n\
         pub const GENERATED_BLOCK_WEIGHT_FULL_REWARD_ZONE: u64 = {block_weight_full_reward_zone};\n\
         pub const GENERATED_BLOCK_WEIGHT_LONG_TERM_WINDOW: u64 = {block_weight_long_term_window};\n\
         pub const GENERATED_BLOCK_WEIGHT_SHORT_TERM_WINDOW: u64 = {block_weight_short_term_window};\n\
         pub const GENERATED_SCALE: u64 = {scale};\n\
         pub const GENERATED_RELEASE_MIN: u64 = {release_min};\n\
         pub const GENERATED_RELEASE_MAX: u64 = {release_max};\n\
         pub const GENERATED_TX_VOLUME_BASELINE: u64 = {tx_baseline};\n\
         pub const GENERATED_BURN_BASE_RATE: u64 = {burn_base_rate};\n\
         pub const GENERATED_BURN_CAP: u64 = {burn_cap};\n\
         pub const GENERATED_STAKER_POOL_SHARE: u64 = {staker_pool_share};\n\
         pub const GENERATED_ESCALATION_KNEE_N: u64 = {escalation_knee_n};\n\
         pub const GENERATED_ESCALATION_ASYMPTOTE_SHARE: u64 = {escalation_asymptote};\n\
         pub const GENERATED_EMISSION_CURVE_ASYMPTOTE: u64 = {emission_curve_asymptote};\n\
         pub const GENERATED_EMISSION_SPEED_FACTOR_PER_BLOCK: u64 = {esf};\n\
         pub const GENERATED_FINAL_SUBSIDY_PER_MINUTE: u64 = {final_subsidy};\n\
         pub const GENERATED_DAA_TARGET_SECONDS: u64 = {daa_target};\n\
         pub const GENERATED_STAKER_EMISSION_SHARE: u64 = {staker_emission_share};\n\
         pub const GENERATED_STAKER_EMISSION_DECAY: u64 = {staker_emission_decay};\n\
         pub const GENERATED_TX_VOLUME_WINDOW: u64 = {tx_volume_window};\n\
         pub const GENERATED_RELAY_FLOOR_LOOKBACK: u64 = {relay_lookback};\n\
         pub const GENERATED_RELAY_ADMISSION_SLACK_BP: u64 = {relay_slack};\n\
         pub const GENERATED_FEE_DECIMAL_PLACES: u64 = {fee_decimals};\n\
         pub const GENERATED_RELAY_FLOOR_REFERENCE_TX_WEIGHT: u64 = {w_ref};\n\
         pub const GENERATED_STANDARD_RUNG_OVER_ECONOMY: u64 = {standard};\n\
         pub const GENERATED_PRIORITY_RUNG_FACTOR: u64 = {priority};\n\
         pub const GENERATED_EMISSION_CLAIM_FEE_FLOOR: u64 = {claim_hold};\n",
        scale = get_u64(&map, "shekyl_fixed_point_scale"),
        release_min = get_u64(&map, "shekyl_release_min"),
        release_max = get_u64(&map, "shekyl_release_max"),
        tx_baseline = get_u64(&map, "shekyl_tx_volume_baseline"),
        burn_base_rate = get_u64(&map, "shekyl_burn_base_rate"),
        burn_cap = get_u64(&map, "shekyl_burn_cap"),
        staker_pool_share = get_u64(&map, "shekyl_staker_pool_share"),
        escalation_knee_n = get_u64(&map, "shekyl_escalation_knee_n"),
        escalation_asymptote = get_u64(&map, "shekyl_escalation_asymptote_share"),
        emission_curve_asymptote = get_u64(&map, "emission_curve_asymptote"),
        esf = get_u64(&map, "emission_speed_factor_per_block"),
        final_subsidy = get_u64(&map, "final_subsidy_per_minute"),
        daa_target = daa_target_seconds,
        staker_emission_share = get_u64(&map, "shekyl_staker_emission_share"),
        staker_emission_decay = get_u64(&map, "shekyl_staker_emission_decay"),
        tx_volume_window = get_u64(&map, "shekyl_tx_volume_window"),
        relay_lookback = get_u64(&relay, "relay_floor_lookback"),
        relay_slack = get_u64(&relay, "relay_admission_slack_bp"),
        fee_decimals = get_u64(&relay, "fee_decimal_places"),
        w_ref = get_u64(&relay, "relay_floor_reference_tx_weight"),
        standard = get_u64(&relay, "standard_rung_over_economy"),
        priority = get_u64(&relay, "priority_rung_factor"),
        claim_hold = get_u64(&relay, "emission_claim_fee_floor_atomic"),
    );

    fs::write(&out_file, output).expect("failed writing generated Rust economics params");
}
