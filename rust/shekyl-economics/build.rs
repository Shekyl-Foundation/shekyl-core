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
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .expect("workspace/rust path expected")
        .parent()
        .expect("workspace root path expected")
        .join("config")
        .join("economics_params.json");

    println!("cargo:rerun-if-changed={}", config_path.display());

    let raw = fs::read_to_string(&config_path).expect("failed to read economics_params.json");
    let map: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&raw).expect("invalid JSON in economics_params.json");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let out_file = out_dir.join("params_generated.rs");

    let output = format!(
        "pub const GENERATED_SCALE: u64 = {scale};\n\
         pub const GENERATED_RELEASE_MIN: u64 = {release_min};\n\
         pub const GENERATED_RELEASE_MAX: u64 = {release_max};\n\
         pub const GENERATED_TX_VOLUME_BASELINE: u64 = {tx_baseline};\n\
         pub const GENERATED_BURN_BASE_RATE: u64 = {burn_base_rate};\n\
         pub const GENERATED_BURN_CAP: u64 = {burn_cap};\n\
         pub const GENERATED_STAKER_POOL_SHARE: u64 = {staker_pool_share};\n\
         pub const GENERATED_MONEY_SUPPLY: u64 = {money_supply};\n",
        scale = get_u64(&map, "shekyl_fixed_point_scale"),
        release_min = get_u64(&map, "shekyl_release_min"),
        release_max = get_u64(&map, "shekyl_release_max"),
        tx_baseline = get_u64(&map, "shekyl_tx_volume_baseline"),
        burn_base_rate = get_u64(&map, "shekyl_burn_base_rate"),
        burn_cap = get_u64(&map, "shekyl_burn_cap"),
        staker_pool_share = get_u64(&map, "shekyl_staker_pool_share"),
        money_supply = get_u64(&map, "money_supply"),
    );

    fs::write(&out_file, output).expect("failed writing generated Rust economics params");
}
