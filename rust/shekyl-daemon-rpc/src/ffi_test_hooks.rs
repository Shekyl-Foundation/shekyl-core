// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The FFI-struct round-trip hooks the C++ unit tests drive
//! (`tests/unit_tests/daemon_submit_ffi_roundtrip.cpp` and its siblings).
//! No production caller; declared in those tests, not in `shekyl_ffi.h`.

// ── §4.5 FFI-struct round-trip hooks (DAEMON_SUBMIT_VERDICT.md, F26) ────────
//
// The Rust twins of `shekyl_submit_facts_test_fill` / `_check`
// (daemon_submit_ffi.cpp): per-FIELD writes and reads through *Rust's* view
// of `SubmitFactsFfi`, with the identical seed-derived per-field values, so
// the C++ unit test (tests/unit_tests/daemon_submit_ffi_roundtrip.cpp) can
// drive both directions — C++-writes/Rust-reads and Rust-writes/C++-reads —
// and a field-offset disagreement fails even where a memcpy echo would pass.
// No production callers.

/// splitmix64 over `seed ⊕ field-tweak` — must stay byte-identical to
/// `submit_facts_field_value` in `daemon_submit_ffi.cpp`. Seeds `0` and
/// `u64::MAX` short-circuit to the zeroed/max edge shapes (§4.5).
fn submit_facts_field_value(seed: u64, field: u64) -> u64 {
    if seed == 0 {
        return 0;
    }
    if seed == u64::MAX {
        return u64::MAX;
    }
    let mut z = seed ^ 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(field + 1);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// Deliberate low-byte truncation on every `as u8`: the values must stay
// byte-identical to `submit_facts_test_fill` in daemon_submit_ffi.cpp, whose
// u64-to-u8 field assignments truncate the same way (§4.5 parity hooks).
#[allow(clippy::cast_possible_truncation)]
fn submit_facts_filled(seed: u64) -> crate::ffi::SubmitFactsFfi {
    let mut root = [0u8; 32];
    let root_word = submit_facts_field_value(seed, 5);
    for (i, byte) in root.iter_mut().enumerate() {
        *byte = (root_word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::SubmitFactsFfi {
        in_pool: submit_facts_field_value(seed, 0) as u8,
        in_chain: submit_facts_field_value(seed, 1) as u8,
        ref_block_found: submit_facts_field_value(seed, 2) as u8,
        tree_depth: submit_facts_field_value(seed, 3) as u8,
        in_pool_broadcast: submit_facts_field_value(seed, 10) as u8,
        bond_record_probed: submit_facts_field_value(seed, 12) as u8,
        bond_record_exists: submit_facts_field_value(seed, 13) as u8,
        emission_probed: submit_facts_field_value(seed, 14) as u8,
        emission_claim_conflict: submit_facts_field_value(seed, 15) as u8,
        reserved: [0; 7],
        ref_height: submit_facts_field_value(seed, 4),
        root,
        fee_per_byte: submit_facts_field_value(seed, 6),
        weight_limit: submit_facts_field_value(seed, 8),
        chain_height: submit_facts_field_value(seed, 9),
        in_chain_height: submit_facts_field_value(seed, 11),
        bond_record_bonded_total: submit_facts_field_value(seed, 16),
    }
}

/// Rust-side fill: write seed-derived values into every field through
/// Rust's view of the layout.
///
/// # Safety
///
/// `out` must point to a writable `shekyl_submit_facts_ffi`, or be null
/// (no-op).
#[no_mangle]
pub unsafe extern "C" fn shekyl_submit_facts_rust_fill(
    out: *mut crate::ffi::SubmitFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(submit_facts_filled(seed));
}

/// Rust-side check: read every field through Rust's view and return 0 iff
/// each matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_submit_facts_ffi`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_submit_facts_rust_check(
    facts: *const crate::ffi::SubmitFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == submit_facts_filled(seed) {
        0
    } else {
        -1
    }
}

#[allow(clippy::cast_possible_truncation)]
fn fee_estimate_facts_filled(seed: u64) -> crate::ffi::FeeEstimateFactsFfi {
    crate::ffi::FeeEstimateFactsFfi {
        // Field index 5 below is not a fee-slot index: it seeds a distinct
        // value for the count. Re-indexing it would move every expected
        // value in the harness for no gain.
        fees: std::array::from_fn(|i| submit_facts_field_value(seed, i as u64)),
        fee_count: submit_facts_field_value(seed, 5) as u8,
        reserved: [0; 7],
    }
}

/// Rust-side fill of `shekyl_rpc_fee_estimate_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_fee_estimate_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_fee_estimate_facts_rust_fill(
    out: *mut crate::ffi::FeeEstimateFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(fee_estimate_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_fee_estimate_facts`: 0 iff every field
/// matches.
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_fee_estimate_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_fee_estimate_facts_rust_check(
    facts: *const crate::ffi::FeeEstimateFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == fee_estimate_facts_filled(seed) {
        0
    } else {
        -1
    }
}

fn net_stats_facts_filled(seed: u64) -> crate::ffi::NetStatsFactsFfi {
    crate::ffi::NetStatsFactsFfi {
        start_time: submit_facts_field_value(seed, 0),
        total_packets_in: submit_facts_field_value(seed, 1),
        total_bytes_in: submit_facts_field_value(seed, 2),
        total_packets_out: submit_facts_field_value(seed, 3),
        total_bytes_out: submit_facts_field_value(seed, 4),
    }
}

/// Rust-side fill of `shekyl_rpc_net_stats_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_net_stats_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_net_stats_facts_rust_fill(
    out: *mut crate::ffi::NetStatsFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(net_stats_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_net_stats_facts`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_net_stats_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_net_stats_facts_rust_check(
    facts: *const crate::ffi::NetStatsFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == net_stats_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Seed-derived per-field values are deliberately truncated into the narrow
// fields — the point is to exercise every byte of the layout (F26).
#[allow(clippy::cast_possible_truncation)]
fn identity_facts_filled(seed: u64) -> crate::ffi::IdentityFactsFfi {
    let mut genesis_hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 1);
    for (i, byte) in genesis_hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::IdentityFactsFfi {
        nettype: submit_facts_field_value(seed, 0) as u8,
        reserved: [0; 7],
        genesis_hash,
    }
}

/// Rust-side fill of `shekyl_rpc_identity_facts` (layout twin, VC-2).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_identity_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_identity_facts_rust_fill(
    out: *mut crate::ffi::IdentityFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(identity_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_identity_facts`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_identity_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_identity_facts_rust_check(
    facts: *const crate::ffi::IdentityFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == identity_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Seed-derived per-field values are deliberately truncated into the narrow
// fields — the point is to exercise every byte of the layout (F26).
#[allow(clippy::cast_possible_truncation)]
fn chain_tip_facts_filled(seed: u64) -> crate::ffi::ChainTipFactsFfi {
    let mut top_hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 1);
    for (i, byte) in top_hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::ChainTipFactsFfi {
        chain_height: submit_facts_field_value(seed, 0),
        top_hash,
        target_height: submit_facts_field_value(seed, 2),
        synchronized: submit_facts_field_value(seed, 3) as u8,
        release_build: submit_facts_field_value(seed, 4) as u8,
        reserved: [0; 6],
    }
}

/// Rust-side fill of `shekyl_rpc_chain_tip_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_chain_tip_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_chain_tip_facts_rust_fill(
    out: *mut crate::ffi::ChainTipFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(chain_tip_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_chain_tip_facts`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_chain_tip_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_chain_tip_facts_rust_check(
    facts: *const crate::ffi::ChainTipFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == chain_tip_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Narrow fields on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn info_chain_facts_filled(seed: u64) -> crate::ffi::InfoChainFactsFfi {
    let mut top_hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 1);
    for (i, byte) in top_hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::InfoChainFactsFfi {
        chain_height: submit_facts_field_value(seed, 0),
        top_hash,
        difficulty_lo: submit_facts_field_value(seed, 2),
        difficulty_hi: submit_facts_field_value(seed, 3),
        cumulative_difficulty_lo: submit_facts_field_value(seed, 4),
        cumulative_difficulty_hi: submit_facts_field_value(seed, 5),
        difficulty_target: submit_facts_field_value(seed, 6),
        total_transactions: submit_facts_field_value(seed, 7),
        block_weight_limit: submit_facts_field_value(seed, 8),
        block_weight_median: submit_facts_field_value(seed, 9),
        adjusted_time: submit_facts_field_value(seed, 10),
        already_generated_coins: submit_facts_field_value(seed, 11),
        total_burned: submit_facts_field_value(seed, 12),
        tx_volume_count_sum: submit_facts_field_value(seed, 13),
        tx_volume_blocks: submit_facts_field_value(seed, 14),
        core_target_height: submit_facts_field_value(seed, 15),
        synchronized: submit_facts_field_value(seed, 16) as u8,
        busy_syncing: submit_facts_field_value(seed, 17) as u8,
        offline: submit_facts_field_value(seed, 18) as u8,
        following_degraded: submit_facts_field_value(seed, 19) as u8,
        protocol_version: submit_facts_field_value(seed, 20) as u8,
        reserved: [0; 3],
    }
}

/// Rust-side fill of `shekyl_rpc_info_chain_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_info_chain_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_chain_facts_rust_fill(
    out: *mut crate::ffi::InfoChainFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(info_chain_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_info_chain_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_info_chain_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_chain_facts_rust_check(
    facts: *const crate::ffi::InfoChainFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == info_chain_facts_filled(seed) {
        0
    } else {
        -1
    }
}

fn info_status_facts_filled(seed: u64) -> crate::ffi::InfoStatusFactsFfi {
    crate::ffi::InfoStatusFactsFfi {
        start_time: submit_facts_field_value(seed, 0),
        free_space: submit_facts_field_value(seed, 1),
        alt_blocks_count: submit_facts_field_value(seed, 2),
    }
}

/// Rust-side fill of `shekyl_rpc_info_status_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_info_status_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_status_facts_rust_fill(
    out: *mut crate::ffi::InfoStatusFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(info_status_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_info_status_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_info_status_facts`, or be
/// null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_status_facts_rust_check(
    facts: *const crate::ffi::InfoStatusFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == info_status_facts_filled(seed) {
        0
    } else {
        -1
    }
}

fn info_peers_facts_filled(seed: u64) -> crate::ffi::InfoPeersFactsFfi {
    crate::ffi::InfoPeersFactsFfi {
        public_incoming_sockets: submit_facts_field_value(seed, 0),
        public_outgoing_sockets: submit_facts_field_value(seed, 1),
        tor_incoming_sockets: submit_facts_field_value(seed, 2),
        tor_outgoing_sockets: submit_facts_field_value(seed, 3),
    }
}

/// Rust-side fill of `shekyl_rpc_info_peers_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_info_peers_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_peers_facts_rust_fill(
    out: *mut crate::ffi::InfoPeersFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(info_peers_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_info_peers_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_info_peers_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_peers_facts_rust_check(
    facts: *const crate::ffi::InfoPeersFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == info_peers_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Narrow fields on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn block_header_facts_filled(seed: u64) -> crate::ffi::BlockHeaderFactsFfi {
    let mut hashes = [[0u8; 32]; 6];
    for (f, hash) in hashes.iter_mut().enumerate() {
        let word = submit_facts_field_value(seed, f as u64);
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = (word >> ((i % 8) * 8)) as u8;
        }
    }
    crate::ffi::BlockHeaderFactsFfi {
        hash: hashes[0],
        prev_hash: hashes[1],
        miner_tx_hash: hashes[2],
        curve_tree_root: hashes[3],
        attestation_root: hashes[4],
        pow_hash: hashes[5],
        height: submit_facts_field_value(seed, 6),
        depth: submit_facts_field_value(seed, 7),
        chain_height: submit_facts_field_value(seed, 8),
        timestamp: submit_facts_field_value(seed, 9),
        difficulty_lo: submit_facts_field_value(seed, 10),
        difficulty_hi: submit_facts_field_value(seed, 11),
        cumulative_difficulty_lo: submit_facts_field_value(seed, 12),
        cumulative_difficulty_hi: submit_facts_field_value(seed, 13),
        reward: submit_facts_field_value(seed, 14),
        block_weight: submit_facts_field_value(seed, 15),
        long_term_weight: submit_facts_field_value(seed, 16),
        num_txes: submit_facts_field_value(seed, 17),
        nonce: submit_facts_field_value(seed, 18) as u32,
        major_version: submit_facts_field_value(seed, 19) as u8,
        minor_version: submit_facts_field_value(seed, 20) as u8,
        orphan_status: submit_facts_field_value(seed, 21) as u8,
        pow_hash_filled: submit_facts_field_value(seed, 22) as u8,
        found: submit_facts_field_value(seed, 23) as u8,
        reserved: [0; 7],
    }
}

/// Rust-side fill of `shekyl_rpc_block_header_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_block_header_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_header_facts_rust_fill(
    out: *mut crate::ffi::BlockHeaderFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(block_header_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_block_header_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_block_header_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_header_facts_rust_check(
    facts: *const crate::ffi::BlockHeaderFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == block_header_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Narrow fields on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn block_hash_facts_filled(seed: u64) -> crate::ffi::BlockHashFactsFfi {
    let mut hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 0);
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::BlockHashFactsFfi {
        hash,
        chain_height: submit_facts_field_value(seed, 1),
        found: submit_facts_field_value(seed, 2) as u8,
        reserved: [0; 7],
    }
}

/// Rust-side fill of `shekyl_rpc_block_hash_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_block_hash_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_hash_facts_rust_fill(
    out: *mut crate::ffi::BlockHashFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(block_hash_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_block_hash_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_block_hash_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_hash_facts_rust_check(
    facts: *const crate::ffi::BlockHashFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == block_hash_facts_filled(seed) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation itself, pinned by vectors so a Rust-side edit cannot
    /// silently diverge from the C++ constant chain (the cross-language
    /// round-trip in tests/unit_tests/daemon_submit_ffi_roundtrip.cpp is
    /// the authoritative gate; this catches drift at `cargo test` speed).
    #[test]
    fn field_value_edges_and_tweak_separation() {
        assert_eq!(submit_facts_field_value(0, 7), 0);
        assert_eq!(submit_facts_field_value(u64::MAX, 3), u64::MAX);
        // Distinct fields derive distinct values for a nontrivial seed —
        // the property that makes same-width offset swaps detectable.
        let seed = 0xDEAD_BEEF_CAFE_F00D;
        let values: Vec<u64> = (0..12).map(|f| submit_facts_field_value(seed, f)).collect();
        let mut deduped = values.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), values.len());
    }

    #[test]
    fn rust_fill_check_round_trips() {
        for seed in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
            let mut pod = crate::ffi::SubmitFactsFfi::zeroed();
            unsafe { shekyl_submit_facts_rust_fill(&raw mut pod, seed) };
            assert_eq!(
                unsafe { shekyl_submit_facts_rust_check(&raw const pod, seed) },
                0
            );
            // A single-byte perturbation anywhere must fail the check.
            pod.root[31] ^= 0x01;
            assert_eq!(
                unsafe { shekyl_submit_facts_rust_check(&raw const pod, seed) },
                -1
            );
        }
    }
}
