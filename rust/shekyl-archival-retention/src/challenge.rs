// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic epoch challenge replay per
//! [`ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md) §3.3–§3.4.

use crate::constants::CHALLENGE_BEACON_SEAL_BLOCKS;
use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

/// cSHAKE256 customization for leaf index derivation (§3.3).
pub const CHALLENGE_LEAF_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-challenge-leaf-v1";

/// cSHAKE256 customization for fire-time beacon (§3.4).
pub const CHALLENGE_FIRE_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-challenge-fire-v1";

/// cSHAKE256 customization for the serve-credit response vin signature preimage (§5.2).
pub const SERVE_CREDIT_RESPONSE_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-credit-response-v1";

fn cshake256_32(customization: &[u8], input: &[u8]) -> [u8; 32] {
    let core = CShake256Core::new(customization);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn uint64_from_hash(hash: &[u8; 32]) -> u64 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(le)
}

/// First block height at which `block_hash(H_seal)` is knowable (§3.4).
#[must_use]
pub fn challenge_seal_height(h_open: u64) -> u64 {
    h_open.saturating_add(CHALLENGE_BEACON_SEAL_BLOCKS)
}

/// Segment-relative leaf index `ℓ` for `(P, shard, E)` (§3.3).
///
/// `segment_leaf_count` must be the registry value at epoch close; returns `0` when
/// `segment_leaf_count == 0` (caller should reject zero geometry before verify).
#[must_use]
pub fn challenge_leaf_index(
    p_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
    segment_leaf_count: u64,
) -> u32 {
    if segment_leaf_count == 0 {
        return 0;
    }
    let mut input = Vec::with_capacity(32 + 8 + 8);
    input.extend_from_slice(p_id);
    input.extend_from_slice(&shard_id.to_le_bytes());
    input.extend_from_slice(&settlement_epoch.to_le_bytes());
    let tau = cshake256_32(CHALLENGE_LEAF_CUSTOMIZATION, &input);
    let idx = uint64_from_hash(&tau) % segment_leaf_count;
    u32::try_from(idx).unwrap_or(u32::MAX)
}

/// Beacon fire height `H_fire ∈ (H_open, H_close]` (§3.4).
#[must_use]
pub fn challenge_fire_height(
    h_open: u64,
    h_close: u64,
    block_hash_at_seal: &[u8; 32],
    p_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> u64 {
    let h_seal = challenge_seal_height(h_open);
    let span = h_close.saturating_sub(h_seal);
    let modulus = span.saturating_sub(1).max(1);

    let mut input = Vec::with_capacity(32 + 32 + 8 + 8);
    input.extend_from_slice(block_hash_at_seal);
    input.extend_from_slice(p_id);
    input.extend_from_slice(&shard_id.to_le_bytes());
    input.extend_from_slice(&settlement_epoch.to_le_bytes());
    let beacon = cshake256_32(CHALLENGE_FIRE_CUSTOMIZATION, &input);
    let offset = uint64_from_hash(&beacon) % modulus;
    h_seal.saturating_add(offset).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_index_is_deterministic() {
        let p = [0x42u8; 32];
        let a = challenge_leaf_index(&p, 7, 100, 26_000);
        let b = challenge_leaf_index(&p, 7, 100, 26_000);
        assert_eq!(a, b);
    }

    #[test]
    fn leaf_index_changes_with_epoch() {
        let p = [0x42u8; 32];
        let a = challenge_leaf_index(&p, 7, 100, 26_000);
        let b = challenge_leaf_index(&p, 7, 101, 26_000);
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_index_within_segment() {
        let p = [0x11u8; 32];
        let count = 26_000u64;
        let idx = challenge_leaf_index(&p, 3, 50, count);
        assert!(u64::from(idx) < count);
    }

    #[test]
    fn fire_height_lies_after_seal_and_not_before_open() {
        let p = [0x99u8; 32];
        let hash = [0xABu8; 32];
        let h_open = 1_000_000u64;
        let h_close = h_open + 9_999;
        let h_fire = challenge_fire_height(h_open, h_close, &hash, &p, 1, 42);
        assert!(h_fire > challenge_seal_height(h_open));
        assert!(h_fire <= h_close);
    }

    #[test]
    fn fire_height_is_deterministic_given_seal_hash() {
        let p = [0x55u8; 32];
        let hash = [0xCDu8; 32];
        let a = challenge_fire_height(500, 14_499, &hash, &p, 2, 9);
        let b = challenge_fire_height(500, 14_499, &hash, &p, 2, 9);
        assert_eq!(a, b);
    }
}
