// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic epoch challenge replay per
//! [`ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md) §3.3–§3.4.
//!
//! **Mechanism status (2026-08-11):** the fire-beacon shape this module
//! implements (`H_seal`/`H_fire`, one challenge per pair-epoch) is
//! **superseded by derived assignment** — `ARCHIVAL_CHALLENGE_MECHANISM.md`
//! §2, implemented in [`crate::challenge_assignment`]: `assignment(h)` seeds
//! from `block_hash(h−1)`, issues `CHALLENGES_PER_PAIR_PER_EPOCH = 3` per
//! pair-epoch, and needs no seal lag. This module is **not dead code**: it
//! is the live interim serve-credit admission path (through `shekyl-ffi`
//! into `blockchain.cpp`'s serve-credit gate and `db_lmdb.cpp`'s
//! slash-eligibility consumer) until the format round freezes the
//! replacement response wire. It deletes wholesale with that round's
//! deletion surface — extend the *new* mechanism, never this one.

use crate::constants::CHALLENGE_BEACON_SEAL_BLOCKS;
use crate::hash::cshake256_32;

/// cSHAKE256 customization for leaf index derivation (§3.3).
pub const CHALLENGE_LEAF_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-challenge-leaf-v1";

/// cSHAKE256 customization for fire-time beacon (§3.4).
pub const CHALLENGE_FIRE_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-challenge-fire-v1";

/// cSHAKE256 customization for the serve-credit response vin signature preimage (§5.2).
pub const SERVE_CREDIT_RESPONSE_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-credit-response-v1";

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

/// Is the epoch's challenge seal block committed at `chain_height`?
///
/// `chain_height` is the block **count** (`m_db->height()` on the C++ side), so
/// the highest committed block index is `chain_height - 1`; the seal block
/// `H_seal = challenge_seal_height(h_open)` is on chain iff `H_seal <
/// chain_height`. The fire-time beacon `block_hash(H_seal)` — and therefore
/// `H_fire` — is knowable only once this holds.
///
/// The serve-credit gate calls this before reading `block_hash(H_seal)`: a
/// response whose `settlement_epoch` (attacker-chosen) puts `H_seal` at or
/// beyond the tip is rejected here, rather than by catching the `BLOCK_DNE` the
/// read would otherwise throw. The slash-eligibility consumer applies the same
/// predicate against its just-connected block height.
#[must_use]
pub fn challenge_seal_on_chain(h_open: u64, chain_height: u64) -> bool {
    challenge_seal_height(h_open) < chain_height
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
///
/// The range holds for every well-formed epoch (`H_close > H_seal`, guaranteed by
/// the genesis epoch formulas: `H_close − H_seal = SEB − 2`). Consumers therefore
/// do NOT range-check `H_fire`: a derivation outside `(0, H_close]` needs a
/// degenerate epoch (`H_close ≤ H_seal`) or a saturating-overflow epoch, both of
/// which the epoch formulas preclude and the seal-committed guards
/// ([`challenge_seal_on_chain`] on the serve-credit side, `H_seal ≤ tip` on the
/// slash side) additionally shield. **Reopen criterion (rule 21):** a Round-2
/// epoch re-pin that admits `H_close ≤ H_seal` (or an unbounded epoch) must
/// restore an `H_fire ∈ (0, H_close]` check at both the serve-credit gate
/// (`blockchain.cpp`) and the slash-eligibility consumer (`db_lmdb.cpp`).
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
