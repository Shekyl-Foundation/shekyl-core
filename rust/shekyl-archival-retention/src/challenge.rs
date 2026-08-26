// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic epoch challenge replay per
//! [`ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md) §3.3–§3.4.
//!
//! **Mechanism status (2026-08-11, corrected 2026-08-23):** the fire-beacon
//! shape this module implements (`H_seal`/`H_fire`, one challenge per
//! pair-epoch) is **superseded by derived assignment** for *deciding which
//! pairs get challenged* — `ARCHIVAL_CHALLENGE_MECHANISM.md` §2, implemented
//! in [`crate::challenge_assignment`]: `assignment(h)` seeds from
//! `block_hash(h−1)`, issues `CHALLENGES_PER_PAIR_PER_EPOCH = 3` per
//! pair-epoch, and needs no seal lag. This module is **not dead code**: it is
//! the live serve-credit admission path (through `shekyl-ffi` into
//! `blockchain.cpp`'s serve-credit gate and `db_lmdb.cpp`'s slash-eligibility
//! consumer).
//!
//! # It does NOT delete wholesale, and the trigger that said so has fired
//!
//! The 2026-08-11 wording said this module "deletes wholesale with that
//! round's deletion surface", naming the **format round** as the trigger.
//! That round landed 2026-08-21 (PR #522) and **ruled the opposite way** for
//! the leaf-opening half: `RF-D8` ruling (i) kept the ~1,920 B opening as the
//! one element consensus verifies independently of the witness, so
//! [`challenge_leaf_index`] came **off** the deletion surface and is now
//! permanent consensus admission code — derived verifier-side and fed
//! straight into path verification and the signature preimage
//! (`shekyl-ffi/src/archival_ffi/serve_credit.rs`, reached from
//! `blockchain.cpp`). [`crate::path`] already records that correction; this
//! banner did not, and the two modules disagreed for three days.
//!
//! Deleting on the strength of the old wording would remove **live consensus
//! code**, which is why the correction is written here rather than left to a
//! reader to reconcile against [`crate::path`].
//!
//! **What is settled:** the leaf-opening cluster is kept by `RF-D8`. It spans
//! three modules — [`challenge_leaf_index`] here,
//! [`crate::challenge_leaf_chunk_bounds`] and
//! [`crate::challenged_leaf_offset_in_chunk`] in `segment_freeze`, and
//! [`crate::challenged_leaf_bytes`] in `path` — which is worth stating,
//! because "the sampled-leaf path" reads like one module and deleting it as
//! one is how the fired trigger above would have been executed.
//!
//! **What is not settled here:** the beacon-timing cluster
//! ([`challenge_seal_height`], [`challenge_seal_on_chain`],
//! [`challenge_fire_height`]) is still beacon-shaped and still live as the
//! admission window gate. Every public item in this module has production
//! callers today, so nothing is delete-on-sight. Its disposition belongs to
//! the settlement-writer round (`ARCHIVAL_SETTLEMENT_WRITER.md`), which
//! replaces the settlement side — **it is deliberately not ruled by this
//! comment.**
//!
//! Extend the *new* mechanism, never the beacon half.

use crate::constants::CHALLENGE_BEACON_SEAL_BLOCKS;
use crate::hash::cshake256_32;

/// cSHAKE256 customization for leaf index derivation (§3.3, `PC-D3`).
///
/// **`-v2` because the derivation changed, not because a version was due.**
/// `PC-D3` added `block_hash(h−1)` to the preimage so each of a pair-epoch's
/// three challenges samples an **independently drawn** leaf — independent
/// draws, not guaranteed-distinct ones: two blocks can still land on the same
/// leaf mod `segment_leaf_count`, and the test below tolerates exactly that.
/// Under `-v1` the index was a function of `(P, s, E)` alone, so the three
/// draws were never independent at all: three per-challenge records carried
/// three genuinely distinct countersignatures over three **identical**
/// openings — an artifact that looks like three tests and contains one.
///
/// The label moves with the function (rule 30). Pre-genesis there is nothing to
/// migrate; the bump exists so **one label never names two functions**, which is
/// the failure a second implementation would hit and not notice.
pub const CHALLENGE_LEAF_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-challenge-leaf-v2";

/// The retired `-v1` label, kept **only** so the negative control in this
/// module's tests can assert the new derivation does not reproduce the old
/// one. It has no caller outside those tests and must never acquire one.
#[cfg(test)]
const CHALLENGE_LEAF_CUSTOMIZATION_V1_RETIRED: &[u8] = b"shekyl/archival-serve-challenge-leaf-v1";

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
    prev_block_hash: &[u8; 32],
    segment_leaf_count: u64,
) -> u32 {
    if segment_leaf_count == 0 {
        return 0;
    }
    let mut input = Vec::with_capacity(32 + 8 + 8 + 32);
    input.extend_from_slice(p_id);
    input.extend_from_slice(&shard_id.to_le_bytes());
    input.extend_from_slice(&settlement_epoch.to_le_bytes());
    // `PC-D3`: the challenge's block, as the HASH and not the height. A height
    // is a reference a reorg can silently repoint at a different block; a hash
    // names the block. And `RF-D5`'s nonce already binds this same
    // `block_hash(h−1)`, so the record keeps ONE block reference rather than
    // two that could disagree — a record carrying two references that can
    // diverge has a state nobody has reasoned about.
    //
    // Appended last so the `(P, s, E)` prefix stays where every reader of this
    // preimage already expects it.
    input.extend_from_slice(prev_block_hash);
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
    use crate::segment_freeze::SEGMENT_LEAF_COUNT;

    /// A stand-in block for the tests that hold the block fixed while varying
    /// something else. Named rather than inlined so it is visibly the SAME
    /// block on both sides of a comparison: a test that varies the epoch is
    /// only about the epoch if the block does not move with it.
    const FIXED_BLOCK: [u8; 32] = [0x5Au8; 32];

    #[test]
    fn leaf_index_is_deterministic() {
        let p = [0x42u8; 32];
        let a = challenge_leaf_index(&p, 7, 100, &FIXED_BLOCK, 26_000);
        let b = challenge_leaf_index(&p, 7, 100, &FIXED_BLOCK, 26_000);
        assert_eq!(a, b);
    }

    #[test]
    fn leaf_index_changes_with_epoch() {
        let p = [0x42u8; 32];
        let a = challenge_leaf_index(&p, 7, 100, &FIXED_BLOCK, 26_000);
        let b = challenge_leaf_index(&p, 7, 101, &FIXED_BLOCK, 26_000);
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_index_within_segment() {
        let p = [0x11u8; 32];
        let count = 26_000u64;
        let idx = challenge_leaf_index(&p, 3, 50, &FIXED_BLOCK, count);
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

    // ── `PC-D3`: the block-bound leaf index ──────────────────────────────────

    /// The property the whole round exists for: the block hash materially
    /// affects the draw, so two challenges on the same pair-epoch draw their
    /// leaves independently. NOT distinctness — the tolerance below admits
    /// modulo collisions, and a collision is a valid outcome.
    ///
    /// Under `-v1` even independence was absent — the index was a function of
    /// `(P, s, E)` alone, so three records carried three distinct
    /// countersignatures over three identical openings. The edit that makes
    /// this red is dropping `prev_block_hash` from the preimage.
    #[test]
    fn the_block_hash_materially_affects_the_draw() {
        let p = [0x11u8; 32];
        let mut differing = 0;
        // Over a realistic segment, distinct blocks must land on distinct
        // leaves in the overwhelming majority of draws. Asserting on a spread
        // rather than one pair keeps this from passing on a lucky collision.
        for i in 0..64u8 {
            let mut h1 = [0u8; 32];
            let mut h2 = [0u8; 32];
            h1[0] = i;
            h2[0] = i;
            h1[1] = 0xAA;
            h2[1] = 0xBB;
            let a = challenge_leaf_index(&p, 7, 3, &h1, SEGMENT_LEAF_COUNT);
            let b = challenge_leaf_index(&p, 7, 3, &h2, SEGMENT_LEAF_COUNT);
            if a != b {
                differing += 1;
            }
        }
        assert!(
            differing >= 60,
            "only {differing}/64 block pairs sampled different leaves; the index is \
             not meaningfully block-bound and three records would prove one fetch"
        );
    }

    /// Same block, same everything ⇒ same index. Consensus must agree, so the
    /// derivation is a pure function and not merely well-distributed.
    #[test]
    fn same_block_is_deterministic() {
        let p = [0x22u8; 32];
        let h = [0x5Au8; 32];
        assert_eq!(
            challenge_leaf_index(&p, 9, 4, &h, SEGMENT_LEAF_COUNT),
            challenge_leaf_index(&p, 9, 4, &h, SEGMENT_LEAF_COUNT)
        );
    }

    /// **The negative control on the domain separator.**
    ///
    /// A domain separator that ships is a consensus fact — it is the one
    /// irreversible item in this round, and "it compiled and the tests passed"
    /// cannot distinguish a correct derivation from a differently-wrong one.
    /// So this asserts the new label does not reproduce the old one on the
    /// same preimage: if someone reverts `-v2` to `-v1`, or a second
    /// implementation keeps the retired label, this fails rather than
    /// silently agreeing on a different function.
    #[test]
    fn the_v2_label_does_not_reproduce_the_retired_v1_derivation() {
        let p = [0x33u8; 32];
        let h = [0x77u8; 32];

        let mut input = Vec::with_capacity(32 + 8 + 8 + 32);
        input.extend_from_slice(&p);
        input.extend_from_slice(&9u64.to_le_bytes());
        input.extend_from_slice(&4u64.to_le_bytes());
        input.extend_from_slice(&h);

        let under_v2 = cshake256_32(CHALLENGE_LEAF_CUSTOMIZATION, &input);
        let under_v1 = cshake256_32(CHALLENGE_LEAF_CUSTOMIZATION_V1_RETIRED, &input);

        assert_ne!(
            under_v2, under_v1,
            "the -v2 label reproduced the -v1 derivation on the same preimage: the \
             separator is not separating, so two implementations could disagree \
             about which function a single label names"
        );
        assert_eq!(
            CHALLENGE_LEAF_CUSTOMIZATION, b"shekyl/archival-serve-challenge-leaf-v2",
            "the shipped label is a consensus fact; changing it is a re-pin, not an edit"
        );
    }

    /// **Hand-derived vector: the `-v2` derivation checked against an
    /// implementation that is not this one.**
    ///
    /// Everything else in this module compares `challenge_leaf_index` to
    /// itself — determinism, spread, a label inequality. All of it passes just
    /// as happily if the preimage is assembled in the wrong order, the shard
    /// and epoch are byte-swapped, or the wrong eight bytes of `tau` are read.
    /// "It compiled and the tests passed" cannot separate a correct derivation
    /// from a differently-wrong one, and the separator is a consensus fact, so
    /// the value below comes from outside.
    ///
    /// **Provenance.** Derived with an independent cSHAKE256 written from
    /// FIPS 202 / SP 800-185 against `PC-D3`'s specified preimage — *not* by
    /// transcribing this function — whose Keccak-f[1600] sponge was first
    /// checked against `hashlib.shake_256` and whose customized path
    /// reproduces NIST SP 800-185 cSHAKE256 Sample #3
    /// (`D008828E2B80AC9D…281C8C`). The same oracle reproduces the
    /// `gate2_serve_credit_kat_v1.json` indices (13125 and 14593).
    ///
    /// Inputs are the fixture's `synthetic_p42_epoch_100` case verbatim, so a
    /// regen that moves the fixture without moving the derivation is caught
    /// here rather than accepted as the new truth.
    ///
    /// The edit that makes this red is any change to the preimage byte order,
    /// the integer widths, the `tau` slice, the endianness of either, or the
    /// label.
    #[test]
    fn the_v2_derivation_matches_an_independently_computed_vector() {
        // preimage = P[32] ‖ LE64(shard) ‖ LE64(epoch) ‖ block_hash(h−1)[32]
        let p = [0x42u8; 32];
        // Spelled out rather than computed: a KAT input built by a loop is a
        // small reimplementation, and this vector exists precisely because a
        // small reimplementation can be wrong.
        let prev: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
            0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ];
        assert_eq!(
            challenge_leaf_index(&p, 7, 100, &prev, 25_992),
            13_125,
            "the -v2 derivation disagrees with an independent implementation of \
             its specification; one of the two is wrong and it is not \
             necessarily this one"
        );
    }

    /// A zero-length segment yields index 0 and does not divide by zero — the
    /// pre-existing guard, re-asserted because the preimage grew around it.
    #[test]
    fn empty_segment_is_index_zero() {
        assert_eq!(
            challenge_leaf_index(&[0x44u8; 32], 1, 1, &[0x99u8; 32], 0),
            0
        );
    }
}
