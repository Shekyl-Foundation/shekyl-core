// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Layout-independent logical state digest v0 (DRS-P0d).
//!
//! Canonical encoding of three LMDB families, hashed with cSHAKE256
//! (SP 800-185, house default for new artifacts —
//! `shekyl-crypto-hash::cshake256_32`). The digest is **not** an LMDB
//! page hash: it hashes logical values (height-ordered block hashes,
//! the spent-key **set**, the live curve-tree root), so two engines
//! with the same logical state agree regardless of B-tree layout.
//!
//! # v0 coverage (minimum, `DAEMON_REDB_STORE.md` §7.1 P0d)
//!
//! | Family | Logical input | LMDB tables | Digest mechanism |
//! |---|---|---|---|
//! | Core chain | height-ordered `block_info.bi_hash` | `blocks` / `block_info` | chained cSHAKE over `n ‖ hash_0 ‖ … ‖ hash_{n-1}` |
//! | Spent keys | set of 32-byte key images | `spent_keys` | XOR of per-element cSHAKE (§6.2 set-shaped; order-independent, pop-symmetric) |
//! | Curve root | live Selene root | `curve_tree_meta` `"root"` via `get_curve_tree_root` | 32-byte value as-is (empty tree → Selene `hash_init`) |
//!
//! **Deliberately excluded (P0e / §7.1.1):** archival journals
//! (`archival_*`), txpool, alt-chain, txs, outputs, `curve_tree_roots`
//! history, `hf_versions`, and every other table. A backend that omits
//! archival apply/revert still passes this digest — that is why
//! §7.1.1 forbids extracting S-ARCH until those journals are in the
//! digest (or a named exclusion with a replacement KAT). This module
//! is that named exclusion for v0, without a replacement KAT: do not
//! claim archival parity from a v0 match.
//!
//! # Canonical outer preimage (format version `0x00`)
//!
//! The outer preimage is exactly **113** bytes, hashed with
//! [`OUTER_CUSTOMIZATION`]:
//!
//! | Offset | Width | Field | Notes |
//! |--------|-------|-------|-------|
//! | 0 | 1 | format version tag | [`DIGEST_FORMAT_VERSION`] = `0x00` |
//! | 1 | 8 | `n_blocks` | u64 LE, `BlockchainLMDB::height()` |
//! | 9 | 8 | `n_spent` | u64 LE, cardinality of `spent_keys` |
//! | 17 | 32 | chain component | [`chain_component`] |
//! | 49 | 32 | spent accumulator | [`spent_accumulator`] |
//! | 81 | 32 | curve root | live `get_curve_tree_root()` |
//!
//! Adding, removing, or reordering a field is a breaking layout change
//! and must bump [`DIGEST_FORMAT_VERSION`]. The version tag is how a
//! stale oracle fails loudly rather than matching a preimage that no
//! longer covers the v0 families.
//!
//! # Domain strings (SA-R-2: one string, one context)
//!
//! | Constant | Bytes | Job |
//! |---|---|---|
//! | [`OUTER_CUSTOMIZATION`] | `shekyl/chain-digest/v0` | outer digest |
//! | [`CHAIN_CUSTOMIZATION`] | `shekyl/chain-digest/v0/chain` | height-ordered hash sequence |
//! | [`SPENT_ELEM_CUSTOMIZATION`] | `shekyl/chain-digest/v0/spent-elem` | per-key-image XOR leaf |
//!
//! Incremental accumulators (update-on-insert / reverse-on-delete at
//! every block) are **DRS-0**, not this slice. v0 is a full-domain
//! scan so the canonical logical state is defined before codecs freeze.
//!
//! # Oracle scope (CSR-3 / CSR-3a)
//!
//! A digest match is **correctness** evidence only on a
//! CHECKED-CONFORMANT census row. Over DIVERGENT / UNREVIEWED it is a
//! **regression** instrument. P0d cannot promote rows — that is P0f.
//!
//! # Duplicate spent keys
//!
//! The FFI/hasher treats the spent list as a **set**: LMDB stores it
//! with `MDB_NODUPDATA`, so the walker never yields duplicates. Passing
//! the same key image twice into [`digest_v0`] XORs the leaf with
//! itself and cancels — a caller-contract violation, not a stored
//! state. DRS-0 may replace XOR with an additive field hash; that is a
//! version bump.

use shekyl_crypto_hash::cshake256_32;

/// Format-version tag prefixed to the outer preimage. Bump on any
/// change to the field set, order, widths, or domain strings.
pub const DIGEST_FORMAT_VERSION: u8 = 0x00;

/// Outer cSHAKE customization. Versioned in the string so a preimage
/// change is a new domain rather than a silent reinterpretation.
pub const OUTER_CUSTOMIZATION: &[u8] = b"shekyl/chain-digest/v0";

/// Chain-component cSHAKE customization.
pub const CHAIN_CUSTOMIZATION: &[u8] = b"shekyl/chain-digest/v0/chain";

/// Per-spent-key cSHAKE customization (XOR leaf).
pub const SPENT_ELEM_CUSTOMIZATION: &[u8] = b"shekyl/chain-digest/v0/spent-elem";

/// Length of the outer canonical preimage (`1 + 2×8 + 3×32 = 113`).
///
/// Kept honest by `preimage_length_matches_the_documented_layout`.
pub const DIGEST_PREIMAGE_LEN: usize = 1 + 8 + 8 + 32 + 32 + 32;

/// Layout-independent logical state digest v0.
///
/// `block_hashes` is height-ordered (`hash[h]` at chain height `h`,
/// `h ∈ [0, n)`). `spent_keys` is a set — iteration order is not
/// load-bearing. `curve_root` is the live 32-byte Selene root.
#[must_use]
pub fn digest_v0(
    block_hashes: &[[u8; 32]],
    spent_keys: &[[u8; 32]],
    curve_root: &[u8; 32],
) -> [u8; 32] {
    let preimage = canonical_preimage(block_hashes, spent_keys, curve_root);
    cshake256_32(OUTER_CUSTOMIZATION, &preimage)
}

/// Serialize the v0 families to the documented 113-byte preimage.
///
/// Separated from the hash step so tests can assert the exact byte
/// layout independently of the cSHAKE output.
#[must_use]
pub fn canonical_preimage(
    block_hashes: &[[u8; 32]],
    spent_keys: &[[u8; 32]],
    curve_root: &[u8; 32],
) -> [u8; DIGEST_PREIMAGE_LEN] {
    let mut buf = [0u8; DIGEST_PREIMAGE_LEN];
    buf[0] = DIGEST_FORMAT_VERSION;
    let n_blocks = u64::try_from(block_hashes.len()).expect("block count fits u64");
    let n_spent = u64::try_from(spent_keys.len()).expect("spent-key count fits u64");
    buf[1..9].copy_from_slice(&n_blocks.to_le_bytes());
    buf[9..17].copy_from_slice(&n_spent.to_le_bytes());
    buf[17..49].copy_from_slice(&chain_component(block_hashes));
    buf[49..81].copy_from_slice(&spent_accumulator(spent_keys));
    buf[81..113].copy_from_slice(curve_root);
    buf
}

/// cSHAKE over `u64_le(n) ‖ hash_0 ‖ … ‖ hash_{n-1}` (height order).
///
/// Empty chain (`n = 0`) hashes the 8-byte zero count — not the empty
/// byte string — so a future "forget the count" encoder cannot collide
/// with genesis-only by accident of cSHAKE(empty).
#[must_use]
pub fn chain_component(block_hashes: &[[u8; 32]]) -> [u8; 32] {
    let n = u64::try_from(block_hashes.len()).expect("block count fits u64");
    let mut input = Vec::with_capacity(8 + block_hashes.len() * 32);
    input.extend_from_slice(&n.to_le_bytes());
    for hash in block_hashes {
        input.extend_from_slice(hash);
    }
    cshake256_32(CHAIN_CUSTOMIZATION, &input)
}

/// XOR of `cSHAKE(SPENT_ELEM_CUSTOMIZATION, ki)` over the set.
///
/// Empty set → 32 zero bytes. Order-independent by construction.
#[must_use]
pub fn spent_accumulator(spent_keys: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for ki in spent_keys {
        let leaf = cshake256_32(SPENT_ELEM_CUSTOMIZATION, ki);
        for (dst, src) in acc.iter_mut().zip(leaf.iter()) {
            *dst ^= *src;
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: [u8; 32] = [0x11; 32];
    const HASH_B: [u8; 32] = [0x12; 32];
    const KI_A: [u8; 32] = [0x22; 32];
    const KI_B: [u8; 32] = [0x33; 32];
    const ROOT: [u8; 32] = [0x44; 32];

    /// Self-pinned tripwire for the documented fixture
    /// (`[HASH_A]`, `[KI_A, KI_B]`, `ROOT`). Not a KAT (rule 50): the
    /// value is produced by this module. It bites against an accidental
    /// layout or domain-string edit; it does NOT prove the cSHAKE
    /// primitive, which `shekyl-crypto-hash` already pins.
    const PINNED_FIXTURE: [u8; 32] = [
        0xa6, 0x99, 0x0c, 0x0f, 0xfe, 0xae, 0x0e, 0x0f, 0xfe, 0x43, 0x79, 0x77, 0x62, 0x92, 0x8a,
        0x3c, 0x55, 0xbf, 0xc9, 0x95, 0x2b, 0xfc, 0xbf, 0x81, 0x00, 0xe9, 0x76, 0x65, 0xe0, 0x61,
        0xde, 0xf2,
    ];

    fn fixture() -> [u8; 32] {
        digest_v0(&[HASH_A], &[KI_A, KI_B], &ROOT)
    }

    #[test]
    fn preimage_length_matches_the_documented_layout() {
        assert_eq!(DIGEST_PREIMAGE_LEN, 113);
        let pre = canonical_preimage(&[HASH_A], &[KI_A, KI_B], &ROOT);
        assert_eq!(pre.len(), DIGEST_PREIMAGE_LEN);
        assert_eq!(pre[0], DIGEST_FORMAT_VERSION);
        assert_eq!(&pre[1..9], 1u64.to_le_bytes());
        assert_eq!(&pre[9..17], 2u64.to_le_bytes());
        assert_eq!(&pre[81..113], &ROOT);
    }

    #[test]
    fn spent_accumulator_is_order_independent() {
        let ab = spent_accumulator(&[KI_A, KI_B]);
        let ba = spent_accumulator(&[KI_B, KI_A]);
        assert_eq!(ab, ba);
        assert_eq!(
            digest_v0(&[HASH_A], &[KI_A, KI_B], &ROOT),
            digest_v0(&[HASH_A], &[KI_B, KI_A], &ROOT)
        );
    }

    #[test]
    fn spent_accumulator_is_pop_symmetric() {
        let empty = spent_accumulator(&[]);
        assert_eq!(empty, [0u8; 32]);
        let one = spent_accumulator(&[KI_A]);
        assert_ne!(one, empty);
        // XOR is its own inverse: the leaf of KI_A, XORed twice, is empty.
        let mut restored = one;
        let leaf = cshake256_32(SPENT_ELEM_CUSTOMIZATION, &KI_A);
        for (dst, src) in restored.iter_mut().zip(leaf.iter()) {
            *dst ^= *src;
        }
        assert_eq!(restored, empty);
    }

    #[test]
    fn chain_component_is_height_ordered_not_a_set() {
        let ab = chain_component(&[HASH_A, HASH_B]);
        let ba = chain_component(&[HASH_B, HASH_A]);
        assert_ne!(
            ab, ba,
            "swapping block hashes must change the chain component"
        );
    }

    #[test]
    fn empty_chain_is_not_the_empty_cshake() {
        let counted_empty = chain_component(&[]);
        let empty_bytes = cshake256_32(CHAIN_CUSTOMIZATION, &[]);
        assert_ne!(
            counted_empty, empty_bytes,
            "empty chain must hash the zero count, not the empty string"
        );
    }

    #[test]
    fn curve_root_is_covered() {
        let a = digest_v0(&[], &[], &ROOT);
        let b = digest_v0(&[], &[], &[0x55; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn domain_strings_are_distinct() {
        assert_ne!(OUTER_CUSTOMIZATION, CHAIN_CUSTOMIZATION);
        assert_ne!(OUTER_CUSTOMIZATION, SPENT_ELEM_CUSTOMIZATION);
        assert_ne!(CHAIN_CUSTOMIZATION, SPENT_ELEM_CUSTOMIZATION);
        assert!(!OUTER_CUSTOMIZATION.is_empty());
        assert!(!CHAIN_CUSTOMIZATION.is_empty());
        assert!(!SPENT_ELEM_CUSTOMIZATION.is_empty());
    }

    #[test]
    fn pinned_fixture_tripwire() {
        let got = fixture();
        assert_eq!(
            got, PINNED_FIXTURE,
            "v0 digest fixture moved (got {got:02x?}); this is a layout or \
             domain-string change — bump DIGEST_FORMAT_VERSION and this pin \
             in the same edit"
        );
    }
}
