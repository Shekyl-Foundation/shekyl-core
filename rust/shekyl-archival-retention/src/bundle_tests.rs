// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle's bytes and its three hashes.
//!
//! # Where the pinned hashes come from
//!
//! Every hex value below was computed by a standalone cSHAKE256 (NIST SP
//! 800-185) written over its own Keccak-f[1600], sharing no code with the
//! `sha3` crate the functions under test call. Before it produced these it
//! was held to: SHAKE256 against a second implementation on four inputs,
//! the SP 800-185 cSHAKE256 samples #3 and #4, the specification's §5.2
//! nonce vectors and its §4.5 selection vectors. None is this module's own
//! output pasted back. The inputs are built here by the same small
//! formulas that script used ([`record`], [`witness_key`],
//! [`witness_signature`]); the hash is not.
//!
//! Each test names the edit that turns it red (rule 50).

use super::*;

const SEED: [u8; 32] = [0x11; 32];
const H: BlockHeight = BlockHeight::from_raw(1_000_000);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Record `k` of the vectors: `attempt = k mod 3`, `anchor_height =
/// 999_000 + k`, `delivery_digest = (0xD0 + k) × 32`, and a receipt whose
/// byte `i` is `(7·i + 13·k + 1) mod 251`.
fn record(k: u8) -> BundleRecord {
    let mut receipt = [0u8; BUNDLE_SIGNATURE_LEN];
    for (i, byte) in receipt.iter_mut().enumerate() {
        *byte = u8::try_from((i * 7 + usize::from(k) * 13 + 1) % 251).expect("below 251");
    }
    BundleRecord {
        attempt: k % 3,
        anchor_height: BlockHeight::from_raw(999_000 + u64::from(k)),
        delivery_digest: [0xD0 + k; 32],
        receipt,
    }
}

fn records_bytes(count: u8) -> Vec<u8> {
    (0..count).flat_map(|k| record(k).encode()).collect()
}

/// The vectors' witness key: byte `i` is `(3·i + 5) mod 256`. Not a key;
/// the hashes do not ask.
fn witness_key() -> [u8; BUNDLE_WITNESS_KEY_LEN] {
    let mut out = [0u8; BUNDLE_WITNESS_KEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::try_from((i * 3 + 5) % 256).expect("below 256");
    }
    out
}

/// The vectors' witness signature: byte `i` is `(5·i + 9) mod 256`.
fn witness_signature() -> [u8; BUNDLE_SIGNATURE_LEN] {
    let mut out = [0u8; BUNDLE_SIGNATURE_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::try_from((i * 5 + 9) % 256).expect("below 256");
    }
    out
}

fn body(count: u8) -> BundleBody {
    let records: Vec<BundleRecord> = (0..count).map(record).collect();
    BundleBody::new(&witness_key(), &witness_signature(), &records)
}

// ---------------------------------------------------------------- widths

/// The record is as wide as the scheme's canonical signature makes it, and
/// the scheme's signature is fixed-width: that is the one fact the
/// unframed layout rests on (§7.3). Red edit: add a field to
/// `BundleRecord::encode`, or move scheme 3 to a signature of another
/// length — the module's const assertions stop the build first.
#[test]
fn the_record_width_is_the_schemes_signature_and_41_bytes() {
    assert_eq!(BUNDLE_SIGNATURE_LEN, FnDsaHybridSignature::CANONICAL_LEN);
    assert_eq!(BUNDLE_WITNESS_KEY_LEN, FnDsaHybridPublicKey::CANONICAL_LEN);
    assert_eq!(
        BUNDLE_RECORD_LEN,
        41 + FnDsaHybridSignature::CANONICAL_LEN,
        "attempt, anchor height, delivery digest, receipt"
    );
    assert_eq!(BUNDLE_RECORD_LEN, 1_397);
    assert_eq!(record(0).encode().len(), 1_397);
}

// ---------------------------------------------------------------- bitmap

/// The bitmap projection (`SCS-P35`): draw `j` is bit `j mod 8` of byte
/// `⌊j / 8⌋`, least significant bit first. Red edit: shift from the top
/// (`0x80 >> (j % 8)`) and draw 0 reads `0x80`.
#[test]
fn the_bitmap_is_least_significant_bit_first() {
    let only_zero = PassBitmap::from_passes(12, [0]).expect("in range");
    assert_eq!(only_zero.as_bytes(), [0x01, 0x00]);
    let only_nine = PassBitmap::from_passes(12, [9]).expect("in range");
    assert_eq!(only_nine.as_bytes(), [0x00, 0x02]);
    let three = PassBitmap::from_passes(12, [0, 9, 11]).expect("in range");
    assert_eq!(three.as_bytes(), [0x01, 0x0A]);

    // And read back the same way, from bytes.
    let read = PassBitmap::new(12, &[0x01, 0x0A]).expect("twelve bits");
    assert_eq!(read, three);
    assert_eq!(read.count(), 12);
    assert_eq!(read.popcount(), 3);
    assert_eq!(read.iter_set().collect::<Vec<_>>(), [0, 9, 11]);
    for draw in 0..12 {
        assert_eq!(read.get(draw), [0, 9, 11].contains(&draw), "draw {draw}");
    }
    assert!(!read.get(12), "nothing passes at or beyond the count");
    assert!(!read.get(u32::MAX));
}

/// A set padding bit refuses (`SCS-P35`). Red edit: drop the padding check
/// in `PassBitmap::new`; every assertion here then finds `Ok`.
#[test]
fn a_set_padding_bit_refuses_the_bitmap() {
    // Twelve bits: the top four of the second byte are padding.
    for padding_bit in 4..8 {
        let bytes = [0x01, 0x0A | (1 << padding_bit)];
        assert_eq!(
            PassBitmap::new(12, &bytes),
            Err(BundleWireError::BitmapPadding { count: 12 }),
            "bit {padding_bit} of the last byte"
        );
    }
    // One bit: seven padding bits.
    assert_eq!(
        PassBitmap::new(1, &[0x02]),
        Err(BundleWireError::BitmapPadding { count: 1 })
    );
    // A whole number of bytes has no padding, so every bit may be set.
    assert_eq!(PassBitmap::new(8, &[0xFF]).expect("eight").popcount(), 8);
    assert_eq!(
        PassBitmap::new(16, &[0xFF, 0xFF]).expect("16").popcount(),
        16
    );
}

/// The bitmap is exactly `⌈count / 8⌉` bytes. Red edit: accept `>=` and
/// the long cases pass.
#[test]
fn a_bitmap_of_the_wrong_length_refuses() {
    for (count, len) in [(0u32, 1usize), (1, 0), (1, 2), (8, 2), (9, 1), (12, 3)] {
        let bytes = vec![0u8; len];
        assert_eq!(
            PassBitmap::new(count, &bytes),
            Err(BundleWireError::BitmapLength {
                count,
                expected: PassBitmap::byte_len(count),
                found: len
            }),
            "{count} bits in {len} bytes"
        );
    }
    assert_eq!(PassBitmap::byte_len(0), 0);
    assert_eq!(PassBitmap::byte_len(1), 1);
    assert_eq!(PassBitmap::byte_len(8), 1);
    assert_eq!(PassBitmap::byte_len(9), 2);
    assert_eq!(PassBitmap::byte_len(292), 37);
    assert_eq!(PassBitmap::byte_len(u32::MAX), 536_870_912);
}

/// A block with no draws has an empty bitmap, and it is a bitmap.
#[test]
fn a_block_with_no_draws_has_an_empty_bitmap() {
    let empty = PassBitmap::new(0, &[]).expect("zero bits");
    assert_eq!(empty.count(), 0);
    assert_eq!(empty.popcount(), 0);
    assert_eq!(empty.iter_set().count(), 0);
    assert!(!empty.get(0));
    assert_eq!(
        PassBitmap::from_passes(0, [0]),
        Err(BundleWireError::PassOutOfRange { draw: 0, count: 0 })
    );
}

// ------------------------------------------------------------ wire forms

/// The kept part round-trips, is exactly `40 + ⌈count / 8⌉` bytes, and
/// reads only against its own count. Red edit: write `h` big-endian and
/// the byte assertion fails; accept a longer input and the length cases do.
#[test]
fn the_kept_part_round_trips_at_its_exact_length() {
    let kept = BundleKept {
        h: H,
        seed: SEED,
        passes: PassBitmap::from_passes(12, [0, 9, 11]).expect("in range"),
    };
    let bytes = kept.encode();
    assert_eq!(bytes.len(), 42);
    assert_eq!(bytes[..32], SEED);
    assert_eq!(bytes[32..40], 1_000_000u64.to_le_bytes());
    assert_eq!(bytes[40..], [0x01, 0x0A]);
    assert_eq!(BundleKept::decode(&bytes, 12), Ok(kept.clone()));

    // Any count with the same byte length and no padding conflict reads;
    // a count with another byte length does not.
    assert!(BundleKept::decode(&bytes, 16).is_ok());
    for count in [0u32, 8, 17] {
        assert_eq!(
            BundleKept::decode(&bytes, count),
            Err(BundleWireError::KeptLength {
                expected: 40 + PassBitmap::byte_len(count),
                found: 42
            })
        );
    }
    // Eleven bits: bit 11 is padding, and it is set.
    assert_eq!(
        BundleKept::decode(&bytes, 11),
        Err(BundleWireError::BitmapPadding { count: 11 })
    );
    let mut long = bytes.clone();
    long.push(0);
    assert!(matches!(
        BundleKept::decode(&long, 12),
        Err(BundleWireError::KeptLength { .. })
    ));
    assert!(matches!(
        BundleKept::decode(&bytes[..41], 12),
        Err(BundleWireError::KeptLength { .. })
    ));
}

/// A record round-trips through its 1,397 bytes with every field where
/// §7.2 puts it. Red edit: swap two fields in `encode` and not in `decode`.
#[test]
fn a_record_round_trips_field_by_field() {
    let r = record(2);
    let bytes = r.encode();
    assert_eq!(bytes[0], 2);
    assert_eq!(bytes[1..9], 999_002u64.to_le_bytes());
    assert_eq!(bytes[9..41], [0xD2; 32]);
    assert_eq!(bytes[41..], r.receipt);
    assert_eq!(BundleRecord::decode(&bytes), r);
}

/// The prunable part round-trips and refuses every length that is not the
/// witness key, the witness signature and whole records. Red edit: drop
/// the remainder check in `BundleBody::decode`.
#[test]
fn the_prunable_part_round_trips_at_its_exact_length() {
    let three = body(3);
    assert_eq!(three.as_bytes().len(), 3_193 + 3 * 1_397);
    assert_eq!(three.witness_public_key(), &witness_key());
    assert_eq!(three.witness_signature(), &witness_signature());
    assert_eq!(three.record_count(), 3);
    assert_eq!(
        three.records().collect::<Vec<_>>(),
        [record(0), record(1), record(2)]
    );
    assert_eq!(three.records_bytes(), records_bytes(3));
    assert_eq!(BundleBody::decode(three.as_bytes()), Ok(three.clone()));

    let none = body(0);
    assert_eq!(none.as_bytes().len(), 3_193);
    assert_eq!(none.record_count(), 0);
    assert_eq!(BundleBody::decode(none.as_bytes()), Ok(none));

    let bytes = three.as_bytes();
    for len in [
        0,
        3_192,
        3_194,
        3_193 + 1_396,
        3_193 + 1_398,
        bytes.len() - 1,
    ] {
        let mut cut = bytes.to_vec();
        cut.resize(len, 0);
        assert_eq!(
            BundleBody::decode(&cut),
            Err(BundleWireError::BodyLength { found: len }),
            "{len} bytes"
        );
    }
}

/// A reference is the kept bytes and the prunable hash, round-trips, and
/// refuses fewer than its 72 fixed bytes. Red edit: read the hash from the
/// front and the field assertions fail.
#[test]
fn a_reference_round_trips_and_is_the_kept_bytes_then_the_hash() {
    let kept = BundleKept {
        h: H,
        seed: SEED,
        passes: PassBitmap::from_passes(12, [0, 9, 11]).expect("in range"),
    };
    let three = body(3);
    let reference = BundleRef::of(&kept, &three);
    let bytes = reference.encode();
    assert_eq!(bytes.len(), 74, "72 and a two-byte bitmap (§7.5, SCS-F17)");
    assert_eq!(bytes[..42], kept.encode(), "the kept bytes, verbatim");
    assert_eq!(bytes[42..], three.prunable_hash());
    assert_eq!(BundleRef::decode(&bytes), Ok(reference.clone()));
    assert_eq!(reference.h(), H);
    assert_eq!(reference.seed(), &SEED);
    assert_eq!(reference.bitmap_bytes(), [0x01, 0x0A]);
    assert_eq!(reference.kept(12), Ok(kept));
    assert_eq!(
        reference.kept(4),
        Err(BundleWireError::BitmapLength {
            count: 4,
            expected: 1,
            found: 2
        })
    );
    assert_eq!(
        reference.body_len(),
        three.as_bytes().len() as u64,
        "the reference fixes its body's length"
    );

    for len in [0usize, 71] {
        assert_eq!(
            BundleRef::decode(&bytes[..len]),
            Err(BundleWireError::ReferenceLength { found: len })
        );
    }
    // 72 bytes is a reference to a bundle of no draws.
    let empty = BundleRef::new(SEED, H, &[], [7; 32]).expect("no bitmap");
    assert_eq!(empty.encode().len(), 72);
    assert_eq!(BundleRef::decode(&empty.encode()), Ok(empty.clone()));
    assert_eq!(empty.body_len(), 3_193);
}

// ------------------------------------------------------------ commitment

/// The bundle commitment's vectors (§7.3, `SCS-P35`): no draws; eight
/// draws and no pass; one record; three records with a bitmap that crosses
/// a byte boundary; that case at `h + 1`; that case with one more bit set
/// and the same records. Red edits: drop `count_le[4]`; write `h`
/// big-endian; rename the label; put the records before the bitmap.
#[test]
fn the_bundle_commitment_matches_its_vectors() {
    let three = records_bytes(3);
    assert_eq!(
        hex(&bundle_commitment(&SEED, H, 0, &[], &[])),
        "0095223a6b8da68f74cb3a7b4172de3535846465118aee794cd7cd23841db5e9"
    );
    assert_eq!(
        hex(&bundle_commitment(&SEED, H, 8, &[0x00], &[])),
        "c2754942eca20acb5ea172d6b9590c0998f8cdb2c2c055db56b9f7cd65394dac"
    );
    assert_eq!(
        hex(&bundle_commitment(
            &SEED,
            H,
            1,
            &[0x01],
            &record(0).encode()
        )),
        "fe450e70bf107a130c82a2cf081a667470e58f24f7d6fa3db850ef455128a65b"
    );
    assert_eq!(
        hex(&bundle_commitment(&SEED, H, 12, &[0x01, 0x0A], &three)),
        "63a50faab6ab3a97baa9f86e0ad3aa639e57a18c4f1dcbb9b9de75c1fd558796"
    );
    assert_eq!(
        hex(&bundle_commitment(
            &SEED,
            BlockHeight::from_raw(1_000_001),
            12,
            &[0x01, 0x0A],
            &three
        )),
        "5fb66eec3dbc2df6e99be83f51b7112020417b1db1224422794ef4cdbf6793e3"
    );
    assert_eq!(
        hex(&bundle_commitment(&SEED, H, 12, &[0x09, 0x0A], &three)),
        "2dacbfd26047a38e935d6cbb5ef99391b84492d3aa6d1bcf5120b38542ce1557"
    );
}

/// The typed path computes the same commitment as the byte path, so the
/// vectors above pin what the verifier compares. Red edit: have
/// `BundleKept::commitment` pass the bitmap's popcount for `count`.
#[test]
fn the_kept_parts_commitment_is_the_vectors_commitment() {
    let kept = BundleKept {
        h: H,
        seed: SEED,
        passes: PassBitmap::from_passes(12, [0, 9, 11]).expect("in range"),
    };
    assert_eq!(
        hex(&kept.commitment(body(3).records_bytes())),
        "63a50faab6ab3a97baa9f86e0ad3aa639e57a18c4f1dcbb9b9de75c1fd558796"
    );
}

/// The commitment covers every byte of the seed, `h`, the count, the
/// bitmap and each record. Red edit: stop hashing any one of them.
#[test]
fn the_commitment_moves_with_every_field() {
    let three = records_bytes(3);
    let base = bundle_commitment(&SEED, H, 12, &[0x01, 0x0A], &three);
    let mut seed = SEED;
    seed[31] ^= 1;
    assert_ne!(base, bundle_commitment(&seed, H, 12, &[0x01, 0x0A], &three));
    // Thirteen bits in the same two bytes: only the count differs.
    assert_ne!(base, bundle_commitment(&SEED, H, 13, &[0x01, 0x0A], &three));
    for at in [0, 1, 9, 41, 1_396, 1_397, 2 * 1_397 + 700, three.len() - 1] {
        let mut flipped = three.clone();
        flipped[at] ^= 0x01;
        assert_ne!(
            base,
            bundle_commitment(&SEED, H, 12, &[0x01, 0x0A], &flipped),
            "record byte {at}"
        );
    }
    // The records in another order are another bundle.
    let mut swapped = record(1).encode().to_vec();
    swapped.extend_from_slice(&record(0).encode());
    swapped.extend_from_slice(&record(2).encode());
    assert_ne!(
        base,
        bundle_commitment(&SEED, H, 12, &[0x01, 0x0A], &swapped)
    );
}

/// The bundle commitment is not the carrier's set commitment over the same
/// seed and height: a new message under a new label (§7.3). Red edit: give
/// `BUNDLE_COMMITMENT_CUSTOMIZATION` the carrier's bytes.
#[test]
fn the_bundle_label_is_not_the_carriers() {
    assert_ne!(
        BUNDLE_COMMITMENT_CUSTOMIZATION,
        crate::secret_draw::SERVE_CREDIT_BATCH_CUSTOMIZATION
    );
    assert_ne!(
        BUNDLE_COMMITMENT_CUSTOMIZATION,
        BUNDLE_PRUNABLE_CUSTOMIZATION
    );
    assert_ne!(BUNDLE_COMMITMENT_CUSTOMIZATION, BUNDLE_ROOT_CUSTOMIZATION);
    assert_ne!(BUNDLE_PRUNABLE_CUSTOMIZATION, BUNDLE_ROOT_CUSTOMIZATION);
}

// ---------------------------------------------------- prunable hash, root

/// The prunable hash's vectors: a body with no records and one with
/// three. Red edit: hash only the records, or rename the label.
#[test]
fn the_prunable_hash_matches_its_vectors() {
    assert_eq!(
        hex(&body(0).prunable_hash()),
        "dbe9e9c1bc25076eb62dea786a02651090551b7a918f7338a9e25ddc5fc91e0a"
    );
    assert_eq!(
        hex(&body(3).prunable_hash()),
        "55200abf66225b662f00844f3fc20d27f0dac951644a7f3e9c105893ee98795c"
    );
    assert_eq!(
        body(3).prunable_hash(),
        bundle_prunable_hash(body(3).as_bytes())
    );
}

/// The two references of the root's vectors: a bundle of twelve draws with
/// three passes at `h`, and a bundle of no draws at `h + 7` under seed
/// `0x12 × 32`.
fn vector_refs() -> (BundleRef, BundleRef) {
    let first = BundleRef::new(SEED, H, &[0x01, 0x0A], body(3).prunable_hash()).expect("short");
    let second = BundleRef::new(
        [0x12; 32],
        BlockHeight::from_raw(1_000_007),
        &[],
        body(0).prunable_hash(),
    )
    .expect("short");
    (first, second)
}

/// The header root's vectors: over no reference, one, and two. Red edits:
/// drop `n_le[4]`; drop the per-reference length; hash `h` before the
/// seed; rename the label.
#[test]
fn the_root_matches_its_vectors() {
    let (first, second) = vector_refs();
    assert_eq!(
        hex(&bundle_root(&[])),
        "1d271689c2934e75f2b8a25f57a686a75744d5f254ce014341eeba7b56845226"
    );
    assert_eq!(
        hex(&bundle_root(std::slice::from_ref(&first))),
        "28f79edee4d4b9c73eb4502893f34cf62196ea7741e78d910da023d2c4b64586"
    );
    assert_eq!(
        hex(&bundle_root(&[first.clone(), second.clone()])),
        "d51fdf589f25e1fd2faf0f034041ab2ce20e6490831fac9b66efb5e524a4c85e"
    );
    // The control the standalone implementation also printed: one
    // reference hashed without its length frame. The root is not that.
    assert_ne!(
        hex(&bundle_root(std::slice::from_ref(&first))),
        "a0cd5a63ab59a2ad0579d327cdd65032ae129ebc48825d8f63483fa893a510c9"
    );
    // Order is hashed: the section check refuses the swap, and the root
    // would not agree with it either.
    assert_ne!(
        bundle_root(&[first.clone(), second.clone()]),
        bundle_root(&[second, first])
    );
}

/// The root covers each reference's seed, `h`, bitmap and prunable hash.
/// Red edit: leave any one out of `BundleRef::encode`.
#[test]
fn the_root_moves_with_every_field_of_a_reference() {
    let (first, second) = vector_refs();
    let base = bundle_root(&[first.clone(), second.clone()]);
    let with = |changed: BundleRef| bundle_root(&[changed, second.clone()]);
    let ph = *first.prunable_hash();
    let mut seed = SEED;
    seed[0] ^= 1;
    assert_ne!(
        base,
        with(BundleRef::new(seed, H, &[0x01, 0x0A], ph).expect("short"))
    );
    assert_ne!(
        base,
        with(
            BundleRef::new(SEED, BlockHeight::from_raw(999_999), &[0x01, 0x0A], ph).expect("short")
        )
    );
    assert_ne!(
        base,
        with(BundleRef::new(SEED, H, &[0x01, 0x08], ph).expect("short"))
    );
    let mut other = ph;
    other[31] ^= 1;
    assert_ne!(
        base,
        with(BundleRef::new(SEED, H, &[0x01, 0x0A], other).expect("short"))
    );
}

// ---------------------------------------------------------------- budget

/// The section budget (§7.4, `SCS-P33`): `c · (⌊9·D / SEB⌋ + 1)`. Red
/// edits: drop the `+ 1` (the small-`D` rows read 0); multiply before
/// flooring (`D` = 1,112 reads 4 only by the floor).
#[test]
fn the_section_budget_is_c_count_caps() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let c = BUNDLE_SECTION_BUDGET_MULTIPLE;
    assert_eq!(c, 2, "PROVISIONAL (§13.2 V6)");
    // Below SEB / 9 pairs the floor is zero and the cap is the `+ 1`.
    assert_eq!(section_budget(c, 0, seb), 2);
    assert_eq!(section_budget(c, 8, seb), 2);
    assert_eq!(section_budget(c, 1_111, seb), 2);
    // 9 · 1,112 = 10,008: the floor reaches one.
    assert_eq!(section_budget(c, 1_112, seb), 4);
    // §7.4's table: the count cap is 292 at D = 324,000 and 2,791 at
    // D = 3,100,000.
    assert_eq!(section_budget(1, 324_000, seb), 292);
    assert_eq!(section_budget(c, 324_000, seb), 584);
    assert_eq!(section_budget(1, 3_100_000, seb), 2_791);
    assert_eq!(section_budget(0, 324_000, seb), 0);
}

/// The budget does not overflow: it saturates. Red edit: compute in `u64`
/// and the first line panics under `overflow-checks`.
#[test]
fn the_section_budget_saturates() {
    let one = SettlementEpochBlocks::new(1).expect("non-zero");
    assert_eq!(section_budget(2, u64::MAX, one), u64::MAX);
    assert_eq!(section_budget(u64::MAX, u64::MAX, one), u64::MAX);
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    assert_eq!(
        section_budget(1, u64::MAX, seb),
        u64::try_from(u128::from(u64::MAX) * 9 / 10_000 + 1).expect("fits")
    );
}
