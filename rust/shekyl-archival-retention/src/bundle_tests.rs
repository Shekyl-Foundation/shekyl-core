// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle's bytes and its three hashes.
//!
//! # Where the pinned hashes come from
//!
//! The pins through 2026-10-12 were computed by a standalone cSHAKE256
//! (NIST SP 800-185) written over its own Keccak-f[1600], sharing no code
//! with the `sha3` crate the functions under test call. Before it produced
//! those it was held to: SHAKE256 against a second implementation on four
//! inputs, the SP 800-185 cSHAKE256 samples #3 and #4, the specification's
//! §5.2 nonce vectors and its §4.5 selection vectors. The root's vectors
//! were recomputed by that script on 2026-10-12, when the kept part gained
//! its `count` and the root lost its per-reference frame (`SCS-P39`).
//! On 2026-10-22 the kept encoding gained the support count and its bitmap
//! (`ARCHIVAL_SUPPORT_DRAW.md` §5). On 2026-10-23 the empty-support figures
//! below, and the nonempty support commitment and root, were produced by
//! `docs/test_vectors/RPC_CHANNEL_NAMES_V1/generate.py`. Its `cshake256` is
//! its own Keccak, checked against hashlib's SHAKE256 and NIST SP 800-185
//! sample #3, and it shares no code with this crate. The inputs are built
//! here by those formulas ([`record`], [`witness_key`],
//! [`witness_signature`]).
//!
//! Each test names the edit that turns it red (rule 50).

use super::*;

const SEED: [u8; 32] = [0x11; 32];
const H: BlockHeight = BlockHeight::from_raw(1_000_000);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// [`bundle_root`] over a section every test here can hold: far fewer than
/// 2³² references, so the one refusal is not this helper's.
fn root(refs: &[BundleRef]) -> [u8; 32] {
    bundle_root(refs).expect("a test section's count fits 32 bits")
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

/// A kept part at `h` under [`SEED`] with these bitmap bytes read as
/// `count` bits, and no support draws.
fn kept_at(h: BlockHeight, count: u32, bitmap: &[u8]) -> BundleKept {
    BundleKept {
        h,
        seed: SEED,
        passes: PassBitmap::new(count, bitmap).expect("the vector's bitmap"),
        support: PassBitmap::none(),
    }
}

/// The twelve-draw vector with support draw 0 also set. The support
/// bitmap is one byte, bit 0.
fn twelve_with_one_support() -> BundleKept {
    BundleKept {
        h: H,
        seed: SEED,
        passes: PassBitmap::new(12, &[0x01, 0x0A]).expect("twelve draws"),
        support: PassBitmap::from_passes(1, [0]).expect("support draw 0"),
    }
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

/// The kept part states its own count (`SCS-P39`): it round-trips, is
/// exactly `44 + ⌈count / 8⌉` bytes, and parses with nothing supplied
/// from outside. Red edits: write `h` or `count` big-endian (the byte
/// assertions fail); take the count from the bitmap's length (`8 · len`)
/// instead of the stated field — twelve bits then read as sixteen and the
/// round trip fails; accept a longer input.
#[test]
fn the_kept_part_states_its_count_and_round_trips_at_its_exact_length() {
    let kept = kept_at(H, 12, &[0x01, 0x0A]);
    let bytes = kept.encode();
    assert_eq!(bytes.len(), 50);
    assert_eq!(kept.encoded_len(), 50);
    assert_eq!(bytes[..32], SEED);
    assert_eq!(bytes[32..40], 1_000_000u64.to_le_bytes());
    assert_eq!(bytes[40..44], 12u32.to_le_bytes());
    assert_eq!(bytes[44..46], [0x01, 0x0A]);
    assert_eq!(bytes[46..], [0, 0, 0, 0]);
    assert_eq!(BundleKept::decode(&bytes), Ok(kept.clone()));

    // The same two bitmap bytes under every count they could be read as
    // are different kept parts: the bytes of the bitmap do not say which.
    for count in 12u32..=16 {
        let other = kept_at(H, count, &[0x01, 0x0A]);
        let decoded = BundleKept::decode(&other.encode()).expect("its own count");
        assert_eq!(decoded.passes.count(), count);
        assert_eq!(decoded == kept, count == 12);
    }

    // The stated count fixes the length: one byte more or fewer refuses.
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        BundleKept::decode(&long),
        Err(BundleWireError::KeptLength {
            expected: 50,
            found: 51
        })
    );
    assert_eq!(
        BundleKept::decode(&bytes[..45]),
        Err(BundleWireError::KeptLength {
            expected: 46,
            found: 45
        })
    );
    // Too few bytes to state a count at all.
    for len in [0usize, 43] {
        assert_eq!(
            BundleKept::decode(&bytes[..len]),
            Err(BundleWireError::KeptLength {
                expected: 44,
                found: len
            })
        );
    }
    // A stated count of eleven with bit 11 set: padding, checked with no
    // chain.
    let mut eleven = bytes.clone();
    eleven[40..44].copy_from_slice(&11u32.to_le_bytes());
    assert_eq!(
        BundleKept::decode(&eleven),
        Err(BundleWireError::BitmapPadding { count: 11 })
    );
    // A stated count the bytes cannot hold.
    let mut huge = bytes;
    huge[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        BundleKept::decode(&huge),
        Err(BundleWireError::KeptLength {
            expected: 44 + 536_870_912,
            found: 50
        })
    );
    // A block of no draws: the fixed prefix and a zero support count.
    let empty = kept_at(H, 0, &[]);
    assert_eq!(empty.encode().len(), 48);
    assert_eq!(BundleKept::decode(&empty.encode()), Ok(empty));
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

/// A reference is its kept part and the prunable hash: it round-trips,
/// is exactly `80 + ⌈count / 8⌉` bytes when the support bitmap is empty, and its
/// encoding is pinned. The hex is the independent cSHAKE named in the
/// module docs. Red edits: put
/// `count` before `h`; drop it; read the hash from the front.
#[test]
fn kat_a_reference_is_its_kept_part_then_the_hash() {
    let kept = kept_at(H, 12, &[0x01, 0x0A]);
    let three = body(3);
    let reference = BundleRef::of(&kept, &three);
    let bytes = reference.encode();
    assert_eq!(
        hex(&bytes),
        "1111111111111111111111111111111111111111111111111111111111111111\
         40420f0000000000\
         0c000000\
         010a\
         00000000\
         55200abf66225b662f00844f3fc20d27f0dac951644a7f3e9c105893ee98795c"
    );
    assert_eq!(bytes.len(), 82, "80 and a two-byte bitmap (§7.5, SCS-F17)");
    assert_eq!(bytes[..50], kept.encode(), "the kept bytes, verbatim");
    assert_eq!(bytes[50..], three.prunable_hash());
    assert_eq!(BundleRef::decode(&bytes), Ok(reference.clone()));
    assert_eq!(reference.kept(), &kept);
    assert_eq!(reference.h(), H);
    assert_eq!(reference.seed(), &SEED);
    assert_eq!(reference.count(), 12);
    assert_eq!(reference.passes().as_bytes(), [0x01, 0x0A]);
    assert_eq!(
        reference.body_len(),
        three.as_bytes().len() as u64,
        "the reference fixes its body's length"
    );

    // A reference to a bundle of no draws is 80 bytes: the 44-byte
    // kept prefix, the support count, and the hash. That one is pinned too.
    let empty = BundleRef::new(
        BundleKept {
            h: BlockHeight::from_raw(1_000_007),
            seed: [0x12; 32],
            passes: PassBitmap::new(0, &[]).expect("no bits"),
            support: PassBitmap::none(),
        },
        body(0).prunable_hash(),
    );
    assert_eq!(
        hex(&empty.encode()),
        "1212121212121212121212121212121212121212121212121212121212121212\
         47420f0000000000\
         00000000\
         00000000\
         dbe9e9c1bc25076eb62dea786a02651090551b7a918f7338a9e25ddc5fc91e0a"
    );
    assert_eq!(empty.encode().len(), 80);
    assert_eq!(BundleRef::decode(&empty.encode()), Ok(empty.clone()));
    assert_eq!(empty.body_len(), 3_193);

    // The length is the witness plus one record per set bit of either
    // bitmap. The expected length is a body's own encoding, so it does
    // not restate [`BundleRef::body_len`]'s popcount sum.
    let support_only = BundleRef::new(
        BundleKept {
            h: H,
            seed: SEED,
            passes: PassBitmap::none(),
            support: PassBitmap::from_passes(1, [0]).expect("support draw 0"),
        },
        body(1).prunable_hash(),
    );
    assert_eq!(
        support_only.body_len(),
        u64::try_from(body(1).as_bytes().len()).expect("a body fits")
    );
    let economy_and_support = BundleRef::new(
        BundleKept {
            h: H,
            seed: SEED,
            passes: PassBitmap::from_passes(3, [0, 1, 2]).expect("three economy draws"),
            support: PassBitmap::from_passes(1, [0]).expect("support draw 0"),
        },
        body(4).prunable_hash(),
    );
    assert_eq!(
        economy_and_support.body_len(),
        u64::try_from(body(4).as_bytes().len()).expect("a body fits")
    );
}

/// A reference is self-delimiting (`SCS-P39`): its stated count fixes its
/// length, so every other length refuses, and so does a set padding bit —
/// both with no chain. This is what lets the header root drop its
/// per-reference frame. Red edit: accept `>=` the implied length; the
/// long case then parses and a byte can move between a bitmap and the
/// hash beside it.
#[test]
fn a_reference_of_any_length_but_its_own_refuses() {
    let reference = BundleRef::of(&kept_at(H, 12, &[0x01, 0x0A]), &body(3));
    let bytes = reference.encode();
    for len in [0usize, 31, 75, 77] {
        assert_eq!(
            BundleRef::decode(&bytes[..len]),
            Err(BundleWireError::ReferenceLength { found: len }),
            "{len} bytes"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        BundleRef::decode(&long),
        Err(BundleWireError::ReferenceLength { found: 83 })
    );
    // The same 78 bytes with the count restated: nine to sixteen bits are
    // two bytes, so the length holds and only the padding rule speaks.
    let restated = |count: u32| {
        let mut other = bytes.clone();
        other[40..44].copy_from_slice(&count.to_le_bytes());
        BundleRef::decode(&other)
    };
    assert_eq!(
        restated(11),
        Err(BundleWireError::BitmapPadding { count: 11 })
    );
    assert_eq!(restated(13).map(|r| r.count()), Ok(13));
    for count in [0u32, 8, 17, 104] {
        assert_eq!(
            restated(count),
            Err(BundleWireError::ReferenceLength { found: 82 }),
            "a stated count of {count}"
        );
    }
}

// ------------------------------------------------------------ commitment

/// The bundle commitment's vectors (§7.3, `SCS-P35`): no draws; eight
/// draws and no pass; one record; three records with a bitmap that crosses
/// a byte boundary; that case at `h + 1`; that case with one more economy
/// bit set and the same records; and the twelve-draw case with one support
/// bit. Every support bitmap is empty except that last one. The preimage
/// is the kept part followed by the records, support count included. The
/// hex is the independent cSHAKE named in the module docs. Red edits: hash
/// anything but `BundleKept::encode` in front of the records; write `h` or
/// a count big-endian; rename the label; put the records first; leave the
/// support count out.
#[test]
fn the_bundle_commitment_matches_its_vectors() {
    let three = records_bytes(3);
    let commit = |h: BlockHeight, count: u32, bitmap: &[u8], records: &[u8]| {
        hex(&bundle_commitment(&kept_at(h, count, bitmap), records))
    };
    assert_eq!(
        commit(H, 0, &[], &[]),
        "3d2a83a7b959e521e409e25e8aa03b528c475380ee8e0b4b8006c62ea74a9023"
    );
    assert_eq!(
        commit(H, 8, &[0x00], &[]),
        "2ce39ad03bb353db1f7115da22c4ce5564b021f48d2ba4322140851b0d31dc65"
    );
    assert_eq!(
        commit(H, 1, &[0x01], &record(0).encode()),
        "bcd6ae8354943380172c9ecc4e80decd4c2eb8a2006e0c1f3e17f8f103dd000c"
    );
    assert_eq!(
        commit(H, 12, &[0x01, 0x0A], &three),
        "7474d1f829369e895a6019f63a3c033ec5b438786cd17c69e91a52cda9d584d7"
    );
    assert_eq!(
        commit(BlockHeight::from_raw(1_000_001), 12, &[0x01, 0x0A], &three),
        "65ff3cc44efa77bc055ca3ff645d6d2881f880e6bd2ca60942e6e3af0609ec09"
    );
    assert_eq!(
        commit(H, 12, &[0x09, 0x0A], &three),
        "e6c849bf022b175965c02c9f402df9ba2d277d7a0cba457d5efe4b980e4230e0"
    );
    assert_eq!(
        hex(&bundle_commitment(&twelve_with_one_support(), &three)),
        "f626f6c4af284f660f45679bd3c8126f9d3ddc914e80f3649ca9ad020f31a16d"
    );
}

/// The commitment is the hash of the kept part's one encoding followed by
/// the records — the same bytes a reference opens with. Red edit: give
/// `bundle_commitment` its own serialisation of the kept fields; the two
/// then agree only until one of them changes.
#[test]
fn the_commitment_is_over_the_kept_parts_encoding_then_the_records() {
    let kept = kept_at(H, 12, &[0x01, 0x0A]);
    let three = body(3);
    let mut preimage = kept.encode();
    preimage.extend_from_slice(three.records_bytes());
    let expected = crate::hash::cshake256_32(BUNDLE_COMMITMENT_CUSTOMIZATION, &preimage);
    assert_eq!(bundle_commitment(&kept, three.records_bytes()), expected);
    assert_eq!(kept.commitment(three.records_bytes()), expected);
    assert_eq!(
        hex(&expected),
        "7474d1f829369e895a6019f63a3c033ec5b438786cd17c69e91a52cda9d584d7"
    );
    assert_eq!(
        BundleRef::of(&kept, &three).encode()[..50],
        preimage[..50],
        "a reference opens with the bytes the commitment opens with"
    );
}

/// The commitment covers every byte of the seed, `h`, both counts, both
/// bitmaps and each record. Red edit: stop hashing any one of them.
#[test]
fn the_commitment_moves_with_every_field() {
    let three = records_bytes(3);
    let kept = kept_at(H, 12, &[0x01, 0x0A]);
    let base = bundle_commitment(&kept, &three);
    let mut other_seed = kept.clone();
    other_seed.seed[31] ^= 1;
    assert_ne!(base, bundle_commitment(&other_seed, &three));
    // Thirteen bits in the same two bytes: only the count differs.
    assert_ne!(
        base,
        bundle_commitment(&kept_at(H, 13, &[0x01, 0x0A]), &three)
    );
    for at in [0, 1, 9, 41, 1_396, 1_397, 2 * 1_397 + 700, three.len() - 1] {
        let mut flipped = three.clone();
        flipped[at] ^= 0x01;
        assert_ne!(base, bundle_commitment(&kept, &flipped), "record byte {at}");
    }
    // The records in another order are another bundle.
    let mut swapped = record(1).encode().to_vec();
    swapped.extend_from_slice(&record(0).encode());
    swapped.extend_from_slice(&record(2).encode());
    assert_ne!(base, bundle_commitment(&kept, &swapped));
    assert_ne!(
        base,
        bundle_commitment(&twelve_with_one_support(), &three),
        "a support bit is in the preimage"
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
    let first = BundleRef::new(kept_at(H, 12, &[0x01, 0x0A]), body(3).prunable_hash());
    let second = BundleRef::new(
        BundleKept {
            h: BlockHeight::from_raw(1_000_007),
            seed: [0x12; 32],
            passes: PassBitmap::new(0, &[]).expect("no bits"),
            support: PassBitmap::none(),
        },
        body(0).prunable_hash(),
    );
    (first, second)
}

/// The header root's vectors: over no reference, one, and two — `n_le[4]`
/// and then each reference's own bytes, with no frame between them
/// (`SCS-P39`). The one-reference and two-reference hashes, and the
/// twelve-draw reference with one support bit, were produced by the
/// independent cSHAKE named in the module docs, over the encoding that
/// carries the support count. The empty
/// root has no reference and is unchanged. Records-was: the length-framed
/// preimage hashed to `28f79ede…c4b64586` and `d51fdf58…24a4c85e`. Red
/// edits: drop `n_le[4]`; frame a reference by its length; leave `count`
/// or the support count out of a reference; hash `h` before the seed;
/// rename the label.
#[test]
fn the_root_matches_its_vectors() {
    let (first, second) = vector_refs();
    assert_eq!(
        hex(&root(&[])),
        "1d271689c2934e75f2b8a25f57a686a75744d5f254ce014341eeba7b56845226"
    );
    assert_eq!(
        hex(&root(std::slice::from_ref(&first))),
        "8da7e9d5e7cb6cc1d947a385ff09316a0b66a42231775c51d452b0fcd669977e"
    );
    assert_eq!(
        hex(&root(&[first.clone(), second.clone()])),
        "0c7f9da64f6d3cf7edee74761c6e92cd9099bcdd51e8d9333eb691d1de1af8e5"
    );
    let supported = BundleRef::new(twelve_with_one_support(), body(3).prunable_hash());
    assert_eq!(
        hex(&root(std::slice::from_ref(&supported))),
        "88824ae7bd5dec403bcfc29f02abf4ecc83358e5b2d20f69051d3aa54736a532"
    );
    // Order is hashed: the section check refuses the swap, and the root
    // would not agree with it either.
    assert_ne!(
        root(&[first.clone(), second.clone()]),
        root(&[second, first])
    );
}

/// Two different sections cannot share a root preimage. Two controls over
/// this encoding's references: the two references' bytes under `n = 1`,
/// and one reference with no `n`. The figures those controls replaced
/// (`c4e00666…`, `c6bdd61d…`) were the pre-support preimage. And the
/// structural reason, checked rather than argued: the
/// concatenation of two references parses back into exactly those two,
/// because each reference's own count says where it ends — no byte can
/// move between one reference's bitmap, its hash and the next reference.
/// Red edit: drop `count` from the reference's encoding; `split_first`
/// below can no longer find the boundary.
#[test]
fn two_sections_cannot_share_a_root_preimage() {
    let (first, second) = vector_refs();
    let two = root(&[first.clone(), second.clone()]);
    assert_ne!(
        hex(&two),
        "1db7631e56a63be2081de642b80c1401e19f90f51fcc4f3ab4206e614c4316f4",
        "n counts references, not bytes"
    );
    assert_ne!(
        hex(&root(std::slice::from_ref(&first))),
        "ccceabe7d4795393ca05afc36ca0c35b0dbfac365eff1f47c4c6fcec4edbc04c",
        "n is hashed"
    );

    /// The first reference of a concatenation and what follows it, read
    /// from the bytes alone.
    fn split_first(bytes: &[u8]) -> (BundleRef, &[u8]) {
        let count = u32::from_le_bytes(bytes[40..44].try_into().expect("4 bytes"));
        let economy = PassBitmap::byte_len(count);
        let support_at = BUNDLE_KEPT_FIXED_LEN + economy;
        let support_count = u32::from_le_bytes(
            bytes[support_at..support_at + 4]
                .try_into()
                .expect("4 bytes"),
        );
        let len = support_at + 4 + PassBitmap::byte_len(support_count) + 32;
        let (head, tail) = bytes.split_at(len);
        (BundleRef::decode(head).expect("a reference"), tail)
    }
    // Sections whose bitmaps differ in length, so a shifted boundary would
    // show: 12 bits then 0 bits, 0 then 12, and 97 then 104 (13 bytes each,
    // the pair a byte length cannot tell apart).
    let wide = |count: u32, h: u64| {
        BundleRef::new(
            kept_at(
                BlockHeight::from_raw(h),
                count,
                &vec![0u8; PassBitmap::byte_len(count)],
            ),
            [0xEE; 32],
        )
    };
    for section in [
        vec![first.clone(), second.clone()],
        vec![second.clone(), first.clone()],
        vec![wide(97, 5), wide(104, 6), wide(0, 7), wide(1, 8)],
    ] {
        let mut bytes: Vec<u8> = section.iter().flat_map(BundleRef::encode).collect();
        let mut parsed = Vec::new();
        while !bytes.is_empty() {
            let (reference, rest) = split_first(&bytes);
            parsed.push(reference);
            bytes = rest.to_vec();
        }
        assert_eq!(parsed, section);
    }
    // 97 and 104 draws are both 13 bytes of bitmap and are different
    // references, with different roots: the count is in the preimage.
    assert_eq!(wide(97, 5).encode().len(), wide(104, 5).encode().len());
    assert_ne!(root(&[wide(97, 5)]), root(&[wide(104, 5)]));
}

/// The root covers each reference's seed, `h`, both counts, both bitmaps
/// and the prunable hash. Red edit: leave any one out of `BundleRef::encode`.
#[test]
fn the_root_moves_with_every_field_of_a_reference() {
    let (first, second) = vector_refs();
    let base = root(&[first.clone(), second.clone()]);
    let with = |changed: BundleRef| root(&[changed, second.clone()]);
    let ph = *first.prunable_hash();
    let mut seed = first.kept().clone();
    seed.seed[0] ^= 1;
    assert_ne!(base, with(BundleRef::new(seed, ph)));
    assert_ne!(
        base,
        with(BundleRef::new(
            kept_at(BlockHeight::from_raw(999_999), 12, &[0x01, 0x0A]),
            ph
        ))
    );
    assert_ne!(
        base,
        with(BundleRef::new(kept_at(H, 13, &[0x01, 0x0A]), ph))
    );
    assert_ne!(
        base,
        with(BundleRef::new(kept_at(H, 12, &[0x01, 0x08]), ph))
    );
    let mut other = ph;
    other[31] ^= 1;
    assert_ne!(base, with(BundleRef::new(first.kept().clone(), other)));
    assert_ne!(
        base,
        with(BundleRef::new(twelve_with_one_support(), ph)),
        "a support bit is in the preimage"
    );
}

/// The root counts its references in four bytes, and a section the count
/// cannot hold has no root rather than a panic: the conversion is checked
/// where a section's length becomes `n`. Tested on the conversion, which is
/// the one place the bound lives, because a section of 2³² references is
/// not something a test allocates. Red edit: `len as u32` (the count
/// wraps to 0 and the section hashes as empty), or `unwrap_or(u32::MAX)`.
#[test]
fn a_section_the_root_cannot_count_has_no_root() {
    assert_eq!(section_reference_count(0), Ok(0));
    assert_eq!(section_reference_count(1), Ok(1));
    let (first, second) = vector_refs();
    assert_eq!(
        bundle_root(&[first, second]).map(|root| hex(&root)),
        Ok("0c7f9da64f6d3cf7edee74761c6e92cd9099bcdd51e8d9333eb691d1de1af8e5".to_string())
    );
    // The boundary itself needs a `usize` wider than 32 bits to state.
    #[cfg(target_pointer_width = "64")]
    {
        let last = usize::try_from(u32::MAX).expect("fits");
        assert_eq!(section_reference_count(last), Ok(u32::MAX));
        let first_past = last + 1;
        assert_eq!(
            section_reference_count(first_past),
            Err(TooManyReferences { found: first_past })
        );
        assert_eq!(
            section_reference_count(usize::MAX),
            Err(TooManyReferences { found: usize::MAX })
        );
        assert_eq!(
            TooManyReferences { found: first_past }.to_string(),
            "a section of 4294967296 references has no root: the root counts them in 32 bits"
        );
    }
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
    assert_eq!(section_budget(c, 0, seb), SectionBudget::from_draws(2));
    assert_eq!(section_budget(c, 8, seb), SectionBudget::from_draws(2));
    assert_eq!(section_budget(c, 1_111, seb), SectionBudget::from_draws(2));
    // 9 · 1,112 = 10,008: the floor reaches one.
    assert_eq!(section_budget(c, 1_112, seb), SectionBudget::from_draws(4));
    // §7.4's table: the count cap is 292 at D = 324,000 and 2,791 at
    // D = 3,100,000.
    assert_eq!(
        section_budget(1, 324_000, seb),
        SectionBudget::from_draws(292)
    );
    assert_eq!(
        section_budget(c, 324_000, seb),
        SectionBudget::from_draws(584)
    );
    assert_eq!(
        section_budget(1, 3_100_000, seb),
        SectionBudget::from_draws(2_791)
    );
    assert_eq!(
        section_budget(0, 324_000, seb),
        SectionBudget::from_draws(0)
    );
}

/// `D` for the budget is the largest `D` among the epochs of the bundles in
/// the section (§7.4), asked once per distinct epoch; a section the
/// specification allows spans two. Red edits: take the first reference's
/// `D` (the ascending section reads 300); take the last (the descending
/// section reads 300); take the including block's — a caller's `D` the
/// helper never sees.
#[test]
fn the_sections_d_is_the_largest_among_its_epochs() {
    let schedule = SettlementSchedule::new(SettlementEpochBlocks::new(10_000).expect("non-zero"));
    let at = |h: u64| BundleRef::new(kept_at(BlockHeight::from_raw(h), 0, &[]), [0xAB; 32]);
    let d = |epoch: SettlementEpoch| -> Result<Option<u64>, ()> {
        Ok(match epoch.to_raw() {
            0 => Some(300),
            1 => Some(1_000),
            _ => None,
        })
    };
    // Epoch 0 then epoch 1: the larger `D` is the later epoch's.
    assert_eq!(
        section_d_max(&[at(9_998), at(9_999), at(10_000)], schedule, d),
        Ok(Some(1_000))
    );
    // One reference per epoch, and the larger `D` first (a section in
    // descending `h` is refused by the verifier, so this holds the helper
    // alone to "largest", not "last").
    let mut descending_d = |epoch: SettlementEpoch| -> Result<Option<u64>, ()> {
        Ok(match epoch.to_raw() {
            0 => Some(1_000),
            1 => Some(300),
            _ => None,
        })
    };
    assert_eq!(
        section_d_max(&[at(9_999), at(10_000)], schedule, &mut descending_d),
        Ok(Some(1_000))
    );
    // A single-epoch section is that epoch's `D`, asked once.
    let mut asked = Vec::new();
    assert_eq!(
        section_d_max(&[at(100), at(5_000), at(9_999)], schedule, |epoch| {
            asked.push(epoch);
            d(epoch)
        }),
        Ok(Some(300))
    );
    assert_eq!(asked, [SettlementEpoch::from_raw(0)]);
    // Two epochs: each asked once, in the section's order.
    let mut asked = Vec::new();
    assert_eq!(
        section_d_max(&[at(9_999), at(10_000), at(10_001)], schedule, |epoch| {
            asked.push(epoch);
            d(epoch)
        }),
        Ok(Some(1_000))
    );
    assert_eq!(
        asked,
        [SettlementEpoch::from_raw(0), SettlementEpoch::from_raw(1)]
    );
}

/// An unknown `D` is `None` for the section, never a partial maximum, and
/// an empty section has no `D`. A fault is itself. Red edits: skip an
/// epoch whose `D` is unknown and return the maximum of the rest; return
/// `Some(0)` for an empty section; map a fault to `None`.
#[test]
fn an_unknown_d_is_no_d_for_the_section_and_a_fault_is_itself() {
    let schedule = SettlementSchedule::new(SettlementEpochBlocks::new(10_000).expect("non-zero"));
    let at = |h: u64| BundleRef::new(kept_at(BlockHeight::from_raw(h), 0, &[]), [0xAB; 32]);
    let known_only_0 = |epoch: SettlementEpoch| -> Result<Option<u64>, &'static str> {
        Ok((epoch.to_raw() == 0).then_some(300))
    };
    let known_only_1 = |epoch: SettlementEpoch| -> Result<Option<u64>, &'static str> {
        Ok((epoch.to_raw() == 1).then_some(1_000))
    };
    // The unknown epoch is the later one, and the earlier one.
    assert_eq!(
        section_d_max(&[at(9_999), at(10_000)], schedule, known_only_0),
        Ok(None)
    );
    assert_eq!(
        section_d_max(&[at(9_999), at(10_000)], schedule, known_only_1),
        Ok(None)
    );
    // Known where the section has only the known epoch.
    assert_eq!(
        section_d_max(&[at(9_999)], schedule, known_only_0),
        Ok(Some(300))
    );
    // Empty: no epoch, no `D`, nothing asked.
    let mut asked = false;
    assert_eq!(
        section_d_max(&[], schedule, |_| {
            asked = true;
            Ok::<_, &str>(Some(7))
        }),
        Ok(None)
    );
    assert!(!asked);
    // A fault on the second epoch is returned as the fault, not as `None`
    // and not as the first epoch's `D`.
    assert_eq!(
        section_d_max(&[at(9_999), at(10_000)], schedule, |epoch| {
            if epoch.to_raw() == 0 {
                Ok(Some(300))
            } else {
                Err("unreadable")
            }
        }),
        Err("unreadable")
    );
}

/// The budget does not overflow: it saturates. Red edit: compute in `u64`
/// and the first line panics under `overflow-checks`.
#[test]
fn the_section_budget_saturates() {
    let one = SettlementEpochBlocks::new(1).expect("non-zero");
    assert_eq!(
        section_budget(2, u64::MAX, one),
        SectionBudget::from_draws(u64::MAX)
    );
    assert_eq!(
        section_budget(u64::MAX, u64::MAX, one),
        SectionBudget::from_draws(u64::MAX)
    );
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    assert_eq!(
        section_budget(1, u64::MAX, seb),
        SectionBudget::from_draws(
            u64::try_from(u128::from(u64::MAX) * 9 / 10_000 + 1).expect("fits")
        )
    );
}

/// A bundle is charged `max(count, 1)` (`SCS-P40`): its draws, and one if
/// it has none. Red edit: return `count`; a zero-draw bundle is then free.
#[test]
fn a_bundle_is_charged_its_draws_and_never_nothing() {
    assert_eq!(bundle_charge(0), 1);
    assert_eq!(bundle_charge(1), 1);
    assert_eq!(bundle_charge(2), 2);
    assert_eq!(bundle_charge(292), 292);
    assert_eq!(bundle_charge(u32::MAX), u64::from(u32::MAX));
    let empty = kept_at(H, 0, &[]);
    assert_eq!(empty.charge(), 1);
    assert_eq!(BundleRef::new(empty, [0; 32]).charge(), 1);
    assert_eq!(kept_at(H, 12, &[0x01, 0x0A]).charge(), 12);
}
