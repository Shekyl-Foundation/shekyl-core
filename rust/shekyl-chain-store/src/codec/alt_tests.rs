// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::alt::test_block_bytes;
use super::{AltBlock, AltBlockError, AltBlockFacts, AltBodies};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::archival::BundleReferences;
use shekyl_types::{BlockHeight, BlockWeight};

fn facts(weight: u64) -> AltBlockFacts {
    AltBlockFacts {
        height: BlockHeight::from_raw(41),
        block_weight: BlockWeight::from_raw(weight),
        cumulative_difficulty: CumulativeDifficulty::from_raw((5u128 << 64) | 4),
        pow: crate::codec::RecordedPow {
            seed: shekyl_types::BlockHash::from_bytes([0x5E; 32]),
            pow: shekyl_types::PowHash::from_bytes([0x70; 32]),
        },
    }
}

fn block() -> Vec<u8> {
    test_block_bytes(41)
}

fn references() -> BundleReferences {
    BundleReferences::new(vec![vec![0xA5; 80], vec![0xA6; 81]]).expect("a section")
}

#[test]
fn round_trips_with_and_without_references() {
    let bare = AltBlock::checked(facts(2_048), &block(), None).expect("bare");
    let full = AltBlock::checked(facts(2_048), &block(), Some(references())).expect("full");
    for record in [&bare, &full] {
        let bytes = record.encode();
        assert_eq!(AltBlock::decode(&bytes).as_ref(), Ok(record));
    }
    assert_eq!(bare.block_weight(), BlockWeight::from_raw(2_048));
    assert_eq!(bare.bundle_references(), None);
    assert_eq!(full.block_weight(), BlockWeight::from_raw(2_048));
    assert_eq!(full.bundle_references(), Some(&references()));
    assert_eq!(
        full.block().serialize(),
        block(),
        "encode writes the canonical block, which is the bytes checked parsed"
    );
    assert_eq!(full.facts(), facts(2_048));
    assert_eq!(
        full.cumulative_difficulty().to_raw(),
        (5u128 << 64) | 4,
        "one u128, not two u64 halves"
    );
}

/// CEN-K8's falsifier (`DRS_E5_POOL_ALT_PRUNE.md` §2.1): the alt row has no
/// supply word. The layout is pinned field by field, so a word re-minted
/// anywhere in it — the C++ `already_generated_coins` or a successor —
/// lengthens the record and fails here, not only in the snapshot.
#[test]
fn an_alt_row_has_no_supply_word() {
    let record = AltBlock::checked(facts(2_048), &block(), Some(references())).expect("full");
    let bytes = record.encode();
    let mut expected = Vec::new();
    expected.extend_from_slice(&41u64.to_le_bytes()); // height
    expected.extend_from_slice(&2_048u64.to_le_bytes()); // weight, always
    expected.extend_from_slice(&((5u128 << 64) | 4).to_le_bytes()); // one u128
    expected.extend_from_slice(&[0x5E; 32]); // the recorded PoW's seed
    expected.extend_from_slice(&[0x70; 32]); // the recorded PoW
    expected.extend_from_slice(&u32::try_from(block().len()).unwrap().to_le_bytes());
    expected.extend_from_slice(&block());
    let section = references().encode();
    expected.push(1); // references present
    expected.extend_from_slice(&u32::try_from(section.len()).unwrap().to_le_bytes());
    expected.extend_from_slice(&section);
    assert_eq!(
        bytes, expected,
        "height, weight, difficulty, recorded PoW, block, references — nothing else"
    );
    // The facts half is the three scalars and the recorded PoW; a fifth
    // would not build here.
    let AltBlockFacts {
        height,
        block_weight,
        cumulative_difficulty,
        pow: _,
    } = record.facts();
    assert_eq!(height, BlockHeight::from_raw(41));
    assert_eq!(block_weight, BlockWeight::from_raw(2_048));
    assert_eq!(cumulative_difficulty.to_raw(), (5u128 << 64) | 4);
}

#[test]
fn checked_refuses_what_decode_refuses() {
    assert_eq!(
        AltBlock::checked(facts(2_048), &[0xFF; 7], None).map(drop),
        Err(AltBlockError::BlockMalformed)
    );
    assert_eq!(
        AltBlock::checked(facts(2_048), &[], None).map(drop),
        Err(AltBlockError::BlockMalformed),
        "an empty block is not a block"
    );
    assert_eq!(
        AltBlock::checked(facts(0), &block(), None).map(drop),
        Err(AltBlockError::ZeroWeight),
        "zero is not a weight"
    );
}

/// Encode a record that `checked` would have refused, by writing the bytes
/// by hand in the codec's layout.
fn forged(weight: u64, block: &[u8], references: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&41u64.to_le_bytes());
    out.extend_from_slice(&weight.to_le_bytes());
    out.extend_from_slice(&((5u128 << 64) | 4).to_le_bytes());
    out.extend_from_slice(&[0x5E; 32]); // recorded pow: seed
    out.extend_from_slice(&[0x70; 32]); // recorded pow: hash
    out.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
    out.extend_from_slice(block);
    match references {
        None => out.push(0),
        Some(w) => {
            out.push(1);
            out.extend_from_slice(&u32::try_from(w.len()).unwrap().to_le_bytes());
            out.extend_from_slice(w);
        }
    }
    out
}

fn reason(result: Result<AltBlock, CodecError>) -> &'static str {
    match result {
        Err(CodecError::Invalid { codec, reason }) => {
            assert_eq!(codec, "alt_block");
            reason
        }
        other => panic!("expected an Invalid refusal, got {other:?}"),
    }
}

#[test]
fn decode_refuses_the_forged_shapes() {
    // The forger agrees with the codec on a valid record.
    assert!(AltBlock::decode(&forged(9, &block(), Some(&references().encode()))).is_ok());

    assert_eq!(
        reason(AltBlock::decode(&forged(0, &block(), None))),
        "block weight is zero"
    );
    assert_eq!(
        reason(AltBlock::decode(&forged(9, &[0xFF; 7], None))),
        "alt block bytes do not parse as a block"
    );
    // Present and empty, and present but past the bound: neither is a
    // section; absence is the presence byte, not an empty one.
    assert_eq!(
        reason(AltBlock::decode(&forged(
            9,
            &block(),
            Some(&0u32.to_le_bytes())
        ))),
        "stored bundle references are not a section"
    );
    let over = u32::try_from(shekyl_types::archival::MAX_SECTION_REFERENCES + 1).unwrap();
    assert_eq!(
        reason(AltBlock::decode(&forged(
            9,
            &block(),
            Some(&over.to_le_bytes())
        ))),
        "stored bundle references are not a section"
    );

    // No references is one trailing presence byte. That is the byte a
    // forger can set off {0, 1}; the weight has no presence byte to forge.
    let mut bad_presence = forged(9, &block(), None);
    let presence = bad_presence.len() - 1;
    bad_presence[presence] = 2;
    assert_eq!(
        reason(AltBlock::decode(&bad_presence)),
        "bundle_references presence byte is not 0 or 1"
    );

    let mut trailing = forged(9, &block(), None);
    trailing.push(0);
    assert_eq!(
        reason(AltBlock::decode(&trailing)),
        "trailing bytes after the alt block record"
    );

    let truncated = &forged(9, &block(), None)[..20];
    assert!(matches!(
        AltBlock::decode(truncated),
        Err(CodecError::Invalid {
            codec: "alt_block",
            ..
        })
    ));
}

/// The listed bodies' codec round-trips none, one and two bodies, and
/// refuses bytes that do not parse as a transaction, a count the bytes
/// cannot back and trailing bytes.
#[test]
fn the_bodies_round_trip_and_refuse_malformed_rows() {
    let coinbase = super::BlockBody::parse(&block())
        .expect("the fixture parses")
        .miner_transaction
        .clone();
    for bodies in [
        AltBodies::of(Vec::new()),
        AltBodies::of(vec![coinbase.clone()]),
        AltBodies::of(vec![coinbase.clone(), coinbase.clone()]),
    ] {
        assert_eq!(AltBodies::decode(&bodies.encode()), Ok(bodies));
    }
    let reason = |bytes: &[u8]| match AltBodies::decode(bytes) {
        Err(CodecError::Invalid { reason, .. }) => reason,
        other => panic!("refused, not {other:?}"),
    };
    let good = AltBodies::of(vec![coinbase]).encode();
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        reason(&trailing),
        "trailing bytes after the alt block's bodies"
    );
    // One body of three bytes that are not a transaction.
    let mut junk = 1u32.to_le_bytes().to_vec();
    junk.extend_from_slice(&3u32.to_le_bytes());
    junk.extend_from_slice(&[0xFF; 3]);
    assert_eq!(
        reason(&junk),
        "a listed body does not parse as a transaction"
    );
    // A count the remaining bytes cannot hold.
    assert_eq!(
        reason(&9u32.to_le_bytes()),
        "element count exceeds what the row's bytes can hold"
    );
}
