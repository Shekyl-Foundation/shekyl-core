// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockHeight, BlockWeight, MAX_ATTESTATION_WITNESS_BYTES};
use shekyl_units::AtomicUnits;

use super::alt::test_block_bytes;
use super::{AltBlock, AltBlockError, AltBlockFacts};

fn facts(weight: Option<u64>) -> AltBlockFacts {
    AltBlockFacts {
        height: BlockHeight::from_raw(41),
        block_weight: weight.map(BlockWeight::from_raw),
        cumulative_difficulty: CumulativeDifficulty::from_raw((5u128 << 64) | 4),
        coins_generated: AtomicUnits::from_raw(1_234_567),
    }
}

fn block() -> Vec<u8> {
    test_block_bytes(41)
}

fn witness() -> Vec<u8> {
    vec![0xA5; 40]
}

#[test]
fn round_trips_with_and_without_the_optional_parts() {
    let bare = AltBlock::checked(facts(None), block(), None).expect("bare");
    let full = AltBlock::checked(facts(Some(2_048)), block(), Some(witness())).expect("full");
    for record in [&bare, &full] {
        let bytes = record.encode();
        assert_eq!(AltBlock::decode(&bytes).as_ref(), Ok(record));
    }
    assert_eq!(bare.block_weight(), None);
    assert_eq!(bare.attestation_witness(), None);
    assert_eq!(full.block_weight(), Some(BlockWeight::from_raw(2_048)));
    assert_eq!(full.attestation_witness(), Some(witness().as_slice()));
    assert_eq!(full.block(), block().as_slice());
    assert_eq!(full.facts(), facts(Some(2_048)));
    assert_eq!(
        full.cumulative_difficulty().to_raw(),
        (5u128 << 64) | 4,
        "one u128, not two u64 halves"
    );
}

#[test]
fn checked_refuses_what_decode_refuses() {
    assert_eq!(
        AltBlock::checked(facts(None), vec![0xFF; 7], None).map(drop),
        Err(AltBlockError::BlockMalformed)
    );
    assert_eq!(
        AltBlock::checked(facts(None), Vec::new(), None).map(drop),
        Err(AltBlockError::BlockMalformed),
        "an empty block is not a block"
    );
    assert_eq!(
        AltBlock::checked(facts(None), block(), Some(Vec::new())).map(drop),
        Err(AltBlockError::WitnessMalformed),
        "empty stores no row: absence is None, not Some(empty)"
    );
    assert_eq!(
        AltBlock::checked(
            facts(None),
            block(),
            Some(vec![0; MAX_ATTESTATION_WITNESS_BYTES + 1])
        )
        .map(drop),
        Err(AltBlockError::WitnessMalformed)
    );
    assert_eq!(
        AltBlock::checked(facts(Some(0)), block(), None).map(drop),
        Err(AltBlockError::ZeroWeight),
        "the C++ sentinel is not re-minted"
    );
}

/// Encode a record that `checked` would have refused, by writing the bytes
/// by hand in the codec's layout.
fn forged(weight: Option<u64>, block: &[u8], witness: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&41u64.to_le_bytes());
    match weight {
        None => out.push(0),
        Some(w) => {
            out.push(1);
            out.extend_from_slice(&w.to_le_bytes());
        }
    }
    out.extend_from_slice(&((5u128 << 64) | 4).to_le_bytes());
    out.extend_from_slice(&1_234_567u64.to_le_bytes());
    out.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
    out.extend_from_slice(block);
    match witness {
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
    assert!(AltBlock::decode(&forged(Some(9), &block(), Some(&witness()))).is_ok());

    assert_eq!(
        reason(AltBlock::decode(&forged(Some(0), &block(), None))),
        "block weight is zero; undetermined is a missing option"
    );
    assert_eq!(
        reason(AltBlock::decode(&forged(None, &[0xFF; 7], None))),
        "alt block bytes do not parse as a block"
    );
    assert_eq!(
        reason(AltBlock::decode(&forged(None, &block(), Some(&[])))),
        "attestation witness is empty or over its bound; absence is a missing option"
    );

    let mut bad_presence = forged(None, &block(), None);
    bad_presence[8] = 2;
    assert_eq!(
        reason(AltBlock::decode(&bad_presence)),
        "block_weight presence byte is not 0 or 1"
    );

    let mut trailing = forged(None, &block(), None);
    trailing.push(0);
    assert_eq!(
        reason(AltBlock::decode(&trailing)),
        "trailing bytes after the alt block record"
    );

    let truncated = &forged(None, &block(), None)[..20];
    assert!(matches!(
        AltBlock::decode(truncated),
        Err(CodecError::Invalid {
            codec: "alt_block",
            ..
        })
    ));
}
