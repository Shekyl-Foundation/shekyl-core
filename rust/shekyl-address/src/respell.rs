// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Test-only: the other spellings of a canonical Bech32m string, each of
//! which the `bech32` crate would read as the same HRP and bytes and the
//! one codec (`shekyl-encoding`) refuses.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Bech32m, ByteIterExt, Fe32, Fe32IterExt};

/// Bits per Bech32 character.
const FE_BITS: usize = 5;

/// A non-canonical spelling of one string.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Spelling {
    /// Every letter upper-cased: valid Bech32m as specified.
    Uppercase,
    /// One letter upper-cased.
    MixedCase,
    /// The same HRP and bytes under the older Bech32 checksum.
    Bech32Checksum,
    /// The last character's padding bits set.
    NonZeroPadding,
    /// One more zero character, where the padding stays under a byte.
    ExtraCharacter,
}

impl Spelling {
    pub(crate) const ALL: [Self; 5] = [
        Self::Uppercase,
        Self::MixedCase,
        Self::Bech32Checksum,
        Self::NonZeroPadding,
        Self::ExtraCharacter,
    ];

    /// `canonical` spelled this way, or `None` where its length admits no
    /// such spelling: no padding bit to set, or too many to add a
    /// character without adding a byte.
    ///
    /// # Panics
    ///
    /// If `canonical` is not Bech32m.
    pub(crate) fn of(self, canonical: &str) -> Option<String> {
        let checked = CheckedHrpstring::new::<Bech32m>(canonical).expect("a Bech32m string");
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        let fes: Vec<Fe32> = data.iter().copied().bytes_to_fes().collect();
        let padding = fes.len() * FE_BITS - data.len() * 8;
        let with_checksum = |fes: Vec<Fe32>| -> String {
            fes.into_iter()
                .with_checksum::<Bech32m>(&hrp)
                .chars()
                .collect()
        };
        match self {
            Self::Uppercase => Some(canonical.to_uppercase()),
            Self::MixedCase => {
                let at = canonical
                    .rfind(|c: char| c.is_ascii_lowercase())
                    .expect("a Bech32m string holds a letter");
                let mut mixed = canonical.to_owned();
                mixed[at..=at].make_ascii_uppercase();
                Some(mixed)
            }
            Self::Bech32Checksum => {
                Some(bech32::encode::<Bech32>(hrp, &data).expect("the HRP encodes"))
            }
            Self::NonZeroPadding => (padding > 0).then(|| {
                let mut fes = fes;
                let last = fes.pop().expect("a padded payload is not empty");
                fes.push(Fe32::try_from(last.to_u8() | 1).expect("a 5-bit value"));
                with_checksum(fes)
            }),
            Self::ExtraCharacter => (padding + FE_BITS < 8).then(|| {
                let mut fes = fes;
                fes.push(Fe32::Q);
                with_checksum(fes)
            }),
        }
    }

    /// Whether `err` is the refusal this spelling meets.
    pub(crate) fn refused_by(self, err: &shekyl_encoding::EncodingError) -> bool {
        use bech32::primitives::decode::CheckedHrpstringError;
        use shekyl_encoding::EncodingError;
        match self {
            Self::Uppercase | Self::MixedCase => matches!(err, EncodingError::NotLowercase),
            Self::Bech32Checksum => matches!(
                err,
                EncodingError::Decode(CheckedHrpstringError::Checksum(_))
            ),
            Self::NonZeroPadding | Self::ExtraCharacter => {
                matches!(err, EncodingError::NotCanonical)
            }
        }
    }
}
