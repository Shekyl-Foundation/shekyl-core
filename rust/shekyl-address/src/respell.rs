// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Test-only: the other spellings of a canonical Bech32m string, each of
//! which the `bech32` crate would read as the same HRP and bytes and the
//! one codec (`shekyl-encoding`) refuses.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Bech32m, ByteIterExt, Fe32, Fe32IterExt};

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
}

impl Spelling {
    pub(crate) const ALL: [Self; 4] = [
        Self::Uppercase,
        Self::MixedCase,
        Self::Bech32Checksum,
        Self::NonZeroPadding,
    ];

    /// `canonical` spelled this way.
    ///
    /// # Panics
    ///
    /// If `canonical` is not Bech32m, or (for [`Self::NonZeroPadding`])
    /// its bytes fill their characters exactly, leaving no padding bit.
    pub(crate) fn of(self, canonical: &str) -> String {
        let checked = CheckedHrpstring::new::<Bech32m>(canonical).expect("a Bech32m string");
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        match self {
            Self::Uppercase => canonical.to_uppercase(),
            Self::MixedCase => {
                let at = canonical
                    .rfind(|c: char| c.is_ascii_lowercase())
                    .expect("a Bech32m string holds a letter");
                let mut mixed = canonical.to_owned();
                mixed[at..=at].make_ascii_uppercase();
                mixed
            }
            Self::Bech32Checksum => bech32::encode::<Bech32>(hrp, &data).expect("the HRP encodes"),
            Self::NonZeroPadding => {
                assert_ne!(
                    data.len() * 8 % 5,
                    0,
                    "{} bytes leave no padding bit",
                    data.len()
                );
                let mut fes: Vec<Fe32> = data.iter().copied().bytes_to_fes().collect();
                let last = fes.pop().expect("a non-empty payload");
                fes.push(Fe32::try_from(last.to_u8() | 1).expect("a 5-bit value"));
                fes.into_iter()
                    .with_checksum::<Bech32m>(&hrp)
                    .chars()
                    .collect()
            }
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
            Self::NonZeroPadding => matches!(err, EncodingError::NotCanonical),
        }
    }
}
