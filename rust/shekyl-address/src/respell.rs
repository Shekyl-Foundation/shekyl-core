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
        use shekyl_encoding::EncodingError;
        match self {
            Self::Uppercase | Self::MixedCase => matches!(err, EncodingError::NotLowercase),
            Self::Bech32Checksum => matches!(err, EncodingError::Checksum),
            Self::NonZeroPadding | Self::ExtraCharacter => {
                matches!(err, EncodingError::NotCanonical)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Spelling;
    use crate::address::{
        AddressError, PaymentAddress, ShekylAddress, FULL_SEGMENT_COUNT, SEGMENT_SEPARATOR,
    };
    use crate::{Network, MSG_SIGN_PK_LEN, PQC_PAYLOAD_LEN};
    use shekyl_encoding::EncodingError;

    fn fixture(net: Network) -> ShekylAddress {
        ShekylAddress::new(
            net,
            [0xaa; 32],
            [0xbb; 32],
            [0xee; MSG_SIGN_PK_LEN],
            vec![0xcc; PQC_PAYLOAD_LEN],
        )
    }

    /// `encoded` with its segment `at` spelled `spelling`, where that
    /// segment's length admits the spelling.
    fn respell_segment(encoded: &str, at: usize, spelling: Spelling) -> Option<String> {
        let mut segments: Vec<String> = encoded
            .split(SEGMENT_SEPARATOR)
            .map(str::to_owned)
            .collect();
        segments[at] = spelling.of(&segments[at])?;
        let mut joined = String::new();
        for (i, segment) in segments.iter().enumerate() {
            if i > 0 {
                joined.push(SEGMENT_SEPARATOR);
            }
            joined.push_str(segment);
        }
        Some(joined)
    }

    fn assert_refused(encoded: &str, spelling: Spelling, what: &str) {
        match ShekylAddress::decode(encoded) {
            Err(AddressError::Bech32m(err)) => {
                assert!(
                    spelling.refused_by(&err),
                    "{what} {spelling:?}: refused as {err:?}"
                );
            }
            other => panic!("{what} {spelling:?}: {other:?}"),
        }
    }

    /// Every network's address round-trips through its one string.
    #[test]
    fn every_network_round_trips_its_one_string() {
        for net in Network::ALL {
            let addr = fixture(net);
            let full = addr.encode().unwrap();
            assert_eq!(ShekylAddress::decode(&full).unwrap(), addr, "{net}");
            assert_eq!(
                ShekylAddress::decode(&full).unwrap().encode().unwrap(),
                full
            );
            let display = addr.encode_classical_display().unwrap();
            assert_eq!(
                ShekylAddress::decode(&display)
                    .unwrap()
                    .encode_classical_display()
                    .unwrap(),
                display,
                "{net}"
            );
        }
    }

    /// An address has one string. Each other spelling the `bech32` crate
    /// reads as the same address, on any full-address segment, is refused
    /// by the refusal that names it. No full-address segment admits an
    /// extra character, and that absence is pinned, so a layout change
    /// brings the spelling back here.
    #[test]
    fn a_full_address_has_one_string() {
        for net in Network::ALL {
            let full = fixture(net).encode().unwrap();
            let segments: Vec<&str> = full.split(SEGMENT_SEPARATOR).collect();
            assert_eq!(segments.len(), FULL_SEGMENT_COUNT, "{net}");
            for at in 0..segments.len() {
                for spelling in Spelling::ALL {
                    match respell_segment(&full, at, spelling) {
                        Some(respelled) => {
                            assert_refused(&respelled, spelling, &format!("{net} segment {at}"));
                        }
                        None => assert!(
                            matches!(spelling, Spelling::ExtraCharacter),
                            "{net} segment {at} admits {spelling:?}"
                        ),
                    }
                }
            }
        }
    }

    /// The display form has one string too. `CLASSICAL_SEGMENT_LEN`
    /// leaves one padding bit, so every spelling applies, the extra
    /// character included. A layout that drops that bit fails the
    /// unwrap below.
    #[test]
    fn a_classical_only_address_has_one_string() {
        for net in Network::ALL {
            let display = fixture(net).encode_classical_display().unwrap();
            for spelling in Spelling::ALL {
                let respelled = spelling
                    .of(&display)
                    .unwrap_or_else(|| panic!("{net} display admits {spelling:?}"));
                assert_refused(&respelled, spelling, &format!("{net} display"));
            }
        }
    }

    /// Paying decodes through the same codec: an upper-cased address is
    /// refused at the payer's door, not only at [`ShekylAddress::decode`].
    #[test]
    fn a_payment_address_has_one_string() {
        let full = fixture(Network::Mainnet).encode().unwrap();
        assert!(matches!(
            PaymentAddress::decode(&full.to_uppercase(), Network::Mainnet),
            Err(AddressError::Bech32m(EncodingError::NotLowercase))
        ));
        assert!(PaymentAddress::decode(&full, Network::Mainnet).is_ok());
    }
}
