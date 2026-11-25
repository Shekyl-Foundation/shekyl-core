// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed view of the envelope's `capability_mode` byte.
//!
//! The envelope layer ([`shekyl_crypto_pq::wallet_envelope`]) speaks in raw
//! `u8` discriminants so the AAD layout is byte-stable across language
//! boundaries. Callers at the orchestrator level should never pattern-match
//! on those raw bytes — they are a transport concern. [`Capability`] is the
//! typed surface we expose on [`crate::WalletFile`] and through the
//! eventual FFI opaque-handle getter.
//!
//! # One variant is the correct end state, not a smell
//!
//! `Full` is the only capability a [`crate::WalletFile`] holds (rule 23:
//! ViewOnly is REJECTED and hardware-offload is DEFERRED with zero code —
//! decision log 2026-09-07). A group wallet (`0x04`, R-30) is not a
//! capability of this handle: it is its own type,
//! [`crate::GroupWalletFile`], and this decode refuses its byte by name.
//! The enum stays an enum because [`Capability::from_envelope_byte`]
//! returning a `Result` is the parse boundary that makes "capability was
//! validated" a type-level fact rather than a runtime predicate. Do not
//! collapse it to a unit struct or a bool.
//!
//! # Defensive decoding
//!
//! The envelope's `validate_cap_content` already rejects every byte other
//! than [`CAPABILITY_FULL`] and [`CAPABILITY_GROUP_MEMBER`] with
//! `UnknownCapabilityMode`. [`Capability::from_envelope_byte`] still covers
//! the other bytes defensively: the envelope and the orchestrator live in
//! separate crates, and a future refactor that skips `validate_cap_content`
//! (e.g. a direct `OpenedKeysFile` constructed by a test helper) should not
//! silently produce a malformed [`Capability`]. The retired v1 bytes
//! (`0x02`, `0x03`) are in `docs/WALLET_FILE_FORMAT_V1.md`'s discriminant
//! table — in the spec, deliberately not as code constants.

use shekyl_crypto_pq::wallet_envelope::{CAPABILITY_FULL, CAPABILITY_GROUP_MEMBER};

use crate::error::WalletFileError;

/// Typed projection of the envelope's `capability_mode` byte. The raw
/// `u8` discriminant is not stabilized as part of this crate's public
/// API — callers should use this type rather than comparing against
/// [`shekyl_crypto_pq::wallet_envelope::CAPABILITY_FULL`] directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Spendable wallet: the keys file carries the 64-byte master seed,
    /// from which all private key material is re-derived on open.
    Full,
}

impl Capability {
    /// Decode the envelope's `capability_mode` byte into a typed
    /// [`Capability`]. A group wallet's byte refuses as
    /// [`WalletFileError::GroupWalletKeysFile`]. Any other byte returns the
    /// generic unsupported-capability error — it deliberately names no
    /// specific future arm; the envelope layer's own validation already
    /// rejects those bytes at seal/open time, so a caller that reaches that
    /// path has encountered an internal invariant violation.
    pub(crate) fn from_envelope_byte(v: u8) -> Result<Self, WalletFileError> {
        match v {
            CAPABILITY_FULL => Ok(Self::Full),
            CAPABILITY_GROUP_MEMBER => Err(WalletFileError::GroupWalletKeysFile),
            other => Err(WalletFileError::UnknownCapability(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full() {
        assert_eq!(
            Capability::from_envelope_byte(CAPABILITY_FULL).unwrap(),
            Capability::Full,
        );
    }

    /// A solo handle refuses a group wallet's keys file by name.
    #[test]
    fn refuses_a_group_wallets_byte_by_name() {
        assert!(matches!(
            Capability::from_envelope_byte(CAPABILITY_GROUP_MEMBER),
            Err(WalletFileError::GroupWalletKeysFile)
        ));
    }

    /// Fail-closed: the retired v1 bytes (`0x02` ViewOnly, `0x03`
    /// hardware-offload) and a never-assigned byte all refuse with the
    /// generic unsupported-capability error.
    #[test]
    fn refuses_every_non_full_byte() {
        for byte in [0x02u8, 0x03, 0x00, 0xEF] {
            let err = Capability::from_envelope_byte(byte).unwrap_err();
            match err {
                WalletFileError::UnknownCapability(b) => assert_eq!(b, byte),
                other => panic!("expected UnknownCapability, got {other:?}"),
            }
        }
    }
}
