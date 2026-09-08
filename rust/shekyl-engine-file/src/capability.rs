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
//! `Full` is the only capability (rule 23: ViewOnly is REJECTED and
//! hardware-offload is DEFERRED with zero code — decision log 2026-09-07).
//! The enum stays an enum because [`Capability::from_envelope_byte`]
//! returning a `Result` is the parse boundary that makes "capability was
//! validated" a type-level fact rather than a runtime predicate. Do not
//! collapse it to a unit struct or a bool; a future capability, if one is
//! ever ratified, joins as a variant through this same boundary.
//!
//! # Defensive decoding
//!
//! The envelope's `validate_cap_content` already rejects every byte other
//! than [`CAPABILITY_FULL`] with `UnknownCapabilityMode`, so an
//! `OpenedKeysFile` reaching this layer cannot legitimately carry another
//! value. [`Capability::from_envelope_byte`] still covers the non-Full
//! bytes defensively: the envelope and the orchestrator live in separate
//! crates, and a future refactor that skips `validate_cap_content` (e.g. a
//! direct `OpenedKeysFile` constructed by a test helper) should not
//! silently produce a malformed [`Capability`]. The unused v1 bytes
//! (`0x02`–`0x04`) are RESERVED in `docs/WALLET_FILE_FORMAT_V1.md`'s
//! discriminant table — in the spec, deliberately not as code constants.

use shekyl_crypto_pq::wallet_envelope::CAPABILITY_FULL;

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
    /// [`Capability`]. Any byte other than [`CAPABILITY_FULL`] returns
    /// the generic unsupported-capability error — it deliberately names
    /// no specific future arm. The envelope layer's own validation
    /// already rejects those bytes at seal/open time, so a caller that
    /// reaches the error path has encountered an internal invariant
    /// violation.
    pub(crate) fn from_envelope_byte(v: u8) -> Result<Self, WalletFileError> {
        match v {
            CAPABILITY_FULL => Ok(Self::Full),
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

    /// Fail-closed: the retired v1 bytes (`0x02` ViewOnly, `0x03`
    /// hardware-offload, `0x04` reserved-multisig — RESERVED in the
    /// format spec, unlabeled) and a never-assigned byte all refuse
    /// with the generic unsupported-capability error.
    #[test]
    fn refuses_every_non_full_byte() {
        for byte in [0x02u8, 0x03, 0x04, 0x00, 0xEF] {
            let err = Capability::from_envelope_byte(byte).unwrap_err();
            match err {
                WalletFileError::UnknownCapability(b) => assert_eq!(b, byte),
                other => panic!("expected UnknownCapability, got {other:?}"),
            }
        }
    }
}
