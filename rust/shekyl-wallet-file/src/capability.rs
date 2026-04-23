// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed view of the envelope's `capability_mode` byte.
//!
//! The envelope layer ([`shekyl_crypto_pq::wallet_envelope`]) speaks in raw
//! `u8` discriminants so the AAD layout is byte-stable across language
//! boundaries and forward-compatible with capabilities we have not yet
//! specified. Callers at the orchestrator level should never pattern-match
//! on those raw bytes — they are a transport concern. [`Capability`] is the
//! typed surface we expose on [`crate::WalletFileHandle`] and through the
//! eventual FFI opaque-handle getter.
//!
//! # Defensive decoding
//!
//! The envelope's `validate_cap_content` already rejects
//! [`CAPABILITY_RESERVED_MULTISIG`] with `RequiresMultisigSupport` and any
//! unknown byte with `UnknownCapabilityMode`, so an `OpenedKeysFile`
//! reaching this layer cannot legitimately carry one of those values.
//! [`Capability::from_envelope_byte`] still covers them defensively for
//! two reasons:
//!
//! 1. The envelope and the orchestrator live in separate crates; a future
//!    refactor that skips `validate_cap_content` (e.g. a direct
//!    `OpenedKeysFile` constructed by a test helper) should not silently
//!    produce a malformed `Capability`.
//! 2. Clippy-clean exhaustive matching requires every envelope constant to
//!    be handled explicitly. Mapping the reserved/unknown cases to typed
//!    errors ([`WalletFileError::MultisigNotSupported`] /
//!    [`WalletFileError::UnknownCapability`]) is cheaper than threading
//!    `unreachable!()` calls around the call sites.

use shekyl_crypto_pq::wallet_envelope::{
    CAPABILITY_FULL, CAPABILITY_HARDWARE_OFFLOAD, CAPABILITY_RESERVED_MULTISIG,
    CAPABILITY_VIEW_ONLY,
};

use crate::error::WalletFileError;

/// Typed projection of the envelope's `capability_mode` byte. The raw
/// `u8` discriminants are not stabilized as part of this crate's public
/// API — callers should use these variants and the
/// [`Self::can_spend_locally`] predicate rather than comparing against
/// [`shekyl_crypto_pq::wallet_envelope::CAPABILITY_FULL`] directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Spendable wallet: the keys file carries the 64-byte master seed,
    /// from which all private key material is re-derived on open.
    Full,

    /// View-only wallet: can scan the chain (classical view key plus
    /// ML-KEM decapsulation key) but cannot sign spends.
    ViewOnly,

    /// Hardware-offload wallet: the host holds view material and a
    /// commitment to a signing device; spend authorization is proxied
    /// to the device out-of-band.
    HardwareOffload,
}

impl Capability {
    /// Decode the envelope's `capability_mode` byte into a typed
    /// [`Capability`]. Returns a typed error for the reserved-multisig
    /// placeholder and for any unknown discriminant; the envelope
    /// layer's own validation already rejects both at seal/open time,
    /// so a caller that reaches the typed error path has encountered
    /// an internal invariant violation.
    pub(crate) fn from_envelope_byte(v: u8) -> Result<Self, WalletFileError> {
        match v {
            CAPABILITY_FULL => Ok(Self::Full),
            CAPABILITY_VIEW_ONLY => Ok(Self::ViewOnly),
            CAPABILITY_HARDWARE_OFFLOAD => Ok(Self::HardwareOffload),
            CAPABILITY_RESERVED_MULTISIG => Err(WalletFileError::MultisigNotSupported),
            other => Err(WalletFileError::UnknownCapability(other)),
        }
    }

    /// Whether the wallet holds signing material locally. `Full` does;
    /// `HardwareOffload` defers to an external device, so the
    /// on-device bytes alone cannot produce a spend. `ViewOnly` never
    /// can.
    ///
    /// This predicate is the canonical check for "should I offer the
    /// 'send' button?" — callers must use it instead of open-coding a
    /// `matches!(cap, Capability::Full)` check, because the latter
    /// silently excludes future capability variants.
    pub fn can_spend_locally(self) -> bool {
        matches!(self, Self::Full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_all_supported_bytes() {
        assert_eq!(
            Capability::from_envelope_byte(CAPABILITY_FULL).unwrap(),
            Capability::Full,
        );
        assert_eq!(
            Capability::from_envelope_byte(CAPABILITY_VIEW_ONLY).unwrap(),
            Capability::ViewOnly,
        );
        assert_eq!(
            Capability::from_envelope_byte(CAPABILITY_HARDWARE_OFFLOAD).unwrap(),
            Capability::HardwareOffload,
        );
    }

    #[test]
    fn refuses_reserved_multisig_byte() {
        let err = Capability::from_envelope_byte(CAPABILITY_RESERVED_MULTISIG).unwrap_err();
        assert!(matches!(err, WalletFileError::MultisigNotSupported));
    }

    #[test]
    fn refuses_unknown_byte() {
        let err = Capability::from_envelope_byte(0xEF).unwrap_err();
        match err {
            WalletFileError::UnknownCapability(b) => assert_eq!(b, 0xEF),
            other => panic!("expected UnknownCapability, got {other:?}"),
        }
    }

    #[test]
    fn can_spend_locally_matrix() {
        assert!(Capability::Full.can_spend_locally());
        assert!(!Capability::ViewOnly.can_spend_locally());
        assert!(!Capability::HardwareOffload.can_spend_locally());
    }
}
