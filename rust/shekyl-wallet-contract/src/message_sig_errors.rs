// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Message-signing failures onto the contract's `-29800` band.
//!
//! Shape errors are the caller's bug (`-32602`). Everything else is an
//! answer with its own code: `-29800` does not verify, `-29801` the paste
//! is corrupted, `-29802` the scheme byte is one this build does not
//! implement. A boolean `valid: false` cannot carry those four remedies,
//! so [`VerifyMessageError`](shekyl_engine_core::engine::message_signing::VerifyMessageError)
//! never becomes a success payload.

use shekyl_crypto_pq::message_signing::MessageSigError;
use shekyl_engine_core::engine::message_signing::{SignMessageError, VerifyMessageError};

use crate::error::WalletRpcError;

impl From<MessageSigError> for WalletRpcError {
    fn from(err: MessageSigError) -> Self {
        match err {
            MessageSigError::Malformed(detail) => {
                WalletRpcError::InvalidParams(format!("malformed signature string: {detail}"))
            }
            MessageSigError::UnsupportedScheme(scheme) => {
                WalletRpcError::MessageSigUnsupportedScheme { scheme }
            }
            MessageSigError::Corrupted => WalletRpcError::MessageSigCorrupted,
            MessageSigError::VerifyFailed => WalletRpcError::MessageSigVerifyFailed,
            MessageSigError::InvalidKey => {
                WalletRpcError::InternalError("message-signing key material invalid".into())
            }
            MessageSigError::Rng => WalletRpcError::InternalError(
                "the system random number generator failed — try again".into(),
            ),
        }
    }
}

impl From<SignMessageError> for WalletRpcError {
    fn from(err: SignMessageError) -> Self {
        match err {
            // Close and reopen. Its own code, so a client branches on the
            // code rather than on an English sentence.
            SignMessageError::WalletSessionEnded => WalletRpcError::WalletSessionEnded,
            SignMessageError::Key(detail) => {
                tracing::warn!(detail = %detail, "sign_message key-engine failure");
                WalletRpcError::InternalError("sign_message key-engine failure".into())
            }
            SignMessageError::Crypto(inner) => {
                tracing::warn!(detail = %inner, "sign_message crypto refusal");
                WalletRpcError::from(inner)
            }
            SignMessageError::Internal(detail) => {
                tracing::warn!(detail = %detail, "sign_message internal failure");
                WalletRpcError::InternalError("sign_message internal failure".into())
            }
        }
    }
}

impl From<VerifyMessageError> for WalletRpcError {
    fn from(err: VerifyMessageError) -> Self {
        match err {
            // Address shape is the caller's bug (`-32602`), never the
            // proofs-surface `-29100`.
            VerifyMessageError::InvalidAddress | VerifyMessageError::ClassicalOnly => {
                WalletRpcError::InvalidParams(err.to_string())
            }
            VerifyMessageError::Crypto(inner) => WalletRpcError::from(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;

    #[test]
    fn crypto_taxonomy_maps_to_contract_codes() {
        let cases = [
            (
                MessageSigError::Malformed("x"),
                WalletRpcErrorCode::InvalidParams,
            ),
            (
                MessageSigError::UnsupportedScheme(0x7f),
                WalletRpcErrorCode::MessageSigUnsupportedScheme,
            ),
            (
                MessageSigError::Corrupted,
                WalletRpcErrorCode::MessageSigCorrupted,
            ),
            (
                MessageSigError::VerifyFailed,
                WalletRpcErrorCode::MessageSigVerifyFailed,
            ),
            (
                MessageSigError::InvalidKey,
                WalletRpcErrorCode::InternalError,
            ),
            (MessageSigError::Rng, WalletRpcErrorCode::InternalError),
        ];
        for (err, code) in cases {
            assert_eq!(WalletRpcError::from(err).code(), code);
        }
    }

    #[test]
    fn unsupported_scheme_data_carries_the_byte() {
        let err = WalletRpcError::from(MessageSigError::UnsupportedScheme(0x42));
        assert_eq!(err.code().as_i32(), -29802);
        assert_eq!(err.data().expect("data")["scheme"], 0x42);
    }

    #[test]
    fn verify_failed_is_an_error_not_a_false_success() {
        let err = WalletRpcError::from(VerifyMessageError::Crypto(MessageSigError::VerifyFailed));
        assert_eq!(err.code(), WalletRpcErrorCode::MessageSigVerifyFailed);
        assert_eq!(err.code().as_i32(), -29800);
    }

    #[test]
    fn wallet_session_ended_gets_its_own_code() {
        let err = WalletRpcError::from(SignMessageError::WalletSessionEnded);
        assert_eq!(err.code(), WalletRpcErrorCode::WalletSessionEnded);
        assert_eq!(err.code().as_i32(), -29006);
        assert!(
            err.message().contains("close and reopen"),
            "the remedy sentence must survive onto the wire: {}",
            err.message()
        );
    }

    #[test]
    fn sign_internal_failures_are_category_only() {
        let err = WalletRpcError::from(SignMessageError::Internal(
            "/home/user/.shekyl/w.wallet: ENOSPC".into(),
        ));
        assert_eq!(err.code(), WalletRpcErrorCode::InternalError);
        assert!(
            !err.message().contains("/home"),
            "internal detail must not cross the wire: {}",
            err.message()
        );
    }

    #[test]
    fn address_shape_errors_are_params_not_proofs_codes() {
        for err in [
            VerifyMessageError::InvalidAddress,
            VerifyMessageError::ClassicalOnly,
        ] {
            assert_eq!(
                WalletRpcError::from(err).code(),
                WalletRpcErrorCode::InvalidParams
            );
        }
    }
}
