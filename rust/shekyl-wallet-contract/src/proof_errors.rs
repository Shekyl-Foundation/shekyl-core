// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`ProofsError`](shekyl_engine_core::engine::proofs::ProofsError) onto the
//! contract's proof codes.
//!
//! One map for every embedder. The RPC server and the desktop wallet both
//! answer a malformed proof, a missing tx secret, and a syncing daemon with
//! the same code and the same sentence. Detail that can echo a client string
//! is logged here and does not cross the wire.

use shekyl_engine_core::engine::proofs::ProofsError;

use crate::error::{from_daemon_rpc_error, WalletRpcError};

impl From<ProofsError> for WalletRpcError {
    fn from(err: ProofsError) -> Self {
        match err {
            ProofsError::Malformed(detail) => {
                tracing::warn!(detail = %detail, "proof rejected as malformed");
                WalletRpcError::ProofMalformed
            }
            ProofsError::TxSecretUnavailable => WalletRpcError::ProofTxSecretUnavailable,
            ProofsError::NoProvableOutputs(detail) => {
                tracing::info!(detail = %detail, "proof request had no provable outputs");
                WalletRpcError::ProofNoProvableOutputs
            }
            ProofsError::TxNotFound(txid) => {
                tracing::info!(txid = %txid, "proof-named tx unknown to the daemon");
                WalletRpcError::ProofTxNotFound
            }
            ProofsError::TxUnconfirmed(txid) => {
                tracing::info!(txid = %txid, "reserve locator names a pooled (unconfirmed) tx");
                WalletRpcError::ProofTxUnconfirmed
            }
            ProofsError::DaemonSyncing => {
                tracing::info!("proof verification refused: daemon is syncing");
                WalletRpcError::ProofDaemonSyncing
            }
            ProofsError::InvalidRecipient => WalletRpcError::InvalidRecipient,
            ProofsError::AmountOverflow => {
                WalletRpcError::InternalError("proof amount sum overflow".into())
            }
            ProofsError::Daemon(err) => from_daemon_rpc_error(&err),
            ProofsError::Key(detail) => {
                tracing::warn!(detail = %detail, "proof key-engine failure");
                WalletRpcError::InternalError("proof key-engine failure".into())
            }
            ProofsError::Generate(detail) => {
                tracing::warn!(detail = %detail, "proof generation failure");
                WalletRpcError::InternalError("proof generation failure".into())
            }
            ProofsError::Encoding(detail) => {
                tracing::warn!(detail = %detail, "proof encoding failure");
                WalletRpcError::InternalError("proof encoding failure".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;

    #[test]
    fn proofs_errors_map_to_contract_codes() {
        let cases = [
            (
                ProofsError::Malformed("x".into()),
                WalletRpcErrorCode::ProofMalformed,
            ),
            (
                ProofsError::TxSecretUnavailable,
                WalletRpcErrorCode::ProofTxSecretUnavailable,
            ),
            (
                ProofsError::NoProvableOutputs("x".into()),
                WalletRpcErrorCode::ProofNoProvableOutputs,
            ),
            (
                ProofsError::TxNotFound("ab".repeat(32)),
                WalletRpcErrorCode::ProofTxNotFound,
            ),
            (
                ProofsError::TxUnconfirmed("cd".repeat(32)),
                WalletRpcErrorCode::ProofTxUnconfirmed,
            ),
            (
                ProofsError::DaemonSyncing,
                WalletRpcErrorCode::ProofDaemonSyncing,
            ),
            (
                ProofsError::InvalidRecipient,
                WalletRpcErrorCode::InvalidRecipient,
            ),
            (
                ProofsError::AmountOverflow,
                WalletRpcErrorCode::InternalError,
            ),
            (
                ProofsError::Key("x".into()),
                WalletRpcErrorCode::InternalError,
            ),
        ];
        for (err, code) in cases {
            assert_eq!(WalletRpcError::from(err).code(), code);
        }
    }

    #[test]
    fn malformed_message_is_stable_and_detail_free() {
        let err = WalletRpcError::from(ProofsError::Malformed(
            "wrong HRP 'attacker-controlled'".into(),
        ));
        assert_eq!(err.message(), "proof string malformed");
        assert!(!err.message().contains("attacker"));
    }

    #[test]
    fn key_engine_detail_stays_off_the_wire() {
        let err = WalletRpcError::from(ProofsError::Key("/home/user/.shekyl/w.wallet".into()));
        assert_eq!(err.message(), "internal error: proof key-engine failure");
        assert!(!err.message().contains("/home"));
    }

    #[test]
    fn daemon_syncing_names_the_retry_and_the_code() {
        let err = WalletRpcError::from(ProofsError::DaemonSyncing);
        assert_eq!(
            err.message(),
            "daemon is syncing; retry proof verification once it has caught up"
        );
        assert_eq!(err.code().as_i32(), -29305);
    }
}
