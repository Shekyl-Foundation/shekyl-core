// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! IO error vocabulary.

// --- IO --------------------------------------------------------------------

/// Failures at the wallet's IO boundary: its files, the daemon RPC, and
/// scanner network calls.
///
/// `IoError` is intentionally distinct from [`std::io::Error`] — the
/// wallet-core layer's IO surface includes daemon RPC and scanner failures,
/// not just filesystem syscalls. The RPC binary maps each variant to a
/// stable JSON-RPC error code. The file, store and daemon variants carry
/// their causes typed, so that mapping is a `match`, never a reading of the
/// message text.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// A failure of the wallet's own files: envelope, payload frame, ledger
    /// decode, atomic write, advisory lock, preferences, or the filesystem
    /// beneath them. The upstream error, typed.
    #[error("wallet-file failure: {0}")]
    WalletFile(#[from] shekyl_engine_file::WalletFileError),

    /// The wallet's curve-tree companion store would not open. `fault` is
    /// what the failure means for the remedy, classified where it was
    /// raised ([`shekyl_curve_tree::ClientError::open_fault`]); `detail` is
    /// the store's own diagnosis, for the log only — it can name local
    /// paths, so it never reaches a wire.
    #[error("curve-tree store open failed: {detail}")]
    CurveTreeStore {
        /// What the failure means for whoever has to act on it.
        fault: shekyl_curve_tree::StoreOpenFault,
        /// The store's diagnosis, for the log.
        detail: String,
    },

    /// `P`'s serving body store (`.pstore`) would not open. `detail` is
    /// the store's own diagnosis, for the log only — it can name local
    /// paths, so it never reaches a wire.
    #[error("persona body store open failed: {detail}")]
    PStore {
        /// The store's diagnosis, for the log.
        detail: String,
    },

    /// A daemon RPC failed. `fault` is what the failure means for the
    /// remedy, classified where it was raised ([`RpcError::fault`]);
    /// `detail` is the failure's own rendering, for the log. It can carry
    /// text the daemon sent, so it never reaches a wire.
    ///
    /// [`RpcError::fault`]: shekyl_rpc_client::RpcError::fault
    #[error("daemon RPC failure: {detail}")]
    Daemon {
        /// What the failure means for whoever has to act on it.
        fault: shekyl_rpc_client::DaemonFault,
        /// The failure's own rendering, for the log.
        detail: String,
    },

    /// Scanner failure: chain scan, output identification, key-image
    /// computation, or pool-state retrieval.
    #[error("scanner failure: {detail}")]
    Scanner {
        /// Stringified upstream error.
        detail: String,
    },
}

impl From<shekyl_rpc_client::RpcError> for IoError {
    /// Classify the failure where it is raised and keep its rendering for
    /// the log. The `DaemonEngine` trait declares `type Error: Into<IoError>`,
    /// so orchestration code propagates daemon failures with `?` and the
    /// remedy travels with them as a value.
    fn from(err: shekyl_rpc_client::RpcError) -> Self {
        IoError::Daemon {
            fault: err.fault(),
            detail: err.to_string(),
        }
    }
}
