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
/// stable JSON-RPC error code. The file variants carry their causes typed,
/// so that mapping is a `match`, never a reading of the message text.
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

    /// Daemon RPC call failed at the transport, JSON-decode, or
    /// daemon-application layer.
    #[error("daemon RPC failure: {detail}")]
    Daemon {
        /// Stringified upstream error.
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
    /// Map the upstream `shekyl_rpc_client::RpcError` into an
    /// [`IoError::Daemon`] by stringifying the upstream variant.
    ///
    /// This conversion exists so the crate-internal `DaemonEngine`
    /// trait (in `crate::engine::traits`) can declare
    /// `type Error: Into<IoError>` and have
    /// [`Engine`](crate::engine::Engine) orchestration code propagate
    /// daemon-RPC failures uniformly via `?`. The stringification is
    /// deliberate: `IoError` is the wallet-core error surface, not
    /// the upstream's; preserving the upstream's typed shape would
    /// either leak the upstream type into the wallet-core API or
    /// require duplicating the upstream's variant taxonomy here.
    /// Stringification keeps the boundary clean while preserving the
    /// failure detail for logs and JSON-RPC error responses. The
    /// upstream type carries a `thiserror`-derived `Display` impl
    /// whose `#[error("...")]` attributes produce stable, human-
    /// readable messages (`"connection error (...)"`,
    /// `"invalid transaction (...)"`, etc.); `Display` is the
    /// canonical stringification rather than `Debug`, which would
    /// leak variant names and bracket-quoted field shapes that are
    /// brittle to upstream refactors.
    fn from(err: shekyl_rpc_client::RpcError) -> Self {
        IoError::Daemon {
            detail: err.to_string(),
        }
    }
}
