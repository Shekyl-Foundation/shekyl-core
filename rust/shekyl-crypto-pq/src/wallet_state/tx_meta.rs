// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **tx-meta block** of [`WalletState`](super::WalletState).
//!
//! Covers the per-transaction metadata that the wallet keeps after a
//! send: the tx-key(s) the wallet generated (for proof-of-payment), any
//! user-authored notes attached to a tx, generic key/value attributes,
//! and the set of scanned mempool-only transactions. At the 2a.1
//! restructure this block is a versioned stub with no field content;
//! typed fields land in commit 2d.

use serde::{Deserialize, Serialize};

use super::primitives::WalletStateError;

/// Schema version of the tx-meta block. V3.0 ships version `1`
/// (empty-stub shape). Commit 2d populates fields and bumps to `2`.
pub const TX_META_BLOCK_VERSION: u32 = 1;

/// The tx-meta block. See module docs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxMetaBlock {
    /// Per-block schema version. Always [`TX_META_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,
    // Fields land in commit 2d:
    //   pub tx_keys: TxKeyRegistry,
    //   pub tx_notes: TxNoteRegistry,
    //   pub attributes: Attributes,
    //   pub scanned_pool: ScannedPoolSet,
}

impl Default for TxMetaBlock {
    fn default() -> Self {
        Self {
            block_version: TX_META_BLOCK_VERSION,
        }
    }
}

impl TxMetaBlock {
    /// Refuse a load whose block version this binary does not recognize.
    pub(crate) fn check_version(&self) -> Result<(), WalletStateError> {
        if self.block_version != TX_META_BLOCK_VERSION {
            return Err(WalletStateError::UnsupportedBlockVersion {
                block: "tx_meta",
                file: self.block_version,
                binary: TX_META_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_current_block_version() {
        assert_eq!(TxMetaBlock::default().block_version, TX_META_BLOCK_VERSION);
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let b = TxMetaBlock { block_version: 999 };
        match b.check_version().unwrap_err() {
            WalletStateError::UnsupportedBlockVersion { block, .. } => {
                assert_eq!(block, "tx_meta")
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }
}
