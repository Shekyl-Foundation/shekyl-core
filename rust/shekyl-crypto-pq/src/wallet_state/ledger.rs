// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **ledger block** of [`WalletState`](super::WalletState).
//!
//! The ledger is the list of transfers (outputs the wallet has scanned
//! as belonging to it) plus the blockchain-tip metadata needed for the
//! scanner to resume. At the 2a.1 restructure this block is a versioned
//! stub with no field content; typed fields land in commit 2b.

use serde::{Deserialize, Serialize};

use super::primitives::WalletStateError;

/// Schema version of the ledger block. V3.0 ships version `1`
/// (empty-stub shape). Commit 2b populates fields and bumps to `2`.
pub const LEDGER_BLOCK_VERSION: u32 = 1;

/// The ledger block. See module docs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerBlock {
    /// Per-block schema version. Always [`LEDGER_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,
    // Fields land in commit 2b:
    //   pub transfers: Vec<Transfer>,
    //   pub blockchain_tip: BlockchainTip,
    //   pub scan_progress: ScanProgress,
}

impl Default for LedgerBlock {
    fn default() -> Self {
        Self {
            block_version: LEDGER_BLOCK_VERSION,
        }
    }
}

impl LedgerBlock {
    /// Refuse a load whose block version this binary does not recognize.
    pub(crate) fn check_version(&self) -> Result<(), WalletStateError> {
        if self.block_version != LEDGER_BLOCK_VERSION {
            return Err(WalletStateError::UnsupportedBlockVersion {
                block: "ledger",
                file: self.block_version,
                binary: LEDGER_BLOCK_VERSION,
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
        assert_eq!(LedgerBlock::default().block_version, LEDGER_BLOCK_VERSION);
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let b = LedgerBlock { block_version: 999 };
        match b.check_version().unwrap_err() {
            WalletStateError::UnsupportedBlockVersion { block, .. } => {
                assert_eq!(block, "ledger")
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }
}
