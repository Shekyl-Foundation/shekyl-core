// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **sync-state block** of [`WalletState`](super::WalletState).
//!
//! Covers live-transaction tracking that only matters while a wallet is
//! actively syncing: pending sends the wallet has broadcast, transactions
//! it has seen confirm, incoming payments awaiting confirmation, and the
//! optional background-sync cache used by the `.background-sync.wallet`
//! companion. At the 2a.1 restructure this block is a versioned stub
//! with no field content; typed fields land in commit 2e.

use serde::{Deserialize, Serialize};

use super::primitives::WalletStateError;

/// Schema version of the sync-state block. V3.0 ships version `1`
/// (empty-stub shape). Commit 2e populates fields and bumps to `2`.
pub const SYNC_STATE_BLOCK_VERSION: u32 = 1;

/// The sync-state block. See module docs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStateBlock {
    /// Per-block schema version. Always [`SYNC_STATE_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,
    // Fields land in commit 2e:
    //   pub unconfirmed_txs: UnconfirmedTxTable,
    //   pub confirmed_txs:   ConfirmedTxTable,
    //   pub unconfirmed_payments: UnconfirmedPaymentTable,
    //   pub background_sync: BackgroundSyncCache,
    //   pub has_ever_refreshed: bool,
}

impl Default for SyncStateBlock {
    fn default() -> Self {
        Self {
            block_version: SYNC_STATE_BLOCK_VERSION,
        }
    }
}

impl SyncStateBlock {
    /// Refuse a load whose block version this binary does not recognize.
    pub(crate) fn check_version(&self) -> Result<(), WalletStateError> {
        if self.block_version != SYNC_STATE_BLOCK_VERSION {
            return Err(WalletStateError::UnsupportedBlockVersion {
                block: "sync_state",
                file: self.block_version,
                binary: SYNC_STATE_BLOCK_VERSION,
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
        assert_eq!(
            SyncStateBlock::default().block_version,
            SYNC_STATE_BLOCK_VERSION
        );
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let b = SyncStateBlock { block_version: 999 };
        match b.check_version().unwrap_err() {
            WalletStateError::UnsupportedBlockVersion { block, .. } => {
                assert_eq!(block, "sync_state")
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }
}
