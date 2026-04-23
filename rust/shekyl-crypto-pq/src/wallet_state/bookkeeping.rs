// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **bookkeeping block** of [`WalletState`](super::WalletState).
//!
//! Covers the subaddress registry (indices, labels, reverse lookup),
//! the address book (contacts / destinations the user has saved), and
//! account tags. At the 2a.1 restructure this block is a versioned
//! stub with no field content; typed fields land in commit 2c.

use serde::{Deserialize, Serialize};

use super::primitives::WalletStateError;

/// Schema version of the bookkeeping block. V3.0 ships version `1`
/// (empty-stub shape). Commit 2c populates fields and bumps to `2`.
pub const BOOKKEEPING_BLOCK_VERSION: u32 = 1;

/// The bookkeeping block. See module docs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookkeepingBlock {
    /// Per-block schema version. Always [`BOOKKEEPING_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,
    // Fields land in commit 2c:
    //   pub subaddresses: SubaddressRegistry,
    //   pub address_book: AddressBook,
    //   pub account_tags: AccountTags,
}

impl Default for BookkeepingBlock {
    fn default() -> Self {
        Self {
            block_version: BOOKKEEPING_BLOCK_VERSION,
        }
    }
}

impl BookkeepingBlock {
    /// Refuse a load whose block version this binary does not recognize.
    pub(crate) fn check_version(&self) -> Result<(), WalletStateError> {
        if self.block_version != BOOKKEEPING_BLOCK_VERSION {
            return Err(WalletStateError::UnsupportedBlockVersion {
                block: "bookkeeping",
                file: self.block_version,
                binary: BOOKKEEPING_BLOCK_VERSION,
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
            BookkeepingBlock::default().block_version,
            BOOKKEEPING_BLOCK_VERSION
        );
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let b = BookkeepingBlock { block_version: 999 };
        match b.check_version().unwrap_err() {
            WalletStateError::UnsupportedBlockVersion { block, .. } => {
                assert_eq!(block, "bookkeeping")
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }
}
