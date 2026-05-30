// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Scanner state shared across the RPC server when `rust-scanner` is enabled.

use std::sync::Mutex;

use shekyl_scanner::{LedgerBlock, LedgerIndexes};

/// Live `(LedgerBlock, LedgerIndexes)` pair under a single lock.
///
/// `LedgerBlock` is the persisted on-chain-derived state; `LedgerIndexes`
/// is the runtime-only lookup-and-accrual state that is rebuilt from the
/// ledger + scanner replay on every wallet open. They live behind a
/// single mutex because every block-ingestion path mutates both, so
/// splitting them across two locks would introduce inconsistent
/// observation windows for nothing.
///
/// See `docs/V3_WALLET_DECISION_LOG.md` ("`RuntimeWalletState` audit",
/// 2026-04-25) for the rationale that pinned this shape.
pub type LiveLedger = (LedgerBlock, LedgerIndexes);

/// Shared scanner state for the RPC server.
///
/// Holds the Rust-native wallet state behind a mutex for thread-safe
/// concurrent access from RPC handler threads.
pub struct ScannerState {
    pub state: Mutex<LiveLedger>,
}

impl ScannerState {
    /// Create a new empty scanner state.
    pub fn new() -> Self {
        ScannerState {
            state: Mutex::new((LedgerBlock::empty(), LedgerIndexes::empty())),
        }
    }
}

impl Default for ScannerState {
    fn default() -> Self {
        Self::new()
    }
}
