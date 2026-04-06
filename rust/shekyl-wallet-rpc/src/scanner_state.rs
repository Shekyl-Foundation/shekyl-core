// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Scanner state shared across the RPC server when `rust-scanner` is enabled.

use std::sync::Mutex;

use shekyl_scanner::WalletState;

/// Shared scanner state for the RPC server.
///
/// Holds the Rust-native wallet state behind a mutex for thread-safe
/// concurrent access from RPC handler threads.
pub struct ScannerState {
    pub state: Mutex<WalletState>,
}

impl ScannerState {
    /// Create a new empty scanner state.
    pub fn new() -> Self {
        ScannerState {
            state: Mutex::new(WalletState::new()),
        }
    }
}

impl Default for ScannerState {
    fn default() -> Self {
        Self::new()
    }
}
