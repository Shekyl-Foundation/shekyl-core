// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Subaddress index type for the scanner.
//!
//! Subaddresses are derived from a root keypair using an `(account, address)` tuple.
//! The `(0, 0)` index is reserved for the primary address and cannot be constructed.

use zeroize::Zeroize;

/// A subaddress index identifying a derived address within a wallet.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub struct SubaddressIndex {
    account: u32,
    address: u32,
}

impl SubaddressIndex {
    /// Create a new SubaddressIndex. Returns `None` for the primary address `(0, 0)`.
    pub const fn new(account: u32, address: u32) -> Option<SubaddressIndex> {
        if (account == 0) && (address == 0) {
            return None;
        }
        Some(SubaddressIndex { account, address })
    }

    /// The account this subaddress belongs to.
    pub const fn account(&self) -> u32 {
        self.account
    }

    /// The address index within its account.
    pub const fn address(&self) -> u32 {
        self.address
    }
}
