// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Subaddress index type.
//!
//! Subaddresses are derived from a root keypair using an `(account, address)` tuple.
//! The `(0, 0)` index is reserved for the primary address and cannot be constructed;
//! serde deserialization rejects it explicitly.

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroize;

/// A subaddress index identifying a derived address within a wallet.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, Serialize)]
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

// Deserialization enforces the `(0, 0)` invariant that `new` does.
impl<'de> Deserialize<'de> for SubaddressIndex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            account: u32,
            address: u32,
        }
        let r = Raw::deserialize(d)?;
        Self::new(r.account, r.address)
            .ok_or_else(|| serde::de::Error::custom("(0, 0) is reserved for the primary address"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json() {
        let idx = SubaddressIndex::new(3, 7).unwrap();
        let s = serde_json::to_string(&idx).unwrap();
        let back: SubaddressIndex = serde_json::from_str(&s).unwrap();
        assert_eq!(idx, back);
    }

    #[test]
    fn deserialize_rejects_zero_zero() {
        let s = r#"{"account":0,"address":0}"#;
        assert!(serde_json::from_str::<SubaddressIndex>(s).is_err());
    }
}
