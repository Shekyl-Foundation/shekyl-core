// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bookkeeping block — primary label + external address book.
//!
//! Companion to [`LedgerBlock`](crate::ledger_block::LedgerBlock). The
//! bookkeeping block holds purely-UX state the wallet needs to render
//! addresses and contacts to the user. None of its fields affect consensus.
//!
//! # Wire format
//!
//! Postcard (`serde`-compatible binary format). Field order is fixed by
//! the struct layout; there are no map-typed fields after FA-2.
//!
//! # FA-2 (End-state 5)
//!
//! Subaddress registry and per-index labels were deleted per
//! `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7.4 / §6.2. Payment requests
//! (FA-8) replace subaddress-based receive UX.

use serde::{Deserialize, Serialize};

use crate::{error::WalletLedgerError, payment_id::PaymentId, payment_request::PaymentRequest};

/// Schema version of the bookkeeping block.
///
/// Primary-claim rename ships [`BOOKKEEPING_BLOCK_VERSION`] `5`
/// (`AddressBookEntry::is_subaddress` deleted). Version `4` carried
/// payment requests (FA-8). Version `3` carried `primary_label` and
/// `address_book` only (FA-2 End-state 5). Shekyl is pre-genesis — loads
/// that see any other version refuse rather than migrate.
pub const BOOKKEEPING_BLOCK_VERSION: u32 = 5;

/// One entry in the external address book — a contact / recurring payee
/// the user has saved for convenience.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct AddressBookEntry {
    /// Shekyl-encoded address (standard or integrated).
    pub address: String,

    /// Human-readable description the user set for this entry.
    pub description: String,

    /// Optional encrypted payment ID attached to this entry. Always
    /// the 8-byte encrypted form — [`PaymentId::read`] refuses the
    /// legacy unencrypted marker at parse time.
    #[serde(default)]
    pub payment_id: Option<PaymentId>,
}

/// The bookkeeping block. See module docs for scope, versioning, and
/// design rationale.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct BookkeepingBlock {
    /// Per-block schema version. Always [`BOOKKEEPING_BLOCK_VERSION`]
    /// on construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Optional human-readable label for the wallet's primary address.
    #[serde(default)]
    pub primary_label: Option<String>,

    /// External address book (contacts / recurring payees). Ordered by
    /// the user-controlled insertion order; the persistence layer
    /// preserves that order verbatim.
    #[serde(default)]
    pub address_book: Vec<AddressBookEntry>,

    /// Off-chain payment requests (FA-8, `SUBADDRESS_UNDER_PQC.md` §5.7.9).
    #[serde(default)]
    pub payment_requests: Vec<PaymentRequest>,
}

impl BookkeepingBlock {
    /// Construct a fresh, empty bookkeeping block at the current version.
    pub fn empty() -> Self {
        Self {
            block_version: BOOKKEEPING_BLOCK_VERSION,
            ..Self::default()
        }
    }

    /// Construct a bookkeeping block by setting the version field on a
    /// freshly-built `Self::default`. Convenience for tests and the
    /// orchestrator's construction path.
    pub fn new(primary_label: Option<String>, address_book: Vec<AddressBookEntry>) -> Self {
        Self {
            block_version: BOOKKEEPING_BLOCK_VERSION,
            primary_label,
            address_book,
            payment_requests: Vec::new(),
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. Refuses any version mismatch.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let block: Self = postcard::from_bytes(bytes)?;
        block.check_version()?;
        Ok(block)
    }

    /// Version gate. Called automatically by
    /// [`Self::from_postcard_bytes`]; exposed publicly so the
    /// `WalletLedger` aggregator can fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.block_version != BOOKKEEPING_BLOCK_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "bookkeeping",
                file: self.block_version,
                binary: BOOKKEEPING_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn populated() -> BookkeepingBlock {
        BookkeepingBlock::new(
            Some("Main".into()),
            vec![
                AddressBookEntry {
                    address: "Shk1example".into(),
                    description: "alice".into(),
                    payment_id: Some(PaymentId([1u8; 8])),
                },
                AddressBookEntry {
                    address: "Shk1sub".into(),
                    description: "bob contact".into(),
                    payment_id: None,
                },
            ],
        )
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = BookkeepingBlock::empty();
        assert_eq!(b.block_version, BOOKKEEPING_BLOCK_VERSION);
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = BookkeepingBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_roundtrips_value_equality() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = BookkeepingBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_is_byte_stable() {
        let b = populated();
        let bytes1 = b.to_postcard_bytes().expect("serialize1");
        let back = BookkeepingBlock::from_postcard_bytes(&bytes1).expect("deserialize");
        let bytes2 = back.to_postcard_bytes().expect("serialize2");
        assert_eq!(bytes1, bytes2, "postcard encoding must be byte-stable");
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let mut b = BookkeepingBlock::empty();
        b.block_version = 999;
        let bytes = b.to_postcard_bytes().expect("serialize");
        match BookkeepingBlock::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "bookkeeping");
                assert_eq!(file, 999);
                assert_eq!(binary, BOOKKEEPING_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }

    #[test]
    fn truncated_postcard_input_is_refused() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let chopped = &bytes[..bytes.len() / 2];
        let is_postcard = matches!(
            BookkeepingBlock::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        );
        assert!(is_postcard, "truncated input must hit the postcard branch");
    }

    proptest! {
        #[test]
        fn populated_block_round_trip_proptest(
            primary_label in proptest::option::of("[a-z]{0,8}"),
            addr_book in proptest::collection::vec(
                (
                    "[A-Za-z0-9]{1,16}",
                    "[a-z ]{0,12}",
                    any::<Option<[u8; 8]>>(),
                ),
                0..5,
            ),
        ) {
            let address_book: Vec<_> = addr_book
                .into_iter()
                .map(|(a, d, pid)| AddressBookEntry {
                    address: a,
                    description: d,
                    payment_id: pid.map(PaymentId),
                })
                .collect();
            let b = BookkeepingBlock::new(primary_label, address_book);
            let bytes = b.to_postcard_bytes().expect("serialize");
            let back = BookkeepingBlock::from_postcard_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(&back, &b);
            let bytes2 = back.to_postcard_bytes().expect("serialize2");
            prop_assert_eq!(bytes, bytes2);
        }

        #[test]
        fn any_wrong_version_is_refused(bad in any::<u32>().prop_filter(
            "must differ from current version",
            |v| *v != BOOKKEEPING_BLOCK_VERSION,
        )) {
            let mut b = BookkeepingBlock::empty();
            b.block_version = bad;
            let bytes = b.to_postcard_bytes().expect("serialize");
            let err = BookkeepingBlock::from_postcard_bytes(&bytes).unwrap_err();
            let is_version_err = matches!(
                err,
                WalletLedgerError::UnsupportedBlockVersion { .. }
            );
            prop_assert!(is_version_err, "expected UnsupportedBlockVersion");
        }
    }
}
