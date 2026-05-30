// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bookkeeping block — subaddress registry + labels + external address
//! book.
//!
//! Companion to [`LedgerBlock`](crate::ledger_block::LedgerBlock). The
//! bookkeeping block holds the purely-UX state the wallet needs to
//! decide which outputs belong to which subaddress and how to render
//! addresses to the user. None of its fields affect consensus.
//!
//! # Wire format
//!
//! Postcard (`serde`-compatible binary format). Every key-sorted
//! container is a [`BTreeMap`] rather than a `HashMap` so that repeat
//! serialization of the same logical value produces the same bytes —
//! required for the byte-stability tests and for any future on-disk
//! equality check the orchestrator may perform (e.g. "don't fsync if
//! nothing changed").
//!
//! # Shekyl-native design notes
//!
//! The Monero wallet2 persistence for this surface is a grab-bag of
//! nested `std::vector`s and `std::pair`s with positional semantics.
//! The block version here is **not** a port of that layout — it is a
//! designed schema that happens to cover the same functional surface:
//!
//! * `subaddress_registry` becomes a `BTreeMap<[u8; 32], SubaddressIndex>`
//!   keyed by the compressed-Edwards subaddress public spend key. In
//!   wallet2 this was a `serializable_unordered_map<public_key,
//!   subaddress_index>` — we normalize to the byte-stable sorted map.
//! * `subaddress_labels` is a single sparse
//!   `BTreeMap<SubaddressIndex, String>` covering both the primary
//!   address ([`SubaddressIndex::PRIMARY`]) and every derived
//!   subaddress. The flat-namespace decision (see
//!   `docs/V3_WALLET_DECISION_LOG.md`, "Subaddress hierarchy") removes
//!   the need for a special primary-address slot.
//! * `address_book` stays a `Vec<AddressBookEntry>` to preserve the
//!   user-controlled insertion order that GUIs render. Each entry
//!   carries an optional encrypted [`PaymentId`]; the legacy
//!   unencrypted form is rejected at parse time per the `PaymentId`
//!   module.
//!
//! Account-level tagging (the wallet2 `account_tags` field) is dropped
//! entirely: with no account hierarchy in Shekyl V3, per-account UX
//! grouping has no anchor. Subaddress-level grouping, if it surfaces as
//! a real user need, is a separate post-V3.0 feature with its own
//! design pass.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{error::WalletLedgerError, payment_id::PaymentId, subaddress::SubaddressIndex};

/// Schema version of the bookkeeping block.
///
/// V3.0 ships version `2`. Version `1` (pre-flat-namespace) carried a
/// two-field `SubaddressIndex { account, address }`, a primary-label
/// split-out field, and an `account_tags` map; none of those exist on
/// disk yet (Shekyl is pre-genesis), so the bump is for in-source
/// hygiene rather than migration handling. Loads that see any other
/// version refuse rather than migrate.
pub const BOOKKEEPING_BLOCK_VERSION: u32 = 2;

/// Labels covering every address the wallet can generate.
///
/// Single sparse map keyed by [`SubaddressIndex`]; missing entries mean
/// "no label". The primary address ([`SubaddressIndex::PRIMARY`]) is a
/// regular key in this map — there is no carved-out primary slot, in
/// keeping with the flat-namespace decision (see crate docs).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SubaddressLabels {
    /// Labels for every labeled address, primary or derived. Missing
    /// entries mean "no label" — callers should not treat an absent
    /// key differently from an entry whose value is the empty string,
    /// but both are representable and round-trip faithfully.
    #[serde(default)]
    pub per_index: BTreeMap<SubaddressIndex, String>,
}

/// One entry in the external address book — a contact / recurring payee
/// the user has saved for convenience.
///
/// The address is stored as a Shekyl-encoded string so the bookkeeping
/// block stays network-agnostic at the type level; the orchestrator is
/// responsible for parsing it (and its optional payment-id) against the
/// wallet's declared [`Network`](shekyl_crypto_pq::wallet_state::Network)
/// on display / send.
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

    /// True when `address` decodes to a subaddress (rather than the
    /// contact's primary address). Cached here so rendering does not
    /// need a parse round-trip.
    pub is_subaddress: bool,
}

/// The bookkeeping block. See module docs for scope, versioning, and
/// design rationale.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct BookkeepingBlock {
    /// Per-block schema version. Always [`BOOKKEEPING_BLOCK_VERSION`]
    /// on construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Reverse lookup from the compressed-Edwards public spend key of
    /// a subaddress to its [`SubaddressIndex`]. Populated incrementally
    /// by the subaddress-generation code as the user creates new
    /// addresses or walks the lookahead window.
    ///
    /// Keyed by raw 32-byte compressed-Edwards bytes (rather than a
    /// `curve25519_dalek::EdwardsPoint`) so that the `BTreeMap` order
    /// is byte-stable and free of any curve-arithmetic dependency on
    /// the ordering.
    #[serde(default)]
    pub subaddress_registry: BTreeMap<[u8; 32], SubaddressIndex>,

    /// Labels for the primary address and every derived subaddress.
    #[serde(default)]
    pub subaddress_labels: SubaddressLabels,

    /// External address book (contacts / recurring payees). Ordered by
    /// the user-controlled insertion order; the persistence layer
    /// preserves that order verbatim.
    #[serde(default)]
    pub address_book: Vec<AddressBookEntry>,
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
    pub fn new(
        subaddress_registry: BTreeMap<[u8; 32], SubaddressIndex>,
        subaddress_labels: SubaddressLabels,
        address_book: Vec<AddressBookEntry>,
    ) -> Self {
        Self {
            block_version: BOOKKEEPING_BLOCK_VERSION,
            subaddress_registry,
            subaddress_labels,
            address_book,
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
    /// `WalletLedger` aggregator (commit 2g) can fan out the same check.
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

    fn sample_subaddress_index(seed: u32) -> SubaddressIndex {
        SubaddressIndex::new(seed)
    }

    fn populated() -> BookkeepingBlock {
        let mut registry = BTreeMap::new();
        registry.insert([0x11; 32], sample_subaddress_index(1));
        registry.insert([0x22; 32], sample_subaddress_index(2));

        let mut per_index = BTreeMap::new();
        per_index.insert(SubaddressIndex::PRIMARY, "Main".into());
        per_index.insert(sample_subaddress_index(1), "savings".into());
        per_index.insert(sample_subaddress_index(2), "hot".into());

        BookkeepingBlock::new(
            registry,
            SubaddressLabels { per_index },
            vec![
                AddressBookEntry {
                    address: "Shk1example".into(),
                    description: "alice".into(),
                    payment_id: Some(PaymentId([1u8; 8])),
                    is_subaddress: false,
                },
                AddressBookEntry {
                    address: "Shk1sub".into(),
                    description: "bob subaddr".into(),
                    payment_id: None,
                    is_subaddress: true,
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
        // `BookkeepingBlock` is `PartialEq` (all its fields are), so we
        // can assert stronger value equality than the `LedgerBlock`
        // byte-stability test.
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
        // Arbitrary labels + address book — exercises the block
        // end-to-end with wide coverage of map/Vec shapes.
        #[test]
        fn populated_block_round_trip_proptest(
            labels in proptest::collection::btree_map(
                (0u32..64).prop_map(SubaddressIndex::new),
                "[a-z]{0,8}",
                0..8,
            ),
            addr_book in proptest::collection::vec(
                (
                    "[A-Za-z0-9]{1,16}",
                    "[a-z ]{0,12}",
                    any::<bool>(),
                    any::<Option<[u8; 8]>>(),
                ),
                0..5,
            ),
        ) {
            let registry = BTreeMap::new();
            let per_index = labels;
            let address_book: Vec<_> = addr_book
                .into_iter()
                .map(|(a, d, is_sub, pid)| AddressBookEntry {
                    address: a,
                    description: d,
                    payment_id: pid.map(PaymentId),
                    is_subaddress: is_sub,
                })
                .collect();
            let b = BookkeepingBlock::new(
                registry,
                SubaddressLabels { per_index },
                address_book,
            );
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
