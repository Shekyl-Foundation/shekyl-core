// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bookkeeping block — subaddress registry + labels + external address
//! book + account-tag index.
//!
//! Companion to [`LedgerBlock`](crate::ledger_block::LedgerBlock). The
//! bookkeeping block holds the purely-UX state the wallet needs to
//! decide which outputs belong to which subaddress and how to render
//! addresses / accounts to the user. None of its fields affect consensus.
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
//! * `subaddress_labels` splits the primary-address label into its own
//!   field (`primary_label: String`) and uses a sparse
//!   `BTreeMap<SubaddressIndex, String>` for everything else. This is
//!   forced by the Shekyl-native [`SubaddressIndex`] invariant that
//!   refuses to construct `(0, 0)` — the primary needs a home, but the
//!   map cannot carry it.
//! * `address_book` stays a `Vec<AddressBookEntry>` to preserve the
//!   user-controlled insertion order that GUIs render. Each entry
//!   carries an optional encrypted [`PaymentId`]; the legacy
//!   unencrypted form is rejected at parse time per the `PaymentId`
//!   module.
//! * `account_tags` becomes two fields — the set of known tag names
//!   with descriptions, and the assignment of a tag to each tagged
//!   account. The wallet2 `std::pair<map, vector>` positional encoding
//!   is replaced by explicit map-based accounting.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{error::WalletLedgerError, payment_id::PaymentId, subaddress::SubaddressIndex};

/// Schema version of the bookkeeping block. V3.0 ships version `1`.
/// Any field addition / removal / renaming inside the block bumps
/// this; loads that see a different version refuse rather than migrate.
pub const BOOKKEEPING_BLOCK_VERSION: u32 = 1;

/// Labels covering every address the wallet can generate: the primary
/// and all derived subaddresses.
///
/// Split into two fields because Shekyl's [`SubaddressIndex`] refuses
/// to construct `(0, 0)` — the primary lives outside the map, in
/// [`SubaddressLabels::primary`]. Every other `(account, address)` with
/// `(account, address) != (0, 0)` is eligible for a `per_index` entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubaddressLabels {
    /// Label for the primary address `(0, 0)`. Empty string = no label.
    #[serde(default)]
    pub primary: String,

    /// Labels for non-primary subaddresses, keyed by `(account, address)`.
    /// Missing entries mean "no label" — the caller should not treat an
    /// absent key differently from an entry whose value is the empty
    /// string, but both are representable and round-trip faithfully.
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
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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

/// Per-account tagging for UX filtering (e.g. "business", "personal").
///
/// Tags are entirely user-facing: they never leave the wallet and have
/// no consensus effect. Two pieces of state:
///
/// 1. The set of tag names the user has declared, with an optional
///    human-readable description per tag.
/// 2. The current assignment of (at most) one tag to each tagged
///    account. Accounts not present in the map have no tag.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountTags {
    /// Declared tag names mapped to their descriptions. Empty string =
    /// known tag with no description. Using a `BTreeMap` so the wire
    /// format is deterministic regardless of insertion order.
    #[serde(default)]
    pub tag_descriptions: BTreeMap<String, String>,

    /// Per-account tag assignment keyed by account major index. A tag
    /// referenced here **must** be a key in `tag_descriptions` for the
    /// block to make semantic sense; this invariant is the orchestrator's
    /// responsibility (the deserializer does not enforce it, so wallets
    /// that drop a tag description without clearing assignments still
    /// load — the rendering layer falls back to showing the raw tag
    /// name).
    #[serde(default)]
    pub per_account_tag: BTreeMap<u32, String>,
}

/// The bookkeeping block. See module docs for scope, versioning, and
/// design rationale.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookkeepingBlock {
    /// Per-block schema version. Always [`BOOKKEEPING_BLOCK_VERSION`]
    /// on construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Reverse lookup from the compressed-Edwards public spend key of
    /// a subaddress to its `(account, address)` index. Populated
    /// incrementally by the subaddress-generation code as the user
    /// creates new addresses or walks the lookahead window.
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

    /// Per-account tag state.
    #[serde(default)]
    pub account_tags: AccountTags,
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
        account_tags: AccountTags,
    ) -> Self {
        Self {
            block_version: BOOKKEEPING_BLOCK_VERSION,
            subaddress_registry,
            subaddress_labels,
            address_book,
            account_tags,
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
        // Force a non-(0, 0) index: `(seed + 1, seed)` always has a
        // nonzero account, so the `SubaddressIndex::new` invariant is
        // always satisfied for any `seed`.
        SubaddressIndex::new(seed + 1, seed).expect("non-(0,0)")
    }

    fn populated() -> BookkeepingBlock {
        let mut registry = BTreeMap::new();
        registry.insert([0x11; 32], sample_subaddress_index(1));
        registry.insert([0x22; 32], sample_subaddress_index(2));

        let mut per_index = BTreeMap::new();
        per_index.insert(sample_subaddress_index(1), "savings".into());
        per_index.insert(sample_subaddress_index(2), "hot".into());

        let mut tag_descriptions = BTreeMap::new();
        tag_descriptions.insert("business".into(), "work-related".into());
        tag_descriptions.insert("personal".into(), String::new());

        let mut per_account_tag = BTreeMap::new();
        per_account_tag.insert(0u32, "personal".into());
        per_account_tag.insert(3u32, "business".into());

        BookkeepingBlock::new(
            registry,
            SubaddressLabels {
                primary: "Main".into(),
                per_index,
            },
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
            AccountTags {
                tag_descriptions,
                per_account_tag,
            },
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
        // Arbitrary labels + address book + tags — exercises the block
        // end-to-end with wide coverage of map/Vec shapes.
        #[test]
        fn populated_block_round_trip_proptest(
            primary in "[a-zA-Z0-9 ]{0,16}",
            labels in proptest::collection::btree_map(
                (1u32..8, 0u32..8).prop_map(|(a, b)| SubaddressIndex::new(a, b).unwrap()),
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
            tag_names in proptest::collection::btree_map(
                "[a-z]{1,8}",
                "[a-z ]{0,8}",
                0..4,
            ),
            tag_assign in proptest::collection::btree_map(
                0u32..32,
                "[a-z]{1,8}",
                0..4,
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
                SubaddressLabels { primary, per_index },
                address_book,
                AccountTags {
                    tag_descriptions: tag_names,
                    per_account_tag: tag_assign,
                },
            );
            let bytes = b.to_postcard_bytes().expect("serialize");
            let back = BookkeepingBlock::from_postcard_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(&back, &b);
            // and byte-stable under a second round-trip
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
