// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cryptonote notify maps 2002–2004 / 2006–2010 (`cryptonote_protocol_defs.h`).
//!
//! 2011–2014 are the chain-sync commands ([`super::sync`]). They are named
//! here, beside the ids they follow. The C++ ingress does not admit them:
//! the router hands them to chain sync's owner.

use shekyl_portable_storage::{varint_len, Section, Value, HEADER};
use shekyl_wire::transaction::MAX_TX_SIZE;

use super::block::BlockCompleteEntry;
use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::PortableMap;
use crate::header::DEFAULT_MAX_PACKET_SIZE;

/// `NOTIFY_NEW_TRANSACTIONS`.
pub const NOTIFY_NEW_TRANSACTIONS: u32 = 2002;
/// `NOTIFY_NEW_COMPACT_BLOCK`.
pub const NOTIFY_NEW_COMPACT_BLOCK: u32 = 2008;
/// `NOTIFY_REQUEST_COMPACT_MISSING_TX`.
pub const NOTIFY_REQUEST_COMPACT_MISSING_TX: u32 = 2009;
/// `NOTIFY_GET_TXPOOL_COMPLEMENT`.
pub const NOTIFY_GET_TXPOOL_COMPLEMENT: u32 = 2010;
/// Chain-sync header request. The next free id after 2010, a
/// [`crate::Command`] arm like the rest. 2003, 2004, 2006 and 2007, the
/// inherited block and chain requests, are retired (CS-5): their ids are
/// not commands this protocol defines.
pub const NOTIFY_REQUEST_HEADERS: u32 = 2011;
/// Chain-sync header response.
pub const NOTIFY_RESPONSE_HEADERS: u32 = 2012;
/// Chain-sync body request.
pub const NOTIFY_REQUEST_BODIES: u32 = 2013;
/// Chain-sync body response.
pub const NOTIFY_RESPONSE_BODIES: u32 = 2014;

/// Body of `NOTIFY_NEW_COMPACT_BLOCK` (2008), the sole block-announce command.
/// Header plus optional tx bodies; omitted txs are fetched via 2009.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCompactBlock {
    /// Block header blob plus any tx bodies the sender included.
    pub b: BlockCompleteEntry,
    /// Advertised chain height.
    pub current_blockchain_height: u64,
}

impl PortableMap for NewCompactBlock {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("b", Value::Object(self.b.to_section()?));
        section.insert(
            "current_blockchain_height",
            Value::UInt64(self.current_blockchain_height),
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            b: BlockCompleteEntry::from_section(get::object(section, "b")?)?,
            current_blockchain_height: get::u64_val(section, "current_blockchain_height")?,
        })
    }
}

/// The key of [`NewTransactions::txs`].
const KEY_TXS: &str = "txs";
/// The key of [`NewTransactions::padding`].
const KEY_PADDING: &str = "_";
/// The key of [`NewTransactions::dandelionpp_fluff`].
const KEY_FLUFF: &str = "dandelionpp_fluff";
/// What `dandelionpp_fluff` reads as when the key is absent, so the value
/// a notice does not write.
const FLUFF_DEFAULT: bool = true;

/// The length byte a section key opens with.
const KEY_LENGTH_BYTES: u64 = 1;

/// A section key: its length byte and its name
/// (`shekyl-portable-storage`'s `write_key`).
const fn key_bytes(key: &str) -> u64 {
    KEY_LENGTH_BYTES + key.len() as u64
}

/// The byte that names a value's type, written after its key.
const TYPE_TAG_BYTES: u64 = 1;
/// A boolean value's one byte.
const BOOL_BYTES: u64 = 1;

/// The padding member of a notice that carries no padding: its key, its
/// type tag and the varint of a zero length. Always written.
const EMPTY_PADDING_FIELD_BYTES: u64 = key_bytes(KEY_PADDING) + TYPE_TAG_BYTES + varint_len(0);
/// The flag member, written only when the flag is not [`FLUFF_DEFAULT`]:
/// its key, its type tag and the boolean.
const FLUFF_FIELD_BYTES: u64 = key_bytes(KEY_FLUFF) + TYPE_TAG_BYTES + BOOL_BYTES;
/// The `txs` member without its count and entries: its key and its type
/// tag. Written only when there is an entry.
const TXS_FIELD_BYTES: u64 = key_bytes(KEY_TXS) + TYPE_TAG_BYTES;

/// The encoded size of a [`NewTransactions`] with no padding, counted
/// without building it.
///
/// One accounting for both ends of PWD-B12's release bound: the relay's
/// flush adds whole transactions while [`Self::encoded_len`] stays within
/// [`CAP_NEW_TRANSACTIONS`], and that cap is this count for one
/// transaction of [`MAX_TX_SIZE`] bytes. `tests/new_transactions_bound.rs`
/// holds the count to the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewTransactionsSize {
    /// How many blobs.
    count: u64,
    /// Their bytes, each with its length varint.
    entries: u64,
}

impl NewTransactionsSize {
    /// A notice with no transaction.
    pub const EMPTY: Self = Self {
        count: 0,
        entries: 0,
    };

    /// This notice with one more blob of `blob_len` bytes: the blob and
    /// the varint of its length.
    #[must_use]
    pub const fn with(self, blob_len: usize) -> Self {
        let blob_len = blob_len as u64;
        Self {
            count: self.count.saturating_add(1),
            entries: self
                .entries
                .saturating_add(varint_len(blob_len))
                .saturating_add(blob_len),
        }
    }

    /// The payload bytes [`PortableMap::store`] writes for this notice with
    /// `dandelionpp_fluff` as given and empty padding.
    ///
    /// Line by line: the storage header; the varint of the member count;
    /// the padding member; the `txs` member when there is an entry (its
    /// key and tag, the varint of the entry count, the entries); the flag
    /// member when the notice is a stem.
    #[must_use]
    pub const fn encoded_len(self, dandelionpp_fluff: bool) -> u64 {
        let has_txs = self.count > 0;
        let writes_flag = dandelionpp_fluff != FLUFF_DEFAULT;
        // The padding member is always there.
        let mut members: u64 = 1;
        let mut fields = EMPTY_PADDING_FIELD_BYTES;
        if has_txs {
            members += 1;
            fields = fields
                .saturating_add(TXS_FIELD_BYTES)
                .saturating_add(varint_len(self.count))
                .saturating_add(self.entries);
        }
        if writes_flag {
            members += 1;
            fields = fields.saturating_add(FLUFF_FIELD_BYTES);
        }
        (HEADER.len() as u64 + varint_len(members)).saturating_add(fields)
    }
}

/// Encoded cap of [`NewTransactions`] (PWD-B12's release bound): a notice
/// that carries one transaction of [`MAX_TX_SIZE`] bytes, as a stem, which
/// is the larger of the two forms because a stem writes its flag.
///
/// Derived, not chosen. The receiver refuses a 2002 above it
/// ([`crate::Command::payload_cap`]) and the relay's flush releases whole
/// transactions up to it, so the two ends read one figure. A notice of one
/// transaction always fits: nothing a node may relay is refused for size.
pub const CAP_NEW_TRANSACTIONS: u64 = NewTransactionsSize::EMPTY
    .with(MAX_TX_SIZE)
    .encoded_len(!FLUFF_DEFAULT);

// The figure, so a change to `MAX_TX_SIZE` or to the notice's members is a
// change someone reads: 1 000 000 bytes of transaction, 4 of its length
// varint, and 40 of envelope (9 storage header, 1 member count, 4 padding
// member, 6 `txs` key, tag and count, 20 flag member).
const _: () = assert!(CAP_NEW_TRANSACTIONS == 1_000_044);
const _: () =
    assert!(CAP_NEW_TRANSACTIONS == MAX_TX_SIZE as u64 + varint_len(MAX_TX_SIZE as u64) + 40);
// Tight to the transaction: one more byte of it does not fit.
const _: () = assert!(
    NewTransactionsSize::EMPTY
        .with(MAX_TX_SIZE + 1)
        .encoded_len(!FLUFF_DEFAULT)
        > CAP_NEW_TRANSACTIONS
);
// A fluff of that one transaction is the smaller form.
const _: () = assert!(
    NewTransactionsSize::EMPTY
        .with(MAX_TX_SIZE)
        .encoded_len(FLUFF_DEFAULT)
        + FLUFF_FIELD_BYTES
        == CAP_NEW_TRANSACTIONS
);
const _: () = assert!(CAP_NEW_TRANSACTIONS < DEFAULT_MAX_PACKET_SIZE);

/// `NOTIFY_NEW_TRANSACTIONS` body.
///
/// `_` padding is **always stored** (even empty). `dandelionpp_fluff` is
/// `KV_SERIALIZE_OPT` default **true** (omit when fluff). Empty `txs` omit
/// the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTransactions {
    /// Opaque tx blobs.
    pub txs: Vec<Vec<u8>>,
    /// Cover-traffic padding.
    pub padding: Vec<u8>,
    /// Fluff (true, default) vs stem (false).
    pub dandelionpp_fluff: bool,
}

impl PortableMap for NewTransactions {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_bytes_array(&mut section, KEY_TXS, &self.txs);
        section.insert(KEY_PADDING, Value::Bytes(self.padding.clone()));
        get::insert_opt_bool(
            &mut section,
            KEY_FLUFF,
            self.dandelionpp_fluff,
            FLUFF_DEFAULT,
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            txs: get::bytes_array(section, KEY_TXS)?,
            padding: get::bytes(section, KEY_PADDING)?.to_vec(),
            dandelionpp_fluff: get::opt_bool(section, KEY_FLUFF, FLUFF_DEFAULT)?,
        })
    }
}

/// `NOTIFY_REQUEST_COMPACT_MISSING_TX` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestCompactMissingTx {
    /// Block hash, POD-as-blob.
    pub block_hash: [u8; HASH_SIZE],
    /// Advertised chain height.
    pub current_blockchain_height: u64,
    /// Missing indices, `CONTAINER_POD_AS_BLOB` of `uint64`.
    pub missing_tx_indices: Vec<u64>,
}

impl PortableMap for RequestCompactMissingTx {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("block_hash", Value::Bytes(self.block_hash.to_vec()));
        section.insert(
            "current_blockchain_height",
            Value::UInt64(self.current_blockchain_height),
        );
        get::insert_pod_u64s(&mut section, "missing_tx_indices", &self.missing_tx_indices);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            block_hash: get::blob(section, "block_hash")?,
            current_blockchain_height: get::u64_val(section, "current_blockchain_height")?,
            missing_tx_indices: get::pod_u64s(section, "missing_tx_indices")?,
        })
    }
}

/// `NOTIFY_GET_TXPOOL_COMPLEMENT` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTxpoolComplement {
    /// Pool hashes, `CONTAINER_POD_AS_BLOB`.
    pub hashes: Vec<[u8; HASH_SIZE]>,
}

impl PortableMap for GetTxpoolComplement {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_pod_hashes(&mut section, "hashes", &self.hashes);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            hashes: get::pod_hashes(section, "hashes")?,
        })
    }
}
