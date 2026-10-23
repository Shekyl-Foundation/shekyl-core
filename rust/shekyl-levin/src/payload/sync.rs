// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-sync commands 2011–2014 (CS-Q3, `P2P_3_CHAIN_SYNC_BRIEF.md`).
//!
//! These are new commands with new ids. They are not [`crate::DefinedCommand`]
//! arms: ingress admits a command for dispatch, and no handler exists until
//! the cutover. The ids they replace (2003, 2004, 2006, 2007) stay until
//! that cutover retires them.
//!
//! A body is a [`shekyl_wire::BlockBody`]. This module moves it; it does
//! not judge it. The partition of a body response is judged here, because
//! that judgment needs nothing but the request and the response.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_crypto_hash::keccak256;
use shekyl_portable_storage::{load_from_binary, Limits, Section, Value};
use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash};
use shekyl_wire::{Block, BlockBody, SkeletonTx, TxBody, MIN_POW_BLOB_SIZE, MIN_PRUNED_SEGMENT};

use super::block::ATTESTATION_WITNESS_MAX_BYTES;
use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::notifies::{
    NOTIFY_REQUEST_BODIES, NOTIFY_REQUEST_HEADERS, NOTIFY_RESPONSE_BODIES, NOTIFY_RESPONSE_HEADERS,
};
use super::PortableMap;
use crate::header::DEFAULT_MAX_PACKET_SIZE;
use crate::ingress::{hash_list_cap, BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT, MAX_OBJECT_REQUEST_COUNT};

/// A full transaction body (`form` on the wire).
const FORM_FULL: u8 = 1;
/// A skeleton transaction body.
const FORM_SKELETON: u8 = 2;

/// Byte budget of one header response's preimages.
///
/// `Assumption` (Ruling B): written down, not measured. About ten thousand
/// headers at ~200 B, past the tip case (~144 KiB) and short of a whole
/// initial-sync run. Replaced by the CS-Q11 floor-device figures: headers
/// per second and peak memory, after the cutover.
pub const HEADERS_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

/// Byte budget of the blocks a body response adds after the first held one.
///
/// `Assumption` (Ruling B): written down, not measured. The first held
/// block is sent whatever its size — consensus weight and the packet cap
/// bound it — and this budget bounds the rest. Not derived from the weight
/// limit. Replaced by the CS-Q11 floor-device figures: bodies per second
/// and peak memory, after the cutover.
pub const BODIES_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// The smallest string whose portable-storage length varint is two bytes.
/// `0..=63` is one byte (`shekyl-portable-storage`'s `write_varint`).
const TWO_BYTE_LENGTH_FROM: u64 = 64;
/// The largest string whose portable-storage length varint is two bytes.
const TWO_BYTE_LENGTH_TO: u64 = 16_383;
/// Bytes of that two-byte length prefix.
const PREIMAGE_LENGTH_PREFIX: u64 = 2;
/// Section keys, the array envelope, and the work fields. Smaller than this.
const RESPONSE_HEADERS_SECTION: u64 = 4_096;

/// Length prefixes a budget of preimages can force, plus the section.
///
/// A preimage of [`TWO_BYTE_LENGTH_FROM`] bytes or more encodes its length
/// in [`PREIMAGE_LENGTH_PREFIX`] bytes. Filling [`HEADERS_RESPONSE_BYTES`]
/// with the shortest such preimage is one prefix per that many bytes. The
/// section is smaller than [`RESPONSE_HEADERS_SECTION`]. A preimage shorter
/// than [`MIN_POW_BLOB_SIZE`] is refused, and that minimum sits in the
/// two-byte band, so this allowance is an upper bound.
const RESPONSE_HEADERS_OVERHEAD: u64 = (HEADERS_RESPONSE_BYTES / TWO_BYTE_LENGTH_FROM)
    * PREIMAGE_LENGTH_PREFIX
    + RESPONSE_HEADERS_SECTION;

/// Encoded cap of [`RequestHeaders`]. Derived from the locator count
/// [`RequestChain`](super::RequestChain) already uses.
pub const CAP_REQUEST_HEADERS: u64 = hash_list_cap(BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT);

/// Encoded cap of [`ResponseHeaders`]: the preimage budget plus the section.
pub const CAP_RESPONSE_HEADERS: u64 = HEADERS_RESPONSE_BYTES + RESPONSE_HEADERS_OVERHEAD;

/// Encoded cap of [`RequestBodies`]. Derived from
/// [`MAX_OBJECT_REQUEST_COUNT`].
pub const CAP_REQUEST_BODIES: u64 = hash_list_cap(MAX_OBJECT_REQUEST_COUNT);

/// Encoded cap of [`ResponseBodies`]. The first held block is bounded by
/// the packet, so the decoder's cap is the packet. [`BODIES_RESPONSE_BYTES`]
/// is the budget later blocks are added under, not this cap.
pub const CAP_RESPONSE_BODIES: u64 = DEFAULT_MAX_PACKET_SIZE;

const _: () = assert!(CAP_REQUEST_HEADERS == 1_200_256);
const _: () = assert!(CAP_REQUEST_BODIES == 5_056);
const _: () = assert!(CAP_RESPONSE_HEADERS == HEADERS_RESPONSE_BYTES + RESPONSE_HEADERS_OVERHEAD);
const _: () = assert!(CAP_RESPONSE_HEADERS < DEFAULT_MAX_PACKET_SIZE);
const _: () = assert!(CAP_RESPONSE_BODIES == DEFAULT_MAX_PACKET_SIZE);
const _: () = assert!(HEADERS_RESPONSE_BYTES == 2 * 1024 * 1024);
const _: () = assert!(BODIES_RESPONSE_BYTES == 8 * 1024 * 1024);
const _: () = assert!(MIN_POW_BLOB_SIZE as u64 >= TWO_BYTE_LENGTH_FROM);
const _: () = assert!(MIN_POW_BLOB_SIZE as u64 <= TWO_BYTE_LENGTH_TO);
/// A cap or a count as `usize`. Each one is at most `u32::MAX`, so the
/// conversion does not truncate on a 32-bit target.
#[allow(clippy::cast_possible_truncation)]
const fn cap_usize(n: u64) -> usize {
    assert!(n <= 4_294_967_295);
    n as usize
}

/// Portable-storage varint width. `0..=63` is one byte, then two, four, eight.
const fn ps_varint_len(val: usize) -> usize {
    if val <= 63 {
        1
    } else if val <= 16_383 {
        2
    } else if val <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// A section key: its length byte and the key.
const fn key_len(chars: usize) -> usize {
    1 + chars
}

/// A `uint8` field: key, type tag, value.
const fn u8_field(chars: usize) -> usize {
    key_len(chars) + 1 + 1
}

/// A `uint64` field: key, type tag, eight value bytes.
const fn u64_field(chars: usize) -> usize {
    key_len(chars) + 1 + 8
}

/// A string field: key, type tag, length varint, bytes.
const fn bytes_field(chars: usize, n: usize) -> usize {
    key_len(chars) + 1 + ps_varint_len(n) + n
}

/// A full transaction section at [`MIN_PRUNED_SEGMENT`]: `form` and `blob`.
const FULL_TX_SECTION_BYTES: usize =
    ps_varint_len(2) + bytes_field(4, MIN_PRUNED_SEGMENT) + u8_field(4);

/// A skeleton section at the same segment: `form`, `unprunable`, the two
/// hashes (`prunable_hash`, `pqc_auth_hash`) and `archival_len`.
const SKELETON_TX_SECTION_BYTES: usize = ps_varint_len(5)
    + u8_field(4)
    + bytes_field(10, MIN_PRUNED_SEGMENT)
    + bytes_field(13, 32)
    + bytes_field(13, 32)
    + u64_field(12);

/// The smaller transaction section an accepted body can contain.
pub const MIN_TX_SECTION_BYTES: usize = if FULL_TX_SECTION_BYTES < SKELETON_TX_SECTION_BYTES {
    FULL_TX_SECTION_BYTES
} else {
    SKELETON_TX_SECTION_BYTES
};

/// Header-section fields: `blobs`, `tip_work`, `tip_work_top64`, `more`.
const RESPONSE_HEADERS_FIELDS: usize = 4;
/// A header section has no string outside the preimage array.
const RESPONSE_HEADERS_OWN_STRINGS: usize = 0;

/// Strings a header response may declare. One preimage is at least
/// [`MIN_POW_BLOB_SIZE`] plus its two-byte length prefix.
pub const RESPONSE_HEADERS_MAX_STRINGS: usize = (cap_usize(CAP_RESPONSE_HEADERS)
    / (MIN_POW_BLOB_SIZE + cap_usize(PREIMAGE_LENGTH_PREFIX)))
    + RESPONSE_HEADERS_OWN_STRINGS;

/// Transactions a body response may declare: the packet divided by the
/// smaller transaction section.
pub const RESPONSE_BODIES_MAX_TXS: usize = cap_usize(CAP_RESPONSE_BODIES) / MIN_TX_SECTION_BYTES;

/// Objects: one per body, plus one per transaction.
pub const RESPONSE_BODIES_MAX_OBJECTS: usize =
    cap_usize(MAX_OBJECT_REQUEST_COUNT) + RESPONSE_BODIES_MAX_TXS;

/// Strings in the minimum (full) section: the blob. A body adds `block`
/// and, at most, `attestation_witness`. The root adds `deferred` and
/// `missed_ids`.
const FULL_TX_STRINGS: usize = 1;
const BODY_STRINGS: usize = 2;
const ROOT_STRINGS: usize = 2;

/// Strings a body response may declare, from the same two counts.
pub const RESPONSE_BODIES_MAX_STRINGS: usize = ROOT_STRINGS
    + cap_usize(MAX_OBJECT_REQUEST_COUNT) * BODY_STRINGS
    + RESPONSE_BODIES_MAX_TXS * FULL_TX_STRINGS;

/// Fields: the root's three, two on a body (`block`, `txs`), two on the
/// minimum transaction section (`form`, `blob`).
const ROOT_FIELDS: usize = 3;
const BODY_FIELDS: usize = 2;
const FULL_TX_FIELDS: usize = 2;

/// Fields a body response may declare, from the same two counts.
pub const RESPONSE_BODIES_MAX_FIELDS: usize = ROOT_FIELDS
    + cap_usize(MAX_OBJECT_REQUEST_COUNT) * BODY_FIELDS
    + RESPONSE_BODIES_MAX_TXS * FULL_TX_FIELDS;

const RESPONSE_HEADERS_LIMITS: Limits = Limits {
    objects: 0,
    fields: RESPONSE_HEADERS_FIELDS,
    strings: RESPONSE_HEADERS_MAX_STRINGS,
};

const RESPONSE_BODIES_LIMITS: Limits = Limits {
    objects: RESPONSE_BODIES_MAX_OBJECTS,
    fields: RESPONSE_BODIES_MAX_FIELDS,
    strings: RESPONSE_BODIES_MAX_STRINGS,
};

/// A request is one hash-list field and no object.
const REQUEST_LIMITS: Limits = Limits {
    objects: 0,
    fields: 1,
    strings: 1,
};

const _: () = assert!(FULL_TX_SECTION_BYTES < SKELETON_TX_SECTION_BYTES);
const _: () = assert!(MIN_TX_SECTION_BYTES == FULL_TX_SECTION_BYTES);
const _: () = assert!(MIN_TX_SECTION_BYTES == 21);
const _: () = assert!(SKELETON_TX_SECTION_BYTES == 145);
const _: () = assert!(RESPONSE_HEADERS_MAX_STRINGS > 0);
const _: () = assert!(RESPONSE_BODIES_MAX_OBJECTS > cap_usize(MAX_OBJECT_REQUEST_COUNT));
const _: () = assert!(NOTIFY_REQUEST_HEADERS == 2011);
const _: () = assert!(NOTIFY_RESPONSE_HEADERS == 2012);
const _: () = assert!(NOTIFY_REQUEST_BODIES == 2013);
const _: () = assert!(NOTIFY_RESPONSE_BODIES == 2014);

/// The chain-sync commands, as chain sync's router admits them
/// (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-3 §4.2).
///
/// Not [`crate::DefinedCommand`]: that set is what the C++ ingress admits
/// for its handler, and 2011–2014 are not added to it. The router reads a
/// bucket's command, admits these here with their caps, and hands the bytes
/// to the sync owner; every other command goes on to the C++ handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncCommand {
    /// `NOTIFY_REQUEST_HEADERS` (2011).
    RequestHeaders,
    /// `NOTIFY_RESPONSE_HEADERS` (2012).
    ResponseHeaders,
    /// `NOTIFY_REQUEST_BODIES` (2013).
    RequestBodies,
    /// `NOTIFY_RESPONSE_BODIES` (2014).
    ResponseBodies,
}

impl SyncCommand {
    /// Every arm.
    pub const ALL: [Self; 4] = [
        Self::RequestHeaders,
        Self::ResponseHeaders,
        Self::RequestBodies,
        Self::ResponseBodies,
    ];

    /// The wire id this arm speaks.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        match self {
            Self::RequestHeaders => NOTIFY_REQUEST_HEADERS,
            Self::ResponseHeaders => NOTIFY_RESPONSE_HEADERS,
            Self::RequestBodies => NOTIFY_REQUEST_BODIES,
            Self::ResponseBodies => NOTIFY_RESPONSE_BODIES,
        }
    }

    /// A wire command id as a chain-sync command, or `None`.
    #[must_use]
    pub const fn from_wire(command: u32) -> Option<Self> {
        match command {
            NOTIFY_REQUEST_HEADERS => Some(Self::RequestHeaders),
            NOTIFY_RESPONSE_HEADERS => Some(Self::ResponseHeaders),
            NOTIFY_REQUEST_BODIES => Some(Self::RequestBodies),
            NOTIFY_RESPONSE_BODIES => Some(Self::ResponseBodies),
            _ => None,
        }
    }

    /// The payload cap the router applies before it buffers a message.
    #[must_use]
    pub const fn payload_cap(self) -> u64 {
        match self {
            Self::RequestHeaders => CAP_REQUEST_HEADERS,
            Self::ResponseHeaders => CAP_RESPONSE_HEADERS,
            Self::RequestBodies => CAP_REQUEST_BODIES,
            Self::ResponseBodies => CAP_RESPONSE_BODIES,
        }
    }
}

fn capped<T: PortableMap>(bytes: &[u8], cap: u64, limits: Limits) -> Result<T, Error> {
    let max = usize::try_from(cap).expect("an encoded cap fits usize");
    if bytes.len() > max {
        return Err(Error::OverCap {
            got: bytes.len(),
            max,
        });
    }
    // `limits` is derived from the smallest element this payload accepts,
    // not from `cap`. The decoder allocates an array from its declared
    // count once that count is under the limit, so a limit of `cap` lets a
    // payload of one-byte elements allocate hundreds of millions of sections.
    T::from_section(&load_from_binary(bytes, limits)?)
}

fn within_count(field: &'static str, got: usize, max: u64) -> Result<(), Error> {
    let max = usize::try_from(max).expect("a count cap fits usize");
    if got > max {
        return Err(Error::OverCount { field, got, max });
    }
    Ok(())
}

/// `NOTIFY_REQUEST_HEADERS` (2011). The locator, as `RequestChain`'s
/// `block_ids`. No prune flag: a header request has nothing to prune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeaders {
    /// Locator hashes, newest last, `CONTAINER_POD_AS_BLOB`.
    pub block_ids: Vec<[u8; HASH_SIZE]>,
}

impl RequestHeaders {
    /// Decode, refusing a payload one byte over [`CAP_REQUEST_HEADERS`]
    /// before the codec runs.
    ///
    /// # Errors
    ///
    /// [`Error::OverCap`] over the encoded cap, [`Error::OverCount`] over
    /// the locator count, or a schema error.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = capped::<Self>(bytes, CAP_REQUEST_HEADERS, REQUEST_LIMITS)?;
        within_count(
            "block_ids",
            value.block_ids.len(),
            BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT,
        )?;
        Ok(value)
    }
}

impl PortableMap for RequestHeaders {
    fn to_section(&self) -> Result<Section, Error> {
        within_count(
            "block_ids",
            self.block_ids.len(),
            BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT,
        )?;
        let mut section = Section::new();
        get::insert_pod_hashes(&mut section, "block_ids", &self.block_ids);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            block_ids: get::pod_hashes(section, "block_ids")?,
        })
    }
}

/// `NOTIFY_RESPONSE_HEADERS` (2012). Preimages starting at the child of
/// the first locator hash the responder holds: the first preimage's
/// parent is that hash. Then the responder's claimed cumulative work,
/// and whether another response follows.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseHeaders {
    /// Each entry is a [`shekyl_wire::PowBlob`]'s bytes.
    pub blobs: Vec<Vec<u8>>,
    /// The responder's claimed cumulative work.
    pub tip_work: u128,
    /// Whether more headers follow this response. Stored always: an absent
    /// field is a schema error, not a silent end of chain.
    pub more: bool,
}

impl ResponseHeaders {
    /// Decode, refusing a payload over [`CAP_RESPONSE_HEADERS`] before the
    /// codec runs, and a preimage total over [`HEADERS_RESPONSE_BYTES`].
    ///
    /// # Errors
    ///
    /// [`Error::OverCap`], [`Error::OverBudget`], [`Error::PreimageTooShort`],
    /// or a schema error.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = capped::<Self>(bytes, CAP_RESPONSE_HEADERS, RESPONSE_HEADERS_LIMITS)?;
        value.check_budget()?;
        Ok(value)
    }

    fn check_budget(&self) -> Result<(), Error> {
        let max = usize::try_from(HEADERS_RESPONSE_BYTES).expect("the budget fits usize");
        let mut got = 0usize;
        for blob in &self.blobs {
            if blob.len() < MIN_POW_BLOB_SIZE {
                return Err(Error::PreimageTooShort {
                    got: blob.len(),
                    min: MIN_POW_BLOB_SIZE,
                });
            }
            got = match got.checked_add(blob.len()) {
                Some(sum) => sum,
                None => {
                    return Err(Error::OverBudget {
                        field: "blobs",
                        got: usize::MAX,
                        max,
                    })
                }
            };
        }
        if got > max {
            return Err(Error::OverBudget {
                field: "blobs",
                got,
                max,
            });
        }
        Ok(())
    }

    fn section(&self) -> Section {
        let mut section = Section::new();
        get::insert_bytes_array(&mut section, "blobs", &self.blobs);
        let low = u64::try_from(self.tip_work & u128::from(u64::MAX)).expect("the low half fits");
        let high = u64::try_from(self.tip_work >> 64).expect("the high half fits");
        section.insert("tip_work", Value::UInt64(low));
        section.insert("tip_work_top64", Value::UInt64(high));
        section.insert("more", Value::Bool(self.more));
        section
    }
}

impl PortableMap for ResponseHeaders {
    fn to_section(&self) -> Result<Section, Error> {
        self.check_budget()?;
        Ok(self.section())
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        let low = get::u64_val(section, "tip_work")?;
        let high = get::u64_val(section, "tip_work_top64")?;
        Ok(Self {
            blobs: get::bytes_array(section, "blobs")?,
            tip_work: u128::from(low) | (u128::from(high) << 64),
            more: get::bool_val(section, "more")?,
        })
    }
}

impl std::fmt::Debug for ResponseHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut raw = Vec::new();
        for blob in &self.blobs {
            raw.extend_from_slice(blob);
        }
        let hash = keccak256(&raw);
        f.debug_struct("ResponseHeaders")
            .field(
                "blobs",
                &format_args!(
                    "{} @ {}B#{:02x}{:02x}{:02x}{:02x}",
                    self.blobs.len(),
                    raw.len(),
                    hash[0],
                    hash[1],
                    hash[2],
                    hash[3]
                ),
            )
            .field("tip_work", &self.tip_work)
            .field("more", &self.more)
            .finish()
    }
}

/// `NOTIFY_REQUEST_BODIES` (2013). The block hashes whose bodies are wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBodies {
    /// Block hashes, `CONTAINER_POD_AS_BLOB`, at most
    /// [`MAX_OBJECT_REQUEST_COUNT`].
    pub hashes: Vec<[u8; HASH_SIZE]>,
}

impl RequestBodies {
    /// Decode, refusing a payload over [`CAP_REQUEST_BODIES`] before the
    /// codec runs.
    ///
    /// # Errors
    ///
    /// [`Error::OverCap`], [`Error::OverCount`], or a schema error.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = capped::<Self>(bytes, CAP_REQUEST_BODIES, REQUEST_LIMITS)?;
        within_count("hashes", value.hashes.len(), MAX_OBJECT_REQUEST_COUNT)?;
        Ok(value)
    }
}

impl PortableMap for RequestBodies {
    fn to_section(&self) -> Result<Section, Error> {
        within_count("hashes", self.hashes.len(), MAX_OBJECT_REQUEST_COUNT)?;
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

/// How a body response fails its form. Checkable from the request and the
/// response: the receiver does not need the responder's holdings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodiesFormFault {
    /// A requested hash is in none of the three lists.
    Unaccounted,
    /// A hash is in more than one list, or twice in one. The response
    /// repeated it. A repeated hash in the request is
    /// [`Self::RequestRepeated`], the caller's own list.
    Repeated,
    /// `requested` names one hash twice. That list is the caller's, so this
    /// is not a fault of the peer's response.
    RequestRepeated,
    /// A listed hash was not requested.
    Unrequested,
    /// In request order, a sent block follows a deferred one.
    SentAfterDeferred,
    /// The first block the responder holds is deferred.
    FirstHeldDeferred,
    /// The sent blocks are not the request's sent hashes, in request order.
    OutOfOrder,
    /// A sent block's bytes are not a block, so they have no identity.
    Unreadable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Sent,
    Deferred,
    Missed,
}

/// `NOTIFY_RESPONSE_BODIES` (2014). Every requested block is sent, deferred
/// by the budget, or unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseBodies {
    /// The blocks sent, in request order.
    pub bodies: Vec<BlockBody>,
    /// Held, but past [`BODIES_RESPONSE_BYTES`].
    pub deferred: Vec<[u8; HASH_SIZE]>,
    /// Unavailable. The name and the meaning are the inherited field's.
    pub missed_ids: Vec<[u8; HASH_SIZE]>,
}

impl ResponseBodies {
    /// Decode, refusing a payload over [`CAP_RESPONSE_BODIES`] before the
    /// codec runs, and a body list over [`BODIES_RESPONSE_BYTES`]. The
    /// first body is exempt, as it is in [`plan_bodies`].
    ///
    /// # Errors
    ///
    /// [`Error::OverCap`], [`Error::OverBudget`], or a schema error.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = capped::<Self>(bytes, CAP_RESPONSE_BODIES, RESPONSE_BODIES_LIMITS)?;
        value.enforce_budget()?;
        Ok(value)
    }

    /// The partition of `requested`.
    ///
    /// Every requested hash is in exactly one of `bodies`, `deferred` and
    /// `missed_ids`, and nothing else is. Deferral is a suffix of what the
    /// responder holds: no sent block follows a deferred one, and the first
    /// held block is sent. A peer that marks a block unavailable is not at
    /// fault; that case is the scheduler's. The byte budget is charged by
    /// [`Self::decode`] and [`PortableMap::to_section`], with the first
    /// body exempt.
    ///
    /// # Errors
    ///
    /// A [`BodiesFormFault`]. The header is not involved.
    pub fn check_form(&self, requested: &[[u8; HASH_SIZE]]) -> Result<(), BodiesFormFault> {
        let mut wanted = BTreeSet::new();
        for hash in requested {
            if !wanted.insert(*hash) {
                return Err(BodiesFormFault::RequestRepeated);
            }
        }
        let body_ids = self.body_ids()?;
        let mut seen: BTreeMap<[u8; HASH_SIZE], Slot> = BTreeMap::new();
        let mut claim = |hash: [u8; HASH_SIZE], slot: Slot| -> Result<(), BodiesFormFault> {
            match seen.insert(hash, slot) {
                None => Ok(()),
                Some(_) => Err(BodiesFormFault::Repeated),
            }
        };
        for id in &body_ids {
            claim(*id, Slot::Sent)?;
        }
        for id in &self.deferred {
            claim(*id, Slot::Deferred)?;
        }
        for id in &self.missed_ids {
            claim(*id, Slot::Missed)?;
        }

        let mut held = false;
        let mut deferred = false;
        let mut sent_in_order = Vec::new();
        for hash in requested {
            match seen.get(hash).copied() {
                None => return Err(BodiesFormFault::Unaccounted),
                Some(Slot::Missed) => {}
                Some(Slot::Deferred) => {
                    if !held {
                        return Err(BodiesFormFault::FirstHeldDeferred);
                    }
                    held = true;
                    deferred = true;
                }
                Some(Slot::Sent) => {
                    if deferred {
                        return Err(BodiesFormFault::SentAfterDeferred);
                    }
                    held = true;
                    sent_in_order.push(*hash);
                }
            }
        }
        if seen.keys().any(|hash| !wanted.contains(hash)) {
            return Err(BodiesFormFault::Unrequested);
        }
        if body_ids != sent_in_order {
            return Err(BodiesFormFault::OutOfOrder);
        }
        Ok(())
    }

    /// The sent bodies, measured by [`body_budget_bytes`] and admitted by
    /// [`charge`], the same step [`plan_bodies`] uses. The first body is
    /// exempt. A later body that does not fit is [`Error::OverBudget`].
    fn enforce_budget(&self) -> Result<(), Error> {
        let max = usize::try_from(BODIES_RESPONSE_BYTES).expect("the budget fits usize");
        let mut sent_bytes = 0usize;
        let mut sent_one = false;
        for body in &self.bodies {
            let size = body_budget_bytes(body);
            match charge(sent_bytes, size, sent_one) {
                Some(next) => {
                    sent_bytes = next;
                    sent_one = true;
                }
                None => {
                    // The sum that did not fit. Overflow is not a length the
                    // peer sent; `usize::MAX` is the report, the same sentinel
                    // `ResponseHeaders::check_budget` uses.
                    let got = match sent_bytes.checked_add(size) {
                        Some(sum) => sum,
                        None => usize::MAX,
                    };
                    return Err(Error::OverBudget {
                        field: "bodies",
                        got,
                        max,
                    });
                }
            }
        }
        Ok(())
    }

    fn body_ids(&self) -> Result<Vec<[u8; HASH_SIZE]>, BodiesFormFault> {
        self.bodies
            .iter()
            .map(|body| {
                Block::from_bytes(&body.block)
                    .map(|block| block.hash().to_bytes())
                    .map_err(|_| BodiesFormFault::Unreadable)
            })
            .collect()
    }
}

impl PortableMap for ResponseBodies {
    fn to_section(&self) -> Result<Section, Error> {
        self.enforce_budget()?;
        let mut section = Section::new();
        let mut bodies = Vec::with_capacity(self.bodies.len());
        for body in &self.bodies {
            bodies.push(block_body_section(body)?);
        }
        get::insert_object_array(&mut section, "bodies", bodies);
        get::insert_pod_hashes(&mut section, "deferred", &self.deferred);
        get::insert_pod_hashes(&mut section, "missed_ids", &self.missed_ids);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        let bodies = get::object_array(section, "bodies")?
            .into_iter()
            .map(block_body_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            bodies,
            deferred: get::pod_hashes(section, "deferred")?,
            missed_ids: get::pod_hashes(section, "missed_ids")?,
        })
    }
}

/// Which requested hashes a response sends, defers and misses.
///
/// The first held block is sent whatever its size. Later held blocks are
/// sent while the sent bytes fit [`BODIES_RESPONSE_BYTES`] and deferred
/// once they do not. A hash `held_len` does not know is missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyPlan {
    /// Sent, in request order.
    pub send: Vec<[u8; HASH_SIZE]>,
    /// Held, past the budget. A suffix of the held hashes.
    pub deferred: Vec<[u8; HASH_SIZE]>,
    /// Not held.
    pub missed: Vec<[u8; HASH_SIZE]>,
}

/// Partition `requested` by what the responder holds.
///
/// `held` is the body the responder has for that hash, or `None` when it
/// does not. The size is [`body_budget_bytes`], the measure
/// [`ResponseBodies::decode`] and [`PortableMap::to_section`] charge.
pub fn plan_bodies<'a>(
    requested: &[[u8; HASH_SIZE]],
    held: impl Fn(&[u8; HASH_SIZE]) -> Option<&'a BlockBody>,
) -> BodyPlan {
    let mut plan = BodyPlan {
        send: Vec::new(),
        deferred: Vec::new(),
        missed: Vec::new(),
    };
    let mut sent_bytes = 0usize;
    let mut sent_one = false;
    // Once a held body does not fit, every later held body is deferred.
    // `charge` alone would send a later small body after a deferred large
    // one, and `check_form` refuses that as `SentAfterDeferred`.
    let mut deferring = false;
    for hash in requested {
        match held(hash) {
            None => plan.missed.push(*hash),
            Some(_) if deferring => plan.deferred.push(*hash),
            Some(body) => match charge(sent_bytes, body_budget_bytes(body), sent_one) {
                Some(next) => {
                    plan.send.push(*hash);
                    sent_bytes = next;
                    sent_one = true;
                }
                None => {
                    plan.deferred.push(*hash);
                    deferring = true;
                }
            },
        }
    }
    plan
}

/// The bytes one sent body counts toward [`BODIES_RESPONSE_BYTES`]: the
/// block, each carried transaction, and the witness. [`plan_bodies`] and
/// the body codec ([`ResponseBodies::decode`], [`PortableMap::to_section`])
/// both charge this and nothing else.
#[must_use]
pub fn body_budget_bytes(body: &BlockBody) -> usize {
    let mut n = body.block.len();
    n = n.saturating_add(body.attestation_witness.len());
    for tx in &body.txs {
        n = n.saturating_add(match tx {
            TxBody::Full(bytes) => bytes.len(),
            TxBody::Skeleton(skeleton) => {
                let auth = skeleton
                    .pqc_auth_hash
                    .map(|hash| hash.as_bytes().len())
                    .unwrap_or(0);
                skeleton
                    .unprunable
                    .len()
                    .saturating_add(skeleton.prunable_hash.as_bytes().len())
                    .saturating_add(auth)
                    .saturating_add(std::mem::size_of::<u64>())
            }
        });
    }
    n
}

/// Admit `size` onto `sent_bytes`. The first body is admitted whatever its
/// size; a later body is admitted only while the sum stays within
/// [`BODIES_RESPONSE_BYTES`]. `Some` is the new sum. `None` is a deferral.
fn charge(sent_bytes: usize, size: usize, sent_one: bool) -> Option<usize> {
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).expect("the budget fits usize");
    let fits = sent_bytes.saturating_add(size) <= budget;
    if !sent_one || fits {
        Some(sent_bytes.saturating_add(size))
    } else {
        None
    }
}

fn block_body_section(body: &BlockBody) -> Result<Section, Error> {
    if body.attestation_witness.len() > ATTESTATION_WITNESS_MAX_BYTES {
        return Err(Error::WitnessTooLarge {
            got: body.attestation_witness.len(),
            max: ATTESTATION_WITNESS_MAX_BYTES,
        });
    }
    let mut section = Section::new();
    section.insert("block", Value::Bytes(body.block.clone()));
    let mut txs = Vec::with_capacity(body.txs.len());
    for tx in &body.txs {
        txs.push(tx_section(tx));
    }
    get::insert_object_array(&mut section, "txs", txs);
    get::insert_opt_bytes(
        &mut section,
        "attestation_witness",
        &body.attestation_witness,
    );
    Ok(section)
}

fn block_body_from(section: &Section) -> Result<BlockBody, Error> {
    let attestation_witness = get::opt_bytes(section, "attestation_witness")?;
    if attestation_witness.len() > ATTESTATION_WITNESS_MAX_BYTES {
        return Err(Error::WitnessTooLarge {
            got: attestation_witness.len(),
            max: ATTESTATION_WITNESS_MAX_BYTES,
        });
    }
    let txs = get::object_array(section, "txs")?
        .into_iter()
        .map(tx_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BlockBody {
        block: get::bytes(section, "block")?.to_vec(),
        txs,
        attestation_witness,
    })
}

fn tx_section(tx: &TxBody) -> Section {
    let mut section = Section::new();
    match tx {
        TxBody::Full(bytes) => {
            section.insert("form", Value::UInt8(FORM_FULL));
            section.insert("blob", Value::Bytes(bytes.clone()));
        }
        TxBody::Skeleton(skeleton) => {
            section.insert("form", Value::UInt8(FORM_SKELETON));
            section.insert("unprunable", Value::Bytes(skeleton.unprunable.clone()));
            section.insert(
                "prunable_hash",
                Value::Bytes(skeleton.prunable_hash.as_bytes().to_vec()),
            );
            if let Some(auth) = skeleton.pqc_auth_hash {
                section.insert("pqc_auth_hash", Value::Bytes(auth.as_bytes().to_vec()));
            }
            section.insert(
                "archival_len",
                Value::UInt64(skeleton.archival_len.to_raw()),
            );
        }
    }
    section
}

fn tx_from(section: &Section) -> Result<TxBody, Error> {
    match get::u8_val(section, "form")? {
        FORM_FULL => Ok(TxBody::Full(get::bytes(section, "blob")?.to_vec())),
        FORM_SKELETON => {
            let pqc_auth_hash = match section.get("pqc_auth_hash") {
                None => None,
                Some(Value::Bytes(bytes)) => {
                    let raw = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        Error::InvalidLength {
                            field: "pqc_auth_hash",
                            expected: 32,
                            got: bytes.len(),
                        }
                    })?;
                    Some(PqcAuthHash::from_bytes(raw))
                }
                Some(_) => {
                    return Err(Error::TypeMismatch {
                        field: "pqc_auth_hash",
                        expected: "string",
                    })
                }
            };
            Ok(TxBody::Skeleton(SkeletonTx {
                unprunable: get::bytes(section, "unprunable")?.to_vec(),
                prunable_hash: PrunableHash::from_bytes(get::blob(section, "prunable_hash")?),
                pqc_auth_hash,
                archival_len: ArchivalLength::from_raw(get::u64_val(section, "archival_len")?),
            }))
        }
        _ => Err(Error::TxForm),
    }
}
