// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival tables' stored shapes — DRS-E1 S-ARCH
//! (`DRS_E1_SARCH.md` §3.4, §4; `SAR-Q3` RULED 2026-09-23).
//!
//! Six tables the C++ left as raw bytes gain types (the seventh row of the
//! read set is a `properties` cell, `codec::property`); E4's writers write
//! what these describe and may not choose a second shape for the same byte.
//!
//! **Where the shapes live (DRS-E4 `ARW-Q8`, 2026-09-29).** The persisted
//! bond record and the two close-row scalars — [`BondRecord`], [`Holdings`],
//! [`HeldShard`], [`HeldShards`], [`FirstPayingHeight`], [`RMarket`],
//! [`SigmaWorkMilli`] — were this module's while the daemon store was their
//! only reader (`SAR-Q2` as built). E6 slice 8 reads the record through
//! `ChainView`, the second reader that ruling's reopening clause named, so
//! the types moved to `shekyl_types::archival` and their `Canonical` impls
//! to `shekyl-store-codec` (the orphan rule: an impl of that crate's trait
//! for the vocabulary crate's type lives where the trait does). This module
//! **re-exports** them so every `crate::codec::…` path in this store is
//! unchanged, and keeps the one shape that is the daemon store's alone: the
//! attestation witness blob. The bytes did not move — `bond_record.snap`,
//! `r_market.snap`, `sigma_work_milli.snap` pin them.

use shekyl_store_codec::BlobKind;
use shekyl_types::archival::MAX_ATTESTATION_WITNESS_BYTES;

pub use shekyl_types::archival::{
    BondRecord, FirstPayingHeight, HeldShard, HeldShards, Holdings, HoldingsError, RMarket,
    SigmaWorkMilli, SlashLogEntry, SlashedHolding, MAX_BOND_KEY_BYTES,
};

/// `archival_attestation_witness[height]` — a block's attestation witness
/// as stored: bytes the store does not parse (`shekyl-archival-retention::
/// attestation_wire` owns the parse). A [`BlobKind`], not a codec: the
/// consumer checks well-formedness, and an empty witness is **no row**, not
/// an empty row (the writer stores nothing for an empty attestation set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationWitnessBytes;

impl BlobKind for AttestationWitnessBytes {
    const NAME: &'static str = "attestation_witness";

    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.is_empty() {
            return Err("an empty witness is no row, never an empty row");
        }
        if bytes.len() > MAX_ATTESTATION_WITNESS_BYTES {
            return Err("attestation witness exceeds MAX_ATTESTATION_WITNESS_BYTES");
        }
        Ok(())
    }
}
