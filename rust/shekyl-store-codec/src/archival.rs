// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival bond record's codec and the two close-row scalars' — the
//! `Canonical` impls for `shekyl_types::archival::{BondRecord, RMarket,
//! SigmaWorkMilli}` (DRS-E1 S-ARCH `SAR-Q3`; moved here from the daemon
//! store with the types by DRS-E4 `ARW-Q8`, 2026-09-29: the types live in
//! the vocabulary crate, so an impl of this crate's trait for them lives
//! here). **The bytes did not move** — `bond_record.snap`, `r_market.snap`
//! and `sigma_work_milli.snap` in the daemon store pin them unchanged.
//!
//! # The bond record is re-specified, not ported (`SAR-Q3`)
//!
//! `ArchivalBondValue` v7 (`src/blockchain_db/shekyl_types.h`) is a 350-line
//! hand codec with a `holdings_kind` byte and two index-parallel vectors
//! whose equal length the encoder throws on and the decoder assumes. The
//! ruling: **same semantics, not byte-compatible** — the field set and the
//! genesis-frozen caps are the C++'s; the encoding is this codec's own, and
//! nothing hashes or relays the stored record (the wire record is
//! `bond_wire.rs`'s, a different object). Every count is bounded **before**
//! it sizes an allocation, by the cap the consensus constant names
//! (`MAX_HOLDINGS_SHARDS`, `MAX_BOND_BAD_INTERVALS`,
//! `MAX_CLAIMED_EPOCH_ENTRIES`) and by the bytes that remain.
//!
//! # Layout
//!
//! All integers little-endian; counts and lengths `u32`.
//!
//! ```text
//! hybrid_pubkey        u32 len ‖ bytes            len ≤ MAX_BOND_KEY_BYTES
//! bond_spend_pk        u32 len ‖ bytes            len ≤ MAX_BOND_KEY_BYTES
//! endpoint             [u8; 32]
//! join_settlement_epoch u64
//! bonded_total         u64                         atomic units
//! holdings             u8 kind
//!                      kind 0: u32 n ‖ (u64 shard ‖ u64 add_epoch) × n   n ≤ MAX_HOLDINGS_SHARDS
//!                      kind 1: nothing
//! bad_intervals        u32 n ‖ (u64 start ‖ u64 end_exclusive) × n      n ≤ MAX_BOND_BAD_INTERVALS
//! claimed_epochs       u32 n ‖ u64 × n, strictly increasing,             n ≤ MAX_CLAIMED_EPOCH_ENTRIES,
//!                      last − first ≤ MAX_CLAIM_AGE_W_EPOCHS
//! first_paying_height  u8 present ‖ (u64 height if present)
//! ```
//!
//! # The v7 cross-check (ruled on PR #840)
//!
//! A round trip of this codec against itself proves it self-consistent, not
//! that it is the same record. `docs/test_vectors/ARCHIVAL_BOND_RECORD_V7.json`
//! holds real `ArchivalBondValue` v7 blobs with the fields the **C++
//! decoder** read from them; the daemon store's `codec::archival_tests`
//! builds a `BondRecord` from each field set and asserts nothing is lost.

use shekyl_types::archival::{
    BadInterval, BondRecord, FirstPayingHeight, HeldShard, Holdings, HoldingsError, HoldingsKind,
    IssuedDigest, IssuedDraw, RMarket, SettlementRow, SettlementRowError, SigmaWorkMilli,
    SlashLogEntry, SlashedHolding, ISSUED_DIGEST_LEN, MAX_BOND_BAD_INTERVALS, MAX_BOND_KEY_BYTES,
    MAX_CLAIMED_EPOCH_ENTRIES, MAX_CLAIM_AGE_W_EPOCHS, MAX_HOLDINGS_SHARDS, SETTLEMENT_ROW_LEN,
};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::reader::{put_bytes, put_count, Reader};
use crate::{Canonical, CodecError};

const HOLDINGS_COMPACT: u8 = HoldingsKind::ShardSetCompact as u8;
const HOLDINGS_COMPLETE: u8 = HoldingsKind::CompleteTree as u8;

impl Canonical for BondRecord {
    const NAME: &'static str = "bond_record";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_bytes(out, &self.hybrid_pubkey);
        put_bytes(out, &self.bond_spend_pk);
        out.extend_from_slice(&self.endpoint);
        out.extend_from_slice(&self.join_settlement_epoch.to_raw().to_le_bytes());
        out.extend_from_slice(&self.bonded_total.to_raw().to_le_bytes());
        match &self.holdings {
            Holdings::CompleteTree => out.push(HOLDINGS_COMPLETE),
            Holdings::ShardSet(held) => {
                out.push(HOLDINGS_COMPACT);
                put_count(out, held.len());
                for h in held.iter() {
                    out.extend_from_slice(&h.shard.to_raw().to_le_bytes());
                    out.extend_from_slice(&h.add_epoch.to_raw().to_le_bytes());
                }
            }
        }
        put_count(out, self.bad_intervals.len());
        for iv in &self.bad_intervals {
            out.extend_from_slice(&iv.start_epoch.to_le_bytes());
            out.extend_from_slice(&iv.end_exclusive.to_le_bytes());
        }
        put_count(out, self.claimed_settlement_epochs.len());
        for e in &self.claimed_settlement_epochs {
            out.extend_from_slice(&e.to_raw().to_le_bytes());
        }
        match self.first_paying_emission_height {
            None => out.push(0),
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_raw().to_le_bytes());
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let hybrid_pubkey = r
            .bytes_bounded(
                MAX_BOND_KEY_BYTES,
                "hybrid_pubkey exceeds MAX_BOND_KEY_BYTES",
            )?
            .to_vec();
        let bond_spend_pk = r
            .bytes_bounded(
                MAX_BOND_KEY_BYTES,
                "bond_spend_pk exceeds MAX_BOND_KEY_BYTES",
            )?
            .to_vec();
        let endpoint = r.array::<32>("buffer ends inside the endpoint")?;
        let join_settlement_epoch = SettlementEpoch::from_raw(r.u64()?);
        let bonded_total = AtomicUnits::from_raw(r.u64()?);
        let holdings = match r.u8()? {
            HOLDINGS_COMPLETE => Holdings::CompleteTree,
            HOLDINGS_COMPACT => {
                let n = r.count_bounded(
                    16,
                    MAX_HOLDINGS_SHARDS,
                    "held-shard count exceeds MAX_HOLDINGS_SHARDS",
                )?;
                let mut held = Vec::with_capacity(n);
                for _ in 0..n {
                    held.push(HeldShard {
                        shard: ShardId::from_raw(r.u64()?),
                        add_epoch: SettlementEpoch::from_raw(r.u64()?),
                    });
                }
                Holdings::shard_set(held).map_err(|e| {
                    r.invalid(match e {
                        HoldingsError::CountExceeded { .. } => "unreachable: count was bounded",
                        HoldingsError::Duplicate { .. } => "a shard is held twice",
                    })
                })?
            }
            _ => return Err(r.invalid("holdings kind byte names neither shape")),
        };
        let n = r.count_bounded(
            16,
            MAX_BOND_BAD_INTERVALS,
            "bad-interval count exceeds MAX_BOND_BAD_INTERVALS",
        )?;
        let mut bad_intervals = Vec::with_capacity(n);
        for _ in 0..n {
            bad_intervals.push(BadInterval {
                start_epoch: r.u64()?,
                end_exclusive: r.u64()?,
            });
        }
        let n = r.count_bounded(
            8,
            MAX_CLAIMED_EPOCH_ENTRIES,
            "claimed-epoch count exceeds MAX_CLAIMED_EPOCH_ENTRIES",
        )?;
        let mut claimed_settlement_epochs = Vec::with_capacity(n);
        for _ in 0..n {
            let e = SettlementEpoch::from_raw(r.u64()?);
            if let Some(prev) = claimed_settlement_epochs.last() {
                if e <= *prev {
                    return Err(r.invalid("claimed epochs are not strictly increasing"));
                }
            }
            claimed_settlement_epochs.push(e);
        }
        // The at-rest span rule the C++ record enforces (`claimed_epochs_well_formed`):
        // an emission claims at most `W` epochs back, so the set spans at most `W`.
        if let (Some(first), Some(last)) = (
            claimed_settlement_epochs.first(),
            claimed_settlement_epochs.last(),
        ) {
            if last.to_raw() - first.to_raw() > MAX_CLAIM_AGE_W_EPOCHS {
                return Err(r.invalid("claimed epochs span more than the claim window W"));
            }
        }
        let first_paying_emission_height = match r.u8()? {
            0 => None,
            1 => {
                let height =
                    FirstPayingHeight::new(BlockHeight::from_raw(r.u64()?)).ok_or_else(|| {
                        r.invalid("first paying height 0 is the unset sentinel, not a payment")
                    })?;
                Some(height)
            }
            _ => return Err(r.invalid("first-paying-height presence byte is neither 0 nor 1")),
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the record"));
        }
        Ok(Self {
            hybrid_pubkey,
            bond_spend_pk,
            endpoint,
            join_settlement_epoch,
            bonded_total,
            holdings,
            bad_intervals,
            claimed_settlement_epochs,
            first_paying_emission_height,
        })
    }
}

impl Canonical for RMarket {
    const NAME: &'static str = "r_market";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.to_raw().encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self::from_raw)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

impl Canonical for SigmaWorkMilli {
    const NAME: &'static str = "sigma_work_milli";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.to_raw().encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self::from_raw)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

/// `archival_slash_log`'s row (DRS-E4 `ARW-Q2`). Layout, all little-endian:
///
/// ```text
/// persona   [u8; 32]
/// shard     u64
/// epoch     u64
/// holding   u8 kind: 0 = Shard ‖ u64 add_epoch;  1 = CompleteTree
/// ```
///
/// Variable width by the kind byte (57 or 49 bytes); a third kind byte or
/// trailing bytes are refused.
impl Canonical for SlashLogEntry {
    const NAME: &'static str = "slash_log_entry";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.persona.to_bytes());
        out.extend_from_slice(&self.shard.to_raw().to_le_bytes());
        out.extend_from_slice(&self.epoch.to_raw().to_le_bytes());
        match self.holding {
            SlashedHolding::Shard { add_epoch } => {
                out.push(0);
                out.extend_from_slice(&add_epoch.to_raw().to_le_bytes());
            }
            SlashedHolding::CompleteTree => out.push(1),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let persona = PCanonicalId::from_bytes(r.array::<32>("buffer ends inside the persona")?);
        let shard = ShardId::from_raw(r.u64()?);
        let epoch = SettlementEpoch::from_raw(r.u64()?);
        let holding = match r.u8()? {
            0 => SlashedHolding::Shard {
                add_epoch: SettlementEpoch::from_raw(r.u64()?),
            },
            1 => SlashedHolding::CompleteTree,
            _ => return Err(r.invalid("slashed-holding kind byte names neither shape")),
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the slash log entry"));
        }
        Ok(Self {
            persona,
            shard,
            epoch,
            holding,
        })
    }
}

/// `archival_settlement`'s row (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D2`):
///
/// ```text
/// outcome   u8    0x01 Served, 0x02 Missed, 0x03 NonObservation
/// passes    u8    passes among the counted draws
/// issued    u8    draws issued to the pair, saturated at 255
/// ```
///
/// The bytes are the type's own ([`SettlementRow::to_bytes`]). Decoding
/// re-settles the two counts and refuses a stored outcome they do not give,
/// so a row this codec returns is one the writer could have written.
impl Canonical for SettlementRow {
    const NAME: &'static str = "settlement_row";
    const FIXED_WIDTH: Option<usize> = Some(SETTLEMENT_ROW_LEN);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::from_bytes(bytes).map_err(|e| CodecError::Invalid {
            codec: Self::NAME,
            reason: match e {
                SettlementRowError::BadLength { .. } => "a settlement row is three bytes",
                SettlementRowError::UnknownOutcome { .. } => "outcome byte names no outcome",
                SettlementRowError::NothingIssued => {
                    "a row with no issued draw; such a pair has no row"
                }
                SettlementRowError::MorePassesThanCounted { .. } => {
                    "more passes than counted draws"
                }
                SettlementRowError::OutcomeDisagrees => {
                    "the stored outcome is not what the counts give"
                }
            },
        })
    }
}

/// `archival_issued_draw`'s row (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §10;
/// `SO-D10c`). Layout:
///
/// ```text
/// revealed_at   u64 LE   the block that admitted the issuing block's seed
/// passed        u8       0 = no pass record admitted, 1 = one admitted
/// ```
///
/// A third value of the flag, or trailing bytes, is refused.
impl Canonical for IssuedDraw {
    const NAME: &'static str = "issued_draw";
    const FIXED_WIDTH: Option<usize> = Some(9);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.revealed_at.to_raw().to_le_bytes());
        out.push(u8::from(self.passed));
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let revealed_at = BlockHeight::from_raw(r.u64()?);
        let passed = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(r.invalid("pass flag is neither 0 nor 1")),
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the issued draw"));
        }
        Ok(Self {
            revealed_at,
            passed,
        })
    }
}

/// `archival_issued_digest`'s row: the 32 bytes of the epoch's running sum,
/// little-endian (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §10).
impl Canonical for IssuedDigest {
    const NAME: &'static str = "issued_digest";
    const FIXED_WIDTH: Option<usize> = Some(ISSUED_DIGEST_LEN);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let digest = r.array::<ISSUED_DIGEST_LEN>("buffer ends inside the digest")?;
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the digest"));
        }
        Ok(Self::from_bytes(digest))
    }
}
