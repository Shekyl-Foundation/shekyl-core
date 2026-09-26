// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One read body for the archival tables (DRS-E1 S-ARCH,
//! `DRS_E1_SARCH.md` §3), the fifth sibling of `chain_reads`,
//! `output_reads`, `tx_reads` and `curve_reads`. Eighteen C++ methods become
//! nine reads (`DRS_E1_SARCH.md` §3.2; A2 travels with E4, `SAR-Q7`):
//!
//! - **A1** [`bond_record`] — `archival_bond[p]`, the persisted record, one
//!   read where the C++ had four over the same row (SAR-1).
//! - **A3** [`last_served_epoch`] — the latest epoch with a pass bit for
//!   `(p, shard)`, one reverse seek.
//! - **A4** [`served_shards`] — every shard `p` ever served, each with its
//!   latest epoch: the persona-prefix hop scan.
//! - **A5** [`pass_count`] — rows under the pair-epoch prefix (`PC-D5`).
//! - **A6–A8** [`r_market`], [`sigma_work`], [`budget`] — the three
//!   close-row scalars, `Option` where the C++ returned `0` for "no row"
//!   (SAR-8).
//! - **A9** [`last_settled_slash_epoch`] — the `properties` cell, `Option`
//!   where the C++ returned `u64::MAX`.
//! - **A10** [`attestation_witness_at`] — a recorded block's witness bytes,
//!   with the two absences the C++ collapsed into one empty blob told apart.
//!
//! # Absence, stated once (`DRS_E1_SARCH.md` §3.3)
//!
//! - **"No bond record" is a case**, not a `false`: every caller branches
//!   on it (a bond post that finds a record is an update; one that finds
//!   none is a join). [`Option`].
//! - **"Never served" is a case** (A3 `None`, A4 empty): the release
//!   cooldown's vacuous arm. The C++ marshal *omitted* never-served shards
//!   from a positional vector (SAR-3); here the absence is typed per shard.
//! - **"No close row" is a case the C++ conflated with zero** (A6, A7): a
//!   closed epoch with zero co-holders is a written `RMarket(0)`; an epoch
//!   that never closed is `None`. The read stops erasing the distinction;
//!   what a rule does with `None` is E6 slice 8's (`SAR-Q6`). A8 is the one
//!   place the C++ kept them apart (`has_budget_row`) and is unchanged in
//!   meaning.
//! - **`u64::MAX` as "none"** (A9) — gone by the type.
//! - **An empty witness and an unrecorded height** (A10) — the writer stores
//!   no row for an empty attestation set, so a recorded block with no row
//!   is `Recorded(None)`; a height past the tip is `AboveTip`. What a
//!   *pruned* height reads as is S-PRUNE's to say when it deletes anything
//!   here; until a prune exists the two states are exhaustive.
//!
//! # SI-15 is armed here
//!
//! Every serve-credit row names a persona with a bond record (the connect
//! hook refuses a pass bit for an unknown persona, CEN-L7). A3–A5 have the
//! persona in hand and walk its rows; a walk that finds rows for a persona
//! with no record is [`StoreInvariant::ServeCreditWithoutBond`]. The check
//! runs only when rows were found — an empty walk asserts nothing, so a
//! never-served persona with no record (a query about a stranger) is an
//! answer, not a fault.
//!
//! # What is not here
//!
//! No fold. `good_through` is `shekyl-archival-retention`'s and already
//! takes the record's parts; `holds_shard_at` joins it with E4 and the slash
//! log (A2). No composed "emission source" read (`SAR-Q4`): the rule that
//! needs A1 + A5 + A7 + A8 composes them at its call site.

use redb::ReadableTable;
use shekyl_chain_rules::AtHeight;
use shekyl_store_codec::{BlobKind, CodecError};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::codec::{AttestationWitnessBytes, BondRecord, RMarket, SigmaWorkMilli};
use crate::ids::ServeCreditKey;
use crate::schema::{
    ARCHIVAL_ATTESTATION_WITNESS, ARCHIVAL_BOND, ARCHIVAL_BUDGET, ARCHIVAL_R_MARKET,
    ARCHIVAL_SERVE_CREDIT, ARCHIVAL_SIGMA_WORK,
};

use super::chain_reads::{self, undecodable, ReadFault, ReadTables};
use super::error::StoreInvariant;

/// The `archival_bond` cell as faults name it.
const BOND: &str = "archival_bond";
/// The `archival_r_market` cell as faults name it.
const R_MARKET: &str = "archival_r_market";
/// The `archival_sigma_work` cell as faults name it.
const SIGMA_WORK: &str = "archival_sigma_work";
/// The `archival_budget` cell as faults name it.
const BUDGET: &str = "archival_budget";
/// The `archival_attestation_witness` cell as faults name it.
const WITNESS: &str = "archival_attestation_witness";

/// How many pass bits a `(persona, shard, epoch)` recorded — `PC-D5`'s
/// enumeration over the pair-epoch prefix. `u32` in the C++ (`PC-D5`'s
/// bound); the newtype keeps it from being added to an epoch. Admission
/// collapsed it to `> 0` while the beacon issued one challenge; the
/// settlement writer and the assignment cutover's count bound consume the
/// number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PassCount(u32);

impl PassCount {
    /// No pass bits.
    pub const ZERO: Self = Self(0);

    /// The count.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        self.0
    }

    /// Whether any pass was recorded — the admission arm's question.
    #[must_use]
    pub const fn any(self) -> bool {
        self.0 > 0
    }
}

/// A served shard and the latest settlement epoch it earned a pass bit in
/// — one row of A4's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedShard {
    /// Which shard.
    pub shard: ShardId,
    /// The latest epoch with a pass bit for it.
    pub last_served: SettlementEpoch,
}

/// **A1.** `archival_bond[p]`, decoded. `None` is "no bond record for `p`";
/// a row that does not decode is SI-7 (which is also SI-14's arm: a record
/// whose holdings name a shard twice fails `BondRecord::decode`).
pub(super) fn bond_record<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
) -> Result<Option<BondRecord>, ReadFault> {
    chain_reads::cell(txn, ARCHIVAL_BOND, *persona.as_bytes(), BOND)
}

/// Whether `persona` has a bond record — SI-15's precondition, read without
/// decoding the row.
fn has_bond<T: ReadTables>(txn: &T, persona: &PCanonicalId) -> Result<bool, ReadFault> {
    Ok(txn
        .table(ARCHIVAL_BOND)?
        .get(*persona.as_bytes())?
        .is_some())
}

/// SI-15: rows were found under `persona`'s prefix; the persona must have a
/// record. Called only after a walk found at least one row.
fn serve_credit_rows_have_a_bond<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
) -> Result<(), ReadFault> {
    if has_bond(txn, persona)? {
        Ok(())
    } else {
        Err(ReadFault::Invariant(
            StoreInvariant::ServeCreditWithoutBond { persona: *persona },
        ))
    }
}

/// **A3.** The latest settlement epoch with a pass bit for `(persona,
/// shard)` — the last key of the `(P, s)` prefix, one reverse seek
/// (`db_lmdb.cpp:6464`'s ceiling probe as a range's last element). `None`
/// is never-served, the cooldown's vacuous arm.
pub(super) fn last_served_epoch<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
    shard: ShardId,
) -> Result<Option<SettlementEpoch>, ReadFault> {
    let table = txn.table(ARCHIVAL_SERVE_CREDIT)?;
    let mut range = table.range(ServeCreditKey::shard_range(*persona, shard))?;
    let Some(last) = range.next_back() else {
        return Ok(None);
    };
    let (key, _present) = last?;
    serve_credit_rows_have_a_bond(txn, persona)?;
    Ok(Some(ServeCreditKey::from_key(key.value()).epoch()))
}

/// **A4.** Every shard `persona` ever earned a pass bit for, each with its
/// latest epoch — the `P`-prefix hop scan (`db_lmdb.cpp:6546`): seek to the
/// persona's first row, take its shard, jump to that shard's last row, step
/// past it; one reverse seek per served shard, never a walk of every row.
/// Empty for a persona that never served. The complete-tree form of the
/// last-served marshal: such a record stores no shard list, so the served
/// set is the only list there is.
pub(super) fn served_shards<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
) -> Result<Vec<ServedShard>, ReadFault> {
    let table = txn.table(ARCHIVAL_SERVE_CREDIT)?;
    let persona_hi = *ServeCreditKey::persona_range(*persona).end();
    let mut out = Vec::new();
    // Seek to the persona's first row; then, per shard found, take that
    // shard's last row and seek to the first key of the next shard. A gap
    // between shard ids is one `range.next()`, not a walk of the gap.
    let mut from = *ServeCreditKey::persona_range(*persona).start();
    loop {
        let Some(row) = table.range(from..=persona_hi)?.next() else {
            break;
        };
        let shard = ServeCreditKey::from_key(row?.0.value()).shard();
        let last = table
            .range(ServeCreditKey::shard_range(*persona, shard))?
            .next_back()
            .expect("the shard's first row is inside its own range")?;
        out.push(ServedShard {
            shard,
            last_served: ServeCreditKey::from_key(last.0.value()).epoch(),
        });
        // No successor shard id: this shard is the persona's last possible.
        let Some(next_shard) = shard.to_raw().checked_add(1) else {
            break;
        };
        from = ServeCreditKey::new(
            *persona,
            ShardId::from_raw(next_shard),
            SettlementEpoch::ZERO,
            BlockHeight::ZERO,
        )
        .key();
    }
    if !out.is_empty() {
        serve_credit_rows_have_a_bond(txn, persona)?;
    }
    Ok(out)
}

/// **A5.** Pass bits recorded for `(persona, shard, epoch)` — the rows under
/// the pair-epoch prefix, counted (`db_lmdb.cpp:4695`). [`PassCount::ZERO`]
/// when none.
pub(super) fn pass_count<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
    shard: ShardId,
    epoch: SettlementEpoch,
) -> Result<PassCount, ReadFault> {
    let table = txn.table(ARCHIVAL_SERVE_CREDIT)?;
    let mut count: u32 = 0;
    for row in table.range(ServeCreditKey::pair_epoch_range(*persona, shard, epoch))? {
        row?;
        count = count
            .checked_add(1)
            .expect("PC-D5 bounds pass bits per pair-epoch far below u32::MAX");
    }
    if count > 0 {
        serve_credit_rows_have_a_bond(txn, persona)?;
    }
    Ok(PassCount(count))
}

/// **A6.** `archival_r_market[(shard, epoch)]`. `None` is an epoch that never
/// closed for this shard; a written `RMarket(0)` is a closed epoch with no
/// co-holders (SAR-8 — the C++ returned `0` for both).
pub(super) fn r_market<T: ReadTables>(
    txn: &T,
    shard: ShardId,
    epoch: SettlementEpoch,
) -> Result<Option<RMarket>, ReadFault> {
    chain_reads::cell(
        txn,
        ARCHIVAL_R_MARKET,
        (shard.to_raw(), epoch.to_raw()),
        R_MARKET,
    )
}

/// **A7.** `archival_sigma_work[epoch]` — the frozen `Σwork(E)`. `None` is an
/// epoch that never closed (SAR-8).
pub(super) fn sigma_work<T: ReadTables>(
    txn: &T,
    epoch: SettlementEpoch,
) -> Result<Option<SigmaWorkMilli>, ReadFault> {
    chain_reads::cell(txn, ARCHIVAL_SIGMA_WORK, epoch.to_raw(), SIGMA_WORK)
}

/// **A8.** `archival_budget[epoch]` — the frozen `budget(E)` close row. The
/// one gather leg the C++ already kept absent and zero apart
/// (`has_budget_row`); `None` is an epoch that never closed.
pub(super) fn budget<T: ReadTables>(
    txn: &T,
    epoch: SettlementEpoch,
) -> Result<Option<AtomicUnits>, ReadFault> {
    chain_reads::cell(txn, ARCHIVAL_BUDGET, epoch.to_raw(), BUDGET)
}

/// **A10.** A recorded block's attestation witness bytes. `AboveTip` for a
/// height the chain has not reached; `Recorded(None)` for a recorded block
/// whose attestation set was empty (the writer stores no row for it);
/// `Recorded(Some(bytes))` for a row [`AttestationWitnessBytes`] accepts
/// (non-empty, within [`MAX_ATTESTATION_WITNESS_BYTES`](shekyl_types::archival::MAX_ATTESTATION_WITNESS_BYTES)).
/// An empty or over-cap row is SI-7. The store does not parse the witness
/// (`shekyl-archival-retention::attestation_wire` does).
pub(super) fn attestation_witness_at<T: ReadTables>(
    txn: &T,
    height: BlockHeight,
) -> Result<AtHeight<Option<Vec<u8>>>, ReadFault> {
    let h = height.to_raw();
    match chain_reads::tip_of(txn)? {
        Some((tip, _)) if h <= tip => {}
        _ => return Ok(AtHeight::AboveTip),
    }
    let table = txn.table(ARCHIVAL_ATTESTATION_WITNESS)?;
    let Some(guard) = table.get(h)? else {
        return Ok(AtHeight::Recorded(None));
    };
    let bytes = guard.value().bytes();
    // `Blob::bytes` does not run the kind's check. An empty row is the
    // absence this read already spells as `Recorded(None)`; a present empty
    // or over-cap row is a value the writer is not allowed to store.
    AttestationWitnessBytes::well_formed(bytes).map_err(|reason| {
        undecodable(
            WITNESS,
            CodecError::Invalid {
                codec: AttestationWitnessBytes::NAME,
                reason,
            },
        )
    })?;
    Ok(AtHeight::Recorded(Some(bytes.to_vec())))
}
