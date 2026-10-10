// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One read body for the archival tables (DRS-E1 S-ARCH,
//! `DRS_E1_SARCH.md` §3), the fifth sibling of `chain_reads`,
//! `output_reads`, `tx_reads` and `curve_reads`. Eighteen C++ methods become
//! ten reads (`DRS_E1_SARCH.md` §3.2; A2 landed with DRS-E4 commit 2, the
//! `SAR-Q7` staged pair):
//!
//! - **A1** [`bond_record`] — `archival_bond[p]`, the persisted record, one
//!   read where the C++ had four over the same row (SAR-1).
//! - **A2** [`slash_log_after`] — every slash logged against `p` at a height
//!   strictly above `h`: the history half of the as-of-height holdings
//!   question, whose fold is `shekyl-archival-retention::holds_shard_at`.
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
//! The transition's own reads (DRS-E4 commit 4; `DRS_E4_ARCHIVAL_WRITER.md`
//! §3.2 phase 9) — over every record, or over a table only the scan reads:
//!
//! - **A11** [`bond_records`] — every record in persona-key order, the slash
//!   scan's and the close's universe.
//! - **A12** [`slash_applied`] — the `(P, shard, E)` set membership the scan
//!   dedups on.
//! - **A13** [`budget_accruing`] — the open epoch's running staker inflow
//!   (SI-23), the accrual's pre-image and the close's operand.
//!
//! Settlement's reads (`ARCHIVAL_SETTLEMENT_WRITER.md` §14, `SO-D10`):
//!
//! - **A14** [`settlement_row`] — what an epoch settled for a pair; absent
//!   is "no draw issued, or not settled yet", never a miss.
//! - **A15** [`issued_draws`] — one epoch's issued-draw index, whole, in
//!   `(P, shard, h, j)` order.
//! - **A16** [`issued_digest`] — the running digest that index is checked
//!   against.
//! - **A17** [`served_at`] — the shards a persona's rows say were Served in
//!   an epoch: what the emission gather credits (`SO-D11`).
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
//! No fold. `good_through` and `holds_shard_at` are
//! `shekyl-archival-retention`'s and take the record's parts — the second
//! takes A2's rows beside A1's record (CEN-L16: the as-of-height holdings
//! question is a fold over recorded state, not a read the store composes).
//! No composed "emission source" read (`SAR-Q4`): the rule that needs
//! A1 + A5 + A7 + A8 composes them at its call site.

use redb::ReadableTable;
use shekyl_chain_rules::AtHeight;
use shekyl_store_codec::{BlobKind, CodecError};
use shekyl_types::archival::SettlementOutcome;
pub use shekyl_types::archival::{
    IndexedDraw, IssuedDigest, PassCount, ServedShard, SettlementRow,
};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::archival_snapshot::{ArchivalSnapshot, SnapshotFamily, SnapshotFault};
use crate::codec::{AttestationWitnessBytes, BondRecord, RMarket, SigmaWorkMilli, SlashLogEntry};
use crate::ids::{IssuedDrawKey, ServeCreditKey, SettlementKey, SlashAppliedKey, SlashLogKey};
use crate::schema::{
    ARCHIVAL_ATTESTATION_WITNESS, ARCHIVAL_BOND, ARCHIVAL_BUDGET, ARCHIVAL_BUDGET_ACCRUING,
    ARCHIVAL_ISSUED_DIGEST, ARCHIVAL_ISSUED_DRAW, ARCHIVAL_R_MARKET, ARCHIVAL_SERVE_CREDIT,
    ARCHIVAL_SETTLEMENT, ARCHIVAL_SIGMA_WORK, ARCHIVAL_SLASH_APPLIED, ARCHIVAL_SLASH_LOG,
};

use super::chain_reads::{self, undecodable, ReadFault, ReadTables};
use super::error::StoreInvariant;
use super::invariant::AccrualFault;

/// The `archival_bond` cell as faults name it.
const BOND: &str = "archival_bond";
/// The `archival_slash_log` cell as faults name it.
const SLASH_LOG: &str = "archival_slash_log";
/// The `archival_r_market` cell as faults name it.
const R_MARKET: &str = "archival_r_market";
/// The `archival_sigma_work` cell as faults name it.
const SIGMA_WORK: &str = "archival_sigma_work";
/// The `archival_budget` cell as faults name it.
const BUDGET: &str = "archival_budget";
/// The `archival_budget_accruing` cell as faults name it.
const BUDGET_ACCRUING: &str = "archival_budget_accruing";
/// The `archival_settlement` cell as faults name it.
const SETTLEMENT: &str = "archival_settlement";
/// The `archival_issued_draw` cell as faults name it.
const ISSUED_DRAW: &str = "archival_issued_draw";
/// The `archival_issued_digest` cell as faults name it.
const ISSUED_DIGEST: &str = "archival_issued_digest";
/// The `archival_attestation_witness` cell as faults name it.
const WITNESS: &str = "archival_attestation_witness";

/// **A1.** `archival_bond[p]`, decoded. `None` is "no bond record for `p`";
/// a row that does not decode is SI-7 (which is also SI-14's arm: a record
/// whose holdings name a shard twice fails `BondRecord::decode`).
pub(super) fn bond_record<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
) -> Result<Option<BondRecord>, ReadFault> {
    chain_reads::cell(txn, ARCHIVAL_BOND, *persona.as_bytes(), BOND)
}

/// **A2.** Every slash logged against `persona` at a height **strictly
/// above** `height`, in log order — the rows `holds_shard_at` folds over
/// the record to answer whether a shard was held *as of* `height`
/// (`db_lmdb.cpp:4804`'s `archival_slash_removed_holding_after`, minus the
/// fold, which is the retention crate's; CEN-L16). The log is keyed by
/// height then sequence and holds every persona's slashes, so the walk is
/// one range from `(height + 1, 0)` filtered to `persona`; the C++ walked
/// the same range and skipped its epoch-marker rows, which the log no
/// longer has (`ARW-Q2`). Empty when nothing above `height` names
/// `persona` — including when `height` is the last height, where
/// [`SlashLogKey::above`] has no range to give (no height lies above it),
/// so the C++'s `u64::MAX` early-return is the key type's `None` and not a
/// case here. A row that does not decode is SI-7.
pub(super) fn slash_log_after<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
    height: BlockHeight,
) -> Result<Vec<SlashLogEntry>, ReadFault> {
    let Some(above) = SlashLogKey::above(height) else {
        return Ok(Vec::new());
    };
    let table = txn.table(ARCHIVAL_SLASH_LOG)?;
    let mut out = Vec::new();
    for row in table.range(above)? {
        let (_key, value) = row?;
        let entry = value
            .value()
            .decode()
            .map_err(|cause| undecodable(SLASH_LOG, cause))?;
        if entry.persona == *persona {
            out.push(entry);
        }
    }
    Ok(out)
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
    Ok(PassCount::from_raw(count))
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

/// **A11.** Every `archival_bond` row, decoded, in key order — the redb
/// B-tree's order over the 32-byte persona, which is the LMDB comparator's
/// order over the same bytes, so the scan applies slashes in the order the
/// C++ cursor did. A row that does not decode is SI-7 (SI-14's arm too).
pub(super) fn bond_records<T: ReadTables>(
    txn: &T,
) -> Result<Vec<(PCanonicalId, BondRecord)>, ReadFault> {
    let table = txn.table(ARCHIVAL_BOND)?;
    let mut out = Vec::new();
    for row in table.iter()? {
        let (key, value) = row?;
        let record = value
            .value()
            .decode()
            .map_err(|cause| undecodable(BOND, cause))?;
        out.push((PCanonicalId::from_bytes(key.value()), record));
    }
    Ok(out)
}

/// **A12.** Whether `archival_slash_applied` holds `(persona, shard,
/// epoch)`. A set table ([`Present`](crate::schema::Present)): the row's
/// existence is the whole fact, so there is nothing to decode and nothing
/// to be `Option` about.
pub(super) fn slash_applied<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
    shard: ShardId,
    epoch: SettlementEpoch,
) -> Result<bool, ReadFault> {
    Ok(txn
        .table(ARCHIVAL_SLASH_APPLIED)?
        .get(SlashAppliedKey::new(*persona, shard, epoch).key())?
        .is_some())
}

/// **A13.** `archival_budget_accruing[epoch]` — the staker inflow accrued
/// so far in an **open** epoch. `None` before the epoch's first accrual and
/// after its close deleted the row (SI-23: the table holds at most the open
/// epoch's row). A row that does not decode is SI-7.
pub(super) fn budget_accruing<T: ReadTables>(
    txn: &T,
    epoch: SettlementEpoch,
) -> Result<Option<AtomicUnits>, ReadFault> {
    chain_reads::cell(
        txn,
        ARCHIVAL_BUDGET_ACCRUING,
        epoch.to_raw(),
        BUDGET_ACCRUING,
    )
}

/// **A14.** `archival_settlement[(persona, shard, epoch)]` — what the epoch
/// settled for the pair. `None` is a pair no draw was issued to in that
/// epoch, or an epoch not settled yet: never a miss. A row that does not
/// decode — an outcome its own counts do not give among them — is SI-7.
pub(super) fn settlement_row<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
    shard: ShardId,
    epoch: SettlementEpoch,
) -> Result<Option<SettlementRow>, ReadFault> {
    chain_reads::cell(
        txn,
        ARCHIVAL_SETTLEMENT,
        SettlementKey::new(*persona, shard, epoch).key(),
        SETTLEMENT,
    )
}

/// **A15.** Every draw issued in `epoch`, in `(P, shard, h, j)` order: one
/// range of `archival_issued_draw`. Empty for an epoch no draw was issued
/// in. A row that does not decode is SI-7.
pub(super) fn issued_draws<T: ReadTables>(
    txn: &T,
    epoch: SettlementEpoch,
) -> Result<Vec<IndexedDraw>, ReadFault> {
    let table = txn.table(ARCHIVAL_ISSUED_DRAW)?;
    let mut out = Vec::new();
    for row in table.range(IssuedDrawKey::epoch(epoch))? {
        let (key, value) = row?;
        let key = IssuedDrawKey::from_key(key.value());
        let state = value
            .value()
            .decode()
            .map_err(|cause| undecodable(ISSUED_DRAW, cause))?;
        out.push(IndexedDraw {
            persona: *key.persona(),
            shard: key.shard(),
            issuing_height: key.issuing_height(),
            draw: key.draw(),
            state,
        });
    }
    Ok(out)
}

/// **A16.** `archival_issued_digest[epoch]` — the running digest of the
/// draws issued in `epoch`. An epoch with no row has had no draw folded,
/// which is [`IssuedDigest::ZERO`]: the digest of no draws, not a hole.
pub(super) fn issued_digest<T: ReadTables>(
    txn: &T,
    epoch: SettlementEpoch,
) -> Result<IssuedDigest, ReadFault> {
    chain_reads::cell(txn, ARCHIVAL_ISSUED_DIGEST, epoch.to_raw(), ISSUED_DIGEST)
        .map(Option::unwrap_or_default)
}

/// **A17.** The shards `persona`'s settlement rows for `epoch` say were
/// Served, ascending. The table is keyed `(P, shard, E)` (`SO-D2`), so this
/// walks the persona's rows and keeps the epoch's: one range, bounded by
/// the persona's shards times the epochs the table retains. A row that
/// does not decode is SI-7.
pub(super) fn served_at<T: ReadTables>(
    txn: &T,
    persona: &PCanonicalId,
    epoch: SettlementEpoch,
) -> Result<Vec<ShardId>, ReadFault> {
    let table = txn.table(ARCHIVAL_SETTLEMENT)?;
    let p = persona.to_bytes();
    let mut out = Vec::new();
    for row in table.range((p, 0, 0)..=(p, u64::MAX, u64::MAX))? {
        let (key, value) = row?;
        let (_, shard, e) = key.value();
        if e != epoch.to_raw() {
            continue;
        }
        let settled: SettlementRow = value
            .value()
            .decode()
            .map_err(|cause| undecodable(SETTLEMENT, cause))?;
        if settled.outcome() == SettlementOutcome::Served {
            out.push(ShardId::from_raw(shard));
        }
    }
    Ok(out)
}

/// The nine table-backed families of the archival snapshot
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.8.1), walked whole and re-encoded
/// through [`ArchivalSnapshot`]'s typed constructors — the same encoding the
/// C++ walker's marshalled fields go through, so a stored row that decodes
/// is compared as the value it decodes to, and a stored row that does not
/// decode is SI-7 here rather than a byte-level mismatch at the grader.
/// The tenth family, the slash watermark, is a `properties` cell and is
/// added by the caller ([`ReadSnapshot::archival_snapshot`](super::ReadSnapshot::archival_snapshot)).
///
/// Two of the constructors' refusals are reachable from a store and are
/// invariants, not snapshot faults: a second `archival_budget_accruing` row
/// is SI-23 ([`StoreInvariant::AccruingNotSingular`]); an empty or over-cap
/// witness row is SI-7, as in A10. The others (a duplicate key, a key of
/// the wrong width, a slash-log epoch marker) cannot arise from typed
/// tables with unique keys and a log the writer never marks; they are
/// mapped to SI-7 against the family so a reader is never left without a
/// name for what happened.
pub(super) fn snapshot_rows<T: ReadTables>(txn: &T) -> Result<ArchivalSnapshot, ReadFault> {
    let mut snapshot = ArchivalSnapshot::empty();

    for row in txn.table(ARCHIVAL_BOND)?.iter()? {
        let (key, value) = row?;
        let record = value
            .value()
            .decode()
            .map_err(|cause| undecodable(BOND, cause))?;
        snapshot
            .push_bond(&PCanonicalId::from_bytes(key.value()), &record)
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_SERVE_CREDIT)?.iter()? {
        let (key, _present) = row?;
        let key = ServeCreditKey::from_key(key.value());
        snapshot
            .push_serve_credit(key.persona(), key.shard(), key.epoch(), key.height())
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_R_MARKET)?.iter()? {
        let (key, value) = row?;
        let (shard, epoch) = key.value();
        let r = value
            .value()
            .decode()
            .map_err(|cause| undecodable(R_MARKET, cause))?;
        // `push_r_market` drops a zero count (§3.6): the C++ close writes
        // zeros the redb close does not, and the snapshot is the non-zero set.
        snapshot
            .push_r_market(
                ShardId::from_raw(shard),
                SettlementEpoch::from_raw(epoch),
                r,
            )
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_SIGMA_WORK)?.iter()? {
        let (key, value) = row?;
        let sigma = value
            .value()
            .decode()
            .map_err(|cause| undecodable(SIGMA_WORK, cause))?;
        snapshot
            .push_sigma_work(SettlementEpoch::from_raw(key.value()), sigma)
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_BUDGET)?.iter()? {
        let (key, value) = row?;
        let budget = value
            .value()
            .decode()
            .map_err(|cause| undecodable(BUDGET, cause))?;
        snapshot
            .push_budget(SettlementEpoch::from_raw(key.value()), budget)
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_ATTESTATION_WITNESS)?.iter()? {
        let (key, value) = row?;
        let bytes = value.value().bytes();
        AttestationWitnessBytes::well_formed(bytes).map_err(|reason| {
            undecodable(
                WITNESS,
                CodecError::Invalid {
                    codec: AttestationWitnessBytes::NAME,
                    reason,
                },
            )
        })?;
        snapshot
            .push_attestation_witness(BlockHeight::from_raw(key.value()), bytes)
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_SLASH_LOG)?.iter()? {
        let (key, value) = row?;
        let key = SlashLogKey::from_key(key.value());
        let entry = value
            .value()
            .decode()
            .map_err(|cause| undecodable(SLASH_LOG, cause))?;
        snapshot
            .push_slash_log(key.height(), key.seq(), &entry)
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_SLASH_APPLIED)?.iter()? {
        let (key, _present) = row?;
        let key = SlashAppliedKey::from_key(key.value());
        snapshot
            .push_slash_applied(key.persona(), key.shard(), key.epoch())
            .map_err(|f| refused(&f))?;
    }
    for row in txn.table(ARCHIVAL_BUDGET_ACCRUING)?.iter()? {
        let (key, value) = row?;
        let epoch = SettlementEpoch::from_raw(key.value());
        let total = value
            .value()
            .decode()
            .map_err(|cause| undecodable(BUDGET_ACCRUING, cause))?;
        snapshot
            .set_budget_accruing(epoch, total)
            .map_err(|fault| match fault {
                SnapshotFault::SecondSingletonRow { .. } => {
                    ReadFault::Invariant(StoreInvariant::AccruingNotSingular {
                        observed: AccrualFault::StaleRow { epoch },
                    })
                }
                other => refused(&other),
            })?;
    }
    Ok(snapshot)
}

/// A snapshot constructor's refusal of a row read from a typed table, as
/// SI-7 against the family — see [`snapshot_rows`] for why these arms are
/// not expected to fire.
fn refused(fault: &SnapshotFault) -> ReadFault {
    let family = match fault {
        SnapshotFault::KeyWidth { family, .. }
        | SnapshotFault::ValueWidth { family, .. }
        | SnapshotFault::DuplicateKey { family, .. }
        | SnapshotFault::SecondSingletonRow { family }
        | SnapshotFault::RowTooLong { family, .. }
        | SnapshotFault::RowTooShort { family, .. } => family.name(),
        SnapshotFault::EpochMarkerSeq { .. } => SnapshotFamily::SlashLog.name(),
        SnapshotFault::WitnessShape { .. } => SnapshotFamily::AttestationWitness.name(),
        SnapshotFault::Truncated | SnapshotFault::Io(_) => "archival_snapshot",
    };
    undecodable(
        family,
        CodecError::Invalid {
            codec: family,
            reason: "the archival snapshot refused a stored row",
        },
    )
}
