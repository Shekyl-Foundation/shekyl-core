// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival snapshot as committed data — `DRS_E4_ARCHIVAL_WRITER.md`
//! `ARW-Q15` (RULED 2026-10-01).
//!
//! A §3.8.1 [`ArchivalSnapshot`] is ten families of `(key, value)` rows,
//! every byte of which the Rust side encoded. This module writes those rows
//! as JSON and reads them back, so a snapshot the C++ LMDB unit fixture
//! walked (`write_e4_fixture_capture`, `tests/unit_tests/archival_substrate_lmdb.cpp`,
//! under `SHEKYL_E4_CAPTURE_DIR`) can be committed beside the Rust replayer
//! that must reproduce it and diffed against what the replayer produced —
//! the same [`ArchivalSnapshot::diff`] the pipeline's archival oracle runs
//! at a checkpoint, with a file in place of the trace. The committed pair is
//! `fixtures/archival_fixture_slash_m_of_n.{inputs,rows}.json`: the rows,
//! and beside them the inputs the Rust side must reproduce — personas and
//! their seeded records, the serve passes, the schedule, the chain's shape
//! and the asserted waypoints — named rather than left as whatever the C++
//! fixture happened to pass. The test at the foot of this file holds the
//! pair readable and self-consistent.
//!
//! **Nothing compares the pair with the Rust stack any more.** The replica
//! that rebuilt the fixture's state through the production stack and held
//! it against these rows was retired with the any-pass slash fold
//! (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10f`): the fixture is one slash
//! the C++ decided on the one-challenge beacon, the Rust slash pass
//! decides on settlement rows, and keeping the old fold alive to feed the
//! comparison was the wrong trade. The pair stays as the capture's record
//! and goes with the capture tooling (`DEL-008`).
//!
//! The shape is deliberately dumb: family name, then rows as hex `key` /
//! `value` pairs in the family's key order. Nothing here interprets a row.
//! A reader who wants to know what a bond row says decodes the value with
//! the codec that wrote it (`shekyl-store-codec`), not with a second JSON
//! schema of the record — one encoding per row (§3.8.1), and this is its
//! transport, not a rival.
//!
//! The ten families are always present, empty or not, in positional order:
//! a fixture with no slash rows says so with an empty `archival_slash_log`,
//! never by omission, so a family the walker forgot to cursor is a visible
//! absence rather than a silent one.

use serde::{Deserialize, Serialize};
use shekyl_chain_store::archival_snapshot::{hex, ArchivalSnapshot, SnapshotFamily, SnapshotFault};

/// The file's `schema` field: bump with any change to the shape below.
pub const ROWS_SCHEMA: &str = "shekyl_e4_archival_rows_v1";

/// The JSON document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RowsFile {
    schema: String,
    families: Vec<FamilyRows>,
}

/// One family's rows, in key order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FamilyRows {
    family: String,
    rows: Vec<Row>,
}

/// One row: lowercase hex of the key and the value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Row {
    key: String,
    value: String,
}

/// Why a rows file did not read back as a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum RowsFileFault {
    /// Not JSON, or not this document's shape.
    #[error("archival rows file: {0}")]
    Json(#[from] serde_json::Error),
    /// The `schema` field is not [`ROWS_SCHEMA`].
    #[error("archival rows file: schema {found:?}, expected {ROWS_SCHEMA:?}")]
    Schema {
        /// What the file said.
        found: String,
    },
    /// The families are not the ten §3.8.1 families in positional order.
    #[error("archival rows file: family {index} is {found:?}, expected {expected:?}")]
    Family {
        /// Position in the file.
        index: usize,
        /// What the file said; `None` when the file ran out of families.
        found: Option<String>,
        /// What §3.8.1 puts there; `None` when the file has an eleventh.
        expected: Option<&'static str>,
    },
    /// A `key` or `value` is not lowercase hex of whole bytes.
    #[error("archival rows file: {family} row {index}: {field} is not hex")]
    Hex {
        /// The family.
        family: &'static str,
        /// Row position within the family.
        index: usize,
        /// `"key"` or `"value"`.
        field: &'static str,
    },
    /// The snapshot refused the row.
    #[error("archival rows file: {0}")]
    Row(#[from] SnapshotFault),
}

/// The snapshot's rows as a pretty-printed JSON document.
#[must_use]
pub fn to_json(snapshot: &ArchivalSnapshot) -> String {
    let families = SnapshotFamily::ALL
        .iter()
        .map(|family| FamilyRows {
            family: family.name().to_owned(),
            rows: snapshot
                .rows(*family)
                .iter()
                .map(|(key, value)| Row {
                    key: hex(key),
                    value: hex(value),
                })
                .collect(),
        })
        .collect();
    let file = RowsFile {
        schema: ROWS_SCHEMA.to_owned(),
        families,
    };
    let mut out = serde_json::to_string_pretty(&file).expect("the rows file serializes");
    out.push('\n');
    out
}

/// The snapshot a rows document describes.
///
/// # Errors
///
/// [`RowsFileFault`]: the document is not this shape, names the families
/// wrongly, carries non-hex, or carries a row the snapshot refuses.
pub fn from_json(text: &str) -> Result<ArchivalSnapshot, RowsFileFault> {
    let file: RowsFile = serde_json::from_str(text)?;
    if file.schema != ROWS_SCHEMA {
        return Err(RowsFileFault::Schema { found: file.schema });
    }
    let mut out = ArchivalSnapshot::empty();
    let mut expected = SnapshotFamily::ALL.iter();
    let mut found = file.families.into_iter();
    let mut index = 0;
    loop {
        match (expected.next(), found.next()) {
            (None, None) => break,
            (Some(family), Some(rows)) if rows.family == family.name() => {
                for (i, row) in rows.rows.iter().enumerate() {
                    let key = unhex(&row.key).ok_or(RowsFileFault::Hex {
                        family: family.name(),
                        index: i,
                        field: "key",
                    })?;
                    let value = unhex(&row.value).ok_or(RowsFileFault::Hex {
                        family: family.name(),
                        index: i,
                        field: "value",
                    })?;
                    out.insert(*family, key, value)?;
                }
            }
            (family, rows) => {
                return Err(RowsFileFault::Family {
                    index,
                    found: rows.map(|r| r.family),
                    expected: family.map(|f| f.name()),
                });
            }
        }
        index += 1;
    }
    Ok(out)
}

/// Bytes from lowercase hex; `None` on an odd length or a non-hex digit.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = digit(pair[0])?;
            let lo = digit(pair[1])?;
            Some(hi << 4 | lo)
        })
        .collect()
}

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
    use shekyl_units::AtomicUnits;

    use super::*;

    fn sample() -> ArchivalSnapshot {
        let mut s = ArchivalSnapshot::empty();
        s.push_serve_credit(
            &PCanonicalId::from_bytes([7; 32]),
            ShardId::from_raw(3),
            SettlementEpoch::from_raw(1),
            BlockHeight::from_raw(900),
        )
        .expect("serve credit");
        s.push_budget(SettlementEpoch::from_raw(0), AtomicUnits::from_raw(5_000))
            .expect("budget");
        s.set_last_slash_epoch(SettlementEpoch::from_raw(1))
            .expect("watermark");
        s
    }

    #[test]
    fn rows_round_trip_through_json() {
        let s = sample();
        let text = to_json(&s);
        assert!(text.contains(ROWS_SCHEMA));
        let back = from_json(&text).expect("reads back");
        assert!(s.diff(&back).is_identical());
        assert_eq!(back.row_count(), 3);
    }

    #[test]
    fn the_empty_snapshot_names_all_ten_families() {
        let text = to_json(&ArchivalSnapshot::empty());
        for family in SnapshotFamily::ALL {
            assert!(text.contains(family.name()), "{} missing", family.name());
        }
        assert!(from_json(&text)
            .expect("reads back")
            .diff(&ArchivalSnapshot::empty())
            .is_identical());
    }

    #[test]
    fn a_misnamed_or_missing_family_is_refused() {
        let text = to_json(&sample()).replace("archival_budget", "archival_budgets");
        let fault = from_json(&text).expect_err("misnamed family");
        assert!(matches!(fault, RowsFileFault::Family { .. }), "{fault}");

        let mut file: RowsFile = serde_json::from_str(&to_json(&sample())).expect("json");
        file.families.pop();
        let text = serde_json::to_string(&file).expect("json");
        let fault = from_json(&text).expect_err("nine families");
        assert!(
            matches!(
                fault,
                RowsFileFault::Family {
                    index: 9,
                    found: None,
                    ..
                }
            ),
            "{fault}"
        );
    }

    #[test]
    fn a_wrong_schema_and_bad_hex_are_refused() {
        let text = to_json(&sample()).replace(ROWS_SCHEMA, "shekyl_e4_archival_rows_v0");
        assert!(matches!(
            from_json(&text).expect_err("schema"),
            RowsFileFault::Schema { .. }
        ));

        let mut file: RowsFile = serde_json::from_str(&to_json(&sample())).expect("json");
        file.families[SnapshotFamily::Budget as usize].rows[0].value = "zz".to_owned();
        let text = serde_json::to_string(&file).expect("json");
        assert!(matches!(
            from_json(&text).expect_err("hex"),
            RowsFileFault::Hex {
                family: "archival_budget",
                index: 0,
                field: "value"
            }
        ));
    }

    #[test]
    fn a_row_the_snapshot_refuses_is_refused_here() {
        let mut file: RowsFile = serde_json::from_str(&to_json(&sample())).expect("json");
        // A second watermark row: the family is a singleton.
        let row = file.families[SnapshotFamily::LastSlashEpoch as usize].rows[0].clone();
        let second = Row {
            key: "01".repeat(8),
            ..row
        };
        file.families[SnapshotFamily::LastSlashEpoch as usize]
            .rows
            .push(second);
        let text = serde_json::to_string(&file).expect("json");
        assert!(matches!(
            from_json(&text).expect_err("singleton"),
            RowsFileFault::Row(SnapshotFault::SecondSingletonRow { .. })
        ));
    }

    /// The committed LMDB-fixture capture (`ARW-Q15`) reads back as a
    /// snapshot, and its rows agree with the inputs file beside it on the
    /// facts the inputs name: the serve passes are the credit rows, the
    /// slash lands at the slash epoch's deadline on the named persona, the
    /// watermark is that epoch, and the accruing row is the tip's open
    /// epoch. Nothing compares the pair with the Rust writer (module
    /// docs); this is what keeps it readable and self-consistent.
    #[test]
    fn the_committed_m_of_n_capture_reads_back_and_matches_its_inputs() {
        let rows = from_json(include_str!(
            "../fixtures/archival_fixture_slash_m_of_n.rows.json"
        ))
        .expect("the committed rows read back");
        let inputs: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/archival_fixture_slash_m_of_n.inputs.json"
        ))
        .expect("the committed inputs are JSON");
        assert_eq!(inputs["schema"], "shekyl_e4_fixture_inputs_v1");

        let u64_at = |v: &serde_json::Value| v.as_u64().expect("u64");
        let le = |n: u64| n.to_le_bytes().to_vec();
        let m = u64_at(&inputs["failure_window"]["m"]);
        let seb = u64_at(&inputs["schedule"]["settlement_epoch_blocks"]);
        let slash_epoch = u64_at(&inputs["expected"]["slash_epoch"]);
        let tip = u64_at(&inputs["chain"]["tip_height"]);
        let persona = |v: &serde_json::Value| unhex(v.as_str().expect("hex")).expect("persona hex");
        let slashed = persona(&inputs["expected"]["slashed_persona"]);
        let deadline =
            u64_at(&inputs["schedule"]["slash_deadline_height_by_epoch"][slash_epoch.to_string()]);
        // The C++ keys its slash log by the block *count* after the connect
        // (`prev_height + 1`), so epoch E's row sits one above E's deadline.
        // The inputs state that operand (`ARW-26`); this test holds the rows
        // to it. The Rust writer keys the same row by the connecting height.
        // No spec named the key; `ARW-Q17` ruled it from the reader's
        // strict-above predicate: the connecting height. The C++'s count is
        // a live off-by-one against its own height-denominated reader
        // (`ARW-27`); the inputs record what the C++ wrote, and the replica
        // test pins both equations as the record of the disagreement.
        let log_height =
            u64_at(&inputs["schedule"]["slash_log_height_by_epoch"][slash_epoch.to_string()]);
        assert_eq!(
            log_height,
            deadline + 1,
            "the inputs name the C++'s count operand"
        );

        // Every serve pass the inputs name is a credit row, and nothing else is.
        let passes = inputs["serve_passes"].as_array().expect("passes");
        assert_eq!(passes.len(), usize::try_from(m).expect("m"));
        let credits = rows.rows(SnapshotFamily::ServeCredit);
        assert_eq!(credits.len(), passes.len());
        for pass in passes {
            let mut key = persona(&pass["persona"]);
            key.extend(le(u64_at(&pass["shard"])));
            key.extend(le(u64_at(&pass["epoch"])));
            key.extend(le(u64_at(&pass["height"])));
            assert!(credits.contains_key(&key), "pass {pass} has no credit row");
        }

        // One slash, at the slash epoch's deadline, on the named persona.
        let slash_log = rows.rows(SnapshotFamily::SlashLog);
        assert_eq!(slash_log.len(), 1);
        let (log_key, log_value) = slash_log.iter().next().expect("one row");
        let mut expected_key = le(log_height);
        expected_key.extend(0u32.to_le_bytes());
        assert_eq!(
            log_key, &expected_key,
            "slash log key is the C++'s fold count ‖ seq 0"
        );
        assert!(
            log_value.starts_with(&slashed),
            "slash log entry names the slashed persona"
        );
        let applied = rows.rows(SnapshotFamily::SlashApplied);
        assert_eq!(applied.len(), 1);
        assert!(applied
            .keys()
            .next()
            .expect("one row")
            .starts_with(&slashed));

        // The watermark is the slash epoch; the two bonds survive as rows.
        assert_eq!(
            rows.rows(SnapshotFamily::LastSlashEpoch)
                .keys()
                .collect::<Vec<_>>(),
            vec![&le(slash_epoch)]
        );
        assert_eq!(
            rows.rows(SnapshotFamily::Bond).len(),
            inputs["personas"].as_array().expect("personas").len()
        );

        // The tip did not close its epoch, so the accruing row is present —
        // the open epoch, a zero total (§3.8.1's corrected row).
        assert_ne!(
            (tip + 1) % seb,
            0,
            "the fixture's tip is inside an open epoch"
        );
        assert_eq!(
            rows.rows(SnapshotFamily::BudgetAccruing)
                .iter()
                .collect::<Vec<_>>(),
            vec![(&le(tip / seb), &le(0))]
        );
        // And every epoch before it closed: one sigma_work and one budget row each.
        assert_eq!(
            rows.rows(SnapshotFamily::SigmaWork).len(),
            usize::try_from(tip / seb).expect("epochs")
        );
        assert_eq!(
            rows.rows(SnapshotFamily::Budget).len(),
            usize::try_from(tip / seb).expect("epochs")
        );
    }
}
