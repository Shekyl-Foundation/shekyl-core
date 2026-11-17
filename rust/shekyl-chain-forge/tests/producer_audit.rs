// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain B's live cross-check (`CHAIN_FORGE.md` §4, `CF-R18` (2) and (3)),
//! exercised on the producer plan.
//!
//! The producer plan is forged twice in this process: once planned (every
//! input the producer audit classes as drawn from the plan's seed), once
//! live (every one from the OS, through the seams a node runs:
//! `WitnessRing::new`, the producer task's `run`, a receipt signer over the
//! OS). The live run's bytes are not the planned run's and are not asked to
//! be. It is held to the planned run on **settlement state, by exclusion**:
//! every archival table the store keeps, except the named tables and the
//! named fields, each with its reason. An excluded field is not dropped:
//! what it records is held by a form that does not depend on timing, named
//! beside it. Equal there means the settlement outcome did not depend on
//! the drawn inputs or the timing the live run had (`CF-R18` (3)).
//!
//! Each row category the projection keeps (a table held whole, or one field
//! of a table) has its negative control, applied to the stored rows before
//! the projection: one row changed in that category alone is told apart,
//! and named. A change confined to the excluded fields, shaped as a reveal
//! admitted one block later, is not told apart; a reveal outside its
//! response window is.

#[allow(
    dead_code,
    reason = "each test-kind target uses part of the executor; this one forges the producer plan in process"
)]
#[path = "../executor/mod.rs"]
mod executor;

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

use executor::{Forge, Options, ProducerOptions};
use shekyl_chain_forge::Plan;
use shekyl_chain_rules::SettlementSchedule;
use shekyl_chain_store::ids::{IssuedDrawKey, IssuedDrawTuple};
use shekyl_chain_store::store::RawRows;
use shekyl_store_codec::Canonical;
use shekyl_types::archival::{BlockDraws, IssuedDraw};
use shekyl_types::BlockHeight;

const BLOCK_DRAWS: &str = "archival_block_draws";
const ISSUED_DRAW: &str = "archival_issued_draw";

/// The archival tables the projection leaves out, and why each may differ
/// between a planned and a live producer run.
const EXCLUDED_TABLES: &[(&str, &str)] = &[
    (
        "archival_bundle_body",
        "a bundle's body carries the witness's key and signature and each \
         record's receipt: drawn inputs, the OS's on a live run",
    ),
    (
        "archival_bundle_references",
        "a reference commits its body and its block's revealed seed, both \
         drawn",
    ),
    (
        "archival_bundle_queue",
        "a queue entry holds the filed reference and body; the queue is empty \
         at the end of either run, and a held entry would carry drawn bytes",
    ),
];

/// The fields of kept tables the projection leaves out: the table, the
/// field, why it may differ, and what holds it instead.
///
/// All three record **when** a draw became visible. A block's draws become
/// visible when a later block admits its bundle, which reveals its seed;
/// which block that is follows when the bundle's reads ran, and their
/// attempt heights are drawn (the OS's on a live run). What the count rule
/// does with the shortfall is held at every height: each block's count and
/// carry are kept fields.
const EXCLUDED_FIELDS: &[(&str, &str, &str)] = &[
    (
        BLOCK_DRAWS,
        "shortfall",
        "the visible shortfall falls at the block that admits a reveal; held \
         instead by each epoch's closing shortfall",
    ),
    (
        BLOCK_DRAWS,
        "issued_short",
        "the reduction sits on the block that admits the reveal; held instead \
         by each epoch's sum of them",
    ),
    (
        ISSUED_DRAW,
        "revealed_at",
        "the block that admitted the issuing block's seed; held instead by \
         the response window: every reveal in (h, h + W2]",
    ),
];

/// Every archival table, by name: the settlement state.
const PREFIX: &str = "archival_";

type Tables = BTreeMap<&'static str, RawRows>;

/// A row category's rows, by key.
type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

/// The settlement state by category: a kept table under its name, a kept
/// field under `table.field`, a timing-free stand-in under `table.what`.
type Projection = BTreeMap<String, Rows>;

fn height_of(key: &[u8]) -> BlockHeight {
    BlockHeight::from_raw(<u64 as redb::Value>::from_bytes(key))
}

fn issued_key_of(key: &[u8]) -> IssuedDrawKey {
    IssuedDrawKey::from_key(<IssuedDrawTuple as redb::Value>::from_bytes(key))
}

fn category<'a>(out: &'a mut Projection, table: &str, what: &str) -> &'a mut Rows {
    out.entry(format!("{table}.{what}")).or_default()
}

/// `archival_block_draws` by field: count, carry and the revealed flag at
/// every height, and per epoch the sum of the reductions and the shortfall
/// the epoch closes on.
fn project_block_draws(rows: &RawRows, schedule: SettlementSchedule, out: &mut Projection) {
    let mut epochs: BTreeMap<u64, (u64, BlockHeight, BlockDraws)> = BTreeMap::new();
    for (key, value) in rows {
        let draws = BlockDraws::decode(value).expect("a stored block-draws row decodes");
        category(out, BLOCK_DRAWS, "count").insert(key.clone(), draws.count.to_le_bytes().to_vec());
        category(out, BLOCK_DRAWS, "carry").insert(key.clone(), draws.carry.to_le_bytes().to_vec());
        category(out, BLOCK_DRAWS, "revealed").insert(key.clone(), vec![u8::from(draws.revealed)]);
        let height = height_of(key);
        let (sum, last, closing) = epochs
            .entry(schedule.epoch_at(height).to_raw())
            .or_insert((0, height, draws));
        *sum += u64::from(draws.issued_short);
        if height >= *last {
            *last = height;
            *closing = draws;
        }
    }
    for (epoch, (sum, last, closing)) in epochs {
        let closes_on = closing
            .shortfall
            .checked_sub(u64::from(closing.issued_short))
            .unwrap_or_else(|| panic!("the row at {last} issues no more than its shortfall"));
        let mut value = sum.to_le_bytes().to_vec();
        value.extend_from_slice(&closes_on.to_le_bytes());
        category(out, BLOCK_DRAWS, "epoch").insert(epoch.to_le_bytes().to_vec(), value);
    }
}

/// `archival_issued_draw` by field: every key, and whether it passed.
fn project_issued_draws(rows: &RawRows, out: &mut Projection) {
    for (key, value) in rows {
        let draw = IssuedDraw::decode(value).expect("a stored issued-draw row decodes");
        category(out, ISSUED_DRAW, "passed").insert(key.clone(), vec![u8::from(draw.passed)]);
    }
}

/// The settlement state of `tables`, by exclusion.
fn projection(tables: &Tables, schedule: SettlementSchedule) -> Projection {
    let excluded: BTreeSet<&str> = EXCLUDED_TABLES.iter().map(|(table, _)| *table).collect();
    let mut out = Projection::new();
    for (name, rows) in tables {
        if !name.starts_with(PREFIX) || excluded.contains(name) {
            continue;
        }
        match *name {
            BLOCK_DRAWS => project_block_draws(rows, schedule, &mut out),
            ISSUED_DRAW => project_issued_draws(rows, &mut out),
            _ => {
                out.insert((*name).to_owned(), rows.iter().cloned().collect());
            }
        }
    }
    out
}

/// Every issued draw whose reveal was admitted outside its response window
/// `(h, h + W₂]`, described.
fn reveals_outside_window(tables: &Tables, schedule: SettlementSchedule) -> Vec<String> {
    let response = schedule
        .challenge_response_blocks()
        .expect("the producer plan's epoch has a response window")
        .get();
    tables
        .get(ISSUED_DRAW)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| {
            let key = issued_key_of(key);
            let draw = IssuedDraw::decode(value).expect("a stored issued-draw row decodes");
            let h = key.issuing_height().to_raw();
            let at = draw.revealed_at.to_raw();
            (at <= h || at > h.saturating_add(response)).then(|| {
                format!(
                    "draw {} of block {h} revealed at {at}, outside ({h}, {}]",
                    key.draw(),
                    h.saturating_add(response)
                )
            })
        })
        .collect()
}

/// The categories in which `a` and `b` differ.
fn differing(a: &Projection, b: &Projection) -> Vec<String> {
    let names: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    names
        .into_iter()
        .filter(|name| a.get(*name) != b.get(*name))
        .cloned()
        .collect()
}

/// Every row on which `planned` and `live` differ, by key: a value that
/// differs, or a key one side lacks.
fn row_differences(planned: Option<&Rows>, live: Option<&Rows>) -> Vec<String> {
    let empty = Rows::new();
    let (a, b) = (planned.unwrap_or(&empty), live.unwrap_or(&empty));
    let keys: BTreeSet<&Vec<u8>> = a.keys().chain(b.keys()).collect();
    let side = |v: Option<&Vec<u8>>| v.map_or_else(|| "absent".to_owned(), hex::encode);
    keys.into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| {
            format!(
                "row {}: planned {}; live {}",
                hex::encode(k),
                side(a.get(k)),
                side(b.get(k))
            )
        })
        .collect()
}

/// `tables` with one table's rows edited.
fn edited(tables: &Tables, table: &str, edit: impl FnOnce(&mut RawRows)) -> Tables {
    let mut changed = tables.clone();
    edit(changed.get_mut(table).expect("the table is present"));
    changed
}

/// `tables` with the block-draws row at `height` edited.
fn edited_draws(
    tables: &Tables,
    height: BlockHeight,
    edit: impl FnOnce(&mut BlockDraws),
) -> Tables {
    edited(tables, BLOCK_DRAWS, |rows| {
        let row = rows
            .iter_mut()
            .find(|(key, _)| height_of(key) == height)
            .expect("the height has a row");
        let mut draws = BlockDraws::decode(&row.1).expect("decodes");
        edit(&mut draws);
        row.1 = draws.encode();
    })
}

/// `tables` with the first issued-draw row edited.
fn edited_issued(tables: &Tables, edit: impl FnOnce(IssuedDrawKey, &mut IssuedDraw)) -> Tables {
    edited(tables, ISSUED_DRAW, |rows| {
        let row = rows.first_mut().expect("an issued draw");
        let key = issued_key_of(&row.0);
        let mut draw = IssuedDraw::decode(&row.1).expect("decodes");
        edit(key, &mut draw);
        row.1 = draw.encode();
    })
}

async fn forged(plan: &Plan, live: bool) -> (tempfile::TempDir, Forge) {
    let out = tempfile::tempdir().expect("a directory");
    let mut forge = Forge::open(
        plan,
        out.path(),
        Options {
            swapped: BTreeSet::new(),
            stop_at_difference: None,
            hashers: NonZeroUsize::MIN,
            producer: ProducerOptions {
                live,
                // The live run's reads start on another spread too: its
                // timing differs from the planned run's on purpose.
                start_spread: live.then(|| std::time::Duration::from_millis(400)),
            },
        },
    )
    .await
    .expect("the forging opens");
    assert!(
        forge.run(plan).await.expect("the plan runs").is_none(),
        "nothing to stop at"
    );
    (out, forge)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two producer-plan forgings, minutes each; run by chain-forge.yml's nightly"]
async fn a_live_producer_run_settles_as_the_planned_one() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("plans/producer.toml");
    let plan = Plan::parse(&std::fs::read_to_string(path).expect("reads")).expect("parses");

    let (_planned_dir, mut planned) = forged(&plan, false).await;
    let schedule = planned.schedule();
    let planned_tables = planned.scenario().table_rows().await.expect("rows");
    planned.abandon().await;
    let (_live_dir, mut live) = forged(&plan, true).await;
    let live_tables = live.scenario().table_rows().await.expect("rows");
    live.abandon().await;
    let (planned_rows, live_rows) = (
        projection(&planned_tables, schedule),
        projection(&live_tables, schedule),
    );

    // The subject exists (rule 47): the settlement the producer fed, and
    // reveals that moved the shortfall, so the stand-ins hold something.
    for table in [
        "archival_settlement",
        "archival_sigma_work",
        "archival_issued_draw.passed",
    ] {
        assert!(
            planned_rows.get(table).is_some_and(|rows| !rows.is_empty()),
            "the planned run wrote {table}"
        );
    }
    assert!(
        planned_rows[&format!("{BLOCK_DRAWS}.epoch")]
            .values()
            .any(|value| value[..8] != [0u8; 8]),
        "a reveal in the planned run took something off a shortfall"
    );

    for (run, tables) in [("planned", &planned_tables), ("live", &live_tables)] {
        let outside = reveals_outside_window(tables, schedule);
        assert!(
            outside.is_empty(),
            "the {run} run admitted reveals outside their response window: {outside:?}"
        );
    }

    let apart = differing(&planned_rows, &live_rows);
    for name in &apart {
        for line in row_differences(planned_rows.get(name), live_rows.get(name)) {
            eprintln!("{name}: {line}");
        }
    }
    assert!(
        apart.is_empty(),
        "a live producer run's settlement state is not the planned run's in {apart:?}"
    );

    // One negative control per row category, on the stored rows: one row
    // changed in that category alone, and the comparison names it.
    let named = |changed: &Tables| differing(&planned_rows, &projection(changed, schedule));
    let mut controlled = BTreeSet::new();
    for (table, rows) in &planned_tables {
        if !planned_rows.contains_key(*table) || rows.is_empty() {
            continue;
        }
        let changed = edited(&planned_tables, table, |rows| {
            let row = rows.last_mut().expect("a row");
            match row.1.last_mut() {
                Some(byte) => *byte ^= 0x01,
                None => row.0.push(0xFF),
            }
        });
        assert_eq!(
            named(&changed),
            vec![(*table).to_owned()],
            "one row of {table} changed"
        );
        controlled.insert((*table).to_owned());
    }

    // The block-draws fields. The reveal the planned run admitted first:
    // `x` carries its reduction, and the next block is in its epoch.
    let draws_at = |height: BlockHeight| {
        planned_tables[BLOCK_DRAWS]
            .iter()
            .find(|(key, _)| height_of(key) == height)
            .map(|(_, value)| BlockDraws::decode(value).expect("decodes"))
    };
    let x = planned_tables[BLOCK_DRAWS]
        .iter()
        .map(|(key, value)| (height_of(key), BlockDraws::decode(value).expect("decodes")))
        .find(|(height, draws)| {
            let next = BlockHeight::from_raw(height.to_raw() + 1);
            draws.issued_short > 0
                && schedule.epoch_at(next) == schedule.epoch_at(*height)
                && draws_at(next).is_some_and(|after| after.issued_short == 0)
        })
        .map(|(height, _)| height)
        .expect("a reveal whose next block is in its epoch and issues nothing");
    let after_x = BlockHeight::from_raw(x.to_raw() + 1);
    for (field, edit) in [
        (
            "count",
            (|d: &mut BlockDraws| d.count ^= 1) as fn(&mut BlockDraws),
        ),
        ("carry", |d| d.carry ^= 1),
        ("revealed", |d| d.revealed = !d.revealed),
        // One reduction more: the epoch's sum moves.
        ("epoch", |d| d.issued_short += 1),
    ] {
        let name = format!("{BLOCK_DRAWS}.{field}");
        assert_eq!(
            named(&edited_draws(&planned_tables, x, edit)),
            vec![name.clone()]
        );
        controlled.insert(name);
    }
    // The same reveal admitted one block later: the reduction moves to the
    // next block and the shortfall between stays up. Only excluded fields
    // change, and nothing is told apart.
    let later = edited_draws(&planned_tables, x, |d| d.issued_short -= 1);
    let later = edited_draws(&later, after_x, |d| {
        d.issued_short += 1;
        d.shortfall += 1;
    });
    assert_eq!(
        named(&later),
        Vec::<String>::new(),
        "a reveal one block later"
    );

    // The issued-draw fields: the pass, a reveal moved inside its window
    // (not told apart), and one moved past it (refused by the window).
    let name = format!("{ISSUED_DRAW}.passed");
    assert_eq!(
        named(&edited_issued(&planned_tables, |_, d| d.passed = !d.passed)),
        vec![name.clone()]
    );
    controlled.insert(name);
    let inside = edited_issued(&planned_tables, |key, d| {
        d.revealed_at = BlockHeight::from_raw(key.issuing_height().to_raw() + 1);
    });
    assert_eq!(
        named(&inside),
        Vec::<String>::new(),
        "a reveal moved inside its window"
    );
    assert!(reveals_outside_window(&inside, schedule).is_empty());
    let response = schedule
        .challenge_response_blocks()
        .expect("a response window")
        .get();
    let outside = edited_issued(&planned_tables, |key, d| {
        d.revealed_at = BlockHeight::from_raw(key.issuing_height().to_raw() + response + 1);
    });
    assert_eq!(
        reveals_outside_window(&outside, schedule).len(),
        1,
        "a reveal past its window"
    );

    let uncontrolled: Vec<&String> = planned_rows
        .iter()
        .filter(|(name, rows)| !rows.is_empty() && !controlled.contains(*name))
        .map(|(name, _)| name)
        .collect();
    assert!(
        uncontrolled.is_empty(),
        "every category with rows has its negative control: {uncontrolled:?} has none"
    );
    eprintln!(
        "a live producer run settles as the planned one on {} categories, each with its negative \
         control; excluded tables: {}; excluded fields: {}",
        controlled.len(),
        EXCLUDED_TABLES
            .iter()
            .map(|(t, _)| *t)
            .collect::<Vec<_>>()
            .join(", "),
        EXCLUDED_FIELDS
            .iter()
            .map(|(t, f, _)| format!("{t}.{f}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
}
