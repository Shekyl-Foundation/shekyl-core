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
//! every archival table the store keeps, except the named ones, each with
//! its reason. Equal there means the settlement outcome did not depend on
//! the drawn inputs or the timing the live run had (`CF-R18` (3)).
//!
//! Each table the projection keeps is a row category, and each has its
//! negative control: the planned projection with one row of that table
//! changed is told apart from the planned projection, and named.

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
use shekyl_chain_store::store::RawRows;

/// The archival tables the projection leaves out, and why each may differ
/// between a planned and a live producer run.
const EXCLUDED: &[(&str, &str)] = &[
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

/// Every archival table, by name: the settlement state.
const PREFIX: &str = "archival_";

type Projection = BTreeMap<&'static str, RawRows>;

/// The settlement state of `tables`, by exclusion.
fn projection(tables: BTreeMap<&'static str, RawRows>) -> Projection {
    let excluded: BTreeSet<&str> = EXCLUDED.iter().map(|(table, _)| *table).collect();
    tables
        .into_iter()
        .filter(|(name, _)| name.starts_with(PREFIX) && !excluded.contains(name))
        .collect()
}

/// The tables in which `a` and `b` differ.
fn differing(a: &Projection, b: &Projection) -> Vec<&'static str> {
    let names: BTreeSet<&'static str> = a.keys().chain(b.keys()).copied().collect();
    names
        .into_iter()
        .filter(|name| a.get(name) != b.get(name))
        .collect()
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
                ..ProducerOptions::default()
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
    let planned_rows = projection(planned.scenario().table_rows().await.expect("rows"));
    planned.abandon().await;
    let (_live_dir, mut live) = forged(&plan, true).await;
    let live_rows = projection(live.scenario().table_rows().await.expect("rows"));
    live.abandon().await;

    // The subject exists (rule 47): the settlement the producer fed.
    for table in [
        "archival_settlement",
        "archival_issued_draw",
        "archival_sigma_work",
    ] {
        assert!(
            planned_rows.get(table).is_some_and(|rows| !rows.is_empty()),
            "the planned run wrote {table}"
        );
    }

    let apart = differing(&planned_rows, &live_rows);
    assert!(
        apart.is_empty(),
        "a live producer run's settlement state is not the planned run's in {apart:?} \
         (planned rows: {:?}; live rows: {:?})",
        apart
            .iter()
            .map(|t| planned_rows.get(t).map_or(0, Vec::len))
            .collect::<Vec<_>>(),
        apart
            .iter()
            .map(|t| live_rows.get(t).map_or(0, Vec::len))
            .collect::<Vec<_>>(),
    );

    // One negative control per row category: one row changed in that table
    // alone, and the comparison names that table.
    let mut controlled = 0usize;
    for (table, rows) in &planned_rows {
        let Some(last) = rows.len().checked_sub(1) else {
            continue;
        };
        let mut changed = planned_rows.clone();
        let row = &mut changed.get_mut(table).expect("present")[last];
        match row.1.last_mut() {
            Some(byte) => *byte ^= 0x01,
            None => row.0.push(0xFF),
        }
        assert_eq!(
            differing(&planned_rows, &changed),
            vec![*table],
            "one row of {table} changed is told apart, and named"
        );
        controlled += 1;
    }
    assert!(controlled > 0, "the projection holds rows to control");
    eprintln!(
        "a live producer run settles as the planned one on {} archival table(s), {} with rows, each with its negative control; excluded: {}",
        planned_rows.len(),
        controlled,
        EXCLUDED.iter().map(|(t, _)| *t).collect::<Vec<_>>().join(", ")
    );
}
