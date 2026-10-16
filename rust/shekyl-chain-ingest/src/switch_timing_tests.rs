// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The switch at the genesis rule set's reorg cap (`D_max` = 720), timed
//! (DRS-E5 a6; `DRS_E5_POOL_ALT_PRUNE.md` §2.3: "the cost is measured, not
//! estimated"). Ignored lane: run with `--release -- --ignored
//! --nocapture`; each run prints one line per phase with its basis. Each
//! run also holds the switched store to the store that connected the
//! winning branch directly, every table but the alt table.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use shekyl_harness_spender::Spender;
use shekyl_pow_randomx::CacheStore;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Transaction;

use crate::connector::{Offered, Switched};
use crate::metrics::Metrics;
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::substrate::ProductionSubstrate;
use crate::test_support::{Family, FIRST_SPEND_HEIGHT};
use shekyl_chain_rules::Substrate;

/// The cap in force at genesis.
fn cap() -> u64 {
    crate::scenario::RULES
        .in_force(BlockHeight::from_raw(0))
        .reorg_cap()
        .to_raw()
}

fn randomx() -> ProductionSubstrate {
    ProductionSubstrate::new(Arc::new(CacheStore::new()), Arc::new(Metrics::new()))
}

/// Two drivers over one prefix of `FIRST_SPEND_HEIGHT + 2` blocks; `x`
/// mines A (`cap` coinbase-only blocks), `y` mines B (`cap + 1` blocks,
/// each listing one validating spend when `spends`). B arrives at `x` and
/// the switch pops the cap exactly.
async fn timed<P>(label: &str, pow: impl Fn() -> P, spends: bool)
where
    P: Substrate + Send + Sync + 'static,
    P::Fault: std::fmt::Debug,
{
    let depth = cap();
    let prefix_len = FIRST_SPEND_HEIGHT + 2;
    let mut x = Scenario::open_with(&format!("switch-timing-{label}-x"), pow());
    let mut y = Scenario::open_with(&format!("switch-timing-{label}-y"), pow());
    let started = Instant::now();
    x.mine(prefix_len).await;
    let prefix = y.mine(prefix_len).await;
    x.mine(depth).await;
    y.idle();
    let mut spender = Spender::over(&prefix);
    let mut b: Vec<Mined> = Vec::new();
    for i in 0..=depth {
        let connecting = prefix_len + i;
        let listed = if spends {
            vec![spender.spend_coinbase(
                y.wallet(),
                BlockHeight::from_raw(connecting - FIRST_SPEND_HEIGHT),
                BlockHeight::from_raw(connecting),
                Family::Main.fee(),
            )]
        } else {
            Vec::new()
        };
        let mined = y
            .mine_listing(listed)
            .await
            .unwrap_or_else(|o| panic!("B block {connecting}: {o}"));
        spender.push(&mined);
        b.push(mined);
    }
    let built = started.elapsed();

    let (last, held) = b.split_last().expect("a branch");
    for mined in held {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    let started = Instant::now();
    let Offered::SwitchDue(plan) = x.offer(last).await.expect("offer") else {
        panic!("the heavier tip did not name a switch");
    };
    let offered = started.elapsed();
    assert_eq!(plan.demoted.len(), usize::try_from(depth).expect("fits"));
    let bodies: HashMap<BlockHash, Vec<Transaction>> = b
        .iter()
        .map(|m| (m.hash, m.template.transactions.clone()))
        .collect();
    let (switched, timing) = x.reorganize_timed(&plan, &bodies).await.expect("switch");
    assert!(matches!(switched, Switched::Done(_)), "{switched:?}");

    let (rows_x, rows_y) = (
        x.table_rows().await.expect("rows"),
        y.table_rows().await.expect("rows"),
    );
    let differ: Vec<&str> = rows_x
        .keys()
        .filter(|t| **t != "alt_blocks" && rows_x.get(*t) != rows_y.get(*t))
        .copied()
        .collect();
    assert!(differ.is_empty(), "A → B differs from B in {differ:?}");

    let basis = format!(
        "{} build, {} threads available, N = {depth} demoted, M = {} promoted, {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        depth + 1,
        if spends {
            "one validating spend per promoted block"
        } else {
            "coinbase-only"
        },
    );
    eprintln!("switch-timing [{label}] chains built in {built:?} ({basis})");
    eprintln!(
        "switch-timing [{label}] offer of the winning block (tier, AL1, plan reads): {offered:?}"
    );
    eprintln!(
        "switch-timing [{label}] form N + M (RandomX, off the actor, across the host's threads): {:?}",
        timing.form
    );
    eprintln!("switch-timing [{label}] Reorganize (plan checks, N cheap-tier verdicts, pops + SI-5, N rows, M validate + connect, M removes): {:?}", timing.switch);
    eprintln!(
        "switch-timing [{label}] total from the winning arrival: {:?}",
        offered + timing.form + timing.switch
    );
    x.close().await;
    y.close().await;
}

#[tokio::test]
#[ignore = "measurement: the switch at the genesis cap; run --release -- --ignored --nocapture"]
async fn production_cap_switch_timing_free_hash_coinbase_only() {
    timed("free-coinbase", || FreeHash, false).await;
}

#[tokio::test]
#[ignore = "measurement: the switch at the genesis cap; run --release -- --ignored --nocapture"]
async fn production_cap_switch_timing_randomx_coinbase_only() {
    timed("randomx-coinbase", randomx, false).await;
}

#[tokio::test]
#[ignore = "measurement: the switch at the genesis cap; run --release -- --ignored --nocapture"]
async fn production_cap_switch_timing_randomx_with_spends() {
    timed("randomx-spends", randomx, true).await;
}
