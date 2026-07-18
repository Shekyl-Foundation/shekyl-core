// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-R0 arm #1 — the DQ-F **logic-discharge fire harness**
//! (`ARCHIVAL_BOND_SP_R0_PLAN.md` §5 DQ-F, precisified 2026-07-18).
//!
//! Drives the arm on the **production code path** and reports the GC firing:
//! a real funding output is discovered by the production dual extractor, its
//! key image is derived **in-actor** by the production watch refresh, a real
//! on-chain spend of it is matched by arm (c), and the record is pruned by the
//! production `PScanAccrual::ingest` — the fire counter
//! ([`PScanAccrual::spent_pruned_total`]) is the DQ-F observer the CI lane
//! asserts non-zero. Both prune paths fire: the **cross-step** watch-cache
//! path and the **in-step** trailing path (discover-then-spend inside one
//! step, the blind spot the handler's trailing pass closes).
//!
//! ## Guard 1 is structural here (no `for_test()` on the path under test)
//!
//! This module is compiled `#[cfg(all(feature = "test-helpers", not(test)))]`:
//! in every compilation that contains it, `#[cfg(test)]` items — including
//! `SpentRecordsDurablyPruned::for_test` and `VerifiedBatch::for_test` — **do
//! not exist**. The witness below can only come from the production
//! [`SpentRecordsDurablyPruned::arm1_watch_pruning_live`] constructor, and the
//! `VerifiedBatch` can only come from the production [`verify_exhaustive`]
//! gate over a genuinely chaining block sequence. Deleting either production
//! path breaks this harness at compile time — the DQ-F "delete `for_test()`;
//! still passes" tell holds vacuously.
//!
//! The **only** stand-in is at the very top: the persona exists by direct key
//! derivation rather than through the #332 staker-activation entry (which is
//! exactly the gate being deferred — the DQ-F split's licensed stand-in).
//! Everything downstream — derive primitive, extractor, watch, prune, seal
//! substrate, witness, sweep refusal — is production code.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::kem::HybridKemPublicKey;
use shekyl_scanner::bench_fixtures::{
    build_typical_case_scannable_block, scannable_block_for_recipient,
};
use shekyl_scanner::ScannableBlock;
use shekyl_types::{BlockHeight, PSlot};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::Input;

use crate::engine::bond_assembly::{sweep_funding_outputs, SpentRecordsDurablyPruned};
use crate::engine::pscan::accrual::PScanAccrual;
use crate::engine::pscan::exhaustiveness::verify_exhaustive;
use crate::engine::pscan::scan_step::{BlockRange, FundingOutputMatch};
use crate::engine::stake_engine::{derive_funding_key_image, StakeEngineHandle};
use shekyl_engine_state::pscan_state::PFundingOutputRecord;

/// What the fire lane asserts (all counts produced by production code).
/// Per-scenario fields throughout — the prune counters and the surviving
/// record counts are reported per path, so a scenario that fails to go
/// clean cannot hide behind the other's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm1FireReport {
    /// Records pruned via the cross-step watch-cache path (expected: 1).
    pub cross_step_pruned: u64,
    /// Records pruned via the in-step trailing path (expected: 1).
    pub in_step_pruned: u64,
    /// Held funding records remaining after the cross-step scenario
    /// (expected: 0).
    pub records_after_cross_step: usize,
    /// Held funding records remaining after the in-step scenario
    /// (expected: 0).
    pub records_after_in_step: usize,
    /// The production-witness sweep refused to select anything after the
    /// prune (expected: true — the spent record is durably gone).
    pub sweep_refuses_after_prune: bool,
}

const SEED: [u8; MASTER_SEED_BYTES] = [0x5Au8; MASTER_SEED_BYTES];
const SLOT: u32 = 0;

fn persona() -> Result<ArchivalPKeys, String> {
    derive_archival_p_keys(&SEED, DerivationNetwork::Fakechain, SeedFormat::Raw32, SLOT)
        .map_err(|e| format!("derive persona: {e}"))
}

/// A funding block carrying one output addressed to the harness persona.
fn funding_block(keys: &ArchivalPKeys) -> ScannableBlock {
    let kem = HybridKemPublicKey {
        x25519: keys.x25519_pk,
        ml_kem: keys.ml_kem_ek.to_vec(),
    };
    scannable_block_for_recipient(1, &kem, keys.spend_pk.as_canonical_bytes())
}

/// Recompute a block's committed tx hashes and set its `previous` pointer —
/// the chaining `verify_exhaustive` (the production exhaustiveness gate)
/// checks for real.
fn chain(mut block: ScannableBlock, previous: [u8; 32]) -> ScannableBlock {
    block.block.header.previous = previous;
    block.block.transaction_hashes = block
        .transactions
        .iter()
        .map(shekyl_wire::transaction::Transaction::hash)
        .collect();
    block
}

/// A block whose first tx additionally spends `key_image` (an FCMP++ `ToKey`
/// input) — the on-chain spend of the watched output.
fn spend_block(key_image: [u8; 32]) -> ScannableBlock {
    let mut block = build_typical_case_scannable_block(1);
    block.transactions[0].prefix.inputs.push(Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image,
    });
    block
}

/// Derive the expected on-chain key image of a discovered funding record —
/// the harness playing the *chain's* role (the spender knows its own key
/// image). Calls the production derivation itself
/// ([`derive_funding_key_image`] — the single shared definition the actor's
/// watch refresh and the assemble path also use); if that derivation ever
/// stops matching what the chain would compute, the watch match fails and
/// the fire counter stays zero — which is exactly the failure the lane
/// exists to catch.
fn expected_key_image(keys: &ArchivalPKeys, m: &FundingOutputMatch) -> Result<[u8; 32], String> {
    derive_funding_key_image(
        keys,
        m.ciphertext_x25519,
        &m.ciphertext_ml_kem,
        m.index_in_transaction,
        m.output_key,
    )
}

fn spawn_actor() -> Result<StakeEngineHandle, String> {
    let keys = persona()?;
    let slot = PSlot::from_raw(SLOT);
    Ok(StakeEngineHandle::spawn(
        BTreeMap::from([(slot, keys)]),
        BTreeSet::from([slot]),
        Some(slot),
    ))
}

/// One production scan step: exhaustiveness-verify, actor scan (watch refresh
/// + dual extraction + trailing pass), ingest (prune + counter).
async fn step(
    handle: &StakeEngineHandle,
    accrual: &mut PScanAccrual,
    start: u64,
    blocks: Vec<ScannableBlock>,
) -> Result<(), String> {
    let end = start + blocks.len() as u64;
    let verified = verify_exhaustive(
        BlockHeight::from_raw(start),
        accrual.frontier_hash(),
        &blocks,
    )
    .map_err(|e| format!("exhaustiveness: {e}"))?;
    let range = BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end))
        .ok_or("empty range")?;
    let result = handle
        .scan_step(range, blocks, accrual.funding_outputs().into())
        .await
        .map_err(|e| format!("scan step: {e}"))?;
    accrual
        .ingest(&result, &verified)
        .map_err(|e| format!("ingest: {e}"))
}

/// Run the arm-#1 fire lane. See the module docs; every assertion below is
/// against production-code outputs.
pub async fn run_arm1_fire() -> Result<Arm1FireReport, String> {
    let keys = persona()?;

    // Shared chain: filler (h0), funding (h1) — chained for the real
    // exhaustiveness gate from the genesis anchor.
    let b0 = chain(build_typical_case_scannable_block(1), [0u8; 32]);
    let b1 = chain(funding_block(&keys), b0.block.hash());

    // ---- Scenario A: cross-step (watch-cache path). --------------------
    let handle = spawn_actor()?;
    let mut accrual = PScanAccrual::genesis();
    step(&handle, &mut accrual, 0, vec![b0.clone(), b1.clone()]).await?;
    if accrual.funding_outputs().len() != 1 {
        return Err(format!(
            "expected 1 discovered funding record, got {}",
            accrual.funding_outputs().len()
        ));
    }
    let key_image = expected_key_image(&keys, &accrual.funding_outputs()[0])?;
    let b2 = chain(spend_block(key_image), b1.block.hash());
    step(&handle, &mut accrual, 2, vec![b2.clone()]).await?;
    let cross_step_pruned = accrual.spent_pruned_total();
    let records_after_a = accrual.funding_outputs().len();

    // The production witness (Guard 1: the only constructor that exists in
    // this compilation) — and the sweep it gates can no longer select the
    // spent record, because the record is durably gone.
    let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
    let records: Vec<PFundingOutputRecord> = accrual
        .funding_outputs()
        .iter()
        .map(PFundingOutputRecord::from)
        .collect();
    let sweep_refuses_after_prune = sweep_funding_outputs(
        &witness,
        records.iter(),
        PSlot::from_raw(SLOT),
        &BTreeSet::new(),
        AtomicUnits::from_raw(1),
        BlockHeight::from_raw(u64::MAX),
    )
    .is_err();

    // ---- Scenario B: in-step (trailing path) — same chain, one step. ---
    let handle_b = spawn_actor()?;
    let mut accrual_b = PScanAccrual::genesis();
    step(&handle_b, &mut accrual_b, 0, vec![b0, b1, b2]).await?;
    let in_step_pruned = accrual_b.spent_pruned_total();
    let records_after_b = accrual_b.funding_outputs().len();

    Ok(Arm1FireReport {
        cross_step_pruned,
        in_step_pruned,
        records_after_cross_step: records_after_a,
        records_after_in_step: records_after_b,
        sweep_refuses_after_prune,
    })
}
