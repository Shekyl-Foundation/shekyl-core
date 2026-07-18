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
use crate::engine::lifecycle::{Credentials, EngineCreateParams};
use crate::engine::pscan::accrual::PScanAccrual;
use crate::engine::pscan::exhaustiveness::verify_exhaustive;
use crate::engine::pscan::scan_step::{BlockRange, FundingOutputMatch};
use crate::engine::stake_engine::{derive_funding_key_image, StakeEngineHandle};
use crate::engine::{CapabilityInput, DaemonClient, Engine, Network, SoloSigner};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_file::SafetyOverrides;
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

/// What the arm-#3 fire lane asserts (all state produced by production code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm3FireReport {
    /// Pre-evidence control: with no sealed scan (`OutsideCovered`), the
    /// durable slot survived a reopen (absence-≠-unscanned held).
    pub unscanned_slot_survived: bool,
    /// With sealed confirmed-absence evidence, the reopen collected the
    /// phantom slot (the GC fired on the production open path).
    pub phantom_dropped: bool,
    /// The sweep emptied `bonded_slots` and reverted the wallet to a
    /// non-staker (no actor spawned at the post-GC open).
    pub reverted_to_non_staker: bool,
}

/// SP-R0 **arm #3** DQ-F fire lane — the fixture SA-DQ-3 co-designed with the
/// activation round: an **activation-induced persist-then-no-broadcast
/// crash**. `persist_bond_record` runs (the durable point of a first-stake),
/// dispatch never happens (the crash), the production scan exhausts a covered
/// range with no bond post, and the next **production open**
/// (`Engine::open_full` → the assemble-time arm-#3 sweep) collects the
/// phantom. Guard 1 holds as in the arm-#1 lane: this module is `not(test)`,
/// so the evidence can only come from the production
/// `verify_exhaustive`/`ingest`/seal path — `VerifiedBatch::for_test` does
/// not exist here.
pub async fn run_arm3_fire(scratch_dir: &std::path::Path) -> Result<Arm3FireReport, String> {
    let base = scratch_dir.join("wallet");
    let password: &[u8] = b"arm3-fire";
    let creds = Credentials::password_only(password);

    let dummy_daemon = || async {
        let rpc = shekyl_rpc_transport::SimpleRequestRpc::new("http://127.0.0.1:1".to_string())
            .await
            .map_err(|e| format!("rpc stub: {e}"))?;
        Ok::<_, String>(DaemonClient::new(rpc))
    };

    // Create the wallet, then simulate the SA-DQ-3 crash: persist the bond
    // record (the activation's durable point) and stop — no assemble, no
    // pending post, no broadcast.
    // Explicit production-shape construction (the RPC/CLI construction path,
    // not the cfg(test) convenience — which does not exist in this
    // compilation). Minimum-wall-clock KDF so the lane runs under a debug
    // build; Stagenet+Bip39 is a permitted pair.
    let params = EngineCreateParams {
        base_path: &base,
        credentials: &creds,
        network: Network::Stagenet,
        capability: CapabilityInput::Full {
            master_seed_64: &SEED,
            seed_format: SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: SafetyOverrides::none(),
        prefs: shekyl_engine_prefs::WalletPrefs::default(),
    };
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon().await?)
        .map_err(|e| format!("create: {e}"))?
        .close(&creds)
        .map_err(|e| format!("close create: {e}"))?;
    let opened = Engine::<SoloSigner>::open_full(
        &base,
        &creds,
        network,
        dummy_daemon().await?,
        SafetyOverrides::none(),
    )
    .map_err(|e| format!("open: {e}"))?
    .into_wallet();
    opened
        .persist_bond_record(PSlot::from_raw(SLOT))
        .map_err(|e| format!("persist: {e}"))?;
    opened.close(&creds).map_err(|e| format!("close: {e}"))?;

    // Control: no sealed scan evidence yet — every verdict is
    // `OutsideCovered`, so the reopen must KEEP the slot (and spawn the
    // staker actor for it).
    let control = Engine::<SoloSigner>::open_full(
        &base,
        &creds,
        network,
        dummy_daemon().await?,
        SafetyOverrides::none(),
    )
    .map_err(|e| format!("control reopen: {e}"))?
    .into_wallet();
    let unscanned_slot_survived = {
        let ledger = control.ledger();
        ledger.staking.staking_enabled && ledger.staking.bonded_slots.contains(&SLOT)
    } && control.has_stake_engine();
    control
        .close(&creds)
        .map_err(|e| format!("close control: {e}"))?;

    // Build confirmed-absence evidence through the production path: scan a
    // chained fixture range (no bond posts anywhere) with the persona's real
    // scanner, then seal it with the production pscan seal.
    // The WALLET's persona (same seed, the wallet's own network/format pair)
    // — the derive-equivalence discipline: one primitive, the wallet's
    // parameters.
    let keys = derive_archival_p_keys(
        &SEED,
        crate::engine::lifecycle::network_to_derivation(network),
        SeedFormat::Bip39,
        SLOT,
    )
    .map_err(|e| format!("derive wallet persona: {e}"))?;
    let scanner = crate::engine::pscan::persona_scanner::guaranteed_scanner_for_persona(&keys)
        .map_err(|e| format!("scanner: {e}"))?;
    let b0 = chain(build_typical_case_scannable_block(1), [0u8; 32]);
    let b1 = chain(build_typical_case_scannable_block(1), b0.block.hash());
    let blocks = vec![b0, b1];
    let verified = verify_exhaustive(BlockHeight::from_raw(0), [0u8; 32], &blocks)
        .map_err(|e| format!("exhaustiveness: {e}"))?;
    let range =
        BlockRange::new(BlockHeight::from_raw(0), BlockHeight::from_raw(2)).ok_or("range")?;
    let out = crate::engine::pscan::scan_step::run_dual_extractor(
        vec![(SLOT, scanner)],
        &std::collections::BTreeMap::new(),
        range,
        &blocks,
        &crate::engine::pscan::scan_step::KeyImageWatchSet::new(),
    )
    .map_err(|e| format!("extract: {e}"))?;
    let mut accrual = PScanAccrual::genesis();
    accrual
        .ingest(&out.result, &verified)
        .map_err(|e| format!("ingest: {e}"))?;
    let state = accrual.to_state();
    let bytes = state
        .to_postcard_bytes()
        .map_err(|e| format!("encode: {e}"))?;
    {
        let (file, _outcome) =
            shekyl_engine_file::WalletFile::open(&base, password, network, SafetyOverrides::none())
                .map_err(|e| format!("file open: {e:?}"))?;
        let key = crate::engine::sealing_keys::state_wrap_key_from_wallet_file(&file);
        file.save_pscan_state(key.as_bytes(), &bytes)
            .map_err(|e| format!("seal: {e}"))?;
    }

    // The fire: the production open runs the arm-#3 sweep before derive.
    let after = Engine::<SoloSigner>::open_full(
        &base,
        &creds,
        network,
        dummy_daemon().await?,
        SafetyOverrides::none(),
    )
    .map_err(|e| format!("post-evidence reopen: {e}"))?
    .into_wallet();
    let (phantom_dropped, reverted) = {
        let ledger = after.ledger();
        (
            !ledger.staking.bonded_slots.contains(&SLOT),
            !ledger.staking.staking_enabled,
        )
    };
    let reverted_to_non_staker = reverted && !after.has_stake_engine();
    after.close(&creds).map_err(|e| format!("close: {e}"))?;

    Ok(Arm3FireReport {
        unscanned_slot_survived,
        phantom_dropped,
        reverted_to_non_staker,
    })
}
