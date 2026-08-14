// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the P-scan task (`engine/pscan/task.rs`).
//!
//! Wired as a `#[path]` child of `task::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use super::*;

use std::collections::BTreeMap;
use std::sync::Mutex;

use shekyl_archival_retention::MAX_CLAIM_AGE_W;
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::kem::HybridKemPublicKey;
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_scanner::bench_fixtures::scannable_block_for_recipient;
use shekyl_scanner::ScannableBlock;
use shekyl_units::AtomicUnits;

use crate::engine::pscan::scan_step::BondPostMatch;
use crate::engine::stake_engine::{PSlot, StakeEngineHandle};
use crate::engine::test_support::{make_synthetic_block, TestDaemon, DEFAULT_TEST_SEED};

const SEED: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

fn persona(slot: u32) -> ArchivalPKeys {
    derive_archival_p_keys(&SEED, DerivationNetwork::Mainnet, SeedFormat::Bip39, slot)
        .expect("derive persona")
}

fn canonical_id(p: &ArchivalPKeys) -> PCanonicalId {
    use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
    p_canonical_id_from_hybrid_pubkey(&p.hybrid_bond_id().to_canonical_bytes().expect("id"))
}

/// A block addressed to `recipient` (one funding output).
fn funding_block(recipient: &ArchivalPKeys) -> ScannableBlock {
    let kem = HybridKemPublicKey {
        x25519: recipient.x25519_pk,
        ml_kem: recipient.ml_kem_ek.to_vec(),
    };
    scannable_block_for_recipient(1, &kem, recipient.spend_pk.as_canonical_bytes())
}

/// A chain of `len` blocks: `recipient_at[i]` (if present) is addressed to the
/// persona; the rest are foreign dummies. Length sets the source's tip.
///
/// The blocks are made **exhaustiveness-verifiable** (the sweep now runs
/// `verify_exhaustive` before extracting): each non-miner body is committed to its
/// real hash (the bench fixture writes a `[0xAA; 32]` placeholder, which the
/// per-body check would reject), and each block is chained to the recomputed hash
/// of its predecessor (anchored at the genesis `[0; 32]`). Linking is
/// deterministic, so an identical prefix in two `chain(..)` calls produces an
/// identical frontier hash — which is what lets the resume test carry an anchor
/// across a rebuilt chain.
fn chain(len: usize, recipient_blocks: &[(usize, ScannableBlock)]) -> Vec<ScannableBlock> {
    let mut c: Vec<ScannableBlock> = (0..len)
        .map(|h| make_synthetic_block(h as u64, [0u8; 32]))
        .collect();
    for (i, b) in recipient_blocks {
        c[*i] = b.clone();
    }
    let mut prev = [0u8; 32];
    for (h, sb) in c.iter_mut().enumerate() {
        // The coinbase claims its own height. The bench fixture hard-codes `Gen(0)`,
        // so set it to the position — both to keep the F5 fetch-loop tripwire honest
        // (a real coinbase claims its height) and because it is folded into the hash
        // recomputed below. The synthetic dummies already carry `Gen(h)`.
        if let Some(input) = sb.block.miner_transaction.prefix.inputs.first_mut() {
            *input = shekyl_wire::Input::Gen(h as u64);
        }
        sb.block.transaction_hashes = sb
            .transactions
            .iter()
            .map(shekyl_wire::Transaction::hash)
            .collect();
        sb.block.header.previous = prev;
        prev = sb.block.hash();
    }
    c
}

fn source(
    chain: Vec<ScannableBlock>,
) -> crate::engine::pscan::block_source::DaemonBlockSource<TestDaemon> {
    crate::engine::pscan::block_source::DaemonBlockSource::new(TestDaemon::with_seed_and_chain(
        DEFAULT_TEST_SEED,
        chain,
    ))
}

/// In-memory [`PScanStore`] for the loop tests.
#[derive(Default)]
struct MemStore(Mutex<Option<PScanState>>);

#[derive(Debug, thiserror::Error)]
#[error("mem store error")]
struct MemErr;

impl PScanStore for MemStore {
    type Error = MemErr;
    fn load(&self) -> impl std::future::Future<Output = Result<Option<PScanState>, MemErr>> + Send {
        // Sync work up front; the returned future is ready (no `self` borrow
        // crosses the await point, so it is trivially `Send`).
        let loaded = self.0.lock().unwrap().clone();
        async move { Ok(loaded) }
    }
    fn save(
        &self,
        state: &PScanState,
    ) -> impl std::future::Future<Output = Result<(), MemErr>> + Send {
        *self.0.lock().unwrap() = Some(state.clone());
        async move { Ok(()) }
    }
}

/// Spawn a StakeEngine over `bonded` persona slots.
fn spawn_stake(bonded: &[u32]) -> StakeEngineHandle {
    let bundles: BTreeMap<PSlot, ArchivalPKeys> = bonded
        .iter()
        .map(|&s| (PSlot::from_raw(s), persona(s)))
        .collect();
    let bonded: BTreeSet<PSlot> = bonded.iter().map(|&s| PSlot::from_raw(s)).collect();
    StakeEngineHandle::spawn(bundles, bonded, None)
}

/// A tiny test horizon so a sweep needs only a few real blocks.
fn cfg(reorg_depth: u64, batch_blocks: u64) -> PScanConfig {
    PScanConfig {
        reorg_depth,
        batch_blocks,
    }
}

#[tokio::test]
async fn sweep_accumulates_funding_and_advances_the_cursor() {
    let p = persona(0);
    // tip = 6, horizon = 6 - 4 = 2 → scan [0, 2). Funding output in block 1.
    let c = chain(6, &[(1, funding_block(&p))]);
    let src = source(c);
    let stake = spawn_stake(&[0]);
    let store = MemStore::default();
    let mut accrual = PScanAccrual::genesis();
    let mut retired = BTreeSet::new();

    pscan_sweep(
        &src,
        &stake,
        &store,
        &mut accrual,
        &mut retired,
        &mut (),
        &cfg(4, 1),
        &CancellationToken::new(),
    )
    .await
    .expect("sweep");

    assert_eq!(
        accrual.next_height(),
        BlockHeight::from_raw(2),
        "cursor at the horizon"
    );
    // Epoch 0 is in progress (< SETTLEMENT_EPOCH_BLOCKS), so finalized_inflow is
    // None, but the partial accrual is sealed.
    let sealed = store.load().await.expect("load").expect("sealed");
    assert_eq!(sealed.synced_height(), BlockHeight::from_raw(2));
    assert!(
        sealed.accrual_for(SettlementEpoch::from_raw(0)) > AtomicUnits::ZERO,
        "the persona's funding accumulated and sealed"
    );
}

#[tokio::test]
async fn resume_from_the_store_does_not_double_count() {
    let p = persona(0);
    // First sweep: tip = 5, horizon = 1 → scan [0, 1). Funding in block 0.
    let store = MemStore::default();
    let stake = spawn_stake(&[0]);
    {
        let src = source(chain(5, &[(0, funding_block(&p))]));
        let mut accrual = PScanAccrual::genesis();
        let mut retired = BTreeSet::new();
        pscan_sweep(
            &src,
            &stake,
            &store,
            &mut accrual,
            &mut retired,
            &mut (),
            &cfg(4, 4),
            &CancellationToken::new(),
        )
        .await
        .expect("sweep 1");
    }
    let after_first = store
        .load()
        .await
        .unwrap()
        .unwrap()
        .accrual_for(SettlementEpoch::from_raw(0));

    // "Crash + restart": reload the accrual from the store, grow the chain.
    let mut accrual = PScanAccrual::from_state(&store.load().await.unwrap().unwrap());
    assert_eq!(accrual.next_height(), BlockHeight::from_raw(1));
    let src = source(chain(6, &[(0, funding_block(&p)), (1, funding_block(&p))]));
    let mut retired = BTreeSet::new();
    // tip = 6, horizon = 2 → scan [1, 2) only (block 0 already counted).
    pscan_sweep(
        &src,
        &stake,
        &store,
        &mut accrual,
        &mut retired,
        &mut (),
        &cfg(4, 4),
        &CancellationToken::new(),
    )
    .await
    .expect("sweep 2");

    let after_second = accrual.to_state().accrual_for(SettlementEpoch::from_raw(0));
    assert_eq!(
        accrual.next_height(),
        BlockHeight::from_raw(2),
        "sweep 2 advanced the cursor 1→2 (it scanned [1,2), not [0,2))"
    );
    assert_eq!(
        after_second.to_raw(),
        after_first.to_raw() * 2,
        "blocks 0 and 1 each counted exactly once — block 0 not re-added on resume"
    );
}

#[tokio::test]
async fn sweep_halts_and_surfaces_on_a_boundary_mismatch_without_rewinding() {
    // The resume-splice (b) exists to forbid: the source serves a chain that does
    // NOT attach to our *own sealed* verified frontier. The cursor resumes at a
    // sealed `(height, hash)` frontier, but the served block's `previous` is a
    // different chain's hash. Given an honest tip this is a beyond-finality anomaly
    // (the frontier is below `ARCHIVAL_REORG_DEPTH_BLOCKS` of the real tip); under
    // an over-claiming source it could be an ordinary reorg the too-high horizon
    // admitted — either way the sweep must RAISE it, never silently rewind or
    // re-derive the anchor, because a silent recovery here re-introduces the (a)
    // vulnerability through the error path. (No fork-point machinery, unlike the
    // principal refresh: 2d-1 can't distinguish the two and halting is safe for both.)
    let p = persona(0);
    // tip=6, horizon=2 → scan [1, 2). Served block[1] chains to block[0], a hash
    // our (deliberately wrong) seeded anchor will not match.
    let src = source(chain(6, &[(1, funding_block(&p))]));
    let stake = spawn_stake(&[0]);
    let store = MemStore::default();

    let wrong_anchor = [0xEE; 32];
    let seeded = PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(1), wrong_anchor),
        BTreeMap::new(),
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    );
    store.save(&seeded).await.expect("seed");
    let mut accrual = PScanAccrual::from_state(&seeded);
    let mut retired = BTreeSet::new();

    let err = pscan_sweep(
        &src,
        &stake,
        &store,
        &mut accrual,
        &mut retired,
        &mut (),
        &cfg(4, 4),
        &CancellationToken::new(),
    )
    .await
    .expect_err("a boundary mismatch must surface, not be absorbed");

    // 1. RAISED as an exhaustiveness failure (the loud halt), not a transient that
    //    `run_pscan_task` would retry.
    assert!(
        matches!(err, PScanTaskError::Exhaustiveness(_)),
        "expected an exhaustiveness halt, got {err:?}"
    );
    // 2. The cursor did NOT advance past the mismatch.
    assert_eq!(
        accrual.next_height(),
        BlockHeight::from_raw(1),
        "the cursor must not advance over an unverified batch"
    );
    // 3. The anchor was NOT rewound and NOT re-derived from the served chain — a
    //    silent re-fetch of a new anchor IS the resume-splice (b) forbids.
    assert_eq!(
        accrual.frontier_hash(),
        wrong_anchor,
        "the sealed anchor is untouched: no silent rewind, no re-derived anchor"
    );
    // 4. Nothing was sealed past the mismatch (the store still holds the pre-sweep
    //    frontier — the halt left no partial advance behind).
    let sealed = store.load().await.expect("load").expect("state");
    assert_eq!(
        sealed.synced_height(),
        BlockHeight::from_raw(1),
        "no advance was sealed across the halt"
    );
}

#[test]
fn record_unbonds_records_only_unbond_posts() {
    let p = persona(0);
    // Drive record_unbonds with the extractor's output shape (the bond-post
    // matches a `ScanStepResult` carries), which is what the sweep feeds it.
    let mut accrual = PScanAccrual::genesis();
    let matches = vec![BondPostMatch {
        height: BlockHeight::from_raw(123),
        p_canonical_id: canonical_id(&p),
        post_kind: UNBOND_POST_KIND,
    }];
    record_unbonds(&mut accrual, &matches);
    assert_eq!(
        accrual.pending_unbonds().get(&canonical_id(&p)),
        Some(&SettlementEpoch::from_raw(0)),
        "an Unbond post at height 123 (epoch 0) is recorded durably"
    );

    // A non-Unbond post is ignored.
    let mut accrual2 = PScanAccrual::genesis();
    record_unbonds(
        &mut accrual2,
        &[BondPostMatch {
            height: BlockHeight::from_raw(1),
            p_canonical_id: canonical_id(&p),
            post_kind: 0, // JoinMarket
        }],
    );
    assert!(accrual2.pending_unbonds().is_empty());
}

#[tokio::test]
async fn dispatch_retires_an_expired_persona_and_dedups_within_session() {
    // A persona whose Unbond at epoch 0 has fallen out of the claim window:
    // settled = W + 1 ⇒ eligible. Build the accrual directly (a real scan to
    // settled = W+1 would be ~270k blocks).
    let p = persona(0);
    let cursor_height = (MAX_CLAIM_AGE_W + 2) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
    let mut pending = BTreeMap::new();
    pending.insert(canonical_id(&p), SettlementEpoch::from_raw(0));
    let state = PScanState::new(
        // Built for `dispatch_retires` (no sweep), so the frontier hash is inert.
        PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
        BTreeMap::new(),
        pending,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    );
    let mut accrual = PScanAccrual::from_state(&state);
    assert_eq!(
        accrual.settled_epoch(),
        Some(SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1))
    );

    let stake = spawn_stake(&[0]);
    let mut retired = BTreeSet::new();
    dispatch_retires(
        &stake,
        &mut accrual,
        &mut retired,
        &CancellationToken::new(),
        BlockHeight::from_raw(u64::MAX),
        PScanConfig::production(),
    )
    .await
    .expect("dispatch");
    assert!(
        retired.contains(&canonical_id(&p)),
        "the expired persona was retired"
    );

    // Dedup within the session: a second dispatch sends nothing new (the entry
    // stays in the accrual — the durable retire-trigger — but is suppressed).
    let before = retired.clone();
    dispatch_retires(
        &stake,
        &mut accrual,
        &mut retired,
        &CancellationToken::new(),
        BlockHeight::from_raw(u64::MAX),
        PScanConfig::production(),
    )
    .await
    .expect("dispatch 2");
    assert_eq!(retired, before, "no re-dispatch within the session");
    // SP-R0 arm #2 (semantics change, by design): under a corroborated
    // token (claimed_tip = MAX here) the durable prune fires with the
    // wipe — the pending entry is REMOVED in the same atomic mutation
    // that writes the retired-record. "Kept until SP-6 durably removes
    // the persona" has arrived at its removal.
    assert!(
        !accrual.pending_unbonds().contains_key(&canonical_id(&p)),
        "the corroborated durable prune removes the pending trigger"
    );
    assert_eq!(accrual.retired_pruned_total(), 1, "arm-#2 fire counter");
    assert_eq!(accrual.retired_records().len(), 1);
}

/// The funded-gate through the dispatch path (finding #1): an expired persona
/// whose slot still holds an unspent funding output is NOT retired — wiping it
/// would strand the funds (the wipe is irreversible and the open path stops
/// deriving a retired slot). The actor wipe is refused (`SkippedFunded`), no
/// durable prune fires, and the pending trigger survives for a later sweep
/// once the funding is drained.
#[tokio::test]
async fn dispatch_defers_retire_while_the_slot_holds_unspent_funding() {
    let p = persona(0);
    let cursor_height = (MAX_CLAIM_AGE_W + 2) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
    let mut pending = BTreeMap::new();
    pending.insert(canonical_id(&p), SettlementEpoch::from_raw(0));
    // A live, unspent funding output pinned to the persona's slot (slot 0).
    let funding = vec![crate::engine::test_support::funding_record(
        0, // p_slot — the retiring persona's slot
        7, // gindex
        5, // height
        1_000,
        shekyl_engine_state::pscan_state::MintLineageOutput::EmissionReward,
    )];
    let mut accrual = PScanAccrual::from_state(&PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
        BTreeMap::new(),
        pending,
        Vec::new(),
        funding,
        Vec::new(),
        BTreeMap::new(),
    ));
    assert_eq!(
        accrual.settled_epoch(),
        Some(SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1)),
        "the claim window has closed — retire is otherwise eligible"
    );

    let stake = spawn_stake(&[0]);
    let mut retired = BTreeSet::new();
    let pruned = dispatch_retires(
        &stake,
        &mut accrual,
        &mut retired,
        &CancellationToken::new(),
        BlockHeight::from_raw(u64::MAX), // fully corroborating tip
        PScanConfig::production(),
    )
    .await
    .expect("dispatch");
    assert!(
        !pruned,
        "a funded slot's retire is deferred — no durable prune"
    );
    assert!(
        retired.is_empty(),
        "the funded persona is NOT session-deduped — it is re-checked as draining proceeds"
    );
    assert!(
        accrual.pending_unbonds().contains_key(&canonical_id(&p)),
        "the durable pending trigger survives to re-fire once the funding drains"
    );
    assert!(accrual.retired_records().is_empty());
}

/// SP-R0 arm #2, DQ-D: a source claiming a LOW tip defers the durable
/// prune (the token clamp fails to corroborate the expiry) while the
/// actor wipe still fires on the frontier basis — fail-safe, and the
/// durable pending trigger survives to re-fire.
#[tokio::test]
async fn durable_prune_defers_when_the_claimed_tip_does_not_corroborate() {
    let p = persona(0);
    let cursor_height = (MAX_CLAIM_AGE_W + 2) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
    let mut pending = BTreeMap::new();
    pending.insert(canonical_id(&p), SettlementEpoch::from_raw(0));
    let mut accrual = PScanAccrual::from_state(&PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
        BTreeMap::new(),
        pending,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    ));
    let stake = spawn_stake(&[0]);
    let mut retired = BTreeSet::new();
    // A claimed tip at genesis: token = min(0, frontier + depth) ⇒ no
    // settled epoch at the token ⇒ no corroboration ⇒ no durable prune.
    let pruned = dispatch_retires(
        &stake,
        &mut accrual,
        &mut retired,
        &CancellationToken::new(),
        BlockHeight::from_raw(0),
        PScanConfig::production(),
    )
    .await
    .expect("dispatch");
    assert!(!pruned, "no durable prune without corroboration");
    assert!(
        retired.contains(&canonical_id(&p)),
        "the actor wipe still fired on the frontier basis"
    );
    assert!(
        accrual.pending_unbonds().contains_key(&canonical_id(&p)),
        "the durable pending trigger survives to re-fire"
    );
    assert_eq!(accrual.retired_pruned_total(), 0);
    assert!(accrual.retired_records().is_empty());
}

#[tokio::test]
async fn dispatch_does_not_retire_before_the_window_closes() {
    // settled = W exactly: U=0 is still the oldest claimable epoch → no retire.
    let p = persona(0);
    let cursor_height = (MAX_CLAIM_AGE_W + 1) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
    let mut pending = BTreeMap::new();
    pending.insert(canonical_id(&p), SettlementEpoch::from_raw(0));
    let mut accrual = PScanAccrual::from_state(&PScanState::new(
        // Built for `dispatch_retires` (no sweep), so the frontier hash is inert.
        PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
        BTreeMap::new(),
        pending,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    ));
    assert_eq!(
        accrual.settled_epoch(),
        Some(SettlementEpoch::from_raw(MAX_CLAIM_AGE_W))
    );

    let stake = spawn_stake(&[0]);
    let mut retired = BTreeSet::new();
    dispatch_retires(
        &stake,
        &mut accrual,
        &mut retired,
        &CancellationToken::new(),
        BlockHeight::from_raw(u64::MAX),
        PScanConfig::production(),
    )
    .await
    .expect("dispatch");
    assert!(
        retired.is_empty(),
        "U is still claimable at settled = U + W; retiring here would be stuck funds"
    );
}
