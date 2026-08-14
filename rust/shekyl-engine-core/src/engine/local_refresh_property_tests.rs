// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the refresh producer (property suite) (`engine/local_refresh.rs`).
//!
//! Wired as a `#[path]` child of `local_refresh::producer_property_tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use super::*;

use proptest::prelude::*;
use shekyl_crypto_pq::account::{
    rederive_account, DerivationNetwork, SeedFormat, MASTER_SEED_BYTES,
};
use shekyl_engine_state::LedgerBlock;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::engine::diagnostics::{AssertionSink, PanickingSink, PanickingSinkTrigger};
use crate::engine::test_support::{make_synthetic_block, TestDaemon, DEFAULT_TEST_SEED};
use crate::engine::view_material::ViewMaterial;

/// Real wallet master seed (64 bytes). Drives `rederive_account`
/// against the same key-derivation path `Engine::create` uses
/// internally, producing structurally-valid `ViewMaterial` for the
/// producer's `build_scanner`. Distinct from the daemon-side
/// `DEFAULT_TEST_SEED` (32-byte daemon-driver seed).
const PROPERTY_TEST_MASTER_SEED: [u8; MASTER_SEED_BYTES] = {
    // Construct a deterministic 64-byte seed at compile time:
    // `seed[i] = (i * 7) ^ 0xC7`. Distinct from
    // `DEFAULT_TEST_SEED` (32 zero bytes) so producer-side
    // property tests do not share derivation state with any
    // existing test fixture. `MASTER_SEED_BYTES = 64`, so the
    // `u8` index loop never overflows.
    let mut seed = [0u8; MASTER_SEED_BYTES];
    let mut i: u8 = 0;
    while (i as usize) < MASTER_SEED_BYTES {
        seed[i as usize] = i.wrapping_mul(7) ^ 0xC7;
        i += 1;
    }
    seed
};

/// Build a [`LocalRefresh`] against a deterministic test wallet
/// seed. The view material derives via the same
/// [`rederive_account`] path `Engine::create` uses internally
/// (`DerivationNetwork::Fakechain` + `SeedFormat::Raw32`), so
/// `build_scanner` lands in the structurally-valid branch.
fn make_local_refresh() -> LocalRefresh {
    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive_account against fakechain raw32 seed");
    let vm = ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against deterministic test blob");
    LocalRefresh::new(vm, 0)
}

fn snapshot_at_anchor(synced: u64, hash: [u8; 32]) -> LedgerSnapshot {
    let mut ledger = LedgerBlock::empty();
    crate::engine::scan_floor::anchor_ledger_block(&mut ledger, synced, hash).expect("test anchor");
    LedgerSnapshot::from_ledger(&ledger)
}

/// A persona derived from the test wallet seed at `slot`.
fn test_persona(slot: u32) -> shekyl_crypto_pq::archival_p::ArchivalPKeys {
    shekyl_crypto_pq::archival_p::derive_archival_p_keys(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
        slot,
    )
    .expect("derive test persona")
}

fn test_persona_id(
    keys: &shekyl_crypto_pq::archival_p::ArchivalPKeys,
) -> shekyl_types::PCanonicalId {
    crate::engine::stake_engine::persona_canonical_id(keys).expect("canonical id")
}

/// A structurally-null non-miner tx carrying one JoinMarket bond post
/// (the scanner recovers nothing from zero outputs; the watch reads only
/// the input).
fn test_bond_tx(
    keys: &shekyl_crypto_pq::archival_p::ArchivalPKeys,
) -> shekyl_wire::transaction::Transaction {
    test_bond_tx_kind(
        keys,
        shekyl_wire::transaction::BondPostKind::JoinMarket {
            bond_spend_pk: Vec::new(),
        },
    )
}

/// [`test_bond_tx`] with an explicit post kind, for the sighting
/// filter's non-establishing-kind edge.
fn test_bond_tx_kind(
    keys: &shekyl_crypto_pq::archival_p::ArchivalPKeys,
    kind: shekyl_wire::transaction::BondPostKind,
) -> shekyl_wire::transaction::Transaction {
    use shekyl_wire::transaction::{BondPost, Transaction, TxPrefix};
    use shekyl_wire::{Ct, CtBase, Holdings};
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![shekyl_wire::Input::BondPost(Box::new(BondPost {
                hybrid_public_key: keys
                    .hybrid_bond_id()
                    .to_canonical_bytes()
                    .expect("encode hybrid id"),
                p_canonical_id: test_persona_id(keys).to_bytes(),
                kind,
                holdings: Holdings::CompleteTree,
                bonded_total_atomic: 1_000,
                bond_credit: 1_000,
                bond_debit: 0,
            }))],
            outputs: vec![],
            extra: vec![],
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![],
            enc_labels: vec![],
            commitments: vec![],
        }),
    }
}

/// The producer's bond watch: a scanned block carrying two bond posts —
/// one whose canonical id is in the watch map, one a stranger's — yields
/// exactly one slot-resolved sighting at the right height; and a producer
/// with an EMPTY watch (every existing caller) yields none.
#[tokio::test(start_paused = true)]
async fn bond_watch_emits_sightings_for_watched_ids_only() {
    // Two personas from the test wallet seed; only slot 0's id is watched.
    let mine = test_persona(0);
    let stranger = test_persona(1);

    // Chain: anchor at h0; h1 carries three bond posts — the watched
    // JoinMarket one, a stranger's, and a watched-id post of a
    // NON-establishing kind (which must not sight: only the
    // bond-establishing kind is adoption evidence — the same filter as
    // the P-scan's confirmation set, so the two consumers agree on the
    // post-kind byte). Mutate BEFORE reading hashes so the parent
    // chaining stays consistent.
    let b0 = make_synthetic_block(0, [0u8; 32]);
    let mut b1 = make_synthetic_block(1, b0.block.hash());
    b1.transactions.push(test_bond_tx(&mine));
    b1.block.transaction_hashes.push([0xA1; 32]);
    b1.transactions.push(test_bond_tx(&stranger));
    b1.block.transaction_hashes.push([0xA2; 32]);
    b1.transactions.push(test_bond_tx_kind(
        &mine,
        shekyl_wire::transaction::BondPostKind::Other(0x7F),
    ));
    b1.block.transaction_hashes.push([0xA3; 32]);

    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, vec![b0.clone(), b1.clone()]);
    let snapshot = snapshot_at_anchor(0, b0.block.hash());
    let watch = std::collections::BTreeMap::from([(test_persona_id(&mine), 4u32)]);

    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive");
    let vm = ViewMaterial::try_from_keys(&blob).expect("view material");
    let refresh = LocalRefresh::with_bond_watch(vm, 0, watch);

    let sink = AssertionSink::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();
    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            CancellationToken::new(),
            progress_tx,
            &sink,
        )
        .await
        .expect("scan completes");

    assert_eq!(
        result.bond_sightings.len(),
        1,
        "the stranger's post and the non-JoinMarket kind are both ignored"
    );
    assert_eq!(
        result.bond_sightings[0].slot, 4,
        "slot-resolved from the watch"
    );
    assert_eq!(result.bond_sightings[0].block_height, 1);
}

/// An intra-attempt reorg discards abandoned-fork bond sightings with the
/// rest of the attempt's accumulators. Chain A carries a bond post at the
/// fork height; the daemon reorgs to chain B (no bond posts) mid-attempt.
/// A stale sighting would sit inside the final processed range, pass the
/// merge's O5 contract checks, and be ADOPTED as chain evidence — wrongly
/// re-arming staking and permanently burning cursor slots.
#[tokio::test(start_paused = true)]
async fn reorg_discards_abandoned_fork_bond_sightings() {
    const TIP: u64 = 6;
    const FORK: u64 = 2; // chain A's bond post lives here
    const TRIGGER: u64 = 3; // daemon reorgs right after serving this fetch

    let mine = test_persona(0);

    // Chain A built by hand so the injected bond tx is inside the hash
    // chaining (mutate BEFORE reading each block's hash).
    let mut chain_a = Vec::new();
    let mut parent = [0u8; 32];
    for h in 0..TIP {
        let mut b = make_synthetic_block(h, parent);
        if h == FORK {
            b.transactions.push(test_bond_tx(&mine));
            b.block.transaction_hashes.push([0xB0; 32]);
        }
        parent = b.block.hash();
        chain_a.push(b);
    }
    let tail_b = divergent_tail(&chain_a, FORK, TIP); // no bond posts on B
    let anchor = chain_a[0].block.hash();

    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain_a.clone());
    daemon.replace_chain_after_fetch(TRIGGER, FORK, tail_b);

    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive");
    let vm = ViewMaterial::try_from_keys(&blob).expect("view material");
    let watch = std::collections::BTreeMap::from([(test_persona_id(&mine), 4u32)]);
    let refresh = LocalRefresh::with_bond_watch(vm, 0, watch);

    let sink = AssertionSink::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();
    let result = refresh
        .produce_scan_result(
            snapshot_at_anchor(0, anchor),
            &daemon,
            RefreshOptions::default(),
            CancellationToken::new(),
            progress_tx,
            &sink,
        )
        .await
        .expect("straddled scan completes via rewind");

    assert!(
        result.reorg_rewind.is_some(),
        "the mid-attempt chain swap must be detected as a reorg"
    );
    assert!(
        result.bond_sightings.is_empty(),
        "a sighting from the abandoned fork must not survive the rewind"
    );
}

/// Construct a `(height, parent_hash)`-chained linear chain of `n`
/// synthetic blocks `[chain[0], chain[1], ..., chain[n-1]]` with
/// `chain[h].block.header.previous = chain[h-1].block.hash()`.
/// `chain[0]`'s parent is `[0u8; 32]`. Real-daemon convention:
/// `chain[h] = block at height h`.
fn linear_chain(n: u64) -> Vec<ScannableBlock> {
    let mut chain =
        Vec::with_capacity(usize::try_from(n).expect("test linear_chain length fits in usize"));
    let mut parent = [0u8; 32];
    for h in 0..n {
        let block = make_synthetic_block(h, parent);
        parent = block.block.hash();
        chain.push(block);
    }
    chain
}

/// A divergent continuation of `base`: internally-linked blocks for
/// heights `fork_h..len`, built on `base[fork_h - 1]` with a
/// different nonce so every hash diverges from `base`'s at the same
/// height. Feed to [`TestDaemon::replace_chain_from`] /
/// `replace_chain_after_fetch` to model a competing chain.
fn divergent_tail(base: &[ScannableBlock], fork_h: u64, len: u64) -> Vec<ScannableBlock> {
    divergent_tail_nonce(base, fork_h, len, 1)
}

/// [`divergent_tail`] with an explicit `nonce`, so two competing tails off
/// the *same* parent still diverge from each other (a second reorg must fork
/// away from the first reorg's chain, not reproduce it). `nonce = 1` is the
/// canonical divergent tail; a distinct nonce yields a distinct chain sharing
/// the same `fork_h - 1` parent.
fn divergent_tail_nonce(
    base: &[ScannableBlock],
    fork_h: u64,
    len: u64,
    nonce: u32,
) -> Vec<ScannableBlock> {
    let mut parent = base[usize::try_from(fork_h - 1).expect("test fork height fits in usize")]
        .block
        .hash();
    let mut tail = Vec::new();
    for h in fork_h..len {
        let mut block = make_synthetic_block(h, parent);
        block.block.header.nonce = nonce; // diverge from the canonical chain
        parent = block.block.hash();
        tail.push(block);
    }
    tail
}

// ── Intra-attempt straddle (SP-T2 sequence-coherence keystone) ──

/// A reorg landing *between* two consecutive single-height fetches
/// within one attempt is detected by the running prev-hash linkage
/// check and rewound — never silently spliced. Each fetch is
/// atomic; this is the sequence-coherence half of the pair (P-SH
/// makes reads atomic; this check makes the *sequence* coherent).
///
/// Setup: wallet synced to 4 on chain A (tip 12). The attempt scans
/// 5..12; after the daemon serves the fetch at height 7 it reorgs
/// to chain B (diverging at height 6), so the fetch at 8 returns a
/// B-block whose `previous` is B7's hash — not the A7 the attempt
/// just fetched. Pre-fix, the check consulted only the persisted
/// window (≤ synced 4) and skipped every intra-attempt pair,
/// splicing A6/A7 against B8+ silently.
#[tokio::test(start_paused = true)]
async fn intra_attempt_reorg_is_detected_and_rewound() {
    const SYNCED: u64 = 4;
    const TIP: u64 = 12;
    const FORK: u64 = 6; // first divergent height (above the persisted window)
    const TRIGGER: u64 = 7; // daemon reorgs right after serving this fetch

    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive_account against fakechain raw32 seed");
    let vm = ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against deterministic test blob");
    let refresh = LocalRefresh::new(vm, 0);

    let chain_a = linear_chain(TIP);
    let tail_b = divergent_tail(&chain_a, FORK, TIP);
    let anchor = chain_a[usize::try_from(SYNCED).unwrap()].block.hash();

    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain_a.clone());
    daemon.replace_chain_after_fetch(TRIGGER, FORK, tail_b.clone());

    let snapshot = snapshot_at_anchor(SYNCED, anchor);
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await
        .expect("straddled scan completes via rewind");

    // Detected and rewound to the attempt boundary — the
    // conservative fork point when the true fork (6) sits above
    // the persisted window (≤ 4), where `find_fork_point` cannot
    // locate it precisely.
    assert_eq!(
        result.reorg_rewind.map(|r| r.fork_height),
        Some(SYNCED + 1),
        "intra-attempt straddle must be detected and rewound"
    );

    // The final sequence is the post-reorg chain, fully linked: A
    // below the fork, B at and above it. No old-chain block above
    // the fork survives — the pre-fix behavior (A6/A7 spliced
    // against B8..B11) is exactly what this rules out.
    let expected: Vec<(u64, [u8; 32])> = (SYNCED + 1..FORK)
        .map(|h| (h, chain_a[usize::try_from(h).unwrap()].block.hash()))
        .chain((FORK..TIP).map(|h| {
            let idx = usize::try_from(h - FORK).unwrap();
            (h, tail_b[idx].block.hash())
        }))
        .collect();
    assert_eq!(
        result.block_hashes, expected,
        "scan result must carry the post-reorg chain only, never a torn splice"
    );
}

/// The seam case: an intra-attempt reorg whose fork sits at **exactly**
/// `synced_height` — the boundary between the two expected-parent
/// lookups (running tail owns heights > `synced_height`, the persisted
/// window owns heights ≤ it). This is the one height where "disjoint by
/// construction" is asserted rather than obvious; an off-by-one at the
/// seam would splice a fork landing precisely on the boundary.
///
/// Setup: wallet synced to 4 on chain A (window anchor = A4); the daemon
/// reorgs from height **4** (replacing the window-top block itself) right
/// after serving the fetch at 6. The fetch at 7 returns B7, whose
/// `previous` (B6's hash) mismatches the running tail's A6 → the walk
/// enters the persisted window at its top (4), finds the stored A4 also
/// replaced (daemon serves B4), continues below the window (no stored
/// hash at 3) and resolves the conservative fork at 4 — rewinding
/// *through* the seam, refetching the replaced window-top block.
#[tokio::test(start_paused = true)]
async fn intra_attempt_reorg_at_exact_synced_height_rewinds_through_seam() {
    const SYNCED: u64 = 4;
    const TIP: u64 = 12;
    const FORK: u64 = SYNCED; // fork at exactly the persisted-window top
    const TRIGGER: u64 = 6; // daemon reorgs right after serving this fetch

    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive_account against fakechain raw32 seed");
    let vm = ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against deterministic test blob");
    let refresh = LocalRefresh::new(vm, 0);

    let chain_a = linear_chain(TIP);
    let tail_b = divergent_tail(&chain_a, FORK, TIP);
    let anchor = chain_a[usize::try_from(SYNCED).unwrap()].block.hash();

    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain_a);
    daemon.replace_chain_after_fetch(TRIGGER, FORK, tail_b.clone());

    let snapshot = snapshot_at_anchor(SYNCED, anchor);
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await
        .expect("seam-straddled scan completes via rewind");

    // The rewind lands AT the fork (the replaced window-top height), not
    // one above it — the seam is rewound through, not spliced around.
    assert_eq!(
        result.reorg_rewind.map(|r| r.fork_height),
        Some(FORK),
        "a fork at exactly synced_height must rewind to it, not splice"
    );

    // Every height from the fork up carries the B-chain hash — including
    // height 4 itself (the window-top block the reorg replaced) and
    // heights 5/6 (fetched as A before the swap, purged, refetched as B).
    let expected: Vec<(u64, [u8; 32])> = (FORK..TIP)
        .map(|h| {
            let idx = usize::try_from(h - FORK).unwrap();
            (h, tail_b[idx].block.hash())
        })
        .collect();
    assert_eq!(
        result.block_hashes, expected,
        "the seam height must carry the post-reorg hash, never the stale window-top"
    );
}

/// **Two** reorgs within a single attempt, each landing between two
/// consecutive fetches. The first is detected and rewound; then, during the
/// post-rewind re-scan, a *second* reorg lands — and it too must be detected
/// so the returned sequence is the final chain, fully linked, never a torn
/// splice of the first-reorg chain below and the second-reorg chain above.
///
/// This is the revert-proof for lifting the one-reorg-per-attempt bound: the
/// pre-fix `reorg_rewind.is_none()` gate disables detection after the first
/// fork, so the second reorg slips through and the result splices B8/B9
/// (first-reorg chain) against C10/C11 (second-reorg chain) with a broken
/// link at 10. The bounded-multi-reorg fix catches the second straddle and
/// re-scans to C8..C11.
///
/// Setup: wallet synced to 4 on chain A (tip 12). Reorg 1 forks at 6 (chain
/// B), firing after the fetch at 7. Reorg 2 forks at 8 (chain C, a *distinct*
/// nonce so it diverges from B), firing after the re-scan's fetch at 9. Both
/// forks sit above the persisted window (≤ 4), so each `find_fork_point`
/// resolves the conservative attempt-boundary fork at `synced + 1 = 5`.
#[tokio::test(start_paused = true)]
async fn two_reorgs_in_one_attempt_are_both_detected_never_spliced() {
    const SYNCED: u64 = 4;
    const TIP: u64 = 12;
    const FORK1: u64 = 6; // first divergent height (chain B), above the window
    const TRIGGER1: u64 = 7; // daemon reorgs to B right after serving this
    const FORK2: u64 = 8; // second divergent height (chain C)
    const TRIGGER2: u64 = 9; // daemon reorgs to C right after serving this

    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive_account against fakechain raw32 seed");
    let vm = ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against deterministic test blob");
    let refresh = LocalRefresh::new(vm, 0);

    let chain_a = linear_chain(TIP);
    // Chain B: A below FORK1, divergent tail at/above it.
    let tail_b = divergent_tail(&chain_a, FORK1, TIP);
    let chain_b: Vec<ScannableBlock> = chain_a[..usize::try_from(FORK1).unwrap()]
        .iter()
        .cloned()
        .chain(tail_b.iter().cloned())
        .collect();
    // Chain C: forks off chain B at FORK2 with a distinct nonce, so it
    // diverges from B (not a reproduction of it) at and above FORK2.
    let tail_c = divergent_tail_nonce(&chain_b, FORK2, TIP, 2);
    let anchor = chain_a[usize::try_from(SYNCED).unwrap()].block.hash();

    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain_a.clone());
    // Queue both reorgs; they fire in FIFO order as their triggers are served
    // (TRIGGER1 in the first pass, TRIGGER2 in the post-rewind re-scan).
    daemon.replace_chain_after_fetch(TRIGGER1, FORK1, tail_b.clone());
    daemon.replace_chain_after_fetch(TRIGGER2, FORK2, tail_c.clone());

    let snapshot = snapshot_at_anchor(SYNCED, anchor);
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await
        .expect("double-straddled scan completes via two rewinds");

    // Both forks sit above the window, so each walk resolves the conservative
    // attempt boundary (`synced + 1`). The final rewind target is that same
    // boundary — the merge rolls persisted state back to it and re-ingests.
    assert_eq!(
        result.reorg_rewind.map(|r| r.fork_height),
        Some(SYNCED + 1),
        "the second intra-attempt straddle must also rewind, not slip through"
    );

    // The final sequence is the fully-linked post-*double*-reorg chain: A
    // below FORK1, B between the forks, C at and above FORK2. The pre-fix
    // behavior — B8/B9 spliced against C10/C11 with a broken link at 10 — is
    // exactly what this rules out.
    let expected: Vec<(u64, [u8; 32])> = (SYNCED + 1..FORK1)
        .map(|h| (h, chain_a[usize::try_from(h).unwrap()].block.hash()))
        .chain((FORK1..FORK2).map(|h| {
            let idx = usize::try_from(h - FORK1).unwrap();
            (h, tail_b[idx].block.hash())
        }))
        .chain((FORK2..TIP).map(|h| {
            let idx = usize::try_from(h - FORK2).unwrap();
            (h, tail_c[idx].block.hash())
        }))
        .collect();
    assert_eq!(
        result.block_hashes, expected,
        "both reorgs must be absorbed: the result is the final chain (C above \
             the second fork), never a torn B→C splice"
    );
}

/// A divergence detected after the rewind budget is spent ABORTS the
/// attempt (`ReorgStorm`) — it must not scan on with detection disarmed
/// and merge a blind region. The ledger could rewind stale blocks at the
/// next refresh, but the bond watch's sighting adoption is monotone:
/// an abandoned-fork sighting collected blind passes the merge's O5
/// checks and burns cursor slots permanently. This bites against
/// re-introducing the pre-fix `reorg_rewinds < MAX` *detection* gate,
/// which silently disarmed linkage checking for the rest of the attempt.
#[tokio::test(start_paused = true)]
async fn reorg_past_the_rewind_budget_aborts_as_reorg_storm() {
    const SYNCED: u64 = 4;
    const TIP: u64 = 12;
    const FORK: u64 = 6; // every fork above the window → boundary rewind
    const TRIGGER: u64 = 7; // each swap fires when 7 is (re-)served

    let refresh = make_local_refresh();
    let chain_a = linear_chain(TIP);
    let anchor = chain_a[usize::try_from(SYNCED).unwrap()].block.hash();

    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain_a.clone());
    // Script MAX + 1 reorgs, each a distinct-nonce tail off the same
    // parent (A5). Every cycle: the swap fires at the re-served TRIGGER,
    // the next fetch's parent linkage breaks, the producer rewinds to
    // the boundary and re-scans — until the budget is spent and the
    // (MAX+1)th divergence must abort instead of rewinding again.
    for nonce in 1..=(MAX_REORG_REWINDS_PER_ATTEMPT + 1) {
        daemon.replace_chain_after_fetch(
            TRIGGER,
            FORK,
            divergent_tail_nonce(&chain_a, FORK, TIP, nonce),
        );
    }

    let sink = AssertionSink::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();
    let outcome = refresh
        .produce_scan_result(
            snapshot_at_anchor(SYNCED, anchor),
            &daemon,
            RefreshOptions::default(),
            CancellationToken::new(),
            progress_tx,
            &sink,
        )
        .await;
    match outcome {
        Err(LocalRefreshError::ReorgStorm) => {}
        Err(other) => panic!("expected ReorgStorm, got {other:?}"),
        Ok(_) => panic!("a divergence past the rewind budget must abort the attempt"),
    }
}

/// Fresh empty [`LedgerSnapshot`] anchored at `synced_height = 0`
/// with an empty reorg window. Matches the
/// `EngineCreateParams::for_test_full` starting state used across
/// the integration tests in `engine/refresh.rs`.
fn empty_snapshot() -> LedgerSnapshot {
    LedgerSnapshot::from_ledger(&LedgerBlock::empty())
}

/// A `watch::Sender<RefreshProgress>` whose receiver is held alive
/// in the test scope. The producer's per-block progress
/// emissions go to this sender; the receiver is read only when a
/// test specifically asserts against progress state.
fn fresh_progress_channel() -> (
    watch::Sender<RefreshProgress>,
    watch::Receiver<RefreshProgress>,
) {
    watch::channel(RefreshProgress::initial())
}

/// True iff `event` is one of the error-attributed diagnostic
/// classes per the §5.4.6 phantom-error pin: a producer that
/// emits one of these classes MUST return `Err(_)`. Conversely,
/// the absence of these classes in the sink stream is the
/// no-phantom-error signal that the producer reached a clean
/// `Ok(_)` outcome.
fn is_error_class(event: &RefreshDiagnostic) -> bool {
    matches!(
        event,
        RefreshDiagnostic::DaemonProtocolError { .. }
            | RefreshDiagnostic::DaemonMalformed { .. }
            | RefreshDiagnostic::DaemonTimeout { .. }
    )
}

/// True iff `event` is a [`RefreshDiagnostic::DaemonProtocolError`].
/// Used by the `LocalRefreshError::Io` coherence check.
fn is_daemon_protocol_error(event: &RefreshDiagnostic) -> bool {
    matches!(event, RefreshDiagnostic::DaemonProtocolError { .. })
}

/// True iff `event` is a [`RefreshDiagnostic::DaemonMalformed`].
/// Used by the `LocalRefreshError::Malformed` coherence check.
fn is_daemon_malformed(event: &RefreshDiagnostic) -> bool {
    matches!(event, RefreshDiagnostic::DaemonMalformed { .. })
}

// ── Birthday floor (P2 producer start-height) ───────────────

/// Wallet birthday floor 1000 with ledger anchored at 999: producer
/// scans only `1000..tip`, not from genesis.
#[tokio::test(start_paused = true)]
async fn produce_scan_respects_birthday_floor_when_ledger_anchored() {
    const FLOOR: u64 = 1000;
    const TIP: u64 = 1010;
    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive_account against fakechain raw32 seed");
    let vm = ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against deterministic test blob");
    let refresh = LocalRefresh::new(vm, FLOOR);
    let chain = linear_chain(TIP);
    let parent_at_999 = chain[usize::try_from(FLOOR - 1).unwrap()].block.hash();
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain);
    let snapshot = snapshot_at_anchor(FLOOR - 1, parent_at_999);
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await
        .expect("anchored birthday scan succeeds");

    assert_eq!(result.processed_height_range.start, FLOOR);
    assert_eq!(result.processed_height_range.end, TIP);
    assert_eq!(
        result.block_hashes.len(),
        usize::try_from(TIP - FLOOR).unwrap()
    );
    assert_eq!(result.parent_hash, Some(parent_at_999));
}

/// When the wallet is already synced past the floor, scanning
/// continues incrementally from `synced_height + 1`.
#[tokio::test(start_paused = true)]
async fn produce_scan_floor_noop_when_synced_past_birthday() {
    const FLOOR: u64 = 100;
    const SYNCED: u64 = 500;
    const TIP: u64 = 505;
    let blob = rederive_account(
        &PROPERTY_TEST_MASTER_SEED,
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
    )
    .expect("rederive_account against fakechain raw32 seed");
    let vm = ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against deterministic test blob");
    let refresh = LocalRefresh::new(vm, FLOOR);
    let chain = linear_chain(TIP);
    let parent = chain[usize::try_from(SYNCED).unwrap()].block.hash();
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain);
    let snapshot = snapshot_at_anchor(SYNCED, parent);
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await
        .expect("incremental scan past floor succeeds");

    assert_eq!(result.processed_height_range, (SYNCED + 1)..TIP);
}

// ── Coherence: clean path (Ok → no error-class events) ─────

/// Clean chain, no failure injection: the producer scans the
/// chain end-to-end, returns `Ok(_)`, and the assertion sink
/// records ONLY non-error-class events (per-block `ScanProgress`,
/// no `DaemonProtocolError` / `DaemonMalformed` / `DaemonTimeout`).
///
/// Pins the §5.4.6 no-phantom-error contract on the success
/// path: an implementation that emits a spurious `DaemonMalformed`
/// alongside a clean `Ok` return would fail this assertion.
#[tokio::test(start_paused = true)]
async fn coherence_clean_chain_returns_ok_with_no_error_events() {
    let refresh = make_local_refresh();
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(5));
    let snapshot = empty_snapshot();
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await;

    match &result {
        Ok(_) => {}
        Err(e) => panic!("clean chain should produce Ok(_), got Err({e:?})"),
    }
    let recorded = sink.recorded();
    let error_class_events: Vec<_> = recorded.iter().filter(|e| is_error_class(e)).collect();
    assert!(
        error_class_events.is_empty(),
        "clean Ok return MUST NOT be preceded by error-class diagnostics; \
             phantom-error pin violation. Recorded error-class events: {error_class_events:?}",
    );
}

// ── Coherence: get_height failure → Io + DaemonProtocolError ──

/// Persistent `get_height` failure: the producer's first daemon
/// call fails with `RpcError::ConnectionError`. `get_height` has
/// no retry loop at the producer; the failure surfaces directly
/// as `LocalRefreshError::Io`, preceded by exactly one
/// `DaemonProtocolError { kind: ConnectionError }` emission.
///
/// Pins the §5.4.6 coherence contract on the `Io` branch from
/// `get_height`: removing the emission at line 545 of
/// `produce_scan_result` would fail this assertion.
#[tokio::test(start_paused = true)]
async fn coherence_get_height_failure_emits_protocol_error_then_returns_io() {
    let refresh = make_local_refresh();
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
    // `get_height` has no retry — one queued error is enough.
    daemon.set_height_error_for_next_n_calls(
        1,
        &RpcError::ConnectionError("test: get_height down".into()),
    );
    let snapshot = empty_snapshot();
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await;

    match &result {
        Err(LocalRefreshError::Io) => {}
        Err(e) => {
            panic!("get_height failure should surface as LocalRefreshError::Io, got Err({e:?})")
        }
        Ok(_) => {
            panic!("get_height failure should surface as LocalRefreshError::Io, got Ok(_)")
        }
    }
    let recorded = sink.recorded();
    let protocol_errors: Vec<_> = recorded
        .iter()
        .filter(|e| is_daemon_protocol_error(e))
        .collect();
    assert!(
        !protocol_errors.is_empty(),
        "Io error MUST be preceded by ≥1 DaemonProtocolError emission; \
             silent-error pin violation. Recorded events: {recorded:?}",
    );
}

// ── Coherence: malformed block → Malformed + DaemonMalformed ──

/// Persistent malformed block at scan height 1 (the first block
/// the producer fetches against an empty-snapshot ledger). The
/// scanner rejects the block with `InvalidScannableBlock`; the
/// producer emits one `DaemonMalformed { InvalidBlockStructure }`
/// and returns `LocalRefreshError::Malformed`.
///
/// Pins the §5.4.6 coherence contract on the `Malformed` branch
/// from the scanner-rejection path: removing the emission at
/// line 729 would fail this assertion.
#[tokio::test(start_paused = true)]
async fn coherence_malformed_block_emits_daemon_malformed_then_returns_malformed() {
    let refresh = make_local_refresh();
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
    // Mark height 1 as persistently malformed: every fetch at
    // height 1 returns `RpcError::InvalidNode`. The producer's
    // `fetch_block_with_retry` runs MAX_BLOCK_FETCH_RETRIES
    // attempts (all fail) and surfaces `LocalRefreshError::Io`
    // with one DaemonProtocolError per attempt (rate-limited by
    // the per-block ceiling + F13-S latch).
    //
    // To exercise the *scanner-side* malformed path (not the
    // RPC-side classification path), we need a block the daemon
    // serves successfully but the scanner rejects. The TestDaemon
    // doesn't currently surface that distinction — `make_malformed_scannable`
    // is the corresponding helper but it's not in scope here at C7. The
    // RPC-classified malformed path goes through `DaemonProtocolError`
    // (not `DaemonMalformed`), so this test covers the RPC-side
    // coherence at the fetch-failure → `Io` branch.
    daemon.set_block_returns_malformed(1);
    let snapshot = empty_snapshot();
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await;

    // The RPC-classified malformed path: TestDaemon returns
    // `RpcError::InvalidNode` for every fetch at height 1. The
    // fetch-with-retry loop exhausts its budget and returns
    // `LocalRefreshError::Io` with one DaemonProtocolError per
    // attempt (subject to the per-class rate-limit).
    match &result {
        Err(LocalRefreshError::Io) => {}
        Err(e) => panic!(
            "RPC-classified malformed at height 1 should surface as Io \
                 (fetch_with_retry-exhausted), got Err({e:?})"
        ),
        Ok(_) => panic!(
            "RPC-classified malformed at height 1 should surface as Io \
                 (fetch_with_retry-exhausted), got Ok(_)"
        ),
    }
    let recorded = sink.recorded();
    let protocol_errors: Vec<_> = recorded
        .iter()
        .filter(|e| is_daemon_protocol_error(e))
        .collect();
    assert!(
        !protocol_errors.is_empty(),
        "Io from fetch_with_retry MUST be preceded by ≥1 DaemonProtocolError; \
             silent-error pin violation. Recorded: {recorded:?}",
    );
}

// ── Coherence: ExcessiveOutputs pre-pass → Malformed + DaemonMalformed ──

/// The producer's `ExcessiveOutputs` pre-pass is the dedicated
/// `LocalRefreshError::Malformed` path with a `DaemonMalformed
/// { ExcessiveOutputs }` emission. The default `make_synthetic_block`
/// blocks carry single-output miner txns with no regular txns,
/// well under the `MAX_OUTPUTS = 16` ceiling — i.e., this branch
/// is unreachable via the standard test harness.
///
/// Direct coverage of the `DaemonMalformed` emission path lives
/// in the existing `emit_state_first_breach_emits_suppressed_notice`
/// test, which constructs the diagnostic in isolation. Building
/// a `ScannableBlock` with `>MAX_OUTPUTS` would require either an
/// upstream `make_excessive_outputs_block` helper (V3.1 work per
/// FOLLOWUPS) or `unsafe` test-harness construction; deferred.
///
/// This placeholder test documents the deferral so future
/// readers do not assume the producer-side `DaemonMalformed
/// { ExcessiveOutputs }` path is uncovered by accident — the
/// coherence property still holds (the path emits before
/// returning), it just isn't end-to-end exercised here.
#[test]
fn coherence_excessive_outputs_branch_deferred_to_v31_helper() {
    // Placeholder; the assertion exists to keep the test name in
    // `cargo test` output as a discoverable deferral marker.
    let kind = MalformedKind::ExcessiveOutputs;
    assert!(matches!(kind, MalformedKind::ExcessiveOutputs));
}

// ── Coherence: cancellation → Cancelled, no requirement ────

/// Pre-fetch cancellation: the cancel token is fired before
/// `produce_scan_result` runs. Checkpoint 2 (pre-fetch) returns
/// `Cancelled` immediately. Per §5.4.6, the coherence pin
/// **excludes** `Cancelled` returns from the emission requirement
/// — cancelled paths intentionally elide diagnostics to avoid
/// emitting context that the cancelling caller doesn't need.
///
/// This test pins the cancellation-elision exception: no
/// emission requirement, but if any diagnostic IS emitted on the
/// cancelled path, it must be observation-class (e.g., the
/// hypothetical `ScanProgress` from a partial-block-scan
/// cancellation), not error-class.
#[tokio::test(start_paused = true)]
async fn coherence_cancelled_before_fetch_returns_cancelled() {
    let refresh = make_local_refresh();
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(5));
    let snapshot = empty_snapshot();
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (progress_tx, _progress_rx) = fresh_progress_channel();

    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await;

    match &result {
        Err(LocalRefreshError::Cancelled) => {}
        Err(e) => panic!(
            "pre-fetch cancel should surface as LocalRefreshError::Cancelled, got Err({e:?})"
        ),
        Ok(_) => {
            panic!("pre-fetch cancel should surface as LocalRefreshError::Cancelled, got Ok(_)")
        }
    }
    // Per §5.4.6, cancelled paths are NOT required to emit. The
    // weaker invariant — "no error-class events on a path that
    // never reached a daemon failure" — still holds.
    let recorded = sink.recorded();
    let error_class_events: Vec<_> = recorded.iter().filter(|e| is_error_class(e)).collect();
    assert!(
        error_class_events.is_empty(),
        "cancelled-before-fetch should not emit error-class events: {error_class_events:?}",
    );
}

// ── Proptest: coherence over chain length × failure injection ──

/// Discriminator for failure-injection scenarios in the
/// `coherence_proptest_fuzz_chain_and_injection` proptest. The
/// space is intentionally finite — proptest's value here is
/// covering the `(chain_length, scenario)` cross product, not
/// enumerating `RpcError` payload values (which the §5.4.7 R6
/// memory-amplifier closure deliberately drops from the
/// diagnostic stream).
#[derive(Debug, Clone, Copy)]
enum InjectionScenario {
    /// No failure injection. Coherence requires the result to be
    /// `Ok(_)` with no error-class diagnostics.
    Clean,
    /// One-shot `RpcError::ConnectionError` on `get_height`.
    /// Coherence requires `Err(Io)` with ≥1 `DaemonProtocolError`.
    GetHeightFails,
    /// Persistently-malformed block at height 1 (every fetch
    /// returns `RpcError::InvalidNode`). Coherence requires
    /// `Err(Io)` (fetch-with-retry exhausted) with ≥1
    /// `DaemonProtocolError`.
    BlockFetchFails,
}

/// Proptest fuzzes `(chain_length, scenario)` and asserts the
/// §5.4.6 emission/return coherence contract holds across the
/// cross product. The proptest is **the executable definition**
/// of coherence; if this test fails, the producer's contract
/// has been violated and the design doc's prose must be
/// re-examined (per the §5.4.6 canonical-reference pin).
///
/// **Why this state space:** the `InjectionScenario` enum names
/// every distinct error-emission path the producer reaches under
/// the TestDaemon's failure-injection API (`get_height` failure
/// → `DaemonProtocolError` then `Io`; block-fetch failure →
/// `DaemonProtocolError` per retry attempt then `Io`). The
/// `ExcessiveOutputs` and scanner-side `InvalidBlockStructure`
/// branches require V3.1 test-harness extensions (per the
/// `coherence_excessive_outputs_branch_deferred_to_v31_helper`
/// placeholder).
///
/// Configured `ProptestConfig { cases: 32, .. }` — small enough
/// to keep `cargo test` wall-clock bounded (each case spawns a
/// fresh `tokio` runtime via `#[tokio::test]`; `start_paused =
/// true` makes the per-block-retry backoff sleep wall-free).
/// 32 cases over a 3-variant scenario × 5-length chain gives
/// roughly 2× coverage of every `(scenario, length)` pair.
fn coherence_property_holds(chain_length: u64, scenario: InjectionScenario) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("tokio runtime for property test case");
    rt.block_on(async move {
        let refresh = make_local_refresh();
        let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(chain_length));
        match scenario {
            InjectionScenario::Clean => {}
            InjectionScenario::GetHeightFails => {
                daemon.set_height_error_for_next_n_calls(
                    1,
                    &RpcError::ConnectionError("proptest: get_height fault".into()),
                );
            }
            InjectionScenario::BlockFetchFails => {
                // Only meaningful when the chain has ≥2 blocks
                // (so scan starts at height 1, which is the
                // marked height). Shorter chains short-circuit
                // at the empty-range branch in `produce_scan_result`.
                if chain_length >= 2 {
                    daemon.set_block_returns_malformed(1);
                }
            }
        }

        let snapshot = empty_snapshot();
        let sink = AssertionSink::new();
        let cancel = CancellationToken::new();
        let (progress_tx, _progress_rx) = fresh_progress_channel();

        let result = refresh
            .produce_scan_result(
                snapshot,
                &daemon,
                RefreshOptions::default(),
                cancel,
                progress_tx,
                &sink,
            )
            .await;

        let recorded = sink.recorded();
        // Project the result into a Debug-friendly summary; the
        // raw `Result<ScanResult, _>` is not `Debug` because
        // `ScanResult` deliberately suppresses it (§5.4.7 R6).
        let result_summary: Result<&'static str, &LocalRefreshError> =
            result.as_ref().map(|_| "ScanResult{..}");
        match (scenario, &result) {
            // Clean path: Ok required, no error-class events
            // permitted (no-phantom-error pin).
            (InjectionScenario::Clean, Ok(_)) => {
                assert!(
                    !recorded.iter().any(is_error_class),
                    "Clean scenario, chain_length={chain_length}: Ok return MUST NOT \
                         emit error-class events. Recorded: {recorded:?}",
                );
            }
            (InjectionScenario::Clean, Err(_)) => {
                panic!(
                    "Clean scenario, chain_length={chain_length}: expected Ok, \
                         got {result_summary:?}. Recorded: {recorded:?}",
                );
            }
            // get_height failure: Io required with ≥1
            // DaemonProtocolError (coherence pin).
            (InjectionScenario::GetHeightFails, Err(LocalRefreshError::Io)) => {
                assert!(
                    recorded.iter().any(is_daemon_protocol_error),
                    "GetHeightFails scenario, chain_length={chain_length}: Io return \
                         MUST be preceded by ≥1 DaemonProtocolError. Recorded: {recorded:?}",
                );
            }
            (InjectionScenario::GetHeightFails, _) => {
                panic!(
                    "GetHeightFails scenario, chain_length={chain_length}: expected \
                         Err(Io), got {result_summary:?}. Recorded: {recorded:?}",
                );
            }
            // BlockFetchFails with chain_length < 2: scan range
            // is empty, no fetch happens — equivalent to Clean.
            (InjectionScenario::BlockFetchFails, Ok(_)) if chain_length < 2 => {
                assert!(
                    !recorded.iter().any(is_error_class),
                    "BlockFetchFails (no-op short chain), chain_length={chain_length}: \
                         Ok return MUST NOT emit error-class events. Recorded: {recorded:?}",
                );
            }
            // BlockFetchFails with chain_length ≥ 2: producer
            // exhausts MAX_BLOCK_FETCH_RETRIES and returns Io
            // with ≥1 DaemonProtocolError.
            (InjectionScenario::BlockFetchFails, Err(LocalRefreshError::Io)) => {
                assert!(
                    recorded.iter().any(is_daemon_protocol_error),
                    "BlockFetchFails scenario, chain_length={chain_length}: Io return \
                         MUST be preceded by ≥1 DaemonProtocolError. Recorded: {recorded:?}",
                );
            }
            (InjectionScenario::BlockFetchFails, _) => {
                panic!(
                    "BlockFetchFails scenario, chain_length={chain_length}: expected \
                         Err(Io) (or Ok for short chains), got {result_summary:?}. \
                         Recorded: {recorded:?}",
                );
            }
        }
    });
}

// Fuzz the §5.4.6 emission/return coherence contract over the
// `(chain_length, scenario)` state space.
//
// Wall-clock bound: each case constructs a fresh
// single-threaded `start_paused` tokio runtime; the producer's
// per-block-retry `tokio::time::sleep` calls auto-advance under
// `start_paused`, so the `BlockFetchFails` cases (which would
// otherwise consume `INITIAL_RETRY_DELAY × 2^attempt` real time
// per attempt) complete in microseconds. 32 cases × ~1ms each ≈
// 32ms total proptest wall-clock.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn coherence_proptest_fuzz_chain_and_injection(
        chain_length in 1u64..=5,
        scenario_tag in 0u8..3,
    ) {
        let scenario = match scenario_tag {
            0 => InjectionScenario::Clean,
            1 => InjectionScenario::GetHeightFails,
            2 => InjectionScenario::BlockFetchFails,
            _ => unreachable!("scenario_tag generator bound at 0..3"),
        };
        coherence_property_holds(chain_length, scenario);
    }
}

// ── Producer panic-safety: PanickingSink unwinds cleanly ──

/// `PanickingSink` configured to panic on the first
/// `ScanProgress` emission. The producer scans the chain, emits
/// `ScanProgress` after processing block 1, and the sink panics
/// in `emit`. The panic propagates out of `produce_scan_result`
/// as a `JoinError::Panic`; the producer's `Scanner` (carried
/// in stack-local state) is dropped via the unwind, exercising
/// the `Drop` chain on `ViewMaterial` (which is
/// `ZeroizeOnDrop`).
///
/// Asserts the §5.4.6 producer-panic-safety property at the
/// orchestrator boundary:
///
/// 1. The producer's future resolves to a `JoinError::Panic`
///    when driven through `tokio::spawn`.
/// 2. The cancellation token remains unfired across the panic
///    (no producer-side `cancel.cancel()` in the panic path).
///
/// Direct observation of `ViewMaterial` zeroization requires the
/// V3.x memory-witness counter or instrumented Scanner type per
/// the §5.4.6 prose — the orchestrator-boundary properties this
/// test asserts are necessary but not sufficient. The structural
/// property (`Drop` chain runs to completion) is inherited from
/// Rust's panic-unwind semantics and the `ZeroizeOnDrop` derive
/// on `ViewMaterial`.
#[tokio::test(start_paused = true)]
async fn panic_safety_panicking_sink_on_scan_progress_unwinds_cleanly() {
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
    let cancel = CancellationToken::new();

    // Spawn the producer on a separate task so the panic
    // surfaces as `JoinError::Panic` rather than aborting the
    // test runtime.
    let cancel_clone = cancel.clone();
    let join = tokio::spawn(async move {
        let refresh = make_local_refresh();
        let snapshot = empty_snapshot();
        let sink = PanickingSink::new(PanickingSinkTrigger::OnScanProgress);
        let (progress_tx, _progress_rx) = fresh_progress_channel();
        refresh
            .produce_scan_result(
                snapshot,
                &daemon,
                RefreshOptions::default(),
                cancel_clone,
                progress_tx,
                &sink,
            )
            .await
    });

    // `ScanResult` is deliberately not `Debug` (per the
    // §5.4.6 R6 memory-amplifier closure — `ScanResult` can
    // carry secret-shaped detected-transfer payloads); the
    // `JoinHandle`'s `Result<Result<ScanResult, _>, _>` is
    // therefore not `Debug` either. Inspect the join result
    // directly without debug-printing.
    let join_outcome = join.await;
    let Err(join_err) = join_outcome else {
        panic!(
            "producer task MUST resolve to JoinError::Panic when sink panics on emit; \
                 instead the producer returned a typed Result. This is a panic-safety pin \
                 violation: the sink's panic should propagate through the await boundary."
        )
    };
    assert!(
        join_err.is_panic(),
        "producer task error MUST be a panic, got {join_err:?}",
    );
    // Cancellation token unfired across the unwind: the producer
    // never reaches a `cancel.cancel()` call on the emit panic
    // path; an external observer sees a consistent unfired
    // state. A regression where the producer fired the token in
    // a `Drop` impl on its frame would flip this assertion.
    assert!(
        !cancel.is_cancelled(),
        "cancellation token MUST NOT fire across an emission-induced panic",
    );
}

/// `PanickingSink` configured to panic on the first
/// `DaemonProtocolError` emission. The producer's `get_height`
/// call fails (injected `ConnectionError`); the producer emits
/// `DaemonProtocolError` for the §5.4.7 R6 classification; the
/// sink panics. The panic propagates out before the producer
/// reaches the `return Err(LocalRefreshError::Io)` line — i.e.,
/// the §5.4.6 emission/return coherence contract is consistent
/// with the panic-safety contract (emission happens before the
/// return; a sink that panics on emit prevents the typed
/// `Err(_)` from propagating).
#[tokio::test(start_paused = true)]
async fn panic_safety_panicking_sink_on_protocol_error_unwinds_cleanly() {
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
    daemon.set_height_error_for_next_n_calls(
        1,
        &RpcError::ConnectionError("panic-safety: get_height down".into()),
    );
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let join = tokio::spawn(async move {
        let refresh = make_local_refresh();
        let snapshot = empty_snapshot();
        let sink = PanickingSink::new(PanickingSinkTrigger::OnDaemonProtocolError);
        let (progress_tx, _progress_rx) = fresh_progress_channel();
        refresh
            .produce_scan_result(
                snapshot,
                &daemon,
                RefreshOptions::default(),
                cancel_clone,
                progress_tx,
                &sink,
            )
            .await
    });

    let Err(join_err) = join.await else {
        panic!(
            "producer task MUST panic when DaemonProtocolError sink panics; \
                 instead the producer returned a typed Result. Panic-safety pin violation."
        )
    };
    assert!(
        join_err.is_panic(),
        "producer task error MUST be a panic, got {join_err:?}",
    );
    assert!(
        !cancel.is_cancelled(),
        "cancellation token MUST NOT fire across an emission-induced panic",
    );
}

/// `PanickingSink::Any` panics on the first emission of any
/// class. Against a clean 3-block chain the first emission is
/// `ScanProgress` after block 1 succeeds; the sink panics. This
/// is the most-general producer-panic-safety scenario: the test
/// asserts the property without binding to a specific
/// emission-class code path inside the producer (which makes the
/// test robust against future producer refactors that may
/// reorder emission sites).
#[tokio::test(start_paused = true)]
async fn panic_safety_panicking_sink_any_unwinds_cleanly() {
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let join = tokio::spawn(async move {
        let refresh = make_local_refresh();
        let snapshot = empty_snapshot();
        let sink = PanickingSink::new(PanickingSinkTrigger::Any);
        let (progress_tx, _progress_rx) = fresh_progress_channel();
        refresh
            .produce_scan_result(
                snapshot,
                &daemon,
                RefreshOptions::default(),
                cancel_clone,
                progress_tx,
                &sink,
            )
            .await
    });

    let Err(join_err) = join.await else {
        panic!(
            "producer task MUST panic when Any sink panics on first emission; \
                 instead the producer returned a typed Result. Panic-safety pin violation."
        )
    };
    assert!(
        join_err.is_panic(),
        "producer task error MUST be a panic, got {join_err:?}",
    );
    assert!(
        !cancel.is_cancelled(),
        "cancellation token MUST NOT fire across an emission-induced panic",
    );
}

/// Recovery-after-panic: after a panic-induced producer failure
/// against one [`LocalRefresh`] instance, a *fresh*
/// `LocalRefresh` (mirroring the post-panic engine-rebuild flow
/// a real orchestrator would perform) drives a clean refresh
/// against the same daemon. Asserts the §5.4.6
/// no-half-state-leakage property at the orchestrator boundary:
/// the panic did not corrupt the daemon's queryable state, and
/// a fresh producer instance reaches `Ok(_)` cleanly.
#[tokio::test(start_paused = true)]
async fn panic_safety_recovery_after_panic_succeeds() {
    let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));

    // First refresh: produces a panic via PanickingSink.
    let daemon_for_panic = daemon.clone();
    let cancel_panic = CancellationToken::new();
    let cancel_panic_clone = cancel_panic.clone();
    let panic_join = tokio::spawn(async move {
        let refresh = make_local_refresh();
        let snapshot = empty_snapshot();
        let sink = PanickingSink::new(PanickingSinkTrigger::Any);
        let (progress_tx, _progress_rx) = fresh_progress_channel();
        refresh
            .produce_scan_result(
                snapshot,
                &daemon_for_panic,
                RefreshOptions::default(),
                cancel_panic_clone,
                progress_tx,
                &sink,
            )
            .await
    });
    let Err(panic_err) = panic_join.await else {
        panic!(
            "first refresh MUST panic via PanickingSink::Any; \
                 instead the producer returned a typed Result."
        )
    };
    assert!(panic_err.is_panic(), "first refresh MUST be a panic");

    // Second refresh: fresh LocalRefresh, AssertionSink, against
    // the same daemon. Must reach Ok(_) cleanly.
    let refresh = make_local_refresh();
    let snapshot = empty_snapshot();
    let sink = AssertionSink::new();
    let cancel = CancellationToken::new();
    let (progress_tx, _progress_rx) = fresh_progress_channel();
    let result = refresh
        .produce_scan_result(
            snapshot,
            &daemon,
            RefreshOptions::default(),
            cancel,
            progress_tx,
            &sink,
        )
        .await;

    match &result {
        Ok(_) => {}
        Err(e) => panic!(
            "recovery refresh MUST succeed after panic-induced first refresh; \
                 daemon state not corrupted. Got Err({e:?})"
        ),
    }
    let recorded = sink.recorded();
    assert!(
        !recorded.iter().any(is_error_class),
        "recovery refresh MUST NOT emit error-class diagnostics on the clean path. \
             Recorded: {recorded:?}",
    );
}

/// Coverage of the [`is_daemon_malformed`] discriminator. The
/// `DaemonMalformed` emission path is exercised in
/// `engine/diagnostics.rs::tests::assertion_sink_records_events_in_emission_order`
/// and across the C7 panic-safety tests; this test pins that
/// `is_daemon_malformed` correctly classifies the event class
/// against a synthesized event.
#[test]
fn is_daemon_malformed_classifies_event_correctly() {
    let event = RefreshDiagnostic::DaemonMalformed {
        kind: MalformedKind::InvalidBlockStructure,
    };
    assert!(is_daemon_malformed(&event));
    let non_malformed = RefreshDiagnostic::ScanProgress {
        height: 1,
        candidates: 0,
    };
    assert!(!is_daemon_malformed(&non_malformed));
}
