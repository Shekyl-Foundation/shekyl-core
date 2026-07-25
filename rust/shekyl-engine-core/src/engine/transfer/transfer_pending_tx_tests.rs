// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the transfer / pending-tx implementor.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use shekyl_address::ShekylAddress;
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};
use shekyl_curve_tree::{
    select_reference_height, AssembleInput, BlockHeight, CurveTreeClient, Gindex, ReferenceBlock,
    REF_ANCHOR_AGE,
};
use shekyl_engine_state::LedgerBlock;
use shekyl_rpc_client::FeeRate;
use shekyl_scanner::RecoveredWalletOutput;
use shekyl_units::AtomicUnits;
use tempfile::TempDir;

use super::support::TreeSpendGate;
use super::types::{ContentFingerprint, Stage1LedgerSpendableAccess, SubmitLoopBreaker};
use super::LocalPendingTx;
use crate::engine::curve_tree_actor::CurveTreeHandle;
use crate::engine::diagnostics::{
    AssertionSink, DiagnosticSink, DiscardReason, PanickingSink, PanickingSinkTrigger,
    PendingTxDiagnostic, TracingDiagnosticSink,
};
use crate::engine::error::{
    AmbiguousErrorKind, PendingTxError, RetryableRejectCause, SendError, SubmitError,
    TerminalErrorKind,
};
use crate::engine::fee_estimator::DaemonFeeEstimator;
use crate::engine::fee_snapshot::FixedFeeSnapshotSource;
use crate::engine::key_actor::KeyEngineHandle;
use crate::engine::local_keys::LocalKeys;
use crate::engine::network::Network;
use crate::engine::output_selector::WalletGreedyOutputSelector;
use crate::engine::pending::{
    FeePriority, InFlightSubmit, PendingTx, ReservationId, ReservationTTLConfig, TxRecipient,
    TxRecipientSummary, TxRequest,
};
use crate::engine::signer::LocalSigner;
use crate::engine::traits::FeeEstimates;
use crate::engine::traits::PendingTxEngine;
use crate::engine::transaction_submitter::{
    canonical_tx_id, SubmitSuccess, SubmitterError, TransactionSubmitter,
};
use crate::engine::tx_counts::{InputCount, OutputCount};
use crate::engine::LocalLedger;

/// Deterministic raw32 test seed. Distinct from `SIGNER_TEST_MASTER_SEED`
/// (`engine/signer.rs`) so pending-tx tests do not share derivation state
/// with the C4α `LocalSigner` fixtures.
const PENDING_TX_TEST_RAW_SEED: [u8; 32] = {
    let mut seed = [0u8; 32];
    let mut i: u8 = 0;
    while (i as usize) < 32 {
        seed[i as usize] = i.wrapping_mul(17) ^ 0x5B;
        i += 1;
    }
    seed
};

const TEST_OUTPUT_TX_KEY: [u8; 32] = [11u8; 32];

fn test_account_blob() -> AllKeysBlob {
    let (_master, blob) =
        generate_account_from_raw_seed(&PENDING_TX_TEST_RAW_SEED, DerivationNetwork::Testnet)
            .expect("testnet raw32 rederivation succeeds");
    blob
}

/// Base spend public key `D = b·G` — the on-chain output key for an output
/// the wallet receives at its primary address. The spend witness is
/// `x = ho + b` (no claim offset; see
/// `LocalKeys::derive_primary_source_secrets_bundle`), so the fixture must
/// build to the base key for the SAL open `x·G + y·T == O` to hold. The
/// pre-fix `D + m₀·G` only matched the now-removed `+ m₀` witness term and
/// was never daemon-verified (every spend was synthetic in-process).
fn test_recipient_spend_pk() -> [u8; 32] {
    *test_account_blob().spend_pk.as_canonical_bytes()
}

fn test_payment_address() -> String {
    let blob = test_account_blob();
    ShekylAddress::new(
        Network::Mainnet,
        test_recipient_spend_pk(),
        *blob.view_pk.as_canonical_bytes(),
        blob.ml_kem_ek.to_vec(),
    )
    .encode()
    .expect("encode payment address for test wallet")
}

/// Spawn a `KeyActor` over the pending-tx test blob.
fn test_signer_handle() -> KeyEngineHandle {
    KeyEngineHandle::spawn(test_account_blob())
}

fn test_ledger() -> LocalLedger {
    LocalLedger::from_test_blocks(Vec::new())
}

fn test_fee_estimates() -> FeeEstimates {
    // mask=1 keeps `FeeRate`'s fee↔weight roundtrip consistent with the
    // structural predictor's fee varint term under `converge_fee`.
    let tiny = FeeRate::new(1, 1).expect("tiny test fee rate is non-zero");
    FeeEstimates {
        economy: tiny,
        standard: tiny,
        priority: tiny,
        quantization_mask: 1,
    }
}

fn test_fee_snapshot_source() -> FixedFeeSnapshotSource {
    FixedFeeSnapshotSource::new(test_fee_estimates())
}

struct TestTransactionSubmitter;

impl TransactionSubmitter for TestTransactionSubmitter {
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<SubmitSuccess, SubmitterError> {
        Ok(SubmitSuccess::Broadcast {
            hash: canonical_tx_id(&tx_bytes),
        })
    }
}

fn test_submitter() -> Arc<TestTransactionSubmitter> {
    Arc::new(TestTransactionSubmitter)
}

/// Smoke test: constructor succeeds and the engine's state
/// initializes to the (γ) empty-collections baseline.
#[tokio::test]
async fn local_pending_tx_new_constructs() {
    let key = test_signer_handle();
    let pending = LocalPendingTx::new(
        Arc::new(LocalSigner::new(key)),
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        test_fee_snapshot_source(),
        test_submitter(),
        Arc::new(test_ledger()),
        None,
        Arc::new(TracingDiagnosticSink),
        ReservationTTLConfig::default(),
        Network::Mainnet,
    );

    let state = pending.state.lock().expect("state lock not poisoned");
    assert!(state.output_locks.is_empty());
    assert!(state.consumer_held.is_empty());
    assert!(state.in_flight.is_empty());
    assert_eq!(state.next_id, 0);
}

fn make_recovered_output(seed: u8, global_index: u64, amount: u64) -> RecoveredWalletOutput {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use shekyl_crypto_pq::output::construct_output;
    use shekyl_curve_primitives::Commitment;
    use shekyl_scanner::{RecoveredWalletOutput, WalletOutput};

    let blob = test_account_blob();
    let mut tx_hash = [0u8; 32];
    tx_hash[..8].copy_from_slice(&global_index.to_le_bytes());
    tx_hash[8] = seed;
    let output_index = u64::from(seed);
    let constructed = construct_output(
        &TEST_OUTPUT_TX_KEY,
        &blob.x25519_pk,
        &blob.ml_kem_ek,
        &test_recipient_spend_pk(),
        amount,
        output_index,
    )
    .expect("construct_output for test wallet output");
    let key = CompressedEdwardsY(constructed.output_key)
        .decompress()
        .expect("output key decompresses");
    let commitment = Commitment {
        mask: Scalar::from_canonical_bytes(constructed.z).expect("mask canonical"),
        amount,
    };
    let base = WalletOutput::new_for_test(
        tx_hash,
        output_index,
        global_index,
        key,
        Scalar::ZERO,
        commitment,
    );
    RecoveredWalletOutput::new_for_test(base, amount)
}

/// Advance the ledger by empty blocks `from..=to` (no owned outputs), keeping
/// the `[h & 0xFF; 32]` block-hash scheme `populate_ledger` uses so an earlier
/// reference height stays canonical. Used by the CT-5d re-anchor KATs to age a
/// reference past the rebuild horizon without changing the funded set.
fn advance_ledger_empty_blocks(ledger: &LocalLedger, from: u64, to: u64) {
    use shekyl_scanner::{LedgerIndexesExt, Timelocked};

    let mut guard = ledger.write();
    let state = &mut *guard;
    let ledger_block = &mut state.ledger.ledger;
    let indexes = &mut state.indexes;
    for h in from..=to {
        let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
        let _ = indexes.process_scanned_outputs(
            ledger_block,
            h,
            hash,
            Timelocked::from_vec(Vec::new()),
        );
    }
}

fn populate_ledger(
    ledger: &LocalLedger,
    block_height: u64,
    outputs: Vec<RecoveredWalletOutput>,
    final_height: u64,
) {
    use shekyl_scanner::{LedgerIndexesExt, Timelocked};

    let mut guard = ledger.write();
    let state = &mut *guard;
    let ledger_block = &mut state.ledger.ledger;
    let indexes = &mut state.indexes;
    let timelocked = Timelocked::from_vec(outputs);
    let block_hash = [u8::try_from(block_height & 0xFF).unwrap(); 32];
    let inserted_range =
        indexes.process_scanned_outputs(ledger_block, block_height, block_hash, timelocked);
    assert!(!inserted_range.is_empty() || ledger_block.transfer_count() == 0);
    for h in (block_height + 1)..=final_height {
        let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
        let _ = indexes.process_scanned_outputs(
            ledger_block,
            h,
            hash,
            Timelocked::from_vec(Vec::new()),
        );
    }

    // Scan-only test paths skip the merge post-pass; align on-chain fields
    // with `construct_output` so the 2a-3 sign bridge can run.
    use shekyl_crypto_pq::handle::derive_output_handle;
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::output::{compute_output_key_image, construct_output};
    use shekyl_curve_generators::biased_hash_to_point;

    let blob = test_account_blob();
    let local = LocalKeys::from_test_seed(PENDING_TX_TEST_RAW_SEED);
    let transfer_count = ledger_block.transfer_count();
    for i in 0..transfer_count {
        let Some(td) = ledger_block.transfer_mut(i) else {
            continue;
        };
        let amount = td.amount().to_raw();
        let output_index = td.internal_output_index;
        let constructed = construct_output(
            &TEST_OUTPUT_TX_KEY,
            &blob.x25519_pk,
            &blob.ml_kem_ek,
            &test_recipient_spend_pk(),
            amount,
            output_index,
        )
        .expect("construct_output for test ledger output");

        let ciphertext = HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };
        td.source_ciphertext = Some(ciphertext.clone());
        td.output_handle = Some(derive_output_handle(
            blob.view_sk.as_canonical_bytes(),
            td.tx_hash.as_bytes(),
            output_index,
        ));

        let bundle = local
            .derive_primary_source_secrets_bundle(&ciphertext, output_index)
            .expect("derive secrets for test output");
        let combined: [u8; 64] = bundle.combined_ss[..64]
            .try_into()
            .expect("combined_ss length");
        let hp = biased_hash_to_point(constructed.output_key)
            .compress()
            .to_bytes();
        let ki = compute_output_key_image(
            &combined,
            output_index,
            blob.spend_sk.as_canonical_bytes(),
            &hp,
        )
        .expect("key image for test output")
        .key_image;
        indexes.set_key_image(ledger_block, i, ki);
    }
}

fn standard_request(amount: u64) -> TxRequest {
    TxRequest {
        recipients: vec![TxRecipient {
            address: test_payment_address(),
            amount_atomic_units: AtomicUnits::from_raw(amount),
        }],
        priority: FeePriority::Standard,
    }
}

type TestPendingTx = LocalPendingTx<
    LocalSigner,
    WalletGreedyOutputSelector,
    DaemonFeeEstimator,
    FixedFeeSnapshotSource,
    TestTransactionSubmitter,
    LocalLedger,
>;

fn test_pending_tx(ledger: Arc<LocalLedger>) -> TestPendingTx {
    LocalPendingTx::new(
        Arc::new(LocalSigner::new(test_signer_handle())),
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        test_fee_snapshot_source(),
        test_submitter(),
        ledger,
        None,
        Arc::new(TracingDiagnosticSink),
        ReservationTTLConfig::default(),
        Network::Mainnet,
    )
}

fn test_pending_tx_with_sink(
    ledger: Arc<LocalLedger>,
    sink: Arc<dyn DiagnosticSink>,
) -> TestPendingTx {
    LocalPendingTx::new(
        Arc::new(LocalSigner::new(test_signer_handle())),
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        test_fee_snapshot_source(),
        test_submitter(),
        ledger,
        None,
        sink,
        ReservationTTLConfig::default(),
        Network::Mainnet,
    )
}

fn funded_ledger() -> Arc<LocalLedger> {
    let ledger = Arc::new(test_ledger());
    populate_ledger(
        ledger.as_ref(),
        1,
        vec![
            make_recovered_output(1, 100, 50_000),
            make_recovered_output(2, 101, 30_000),
        ],
        20,
    );
    ledger
}

// --- CT-5a commit 4b-1: curve-tree spend-gate KATs (D1/D3) --------------

/// A fresh, empty curve-tree handle over a tempdir store. Its
/// `ingested_tip_height` is `None`, so the spend gate (`Enforced { None }`)
/// treats every matured output as `pending_rebuild` — the adopting /
/// first-run wallet whose tree has not begun backfilling.
fn fresh_tree_handle() -> (TempDir, CurveTreeHandle) {
    let dir = TempDir::new().expect("tempdir");
    let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
        .expect("open fresh curve-tree client");
    let handle = CurveTreeHandle::spawn(client);
    (dir, handle)
}

/// A curve-tree handle whose resume cursor has been advanced to `cap` by
/// ingesting empty leaves for every block `0..=cap`. Empty-leaf ingest
/// advances `ingested_tip_height` without contributing leaves (the
/// merge-driven ingest KATs rely on the same property), which is all the
/// spend gate reads — it compares `eligible_height <= covered_through`.
async fn tree_handle_ingested_through(cap: u64) -> (TempDir, CurveTreeHandle) {
    let (dir, handle) = fresh_tree_handle();
    for h in 0..=cap {
        handle
            .ingest(BlockHeight(h), std::sync::Arc::new(Vec::new()))
            .await
            .expect("empty-leaf ingest advances the cursor");
    }
    (dir, handle)
}

/// CT-5c consistent fixture: a `(ledger, tree)` pair whose tree leaves
/// **are** the ledger's owned outputs, so the real `assemble_path` resolves
/// each by gindex and the signer builds a real membership proof.
///
/// Each `specs` entry is `(seed, amount)`; the output's `global_output_index`
/// is its position, so it equals the tree's drain-order gindex (the owned
/// outputs are the chain's first and only leaves). They are populated into
/// the ledger at `owned_block` (which also wires the secret-pathway fields)
/// and ingested into the tree as one non-miner transaction at the same
/// height — `TaggedKey` non-miner maturity is `+DEFAULT_LOCK_WINDOW`
/// (= `SPENDABLE_AGE`), matching the ledger's `eligible_height`. The block's
/// `0x07` leaf-hash blob carries each output's real `h_pqc`, so the tree
/// leaf's identity (`O`, `C`, `h_pqc`) equals the ledger output's. Empty
/// blocks advance the cursor to `synced`. Pick `owned_block` so the leaves
/// are drained at the reference height: `owned_block + SPENDABLE_AGE <=
/// synced - REF_ANCHOR_AGE`.
async fn funded_ledger_and_tree(
    specs: &[(u8, u64)],
    owned_block: u64,
    synced: u64,
) -> (Arc<LocalLedger>, TempDir, CurveTreeHandle) {
    use curve25519_dalek::scalar::Scalar;
    use shekyl_crypto_pq::output::construct_output;
    use shekyl_curve_primitives::Commitment;
    use shekyl_curve_tree::{RawOutput, TargetKind};

    // Ledger side: the same `make_recovered_output` outputs `populate_ledger`
    // wires the secret-pathway fields (`source_ciphertext`, `output_handle`,
    // `key_image`) for. `global_output_index` = position = tree gindex.
    let ledger = Arc::new(test_ledger());
    let recovered: Vec<_> = specs
        .iter()
        .enumerate()
        .map(|(i, &(seed, amt))| make_recovered_output(seed, i as u64, amt))
        .collect();
    populate_ledger(ledger.as_ref(), owned_block, recovered, synced);

    // Tree side: reconstruct each output's on-chain identity (`O`, `C`,
    // `h_pqc`) and ingest them as the chain's first outputs so gindex ==
    // global_output_index.
    let blob = test_account_blob();
    let mut raw_outputs = Vec::with_capacity(specs.len());
    let mut leaf_blob = Vec::with_capacity(specs.len() * 32);
    for &(seed, amt) in specs {
        let output_index = u64::from(seed);
        let c = construct_output(
            &TEST_OUTPUT_TX_KEY,
            &blob.x25519_pk,
            &blob.ml_kem_ek,
            &test_recipient_spend_pk(),
            amt,
            output_index,
        )
        .expect("construct_output for consistent tree leaf");
        let commitment = Commitment {
            mask: Scalar::from_canonical_bytes(c.z).expect("mask canonical"),
            amount: amt,
        }
        .calculate()
        .compress()
        .to_bytes();
        raw_outputs.push(RawOutput {
            output_key: c.output_key,
            commitment: Some(commitment),
            target: TargetKind::TaggedKey,
        });
        leaf_blob.extend_from_slice(&c.h_pqc);
    }

    let (dir, handle) = fresh_tree_handle();
    for h in 0..=synced {
        let txs = if h == owned_block {
            Arc::new(vec![crate::scan::OwnedTxLeaves {
                is_miner: false,
                leaf_hash_blob: Some(leaf_blob.clone()),
                outputs: raw_outputs.clone(),
            }])
        } else {
            Arc::new(Vec::new())
        };
        handle
            .ingest(BlockHeight(h), txs)
            .await
            .expect("consistent-fixture ingest");
    }
    (ledger, dir, handle)
}

fn test_pending_tx_with_tree(ledger: Arc<LocalLedger>, tree: CurveTreeHandle) -> TestPendingTx {
    LocalPendingTx::new(
        Arc::new(LocalSigner::new(test_signer_handle())),
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        test_fee_snapshot_source(),
        test_submitter(),
        ledger,
        Some(tree),
        Arc::new(TracingDiagnosticSink),
        ReservationTTLConfig::default(),
        Network::Mainnet,
    )
}

fn test_pending_tx_with_tree_and_sink(
    ledger: Arc<LocalLedger>,
    tree: CurveTreeHandle,
    sink: Arc<dyn DiagnosticSink>,
) -> TestPendingTx {
    LocalPendingTx::new(
        Arc::new(LocalSigner::new(test_signer_handle())),
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        test_fee_snapshot_source(),
        test_submitter(),
        ledger,
        Some(tree),
        sink,
        ReservationTTLConfig::default(),
        Network::Mainnet,
    )
}

/// CT-5c: the standard funded fixture (`funded_ledger`'s two outputs,
/// 50_000 + 30_000) backed by a **consistent** curve tree — the tree leaves
/// are those outputs, so the real `assemble_path` resolves them and the
/// signer builds a real proof. Returns the pending engine, the ledger, and
/// the tree-store `TempDir` (which the caller must keep alive). Replaces the
/// pre-CT-5c `test_pending_tx(funded_ledger())`, which had no tree.
async fn funded_pending_tx() -> (TestPendingTx, Arc<LocalLedger>, TempDir) {
    let (ledger, dir, tree) = funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
    (pending, ledger, dir)
}

/// [`funded_pending_tx`] with a caller-supplied diagnostic sink.
async fn funded_pending_tx_with_sink(
    sink: Arc<dyn DiagnosticSink>,
) -> (TestPendingTx, Arc<LocalLedger>, TempDir) {
    let (ledger, dir, tree) = funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree_and_sink(Arc::clone(&ledger), tree, sink);
    (pending, ledger, dir)
}

/// [`funded_pending_tx`] with a **single** 50_000 output — for reservation
/// tests that assert a second build is blocked because the one output is
/// locked (a two-output fixture would let the second build use the spare).
async fn funded_pending_tx_one() -> (TestPendingTx, Arc<LocalLedger>, TempDir) {
    let (ledger, dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
    (pending, ledger, dir)
}

/// `TreeSpendGate::covers` boundary: the inert (no-tree) gate covers
/// everything; a fresh tree covers nothing; a cursor at `H` covers
/// eligibility `<= H` and excludes `H + 1`.
#[test]
fn tree_spend_gate_covers_boundary() {
    assert!(TreeSpendGate::Unenforced.covers(0));
    assert!(TreeSpendGate::Unenforced.covers(u64::MAX));
    assert!(!TreeSpendGate::Enforced {
        covered_through: None,
    }
    .covers(0));
    let gate = TreeSpendGate::Enforced {
        covered_through: Some(11),
    };
    assert!(gate.covers(0));
    assert!(gate.covers(11));
    assert!(!gate.covers(12));
}

/// D1/D3 core KAT — the adopting / first-run wallet. Matured balance is in
/// the ledger but the curve tree is fresh (empty), so no output can yet
/// have a membership proof. The gate must surface the self-healing
/// [`SendError::SpendUnavailableRebuilding`] (not a misleading
/// `InsufficientFunds`), reporting nothing spendable and the full matured
/// balance as `pending_rebuild`.
#[tokio::test]
async fn adopting_wallet_spend_unavailable_during_rebuild() {
    let ledger = funded_ledger(); // 50_000 + 30_000 matured at synced=20
    let (_dir, tree) = fresh_tree_handle();
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let err = pending
        .build(standard_request(7_000))
        .await
        .expect_err("a fresh tree gates every matured output");
    match err {
        SendError::SpendUnavailableRebuilding {
            needed,
            spendable_now,
            pending_rebuild,
        } => {
            assert!(needed >= 7_000, "needed covers the request plus fee");
            assert_eq!(spendable_now, 0, "no output is tree-covered yet");
            assert_eq!(
                pending_rebuild, 80_000,
                "the whole matured balance awaits the rebuild"
            );
        }
        other => panic!("expected SpendUnavailableRebuilding, got {other:?}"),
    }
}

/// Once the tree has ingested up to the **reference** height the gate is
/// inert and the spend builds. synced 20 → reference 14; the cursor (20)
/// covers the reference, so its root is reconstructable and the eligible-11
/// outputs are present at the reference block — spendable.
#[tokio::test]
async fn rebuilt_tree_spends_normally() {
    // A consistent tree caught up past the reference height (synced 20 −
    // REF_ANCHOR_AGE 6 = 14): the outputs' leaves are present and the
    // reference root is reconstructable, so the spend gate is inert and the
    // build assembles a real proof.
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("a caught-up tree imposes no gate");
    assert!(
        !built.tx_bytes.is_empty(),
        "the gate-inert build produces a tx"
    );
}

/// CT-5b gate KAT: per-output tree coverage is **necessary but not
/// sufficient**. An output's own leaf can be ingested (cursor ≥ eligible)
/// while the tree is still behind the *reference* height — and the FCMP
/// proof anchors to the reference block, whose root is unreconstructable
/// until the tree reaches it. So such an output is not spendable: the build
/// surfaces the self-healing `SpendUnavailableRebuilding` rather than
/// proceeding against the wrong (placeholder) reference. synced 20 →
/// reference 14; output A (eligible 11) is individually covered by cursor 11
/// but the tree has not reached reference 14.
#[tokio::test]
async fn tree_behind_reference_blocks_individually_covered_output() {
    let ledger = Arc::new(test_ledger());
    // A: block 1 → eligible 11, 50_000; synced 20 → reference 14.
    populate_ledger(
        ledger.as_ref(),
        1,
        vec![make_recovered_output(1, 100, 50_000)],
        20,
    );
    // Cursor 11 covers A's own leaf (11 ≤ 11) but is below reference 14.
    let (_dir, tree) = tree_handle_ingested_through(11).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let err = pending
        .build(standard_request(7_000))
        .await
        .expect_err("the tree has not reached the reference height");
    match err {
        SendError::SpendUnavailableRebuilding {
            spendable_now,
            pending_rebuild,
            ..
        } => {
            assert_eq!(
                spendable_now, 0,
                "no output is spendable until the tree reaches the reference"
            );
            assert_eq!(
                pending_rebuild, 50_000,
                "A awaits the tree reaching reference 14, despite its own leaf being ingested"
            );
        }
        other => panic!("expected SpendUnavailableRebuilding, got {other:?}"),
    }
}

/// C2 KAT (2A §3.7.5, CT-5b DoD). `synced = 15` ⇒ `reference_height =
/// 15 − REF_ANCHOR_AGE(6) = 9`. An output at block 1 matures at
/// `eligible = 1 + SPENDABLE_AGE(10) = 11`: matured at the tip (11 ≤ 15)
/// **and** in the tree (cursor 15 ≥ 11), but too fresh for the reference
/// block (11 > 9). The C2 gate must surface a clean
/// [`SendError::OutputNotYetSpendable`] with a wait-N-blocks signal — not a
/// spendable candidate, a `SpendUnavailableRebuilding`, or an
/// `InsufficientFunds`.
#[tokio::test]
async fn output_not_yet_spendable_at_reference_block() {
    let ledger = Arc::new(test_ledger());
    populate_ledger(
        ledger.as_ref(),
        1,
        vec![make_recovered_output(1, 100, 50_000)],
        15,
    );
    // Cursor at 15 covers the eligible-11 output, isolating C2 (reference
    // depth) from the tree-lag `SpendUnavailableRebuilding` path.
    let (_dir, tree) = tree_handle_ingested_through(15).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let err = pending
        .build(standard_request(7_000))
        .await
        .expect_err("the only output is too fresh for the reference block");
    match err {
        SendError::OutputNotYetSpendable {
            eligible_height,
            reference_block_height,
            wait_blocks,
        } => {
            assert_eq!(eligible_height, 11, "block 1 + SPENDABLE_AGE");
            assert_eq!(reference_block_height, 9, "synced 15 − REF_ANCHOR_AGE");
            assert_eq!(
                wait_blocks, 2,
                "spendable once the reference reaches 11 (tip 17)"
            );
        }
        other => panic!("expected OutputNotYetSpendable, got {other:?}"),
    }
}

/// C2 wait-blocks KAT: when *multiple* too-fresh outputs are needed to cover
/// the spend, `wait_blocks` must reflect the height by which **enough** of
/// them mature — not the soonest single output (which alone is insufficient
/// and would underestimate the wait). synced 15 → reference 9; output A
/// (eligible 11, 10_000) is too small alone for the 30_000 spend (+fee), so
/// B (eligible 13, 50_000) is also required → the wait is `13 − 9 = 4`, not
/// `11 − 9 = 2`.
#[tokio::test]
async fn output_not_yet_spendable_wait_covers_required_subset() {
    let ledger = Arc::new(test_ledger());
    // A: block 1 → eligible 11, 10_000. B: block 3 → eligible 13, 50_000.
    // Fill synced to 15 so both are matured but too fresh (reference 9).
    populate_ledger(
        ledger.as_ref(),
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        2,
    );
    populate_ledger(
        ledger.as_ref(),
        3,
        vec![make_recovered_output(3, 101, 50_000)],
        15,
    );
    let (_dir, tree) = tree_handle_ingested_through(15).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let err = pending
        .build(standard_request(30_000))
        .await
        .expect_err("both too-fresh outputs are needed to cover 30_000 + fee");
    match err {
        SendError::OutputNotYetSpendable {
            eligible_height,
            reference_block_height,
            wait_blocks,
        } => {
            assert_eq!(reference_block_height, 9);
            assert_eq!(
                eligible_height, 13,
                "the binding output is B (eligible 13), not the soonest A (11)"
            );
            assert_eq!(wait_blocks, 4, "wait until enough matures, not the soonest");
        }
        other => panic!("expected OutputNotYetSpendable, got {other:?}"),
    }
}

/// C2 pre-maturity KAT: a curve tree is enforced but `synced = 5 <
/// REF_ANCHOR_AGE(6)`, so `select_reference_height` returns `None` — there is
/// no reference block to anchor a proof. The build must surface the clean
/// [`SendError::WalletTooYoungToSpend`], not a misleading insufficiency.
#[tokio::test]
async fn wallet_too_young_to_spend_before_reference_anchor() {
    let ledger = Arc::new(test_ledger());
    populate_ledger(
        ledger.as_ref(),
        1,
        vec![make_recovered_output(1, 100, 50_000)],
        5,
    );
    let (_dir, tree) = tree_handle_ingested_through(5).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let err = pending
        .build(standard_request(7_000))
        .await
        .expect_err("the chain is too short to anchor a reference block");
    match err {
        SendError::WalletTooYoungToSpend {
            synced_height,
            ref_anchor_age,
        } => {
            assert_eq!(synced_height, 5);
            assert_eq!(ref_anchor_age, REF_ANCHOR_AGE);
        }
        other => panic!("expected WalletTooYoungToSpend, got {other:?}"),
    }
}

/// CT-5c DoD: a real-root membership proof builds and submits end-to-end.
/// The consistent fixture's tree leaves **are** the ledger's owned outputs,
/// so the engine resolves the real `assemble_path` at the reference height
/// (`tip − REF_ANCHOR_AGE` = 14 for synced 20; the eligible-11 output is
/// drained there), folds it into the signing context, and the signer builds
/// a real FCMP++ proof against the reconstructed root — the last synthetic
/// placeholder on the spend path is gone. (The `reference_block` *hash*
/// binding, distinct from the curve-tree root, is pinned by the curve-tree
/// `assemble_kat`; conflating them is the prover bug `shekyl-tx-builder`
/// exists to prevent.)
#[tokio::test]
async fn real_root_membership_proof_builds_and_submits() {
    let (ledger, _tree_dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("a real-root membership proof builds against the consistent tree");
    assert!(
        !built.tx_bytes.is_empty(),
        "the build produces a real signed tx"
    );

    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("submit ok");
    assert_eq!(
        tx_hash,
        canonical_tx_id(&built.tx_bytes),
        "the submitted hash is the signed tx bytes' hash",
    );
}

/// CT-5d (§4 F-G/F-G′): the content fingerprint is semantic and
/// canonically-ordered — it is invariant under the privacy output shuffle
/// (which a reprove re-runs) and excludes the re-randomized change address
/// (the change *amount* is captured, the address is not even a parameter),
/// but it does move on any change to *who gets how much* or the fee.
#[test]
fn content_fingerprint_is_order_invariant_and_amount_sensitive() {
    let r = |addr: &str, amt: u64| TxRecipientSummary {
        address: addr.to_string(),
        amount_atomic_units: AtomicUnits::from_raw(amt),
    };
    let fee = AtomicUnits::from_raw(1_000);
    let change = AtomicUnits::from_raw(500);

    let base = ContentFingerprint::from_parts(fee, &[r("addr_a", 10), r("addr_b", 20)], change);
    // F-G′: the same recipients/amounts in a different output order compare
    // equal — a reprove's reshuffle must not bump content_gen.
    let reshuffled =
        ContentFingerprint::from_parts(fee, &[r("addr_b", 20), r("addr_a", 10)], change);
    assert_eq!(
        base, reshuffled,
        "output order must not change the fingerprint"
    );
    // Idempotent: rebuilding the identical content compares equal.
    let again = ContentFingerprint::from_parts(fee, &[r("addr_a", 10), r("addr_b", 20)], change);
    assert_eq!(base, again, "identical content is idempotent");

    // The consent axis: fee, change amount, and recipient amount each move it.
    assert_ne!(
        base,
        ContentFingerprint::from_parts(
            AtomicUnits::from_raw(2_000),
            &[r("addr_a", 10), r("addr_b", 20)],
            change
        ),
        "a different fee is a content change"
    );
    assert_ne!(
        base,
        ContentFingerprint::from_parts(
            fee,
            &[r("addr_a", 10), r("addr_b", 20)],
            AtomicUnits::from_raw(600)
        ),
        "a different change amount is a content change"
    );
    assert_ne!(
        base,
        ContentFingerprint::from_parts(fee, &[r("addr_a", 11), r("addr_b", 20)], change),
        "a different recipient amount is a content change"
    );
}

/// CT-5d (§3a, headline): a proof carried past the rebuild horizon
/// re-anchors at submit (the reprove path) and broadcasts. Same inputs, same
/// tree depth → the realized content is unchanged → `content_gen` stays put
/// → transparent broadcast.
#[tokio::test]
async fn submit_reanchors_at_horizon_then_broadcasts() {
    let (ledger, _tree_dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
    // Clone the handle so the test can advance the (shared-actor) tree cursor
    // after handing one to the engine.
    let tree_for_advance = tree.clone();
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    assert_eq!(built.reference_height, 14);
    assert_eq!(built.content_gen, 0, "fresh build is generation 0");

    // Advance BOTH the ledger and the tree well past the rebuild horizon:
    // chain tip 80, tree ingested through 80. Reference age 80 − 14 = 66 ≥
    // REBUILD_AT (50) → submit must re-anchor (reprove) at 80 − 6 = 74; the
    // owned leaf (drained at 1 + SPENDABLE_AGE = 11) is in the tree there.
    advance_ledger_empty_blocks(ledger.as_ref(), 21, 80);
    for h in 21..=80 {
        tree_for_advance
            .ingest(BlockHeight(h), std::sync::Arc::new(Vec::new()))
            .await
            .expect("advance tree cursor");
    }

    pending
        .submit(built.id, built.content_gen)
        .await
        .expect("horizon re-anchor reproves and broadcasts transparently");
    assert_eq!(
        pending.outstanding(),
        0,
        "submit consumed the reservation after re-anchor"
    );
}

/// CT-5d (§3b, F-C upper arm): when the tree lags the chain tip so far that a
/// freshly-anchored reference would already be past the rebuild threshold,
/// the re-anchor refuses cleanly (`ReanchorUnavailable`) rather than anchor a
/// stale reference — and the reservation is preserved.
#[tokio::test]
async fn submit_reanchor_unavailable_when_tree_too_far_behind() {
    let (ledger, _tree_dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");

    // Advance the ledger far ahead (chain 80) but NOT the tree (cursor stays
    // at 20): the fresh reference would anchor at min(80, 20) − 6 = 14, age
    // 80 − 14 = 66 > REBUILD_AT (50). The upper arm fails clean.
    advance_ledger_empty_blocks(ledger.as_ref(), 21, 80);

    let err = pending
        .submit(built.id, built.content_gen)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SubmitError::ReanchorUnavailable { reservation_id } if reservation_id == built.id),
        "tree-too-far-behind must fail clean as ReanchorUnavailable, got {err:?}"
    );
    assert_eq!(
        pending.outstanding(),
        1,
        "reservation preserved on clean fail"
    );
}

/// CT-5c: a spend requires the curve tree to assemble a membership proof.
/// With no tree configured (a degenerate test/partial-construction state),
/// a build that clears selection is **refused** rather than producing an
/// unprovable transaction — the synthetic fallback is gone.
#[tokio::test]
async fn build_without_curve_tree_is_refused() {
    let pending = test_pending_tx(funded_ledger());
    let err = pending
        .build(standard_request(7_000))
        .await
        .expect_err("a build with no curve tree must be refused");
    assert!(
        matches!(err, SendError::CannotSign { reason } if reason.contains("curve tree")),
        "no-tree build must be refused with a curve-tree reason: {err:?}"
    );
}

#[tokio::test]
async fn build_then_submit_places_awaiting_confirmation_lock() {
    // CT-5c: a consistent ledger+tree so the real `assemble_path` resolves
    // the spent output and the signer builds a real membership proof.
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    assert!(
        built.fee_atomic_units > AtomicUnits::ZERO,
        "fee estimator returns a positive fee from the test snapshot"
    );
    assert!(
        !built.tx_bytes.is_empty(),
        "2a-3 build produces non-empty signed tx bytes"
    );
    // The built tx parses as the canonical shekyl-wire format, and the a-priori
    // `predict_weight` equals its canonical `weight()` (same n_in/n_out/depth/fee) —
    // the build-path half of the fee-model ↔ wire-weight reconciliation.
    let tx = shekyl_wire::Transaction::from_bytes(&built.tx_bytes)
        .expect("built tx parses as canonical shekyl-wire");
    let (depth, fee) = match &tx.ct {
        shekyl_wire::Ct::Fcmp {
            prunable: Some(p),
            fee,
            ..
        } => (
            // Wire `curve_trees_tree_depth` is the LMDB depth = proof layer
            // count − 1 (`build_wire_tx`); `predict_weight` models the FCMP++
            // proof size from the layer count, so add 1 back.
            u8::try_from(p.tree_depth + 1).expect("tree_depth + 1 fits u8"),
            *fee,
        ),
        _ => panic!("a spend is Fcmp with prunable"),
    };
    assert_eq!(
        crate::engine::tx_fee_model::predict_weight(
            InputCount::clamped(tx.prefix.inputs.len()),
            OutputCount::clamped(tx.prefix.outputs.len()),
            depth,
            fee,
        ),
        tx.weight(),
        "predict_weight must equal the built tx's canonical weight"
    );
    assert_eq!(pending.outstanding(), 1);

    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("submit ok");
    assert_eq!(tx_hash, canonical_tx_id(&built.tx_bytes));
    assert_eq!(pending.outstanding(), 0);

    // F14 (§2.6): submit-accept places the awaiting-confirmation lock
    // (keyed by the accepted txid), not a durable `spent` write —
    // refresh is the settlement authority for `spent`.
    {
        let guard = pending.ledger.read();
        let td = guard.ledger.ledger.transfers().first().expect("output 0");
        assert!(!td.spent, "spent stays refresh-authoritative");
        let lock = td
            .awaiting_confirmation
            .as_ref()
            .expect("submit-accept places the F14 lock");
        assert_eq!(lock.tx_hash, tx_hash);
        assert!(
            !td.is_spendable(u64::MAX),
            "locked output must be excluded from selection"
        );
    }
}

/// WI-RPC-3 retention (`docs/api/wallet_rpc.yaml` OUTBOUND
/// PREREQUISITE pin 1, dispatch form): submit persists the per-tx
/// secret into `tx_meta.tx_keys` keyed by the canonical txid — at
/// dispatch, before the bytes can reach the daemon — and records the
/// txid in `sync_state.pending_tx_hashes` so I-2 holds from the moment
/// of the write.
#[tokio::test]
async fn submit_persists_tx_key_and_pending_hash() {
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");

    // Pin 1's "not at build": a built-but-unsubmitted tx leaves no
    // entry in the persistent store — the secret rides the runtime
    // `consumer_held` entry only.
    {
        let guard = pending.ledger.read();
        assert!(
            guard.ledger.tx_meta.tx_keys.is_empty(),
            "no tx_keys write at build time"
        );
        assert!(
            guard.ledger.sync_state.pending_tx_hashes.is_empty(),
            "no pending_tx_hashes write at build time"
        );
    }

    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("submit ok");

    let guard = pending.ledger.read();
    let stored = guard
        .ledger
        .tx_meta
        .tx_keys
        .get(&tx_hash.to_bytes())
        .expect("dispatch persists the per-tx secret keyed by canonical txid");
    assert_ne!(
        *stored.primary.as_bytes(),
        [0u8; 32],
        "the persisted secret is the minted scalar, not a placeholder"
    );
    assert!(
        guard
            .ledger
            .sync_state
            .pending_tx_hashes
            .contains(&tx_hash.to_bytes()),
        "dispatch records the txid as pending (I-2 live reference)"
    );
}

/// WI-RPC-3 retention pin 1's discard side: a discarded reservation's
/// per-tx secret dies with the runtime entry (structural zeroize on
/// drop) and never reaches the persistent store.
#[tokio::test]
async fn discard_never_persists_tx_key() {
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending
        .discard(built.id, DiscardReason::ConsumerExplicit)
        .expect("discard ok");

    let guard = pending.ledger.read();
    assert!(
        guard.ledger.tx_meta.tx_keys.is_empty(),
        "a discarded build leaves no orphan secret in tx_keys"
    );
    assert!(
        guard.ledger.sync_state.pending_tx_hashes.is_empty(),
        "a discarded build leaves no pending-tx record"
    );
}

/// WI-RPC-3 retention death rule: the watchdog's confirmed-absent
/// release clears the F14 locks but KEEPS the retention record. Its
/// trigger is a terminal reject when the held bytes are re-offered to
/// the wallet's own daemon — a local relay verdict, not a proof of
/// network-wide absence — and a tx that late-settles from a remote
/// pool must still be able to serve its OUTBOUND proof. Exercises the
/// `WatchdogHost::release_awaiting_confirmation` seam the §2.6 release
/// path 2 drives.
#[tokio::test]
async fn confirmed_absent_release_keeps_retention_record() {
    use crate::engine::submit_lifecycle::WatchdogHost;

    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("submit ok");

    let released = WatchdogHost::release_awaiting_confirmation(&pending, &HashSet::from([tx_hash]));
    assert!(released > 0, "the F14 lock is released");

    let guard = pending.ledger.read();
    assert!(
        guard
            .ledger
            .tx_meta
            .tx_keys
            .contains_key(&tx_hash.to_bytes()),
        "the retained secret survives a local confirmed-absent verdict"
    );
    assert!(
        guard
            .ledger
            .sync_state
            .pending_tx_hashes
            .contains(&tx_hash.to_bytes()),
        "the pending record stays as the secret's I-2 live reference"
    );
    assert!(
        guard
            .ledger
            .ledger
            .transfers()
            .iter()
            .all(|td| td.awaiting_confirmation.is_none()),
        "all F14 locks for the confirmed-absent tx are cleared"
    );
    guard.ledger.check_invariants().expect("I-2 after release");
}

/// WI-RPC-3 retention pin 1's refusal side: a terminal submit verdict
/// is a definite, provably-unrelayed refusal — the dispatch-persisted
/// record is retired, so a refused build leaves no residue.
#[tokio::test]
async fn terminal_reject_retires_dispatch_persisted_record() {
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedTerminal {
        kind: TerminalErrorKind::DoubleSpend,
    }));
    pending
        .submit(built.id, built.content_gen)
        .await
        .expect_err("terminal reject");

    let guard = pending.ledger.read();
    assert!(
        guard.ledger.tx_meta.tx_keys.is_empty(),
        "a daemon-refused build leaves no retained secret"
    );
    assert!(
        guard.ledger.sync_state.pending_tx_hashes.is_empty(),
        "a daemon-refused build leaves no pending record"
    );
}

/// The §2.5 retryable arm retires the record the same way — the next
/// submit re-persists at its own dispatch (possibly under a new
/// canonical txid after a re-anchor rebuild).
#[tokio::test]
async fn retryable_reject_retires_dispatch_persisted_record() {
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedRetryable {
        cause: RetryableRejectCause::StaleRoot,
    }));
    pending
        .submit(built.id, built.content_gen)
        .await
        .expect_err("retryable reject");

    let guard = pending.ledger.read();
    assert!(
        guard.ledger.tx_meta.tx_keys.is_empty(),
        "a provably-unrelayed build leaves no retained secret"
    );
    assert!(
        guard.ledger.sync_state.pending_tx_hashes.is_empty(),
        "a provably-unrelayed build leaves no pending record"
    );
}

/// The crash-window shape pin 1's dispatch form exists for: an
/// ambiguous verdict (daemon timeout — the tx may or may not be
/// relayed) keeps the dispatch-persisted record, exactly as a crash
/// between dispatch and verdict would. The secret must outlive every
/// state where the network might still mine the tx.
#[tokio::test]
async fn ambiguous_verdict_keeps_dispatch_persisted_record() {
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::Ambiguous {
        kind: AmbiguousErrorKind::DaemonTimeout,
    }));
    pending
        .submit(built.id, built.content_gen)
        .await
        .expect_err("ambiguous verdict");

    let guard = pending.ledger.read();
    assert_eq!(
        guard.ledger.tx_meta.tx_keys.len(),
        1,
        "the maybe-exposed tx keeps its retained secret"
    );
    assert_eq!(
        guard.ledger.sync_state.pending_tx_hashes.len(),
        1,
        "the maybe-exposed tx keeps its pending record"
    );
    guard
        .ledger
        .check_invariants()
        .expect("I-2 across the ambiguity window");
}

/// F40 §2.5 case (a) — `AlreadyInChain { height }` with the confirming
/// block **above** the wallet's synced height (fixture synced = 20,
/// claimed = 25): the F14 awaiting-confirmation lock is placed exactly
/// as on the `Broadcast` arm (fund safety first — a no-lock
/// disposition would leave a selectable-input window an adversary who
/// slows the wallet's daemon's block delivery could steer it into),
/// but baselined at the **claimed height**, not the wallet's current
/// height. Release is the ordinary §2.6 path 1: refresh reaches the
/// confirming block and `mark_spent` settles. No targeted re-scan is
/// requested — refresh has not yet passed the claimed height, so
/// path 1 is reachable.
#[tokio::test]
async fn submit_already_in_chain_above_synced_locks_at_claimed_height() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    let expected_hash = canonical_tx_id(&built.tx_bytes);
    pending.queue_submit_daemon_outcome(Ok(SubmitSuccess::AlreadyInChain {
        hash: expected_hash,
        height: 25, // > fixture synced height 20
    }));

    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("AlreadyInChain resolves the submit successfully");
    assert_eq!(tx_hash, expected_hash);
    assert_eq!(pending.outstanding(), 0, "reservation released");

    // The F14 lock is placed on the selected inputs, baselined at the
    // claimed confirming height; `spent` stays refresh-written.
    {
        let guard = pending.ledger.read();
        let locked: Vec<_> = guard
            .ledger
            .ledger
            .transfers()
            .iter()
            .filter(|td| td.awaiting_confirmation.is_some())
            .collect();
        assert!(
            !locked.is_empty(),
            "AlreadyInChain must place the F14 lock (F40: no selectable window)"
        );
        for td in &locked {
            assert!(!td.spent, "spent stays refresh-authoritative");
            let lock = td.awaiting_confirmation.as_ref().expect("filtered above");
            assert_eq!(lock.tx_hash, expected_hash);
            assert_eq!(
                lock.accepted_at_height, 25,
                "the lock is baselined at the claimed confirming height, \
                 not the wallet's current height"
            );
            assert!(
                !td.is_spendable(u64::MAX),
                "locked output must be excluded from selection"
            );
        }
    }

    let events = sink.recorded_pending();
    assert!(
        events.iter().any(|e| matches!(
            e,
            PendingTxDiagnostic::SubmitSucceeded { tx_hash: h, .. } if *h == expected_hash
        )),
        "AlreadyInChain resolution emits SubmitSucceeded: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PendingTxDiagnostic::TargetedRescanRequested { .. })),
        "above-synced claim routes to path-1 refresh release, never a re-scan: {events:?}"
    );
}

/// F40 §2.5 case (b) + the R1 pin — `AlreadyInChain { height }` with
/// the confirming block **at/below** the wallet's synced height
/// (fixture synced = 20, claimed = 15): refresh already passed that
/// height without observing the spend, so the §2.6 path-1 release is
/// unreachable by construction (the FOLLOWUPS stranded-lock wedge).
/// The disposition places the F14 lock anyway and requests a
/// **targeted re-scan** ([`PendingTxDiagnostic::TargetedRescanRequested`]);
/// per F40-R1 the request **never releases** — the lock stands after
/// the resolution, and release remains refresh- or
/// watchdog-authoritative only. (The R2 fruitless-re-scan breaker
/// lives with the re-scan executor, the 2c-2b driving actor.)
#[tokio::test]
async fn submit_already_in_chain_at_or_below_synced_requests_rescan_never_releases() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    let expected_hash = canonical_tx_id(&built.tx_bytes);
    pending.queue_submit_daemon_outcome(Ok(SubmitSuccess::AlreadyInChain {
        hash: expected_hash,
        height: 15, // ≤ fixture synced height 20
    }));

    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("AlreadyInChain resolves the submit successfully");
    assert_eq!(tx_hash, expected_hash);
    assert_eq!(pending.outstanding(), 0, "reservation released");

    // R1 pin: the re-scan *request* releases nothing — the F14 lock
    // stands, baselined at the claimed height.
    {
        let guard = pending.ledger.read();
        let locked: Vec<_> = guard
            .ledger
            .ledger
            .transfers()
            .iter()
            .filter(|td| td.awaiting_confirmation.is_some())
            .collect();
        assert!(
            !locked.is_empty(),
            "F40-R1: requesting a re-scan must not release the F14 lock"
        );
        for td in &locked {
            assert!(!td.spent, "spent stays refresh-authoritative");
            let lock = td.awaiting_confirmation.as_ref().expect("filtered above");
            assert_eq!(lock.tx_hash, expected_hash);
            assert_eq!(lock.accepted_at_height, 15);
        }
    }

    let events = sink.recorded_pending();
    assert!(
        events.iter().any(|e| matches!(
            e,
            PendingTxDiagnostic::TargetedRescanRequested {
                tx_hash: h,
                claimed_height: 15,
                ..
            } if *h == expected_hash
        )),
        "at/below-synced claim requests the targeted re-scan: {events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            PendingTxDiagnostic::SubmitSucceeded { tx_hash: h, .. } if *h == expected_hash
        )),
        "AlreadyInChain resolution emits SubmitSucceeded: {events:?}"
    );
}

/// PR 2c-1 — the real-tree closing milestone for archival bond-post
/// construction (`ARCHIVAL_BOND_CONSTRUCTION.md` §3; `FOLLOWUPS.md`).
///
/// PR 2a (`local_keys::join_market_bond_post_signs_and_verifies_through_prover`)
/// proved the construct → prove → verify composition over a **synthetic**
/// single-leaf-chunk tree. This test re-runs the same composition over a
/// **real** curve tree: the funding output is a drained leaf of the
/// consistent `funded_ledger_and_tree` fixture, and its membership path is
/// assembled by the production `CurveTreeClient::assemble_path` (CT-5c) — the
/// same path the real-tree transfer KAT
/// (`build_then_submit_places_awaiting_confirmation_lock`) drives. The bond's `bond_credit`
/// rides as the single-sourced output-side cleartext term through
/// `tx_builder::sign_transaction_with_terms`, the credit-term threading the
/// 2a docstring deferred to this milestone.
///
/// # Why drive the prover directly, not the engine `build`
///
/// Per `ARCHIVAL_BOND_CONSTRUCTION.md` Q3, a bond post does **not** go
/// through the transfer signer (`TxRequest` / `sign_tx`); the StakeEngine
/// constructs it on a parallel path. That production sign path lands with its
/// StakeEngine caller in PR 2c-2 — adding an inert credit-term entry point to
/// the transfer bridge here would be dead code on a path bonds never take
/// (rules 15/21). This KAT assembles the real path from the fixture's tree
/// and calls `sign_transaction_with_terms` directly, exactly as 2c-2's
/// StakeEngine path will, proving the cryptographic composition over a real
/// root independent of the orchestration wiring.
///
/// # What is real here that was synthetic in 2a
///
/// The tree root, the depth, and the `c1`/`c2` branch layers come from the
/// real `assemble_path` over a depth-2 fixture (two drained leaves), so the
/// FCMP++ membership proof traverses genuine branch chunks rather than a
/// single synthetic leaf chunk. Everything else (the prover, BP+, FCMP++
/// verify, the two retention verify entrypoints, the cofactor recovery for
/// the CT balance) is identical to 2a.
///
/// # Commitment encoding
///
/// `SignedProofs.pseudo_outs` are the prime-order FCMP++ `C_tilde` points;
/// `SignedProofs.commitments` are the real prime-order `C = mask*G +
/// amount*H` (the form `sign.rs` emits and consensus stores in
/// `outPk[i].mask`). The CT balance equation is defined over prime-order
/// `C`, so the prover-emitted commitments feed the balance check directly
/// (see 2a's docstring for the full rationale).
///
/// # Accept *and* reject
///
/// Mirrors 2a: the verify side must reject a wrong `bond_credit`, a tampered
/// commitment, a signature that does not cover the post preimage, and a
/// replayed post. A round-trip that only asserts "valid accepts" can pass
/// against a verify that accepts everything.
#[tokio::test]
async fn join_market_bond_post_signs_and_verifies_over_real_tree() {
    use rand_core::OsRng;
    use shekyl_archival_retention::{
        verify_bond_post_ct_balance, verify_join_market_bond_post, BondCtBalanceError,
        BondPostError, BondTerm,
    };
    use shekyl_bulletproofs::Bulletproof;
    use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme};
    use shekyl_curve_io::CompressedPoint;
    use shekyl_curve_primitives::Commitment;
    use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

    use curve25519_dalek::scalar::Scalar;

    // Shared real-tree setup: assemble the real depth-2 membership path and
    // sign the bond post (`bond_credit` as the sole cleartext term). The
    // construct→prove half over genuine branch layers happens here.
    let RealTreeBondProofs {
        signed,
        outputs,
        built,
        p_keys,
        fee,
        floor,
        signable_tx_hash,
        ..
    } = real_tree_bond_post_proofs().await;

    // ── Verify 1/4: vin semantics, record does not yet exist ─────────
    verify_join_market_bond_post(built.vin(), false)
        .expect("verify accepts a fresh JoinMarket post");

    // ── Verify 2/4: hybrid signature under P_pubkey over the preimage ─
    let preimage = built.vin().signature_preimage(&signable_tx_hash);
    assert!(
        HybridEd25519MlDsa
            .verify(p_keys.hybrid_bond_id(), &preimage, built.signature())
            .expect("verify hybrid signature"),
        "JoinMarket signature must verify under P_pubkey"
    );

    // ── Verify 3/4: BP+ over the un-cofactored change commitment ─────
    let bp_commitments: Vec<CompressedPoint> = outputs
        .iter()
        .map(|out| {
            let mask = Scalar::from_canonical_bytes(out.commitment_mask)
                .expect("commitment_mask canonical");
            let c = Commitment::new(mask, out.amount.to_raw());
            CompressedPoint::from(c.calculate().compress().to_bytes())
        })
        .collect();
    let bp = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
        .expect("bulletproof_plus deserializes");
    let mut rng = OsRng;
    assert!(
        bp.verify(&mut rng, &bp_commitments),
        "BP+ verifier must accept the bond-post range proof"
    );

    // ── Verify 4/4 (FCMP++ membership over the REAL root) is deferred ─
    // The construct→prove half already ran in the shared setup:
    // `sign_transaction_with_terms` assembled and proved over genuine
    // depth-2 branch layers from the production `CurveTreeClient`. The
    // verify half — `shekyl_fcmp::proof::verify` *accepting* a proof over a
    // real multi-layer assembled path — is the live sibling
    // `join_market_bond_post_fcmp_verify_over_real_tree` (CT-5 closed in #162:
    // the partial-branch-chunk bug was fixed by zero-padding branch chunks to
    // circuit width, so that test now runs as a normal `#[tokio::test]`).

    // ── CT balance over PROVER-emitted commitments (real prime-order C) ─
    let pseudo_outs_flat: Vec<u8> = signed.pseudo_outs.iter().flatten().copied().collect();
    let out_masks_flat: Vec<u8> = signed.commitments.iter().flatten().copied().collect();
    verify_bond_post_ct_balance(
        &pseudo_outs_flat,
        &out_masks_flat,
        fee,
        BondTerm::Credit(
            NonZeroAtomicUnits::new(AtomicUnits::from_raw(floor)).expect("bond floor is non-zero"),
        ),
    )
    .expect("bond-post CT balance closes over the real-tree prover output");

    // ── Reject 1: a wrong bond_credit must not balance ───────────────
    assert_eq!(
        verify_bond_post_ct_balance(
            &pseudo_outs_flat,
            &out_masks_flat,
            fee,
            BondTerm::Credit(
                NonZeroAtomicUnits::new(AtomicUnits::from_raw(floor - 1))
                    .expect("bond floor is non-zero")
            ),
        ),
        Err(BondCtBalanceError::SumMismatch),
        "a bond_credit other than the funded floor must break the balance"
    );

    // ── Reject 2: a tampered output commitment is rejected ───────────
    let mut tampered = out_masks_flat.clone();
    tampered[0] ^= 0x01;
    assert!(
        verify_bond_post_ct_balance(
            &pseudo_outs_flat,
            &tampered,
            fee,
            BondTerm::Credit(
                NonZeroAtomicUnits::new(AtomicUnits::from_raw(floor))
                    .expect("bond floor is non-zero")
            ),
        )
        .is_err(),
        "a tampered commitment must not satisfy the balance"
    );

    // ── Reject 3: a signature that does not cover the post is rejected ─
    let mut wrong_preimage = preimage;
    wrong_preimage[0] ^= 0x01;
    assert!(
        !HybridEd25519MlDsa
            .verify(p_keys.hybrid_bond_id(), &wrong_preimage, built.signature())
            .expect("verify against tampered preimage"),
        "the bond signature must not verify against a tampered preimage"
    );

    // ── Reject 4: a replayed post (record already exists) is rejected ─
    assert_eq!(
        verify_join_market_bond_post(built.vin(), true),
        Err(BondPostError::RecordExists),
        "verify must reject a post whose P_canonical_id already has a record"
    );
}

/// Single-sourced setup for the PR 2c-1 real-tree bond-post KATs: build a
/// consistent ledger+tree (depth 2: two drained leaves), assemble the real
/// membership path for the funding leaf via the production
/// `CurveTreeClient`, and sign the bond post with `bond_credit` as the sole
/// output-side cleartext term. The construct→prove half over genuine branch
/// layers happens here; both the active composition KAT and the `#[ignore]`d
/// FCMP++-verify KAT consume the result so the intricate setup is not
/// duplicated.
struct RealTreeBondProofs {
    signed: shekyl_tx_builder::types::SignedProofs,
    tree_ctx: shekyl_tx_builder::TreeContext,
    outputs: Vec<shekyl_tx_builder::types::OutputInfo>,
    built: shekyl_archival_bond_builder::JoinMarketVin,
    p_keys: shekyl_crypto_pq::archival_p::ArchivalPKeys,
    output_key: [u8; 32],
    h_pqc: [u8; 32],
    spend_key_x: [u8; 32],
    fee: u64,
    floor: u64,
    signable_tx_hash: [u8; 32],
}

async fn real_tree_bond_post_proofs() -> RealTreeBondProofs {
    use shekyl_archival_bond_builder::{build_join_market_vin, verify_credit_funding};
    use shekyl_archival_retention::{bond_floor, HoldingsDescriptor, HoldingsKind, ShardSet};
    use shekyl_crypto_pq::account::{SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::output::construct_output;
    use shekyl_tx_builder::types::OutputInfo;
    use shekyl_tx_builder::{sign_transaction_with_terms, LeafEntry, SpendInput, TreeContext};

    // ── Bond persona `P` + holdings → bond floor ─────────────────────
    let p_keys = derive_archival_p_keys(
        &[0x33u8; MASTER_SEED_BYTES],
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        0,
    )
    .expect("derive archival P keys");
    let holdings = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
    };
    let floor = bond_floor(&holdings);
    assert!(
        floor > 0,
        "bond floor must be positive for fixture holdings"
    );

    let fee: u64 = 1_000;
    // Funding covers the change output, the fee, and the bond credit.
    let input_amount: u64 = floor + fee + 1_000_000;
    let signable_tx_hash = [0xC3u8; 32];

    // ── A real, consistent ledger+tree (depth 2: two drained leaves) ─
    // The bond spends gindex 0 (the first leaf); the second leaf makes the
    // tree depth 2 so the assembled path carries genuine branch layers,
    // matching the real-tree transfer KAT's fixture shape.
    let spend_seed = 1u8;
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(spend_seed, input_amount), (2, 25_000)], 1, 20).await;

    // ── Reconstruct funding output identity + derive spend bundle ────
    // Mirrors `funded_ledger_and_tree`'s leaf construction so (`O`, `C`,
    // `h_pqc`) equal the ingested leaf, and `populate_ledger`'s bundle
    // derivation so the spend secrets match the on-chain output.
    let blob = test_account_blob();
    let output_index = u64::from(spend_seed);
    let constructed = construct_output(
        &TEST_OUTPUT_TX_KEY,
        &blob.x25519_pk,
        &blob.ml_kem_ek,
        &test_recipient_spend_pk(),
        input_amount,
        output_index,
    )
    .expect("construct funding output");
    let ciphertext = HybridCiphertext {
        x25519: constructed.kem_ciphertext_x25519,
        ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
    };
    let local = LocalKeys::from_test_seed(PENDING_TX_TEST_RAW_SEED);
    let bundle = local
        .derive_primary_source_secrets_bundle(&ciphertext, output_index)
        .expect("derive spend secrets for funding output");

    // ── Reference selection — mirror the engine `build` path ─────────
    let synced = ledger.with_ledger_block(LedgerBlock::height);
    let rh = select_reference_height(synced).expect("reference height resolves");
    let (curve_tree_root, ref_depth) = tree
        .reference_root_and_depth(BlockHeight(rh))
        .await
        .expect("reference root+depth");
    let block_hash = ledger
        .with_ledger_block(|ledger| ledger.block_hash_at(rh).copied())
        .expect("reference block hash present");
    let reference = ReferenceBlock {
        height: BlockHeight(rh),
        curve_tree_root,
        block_hash,
    };

    // ── Assemble the REAL membership path for the funding output ─────
    let paths = tree
        .assemble_tx(
            reference,
            vec![AssembleInput {
                gindex: Gindex(0),
                output_key: constructed.output_key,
                commitment: constructed.commitment,
            }],
        )
        .await
        .expect("real assemble_path resolves the funding leaf");
    let path = paths
        .first()
        .expect("assemble_tx returns one path per AssembleInput");
    assert_eq!(
        path.tree.tree_depth, ref_depth,
        "assembled path depth agrees with the depth resolved from the same reference block"
    );
    assert_eq!(
        path.tree.tree_depth, 2,
        "the two-leaf consistent fixture yields a real depth-2 tree"
    );
    assert!(
        !path.c1_layers.is_empty() || !path.c2_layers.is_empty(),
        "a real depth-2 path carries genuine branch layers, not a synthetic leaf chunk"
    );

    // Map curve-tree path → tx-builder signing inputs (mirror types).
    let leaf_chunk: Vec<LeafEntry> = path
        .leaf_chunk
        .iter()
        .map(|cl| LeafEntry {
            output_key: cl.output_key,
            key_image_gen: cl.key_image_gen,
            commitment: cl.commitment,
            h_pqc: cl.h_pqc,
        })
        .collect();
    let tree_ctx = TreeContext {
        reference_block: path.tree.reference_block,
        tree_root: path.tree.tree_root,
        tree_depth: path.tree.tree_depth,
    };

    let inputs = vec![SpendInput {
        output_key: constructed.output_key,
        commitment: constructed.commitment,
        amount: AtomicUnits::from_raw(input_amount),
        spend_key_x: *bundle.spend_key_x,
        spend_key_y: *bundle.spend_key_y,
        commitment_mask: *bundle.commitment_mask,
        h_pqc: constructed.h_pqc,
        combined_ss: bundle.combined_ss.to_vec(),
        output_index,
        leaf_chunk,
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    }];

    // ── Build the bond vin + the change output ───────────────────────
    let built = build_join_market_vin(&p_keys, holdings.clone(), &signable_tx_hash)
        .expect("build JoinMarket vin");
    assert_eq!(built.vin().bond_credit, floor);
    assert_eq!(built.vin().bond_debit, 0);

    let change: u64 = input_amount - fee - floor;
    // Offset the change index so (combined_ss, output_index) never collides
    // with the input (a collision zeroes the FCMP++ rerandomization scalar).
    let change_output_index: u64 = output_index + 100;
    let change_out = construct_output(
        &TEST_OUTPUT_TX_KEY,
        &blob.x25519_pk,
        &blob.ml_kem_ek,
        &test_recipient_spend_pk(),
        change,
        change_output_index,
    )
    .expect("construct change output");
    let outputs = vec![OutputInfo {
        dest_key: change_out.output_key,
        amount: AtomicUnits::from_raw(change),
        commitment_mask: change_out.z,
        enc_amount: {
            let mut enc = [0u8; 9];
            enc[..8].copy_from_slice(&change_out.enc_amount);
            enc[8] = change_out.amount_tag;
            enc
        },
        enc_label: {
            let mut enc = [0u8; 9];
            enc[..8].copy_from_slice(&change_out.enc_label);
            enc[8] = change_out.label_tag;
            enc
        },
    }];

    // Amount-level credit-funding rule (§7.3): funding == change + fee + credit.
    verify_credit_funding(
        AtomicUnits::from_raw(input_amount),
        AtomicUnits::from_raw(change),
        AtomicUnits::from_raw(fee),
        &built,
    )
    .expect("credit funding rule holds before proving");

    // ── Prove over the REAL tree: bond_credit is the sole cleartext term ─
    let credit_term = built.credit_term();
    let signed = sign_transaction_with_terms(
        signable_tx_hash,
        &inputs,
        &outputs,
        AtomicUnits::from_raw(fee),
        &[],
        &[credit_term],
        &tree_ctx,
    )
    .expect("sign_transaction_with_terms succeeds over the real tree");

    RealTreeBondProofs {
        signed,
        tree_ctx,
        outputs,
        built,
        p_keys,
        output_key: constructed.output_key,
        h_pqc: constructed.h_pqc,
        spend_key_x: *bundle.spend_key_x,
        fee,
        floor,
        signable_tx_hash,
    }
}

/// `shekyl_fcmp::proof::verify` *accepts* a membership proof built over a
/// **real multi-layer** assembled path — the CT-5 real-tree prove↔verify
/// roundtrip, closing PR 2c-1's deferred half and 2a's milestone.
///
/// This was the first test to verify a real multi-layer path (2a and the FFI
/// round-trip only verify a depth-1 synthetic single-leaf root). It surfaced
/// the partial-branch-chunk bug: `shekyl-curve-tree::assemble` emits narrow
/// chunks for incomplete tree nodes, but the FCMP membership circuit needs the
/// full chunk width, so verify returned `Err(BatchVerificationFailed)`. Fixed
/// by zero-padding branch chunks to width in `shekyl_fcmp::proof::prove` (zero
/// scalars vanish in the layer hash, so the consensus root is unchanged).
#[tokio::test]
async fn join_market_bond_post_fcmp_verify_over_real_tree() {
    use shekyl_fcmp::proof::{verify, KeyImage, ShekylFcmpProof};
    use shekyl_fcmp::PqcLeafScalar;

    use curve25519_dalek::scalar::Scalar;

    let RealTreeBondProofs {
        signed,
        tree_ctx,
        output_key,
        h_pqc,
        spend_key_x,
        signable_tx_hash,
        ..
    } = real_tree_bond_post_proofs().await;

    // Key image L = x · Hp(O); the FCMP++ verifier checks the SAL proof
    // binds this exact image (depth-independent — identical to the 2a path).
    let i_point = shekyl_curve_generators::biased_hash_to_point(output_key);
    let x_scalar = Scalar::from_canonical_bytes(spend_key_x).expect("spend_key_x canonical");
    let key_images = vec![KeyImage::from_canonical_bytes(
        (i_point * x_scalar).compress().to_bytes(),
    )];
    let pqc_pk_hashes = vec![PqcLeafScalar(h_pqc)];
    let proof = ShekylFcmpProof {
        data: signed.fcmp_proof.clone(),
        num_inputs: 1,
        tree_depth: tree_ctx.tree_depth,
    };
    let fcmp_result = verify(
        &proof,
        &key_images,
        &signed.pseudo_outs,
        &pqc_pk_hashes,
        &tree_ctx.tree_root,
        tree_ctx.tree_depth,
        signable_tx_hash,
    );
    assert!(
        matches!(fcmp_result, Ok(true)),
        "FCMP++ verifier must accept the bond-post proof over the real root: {fcmp_result:?}"
    );
}

#[tokio::test]
async fn discard_releases_output_locks() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;

    let first = pending
        .build(standard_request(7_000))
        .await
        .expect("first build");
    pending
        .discard(first.id, DiscardReason::ConsumerExplicit)
        .expect("discard ok");
    assert_eq!(pending.outstanding(), 0);

    let second = pending
        .build(standard_request(7_000))
        .await
        .expect("second build reuses released output");
    assert_eq!(second.id.raw(), 1);
}

#[tokio::test]
async fn discard_blocked_while_in_flight() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx_one().await;

    let built = pending
        .build(standard_request(1_000))
        .await
        .expect("build ok");

    // Force in_flight without completing submit by manipulating state.
    {
        let mut state = pending.state.lock().expect("state lock");
        let held = state
            .consumer_held
            .remove(&built.id)
            .expect("consumer_held entry");
        state.in_flight.insert(
            built.id,
            InFlightSubmit {
                entry: held,
                submitted_at: Instant::now(),
            },
        );
    }

    let err = pending
        .discard(built.id, DiscardReason::ConsumerExplicit)
        .unwrap_err();
    assert!(matches!(
        err,
        PendingTxError::DiscardBlockedPendingDaemonAck { .. }
    ));
}

// ── C7 R9 per-error-class (segment-2h emission shape) ─────────

#[tokio::test]
async fn submit_double_spend_emits_terminal_discarded() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedTerminal {
        kind: TerminalErrorKind::DoubleSpend,
    }));

    let err = pending
        .submit(built.id, built.content_gen)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::DoubleSpend
        }
    ));
    assert_eq!(pending.outstanding(), 0);

    let events = sink.recorded_pending();
    assert!(
        matches!(
            events.as_slice(),
            [
                PendingTxDiagnostic::BuildAttempted { .. },
                PendingTxDiagnostic::BuildSucceeded { .. },
                PendingTxDiagnostic::SubmitAttempted { .. },
                PendingTxDiagnostic::Discarded {
                    reason: DiscardReason::DaemonRejectedTerminal {
                        kind: TerminalErrorKind::DoubleSpend
                    },
                    ..
                },
            ]
        ),
        "unexpected pending diagnostic stream: {events:?}"
    );
}

#[tokio::test]
async fn submit_fee_too_low_releases_outputs() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedTerminal {
        kind: TerminalErrorKind::FeeTooLow,
    }));
    let err = pending
        .submit(built.id, built.content_gen)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::FeeTooLow
        }
    ));
    assert_eq!(pending.outstanding(), 0);

    let second = pending
        .build(standard_request(7_000))
        .await
        .expect("outputs released after terminal reject");
    assert_eq!(second.id.raw(), 1);
    let events = sink.recorded_pending();
    assert!(
        events.iter().any(|e| matches!(
            e,
            PendingTxDiagnostic::Discarded {
                reason: DiscardReason::DaemonRejectedTerminal {
                    kind: TerminalErrorKind::FeeTooLow
                },
                ..
            }
        )),
        "expected terminal Discarded emission: {events:?}"
    );
}

#[tokio::test]
async fn submit_malformed_releases_outputs() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedTerminal {
        kind: TerminalErrorKind::Malformed,
    }));
    assert!(matches!(
        pending.submit(built.id, built.content_gen).await,
        Err(SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::Malformed
        })
    ));
    assert_eq!(pending.outstanding(), 0);
    pending
        .build(standard_request(7_000))
        .await
        .expect("outputs released");
}

// -- F28/F37 loop-breaker (`DAEMON_SUBMIT_VERDICT.md` §2.5) --------------

/// Streak semantics, unit-level over [`SubmitLoopBreaker`] directly.
#[test]
fn loop_breaker_streak_semantics() {
    // Second consecutive same-kind rejection trips, exactly once.
    let mut b = SubmitLoopBreaker::default();
    assert!(!b.record_terminal(TerminalErrorKind::Malformed));
    assert!(b.record_terminal(TerminalErrorKind::Malformed));
    assert_eq!(b.tripped(), Some(TerminalErrorKind::Malformed));
    // Already tripped: no re-alarm on further rejections.
    assert!(!b.record_terminal(TerminalErrorKind::Malformed));

    // A different in-scope kind resets the streak.
    let mut b = SubmitLoopBreaker::default();
    assert!(!b.record_terminal(TerminalErrorKind::FeeTooLow));
    assert!(!b.record_terminal(TerminalErrorKind::Malformed));
    assert!(!b.record_terminal(TerminalErrorKind::FeeTooLow));
    assert_eq!(b.tripped(), None);

    // An accept resets the streak.
    let mut b = SubmitLoopBreaker::default();
    assert!(!b.record_terminal(TerminalErrorKind::FeeTooLow));
    b.record_accept();
    assert!(!b.record_terminal(TerminalErrorKind::FeeTooLow));
    assert_eq!(b.tripped(), None);

    // An out-of-scope kind (`DoubleSpend` — no rebuild prescription,
    // so no loop to break) resets the streak: two in-scope
    // `Unrecognized` rejections with an out-of-scope one between
    // them are not consecutive and must not trip.
    let mut b = SubmitLoopBreaker::default();
    assert!(!b.record_terminal(TerminalErrorKind::Unrecognized));
    assert!(!b.record_terminal(TerminalErrorKind::DoubleSpend));
    assert!(!b.record_terminal(TerminalErrorKind::Unrecognized));
    assert_eq!(b.tripped(), None);

    // `Unrecognized` is in scope (§2.5: the F28 loop-breaker applies).
    let mut b = SubmitLoopBreaker::default();
    assert!(!b.record_terminal(TerminalErrorKind::Unrecognized));
    assert!(b.record_terminal(TerminalErrorKind::Unrecognized));
    assert_eq!(b.tripped(), Some(TerminalErrorKind::Unrecognized));

    // Acknowledgment clears tripped state and streak.
    let mut b = SubmitLoopBreaker::default();
    b.record_terminal(TerminalErrorKind::Malformed);
    b.record_terminal(TerminalErrorKind::Malformed);
    b.acknowledge();
    assert_eq!(b.tripped(), None);
    assert!(!b.record_terminal(TerminalErrorKind::Malformed));
}

/// Drive the breaker through the engine: two consecutive same-kind
/// rejections alarm once and gate `build`; acknowledgment re-enables.
async fn assert_loop_breaker_trips_on(kind: TerminalErrorKind) {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;

    // First rejection: outputs released, no alarm, rebuild allowed.
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedTerminal { kind }));
    pending
        .submit(built.id, built.content_gen)
        .await
        .expect_err("first rejection");

    // One-shot rebuild (the §2.5 disposition) — rejected again.
    let rebuilt = pending
        .build(standard_request(7_000))
        .await
        .expect("one-shot rebuild allowed after first rejection");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedTerminal { kind }));
    pending
        .submit(rebuilt.id, rebuilt.content_gen)
        .await
        .expect_err("second rejection");

    // The second consecutive rejection alarmed exactly once.
    let events = sink.recorded_pending();
    let alarms = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                PendingTxDiagnostic::SubmitLoopBreakerTripped { kind: k, .. } if *k == kind
            )
        })
        .count();
    assert_eq!(alarms, 1, "exactly one alarm per trip: {events:?}");

    // Third build is refused: never loop.
    let err = pending
        .build(standard_request(7_000))
        .await
        .expect_err("third build must be refused while tripped");
    assert!(
        matches!(err, SendError::SubmitLoopBreakerTripped { kind: k } if k == kind),
        "expected SubmitLoopBreakerTripped, got {err:?}"
    );

    // Operator acknowledgment re-enables building.
    pending.acknowledge_submit_loop_breaker();
    pending
        .build(standard_request(7_000))
        .await
        .expect("build allowed after acknowledgment");
}

/// F28: `Malformed` one-shot loop-breaker.
#[tokio::test]
async fn loop_breaker_trips_on_second_consecutive_malformed() {
    assert_loop_breaker_trips_on(TerminalErrorKind::Malformed).await;
}

/// F37: `FeeTooLow` bounded retry — second consecutive `FeeTooLow`
/// on the rebuilt tx → alarm, no third build.
#[tokio::test]
async fn loop_breaker_trips_on_second_consecutive_fee_too_low() {
    assert_loop_breaker_trips_on(TerminalErrorKind::FeeTooLow).await;
}

/// §2.5 retryable rejection (`StaleRoot` / `ReferenceTooRecent` /
/// `ReferenceNotFound`): the reservation is restored to
/// `consumer_held` with its `output_locks` retained — a definite
/// verdict whose remedy preserves the input selection — and the
/// same reservation is resubmittable afterwards.
#[tokio::test]
async fn submit_retryable_rejection_restores_reservation() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::RejectedRetryable {
        cause: RetryableRejectCause::StaleRoot,
    }));

    let err = pending
        .submit(built.id, built.content_gen)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SubmitError::DaemonRejectedRetryable {
            cause: RetryableRejectCause::StaleRoot,
            ..
        }
    ));

    // Restored to consumer_held with output locks retained: the
    // reservation is still outstanding, back under consumer
    // ownership, and its inputs stay locked against competing
    // selection.
    assert_eq!(pending.outstanding(), 1);
    {
        let state = pending.state.lock().expect("state lock");
        assert!(
            state.consumer_held.contains_key(&built.id),
            "reservation restored to consumer_held"
        );
        assert!(
            !state.in_flight.contains_key(&built.id),
            "reservation no longer in flight"
        );
        assert!(
            state.output_locks.values().any(|owner| *owner == built.id),
            "output locks retained for the restored reservation"
        );
    }

    let events = sink.recorded_pending();
    assert!(
        events.iter().any(|e| matches!(
            e,
            PendingTxDiagnostic::SubmitRetryablyRejected {
                cause: RetryableRejectCause::StaleRoot,
                ..
            }
        )),
        "expected SubmitRetryablyRejected emission: {events:?}"
    );

    // The restored reservation resubmits — this time accepted.
    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("restored reservation resubmits");
    assert_eq!(tx_hash, canonical_tx_id(&built.tx_bytes));
    assert_eq!(pending.outstanding(), 0);
}

#[tokio::test]
async fn submit_timeout_keeps_reservation_in_flight() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::Ambiguous {
        kind: AmbiguousErrorKind::DaemonTimeout,
    }));

    let err = pending
        .submit(built.id, built.content_gen)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SubmitError::DaemonAmbiguous {
            kind: AmbiguousErrorKind::DaemonTimeout,
            ..
        }
    ));
    assert_eq!(pending.outstanding(), 1);

    let events = sink.recorded_pending();
    assert!(
        matches!(
            events.last(),
            Some(PendingTxDiagnostic::SubmitPendingResolution {
                kind: AmbiguousErrorKind::DaemonTimeout,
                ..
            })
        ),
        "expected SubmitPendingResolution, got {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PendingTxDiagnostic::Discarded { .. })),
        "ambiguous submit must not emit Discarded: {events:?}"
    );

    let discard_err = pending
        .discard(built.id, DiscardReason::ConsumerExplicit)
        .unwrap_err();
    assert!(matches!(
        discard_err,
        PendingTxError::DiscardBlockedPendingDaemonAck { .. }
    ));
}

#[tokio::test]
async fn submit_daemon_unavailable_same_as_timeout() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::Ambiguous {
        kind: AmbiguousErrorKind::DaemonUnavailable,
    }));
    assert!(matches!(
        pending.submit(built.id, built.content_gen).await,
        Err(SubmitError::DaemonAmbiguous {
            kind: AmbiguousErrorKind::DaemonUnavailable,
            ..
        })
    ));
    assert_eq!(pending.outstanding(), 1);
}

// ── Phase 0m: signal_mempool_evicted (STAGE_1_PR_5 §5.6.12 C5β) ─

async fn build_in_flight_via_daemon_timeout(pending: &TestPendingTx) -> PendingTx {
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending.queue_submit_daemon_outcome(Err(SubmitterError::Ambiguous {
        kind: AmbiguousErrorKind::DaemonTimeout,
    }));
    assert!(matches!(
        pending.submit(built.id, built.content_gen).await,
        Err(SubmitError::DaemonAmbiguous {
            kind: AmbiguousErrorKind::DaemonTimeout,
            ..
        })
    ));
    assert_eq!(pending.outstanding(), 1);
    built
}

#[tokio::test]
async fn signal_mempool_evicted_on_in_flight_succeeds() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let built = build_in_flight_via_daemon_timeout(&pending).await;
    pending
        .signal_mempool_evicted(built.id)
        .expect("in_flight eviction succeeds");
    assert_eq!(pending.outstanding(), 0);
}

#[tokio::test]
async fn signal_mempool_evicted_on_consumer_held_returns_not_found() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    let err = pending
        .signal_mempool_evicted(built.id)
        .expect_err("consumer_held is not eviction-relevant");
    assert!(matches!(err, PendingTxError::ReservationNotFound { .. }));
}

#[tokio::test]
async fn signal_mempool_evicted_on_never_existed_returns_not_found() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let err = pending
        .signal_mempool_evicted(ReservationId::new(99))
        .expect_err("unknown rid");
    assert!(matches!(err, PendingTxError::ReservationNotFound { .. }));
}

#[tokio::test]
async fn signal_mempool_evicted_emits_mempool_evicted_diagnostic() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let built = build_in_flight_via_daemon_timeout(&pending).await;
    pending
        .signal_mempool_evicted(built.id)
        .expect("eviction ok");
    let events = sink.recorded_pending();
    assert!(
        matches!(
            events.last(),
            Some(PendingTxDiagnostic::Discarded {
                reason: DiscardReason::MempoolEvicted,
                ..
            })
        ),
        "expected MempoolEvicted diagnostic, got {events:?}"
    );
}

#[tokio::test]
async fn signal_mempool_evicted_releases_output_locks() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let built = build_in_flight_via_daemon_timeout(&pending).await;
    pending
        .signal_mempool_evicted(built.id)
        .expect("eviction releases locks");
    assert_eq!(pending.outstanding(), 0);
    let second = pending
        .build(standard_request(7_000))
        .await
        .expect("outputs released after eviction");
    assert_eq!(second.id.raw(), 1);
}

/// F2 ownership boundary: ambiguous `in_flight` admits eviction signal;
/// post-eviction `discard` is idempotent-not-found, not blocked.
#[tokio::test]
async fn signal_mempool_evicted_ownership_boundary() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
    let built = build_in_flight_via_daemon_timeout(&pending).await;

    pending
        .discard(built.id, DiscardReason::ConsumerExplicit)
        .expect_err("consumer cannot force-discard ambiguous in_flight");
    pending
        .signal_mempool_evicted(built.id)
        .expect("eviction observation succeeds");
    assert_eq!(pending.outstanding(), 0);

    let err = pending
        .discard(built.id, DiscardReason::ConsumerExplicit)
        .expect_err("rid gone after eviction");
    assert!(matches!(err, PendingTxError::ReservationNotFound { .. }));
}

// ── C7 emission/return coherence ──────────────────────────────

#[tokio::test]
async fn pending_tx_build_emission_return_coherence() {
    let sink = Arc::new(AssertionSink::new());
    let (pending, _ledger, _tree_dir) =
        funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
    let err = pending
        .build(standard_request(999_999_999))
        .await
        .unwrap_err();
    assert!(matches!(err, SendError::InsufficientFunds { .. }));
    let events = sink.recorded_pending();
    assert!(
        matches!(
            events.as_slice(),
            [
                PendingTxDiagnostic::BuildAttempted { .. },
                PendingTxDiagnostic::BuildFailed { .. },
            ]
        ),
        "build error must emit BuildFailed before return: {events:?}"
    );
}

/// CT-5d (§5): a benign tip advance no longer invalidates a still-canonical,
/// in-window proof — it broadcasts as-is, with no re-anchor. This replaces the
/// pre-CT-5d `SnapshotInvalidated`-on-every-block behavior: the reference, not
/// the `SnapshotId`, is now the staleness authority.
#[tokio::test]
async fn submit_carries_proof_across_benign_tip_advance() {
    let sink = Arc::new(AssertionSink::new());
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree_and_sink(
        Arc::clone(&ledger),
        tree,
        Arc::clone(&sink) as Arc<dyn DiagnosticSink>,
    );
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    // Reference anchored at tip(20) − REF_ANCHOR_AGE(6) = 14.
    assert_eq!(built.reference_height, 14);

    // Advance the tip a few blocks with no reorg: reference age 25 − 14 = 11,
    // well within the daemon window and still canonical → not stale.
    populate_ledger(
        ledger.as_ref(),
        21,
        vec![make_recovered_output(3, 200, 1_000)],
        25,
    );

    pending
        .submit(built.id, built.content_gen)
        .await
        .expect("benign tip advance broadcasts the existing proof as-is");
    assert_eq!(pending.outstanding(), 0, "submit consumed the reservation");

    let events = sink.recorded_pending();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PendingTxDiagnostic::SubmitSucceeded { .. })),
        "benign advance must submit successfully: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PendingTxDiagnostic::SubmitSnapshotInvalidated { .. })),
        "CT-5d retires SnapshotInvalidated on a benign tip advance: {events:?}"
    );
}

#[tokio::test]
async fn pending_tx_panicking_sink_unwind_safe_on_build() {
    let sink = Arc::new(PanickingSink::new(PanickingSinkTrigger::Any));
    let pending = test_pending_tx_with_sink(funded_ledger(), sink);
    let join = tokio::spawn(async move { pending.build(standard_request(7_000)).await }).await;
    assert!(
        join.is_err(),
        "PanickingSink::Any must panic the spawned build task"
    );

    let (recovery, _r_ledger, _r_tree_dir) = funded_pending_tx().await;
    assert_eq!(recovery.outstanding(), 0);
    recovery
        .build(standard_request(7_000))
        .await
        .expect("engine usable after sink panic");
    assert_eq!(recovery.outstanding(), 1);
}

/// CT-5d (§4): the `content_gen` consent gate. Submitting with a `seen_gen`
/// that does not match the reservation's materialized `content_gen` is
/// withheld as [`SubmitError::ContentChanged`] — never broadcast — and the
/// reservation stays `consumer_held`. Re-confirming with the correct
/// generation broadcasts. (Here the mismatch is synthetic: a fresh build is
/// generation 0, so a consumer passing a stale generation 1 is refused.)
#[tokio::test]
async fn submit_with_mismatched_seen_gen_is_withheld_as_content_changed() {
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
    let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    assert_eq!(built.content_gen, 0, "a fresh build is generation 0");

    // Submit immediately (no tip advance → not stale, no re-anchor) with a
    // generation the consumer never saw: withhold, do not broadcast.
    let err = pending
        .submit(built.id, built.content_gen + 1)
        .await
        .unwrap_err();
    let SubmitError::ContentChanged {
        reservation_id,
        content_gen,
    } = err
    else {
        panic!("expected ContentChanged, got {err:?}");
    };
    assert_eq!(reservation_id, built.id);
    assert_eq!(
        content_gen, 0,
        "the materialized generation to re-confirm with"
    );
    assert_eq!(
        pending.outstanding(),
        1,
        "withheld: the reservation stays consumer_held"
    );

    // Re-confirming with the correct generation broadcasts.
    pending
        .submit(built.id, 0)
        .await
        .expect("correct seen_gen broadcasts");
    assert_eq!(pending.outstanding(), 0);
}

/// Scan ingest only — leaves `key_image == None` (production scan sentinel path).
fn populate_ledger_scan_only(
    ledger: &LocalLedger,
    block_height: u64,
    outputs: Vec<RecoveredWalletOutput>,
    final_height: u64,
) {
    use shekyl_scanner::{LedgerIndexesExt, Timelocked};

    let mut guard = ledger.write();
    let state = &mut *guard;
    let ledger_block = &mut state.ledger.ledger;
    let indexes = &mut state.indexes;
    let timelocked = Timelocked::from_vec(outputs);
    let block_hash = [u8::try_from(block_height & 0xFF).unwrap(); 32];
    let inserted_range =
        indexes.process_scanned_outputs(ledger_block, block_height, block_hash, timelocked);
    assert!(!inserted_range.is_empty() || ledger_block.transfer_count() == 0);
    for h in (block_height + 1)..=final_height {
        let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
        let _ = indexes.process_scanned_outputs(
            ledger_block,
            h,
            hash,
            Timelocked::from_vec(Vec::new()),
        );
    }
}

fn daemon_fee_estimates_distinct() -> FeeEstimates {
    FeeEstimates {
        economy: FeeRate::new(1, 1).expect("economy rate"),
        standard: FeeRate::new(10, 1).expect("standard rate"),
        priority: FeeRate::new(100, 1).expect("priority rate"),
        quantization_mask: 1,
    }
}

type DaemonBackedPendingTx = LocalPendingTx<
    LocalSigner,
    WalletGreedyOutputSelector,
    DaemonFeeEstimator,
    crate::engine::fee_snapshot::DaemonFeeSnapshotSource<crate::engine::test_support::TestDaemon>,
    crate::engine::transaction_submitter::DaemonTransactionSubmitter<
        crate::engine::test_support::TestDaemon,
    >,
    LocalLedger,
>;

fn daemon_backed_pending_tx(
    daemon: Arc<crate::engine::test_support::TestDaemon>,
    ledger: Arc<LocalLedger>,
    tree: CurveTreeHandle,
) -> DaemonBackedPendingTx {
    daemon.set_fee_estimates(daemon_fee_estimates_distinct());
    LocalPendingTx::new(
        Arc::new(LocalSigner::new(test_signer_handle())),
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        crate::engine::fee_snapshot::DaemonFeeSnapshotSource::from_arc(Arc::clone(&daemon)),
        Arc::new(crate::engine::transaction_submitter::DaemonTransactionSubmitter::new(daemon)),
        ledger,
        Some(tree),
        Arc::new(TracingDiagnosticSink),
        ReservationTTLConfig::default(),
        Network::Mainnet,
    )
}

/// PHASE_2A_SEND_PATH.md §8.3 — outputs stay locked after build until submit/discard.
#[tokio::test]
async fn reserved_outputs_blocked_from_second_build() {
    let (pending, _ledger, _tree_dir) = funded_pending_tx_one().await;
    let _first = pending
        .build(standard_request(7_000))
        .await
        .expect("first build");
    let err = pending.build(standard_request(1_000)).await.unwrap_err();
    assert!(
        matches!(err, SendError::InsufficientFunds { .. }),
        "second build must not double-select reserved output: {err:?}"
    );
}

#[test]
fn assemble_tx_to_sign_rejects_missing_key_image() {
    use crate::engine::signing_assembly::assemble_tx_to_sign;
    use crate::engine::tx_fee_model::build_fee_directive;
    use shekyl_curve_tree::{AssembleInput, AssembledPath, Gindex, TreeContext as CtTreeContext};
    use shekyl_rpc_client::FeeRate;

    let ledger = Arc::new(test_ledger());
    populate_ledger_scan_only(
        ledger.as_ref(),
        1,
        vec![make_recovered_output(1, 100, 50_000)],
        20,
    );
    let request = standard_request(7_000);
    let rate = FeeRate::new(10, 1).expect("rate");
    let fee_directive = build_fee_directive(
        &rate,
        InputCount::clamped(1),
        OutputCount::clamped(request.recipients.len()),
        1,
    );
    // The `gindex` must equal the output's `global_output_index` (100) so the
    // index-stability guard passes and the missing-`key_image` check inside
    // `input_context_from_transfer` is reached. The path is unused before
    // that check fires, so a placeholder suffices.
    let assemble_inputs = vec![AssembleInput {
        gindex: Gindex(100),
        output_key: [0u8; 32],
        commitment: [0u8; 32],
    }];
    let paths = vec![AssembledPath {
        leaf_chunk: Vec::new(),
        c1_layers: Vec::new(),
        c2_layers: Vec::new(),
        tree: CtTreeContext {
            reference_block: [0u8; 32],
            tree_root: [0u8; 32],
            tree_depth: 1,
        },
    }];
    let err = ledger.with_ledger_block(|block| {
        assemble_tx_to_sign(
            Network::Mainnet,
            &request,
            &[0],
            block.transfers(),
            &assemble_inputs,
            &paths,
            fee_directive,
        )
    });
    let Err(SendError::CannotSign { reason }) = err else {
        panic!("expected CannotSign for missing key_image, got {err:?}");
    };
    assert!(
        reason.contains("key_image"),
        "reason should name key_image: {reason}"
    );
}

/// PHASE_2A_SEND_PATH.md §8.3 — daemon fee flows through to built tx.
#[tokio::test]
async fn build_then_submit_via_test_daemon_uses_daemon_fee() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};
    use crate::engine::tx_fee_model::{
        converge_fee, fee_from_weight, fee_rate_for_priority, predict_weight,
    };

    let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 500_000), (2, 300_000)], 1, 20).await;
    let pending = daemon_backed_pending_tx(Arc::clone(&daemon), Arc::clone(&ledger), tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    assert!(!built.tx_bytes.is_empty());

    let tx = shekyl_wire::Transaction::from_bytes(&built.tx_bytes).expect("built tx parses");
    let n_in = tx.prefix.inputs.len();
    let n_out = tx.prefix.outputs.len();

    let snapshot = daemon_fee_estimates_distinct();
    let rate = fee_rate_for_priority(FeePriority::Standard, &snapshot).expect("standard rate");
    // Real tree depth for the 2-leaf consistent fixture is 2.
    let seed = fee_from_weight(
        &rate,
        predict_weight(InputCount::clamped(n_in), OutputCount::clamped(n_out), 2, 0),
    );
    let expected_fee = converge_fee(
        &rate,
        InputCount::clamped(n_in),
        OutputCount::clamped(n_out),
        2,
        seed,
    );
    assert_eq!(
        built.fee_atomic_units.to_raw(),
        expected_fee,
        "built fee must match daemon Standard tier through production path"
    );
    // Build-path weight cross-check: the a-priori `predict_weight` equals the
    // canonical weight of the bytes actually built (same n_in/n_out/depth/fee).
    let (depth, fee) = match &tx.ct {
        shekyl_wire::Ct::Fcmp {
            prunable: Some(p),
            fee,
            ..
        } => (
            // Wire `curve_trees_tree_depth` is the LMDB depth = proof layer
            // count − 1 (`build_wire_tx`); `predict_weight` models the FCMP++
            // proof size from the layer count, so add 1 back.
            u8::try_from(p.tree_depth + 1).expect("tree_depth + 1 fits u8"),
            *fee,
        ),
        _ => panic!("a spend is Fcmp with prunable"),
    };
    assert_eq!(
        predict_weight(
            InputCount::clamped(n_in),
            OutputCount::clamped(n_out),
            depth,
            fee
        ),
        tx.weight(),
        "predict_weight must equal the built tx's canonical weight"
    );

    let tx_hash = pending
        .submit(built.id, built.content_gen)
        .await
        .expect("submit ok");
    assert_eq!(tx_hash, canonical_tx_id(&built.tx_bytes));
    assert_eq!(daemon.submitted_count(), 1);

    // F14 (§2.6): accept places the awaiting-confirmation lock, not a
    // durable `spent` write.
    {
        let guard = pending.ledger.read();
        let td = guard.ledger.ledger.transfers().first().expect("output 0");
        assert!(!td.spent, "spent stays refresh-authoritative");
        assert_eq!(
            td.awaiting_confirmation
                .as_ref()
                .expect("submit-accept places the F14 lock")
                .tx_hash,
            tx_hash
        );
    }
}

#[tokio::test]
async fn daemon_dedupes_identical_tx_bytes() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};
    use crate::engine::transaction_submitter::DaemonTransactionSubmitter;

    let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
    let (ledger, _tree_dir, tree) =
        funded_ledger_and_tree(&[(1, 500_000), (2, 300_000)], 1, 20).await;
    let pending = daemon_backed_pending_tx(Arc::clone(&daemon), ledger, tree);

    let built = pending
        .build(standard_request(7_000))
        .await
        .expect("build ok");
    pending
        .submit(built.id, built.content_gen)
        .await
        .expect("first submit");
    assert_eq!(daemon.submitted_count(), 1);

    let submitter = DaemonTransactionSubmitter::new(Arc::clone(&daemon));
    let success = submitter
        .submit(built.tx_bytes.clone())
        .await
        .expect("daemon dedup accepts identical bytes");
    // A pool-resident duplicate is `AlreadyInPool` → the `Broadcast`
    // disposition (§2.5: same as a fresh accept), carrying the local hash.
    assert_eq!(
        success,
        SubmitSuccess::Broadcast {
            hash: canonical_tx_id(&built.tx_bytes)
        }
    );
    assert_eq!(daemon.submitted_count(), 1);

    let err = pending
        .submit(built.id, built.content_gen)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SubmitError::ReservationNotFound { .. }),
        "reservation consumed after first submit: {err:?}"
    );
}
