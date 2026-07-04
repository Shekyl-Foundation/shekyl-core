// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Production-verifier oracle suite: [`DaemonTxVerifier`] over a **real
//! consensus-valid FCMP++ spend** built through the production stack
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §10 item 3).
//!
//! The fixture is the `shekyl-wire` `fcmp_spend_e2e` construction, re-derived
//! at the depth-2 scale (one Selene chunk overflowed) and carried through the
//! **production wallet signing order** (`sign_bridge.rs` parity): proofs
//! first, then `phase1_payload_hashes` over the proof-bearing wire tx with a
//! stub (empty-signature) auth, then `sign_pqc_auths` over those consensus
//! payload hashes — the hashes the daemon's K13 battery re-derives. (The
//! `fcmp_spend_e2e` oracle signs the prefix hash instead; its scope is the
//! serializer, not the daemon battery. This suite is where the payload-hash
//! contract is exercised end-to-end.)
//!
//! Every negative case is a **single-field mutation of that valid spend**, so
//! a rejection can only be attributable to the mutated field: the mutants
//! re-clear Phase A (structural admission) by construction and fail in the
//! Phase-C arm named by the test. Mutation targets are spec-derived (§8 rows
//! O6 / N8 / K10 / K12 / K13), not observed-behavior-derived
//! (`50-testing.mdc`).

mod submit_fixtures;

use std::sync::{Arc, OnceLock};

use curve25519_dalek::constants::{ED25519_BASEPOINT_COMPRESSED, ED25519_BASEPOINT_POINT};
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_crypto_pq::output::{
    compute_output_key_image, construct_output, recover_combined_ss, OutputData,
};
use shekyl_curve_tree::{
    AssembleInput, BlockHeight as TreeHeight, BlockLeaves, CurveTreeClient, Gindex, RawOutput,
    ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_daemon_rpc::submit::{
    parse_submission, CommitOutcome, DaemonTxVerifier, KeyImageConflict, ParsedSubmission,
    ReferenceFacts, SubmitCaller, SubmitEngine, SubmitFacts, SubmitTxKind, TxVerifier,
    VerifyFailure,
};
use shekyl_fcmp::tree::SELENE_CHUNK_WIDTH;
use shekyl_fcmp::MAX_TREE_DEPTH;
use shekyl_rpc_types::SubmitVerdict;
use shekyl_tx_builder::{
    encode_final_tx, phase1_payload_hashes, sign_pqc_auths, sign_transaction,
    tx_prefix_hash_from_parts, LeafEntry, OutputInfo, PqcAuth as BuilderPqcAuth, SpendInput,
    TreeContext, WireEncodeInput,
};
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, CtBase, PqcAuth, Prunable, Transaction};

use submit_fixtures::{hexify, serve_credit_tx, MockShim};

/// Coinbase lock window: the genesis coinbase drains into the tree at
/// reference heights `>= COINBASE_LOCK_WINDOW + 1` (fcmp_spend_e2e's
/// derivation, sourced from the consensus constant).
const COINBASE_LOCK_WINDOW: u64 = shekyl_consensus::COINBASE_LOCK_WINDOW as u64;

/// Genesis output count: one Selene chunk plus two, the minimal overflow
/// that forces a **depth-2** tree (leaf chunk + one Helios branch) — the
/// smallest spendable shape (`build_wire_tx` requires layer count ≥ 2), so
/// the expensive prove/verify battery runs at its cheapest real scale. The
/// depth-3 both-branch-curves surface is `fcmp_spend_e2e`'s scope, not
/// re-proved here.
const TREE_OUTPUTS: usize = SELENE_CHUNK_WIDTH + 2;

/// Fixed witness seed, same rationale as `fcmp_spend_e2e::RNG_SEED`: one
/// expensive single-case oracle, replayable on failure. KEM keypairs and
/// prover randomness stay OS-drawn; by proof completeness they cannot flip
/// the accept/reject outcome for a fixed valid witness.
const RNG_SEED: u64 = 0x5375_626d_6974_3031; // "Submit01"

const INPUT_AMOUNT: u64 = 1_000_000_000;
const FEE: u64 = 1_000_000;

/// The one-time expensive fixture: a consensus-valid spend and the tree
/// facts it verifies against.
struct SpendFixture {
    /// The canonical submit hex (what a wallet would POST).
    hex: String,
    /// Its Phase-A parse — the verifier's input.
    parsed: ParsedSubmission,
    /// Curve-tree root at the reference height (the proof's real anchor).
    tree_root: [u8; 32],
    /// A *different but equally valid* root (one block later, one more
    /// matured leaf) for the wrong-root determinism case.
    other_root: [u8; 32],
    /// Reference height the proof was assembled at.
    reference_height: u64,
    /// Consensus/LMDB tree depth (layer count − 1) at the reference height.
    lmdb_depth: u8,
}

static FIXTURE: OnceLock<SpendFixture> = OnceLock::new();

fn fixture() -> &'static SpendFixture {
    FIXTURE.get_or_init(build_fixture)
}

/// Snapshot facts under which the fixture spend is fully admissible: the
/// real root/depth at the reference height, chain height inside the
/// [min, max] reference-age window, floor of 1/byte, the Shekyl weight
/// limit.
fn admitting_facts(fx: &SpendFixture) -> SubmitFacts {
    SubmitFacts {
        in_pool: false,
        in_pool_broadcast: false,
        in_chain: false,
        key_image_conflicts: vec![KeyImageConflict::Free; fx.parsed.key_images.len()],
        reference: Some(ReferenceFacts {
            height: BlockHeight::from_raw(fx.reference_height),
            root: fx.tree_root,
            tree_depth: fx.lmdb_depth,
        }),
        fee_per_byte: 1,
        fee_quantization_mask: 1,
        weight_limit: 149_400,
        // Reference age 6: ≥ FCMP_REFERENCE_BLOCK_MIN_AGE (5), well under
        // the max (100).
        chain_height: BlockHeight::from_raw(fx.reference_height + 6),
    }
}

fn verify(parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
    DaemonTxVerifier.verify(parsed, facts)
}

/// Re-run Phase A over a mutated transaction. Every mutant in this suite
/// must clear Phase A — the arm under test is the Phase-C battery, and a
/// mutant that already fails structural admission would test nothing.
fn reparse(tx: &Transaction) -> ParsedSubmission {
    parse_submission(&hexify(tx))
        .expect("mutant must clear Phase A (the arm under test is Phase C)")
}

/// Clone the fixture spend, apply one mutation, re-clear Phase A.
fn mutated(f: impl FnOnce(&mut Transaction)) -> ParsedSubmission {
    let mut tx = fixture().parsed.tx.clone();
    f(&mut tx);
    reparse(&tx)
}

/// Mutable access to the spend's Fcmp ct fields (fee, committed base,
/// pqc_auths, prunable) — total for the fixture by construction.
fn fcmp_parts_mut(
    tx: &mut Transaction,
) -> (&mut u64, &mut CtBase, &mut Vec<PqcAuth>, &mut Prunable) {
    let Ct::Fcmp {
        fee,
        base,
        pqc_auths,
        prunable,
        ..
    } = &mut tx.ct
    else {
        panic!("spend fixture carries an Fcmp ct");
    };
    (
        fee,
        base,
        pqc_auths,
        prunable.as_mut().expect("spend fixture carries a prunable"),
    )
}

/// A minimal spendable wallet (spend keypair + hybrid KEM keypair) — the
/// typed analogue of `fcmp_spend_e2e`'s.
struct Wallet {
    spend_secret: [u8; 32],
    spend_public: [u8; 32],
    x25519_pk: [u8; 32],
    x25519_sk: [u8; 32],
    ml_kem_ek: Vec<u8>,
    ml_kem_dk: Vec<u8>,
}

fn random_wallet(rng: &mut ChaCha20Rng) -> Wallet {
    let b = Scalar::random(rng);
    let spend_public = (ED25519_BASEPOINT_POINT * b).compress().to_bytes();
    let (pk, sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    Wallet {
        spend_secret: b.to_bytes(),
        spend_public,
        x25519_pk: pk.x25519,
        x25519_sk: sk.x25519,
        ml_kem_ek: pk.ml_kem,
        ml_kem_dk: sk.ml_kem.clone(),
    }
}

/// A random prime-order compressed point for decoy tree members.
fn random_point(rng: &mut ChaCha20Rng) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * Scalar::random(rng))
        .compress()
        .to_bytes()
}

fn pack_output_info(out: &OutputData, amount: u64) -> OutputInfo {
    let mut enc_amount = [0u8; 9];
    enc_amount[..8].copy_from_slice(&out.enc_amount);
    enc_amount[8] = out.amount_tag;
    let mut enc_label = [0u8; 9];
    enc_label[..8].copy_from_slice(&out.enc_label);
    enc_label[8] = out.label_tag;
    OutputInfo {
        dest_key: out.output_key,
        amount: AtomicUnits::from_raw(amount),
        commitment_mask: out.z,
        enc_amount,
        enc_label,
    }
}

fn build_fixture() -> SpendFixture {
    // ── Wallet + the spent output (fcmp_spend_e2e stages 1–5, depth-2) ──
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED);
    let wallet = random_wallet(&mut rng);
    let spent_index: u64 = 0;

    let tx_secret = Scalar::random(&mut rng).to_bytes();
    let spent = construct_output(
        &tx_secret,
        &wallet.x25519_pk,
        &wallet.ml_kem_ek,
        &wallet.spend_public,
        INPUT_AMOUNT,
        spent_index,
    )
    .expect("construct spent output");

    let combined_ss = recover_combined_ss(
        &wallet.x25519_sk,
        &wallet.ml_kem_dk,
        &spent.kem_ciphertext_x25519,
        &spent.kem_ciphertext_ml_kem,
    )
    .expect("recover combined shared secret");

    let hp_of_o = shekyl_curve_generators::biased_hash_to_point(spent.output_key)
        .compress()
        .to_bytes();
    let ki = compute_output_key_image(&combined_ss.0, spent_index, &wallet.spend_secret, &hp_of_o)
        .expect("compute key image");

    // Genesis coinbase: the spent output at vout 0 plus decoys — one chunk
    // overflowed, so the tree is depth 2. Every decoy shares the spent
    // output's (valid) h_pqc; distinct O/C points keep leaf hashes distinct.
    let mut genesis_outputs: Vec<RawOutput> = Vec::with_capacity(TREE_OUTPUTS);
    let mut genesis_blob: Vec<u8> = Vec::with_capacity(TREE_OUTPUTS * 32);
    genesis_outputs.push(RawOutput {
        output_key: spent.output_key,
        commitment: Some(spent.commitment),
        target: TargetKind::TaggedKey,
    });
    genesis_blob.extend_from_slice(&spent.h_pqc);
    for _ in 1..TREE_OUTPUTS {
        genesis_outputs.push(RawOutput {
            output_key: random_point(&mut rng),
            commitment: Some(random_point(&mut rng)),
            target: TargetKind::TaggedKey,
        });
        genesis_blob.extend_from_slice(&spent.h_pqc);
    }

    // Consecutive block ingestion with one decoy coinbase per filler block;
    // the genesis coinbase drains at reference height LOCK_WINDOW + 1, the
    // height-1 filler one block later (the `other_root` state).
    let filler_key = random_point(&mut rng);
    let filler_commitment = random_point(&mut rng);
    let reference_height = COINBASE_LOCK_WINDOW + 1;

    let mut client = CurveTreeClient::new();
    for height in 0..=(reference_height + 1) {
        let (outputs, blob): (Vec<RawOutput>, Vec<u8>) = if height == 0 {
            (genesis_outputs.clone(), genesis_blob.clone())
        } else {
            (
                vec![RawOutput {
                    output_key: filler_key,
                    commitment: Some(filler_commitment),
                    target: TargetKind::TaggedKey,
                }],
                spent.h_pqc.to_vec(),
            )
        };
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(blob.as_slice()),
            outputs: outputs.as_slice(),
        }];
        client
            .ingest_block(BlockLeaves {
                height: TreeHeight(height),
                txs: &txs,
            })
            .expect("ingest block");
    }

    let (tree_root, tree_depth) = client
        .root_and_depth_at(TreeHeight(reference_height))
        .expect("tree root + depth at reference height");
    assert_eq!(
        usize::from(tree_depth),
        2,
        "one overflowed Selene chunk must build a depth-2 tree"
    );
    // One block later the height-1 filler has matured into the tree: a
    // different, equally valid root at the same depth.
    let (other_root, other_depth) = client
        .root_and_depth_at(TreeHeight(reference_height + 1))
        .expect("tree root + depth one block later");
    assert_eq!(other_depth, tree_depth, "one extra leaf keeps depth 2");
    assert_ne!(other_root, tree_root, "one extra leaf moves the root");

    // ── Membership path + SpendInput ────────────────────────────────────
    let reference = ReferenceBlock {
        height: TreeHeight(reference_height),
        curve_tree_root: tree_root,
        block_hash: [0xAB; 32],
    };
    let target = AssembleInput {
        gindex: Gindex(spent_index),
        output_key: spent.output_key,
        commitment: spent.commitment,
    };
    let path = client
        .assemble_path(&target, &reference)
        .expect("assemble membership path");
    assert_eq!(
        path.c1_layers.len() + path.c2_layers.len() + 1,
        usize::from(path.tree.tree_depth),
        "C3 invariant: c1 + c2 + 1 (leaf) == tree_depth"
    );

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
    let spend_input = SpendInput {
        output_key: spent.output_key,
        commitment: spent.commitment,
        amount: AtomicUnits::from_raw(INPUT_AMOUNT),
        spend_key_x: *ki.spend_secret_x,
        spend_key_y: spent.y,
        commitment_mask: spent.z,
        h_pqc: spent.h_pqc,
        combined_ss: combined_ss.0.to_vec(),
        output_index: spent_index,
        leaf_chunk,
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    };

    // ── Two destinations (payment + change; §12 requires ≥ 2 outputs) ───
    let recipient = random_wallet(&mut rng);
    let dest_secret = Scalar::random(&mut rng).to_bytes();
    let output_amount = INPUT_AMOUNT - FEE;
    let payment_amount = output_amount / 2;
    let change_amount = output_amount - payment_amount;
    let payment = construct_output(
        &dest_secret,
        &recipient.x25519_pk,
        &recipient.ml_kem_ek,
        &recipient.spend_public,
        payment_amount,
        0,
    )
    .expect("construct payment output");
    let change = construct_output(
        &dest_secret,
        &wallet.x25519_pk,
        &wallet.ml_kem_ek,
        &wallet.spend_public,
        change_amount,
        1,
    )
    .expect("construct change output");
    let outputs = [
        pack_output_info(&payment, payment_amount),
        pack_output_info(&change, change_amount),
    ];

    // ── Phase-1 proofs, bound to the real prefix ────────────────────────
    let tx_prefix_hash = tx_prefix_hash_from_parts(
        &[*ki.key_image.as_bytes()],
        &[payment.output_key, change.output_key],
        &[
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ],
        &[],
    );
    let tree_ctx = TreeContext {
        reference_block: path.tree.reference_block,
        tree_root: path.tree.tree_root,
        tree_depth: path.tree.tree_depth,
    };
    let signed = sign_transaction(
        tx_prefix_hash,
        std::slice::from_ref(&spend_input),
        &outputs,
        AtomicUnits::from_raw(FEE),
        &tree_ctx,
    )
    .expect("sign transaction");

    // ── Phase-2 PQC auths over the CONSENSUS payload hashes ─────────────
    // The production signing order (`sign_bridge.rs`): assemble the
    // proof-bearing wire tx with a stub auth carrying the real derived
    // public key and an empty signature — the payload hash covers the auth
    // *header* (version ‖ scheme ‖ flags ‖ len ‖ pk), never the signature —
    // then sign the per-input hashes and swap the real auths in.
    let pqc_pk =
        derive_pqc_public_key(&combined_ss.0, spent_index).expect("derive hybrid public key");
    let mut wire_input = WireEncodeInput {
        key_images: vec![*ki.key_image.as_bytes()],
        output_keys: vec![payment.output_key, change.output_key],
        view_tags: vec![
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ],
        tx_extra: Vec::new(),
        fee: FEE,
        enc_amounts: signed.enc_amounts.clone(),
        enc_labels: signed.enc_labels.clone(),
        out_commitments: signed.commitments.clone(),
        pseudo_outs: signed.pseudo_outs.clone(),
        bulletproof: Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .expect("re-read the signed Bp+"),
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof.clone(),
        pqc_auths: vec![BuilderPqcAuth {
            auth_version: 1,
            signature: Vec::new(),
            public_key: pqc_pk,
        }],
        fcmp_layers: signed.tree_depth,
    };
    let payload_hashes = phase1_payload_hashes(&wire_input).expect("phase-1 payload hashes");
    let pqc_auths = sign_pqc_auths(&payload_hashes, std::slice::from_ref(&spend_input))
        .expect("phase-2 PQC auth signing");
    wire_input.pqc_auths = pqc_auths;

    // ── Encode and clear Phase A ────────────────────────────────────────
    let bytes = encode_final_tx(&wire_input).expect("encode the final spend");
    let hex_blob = hex::encode(&bytes);
    let parsed = parse_submission(&hex_blob).expect("the built spend clears Phase A");
    assert_eq!(parsed.kind, SubmitTxKind::Spend, "fixture is a spend");
    assert_eq!(
        parsed.tx.prefix_hash(),
        tx_prefix_hash,
        "the parsed prefix hash is the proof's signable hash"
    );

    SpendFixture {
        hex: hex_blob,
        parsed,
        tree_root,
        other_root,
        reference_height,
        lmdb_depth: tree_depth - 1,
    }
}

// ─── The positive oracle ────────────────────────────────────────────────

#[test]
fn consensus_valid_spend_passes_the_production_battery() {
    let fx = fixture();
    let facts = admitting_facts(fx);
    assert_eq!(
        verify(&fx.parsed, &facts),
        Ok(()),
        "a consensus-valid spend must clear O6 → CT balance → Bp+ → FCMP++ → PQC"
    );
}

#[test]
fn engine_accepts_the_spend_end_to_end_with_the_production_verifier() {
    // The full §3.1 pipeline over the real crypto battery: Phase A parse,
    // Phase B snapshot, Phase C policy + DaemonTxVerifier, Phase D commit
    // and relay nudge — the same path production takes, minus the C++ shims.
    let fx = fixture();
    let shim = MockShim::new(admitting_facts(fx), CommitOutcome::Committed);
    let engine = SubmitEngine::new(Arc::clone(&shim), DaemonTxVerifier);
    let verdict = engine
        .submit(&fx.hex, SubmitCaller::Owner)
        .expect("no engine fault");
    assert_eq!(verdict, SubmitVerdict::Accepted);
    assert_eq!(shim.commit_count(), 1, "exactly one commit");
    assert_eq!(shim.relay_count(), 1, "accepted ⇒ relay nudged");
}

// ─── O6: commitment mask non-triviality ─────────────────────────────────

#[test]
fn trivial_output_commitments_are_rejected() {
    // Row O6 (`check_commitment_mask_valid` thin-port): a commitment equal
    // to the identity (mask 0, amount 0) or to G (mask 1, amount 0) is a
    // deterministic reject before any expensive proof runs.
    let identity = {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes
    };
    for trivial in [identity, ED25519_BASEPOINT_COMPRESSED.to_bytes()] {
        let parsed = mutated(|tx| {
            let (_, base, _, _) = fcmp_parts_mut(tx);
            base.commitments[0] = trivial;
        });
        assert_eq!(
            verify(&parsed, &admitting_facts(fixture())),
            Err(VerifyFailure::Malformed),
            "a trivial output commitment must be Malformed"
        );
    }
}

// ─── N8 leg 1: CT cleartext balance ─────────────────────────────────────

#[test]
fn ct_imbalance_is_rejected() {
    // Bumping the cleartext fee by one atomic unit breaks
    // `sum(pseudoOuts) == sum(outPk) + fee·H` while leaving every proof
    // byte intact — the balance equation itself must gate.
    let parsed = mutated(|tx| {
        let (fee, _, _, _) = fcmp_parts_mut(tx);
        *fee += 1;
    });
    assert_eq!(
        verify(&parsed, &admitting_facts(fixture())),
        Err(VerifyFailure::Malformed),
        "a fee that breaks the CT balance must be Malformed"
    );
}

// ─── N8 leg 2: Bp+ aggregate range proof ────────────────────────────────

#[test]
fn tampered_bulletproof_is_rejected() {
    // One flipped byte in the Bp+ `A` element: the commitments are intact
    // (O6 and CT balance pass), so the rejection is attributable to the
    // range-proof verification itself.
    let parsed = mutated(|tx| {
        let (_, _, _, prunable) = fcmp_parts_mut(tx);
        prunable.bulletproofs[0].a[0] ^= 0x01;
    });
    assert_eq!(
        verify(&parsed, &admitting_facts(fixture())),
        Err(VerifyFailure::Malformed),
        "a tampered Bp+ must be Malformed"
    );
}

// ─── K12: FCMP++ membership ─────────────────────────────────────────────

#[test]
fn tampered_fcmp_proof_is_rejected() {
    // One flipped byte mid-proof: deterministic reject for these bytes
    // against this root (Malformed, never StaleRoot — a fresh root would
    // not fix a corrupted proof).
    let parsed = mutated(|tx| {
        let (_, _, _, prunable) = fcmp_parts_mut(tx);
        let mid = prunable.fcmp_proof.len() / 2;
        prunable.fcmp_proof[mid] ^= 0x01;
    });
    assert_eq!(
        verify(&parsed, &admitting_facts(fixture())),
        Err(VerifyFailure::Malformed),
        "a tampered FCMP++ proof must be Malformed"
    );
}

#[test]
fn proof_against_a_different_root_is_rejected_deterministically() {
    // The snapshot root is one block later than the proof's anchor — a
    // real, equally valid tree state. Phase C trusts the snapshot root
    // (the reference is pinned *by hash*, so an honest wallet's root always
    // matches; a root that differs means the proof is simply not a
    // membership proof for this tree): deterministic Malformed, not
    // StaleRoot. Reorg-shaped root drift is Phase D's re-check
    // (`classify_race` root compare), which never reaches the verifier.
    let fx = fixture();
    let mut facts = admitting_facts(fx);
    facts.reference = Some(ReferenceFacts {
        height: BlockHeight::from_raw(fx.reference_height),
        root: fx.other_root,
        tree_depth: fx.lmdb_depth,
    });
    assert_eq!(
        verify(&fx.parsed, &facts),
        Err(VerifyFailure::Malformed),
        "a proof against a different (valid) root must be Malformed"
    );
}

#[test]
fn overclaimed_tree_depth_maps_to_stale_root() {
    // Row K10's crypto-side twin: a wire depth beyond the proof system's
    // cap maps to StaleRoot (rebuild against a fresh root), both via the
    // library's TreeDepthTooLarge and via the u8 conversion guard. The
    // engine's Phase-C depth bound rejects these before the verifier in
    // the full pipeline; the mapping is still pinned here because the
    // verifier is a public seam.
    for depth in [u64::from(MAX_TREE_DEPTH), 300] {
        let parsed = mutated(|tx| {
            let (_, _, _, prunable) = fcmp_parts_mut(tx);
            prunable.tree_depth = depth;
        });
        assert_eq!(
            verify(&parsed, &admitting_facts(fixture())),
            Err(VerifyFailure::StaleRoot),
            "an overclaimed tree depth ({depth}) must map to StaleRoot"
        );
    }
}

#[test]
fn missing_reference_facts_map_to_stale_root() {
    // Defensive arm (§7.6 non-panicking posture): the engine never calls
    // the verifier without reference facts for a spend, but the seam is
    // public and must refuse rather than panic.
    let fx = fixture();
    let mut facts = admitting_facts(fx);
    facts.reference = None;
    assert_eq!(
        verify(&fx.parsed, &facts),
        Err(VerifyFailure::StaleRoot),
        "a spend without reference facts must map to StaleRoot"
    );
}

// ─── K13: PQC hybrid auth ───────────────────────────────────────────────

#[test]
fn tampered_pqc_signature_is_rejected() {
    // Flipping one signature byte leaves the membership proof valid (the
    // leaf binds the *public key*, the proof binds the *prefix*), so the
    // rejection is attributable to the hybrid verification itself.
    let parsed = mutated(|tx| {
        let (_, _, pqc_auths, _) = fcmp_parts_mut(tx);
        let last = pqc_auths[0].hybrid_signature.len() - 1;
        pqc_auths[0].hybrid_signature[last] ^= 0x01;
    });
    assert_eq!(
        verify(&parsed, &admitting_facts(fixture())),
        Err(VerifyFailure::Malformed),
        "a tampered hybrid signature must be Malformed"
    );
}

#[test]
fn pqc_public_key_is_bound_by_the_membership_proof() {
    // Flipping one *public key* byte changes the per-input leaf hash, so
    // the FCMP++ battery — not the PQC battery — rejects: the tree binding
    // (PQC_MULTISIG.md §16.3) makes key substitution a membership failure,
    // not merely a signature failure.
    let parsed = mutated(|tx| {
        let (_, _, pqc_auths, _) = fcmp_parts_mut(tx);
        pqc_auths[0].hybrid_public_key[0] ^= 0x01;
    });
    assert_eq!(
        verify(&parsed, &admitting_facts(fixture())),
        Err(VerifyFailure::Malformed),
        "a substituted PQC public key must fail the membership proof"
    );
}

#[test]
fn pqc_header_statics_reject_unknown_versions_flags_and_schemes() {
    // The `verify_transaction_pqc_auth` header battery: version pin, zero
    // flags, closed scheme-id set. Each mutation also perturbs the signed
    // payload header, so the auth could not verify even if the static were
    // skipped — the assert pins the *reject*, the C++-parity statics pin
    // where it fires.
    type AuthMutation = (&'static str, fn(&mut PqcAuth));
    let mutations: [AuthMutation; 3] = [
        ("auth_version 2", |auth| auth.auth_version = 2),
        ("flags 1", |auth| auth.flags = 1),
        ("scheme id 3", |auth| auth.scheme_id = 3),
    ];
    for (label, mutate_auth) in mutations {
        let parsed = mutated(|tx| {
            let (_, _, pqc_auths, _) = fcmp_parts_mut(tx);
            mutate_auth(&mut pqc_auths[0]);
        });
        assert_eq!(
            verify(&parsed, &admitting_facts(fixture())),
            Err(VerifyFailure::Malformed),
            "{label} must be Malformed"
        );
    }
}

// ─── Reachability honesty: the non-Spend arms ───────────────────────────

#[test]
fn non_spend_kinds_refuse_loudly() {
    // The serve-credit arm is unreachable through the engine today (the
    // SP-T4a fee-floor contradiction rejects it in Phase C before the
    // verifier), but the seam is public: the unimplemented battery must
    // refuse as Malformed, never pass or panic (rule 21 reopening criteria
    // live in the verifier's module docs).
    let parsed =
        parse_submission(&hexify(&serve_credit_tx(0))).expect("serve-credit clears Phase A");
    assert_eq!(parsed.kind, SubmitTxKind::ServeCreditOnly);
    let facts = SubmitFacts {
        in_pool: false,
        in_pool_broadcast: false,
        in_chain: false,
        key_image_conflicts: Vec::new(),
        reference: None,
        fee_per_byte: 1,
        fee_quantization_mask: 1,
        weight_limit: 149_400,
        chain_height: BlockHeight::from_raw(200),
    };
    assert_eq!(
        verify(&parsed, &facts),
        Err(VerifyFailure::Malformed),
        "the unimplemented serve-credit battery must refuse loudly"
    );
}
