// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end FCMP++ spend validation against the Rust consensus verifier.
//!
//! # Why this exists (the "no C++ oracle" disposition)
//!
//! The original FCMP++ spend KAT planned to capture a "known-good" transaction
//! blob from the C++ daemon and assert `shekyl-wire` round-trips it
//! byte-identically. That plan is unsound: the C++ FCMP++ spend path never
//! produced a daemon-accepted transaction, so there is no known-good blob to
//! capture. Capturing the broken output would enshrine broken logic as the
//! oracle — building the house in order to draw the blueprint.
//!
//! The authoritative consensus rule for an FCMP++ spend is
//! [`shekyl_fcmp::proof::verify`] itself: it is the exact function the daemon's
//! `shekyl_fcmp_verify` FFI dispatches to. So the correct oracle is a spend
//! that is **built in Rust and self-validates against that verifier**.
//!
//! # What Stage 1 covers
//!
//! This test builds a *real* multi-layer Selene/Helios curve tree from real
//! outputs via the production [`shekyl_curve_tree::CurveTreeClient`], assembles
//! a membership path for one spent output via the production `assemble_path`,
//! signs the spend via the production [`shekyl_tx_builder::sign_transaction`],
//! and verifies the whole proof via [`shekyl_fcmp::proof::verify`].
//!
//! The tree is sized past the depth-2 capacity
//! (`SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH = 38 * 18 = 684`) so it is depth 3
//! — populating **both** a Selene (`c1`) and a Helios (`c2`) internal branch
//! layer in the assembled path. That is the exact surface that broke the C++
//! path (marshaling a real multi-layer branch path into the prover/verifier);
//! the pre-existing `shekyl-ffi` round-trip only exercises a degenerate
//! single-leaf tree with empty branch layers, so it never covered it.
//!
//! # What the later stages cover
//!
//! Stage 2 extends the same spend to full consensus-valid amount checks:
//! CT cleartext balance (`sum(pseudoOuts) == sum(outPk) + fee·H`, via
//! [`shekyl_rct_balance::verify_rct_balance`]) and the Bulletproof+ range proof
//! (via [`Bulletproof::verify`]).
//!
//! Stage 3 assembles the validated spend into a [`shekyl_wire::Transaction`]
//! and proves the serializer round-trips it byte-identically
//! (`read(write(x)) == x`, with a deterministic `write`). This is the test that
//! **replaces** the old `#[ignore]`d live-oracle KAT in
//! `fcmp_spend_roundtrip.rs`: instead of capturing a (non-existent) known-good
//! C++ blob, it serializes a spend whose every FCMP++ field — commitments,
//! pseudo-outs, the Bulletproof+, the FCMP++ proof, the per-input PQC auth — is
//! real and consensus-validated by Stages 1-2.
//!
//! Note on scope: `shekyl-wire` is the Shekyl-owned **canonical** genesis serializer
//! (`lib.rs`). The vendored `shekyl_oxide::transaction` encoder it once diverged from was
//! cut over (`shekyl-tx-builder`, PR #178) and then deleted (un-vendor slice 1), so there
//! is now a single on-wire FCMP++ spend layout; this test validates that serializer
//! against real crypto-valued fields.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_crypto_pq::output::{
    compute_output_key_image, construct_output, recover_combined_ss, OutputData,
};
use shekyl_curve_io::CompressedPoint;
use shekyl_curve_tree::{
    AssembleInput, BlockHeight, BlockLeaves, CurveTreeClient, Gindex, RawOutput, ReferenceBlock,
    TargetKind, TxLeafInputs,
};
use shekyl_fcmp::proof::{self, KeyImage, ShekylFcmpProof};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_rct_balance::verify_rct_balance;
use shekyl_tx_builder::{
    sign_pqc_auths, sign_transaction, tx_prefix_hash_from_parts, LeafEntry, OutputInfo, SpendInput,
    TreeContext,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, Prunable, Transaction, TxPrefix};

/// Coinbase lock window: a coinbase output created at height `h` matures — i.e.
/// drains into the tree — at height `h + COINBASE_LOCK_WINDOW`. The genesis
/// (height 0) coinbase is therefore a tree member at any reference height `>=
/// COINBASE_LOCK_WINDOW`. Sourced from the consensus constant
/// (`shekyl_oxide::COINBASE_LOCK_WINDOW`, a `usize`) so this fixture cannot
/// drift from the parameter; the `as u64` matches the height arithmetic below.
const COINBASE_LOCK_WINDOW: u64 = shekyl_oxide::COINBASE_LOCK_WINDOW as u64;

/// Number of outputs in the genesis coinbase. Exceeds the depth-2 capacity
/// (`SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH = 38 * 18 = 684`), forcing a
/// depth-3 tree so the assembled path carries both a Selene (`c1`) and a Helios
/// (`c2`) internal branch layer.
const TREE_OUTPUTS: usize = 700;

/// Fixed seed for the fixture RNG. This is a heavy *single-case* integration
/// oracle (it builds a 700-output depth-3 tree and runs the full
/// prove/verify/balance pipeline once), not a multi-case property test — the
/// algebraic-relation coverage that samples unfamiliar values lives in the
/// dedicated `shekyl-fcmp` / `shekyl-crypto-pq` `proptest` suites
/// (`50-testing.mdc`). For one expensive case, a fixed seed makes a CI failure
/// replayable, which a per-run `OsRng` draw would not. The seed only fixes the
/// witness *scalars* (spend key, decoy points, tx/dest secrets); the hybrid KEM
/// keypair and the prover's zero-knowledge randomness remain OS-drawn, but by
/// proof completeness they cannot change the accept/reject outcome for a fixed,
/// valid witness — so the pass/fail result is fully determined by this seed.
///
/// Reversion criterion (`21-reversion-clause-discipline.mdc`): if this oracle is
/// ever promoted to a multi-case `proptest`, drop the fixed seed and let the
/// proptest harness drive the witness draw per case.
const RNG_SEED: u64 = 0x5368_656b_796c_3031; // "Shekyl01"

/// A minimal spendable wallet: an Ed25519 spend keypair (`b`, `B = b*G`) plus a
/// hybrid X25519 + ML-KEM-768 KEM keypair. The typed (non-FFI) analogue of the
/// wallet in `shekyl-ffi`'s `signing_round_trip` test.
struct Wallet {
    /// Spend secret `b`.
    spend_secret: [u8; 32],
    /// Spend public `B = b*G` (compressed Ed25519).
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
        // `HybridKemSecretKey` is `ZeroizeOnDrop`; its `Vec` field can't be
        // moved out, so clone the decapsulation key into the test wallet.
        ml_kem_dk: sk.ml_kem.clone(),
    }
}

/// A random valid prime-order compressed Ed25519 point (`r*G`). Used for decoy
/// tree members: only the *spent* output needs recoverable secrets — the rest
/// just have to be well-formed leaves so the tree builds to depth 3.
fn random_point(rng: &mut ChaCha20Rng) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * Scalar::random(rng))
        .compress()
        .to_bytes()
}

/// Reconstruct a [`BpPlus`] from a serialized `shekyl_bulletproofs::Bulletproof`
/// blob.
///
/// The blob layout (`Bulletproof::write`) is `A · A1 · B · r1 · s1 · d1 ·
/// V(L_len)·L · V(R_len)·R` — byte-identical to `shekyl-wire`'s [`BpPlus`]
/// encoding, so the real range proof maps onto the wire struct without
/// re-deriving any field. The canonical varint reader is `shekyl-wire`'s own.
fn bp_plus_from_blob(blob: &[u8]) -> BpPlus {
    use shekyl_wire::varint::read_varint;

    fn take32(r: &mut &[u8]) -> [u8; 32] {
        let mut a = [0u8; 32];
        std::io::Read::read_exact(r, &mut a).expect("Bp+ blob: 32-byte field");
        a
    }

    let mut r: &[u8] = blob;
    let a = take32(&mut r);
    let a1 = take32(&mut r);
    let b = take32(&mut r);
    let r1 = take32(&mut r);
    let s1 = take32(&mut r);
    let d1 = take32(&mut r);
    let l_len: usize = read_varint(&mut r).expect("Bp+ L length varint");
    let l: Vec<[u8; 32]> = (0..l_len).map(|_| take32(&mut r)).collect();
    let r_len: usize = read_varint(&mut r).expect("Bp+ R length varint");
    let r_points: Vec<[u8; 32]> = (0..r_len).map(|_| take32(&mut r)).collect();
    assert!(
        r.is_empty(),
        "Bp+ blob must be fully consumed ({} trailing bytes)",
        r.len()
    );
    BpPlus {
        a,
        a1,
        b,
        r1,
        s1,
        d1,
        l,
        r: r_points,
    }
}

#[test]
fn fcmp_spend_real_tree_verifies_against_consensus() {
    // ── 1. Wallet + the output we will spend ─────────────────────────────
    // One seeded RNG threaded through every fixture draw so the witness (and
    // therefore the accept/reject result) is reproducible — see `RNG_SEED`.
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED);
    let wallet = random_wallet(&mut rng);
    let input_amount: u64 = 1_000_000_000;
    let fee: u64 = 1_000_000;
    let output_amount: u64 = input_amount - fee;
    let spent_index: u64 = 0;

    // Construct the spent output to our own wallet (a self-spend), then recover
    // the per-output secrets the prover needs as the recipient would.
    let tx_secret = Scalar::random(&mut rng).to_bytes();
    let spent = construct_output(
        &tx_secret,
        &wallet.x25519_pk,
        &wallet.ml_kem_ek,
        &wallet.spend_public,
        input_amount,
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

    // I = Hp(O); the prover derives the same generator via
    // `compute_key_image_gen` == `biased_hash_to_point`, so the key image we
    // compute here matches the one the proof binds.
    let hp_of_o = shekyl_curve_generators::biased_hash_to_point(spent.output_key)
        .compress()
        .to_bytes();
    let ki = compute_output_key_image(&combined_ss.0, spent_index, &wallet.spend_secret, &hp_of_o)
        .expect("compute key image");

    // ── 2. Build a real multi-layer curve tree ───────────────────────────
    // Genesis coinbase: the spent output at vout 0, then decoy members. Every
    // output shares the spent output's (valid) `h_pqc`; they differ by their
    // O/C points, so their leaf hashes still differ.
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

    // Heights must be ingested consecutively from 0; a single decoy coinbase
    // per filler block keeps each block well-formed. Filler outputs are created
    // after genesis, so none mature by the reference height — they never enter
    // the tree we prove against.
    let filler_key = random_point(&mut rng);
    let filler_commitment = random_point(&mut rng);
    // A coinbase at height `h` matures at `h + 60` and drains at `h + 61`
    // (`drained_through(H) = H - 1`, filtered `maturity <= drained_through`).
    // The genesis coinbase therefore drains at reference height 61; fillers
    // (heights >= 1) mature at >= 61 and stay out of the tree at this height.
    let reference_height = COINBASE_LOCK_WINDOW + 1;

    let mut client = CurveTreeClient::new();
    for height in 0..=reference_height {
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
                height: BlockHeight(height),
                txs: &txs,
            })
            .expect("ingest block");
    }

    let (tree_root, tree_depth) = client
        .root_and_depth_at(BlockHeight(reference_height))
        .expect("tree root + depth at reference height");
    assert!(
        tree_depth >= 3,
        "expected a depth-3 tree (both c1 and c2 branch layers); got depth {tree_depth}"
    );

    // ── 3. Assemble the membership path via the production client ─────────
    let reference = ReferenceBlock {
        height: BlockHeight(reference_height),
        curve_tree_root: tree_root,
        block_hash: [0xAB; 32],
    };
    let target = AssembleInput {
        gindex: Gindex(spent_index), // genesis vout 0 → first drained leaf
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
    assert!(
        !path.c1_layers.is_empty() && !path.c2_layers.is_empty(),
        "a depth-3 path must populate both Selene (c1) and Helios (c2) branches"
    );

    // ── 4. Map the assembled path + recovered secrets into a SpendInput ───
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
        amount: AtomicUnits::from_raw(input_amount),
        spend_key_x: *ki.spend_secret_x, // x = ho + b
        spend_key_y: spent.y,            // O = x*G + y*T
        commitment_mask: spent.z,        // C = z*G + amount*H
        h_pqc: spent.h_pqc,
        combined_ss: combined_ss.0.to_vec(),
        output_index: spent_index,
        leaf_chunk,
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    };

    // ── 5. Two destination outputs: a payment + change ────────────────────
    // Consensus (§12) rejects a single-output spend — a real spend always
    // carries a payment and a change output — so split the spendable amount
    // into a payment to a fresh recipient (output 0) and change back to the
    // spender (output 1). Both derive from one tx key with distinct output
    // indices, the canonical one-tx-key-per-transaction derivation.
    let recipient = random_wallet(&mut rng);
    let dest_secret = Scalar::random(&mut rng).to_bytes();
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
    let pack_output_info = |out: &OutputData, amount: u64| -> OutputInfo {
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
    };
    let outputs = [
        pack_output_info(&payment, payment_amount),
        pack_output_info(&change, change_amount),
    ];

    // ── 6. Sign via the production transaction builder ────────────────────
    let tree_ctx = TreeContext {
        reference_block: path.tree.reference_block,
        tree_root: path.tree.tree_root,
        tree_depth: path.tree.tree_depth,
    };
    // Bind the proof + PQC auths to the *real* transaction prefix, exactly as
    // the production send path does (`sign_bridge.rs` via
    // `tx_prefix_hash_from_parts`): the FCMP++ signable hash is the Keccak hash
    // over the prefix fields assembled into `wire_tx` below — the key image, the
    // two output keys + view tags, and the (empty) extra. Deriving it from the
    // constructed parts rather than a fixed constant means mutating any of those
    // prefix fields would invalidate the proof, so this oracle actually
    // exercises the prefix-binding consensus rule (not just self-consistency).
    let tx_prefix_hash = tx_prefix_hash_from_parts(
        &[*ki.key_image.as_bytes()],
        &[payment.output_key, change.output_key],
        &[
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ],
        &[],
    );
    let signed = sign_transaction(
        tx_prefix_hash,
        std::slice::from_ref(&spend_input),
        &outputs,
        AtomicUnits::from_raw(fee),
        &tree_ctx,
    )
    .expect("sign transaction");

    // ── 7. Verify against the Rust consensus verifier ─────────────────────
    // `sign_transaction` feeds the raw `tx_prefix_hash` to the prover as the
    // signable hash and returns the (random) pseudo-out blinds in
    // `signed.pseudo_outs`, so verification must reuse both verbatim.
    let verifier_proof = ShekylFcmpProof {
        // Clone: the same proof bytes are re-used by the Stage-3 wire round-trip.
        data: signed.fcmp_proof.clone(),
        num_inputs: 1,
        tree_depth: signed.tree_depth,
    };
    let key_images: [KeyImage; 1] = [ki.key_image];
    let pqc_pk_hashes = [PqcLeafScalar(spent.h_pqc)];
    let ok = proof::verify(
        &verifier_proof,
        &key_images,
        &signed.pseudo_outs,
        &pqc_pk_hashes,
        &tree_root,
        signed.tree_depth,
        tx_prefix_hash,
    )
    .expect("verify must not error");
    assert!(
        ok,
        "FCMP++ spend over a real multi-layer curve tree must verify against \
         shekyl_fcmp::proof::verify (the consensus rule)"
    );

    // Prefix-binding is load-bearing, not cosmetic: the proof commits to
    // `tx_prefix_hash`, so re-verifying against a prefix hash that differs in
    // even one bit — here a flipped output-key byte, i.e. paying a different
    // destination — must be rejected. This is the property a hard-coded hash
    // could never exercise: with a fixed constant a caller could mutate the
    // prefix and still verify.
    let mut mutated_output_keys = [payment.output_key, change.output_key];
    mutated_output_keys[0][0] ^= 0x01;
    let mutated_prefix_hash = tx_prefix_hash_from_parts(
        &[*ki.key_image.as_bytes()],
        &mutated_output_keys,
        &[
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ],
        &[],
    );
    let mutated_result = proof::verify(
        &verifier_proof,
        &key_images,
        &signed.pseudo_outs,
        &pqc_pk_hashes,
        &tree_root,
        signed.tree_depth,
        mutated_prefix_hash,
    );
    assert!(
        !matches!(mutated_result, Ok(true)),
        "proof must NOT verify against a prefix hash derived from mutated output \
         keys — the FCMP++ proof binds to the transaction prefix (got \
         {mutated_result:?})"
    );

    // ── 8. CT cleartext balance ───────────────────────────────────────────
    // `sum(pseudoOuts) == sum(outPk) + fee*H`. `sign_transaction` constrains
    // the last pseudo-out mask so the G-components cancel, and the amounts
    // satisfy `input_amount == output_amount + fee`, so the real-×1 points on
    // both sides sum equal. Both vectors are flattened compressed C points.
    let pseudo_flat: Vec<u8> = signed.pseudo_outs.iter().flatten().copied().collect();
    let out_flat: Vec<u8> = signed.commitments.iter().flatten().copied().collect();
    verify_rct_balance(
        &pseudo_flat,
        &out_flat,
        AtomicUnits::from_raw(fee),
        &[],
        &[],
    )
    .expect("CT cleartext balance must hold (sum pseudoOuts == sum outPk + fee*H)");

    // ── 9. Bulletproof+ range proof ───────────────────────────────────────
    // Deserialize the serialized blob and verify it over the real output
    // commitments (the crate's own round-trip passes `Commitment::calculate()`
    // compressed — i.e. real ×1 C, exactly `signed.commitments`).
    let bp = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
        .expect("deserialize Bulletproof+ blob");
    let bp_commitments: Vec<CompressedPoint> = signed
        .commitments
        .iter()
        .map(|c| CompressedPoint::from(CompressedEdwardsY(*c)))
        .collect();
    assert!(
        bp.verify(&mut rng, &bp_commitments),
        "Bulletproof+ range proof must verify over the output commitments"
    );

    // ── 10. PQC auths (Phase 2) ───────────────────────────────────────────
    // `sign_transaction` returns empty `pqc_auths`; the per-input hybrid
    // (Ed25519 + ML-DSA-65) signatures are a separate phase the caller runs
    // after the proofs exist. Run it now so the assembled wire transaction
    // carries real, canonically-sized auth blobs. The signed message is the
    // prefix hash; the per-input message-binding semantics are exercised by the
    // dedicated `shekyl-ffi` signing test, not asserted here.
    let pqc_auths = sign_pqc_auths(&[tx_prefix_hash], std::slice::from_ref(&spend_input))
        .expect("Phase-2 PQC auth signing");
    assert_eq!(pqc_auths.len(), 1, "one PQC auth per input");

    // ── 11. shekyl-wire byte-identical round-trip (replaces the live KAT) ──
    // Assemble the validated spend into the canonical genesis wire transaction
    // and prove the serializer round-trips it byte-identically. Every FCMP++
    // field carried here is real and consensus-validated by stages 1-9 above.
    let wire_tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image: *ki.key_image.as_bytes(),
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: payment.output_key,
                    view_tag: payment.view_tag_prefilter,
                },
                Output {
                    amount: 0,
                    key: change.output_key,
                    view_tag: change.view_tag_prefilter,
                },
            ],
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee,
            reference_block: signed.reference_block,
            base: CtBase {
                enc_amounts: signed.enc_amounts.clone(),
                enc_labels: signed.enc_labels.clone(),
                commitments: signed.commitments.clone(),
            },
            pqc_auths: pqc_auths
                .iter()
                .map(|auth| shekyl_wire::PqcAuth {
                    auth_version: auth.auth_version,
                    scheme_id: 1, // HYBRID_SCHEME_ID_ED25519_ML_DSA_65
                    flags: 0,
                    hybrid_public_key: auth.public_key.clone(),
                    hybrid_signature: auth.signature.clone(),
                })
                .collect(),
            prunable: Some(Prunable {
                bulletproofs: vec![bp_plus_from_blob(&signed.bulletproof_plus)],
                tree_depth: u64::from(signed.tree_depth),
                fcmp_proof: signed.fcmp_proof.clone(),
                pseudo_outs: signed.pseudo_outs.clone(),
            }),
        },
    };

    wire_tx
        .validate()
        .expect("assembled spend must pass shekyl-wire structural validation (§10/§12)");

    let bytes = wire_tx.serialize();
    let parsed =
        Transaction::from_bytes(&bytes).expect("shekyl-wire must parse the assembled FCMP++ spend");
    assert_eq!(
        parsed, wire_tx,
        "read(write(x)) must equal the assembled spend"
    );
    assert_eq!(
        parsed.serialize(),
        bytes,
        "shekyl-wire serialization must be deterministic (byte-identical re-emit)"
    );

    // ── Cross-crate byte-identity (replaces the assemble-direct shim) ─────────────
    // The hand-assembled `wire_tx` above is a structurally-validated, consensus-valid
    // spend. Feed the SAME signed fields through the production `shekyl-tx-builder`
    // encoder (`encode_final_tx`, the wallet's real send path) and assert it emits those
    // exact bytes — closing the loop between the tx-builder encoder and the canonical
    // `shekyl-wire` format on a real spend (FCMP_SPEND_SIGNING_PREIMAGE.md §5 residual).
    let wire_input = shekyl_tx_builder::WireEncodeInput {
        key_images: vec![*ki.key_image.as_bytes()],
        output_keys: vec![payment.output_key, change.output_key],
        view_tags: vec![
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ],
        tx_extra: Vec::new(),
        fee,
        enc_amounts: signed.enc_amounts.clone(),
        enc_labels: signed.enc_labels.clone(),
        out_commitments: signed.commitments.clone(),
        pseudo_outs: signed.pseudo_outs.clone(),
        bulletproof: bp.clone(),
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof.clone(),
        pqc_auths: pqc_auths.clone(),
        tree_depth: signed.tree_depth,
    };
    let builder_bytes =
        shekyl_tx_builder::encode_final_tx(&wire_input).expect("tx-builder encodes the spend");
    assert_eq!(
        builder_bytes, bytes,
        "tx-builder's production encoder must emit the consensus-validated wire bytes \
         byte-for-byte"
    );

    // The same bytes pass the typed-view boundary: a real spend yields a FullTransaction.
    Transaction::from_bytes(&builder_bytes)
        .expect("re-parse")
        .into_full()
        .expect("a real spend is a full transaction");
}
