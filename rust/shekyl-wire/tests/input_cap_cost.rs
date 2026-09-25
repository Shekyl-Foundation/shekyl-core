// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-I4's cost, measured — not inherited (`CHAIN_RULES_SLICE_6.md` §5.4).
//!
//! `FCMP_MAX_INPUTS_PER_TX = 8` arrived with the comment *"bounds proof
//! generation time and tx size"* (`cryptonote_config.h`, the
//! `FCMP_MAX_INPUTS_PER_TX` define — cite the symbol; its line has moved
//! twice this month). Half of that is
//! not a reason for a consensus rule — generation time is the sender's cost.
//! The only objective a consensus input cap defensibly bounds is **the
//! verifier work one transaction can impose**, and that is observable. So
//! this test builds real 1-, 2-, 4- and 8-input FCMP++ spends through the
//! production builder (`sign_transaction`, `sign_pqc_auths`) over a real
//! depth-3 curve tree, verifies each through the production verifiers
//! (`shekyl_fcmp::proof::verify`, the hybrid Ed25519+ML-DSA-65 auths, the
//! Bulletproof+), and measures:
//!
//! - **bytes per input** on the wire, broken into the PQC auth (key + sig),
//!   the proof's growth, and the prefix (key image + pseudo-out);
//! - **verifier time per input**, broken the same way;
//! - the **implied cap** `(TX_WEIGHT_LIMIT − fixed) / weight_per_input` —
//!   the input count CEN-H3's weight limit (149 400) already refuses past.
//!   If it is below 8 the cap is dead weight; if above, the cap is the
//!   binding constraint and needs a derivation from a stated verifier
//!   budget, not a number from RingCT's era. The parser's `MAX_TX_SIZE`
//!   (1 MiB) is reported beside it as the wider, non-consensus ceiling.
//!
//! The prover refuses more than eight (`shekyl_fcmp::MAX_INPUTS`), so the
//! sweep stops at the cap and the shape past it is read off the slope — the
//! test asserts the per-input deltas are stable (linear) so the read is
//! honest. `#[ignore]`d for the measurement lane: an 8-input proof is
//! seconds in release and much more in debug. Run it as
//! `cargo test --release -p shekyl-wire --test input_cap_cost -- --ignored --nocapture`.

mod common;
use common::{conforming_pqc_extra, random_wallet, Wallet};

use std::time::{Duration, Instant};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::output::{
    compute_output_key_image, construct_output, recover_combined_ss, OutputData,
};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_curve_io::CompressedPoint;
use shekyl_curve_tree::{
    AssembleInput, BlockHash, BlockHeight, BlockLeaves, CurveTreeClient, Gindex, RawOutput,
    ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_fcmp::proof::{self, KeyImage, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_tx_builder::{
    sign_pqc_auths, sign_transaction, tx_prefix_hash_from_parts, LeafEntry, OutputInfo, SpendInput,
    TreeContext,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{MAX_FCMP_INPUTS, MAX_TX_SIZE, TX_WEIGHT_LIMIT};
use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, Prunable, Transaction, TxPrefix};

const COINBASE_LOCK_WINDOW: u64 = shekyl_consensus::COINBASE_LOCK_WINDOW as u64;
/// Past the depth-2 capacity (684), so the tree is depth 3 — the shape the
/// membership proof has on any chain older than a day.
const TREE_OUTPUTS: usize = 700;
const RNG_SEED: u64 = 0x4934_5f63_6f73_7431; // "I4_cost1"

fn random_point(rng: &mut ChaCha20Rng) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * Scalar::random(rng))
        .compress()
        .to_bytes()
}

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
    assert!(r.is_empty(), "Bp+ blob fully consumed");
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

/// One spent output the wallet owns: what the prover needs and what the
/// verifier reads back.
struct Spent {
    data: OutputData,
    combined_ss: [u8; 64],
    key_image: KeyImage,
    spend_secret_x: [u8; 32],
    index: u64,
}

/// What one `n`-input spend measured.
#[derive(Clone, Copy, Debug)]
struct Measured {
    inputs: usize,
    /// Serialized wire bytes of the whole transaction.
    tx_bytes: usize,
    /// CEN-H3's operand: `Transaction::weight()` — the serialized bytes plus
    /// the BP+ clawback, zero for this two-output shape, so equal to
    /// `tx_bytes` here and recorded separately because H3 judges the
    /// weight, not the length.
    tx_weight: usize,
    /// The FCMP++ proof blob alone.
    proof_bytes: usize,
    /// All PQC auths (key + signature blobs, both inputs' worth).
    auth_bytes: usize,
    /// The BP+ range proof blob (over the two outputs; input-independent).
    bp_bytes: usize,
    prove: Duration,
    verify_proof: Duration,
    verify_auths: Duration,
    verify_bp: Duration,
}

impl Measured {
    fn verify_total(&self) -> Duration {
        self.verify_proof + self.verify_auths + self.verify_bp
    }
}

/// Build the tree once — the same tree serves every `n` — with `max_spent`
/// outputs of the wallet's at genesis indices `0..max_spent`, then decoys.
fn tree_with(
    rng: &mut ChaCha20Rng,
    wallet: &Wallet,
    max_spent: usize,
    input_amount: u64,
) -> (CurveTreeClient, Vec<Spent>, u64) {
    let mut spent = Vec::with_capacity(max_spent);
    let mut genesis_outputs: Vec<RawOutput> = Vec::with_capacity(TREE_OUTPUTS);
    let mut genesis_blob: Vec<u8> = Vec::with_capacity(TREE_OUTPUTS * 64);
    for index in 0..max_spent as u64 {
        let tx_secret = Scalar::random(rng).to_bytes();
        let data = construct_output(
            &tx_secret,
            &wallet.x25519_pk,
            &wallet.ml_kem_ek,
            &wallet.spend_public,
            input_amount,
            index,
        )
        .expect("construct spent output");
        let combined_ss = recover_combined_ss(
            &wallet.x25519_sk,
            &wallet.ml_kem_dk,
            &data.kem_ciphertext_x25519,
            &data.kem_ciphertext_ml_kem,
        )
        .expect("recover combined shared secret");
        let hp_of_o = shekyl_curve_generators::biased_hash_to_point(data.output_key)
            .compress()
            .to_bytes();
        let ki = compute_output_key_image(&combined_ss.0, index, &wallet.spend_secret, &hp_of_o)
            .expect("compute key image");
        genesis_outputs.push(RawOutput {
            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(data.output_key),
            commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                data.commitment,
            )),
            target: TargetKind::TaggedKey,
        });
        genesis_blob.extend_from_slice(&data.pqc_leaf.entry_bytes());
        spent.push(Spent {
            combined_ss: combined_ss.0,
            key_image: ki.key_image,
            spend_secret_x: *ki.spend_secret_x,
            index,
            data,
        });
    }
    let filler_entry = spent[0].data.pqc_leaf.entry_bytes();
    for _ in max_spent..TREE_OUTPUTS {
        genesis_outputs.push(RawOutput {
            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(random_point(rng)),
            commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                random_point(rng),
            )),
            target: TargetKind::TaggedKey,
        });
        genesis_blob.extend_from_slice(&filler_entry);
    }
    let filler_key = random_point(rng);
    let filler_commitment = random_point(rng);
    let reference_height = COINBASE_LOCK_WINDOW + 1;
    let mut client = CurveTreeClient::new();
    for height in 0..=reference_height {
        let (outputs, blob): (Vec<RawOutput>, Vec<u8>) = if height == 0 {
            (genesis_outputs.clone(), genesis_blob.clone())
        } else {
            (
                vec![RawOutput {
                    output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(filler_key),
                    commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                        filler_commitment,
                    )),
                    target: TargetKind::TaggedKey,
                }],
                filler_entry.to_vec(),
            )
        };
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_entry_blob: Some(blob.as_slice()),
            outputs: outputs.as_slice(),
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(height),
                txs: &txs,
            })
            .expect("ingest block");
    }
    (client, spent, reference_height)
}

/// Build, sign and verify an `n`-input spend of the first `n` of `spent`.
#[allow(clippy::too_many_lines)]
fn measure(
    rng: &mut ChaCha20Rng,
    wallet: &Wallet,
    client: &CurveTreeClient,
    spent: &[Spent],
    reference_height: u64,
    n: usize,
    input_amount: u64,
) -> Measured {
    let (tree_root, tree_depth) = client
        .root_and_depth_at(BlockHeight::from_raw(reference_height))
        .expect("root + depth");
    assert!(tree_depth >= 3, "depth-3 tree");
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(reference_height),
        curve_tree_root: tree_root,
        block_hash: BlockHash::from_bytes([0xAB; 32]),
    };

    // CEN-I5: inputs in strictly descending key-image order.
    let mut chosen: Vec<&Spent> = spent[..n].iter().collect();
    chosen.sort_unstable_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));

    let spend_inputs: Vec<SpendInput> = chosen
        .iter()
        .map(|s| {
            let path = client
                .assemble_path(
                    &AssembleInput {
                        gindex: Gindex::from_raw(s.index),
                        output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(s.data.output_key),
                        commitment: shekyl_curve_tree::CommitmentBytes::from_bytes(
                            s.data.commitment,
                        ),
                    },
                    &reference,
                )
                .expect("assemble membership path");
            SpendInput {
                output_key: s.data.output_key,
                commitment: s.data.commitment,
                amount: AtomicUnits::from_raw(input_amount),
                spend_key_x: s.spend_secret_x,
                spend_key_y: s.data.y,
                commitment_mask: s.data.z,
                combined_ss: s.combined_ss.to_vec(),
                output_index: s.index,
                leaf_chunk: path
                    .leaf_chunk
                    .iter()
                    .map(|cl| LeafEntry {
                        output_key: cl.output_key.to_bytes(),
                        key_image_gen: cl.key_image_gen,
                        commitment: cl.commitment.to_bytes(),
                        cm_x: cl.cm_x,
                    })
                    .collect(),
                c1_layers: path.c1_layers.clone(),
                c2_layers: path.c2_layers.clone(),
            }
        })
        .collect();

    // Two outputs (CEN-I1): a payment and change.
    let fee: u64 = 1_000_000;
    let total_in = input_amount * n as u64;
    let payment_amount = (total_in - fee) / 2;
    let change_amount = total_in - fee - payment_amount;
    let recipient = random_wallet(rng);
    let dest_secret = Scalar::random(rng).to_bytes();
    let payment = construct_output(
        &dest_secret,
        &recipient.x25519_pk,
        &recipient.ml_kem_ek,
        &recipient.spend_public,
        payment_amount,
        0,
    )
    .expect("payment");
    let change = construct_output(
        &dest_secret,
        &wallet.x25519_pk,
        &wallet.ml_kem_ek,
        &wallet.spend_public,
        change_amount,
        1,
    )
    .expect("change");
    let pack = |out: &OutputData, amount: u64| OutputInfo {
        dest_key: out.output_key,
        amount: AtomicUnits::from_raw(amount),
        commitment_mask: out.z,
        enc_amount: out.enc_amount_wire(),
        enc_label: out.enc_label_wire(),
    };
    let outputs = [pack(&payment, payment_amount), pack(&change, change_amount)];

    let key_images: Vec<[u8; 32]> = chosen.iter().map(|s| *s.key_image.as_bytes()).collect();
    // The prefix the proof and the auths bind to is the prefix the wire
    // carries — `extra` included, built once and reused in `TxPrefix` below.
    // A hash over an empty extra would have signed different bytes than the
    // transaction serialized (#853 review).
    let extra = conforming_pqc_extra(2);
    let tx_prefix_hash = tx_prefix_hash_from_parts(
        &key_images,
        &[payment.output_key, change.output_key],
        &[
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ],
        &extra,
    );
    let tree_ctx = TreeContext {
        reference_block: reference.block_hash,
        tree_root,
        tree_depth,
    };

    let started = Instant::now();
    let signed = sign_transaction(
        tx_prefix_hash,
        &spend_inputs,
        &outputs,
        AtomicUnits::from_raw(fee),
        &tree_ctx,
    )
    .expect("sign transaction");
    let auths = sign_pqc_auths(&vec![tx_prefix_hash.to_bytes(); n], &spend_inputs)
        .expect("Phase-2 PQC auth signing");
    let prove = started.elapsed();

    // ── The verifiers, timed separately ──────────────────────────────────
    let verifier_proof = ShekylFcmpProof {
        data: signed.fcmp_proof.clone(),
        num_inputs: u32::try_from(n).expect("small"),
        tree_depth: signed.tree_depth,
    };
    let kis: Vec<KeyImage> = chosen.iter().map(|s| s.key_image).collect();
    let pqc_pk_hashes: Vec<PqcKeyScalar> = chosen
        .iter()
        .map(|s| {
            PqcKeyScalar::from_pqc_public_key(
                &derive_pqc_public_key(&s.combined_ss, s.index).expect("derive hybrid pk"),
            )
        })
        .collect();
    let started = Instant::now();
    let ok = proof::verify(
        &verifier_proof,
        &kis,
        &signed.pseudo_outs,
        &pqc_pk_hashes,
        tree_root.as_bytes(),
        signed.tree_depth,
        tx_prefix_hash.to_bytes(),
    )
    .expect("verify must not error");
    let verify_proof = started.elapsed();
    assert!(ok, "{n}-input FCMP++ proof verifies");

    let started = Instant::now();
    let scheme = HybridEd25519MlDsa;
    for auth in &auths {
        let pk = HybridPublicKey::from_canonical_bytes(&auth.public_key).expect("key parses");
        let sig = HybridSignature::from_canonical_bytes(&auth.signature).expect("sig parses");
        scheme
            .verify(
                &pk,
                SCHEME_DOMAIN_PQC_AUTH_TX,
                &tx_prefix_hash.to_bytes(),
                &sig,
            )
            .expect("hybrid auth verifies");
    }
    let verify_auths = started.elapsed();

    let bp = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice()).expect("BP+");
    let bp_commitments: Vec<CompressedPoint> = signed
        .commitments
        .iter()
        .map(|c| CompressedPoint::from(CompressedEdwardsY(*c)))
        .collect();
    let started = Instant::now();
    assert!(bp.verify(rng, &bp_commitments), "BP+ verifies");
    let verify_bp = started.elapsed();

    // ── The wire bytes ───────────────────────────────────────────────────
    let wire_tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: key_images
                .iter()
                .map(|key_image| Input::ToKey {
                    amount: 0,
                    key_offsets: Vec::new(),
                    key_image: *key_image,
                })
                .collect(),
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
            extra,
        },
        ct: Ct::Fcmp {
            fee,
            reference_block: signed.reference_block,
            base: CtBase {
                enc_amounts: signed.enc_amounts.iter().map(|f| f.to_bytes()).collect(),
                enc_labels: signed.enc_labels.iter().map(|f| f.to_bytes()).collect(),
                commitments: signed.commitments.clone(),
            },
            pqc_auths: auths
                .iter()
                .map(|auth| shekyl_wire::PqcAuth {
                    auth_version: auth.auth_version,
                    scheme_id: 1,
                    flags: 0,
                    hybrid_public_key: auth.public_key.clone(),
                    hybrid_signature: auth.signature.clone(),
                })
                .collect(),
            prunable: Some(Prunable {
                serve_credit_pruned: Vec::new(),
                bulletproofs: vec![bp_plus_from_blob(&signed.bulletproof_plus)],
                tree_depth: u64::from(signed.tree_depth.checked_sub(1).expect("L >= 1")),
                fcmp_proof: signed.fcmp_proof.clone(),
                pseudo_outs: signed.pseudo_outs.clone(),
            }),
        },
    };
    wire_tx
        .validate()
        .expect("the assembled spend passes the wire's structural validation");
    let bytes = wire_tx.serialize();

    Measured {
        inputs: n,
        tx_bytes: bytes.len(),
        tx_weight: wire_tx.weight(),
        proof_bytes: signed.fcmp_proof.len(),
        auth_bytes: auths
            .iter()
            .map(|a| a.public_key.len() + a.signature.len())
            .sum(),
        bp_bytes: signed.bulletproof_plus.len(),
        prove,
        verify_proof,
        verify_auths,
        verify_bp,
    }
}

#[test]
#[ignore = "measurement lane: proves 1/2/4/8-input FCMP++ spends over a real tree; run with --release --nocapture"]
#[allow(clippy::cast_precision_loss)]
fn the_input_caps_cost_is_measured_not_inherited() {
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED);
    let wallet = random_wallet(&mut rng);
    let input_amount: u64 = 1_000_000_000;
    let (client, spent, reference_height) =
        tree_with(&mut rng, &wallet, MAX_FCMP_INPUTS, input_amount);

    let counts = [1usize, 2, 4, MAX_FCMP_INPUTS];
    let measured: Vec<Measured> = counts
        .iter()
        .map(|&n| {
            measure(
                &mut rng,
                &wallet,
                &client,
                &spent,
                reference_height,
                n,
                input_amount,
            )
        })
        .collect();

    println!();
    println!(
        "{:>3} | {:>9} {:>9} {:>9} {:>7} | {:>9} {:>9} {:>9} {:>9} | {:>8}",
        "n", "tx B", "proof B", "auths B", "bp B", "verify", "proof", "auths", "bp", "prove"
    );
    for m in &measured {
        println!(
            "{:>3} | {:>9} {:>9} {:>9} {:>7} | {:>9.2?} {:>9.2?} {:>9.2?} {:>9.2?} | {:>8.2?}",
            m.inputs,
            m.tx_bytes,
            m.proof_bytes,
            m.auth_bytes,
            m.bp_bytes,
            m.verify_total(),
            m.verify_proof,
            m.verify_auths,
            m.verify_bp,
            m.prove
        );
    }

    // Per-input slopes from the widest pair (1 → 8), and their stability
    // across the sweep: the read past 8 is a line only if these agree.
    let first = measured[0];
    let last = measured[measured.len() - 1];
    let span = (last.inputs - first.inputs) as f64;
    let bytes_per_input = (last.tx_bytes - first.tx_bytes) as f64 / span;
    let proof_bytes_per_input = (last.proof_bytes - first.proof_bytes) as f64 / span;
    let auth_bytes_per_input = (last.auth_bytes - first.auth_bytes) as f64 / span;
    // Saturating: a later, larger spend verifying faster than a smaller one
    // would be noise, not a negative slope, and reads as zero.
    let verify_per_input = last
        .verify_total()
        .saturating_sub(first.verify_total())
        .as_secs_f64()
        / span;
    let proof_verify_per_input = last
        .verify_proof
        .saturating_sub(first.verify_proof)
        .as_secs_f64()
        / span;
    let auth_verify_per_input = last
        .verify_auths
        .saturating_sub(first.verify_auths)
        .as_secs_f64()
        / span;
    let fixed_bytes = first.tx_bytes as f64 - bytes_per_input;
    // Two ceilings, one binding. CEN-H3 refuses a transaction whose weight
    // exceeds `TX_WEIGHT_LIMIT` (149 400) — that is the consensus bound an
    // accepted spend actually meets, and the one the input cap is measured
    // against. `MAX_TX_SIZE` (1 MiB) is the parser's refusal, seven times
    // wider; reported beside it so the two are never confused again (#853
    // review: an earlier cut of this test read the cap off the parser
    // bound and overstated the headroom sevenfold).
    let weight_per_input = (last.tx_weight - first.tx_weight) as f64 / span;
    let fixed_weight = first.tx_weight as f64 - weight_per_input;
    let implied_cap = ((TX_WEIGHT_LIMIT as f64 - fixed_weight) / weight_per_input).floor();
    let parser_cap = ((MAX_TX_SIZE as f64 - fixed_bytes) / bytes_per_input).floor();

    println!();
    println!("bytes/input        {bytes_per_input:>10.0}  (proof {proof_bytes_per_input:.0}, auths {auth_bytes_per_input:.0}, prefix+pseudo-out 64)");
    println!("weight/input       {weight_per_input:>10.0}  (H3's operand; BP+ clawback is 0 at two outputs)");
    println!("verify s/input     {verify_per_input:>10.4}  (proof {proof_verify_per_input:.4}, auths {auth_verify_per_input:.4})");
    println!("fixed bytes        {fixed_bytes:>10.0}  (the two outputs, the BP+, the header)");
    println!(
        "implied cap (H3)   {implied_cap:>10.0}  inputs fit under TX_WEIGHT_LIMIT = {TX_WEIGHT_LIMIT}; consensus caps at {MAX_FCMP_INPUTS}"
    );
    println!(
        "parser cap         {parser_cap:>10.0}  inputs fit under MAX_TX_SIZE = {MAX_TX_SIZE} (the parser's refusal, not a consensus bound)"
    );
    println!(
        "verifier work at the cap  {:.3?} per tx; at the H3-implied cap  {:.3?}",
        Duration::from_secs_f64(
            first.verify_total().as_secs_f64() + verify_per_input * (MAX_FCMP_INPUTS - 1) as f64
        ),
        Duration::from_secs_f64(
            first.verify_total().as_secs_f64() + verify_per_input * (implied_cap - 1.0)
        )
    );

    // Linearity in bytes: the 1→2, 2→4 and 4→8 per-input deltas agree within
    // a few percent — auths are fixed-size and the proof grows by a fixed
    // per-input term. A superlinear proof would show here first.
    for pair in measured.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let delta = (b.tx_bytes - a.tx_bytes) as f64 / (b.inputs - a.inputs) as f64;
        assert!(
            (delta - bytes_per_input).abs() / bytes_per_input < 0.05,
            "bytes per input is linear: {}→{} gives {delta:.0}/input against {bytes_per_input:.0}",
            a.inputs,
            b.inputs
        );
    }
    // H3 refuses past the implied cap; the consensus cap is either tighter
    // (independent work) or looser (dead weight). Recorded, not asserted:
    // which one it is, is the finding. What is asserted is the ordering of
    // the two ceilings — the parser's is the wider one, and the finding is
    // read off H3's.
    assert!(weight_per_input > 0.0 && implied_cap >= 1.0);
    assert!(
        parser_cap > implied_cap,
        "the parser bound is the wider ceiling"
    );
}
