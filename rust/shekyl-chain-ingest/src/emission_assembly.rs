// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's emission claim (E6 slice 8 row 7, Q3 ruled with one pin):
//! the reward-emission transaction a persona emits, assembled here as
//! `shekyl-engine-core`'s `AssembleEmissionClaim` handler assembles it —
//! the membership-only backing proof over the signable hash, the dual
//! auth over the Q1 binding messages, the fee spends' FCMP with the mint
//! on the input side — so the object the 4.J rows judge is the one the
//! wallet produces. The engine handler's steps are re-made here as the
//! bond post's were in `scenario_archival`; this is the **second**
//! re-making, and the slice's §6 records the trigger a third one would
//! trip (a builder crate is the answer then, not a fourth copy).
//!
//! # The pin
//!
//! A driver whose claim differs from the engine's tests a transaction the
//! wallet never produces (the I17 hazard). The pin is a test that the two
//! assemblies emit identical bytes for one shape, and it lives beside the
//! engine's differential fixtures (`shekyl-engine-core`'s
//! `stake_engine_tests::emission_claim_assembly`), because the handler and
//! its message are that crate's alone. This module is reachable from there
//! through the `harness` feature — a TEST_ONLY feature, enabled only from a
//! consumer's `[dev-dependencies]` edge (`check_test_only_features.py`), so
//! no shipping build carries a second producer.
//!
//! # The seam
//!
//! The engine derives its spend inputs from `PFundingOutputRecord`s through
//! `derive_spend_parts`; the driver derives its own from its wallet-side
//! tree through the production scanner (`scenario_spend`). Both end in a
//! [`SpendInput`], and that is where this function begins: `SpendInput`s
//! in, wire bytes out. Everything from the signable hash to the final
//! encoding is one definition on both sides, with the transaction key
//! passed in rather than drawn, so the byte test can hold the two equal.
//!
//! Panics are the instrument's failure mode (`expect`), as the driver's
//! spend's are. Self-verification is the caller's: the scenario verifies
//! both auth legs, the backing proof and the fee FCMP against the root it
//! proved under before it lists the claim.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_archival_retention::{
    ArchivalRewardEmissionVin, MembershipOnlyBacking, RewardCommit, WorkEpochClaim,
};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_crypto_pq::output::{construct_output, sign_pqc_auth_for_output, OutputData};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, SignatureScheme as _, SCHEME_DOMAIN_EMISSION_BACKING,
    SCHEME_DOMAIN_EMISSION_CLAIM, SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_curve_generators::biased_hash_to_point;
use shekyl_tx_builder::{
    encode_final_tx, phase1_payload_hashes, prove_backing_membership, sign_pqc_auths,
    sign_transaction_with_terms, tx_prefix_hash_from_parts_with_extra, InputTerm, OutputInfo,
    PqcAuth, SpendInput, TreeContext, WireEncodeInput,
};
use shekyl_types::{HoldingsDescriptor, PCanonicalId, PrefixHash};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{serialize, TxExtraField};
use shekyl_wire::Input;
use zeroize::Zeroizing;

/// What the claim says — the vin's fields 2–4 and 6, as the engine's
/// `AssembledClaims` carries them: the holdings descriptor the record
/// holds, the settled epochs claimed in increasing order, one work claim
/// per epoch in the same order, and the plain reward per epoch.
#[derive(Clone, Debug)]
pub struct ClaimTerms {
    pub holdings: HoldingsDescriptor,
    pub settlement_epochs: Vec<u64>,
    pub work_claim: Vec<WorkEpochClaim>,
    pub reward_amount_plain: Vec<u64>,
}

/// The assembled claim: the wire bytes, and the facts a caller verifies
/// them with.
pub struct AssembledClaim {
    /// The transaction as the production encoder emitted it.
    pub bytes: Vec<u8>,
    /// The signable hash (F-C1c): the prefix with the emission vin erased
    /// wholesale — what the backing proof and both auth legs bind.
    pub signable: PrefixHash,
    /// The full prefix hash, emission vin included — what the fee spends'
    /// FCMP and the Bulletproof+ were proved over.
    pub prefix_hash: PrefixHash,
    /// The vin as encoded into the prefix.
    pub vin: ArchivalRewardEmissionVin,
    /// The one reward commit the auth digest bound (the loud vout).
    pub reward_commits: Vec<RewardCommit>,
    /// The persona the claim names, derived from the vin's identity key.
    pub persona: PCanonicalId,
    /// The fee spends' key images in the prefix's order (descending).
    pub key_images: Vec<[u8; 32]>,
    /// The fee spends' output-derived hybrid public keys, in the same order.
    pub fee_pubkeys: Vec<Vec<u8>>,
    /// `SignedProofs::pseudo_outs`, for the fee FCMP's verification.
    pub pseudo_outs: Vec<[u8; 32]>,
    /// `SignedProofs::fcmp_proof`, likewise.
    pub fcmp_proof: Vec<u8>,
    /// The tree depth the proofs were made at.
    pub tree_depth: u8,
}

/// Assemble a persona's emission claim: `fee_inputs` are spent for the fee
/// (and the change back to the persona), `backing` is proved a member of
/// the tree at `tree` without being spent, `terms` are the claim, and
/// `tx_key_secret` is the transaction key — passed in so two assemblies can
/// draw the same one.
///
/// The steps are the engine handler's, numbered as there (`claim.rs`):
/// 5 the fee and the change split; 6 three vouts to the persona's base
/// address, the reward loud; 7 `tx_extra`; 8 the fee spends in descending
/// key-image order; 9 the signable hash; 10–11 the backing's
/// membership-only proof over it; 12–13 the vin and its dual auth;
/// 14 the full prefix hash; 15 the fee-side proving with the reward as the
/// input-side cleartext term; 16–17 the PQC auth slots, fee keys then the
/// identity key; 19 the production encoder.
#[allow(clippy::too_many_lines)]
pub fn assemble_emission_claim(
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    fee_inputs: Vec<SpendInput>,
    backing: SpendInput,
    terms: ClaimTerms,
    fee: u64,
    tree: &TreeContext,
) -> AssembledClaim {
    // Step 5: the mint is the sum of the per-epoch plain rewards; the fee
    // spends fund the fee and return the rest as two confidential vouts.
    let total_reward: u64 = terms
        .reward_amount_plain
        .iter()
        .try_fold(0u64, |acc, r| acc.checked_add(*r))
        .expect("the claimed rewards sum");
    assert!(
        total_reward > 0,
        "an emission's reward is positive (CEN-H22)"
    );
    let fee_total: u64 = fee_inputs
        .iter()
        .try_fold(0u64, |acc, i| acc.checked_add(i.amount.to_raw()))
        .expect("the fee inputs sum");
    let change = fee_total
        .checked_sub(fee)
        .expect("the fee inputs fund the fee");
    let change_lo = change / 2;
    let change_hi = change - change_lo;

    // Step 6: three vouts to P's base address — the reward vout loud, the
    // change vouts confidential. The reward commit the auth digest binds is
    // vout 0's commitment; the post-sign cross-check below holds it equal
    // to the signer's.
    let tx_pubkey = &Scalar::from_bytes_mod_order(**tx_key_secret) * ED25519_BASEPOINT_TABLE;
    let vout_amounts = [total_reward, change_lo, change_hi];
    let constructed: Vec<OutputData> = vout_amounts
        .iter()
        .enumerate()
        .map(|(idx, amount)| {
            construct_output(
                tx_key_secret,
                &keys.x25519_pk,
                &keys.ml_kem_ek,
                keys.spend_pk.as_canonical_bytes(),
                *amount,
                idx as u64,
            )
            .expect("claim-output construction")
        })
        .collect();
    let reward_commits = vec![RewardCommit {
        commitment: constructed[0].commitment,
        amount_plain: total_reward,
        one_time_key: constructed[0].output_key,
    }];
    let output_infos: Vec<OutputInfo> = constructed
        .iter()
        .zip(vout_amounts)
        .map(|(od, amount)| OutputInfo {
            dest_key: od.output_key,
            amount: AtomicUnits::from_raw(amount),
            commitment_mask: od.z,
            enc_amount: od.enc_amount_wire(),
            enc_label: od.enc_label_wire(),
        })
        .collect();
    let output_keys: Vec<[u8; 32]> = constructed.iter().map(|od| od.output_key).collect();
    let view_tags: Vec<Option<u8>> = constructed
        .iter()
        .map(|od| Some(od.view_tag_prefilter))
        .collect();
    let output_amounts: Vec<u64> = vec![total_reward, 0, 0];

    // Step 7: tx_extra — the tx pubkey, the per-output KEM blobs, the 0x07
    // leaf entries (`Extra::for_hybrid_transfer` + `push_pqc_leaf_entries`,
    // field for field).
    let mut kem_blob = Vec::new();
    let mut leaf_blob = Vec::new();
    for od in &constructed {
        kem_blob.extend_from_slice(&od.kem_ciphertext_x25519);
        kem_blob.extend_from_slice(&od.kem_ciphertext_ml_kem);
        leaf_blob.extend_from_slice(&od.pqc_leaf.entry_bytes());
    }
    let tx_extra = serialize(&[
        TxExtraField::PubKey(tx_pubkey.compress().to_bytes()),
        TxExtraField::PqcKemCiphertext(kem_blob),
        TxExtraField::PqcLeafEntries(leaf_blob),
    ])
    .expect("extra serializes");

    // Step 8: the fee spends — `KI = x·Hp(O)`, the output-derived hybrid
    // key, descending key-image order (`prepare_funding_inputs`).
    let mut prepared: Vec<(SpendInput, [u8; 32], Vec<u8>)> = fee_inputs
        .into_iter()
        .map(|spend| {
            let key_image = key_image_of(&spend);
            let pubkey = derive_pqc_public_key(combined64(&spend), spend.output_index)
                .expect("the fee spend's hybrid key derives");
            (spend, key_image, pubkey)
        })
        .collect();
    prepared.sort_by_key(|(_, key_image, _)| std::cmp::Reverse(*key_image));
    let key_images: Vec<[u8; 32]> = prepared.iter().map(|(_, ki, _)| *ki).collect();
    let fee_pubkeys: Vec<Vec<u8>> = prepared.iter().map(|(_, _, pk)| pk.clone()).collect();
    let spend_inputs: Vec<SpendInput> = prepared.into_iter().map(|(spend, _, _)| spend).collect();

    // Step 9: the signable hash — the prefix with the emission vin erased.
    let signable = tx_prefix_hash_from_parts_with_extra(
        &key_images,
        &[],
        &output_keys,
        &output_amounts,
        &view_tags,
        &tx_extra,
    )
    .expect("the signable prefix hashes");

    // Steps 10–11: the backing's output-derived key and its membership-only
    // proof over the signable hash.
    let backing_combined = Zeroizing::new(*combined64(&backing));
    let backing_index = backing.output_index;
    let backing_pubkey = derive_pqc_public_key(&backing_combined, backing_index)
        .expect("the backing's hybrid key derives");
    let membership =
        prove_backing_membership(&backing, tree, signable).expect("the backing proves membership");
    drop(backing);

    // Steps 12–13: the vin with placeholder auths at canonical length, then
    // the dual auth — Auth-B by the backing's output-derived key, Auth-P by
    // the persona's identity key — over the Q1 binding messages.
    let hybrid_pk_bytes = keys
        .hybrid_sign_pk
        .to_canonical_bytes()
        .expect("the identity key encodes");
    let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
    let mut vin = ArchivalRewardEmissionVin {
        p_pubkey: hybrid_pk_bytes.clone(),
        holdings: terms.holdings,
        settlement_epochs: terms.settlement_epochs,
        work_claim: terms.work_claim,
        backing: MembershipOnlyBacking {
            proof: membership.proof,
            pseudo_out: membership.pseudo_out,
            backing_pubkey: backing_pubkey.clone(),
            tree_depth: membership.tree_depth,
        },
        reward_amount_plain: terms.reward_amount_plain,
        auth_backing: vec![0u8; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0u8; SINGLE_SIG_CANONICAL_LEN],
    };
    let auth_msgs = vin
        .auth_msgs(&reward_commits, signable.as_bytes())
        .expect("the auth binding messages derive");
    let auth_b = sign_pqc_auth_for_output(
        &backing_combined,
        backing_index,
        SCHEME_DOMAIN_EMISSION_BACKING,
        &auth_msgs.backing,
    )
    .expect("Auth-B signs");
    assert_eq!(
        auth_b.hybrid_public_key, backing_pubkey,
        "Auth-B's key is the vin's backing_pubkey"
    );
    vin.auth_backing = auth_b.signature;
    vin.auth_claim = HybridEd25519MlDsa
        .sign(
            &keys.hybrid_sign_sk,
            SCHEME_DOMAIN_EMISSION_CLAIM,
            &auth_msgs.claim,
        )
        .expect("Auth-P signs")
        .to_canonical_bytes()
        .expect("Auth-P encodes");

    // Step 14: the completed vin joins the prefix.
    let extra_inputs = vec![Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("the vin encodes"),
    }];
    let prefix_hash = tx_prefix_hash_from_parts_with_extra(
        &key_images,
        &extra_inputs,
        &output_keys,
        &output_amounts,
        &view_tags,
        &tx_extra,
    )
    .expect("the prefix hashes");

    // Step 15: the fee-side proving, the mint as the input-side cleartext
    // term — `Σ pseudoOuts + total_reward·H = Σ masks + fee·H` (CEN-H22).
    let signed = sign_transaction_with_terms(
        prefix_hash,
        &spend_inputs,
        &output_infos,
        AtomicUnits::from_raw(fee),
        &[InputTerm::new(AtomicUnits::from_raw(total_reward))],
        &[],
        tree,
    )
    .expect("the fee side proves");
    assert_eq!(
        signed.commitments.first(),
        Some(&reward_commits[0].commitment),
        "the signer's reward commitment is the auth-bound commit"
    );
    let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
        .expect("the signer's Bulletproof+ blob reads back");

    // Steps 16–17: one PQC auth slot per prefix input — the fee slots at
    // their output-derived keys, the emission slot at the identity key —
    // hashed with empty signatures, then signed.
    let mut wire = WireEncodeInput {
        key_images: key_images.clone(),
        extra_inputs,
        output_amounts,
        output_keys,
        view_tags,
        tx_extra,
        fee,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        out_commitments: signed.commitments,
        pseudo_outs: signed.pseudo_outs.clone(),
        bulletproof,
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof.clone(),
        pqc_auths: fee_pubkeys
            .iter()
            .cloned()
            .chain(std::iter::once(hybrid_pk_bytes.clone()))
            .map(|public_key| PqcAuth {
                auth_version: 1,
                signature: Vec::new(),
                public_key,
            })
            .collect(),
        fcmp_layers: signed.tree_depth,
    };
    let payload_hashes = phase1_payload_hashes(&wire).expect("the unsigned body hashes");
    assert_eq!(
        payload_hashes.len(),
        spend_inputs.len() + 1,
        "one payload per prefix input"
    );
    let mut pqc_auths = sign_pqc_auths(&payload_hashes[..spend_inputs.len()], &spend_inputs)
        .expect("the fee slots sign");
    let emission_sig = HybridEd25519MlDsa
        .sign(
            &keys.hybrid_sign_sk,
            SCHEME_DOMAIN_PQC_AUTH_TX,
            payload_hashes[spend_inputs.len()].as_bytes(),
        )
        .expect("the emission slot signs");
    pqc_auths.push(PqcAuth {
        auth_version: 1,
        signature: emission_sig
            .to_canonical_bytes()
            .expect("the emission slot's signature encodes"),
        public_key: hybrid_pk_bytes,
    });
    wire.pqc_auths = pqc_auths;
    drop(spend_inputs);

    // Step 19: the production encoder.
    let bytes = encode_final_tx(&wire).expect("the production encoder emits the claim");

    AssembledClaim {
        bytes,
        signable,
        prefix_hash,
        vin,
        reward_commits,
        persona,
        key_images,
        fee_pubkeys,
        pseudo_outs: signed.pseudo_outs,
        fcmp_proof: signed.fcmp_proof,
        tree_depth: signed.tree_depth,
    }
}

/// The 64-byte combined shared secret a [`SpendInput`] carries — what
/// `derive_spend_parts` keeps as `combined64` and the scanner recovers.
fn combined64(spend: &SpendInput) -> &[u8; 64] {
    spend
        .combined_ss
        .as_slice()
        .try_into()
        .expect("a spend input's combined secret is 64 bytes")
}

/// `KI = x·Hp(O)` — the engine's `key_image_from_spend_key_x`, the one
/// definition the watch path and the sweep share.
fn key_image_of(spend: &SpendInput) -> [u8; 32] {
    let x: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(spend.spend_key_x))
            .expect("a spend input's x is canonical"),
    );
    (biased_hash_to_point(spend.output_key) * *x)
        .compress()
        .to_bytes()
}
