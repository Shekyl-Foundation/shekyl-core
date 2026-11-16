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
//! bond post's were in `scenario_archival`. The prove / phase-1 /
//! spend-slot / encode sequence both share is
//! [`shekyl_tx_builder::open_spend`]. What stays here is the emission vin:
//! the membership-only backing, the dual auth, and the loud reward output.
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
//! tree through the production scanner (`shekyl-harness-spender`). Both
//! end in a [`SpendInput`], and that is where this function begins:
//! `SpendInput`s in, wire bytes out. Everything from the signable hash to
//! the final encoding is one definition on both sides, with the
//! transaction key passed in rather than drawn, so the byte test can hold
//! the two equal.
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
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_crypto_pq::output::{construct_output, sign_emission_backing_for_output, OutputData};
use shekyl_crypto_pq::signature::{
    sign_emission_claim, HybridEd25519MlDsa, SignatureScheme as _, SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_curve_generators::biased_hash_to_point;
use shekyl_network::NetworkId;
use shekyl_tx_builder::{
    open_spend, prove_backing_membership, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, tx_signable_for, AuthSlots, InputTerm, OutputInfo,
    SpendInput, SpendLayout, TreeContext,
};
use shekyl_types::{HoldingsDescriptor, PCanonicalId, SigningPayloadHash, TxSignableHash};
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

/// One claim's seeds, one per draw of randomness (`CHAIN_FORGE.md` §5.2):
/// the fee side's range proof, blinds and membership proof (S1–S3), the
/// backing's membership-only proof (S4), Auth-B under the backing output's
/// key and the fee slots under theirs, and Auth-P and the emission slot
/// under the persona's identity key (S5). Apart, so no two signatures or
/// proofs share randomness and the forge's controls can swap one source.
/// Only under the TEST_ONLY `forge` feature; elsewhere the type has no
/// value, so the only claim is the OS-drawn one.
#[cfg(feature = "forge")]
pub struct EmissionSeeds {
    /// The fee side's proofs.
    pub proofs: shekyl_tx_builder::ProofSeeds,
    /// The backing's membership-only proof.
    pub backing: Zeroizing<[u8; 32]>,
    /// Auth-B.
    pub backing_auth: Zeroizing<[u8; 32]>,
    /// The fee spends' slots.
    pub fee_slots: Zeroizing<[u8; 32]>,
    /// Auth-P.
    pub claim_auth: Zeroizing<[u8; 32]>,
    /// The emission slot.
    pub emission_slot: Zeroizing<[u8; 32]>,
}

/// A build without `forge` has no seeded claim.
#[cfg(not(feature = "forge"))]
pub enum EmissionSeeds {}

/// The assembled claim: the wire bytes, and the facts a caller verifies
/// them with.
pub struct AssembledClaim {
    /// The transaction as the production encoder emitted it.
    pub bytes: Vec<u8>,
    /// The transaction's one network-bound message, framed over CEN-J22's
    /// signable prefix (the prefix with the emission vin erased wholesale):
    /// what the backing proof, both auth legs and the fee spends' FCMP all
    /// prove over (the signing envelope §2.2).
    pub tx_signable: TxSignableHash,
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
/// identity key; 19 the production encoder. `network` is the chain the
/// claim lists on: every network-bound message (the `tx_signable`, the
/// vin's auth digests, the fee spends' proofs and slots) is framed with
/// it. `tree` is the reference those proofs anchor at. A spender hands
/// both out with every sourced output (`Sourced::network`, `Sourced::tree`).
// CLIPPY: the network id and the proof reference are separate inputs.
// Pairing them held no invariant the two parameters do not name.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input of the claim; the network id and the proof reference are not one value"
)]
pub fn assemble_emission_claim(
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    fee_inputs: Vec<SpendInput>,
    backing: SpendInput,
    terms: ClaimTerms,
    fee: u64,
    network: &NetworkId,
    tree: &TreeContext,
) -> AssembledClaim {
    assemble_emission_claim_drawing(
        None,
        keys,
        tx_key_secret,
        fee_inputs,
        backing,
        terms,
        fee,
        network,
        tree,
    )
}

/// [`assemble_emission_claim`] with every proof and signature drawing from
/// `seeds` when it is `Some` (the chain forge, `forge` only), the OS's
/// otherwise, as the engine handler draws them.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input of the claim; the seeds are the claim's randomness"
)]
pub fn assemble_emission_claim_drawing(
    seeds: Option<&EmissionSeeds>,
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    fee_inputs: Vec<SpendInput>,
    backing: SpendInput,
    terms: ClaimTerms,
    fee: u64,
    network: &NetworkId,
    tree: &TreeContext,
) -> AssembledClaim {
    assemble(
        network,
        keys,
        tx_key_secret,
        fee_inputs,
        backing,
        terms,
        fee,
        tree,
        FeeProof::AsProved,
        seeds,
    )
}

/// [`assemble_emission_claim`] with its fee-input FCMP++ proof one bit off
/// what the prover made, signed **after** the flip: the claim a producer
/// lists with a bad fee proof under valid signatures. Every other row
/// passes it — the vin's backing proof and its auths are over the signable
/// prefix, and the signatures cover the flipped prunable region — so
/// CEN-J26 is the only row that can refuse it. A proof flipped after
/// signing is CEN-I18's refusal instead, and I18 runs first. The same
/// shape as the spender's `spend_coinbase_breaking_range_proof`.
// CLIPPY: same argument list as [`assemble_emission_claim`].
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input of the claim; the network id and the proof reference are not one value"
)]
pub fn assemble_emission_claim_breaking_fee_proof(
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    fee_inputs: Vec<SpendInput>,
    backing: SpendInput,
    terms: ClaimTerms,
    fee: u64,
    network: &NetworkId,
    tree: &TreeContext,
) -> AssembledClaim {
    assemble(
        network,
        keys,
        tx_key_secret,
        fee_inputs,
        backing,
        terms,
        fee,
        tree,
        FeeProof::FlippedBeforeSigning,
        None,
    )
}

/// `claim`, a claim listed on one network, with its authorizations signed
/// again under `network`'s id: Auth-B and Auth-P over `network`'s binding
/// messages, the fee spends' slots and the emission slot over `network`'s
/// payloads of the re-signed body. The proofs stay as they were made, over
/// the first network's `tx_signable`. Under `network`'s judgement every
/// signature then holds and the proof row is the one that refuses: the
/// claim's leg of the identity test's lock 3 (`CHAIN_FORGE.md` §6), as
/// `Spender::signed_under` is a spend's and a post's.
///
/// `fee_inputs` and `backing` are the claim's own, as its assembly took them
/// (their keys sign; their trees are not read).
///
/// # Panics
///
/// If `claim` carries no emission vin, or a key does not sign.
#[must_use]
pub fn claim_signed_under(
    claim: &shekyl_wire::Transaction,
    keys: &ArchivalPKeys,
    fee_inputs: &[SpendInput],
    backing: &SpendInput,
    network: &NetworkId,
) -> shekyl_wire::Transaction {
    let mut body = claim.clone();
    let at = body
        .prefix
        .inputs
        .iter()
        .position(|input| matches!(input, Input::ArchivalRewardEmission { .. }))
        .expect("a claim carries an emission vin");
    let Input::ArchivalRewardEmission { canonical_bytes } = &body.prefix.inputs[at] else {
        unreachable!("the position found an emission vin");
    };
    let mut vin = ArchivalRewardEmissionVin::read(&mut canonical_bytes.as_slice())
        .expect("the claim's vin decodes");
    let shekyl_wire::Ct::Fcmp { base, .. } = &body.ct else {
        panic!("a claim carries FCMP proofs");
    };
    // The reward commit set the verifier rebuilds (CEN-J24): every output
    // with a loud amount.
    let reward_commits: Vec<RewardCommit> = body
        .prefix
        .outputs
        .iter()
        .zip(&base.commitments)
        .filter(|(output, _)| output.amount != 0)
        .map(|(output, commitment)| RewardCommit {
            commitment: *commitment,
            amount_plain: output.amount,
            one_time_key: output.key,
        })
        .collect();
    let msgs = vin
        .auth_msgs(network, &reward_commits, &body.tx_signable(network))
        .expect("the auth binding messages derive");
    vin.auth_backing =
        sign_emission_backing_for_output(combined64(backing), backing.output_index, &msgs.backing)
            .expect("Auth-B signs")
            .signature;
    vin.auth_claim = sign_emission_claim(&keys.hybrid_sign_sk, &msgs.claim)
        .expect("Auth-P signs")
        .to_canonical_bytes()
        .expect("Auth-P encodes");
    body.prefix.inputs[at] = Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("the vin encodes"),
    };

    // The slots over the re-signed body: the fee spends' first, then the
    // emission slot, the persona's identity key.
    let hashes = body.pqc_signing_payload_hashes(network);
    assert_eq!(
        hashes.len(),
        fee_inputs.len() + 1,
        "one slot per fee input and the emission's"
    );
    let fee_auths = shekyl_tx_builder::sign_pqc_auths(&hashes[..fee_inputs.len()], fee_inputs)
        .expect("the fee keys sign");
    let emission = HybridEd25519MlDsa
        .sign(
            &keys.hybrid_sign_sk,
            SCHEME_DOMAIN_PQC_AUTH_TX,
            hashes[fee_inputs.len()].as_bytes(),
        )
        .expect("the emission slot signs")
        .to_canonical_bytes()
        .expect("the emission slot's signature encodes");
    let shekyl_wire::Ct::Fcmp { pqc_auths, .. } = &mut body.ct else {
        panic!("a claim carries FCMP authorizations");
    };
    for (slot, auth) in pqc_auths.iter_mut().zip(fee_auths) {
        assert_eq!(
            slot.hybrid_public_key, auth.public_key,
            "the fee slot's key"
        );
        slot.hybrid_signature = auth.signature;
    }
    pqc_auths
        .last_mut()
        .expect("the emission slot")
        .hybrid_signature = emission;
    shekyl_wire::Transaction::from_bytes(&body.serialize()).expect("the re-signed claim parses")
}

/// The fee-input proof an assembly signs over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FeeProof {
    /// The prover's.
    AsProved,
    /// The prover's with its first byte flipped, then signed.
    FlippedBeforeSigning,
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn assemble(
    network: &NetworkId,
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    fee_inputs: Vec<SpendInput>,
    backing: SpendInput,
    terms: ClaimTerms,
    fee: u64,
    tree: &TreeContext,
    fee_proof: FeeProof,
    seeds: Option<&EmissionSeeds>,
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
    // The transaction's one network-bound message (the signing envelope
    // §2.2), over that prefix and the base the outputs commit.
    let tx_signable = tx_signable_for(
        network,
        signable,
        AtomicUnits::from_raw(fee),
        &tree.reference_block,
        &output_infos,
    );

    // Steps 10–11: the backing's output-derived key and its membership-only
    // proof over the signable hash.
    let backing_combined = Zeroizing::new(*combined64(&backing));
    let backing_index = backing.output_index;
    let backing_pubkey = derive_pqc_public_key(&backing_combined, backing_index)
        .expect("the backing's hybrid key derives");
    let membership = match seeds {
        #[cfg(feature = "forge")]
        Some(seeds) => shekyl_tx_builder::prove_backing_membership_seeded(
            &seeds.backing,
            &backing,
            tree,
            tx_signable,
        ),
        _ => prove_backing_membership(&backing, tree, tx_signable),
    }
    .expect("the backing proves membership");
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
        .auth_msgs(network, &reward_commits, &tx_signable)
        .expect("the auth binding messages derive");
    let auth_b = match seeds {
        #[cfg(feature = "forge")]
        Some(seeds) => shekyl_crypto_pq::output::sign_emission_backing_for_output_with_ml_dsa_seed(
            &backing_combined,
            backing_index,
            &auth_msgs.backing,
            &seeds.backing_auth,
        ),
        _ => sign_emission_backing_for_output(&backing_combined, backing_index, &auth_msgs.backing),
    }
    .expect("Auth-B signs");
    assert_eq!(
        auth_b.hybrid_public_key, backing_pubkey,
        "Auth-B's key is the vin's backing_pubkey"
    );
    vin.auth_backing = auth_b.signature;
    vin.auth_claim = match seeds {
        #[cfg(feature = "forge")]
        Some(seeds) => shekyl_crypto_pq::signature::sign_emission_claim_with_ml_dsa_seed(
            &keys.hybrid_sign_sk,
            &auth_msgs.claim,
            &seeds.claim_auth,
        ),
        _ => sign_emission_claim(&keys.hybrid_sign_sk, &auth_msgs.claim),
    }
    .expect("Auth-P signs")
    .to_canonical_bytes()
    .expect("Auth-P encodes");

    // Step 14: the completed vin joins the prefix.
    let extra_inputs = vec![Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("the vin encodes"),
    }];

    // Step 15: the fee-side proving, the mint as the input-side cleartext
    // term — `Σ pseudoOuts + total_reward·H = Σ masks + fee·H` (CEN-H22).
    // J22's prefix: the signer frames the tx_signable the backing proof and
    // the auths were made over.
    let mint = [InputTerm::new(AtomicUnits::from_raw(total_reward))];
    let mut signed = match seeds {
        #[cfg(feature = "forge")]
        Some(seeds) => shekyl_tx_builder::sign_transaction_with_terms_seeded(
            &seeds.proofs,
            network,
            signable,
            &spend_inputs,
            &output_infos,
            AtomicUnits::from_raw(fee),
            &mint,
            &[],
            tree,
        ),
        _ => sign_transaction_with_terms(
            network,
            signable,
            &spend_inputs,
            &output_infos,
            AtomicUnits::from_raw(fee),
            &mint,
            &[],
            tree,
        ),
    }
    .expect("the fee side proves");
    assert_eq!(
        signed.commitments.first(),
        Some(&reward_commits[0].commitment),
        "the signer's reward commitment is the auth-bound commit"
    );
    if fee_proof == FeeProof::FlippedBeforeSigning {
        signed.fcmp_proof[0] ^= 0x01;
    }

    // Steps 16–17: fee slots sign inside `open_spend`; the emission slot
    // signs with the persona's identity key over its own payload.
    let layout = SpendLayout {
        key_images: key_images.clone(),
        extra_inputs,
        output_amounts,
        output_keys,
        view_tags,
        tx_extra,
        fee,
        slots: AuthSlots {
            spend: fee_pubkeys.clone(),
            extra: vec![hybrid_pk_bytes],
        },
    };
    let open = match seeds {
        #[cfg(feature = "forge")]
        Some(seeds) => shekyl_tx_builder::open_spend_seeded(
            &seeds.fee_slots,
            signed,
            &spend_inputs,
            layout,
            network,
        ),
        _ => open_spend(signed, &spend_inputs, layout, network),
    }
    .expect("the fee side opens");
    drop(spend_inputs);
    let emission_sig = {
        let payload: &SigningPayloadHash = open
            .sole_extra_payload()
            .expect("the emission slot has a payload");
        match seeds {
            #[cfg(feature = "forge")]
            Some(seeds) => HybridEd25519MlDsa.sign_with_ml_dsa_seed(
                &keys.hybrid_sign_sk,
                SCHEME_DOMAIN_PQC_AUTH_TX,
                payload.as_bytes(),
                &seeds.emission_slot,
            ),
            _ => HybridEd25519MlDsa.sign(
                &keys.hybrid_sign_sk,
                SCHEME_DOMAIN_PQC_AUTH_TX,
                payload.as_bytes(),
            ),
        }
        .expect("the emission slot signs")
    };
    let pseudo_outs = open.pseudo_outs().to_vec();
    let fcmp_proof = open.fcmp_proof().to_vec();
    let tree_depth = open.layers();
    let bytes = open
        .encode(vec![emission_sig
            .to_canonical_bytes()
            .expect("the emission slot's signature encodes")])
        .expect("the production encoder emits the claim");

    AssembledClaim {
        bytes,
        tx_signable,
        vin,
        reward_commits,
        persona,
        key_images,
        fee_pubkeys,
        pseudo_outs,
        fcmp_proof,
        tree_depth,
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
