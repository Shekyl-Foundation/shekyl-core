// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `KeyEngine::sign_transaction` bridge (Phase 2a §3.7–3.9).

use std::collections::HashMap;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;
use rand_core::{OsRng, RngCore};
use shekyl_address::{Network, ShekylAddress};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::output::construct_output;
use shekyl_crypto_pq::output_claim::output_spend_offset_scalar;
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction as tx_sign_proofs,
    tx_prefix_hash_from_parts, LeafEntry, OutputInfo, PqcAuth, SpendInput, WireEncodeInput,
};
use shekyl_units::AtomicUnits;
use zeroize::Zeroizing;

use super::error::KeyEngineError;
use super::local_keys::LocalKeys;
use super::traits::key::{
    TxInputSignature, TxInputSigningContext, TxOutputContext, TxSignatures, TxToSign,
};

struct DerivedScalars {
    view_scalar: Zeroizing<Scalar>,
    spend_public: EdwardsPoint,
}

impl DerivedScalars {
    fn from_keys(keys: &AllKeysBlob) -> Self {
        let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(
            *keys.view_sk.as_canonical_bytes(),
        ));
        let spend_public = CompressedEdwardsY(*keys.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("AllKeysBlob::spend_pk decompresses");
        Self {
            view_scalar,
            spend_public,
        }
    }

    fn change_spend_pk(&self, subaddress_index: u32) -> [u8; 32] {
        let idx_le = subaddress_index.to_le_bytes();
        let m = output_spend_offset_scalar(&self.view_scalar, &idx_le);
        (self.spend_public + (&m * ED25519_BASEPOINT_TABLE))
            .compress()
            .to_bytes()
    }
}

struct BuiltOutput {
    info: OutputInfo,
    output_key: [u8; 32],
    view_tag: Option<u8>,
    kem_blob: Vec<u8>,
}

fn build_output(
    tx_key_secret: &[u8; 32],
    recipient_spend_pk: &[u8; 32],
    recipient_x25519: &[u8; 32],
    recipient_ml_kem: &[u8],
    amount: u64,
    output_index: u64,
) -> Result<BuiltOutput, KeyEngineError> {
    let constructed = construct_output(
        tx_key_secret,
        recipient_x25519,
        recipient_ml_kem,
        recipient_spend_pk,
        amount,
        output_index,
    )
    .map_err(KeyEngineError::SourceCiphertextDecapsulationFailed)?;

    let mut kem_blob = Vec::with_capacity(32 + constructed.kem_ciphertext_ml_kem.len());
    kem_blob.extend_from_slice(&constructed.kem_ciphertext_x25519);
    kem_blob.extend_from_slice(&constructed.kem_ciphertext_ml_kem);

    let enc_amount = {
        let mut buf = [0u8; 9];
        buf[..8].copy_from_slice(&constructed.enc_amount);
        buf[8] = constructed.amount_tag;
        buf
    };
    let enc_label = {
        let mut buf = [0u8; 9];
        buf[..8].copy_from_slice(&constructed.enc_label);
        buf[8] = constructed.label_tag;
        buf
    };

    Ok(BuiltOutput {
        info: OutputInfo {
            dest_key: constructed.output_key,
            amount: AtomicUnits::from_raw(amount),
            commitment_mask: constructed.z,
            enc_amount,
            enc_label,
        },
        output_key: constructed.output_key,
        view_tag: Some(constructed.view_tag_prefilter),
        kem_blob,
    })
}

fn decode_recipient(address: &str, network: Network) -> Result<ShekylAddress, KeyEngineError> {
    ShekylAddress::decode_for_network(address, network).map_err(|_| KeyEngineError::Primitive {
        detail: "invalid recipient address",
    })
}

fn spend_input_from_context(
    ctx: &TxInputSigningContext,
    bundle: &super::traits::key::SourceSecretsBundle,
    leaf_chunk: Vec<LeafEntry>,
    c1_layers: Vec<Vec<[u8; 32]>>,
    c2_layers: Vec<Vec<[u8; 32]>>,
) -> SpendInput {
    SpendInput {
        output_key: ctx.output_key,
        commitment: ctx.commitment,
        amount: ctx.amount,
        spend_key_x: *bundle.spend_key_x,
        spend_key_y: *bundle.spend_key_y,
        commitment_mask: *bundle.commitment_mask,
        h_pqc: ctx.h_pqc,
        combined_ss: bundle.combined_ss.to_vec(),
        output_index: ctx.internal_output_index,
        leaf_chunk,
        c1_layers,
        c2_layers,
    }
}

/// Sign a populated [`TxToSign`] using wallet key material (actor round-trip).
pub(crate) fn sign_tx(local: &LocalKeys, tx: &TxToSign) -> Result<TxSignatures, KeyEngineError> {
    let keys = &local.keys;
    if tx.inputs.is_empty() {
        return Err(KeyEngineError::Primitive {
            detail: "sign_transaction requires at least one input",
        });
    }

    let derived = DerivedScalars::from_keys(keys);
    let network = tx.network;
    let tree_ctx = tx.fcmp_plus_plus_context.tree.clone();
    let fee_directive = tx.fee;

    let mut input_amounts = 0u64;
    for input in &tx.inputs {
        input_amounts = input_amounts
            .checked_add(input.amount.to_raw())
            .ok_or(KeyEngineError::InsufficientFunds { shortfall: 0 })?;
    }

    let mut payment_total = 0u64;
    let mut payment_outputs: Vec<(String, u64)> = Vec::new();
    let mut change_index: Option<u32> = None;
    for output in &tx.outputs {
        match output {
            TxOutputContext::Payment { dest, amount } => {
                payment_total = payment_total
                    .checked_add(*amount)
                    .ok_or(KeyEngineError::InsufficientFunds { shortfall: 0 })?;
                payment_outputs.push((dest.address.clone(), *amount));
            }
            TxOutputContext::Change { subaddress_index } => {
                change_index = Some(*subaddress_index);
            }
        }
    }

    let leftover =
        input_amounts
            .checked_sub(payment_total)
            .ok_or(KeyEngineError::InsufficientFunds {
                shortfall: payment_total.saturating_sub(input_amounts),
            })?;

    let (fee, include_change) = if leftover
        >= fee_directive
            .fee_with_change
            .saturating_add(fee_directive.dust_threshold)
    {
        (fee_directive.fee_with_change, true)
    } else if leftover >= fee_directive.fee_no_change {
        (fee_directive.fee_no_change, false)
    } else {
        return Err(KeyEngineError::InsufficientFunds {
            shortfall: fee_directive.fee_no_change.saturating_sub(leftover),
        });
    };

    let mut tx_key_secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(tx_key_secret.as_mut());

    let tx_pubkey_scalar = Scalar::from_bytes_mod_order(*tx_key_secret);
    let tx_pubkey = &tx_pubkey_scalar * ED25519_BASEPOINT_TABLE;

    let mut built_outputs: Vec<BuiltOutput> = Vec::new();
    let mut kem_blobs: Vec<Vec<u8>> = Vec::new();
    let mut output_index: u64 = 0;

    for (address, amount) in payment_outputs {
        let recipient = decode_recipient(&address, network)?;
        let built = build_output(
            &tx_key_secret,
            &recipient.spend_key,
            &recipient.view_key,
            &recipient.ml_kem_encap_key,
            amount,
            output_index,
        )?;
        kem_blobs.push(built.kem_blob.clone());
        built_outputs.push(built);
        output_index += 1;
    }

    if include_change {
        let sub_idx = change_index.unwrap_or(0);
        let change_amount = leftover
            .checked_sub(fee)
            .ok_or(KeyEngineError::InsufficientFunds { shortfall: 1 })?;
        if change_amount > 0 {
            let change_pk = derived.change_spend_pk(sub_idx);
            let built = build_output(
                &tx_key_secret,
                &change_pk,
                &keys.x25519_pk,
                &keys.ml_kem_ek,
                change_amount,
                output_index,
            )?;
            kem_blobs.push(built.kem_blob.clone());
            built_outputs.push(built);
        }
    }

    if built_outputs.is_empty() {
        return Err(KeyEngineError::Primitive {
            detail: "no outputs after fee variant selection",
        });
    }

    let tx_extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs).serialize();

    let mut bundles = HashMap::new();
    for input in &tx.inputs {
        let expected = derive_output_handle(
            keys.view_sk.as_canonical_bytes(),
            &input.tx_hash,
            input.internal_output_index,
        );
        if expected != input.handle {
            return Err(KeyEngineError::HandleMismatch {
                output_index: input.internal_output_index,
            });
        }

        let bundle = local.derive_primary_source_secrets_bundle(
            &input.source_ciphertext,
            input.internal_output_index,
        )?;
        bundles.insert(input.internal_output_index, bundle);
    }

    let mut spend_inputs = Vec::with_capacity(tx.inputs.len());
    let mut key_images = Vec::with_capacity(tx.inputs.len());
    let mut pqc_pubkeys = Vec::with_capacity(tx.inputs.len());

    for input in &tx.inputs {
        let bundle = bundles
            .get(&input.internal_output_index)
            .expect("bundle inserted above");
        let combined: [u8; 64] =
            bundle.combined_ss[..64]
                .try_into()
                .map_err(|_| KeyEngineError::Primitive {
                    detail: "combined_ss wrong length",
                })?;
        let pk = derive_pqc_public_key(&combined, input.internal_output_index)
            .map_err(KeyEngineError::SourceCiphertextDecapsulationFailed)?;

        if input.key_image.as_bytes().iter().all(|b| *b == 0) {
            return Err(KeyEngineError::MissingKeyImage {
                output_index: input.internal_output_index,
            });
        }
        // CT-5c: the membership path (leaf chunk + branch layers) is the *real*
        // path the curve-tree client assembled, threaded verbatim through the
        // signing context — not re-derived or padded here. The pre-CT-5c
        // synthetic re-run (`enrich_input_tree`) is gone; clobbering the real
        // branches with placeholders was the second of the two synthetic sites.
        spend_inputs.push(spend_input_from_context(
            input,
            bundle,
            input.leaf_chunk.clone(),
            input.c1_layers.clone(),
            input.c2_layers.clone(),
        ));
        key_images.push(*input.key_image.as_bytes());
        pqc_pubkeys.push(pk);
    }

    // CT-5c: the real tree context from the assembled paths, used verbatim. The
    // pre-CT-5c synthetic root overwrite (`synthetic_tree_root_from_leaf_chunk`)
    // is gone — `tree_ctx.tree_root` is the consensus root the proof anchors to.
    let tree = tree_ctx;

    let output_infos: Vec<OutputInfo> = built_outputs.iter().map(|b| b.info.clone()).collect();
    let output_keys: Vec<[u8; 32]> = built_outputs.iter().map(|b| b.output_key).collect();
    let view_tags: Vec<Option<u8>> = built_outputs.iter().map(|b| b.view_tag).collect();

    let prefix_hash = tx_prefix_hash_from_parts(&key_images, &output_keys, &view_tags, &tx_extra);

    let signed = tx_sign_proofs(
        prefix_hash,
        &spend_inputs,
        &output_infos,
        AtomicUnits::from_raw(fee),
        &tree,
    )
    .map_err(|e| KeyEngineError::Primitive {
        detail: match e {
            shekyl_tx_builder::TxBuilderError::InsufficientFunds { .. } => {
                "tx-builder insufficient funds"
            }
            _ => "tx-builder sign_transaction failed",
        },
    })?;

    let bulletproof =
        Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice()).map_err(|_| {
            KeyEngineError::Primitive {
                detail: "bulletproof parse failed",
            }
        })?;

    let mut wire_with_proofs = WireEncodeInput {
        key_images: key_images.clone(),
        output_keys: output_keys.clone(),
        view_tags: view_tags.clone(),
        tx_extra: tx_extra.clone(),
        fee,
        enc_amounts: signed.enc_amounts.clone(),
        enc_labels: signed.enc_labels.clone(),
        out_commitments: signed.commitments.clone(),
        pseudo_outs: signed.pseudo_outs.clone(),
        bulletproof: bulletproof.clone(),
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof.clone(),
        pqc_auths: pqc_pubkeys
            .iter()
            .map(|pk| PqcAuth {
                auth_version: 1,
                signature: Vec::new(),
                public_key: pk.clone(),
            })
            .collect(),
        tree_depth: signed.tree_depth,
    };

    let payload_hashes =
        phase1_payload_hashes(&wire_with_proofs).map_err(|_| KeyEngineError::Primitive {
            detail: "phase1 payload hash failed",
        })?;

    let pqc_auths =
        sign_pqc_auths(&payload_hashes, &spend_inputs).map_err(|_| KeyEngineError::Primitive {
            detail: "pqc auth signing failed",
        })?;

    wire_with_proofs.pqc_auths = pqc_auths.clone();

    let per_input: Vec<TxInputSignature> = spend_inputs
        .iter()
        .zip(signed.pseudo_outs.iter())
        .zip(key_images.iter())
        .zip(pqc_auths.iter())
        .map(|(((_inp, pseudo), ki), auth)| TxInputSignature {
            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(*ki),
            pseudo_out: *pseudo,
            pqc_auth: auth.clone(),
        })
        .collect();

    Ok(TxSignatures {
        bulletproof_plus: signed.bulletproof_plus,
        out_commitments: signed.commitments,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        per_input,
        fcmp_proof: signed.fcmp_proof,
        fee,
        reference_block: signed.reference_block,
        tree_depth: signed.tree_depth,
        output_keys,
        view_tags,
        tx_extra,
    })
}
