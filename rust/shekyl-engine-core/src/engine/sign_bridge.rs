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
use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
use shekyl_crypto_pq::output::construct_output;
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction as tx_sign_proofs,
    tx_prefix_hash_from_parts, LeafEntry, OutputInfo, PqcAuth, SignedProofs, SpendInput,
    WireEncodeInput,
};
use shekyl_units::AtomicUnits;
use zeroize::Zeroizing;

use super::error::KeyEngineError;
use super::local_keys::LocalKeys;
use super::traits::key::{
    TxInputSignature, TxInputSigningContext, TxOutputContext, TxSignatures, TxToSign,
};

struct DerivedScalars {
    spend_public: EdwardsPoint,
}

impl DerivedScalars {
    fn from_keys(keys: &AllKeysBlob) -> Self {
        let spend_public = CompressedEdwardsY(*keys.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("AllKeysBlob::spend_pk decompresses");
        Self { spend_public }
    }

    /// Spend key for a self-paid change output: the wallet's **base** spend key
    /// `D = b·G`. V3.0 is primary-only and the spend witness carries no claim
    /// offset (`x = ho + b`; see `LocalKeys::derive_primary_source_secrets_bundle`),
    /// so change MUST be paid to the base key — the same key any external sender
    /// pays to — for the wallet to detect it (scanner `B' == D`) and spend it
    /// (SAL open) later. The pre-fix `D + m₀·G` change was unspendable AND
    /// invisible to the scanner.
    fn change_spend_pk(&self) -> [u8; 32] {
        self.spend_public.compress().to_bytes()
    }
}

// `pub(super)`: the F-D2 drain assembly (`drain_assembly.rs`) constructs its
// two outputs through this exact primitive so a drain vout is byte-identical to
// an ordinary transfer vout (T-DS-6/T-DS-7 composite wire-shape arm — the
// output-construction leg has one definition, shared with the transfer path).
pub(super) struct BuiltOutput {
    pub(super) info: OutputInfo,
    pub(super) output_key: [u8; 32],
    pub(super) view_tag: Option<u8>,
    pub(super) kem_blob: Vec<u8>,
    /// The output's `H(pqc_pk)` curve-tree leaf component, for the tx_extra
    /// `0x07` leaf-hash blob (vout order). An output whose transaction omits
    /// the field ingests with a **zero** `h_pqc` leaf and is unspendable —
    /// no FCMP++ spend of it can satisfy the verifier's
    /// `pqc_auths`-derived leaf hash (the PR-4b bond e2e surfaced this
    /// live: the persona funding transfer's outputs could not fund a bond).
    pub(super) h_pqc: [u8; 32],
}

pub(super) fn build_output(
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
        h_pqc: constructed.h_pqc,
    })
}

/// Assemble the transfer-shaped [`WireEncodeInput`] shared by the ordinary
/// transfer path ([`sign_tx`]) and the F-D2 drain
/// ([`assemble_drain_tx`](super::drain_assembly::assemble_drain_tx)).
///
/// This is the **single definition** of a confidential FCMP++ spend's wire
/// shape: empty `extra_inputs` (no bond/emission prefix input), all-zero
/// `output_amounts` (every vout confidential), and exactly one *placeholder*
/// `pqc_auth` per spend — public key only; the signature is filled by the
/// caller's [`phase1_payload_hashes`] + [`sign_pqc_auths`] pass. Because both
/// paths route through here, a drain's full wire serialization is
/// transfer-identical **by construction** rather than by a hand-copied literal
/// that could silently drift — this is the enforcement mechanism for the
/// T-DS-6 ∧ T-DS-7 composite wire-shape arm (`ARCHIVAL_DRAIN_SEND_FD2.md` §5),
/// not a test that green-checks each sub-surface separately.
///
/// `pqc_pubkeys` is one serialized hybrid public key per spend input, in the
/// same (strict-descending key-image) order as `key_images`.
///
/// `signed` is taken **by value**: the constructor moves its large proof buffers
/// (`enc_amounts`, `enc_labels`, `commitments`, `pseudo_outs`, `fcmp_proof`)
/// straight into the [`WireEncodeInput`] rather than cloning them. The drain
/// path — which discards `signed` after this call — passes it by move for free;
/// [`sign_tx`], which still needs the proofs to build its [`TxSignatures`],
/// hands in a `signed.clone()`. Keeping this one owning constructor (rather than
/// a borrowed + owned pair) is what preserves the "one constructor, two callers"
/// compile-time transfer-parity guarantee for T-DS-6 ∧ T-DS-7.
///
/// Returns [`KeyEngineError::Primitive`] if the documented length invariants are
/// violated — `view_tags` must be per-output (align with `output_keys`) and
/// `pqc_pubkeys` must be one-per-spend (align with `key_images`) — so a caller
/// mismatch fails here with a precise message instead of surfacing later as an
/// opaque `phase1_payload_hashes`/wire-encode error.
pub(super) fn assemble_transfer_wire(
    key_images: Vec<[u8; 32]>,
    output_keys: Vec<[u8; 32]>,
    view_tags: Vec<Option<u8>>,
    tx_extra: Vec<u8>,
    fee: u64,
    signed: SignedProofs,
    pqc_pubkeys: &[Vec<u8>],
) -> Result<WireEncodeInput, KeyEngineError> {
    if view_tags.len() != output_keys.len() {
        return Err(KeyEngineError::Primitive {
            detail: "assemble_transfer_wire: view_tags length must equal output_keys length",
        });
    }
    if pqc_pubkeys.len() != key_images.len() {
        return Err(KeyEngineError::Primitive {
            detail: "assemble_transfer_wire: pqc_pubkeys length must equal key_images length",
        });
    }

    let bulletproof =
        Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice()).map_err(|_| {
            KeyEngineError::Primitive {
                detail: "bulletproof parse failed",
            }
        })?;
    let output_amounts = vec![0u64; output_keys.len()];
    Ok(WireEncodeInput {
        key_images,
        extra_inputs: Vec::new(),
        output_amounts,
        output_keys,
        view_tags,
        tx_extra,
        fee,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        out_commitments: signed.commitments,
        pseudo_outs: signed.pseudo_outs,
        bulletproof,
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof,
        pqc_auths: pqc_pubkeys
            .iter()
            .map(|pk| PqcAuth {
                auth_version: 1,
                signature: Vec::new(),
                public_key: pk.clone(),
            })
            .collect(),
        fcmp_layers: signed.tree_depth,
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
    for output in &tx.outputs {
        match output {
            TxOutputContext::Payment { dest, amount } => {
                payment_total = payment_total
                    .checked_add(*amount)
                    .ok_or(KeyEngineError::InsufficientFunds { shortfall: 0 })?;
                payment_outputs.push((dest.address.clone(), *amount));
            }
            // V3.0 is primary-only: change always returns to the base spend key,
            // so the requested change index (if any) carries no signing meaning.
            TxOutputContext::Change { .. } => {}
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
        // The address carries the recipient's **Edwards** view key; the KEM's
        // X25519 half encapsulates to `montgomery(view_pk)` (the parameter-free
        // birational map — the same one the recipient's scanner inverts by using
        // its view scalar as the Montgomery secret). Passing the Edwards bytes
        // straight through would encapsulate to a wrong point: the daemon still
        // accepts the tx (the sender's own proofs re-derive consistently), but
        // the recipient's decap silently fails and the output is unrecoverable.
        let recipient_x25519 = ed25519_pk_to_x25519_pk(&recipient.view_key).map_err(|_| {
            KeyEngineError::Primitive {
                detail: "recipient view key does not map to a valid X25519 point",
            }
        })?;
        let built = build_output(
            &tx_key_secret,
            &recipient.spend_key,
            &recipient_x25519,
            &recipient.ml_kem_encap_key,
            amount,
            output_index,
        )?;
        kem_blobs.push(built.kem_blob.clone());
        built_outputs.push(built);
        output_index += 1;
    }

    if include_change {
        let change_amount = leftover
            .checked_sub(fee)
            .ok_or(KeyEngineError::InsufficientFunds { shortfall: 1 })?;
        if change_amount > 0 {
            let change_pk = derived.change_spend_pk();
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

    // tx_extra: tx pubkey + per-output KEM blobs + the `0x07` PQC leaf-hash
    // blob (`H(pqc_pk)` per output, vout order). Without the `0x07` field
    // every output of this transfer ingests into the curve tree with a zero
    // `h_pqc` leaf and is **unspendable** — the FCMP++ verifier derives the
    // leaf hash from the spender's pqc auth key, which can never equal zero.
    // The bond/emission assembly paths (stake_engine.rs) have always
    // appended it; the PR-4b bond e2e surfaced this gap live when a persona
    // funding output built by this path could not fund a bond post.
    let leaf_hash_blob: Vec<u8> = built_outputs.iter().flat_map(|b| b.h_pqc).collect();
    let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
    extra.push_pqc_leaf_hashes(leaf_hash_blob);
    let tx_extra = extra.serialize();

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
        // Key by the *globally unique* output identity `(tx_hash, output_index)`,
        // NOT `internal_output_index` alone: that index is per-transaction, so a
        // multi-input spend over coinbase outputs (each output 0 of its own tx)
        // would collide on key 0 and clobber all-but-one bundle, pairing every
        // input with the wrong `(x, y)`.
        bundles.insert((input.tx_hash, input.internal_output_index), bundle);
    }

    let mut spend_inputs = Vec::with_capacity(tx.inputs.len());
    let mut key_images = Vec::with_capacity(tx.inputs.len());
    let mut pqc_pubkeys = Vec::with_capacity(tx.inputs.len());

    // Consensus requires spend inputs strictly DESCENDING by key image
    // (`blockchain.cpp:3650`; shekyl-wire validate, `transaction.rs:1547`). The
    // FCMP++ proof binds the input order, so sort BEFORE building witnesses, key
    // images, and the proof — one canonical order shared by the proof, the wire
    // key-image list, and the returned per-input pseudo-outs. Distinct UTXOs ⇒
    // distinct key images, so the strict ordering never rejects our own tx.
    let mut sorted_inputs: Vec<_> = tx.inputs.iter().collect();
    sorted_inputs.sort_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));

    for input in sorted_inputs {
        let bundle = bundles
            .get(&(input.tx_hash, input.internal_output_index))
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

    // The wire shape is assembled by the single shared constructor both this
    // path and the F-D2 drain route through, so the two serialize identically
    // by construction (T-DS-6 ∧ T-DS-7 — `ARCHIVAL_DRAIN_SEND_FD2.md` §5).
    // `key_images`/`output_keys`/`view_tags`/`tx_extra` and `signed` are cloned
    // in because this path still needs them below: the returned `TxSignatures`
    // echoes the buffers, moves `signed`'s proof fields, and `per_input`
    // re-walks the key images and `signed.pseudo_outs`. The drain path, which
    // discards these afterward, moves them in at zero clones.
    let mut wire_with_proofs = assemble_transfer_wire(
        key_images.clone(),
        output_keys.clone(),
        view_tags.clone(),
        tx_extra.clone(),
        fee,
        signed.clone(),
        &pqc_pubkeys,
    )?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::local_keys::LocalKeys;
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::output::scan_output_recover;

    /// A self-paid **change** output must return to the wallet's base spend key
    /// `D = b·G` so the wallet can both **detect** it (the scanner recovers
    /// `B' == D`) and **spend** it (the derived witness opens `O = x·G + y·T`).
    ///
    /// The pre-fix change path paid to `D + m₀·G`, which is *neither*: invisible
    /// to the scanner (which matches the base key) and unspendable (the witness
    /// is `x = ho + b`, no offset). The whole-tx north-star did not catch it —
    /// the daemon accepts the change output as a valid point regardless — so this
    /// is the direct guard against reintroducing the offset on the change side.
    #[test]
    fn change_output_returns_to_base_and_is_detectable_and_spendable() {
        const SEED: [u8; 32] = [7u8; 32];
        const TX_KEY: [u8; 32] = [11u8; 32];
        const OUT_IDX: u64 = 0;
        const AMOUNT: u64 = 1_000_000;

        let keys = LocalKeys::from_test_seed(SEED);
        let derived = DerivedScalars::from_keys(&keys.keys);

        // (1) change spend key is the bare base key — no claim offset.
        let change_pk = derived.change_spend_pk();
        assert_eq!(
            change_pk,
            *keys.keys.spend_pk.as_canonical_bytes(),
            "change must return to the base spend key D = b·G"
        );

        // Build the change output exactly as `sign_tx` does.
        let constructed = construct_output(
            &TX_KEY,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            &change_pk,
            AMOUNT,
            OUT_IDX,
        )
        .expect("construct change output");

        // (2) Detectable: the scanner recovers B' == the base spend key.
        let recovered = scan_output_recover(
            keys.keys.view_sk.as_canonical_bytes(),
            keys.keys.ml_kem_dk.as_canonical_bytes(),
            &constructed.kem_ciphertext_x25519,
            &constructed.kem_ciphertext_ml_kem,
            &constructed.output_key,
            &constructed.commitment,
            &constructed.enc_amount,
            constructed.amount_tag,
            &constructed.enc_label,
            constructed.label_tag,
            constructed.view_tag_prefilter,
            OUT_IDX,
        )
        .expect("scanner detects the self-paid change output");
        assert_eq!(
            recovered.recovered_spend_key, change_pk,
            "scanner must recover the base spend key for change"
        );

        // (3) Spendable: the derived witness opens the output key, x·G + y·T == O.
        let ciphertext = HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };
        let bundle = keys
            .derive_primary_source_secrets_bundle(&ciphertext, OUT_IDX)
            .expect("derive change-output spend bundle");
        let x: Scalar =
            Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_x)).expect("x canonical");
        let y: Scalar =
            Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_y)).expect("y canonical");
        let o = CompressedEdwardsY(constructed.output_key)
            .decompress()
            .expect("O decompresses");
        assert_eq!(
            (&x * ED25519_BASEPOINT_TABLE) + (*shekyl_curve_generators::T * y),
            o,
            "change output must open with x·G + y·T == O (spendable)"
        );
    }

    /// A **payment** output built from a decoded address must be recoverable by
    /// the recipient — the sender-side X25519 encapsulation key is
    /// `montgomery(view_pk)`, never the raw Edwards `view_key` bytes the
    /// address carries.
    ///
    /// The pre-fix payment path passed `recipient.view_key` (compressed
    /// Edwards) straight into `construct_output`'s `x25519_pk` parameter, which
    /// interprets the bytes as a Montgomery u-coordinate. The ECDH then targets
    /// a wrong point: the daemon still accepts the transaction (the sender's
    /// own proofs re-derive from the same wrong point, consistently), but the
    /// recipient's decap silently fails and the payment is invisible to its
    /// scanner. Self-paid change never hit this (it uses the wallet's stored
    /// `x25519_pk`), so only a cross-wallet recovery pins it — this is the
    /// unit-level distillation of the PR-4 staker regtest harness's
    /// persona-funding discovery leg.
    #[test]
    fn payment_output_from_decoded_address_is_recoverable_by_the_recipient() {
        const SEED: [u8; 32] = [9u8; 32];
        const TX_KEY: [u8; 32] = [13u8; 32];
        const OUT_IDX: u64 = 0;
        const AMOUNT: u64 = 5_000_000;

        // Recipient wallet: encode its primary address (Edwards view key on the
        // wire), then decode it exactly as `sign_tx` does.
        let recipient_keys = LocalKeys::from_test_seed(SEED);
        let address = ShekylAddress::new(
            Network::Mainnet,
            *recipient_keys.keys.spend_pk.as_canonical_bytes(),
            *recipient_keys.keys.view_pk.as_canonical_bytes(),
            recipient_keys.keys.ml_kem_ek.to_vec(),
        )
        .encode()
        .expect("encode recipient address");
        let decoded = decode_recipient(&address, Network::Mainnet).expect("decode recipient");

        // Sender-side mapping, exactly as the `sign_tx` payment loop does it.
        let recipient_x25519 =
            ed25519_pk_to_x25519_pk(&decoded.view_key).expect("map view key to X25519");
        assert_eq!(
            recipient_x25519, recipient_keys.keys.x25519_pk,
            "the mapped key must equal the wallet's stored montgomery(view_pk)"
        );

        // Positive arm: an output encapsulated to the MAPPED key is recovered
        // by the recipient's view-derived Montgomery secret (the production
        // scanner's derivation).
        let constructed = construct_output(
            &TX_KEY,
            &recipient_x25519,
            &decoded.ml_kem_encap_key,
            &decoded.spend_key,
            AMOUNT,
            OUT_IDX,
        )
        .expect("construct payment output");
        let recovered = scan_output_recover(
            recipient_keys.keys.view_sk.as_canonical_bytes(),
            recipient_keys.keys.ml_kem_dk.as_canonical_bytes(),
            &constructed.kem_ciphertext_x25519,
            &constructed.kem_ciphertext_ml_kem,
            &constructed.output_key,
            &constructed.commitment,
            &constructed.enc_amount,
            constructed.amount_tag,
            &constructed.enc_label,
            constructed.label_tag,
            constructed.view_tag_prefilter,
            OUT_IDX,
        )
        .expect("recipient must recover the payment output");
        assert_eq!(
            recovered.recovered_spend_key, decoded.spend_key,
            "recovery must yield the recipient's spend key"
        );

        // Negative arm — the bug class this test exists for: encapsulating to
        // the RAW Edwards view-key bytes (interpreted as a Montgomery
        // u-coordinate) produces an output the recipient CANNOT recover.
        let wrong = construct_output(
            &TX_KEY,
            &decoded.view_key,
            &decoded.ml_kem_encap_key,
            &decoded.spend_key,
            AMOUNT,
            OUT_IDX,
        )
        .expect("construct output to the wrong point (daemon-acceptable)");
        assert!(
            scan_output_recover(
                recipient_keys.keys.view_sk.as_canonical_bytes(),
                recipient_keys.keys.ml_kem_dk.as_canonical_bytes(),
                &wrong.kem_ciphertext_x25519,
                &wrong.kem_ciphertext_ml_kem,
                &wrong.output_key,
                &wrong.commitment,
                &wrong.enc_amount,
                wrong.amount_tag,
                &wrong.enc_label,
                wrong.label_tag,
                wrong.view_tag_prefilter,
                OUT_IDX,
            )
            .is_err(),
            "an output encapsulated to the raw Edwards bytes must NOT be recoverable"
        );
    }
}
