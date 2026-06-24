//! Wire adapter: map the builder's spend material onto a canonical
//! `shekyl_wire::Transaction`, then serialize it / derive its signing hashes.
//!
//! shekyl-wire is the single authority for the genesis spend layout AND its signing
//! hashes (`FCMP_SPEND_SIGNING_PREIMAGE.md` §4). This module only *maps* onto it; it
//! keeps shekyl-oxide's **crypto** (`Bulletproof`) but no longer its wire/proof types,
//! and the four §3 divergences of the old shekyl-oxide encoder are gone with it.

use shekyl_crypto_pq::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65;
use shekyl_oxide::fcmp::bulletproofs::Bulletproof;
use shekyl_wire::{
    BpPlus, Ct, CtBase, Input, Output, PqcAuth as WirePqcAuth, Prunable, Transaction, TxPrefix,
};

use crate::error::TxBuilderError;
use crate::types::PqcAuth;

/// Material for final on-wire transaction encoding (Phase 2a §4).
#[derive(Clone, Debug)]
pub struct WireEncodeInput {
    pub key_images: Vec<[u8; 32]>,
    pub output_keys: Vec<[u8; 32]>,
    pub view_tags: Vec<Option<u8>>,
    pub tx_extra: Vec<u8>,
    pub fee: u64,
    pub enc_amounts: Vec<[u8; 9]>,
    pub enc_labels: Vec<[u8; 9]>,
    pub out_commitments: Vec<[u8; 32]>,
    pub pseudo_outs: Vec<[u8; 32]>,
    pub bulletproof: Bulletproof,
    pub reference_block: [u8; 32],
    pub fcmp_proof: Vec<u8>,
    pub pqc_auths: Vec<PqcAuth>,
    /// Curve-tree depth the FCMP++ proof was built against — the prunable's
    /// `tree_depth` (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.4). The old shekyl-oxide encoder
    /// omitted it (it put `reference_block` in the prunable instead — divergence §3.2/§3.3).
    pub tree_depth: u8,
}

/// Map key images to `shekyl_wire::Input::ToKey` (FCMP++ inputs: amount 0, no offsets).
fn wire_inputs(key_images: &[[u8; 32]]) -> Vec<Input> {
    key_images
        .iter()
        .map(|ki| Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: *ki,
        })
        .collect()
}

/// Map output keys + view tags to `shekyl_wire::Output`. Genesis outputs always carry a
/// view_tag (FA-6); the optional form is a pre-genesis inheritance that must not reach
/// the wire, so a `None` is a hard error.
fn wire_outputs(
    output_keys: &[[u8; 32]],
    view_tags: &[Option<u8>],
) -> Result<Vec<Output>, TxBuilderError> {
    // `zip` would silently truncate to the shorter slice — emitting fewer outputs (or
    // dropping tags) and building an invalid tx unnoticed. Couple the lengths explicitly.
    if output_keys.len() != view_tags.len() {
        return Err(TxBuilderError::WireError(format!(
            "output_keys ({}) / view_tags ({}) length mismatch",
            output_keys.len(),
            view_tags.len()
        )));
    }
    output_keys
        .iter()
        .zip(view_tags.iter())
        .map(|(key, view_tag)| {
            let view_tag = view_tag.ok_or_else(|| {
                TxBuilderError::WireError("output missing view_tag (genesis requires it)".into())
            })?;
            Ok(Output {
                amount: 0,
                key: *key,
                view_tag,
            })
        })
        .collect()
}

/// Map the builder's spend material onto a canonical `shekyl_wire::Transaction`.
///
/// This replaces the old shekyl-oxide assembly and fixes its four §3 divergences vs the
/// C++ daemon: the version is part of the prefix hash, `reference_block` is a 32-byte
/// hash in the *base*, the prunable is `nbp ‖ bp+ ‖ tree_depth ‖ proof ‖ pseudoOuts`, and
/// the pqc_header uses a varint public-key length.
fn build_wire_tx(input: &WireEncodeInput) -> Result<Transaction, TxBuilderError> {
    // Enforce the wire arity couplings up front: the committed-base arrays are per-output
    // and pqc_auths / pseudo_outs are per-input (the invariants `Transaction::validate`
    // assumes). A mismatch would otherwise serialize a tx only the daemon (or
    // `from_bytes`) rejects — far from the cause. (Not full `validate()`: that adds the
    // ≥2-output rule, which would false-reject the minimal fixtures and the unproven
    // daemon path.)
    let n_in = input.key_images.len();
    let n_out = input.output_keys.len();
    for (label, got) in [
        ("enc_amounts", input.enc_amounts.len()),
        ("enc_labels", input.enc_labels.len()),
        ("out_commitments", input.out_commitments.len()),
    ] {
        if got != n_out {
            return Err(TxBuilderError::WireError(format!(
                "{label} count {got} != output count {n_out}"
            )));
        }
    }
    for (label, got) in [
        ("pqc_auths", input.pqc_auths.len()),
        ("pseudo_outs", input.pseudo_outs.len()),
    ] {
        if got != n_in {
            return Err(TxBuilderError::WireError(format!(
                "{label} count {got} != input count {n_in}"
            )));
        }
    }

    // Bp+: oxide `Bulletproof::write` and wire `BpPlus` share the exact byte layout
    // (`a‖a1‖b‖r1‖s1‖d1‖vec(L)‖vec(R)`), so round-trip through the bytes. Pinned by
    // `bulletproof_oxide_layout_parses_as_wire_bpplus`.
    let mut bp_bytes = Vec::new();
    input
        .bulletproof
        .write(&mut bp_bytes)
        .map_err(|e| TxBuilderError::WireError(format!("bulletproof write: {e}")))?;
    let bp_plus = BpPlus::from_bytes(&bp_bytes)
        .map_err(|e| TxBuilderError::WireError(format!("bulletproof -> BpPlus: {e}")))?;

    let pqc_auths = input
        .pqc_auths
        .iter()
        .map(|a| WirePqcAuth {
            auth_version: a.auth_version,
            scheme_id: HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
            flags: 0,
            hybrid_public_key: a.public_key.clone(),
            hybrid_signature: a.signature.clone(),
        })
        .collect();

    Ok(Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: wire_inputs(&input.key_images),
            outputs: wire_outputs(&input.output_keys, &input.view_tags)?,
            extra: input.tx_extra.clone(),
        },
        ct: Ct::Fcmp {
            fee: input.fee,
            reference_block: input.reference_block,
            base: CtBase {
                enc_amounts: input.enc_amounts.clone(),
                enc_labels: input.enc_labels.clone(),
                commitments: input.out_commitments.clone(),
            },
            pqc_auths,
            prunable: Some(Prunable {
                bulletproofs: vec![bp_plus],
                tree_depth: u64::from(input.tree_depth),
                fcmp_proof: input.fcmp_proof.clone(),
                pseudo_outs: input.pseudo_outs.clone(),
            }),
        },
    })
}

/// A prefix-only `Transaction` (placeholder `Null` ct) for the prefix-hash path —
/// [`Transaction::prefix_hash`] reads only the prefix, so the ct is irrelevant.
fn prefix_only_tx(
    key_images: &[[u8; 32]],
    output_keys: &[[u8; 32]],
    view_tags: &[Option<u8>],
    tx_extra: &[u8],
) -> Result<Transaction, TxBuilderError> {
    Ok(Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: wire_inputs(key_images),
            outputs: wire_outputs(output_keys, view_tags)?,
            extra: tx_extra.to_vec(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: Vec::new(),
            enc_labels: Vec::new(),
            commitments: Vec::new(),
        }),
    })
}

/// Per-input PQC signing-preimage hashes — delegates to the canonical
/// [`shekyl_wire::Transaction::pqc_signing_payload_hashes`]
/// (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1; C++ `get_transaction_signed_payload`).
pub fn phase1_payload_hashes(input: &WireEncodeInput) -> Result<Vec<[u8; 32]>, TxBuilderError> {
    Ok(build_wire_tx(input)?.pqc_signing_payload_hashes())
}

/// Assemble and serialize the final signed transaction via the canonical
/// [`shekyl_wire::Transaction`].
pub fn encode_final_tx(input: &WireEncodeInput) -> Result<Vec<u8>, TxBuilderError> {
    Ok(build_wire_tx(input)?.serialize())
}

/// The FCMP++ `signable_tx_hash` — the canonical prefix hash (§1.2), via shekyl-wire.
///
/// Panics only on a genesis-invalid input (an output without a view_tag), which the
/// signing path never produces; this keeps the `[u8; 32]` contract its callers rely on.
pub fn tx_prefix_hash_for_signing(input: &WireEncodeInput) -> [u8; 32] {
    // `prefix_hash` depends only on the prefix, so build a prefix-only tx — skips the
    // ct/Bp+ assembly and its unrelated failure modes (e.g. BpPlus parsing).
    prefix_only_tx(
        &input.key_images,
        &input.output_keys,
        &input.view_tags,
        &input.tx_extra,
    )
    .expect("prefix tx builds for a well-formed spend")
    .prefix_hash()
}

/// Prefix hash from prefix fields only (no proofs) — the canonical `prefix_hash` (the ct
/// section is irrelevant to it). Same panic contract as [`tx_prefix_hash_for_signing`].
pub fn tx_prefix_hash_from_parts(
    key_images: &[[u8; 32]],
    output_keys: &[[u8; 32]],
    view_tags: &[Option<u8>],
    tx_extra: &[u8],
) -> [u8; 32] {
    prefix_only_tx(key_images, output_keys, view_tags, tx_extra)
        .expect("prefix tx builds for well-formed parts")
        .prefix_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_oxide::fcmp::bulletproofs::Bulletproof;

    fn minimal_input() -> WireEncodeInput {
        WireEncodeInput {
            key_images: vec![[1u8; 32]],
            output_keys: vec![[2u8; 32]],
            view_tags: vec![Some(3)],
            tx_extra: vec![1, 2, 3],
            fee: 1_000,
            enc_amounts: vec![[0u8; 9]],
            enc_labels: vec![[0u8; 9]],
            out_commitments: vec![[4u8; 32]],
            pseudo_outs: vec![[5u8; 32]],
            bulletproof: Bulletproof::prove_plus(
                &mut rand_core::OsRng,
                vec![shekyl_primitives::Commitment::new(
                    curve25519_dalek::scalar::Scalar::from(1u64),
                    100,
                )],
            )
            .expect("bp prove"),
            reference_block: [0xAB; 32],
            fcmp_proof: vec![0xCC; 64],
            pqc_auths: vec![PqcAuth {
                auth_version: 1,
                signature: vec![0xDD; 128],
                public_key: vec![0xEE; 64],
            }],
            tree_depth: 1,
        }
    }

    #[test]
    fn encode_final_tx_is_deterministic() {
        let input = minimal_input();
        let a = encode_final_tx(&input).expect("encode");
        let b = encode_final_tx(&input).expect("encode");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn phase1_payload_hashes_len_matches_inputs() {
        let input = minimal_input();
        let hashes = phase1_payload_hashes(&input).expect("hashes");
        assert_eq!(hashes.len(), input.key_images.len());
    }

    #[test]
    fn cn_fast_hash_equals_oxide_keccak256() {
        // The migration replaces the tx-builder's `shekyl_oxide::keccak256` with
        // shekyl-wire's `cn_fast_hash`. Pin that they are the same primitive (original
        // Keccak-256) so the signing-hash bytes are preserved.
        use shekyl_oxide::primitives::keccak256;
        for input in [
            &b""[..],
            b"Shekyl",
            &[0u8; 200][..],
            &vec![0xABu8; 5000][..],
        ] {
            assert_eq!(
                shekyl_crypto_hash::cn_fast_hash(input),
                keccak256(input),
                "cn_fast_hash must equal shekyl-oxide keccak256"
            );
        }
    }

    #[test]
    fn bulletproof_oxide_layout_parses_as_wire_bpplus() {
        // The Bp+ conversion relies on the oxide `Bulletproof::write` bytes being a
        // canonical wire `BpPlus`. `from_bytes` requires exact consumption, so a
        // successful parse of a *real* proof's bytes proves the layouts are identical.
        let mut bytes = Vec::new();
        minimal_input()
            .bulletproof
            .write(&mut bytes)
            .expect("oxide bp write");
        BpPlus::from_bytes(&bytes).expect("oxide bp+ bytes must parse as a wire BpPlus");
    }

    #[test]
    fn encode_round_trips_and_signing_hashes_match_the_encoded_tx() {
        // End-to-end self-consistency: the encoded bytes re-parse as a shekyl-wire tx,
        // and the delegated signing hashes equal the re-parsed tx's own hashes — so the
        // bytes the daemon would verify are exactly the bytes the signatures cover.
        let input = minimal_input();
        let bytes = encode_final_tx(&input).expect("encode");
        let tx = Transaction::from_bytes(&bytes).expect("encoded tx must re-parse");

        assert_eq!(
            phase1_payload_hashes(&input).expect("hashes"),
            tx.pqc_signing_payload_hashes(),
            "delegated phase-1 hashes must match the encoded tx's signing hashes"
        );
        assert_eq!(
            tx_prefix_hash_for_signing(&input),
            tx.prefix_hash(),
            "delegated prefix hash must match the encoded tx's prefix hash"
        );
    }

    #[test]
    fn missing_view_tag_is_rejected() {
        let mut input = minimal_input();
        input.view_tags = vec![None];
        assert!(matches!(
            encode_final_tx(&input),
            Err(TxBuilderError::WireError(_))
        ));
    }

    #[test]
    fn base_arity_mismatch_is_rejected() {
        // A per-output base array out of step with the output count must fail at the
        // boundary, not serialize a tx the daemon later rejects.
        let mut input = minimal_input();
        input.enc_amounts.push([0u8; 9]); // 2 enc_amounts vs 1 output
        assert!(matches!(
            encode_final_tx(&input),
            Err(TxBuilderError::WireError(_))
        ));
    }

    #[test]
    fn pqc_auth_arity_mismatch_is_rejected() {
        let mut input = minimal_input();
        input.pseudo_outs.push([0u8; 32]); // 2 pseudo_outs vs 1 input
        assert!(matches!(
            encode_final_tx(&input),
            Err(TxBuilderError::WireError(_))
        ));
    }

    #[test]
    fn output_view_tag_length_mismatch_is_rejected() {
        let mut input = minimal_input();
        input.view_tags.push(Some(5)); // 2 view_tags vs 1 output key
        assert!(matches!(
            encode_final_tx(&input),
            Err(TxBuilderError::WireError(_))
        ));
    }

    #[test]
    fn shekyl_oxide_wire_types_are_removed() {
        // The wire/proof-type imports moved to shekyl-wire; only shekyl-oxide CRYPTO
        // (`bulletproofs::Bulletproof`, and `primitives::keccak256` in a test) remains.
        // wire.rs is checked on its PRODUCTION half only (split off the test module), so
        // these very assertion strings don't self-match.
        let wire_prod = include_str!("wire.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("wire.rs has a production section");
        for (name, src) in [
            ("wire.rs", wire_prod),
            ("lib.rs", include_str!("lib.rs")),
            ("sign.rs", include_str!("sign.rs")),
            ("types.rs", include_str!("types.rs")),
        ] {
            assert!(
                !src.contains("shekyl_oxide::transaction"),
                "{name} must not reference shekyl_oxide::transaction"
            );
            assert!(
                !src.contains("shekyl_oxide::fcmp::{"),
                "{name} must not import shekyl_oxide::fcmp wire types"
            );
        }
    }
}
