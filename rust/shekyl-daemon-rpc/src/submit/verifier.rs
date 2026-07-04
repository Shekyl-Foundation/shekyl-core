// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production [`TxVerifier`] — the Phase-C cryptographic battery over
//! the native Rust consensus crates
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.1 Phase C; §8 rows O6, N8,
//! K12, K13).
//!
//! Every check here is the same Rust code the C++ oracle itself dispatches
//! to (`shekyl_verify_ct_balance`, `shekyl_fcmp_verify`, `shekyl_pqc_verify`
//! in `shekyl-ffi`) or a pinned thin-port of a C++-native check
//! (`check_commitment_mask_valid`; the Bp+ layout statics of
//! `n_bulletproof_plus_amounts`). Calling the crates natively removes the
//! FFI hop without changing the consensus arithmetic — the oracle and the
//! engine literally share the verifying functions.
//!
//! Check order mirrors the C++ submit path where it is observable in logs
//! (never in the verdict — every failure here is one of the three
//! [`VerifyFailure`] arms): `ver_non_input_consensus`'s battery first
//! (O6 mask non-triviality, N8 CT balance + Bp+ range proof), then
//! `check_tx_inputs`'s (K12 FCMP++ membership, K13 PQC hybrid auth).
//!
//! ## Reachability honesty (SP-T4a / the bond-post wire contradiction)
//!
//! Only [`SubmitTxKind::Spend`] can reach this verifier today:
//!
//! - **Serve-credit-only** carries `fee == 0` by consensus (Phase A pins
//!   it), and the engine's Phase-C fee floor rejects zero fee before the
//!   crypto battery runs — the SP-T4a contradiction, reproduced for parity
//!   (`docs/FOLLOWUPS.md`). Reopening criterion (rule 21): the SP-T4a
//!   fee-floor resolution lands; re-evaluation shape: extend
//!   [`SubmitFacts`] with the §8.7.1 SC-row archival facts and implement
//!   the serve-credit battery (SC1–SC8) in this match arm.
//! - **Bond-post** cannot clear Phase A: the C++ wire layer pins
//!   `pseudoOuts == vin.size()` while bond-post consensus demands
//!   `== funding count` — contradictory for every funded bond-post, so
//!   both C++ and the engine reject the shape before verification
//!   (`phase_a.rs`). Reopening criterion: the §13 (F1/F3) wire reshape;
//!   re-evaluation shape: extend [`SubmitFacts`] with the §8.7.1 BP-row
//!   facts and implement the bond-post battery (BP1–BP5 + the funding-arm
//!   K battery) in this match arm.
//!
//! Until a criterion fires, the non-Spend arms refuse loudly-but-safely
//! (`Malformed`, the §7.6 non-panicking posture) rather than carrying an
//! untested, unreachable battery.

use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
use rand_core::OsRng;

use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::multisig::verify_multisig;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_ct_balance::verify_ct_balance;
use shekyl_curve_io::CompressedPoint;
use shekyl_fcmp::proof::{self, KeyImage, ShekylFcmpProof, VerifyError};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{
    BpPlus, Ct, PqcAuth, Prunable, PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
};
use shekyl_wire::varint::write_varint;

use crate::submit::facts::SubmitFacts;
use crate::submit::phase_a::{ParsedSubmission, SubmitTxKind};
use crate::submit::verify::{TxVerifier, VerifyFailure};

/// PQC scheme ids (`tx_pqc_verify.cpp:47-48`): single hybrid signer /
/// M-of-N multisig container. The closed set — anything else is
/// `Malformed`, exactly as the C++ battery rejects it.
const PQC_SCHEME_SINGLE: u8 = 1;
const PQC_SCHEME_MULTISIG: u8 = 2;

/// Multisig key-blob header (`n_total ‖ m_required`,
/// `tx_pqc_verify.cpp:50`).
const MULTISIG_KEY_HEADER_LEN: usize = 2;

/// Compressed identity — `rct::identity()` byte-for-byte; the O6
/// comparison is over compressed encodings, exactly as the C++
/// `operator==(rct::key)` compares.
const IDENTITY_COMPRESSED: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes
};

/// The production Phase-C verifier over the native consensus crates.
///
/// Stateless: every input comes from the [`ParsedSubmission`] (bytes) and
/// the [`SubmitFacts`] snapshot (root, tree depth), so one instance serves
/// every submission concurrently under the engine's Phase-C gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct DaemonTxVerifier;

impl TxVerifier for DaemonTxVerifier {
    fn verify(&self, parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
        match parsed.kind {
            SubmitTxKind::Spend => verify_spend(parsed, facts),
            // Unreachable today — see the module docs' reachability
            // section for the two named reopening criteria (rule 21).
            SubmitTxKind::BondPost | SubmitTxKind::ServeCreditOnly => {
                tracing::error!(
                    kind = ?parsed.kind,
                    "TxVerifier reached by a kind the engine's earlier phases \
                     reject today (SP-T4a / bond-post wire contradiction); \
                     refusing (no battery is implemented for this arm)"
                );
                Err(VerifyFailure::Malformed)
            }
        }
    }
}

/// The regular FCMP++ spend battery: O6 → CT balance → Bp+ → FCMP++ → PQC.
fn verify_spend(parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
    // Phase A guarantees a spend is `Ct::Fcmp` with a prunable proof;
    // stay non-panicking per the §7.6 posture.
    let Ct::Fcmp {
        fee,
        base,
        pqc_auths,
        prunable: Some(prunable),
        ..
    } = &parsed.tx.ct
    else {
        return Err(VerifyFailure::Malformed);
    };

    // ── O6: commitment mask non-triviality ──────────────────────────────
    // Thin-port of `check_commitment_mask_valid` (blockchain.cpp:3242-3279),
    // non-coinbase legs: reject `C == identity` (mask 0, amount 0) and
    // `C == G` (mask 1, amount 0). Byte-compare over the compressed
    // encoding, as the C++ compares `rct::key`s. The coinbase zeroCommit
    // leg does not apply — Phase A rejects coinbase submissions.
    for commitment in &base.commitments {
        if *commitment == IDENTITY_COMPRESSED
            || *commitment == ED25519_BASEPOINT_COMPRESSED.to_bytes()
        {
            return Err(VerifyFailure::Malformed);
        }
    }

    // ── N8 leg 1: CT cleartext balance ──────────────────────────────────
    // `sum(pseudoOuts) == sum(outPk) + fee·H` via the single-sourced
    // equation (`shekyl-ct-balance`) — the same crate the C++
    // `verRctSemanticsSimple` dispatches to through
    // `shekyl_verify_ct_balance` (rctSigs.cpp:226-241). The arity
    // pre-checks around it (`outPk == enc_amounts == enc_labels`,
    // `pseudoOuts == vin`, base pseudoOuts empty) are structural in
    // `shekyl-wire`'s reader/validator and cannot fail here.
    // `as_flattened()` views `Vec<[u8; 32]>` as `&[u8]` with no per-submission
    // reallocation (the CT crate takes a flat byte slice).
    if verify_ct_balance(
        prunable.pseudo_outs.as_flattened(),
        base.commitments.as_flattened(),
        AtomicUnits::from_raw(*fee),
        &[],
        &[],
    )
    .is_err()
    {
        return Err(VerifyFailure::Malformed);
    }

    // ── N8 leg 2: Bp+ aggregate range proof ─────────────────────────────
    // `nbp == 1` is `validate()`'s §10 rule; the [0] index is therefore
    // total, but stay non-panicking. The commitments are the outPk masks
    // exactly as transmitted: the statement multiplies by `INV_EIGHT` for
    // the transcript and clears the cofactor for evaluation — matching the
    // C++ path, which reconstructs `V = outPk·(1/8)` at deserialization
    // (cryptonote_format_utils.cpp:176) and evaluates `8·V`
    // (bulletproofs_plus.cc). L/R round-count statics
    // (`n_bulletproof_plus_amounts`) are enforced structurally by the WIP
    // verifier's round check; unreduced-scalar rejection (`is_reduced`)
    // by `read_scalar` in the conversion below.
    let [bp_wire] = prunable.bulletproofs.as_slice() else {
        return Err(VerifyFailure::Malformed);
    };
    let Some(bp) = bulletproof_from_wire(bp_wire) else {
        return Err(VerifyFailure::Malformed);
    };
    let bp_commitments: Vec<CompressedPoint> = base
        .commitments
        .iter()
        .map(|c| CompressedPoint::from(*c))
        .collect();
    if !bp.verify(&mut OsRng, &bp_commitments) {
        return Err(VerifyFailure::Malformed);
    }

    // ── K12: FCMP++ membership + SAL ────────────────────────────────────
    // Native call to the exact consensus function the C++ oracle reaches
    // through `shekyl_fcmp_verify` (blockchain.cpp:3835-3850). The engine
    // has already bounded `tree_depth ∈ [1, current]` (row K10); the +1
    // conversion to the library's layer count matches the C++ caller's
    // `fcmp_layers = curve_trees_tree_depth + 1`.
    let reference = facts.reference.ok_or(VerifyFailure::StaleRoot)?;
    let layers = u8::try_from(prunable.tree_depth)
        .ok()
        .and_then(|depth| depth.checked_add(1))
        .ok_or(VerifyFailure::StaleRoot)?;
    verify_fcmp(parsed, prunable, pqc_auths, &reference.root, layers)?;

    // ── K13: PQC hybrid auth + scheme-id consistency ────────────────────
    verify_pqc_auths(parsed, pqc_auths)
}

/// Reassemble a [`Bulletproof`] from the wire [`BpPlus`].
///
/// The two layouts are byte-identical
/// (`A‖A1‖B‖r1‖s1‖d1‖vec(L)‖vec(R)`; the round-trip is pinned by
/// shekyl-tx-builder's mapping test), so the conversion is
/// serialize-then-`read_plus`. `read_plus` enforces reduced scalars —
/// the C++ `is_reduced(r1/s1/d1)` parity — and caps L/R at the maximal
/// round count, so a `None` here is the C++ battery's reject, not a
/// marshalling loss.
fn bulletproof_from_wire(bp: &BpPlus) -> Option<Bulletproof> {
    let mut bytes = Vec::with_capacity((6 + bp.l.len() + bp.r.len()) * 32 + 4);
    bytes.extend_from_slice(&bp.a);
    bytes.extend_from_slice(&bp.a1);
    bytes.extend_from_slice(&bp.b);
    bytes.extend_from_slice(&bp.r1);
    bytes.extend_from_slice(&bp.s1);
    bytes.extend_from_slice(&bp.d1);
    write_varint(bp.l.len(), &mut bytes).ok()?;
    for point in &bp.l {
        bytes.extend_from_slice(point);
    }
    write_varint(bp.r.len(), &mut bytes).ok()?;
    for point in &bp.r {
        bytes.extend_from_slice(point);
    }
    Bulletproof::read_plus(&mut bytes.as_slice()).ok()
}

/// K12 proper: marshal the parsed spend into [`proof::verify`]'s inputs
/// and map its error surface onto the [`VerifyFailure`] arms.
fn verify_fcmp(
    parsed: &ParsedSubmission,
    prunable: &Prunable,
    pqc_auths: &[PqcAuth],
    tree_root: &[u8; 32],
    layers: u8,
) -> Result<(), VerifyFailure> {
    // One leaf hash per input, submission order — the same
    // `H_blake2b(dst ‖ hybrid_public_key)` Selene scalar the C++ caller
    // computes per input via `shekyl_fcmp_pqc_leaf_hash`
    // (blockchain.cpp:3810-3820). `pqc_auths.len() == vin.len()` is
    // `validate()`'s arity rule, so the zip below is total for a spend.
    let key_images: Vec<KeyImage> = parsed
        .key_images
        .iter()
        .map(|ki| KeyImage::from_canonical_bytes(*ki))
        .collect();
    let pqc_hashes: Vec<PqcLeafScalar> = pqc_auths
        .iter()
        .map(|auth| PqcLeafScalar::from_pqc_public_key(&auth.hybrid_public_key))
        .collect();
    if pqc_hashes.len() != key_images.len() {
        return Err(VerifyFailure::Malformed);
    }
    let Ok(num_inputs) = u32::try_from(key_images.len()) else {
        return Err(VerifyFailure::Malformed);
    };

    let fcmp_proof = ShekylFcmpProof {
        data: prunable.fcmp_proof.clone(),
        num_inputs,
        tree_depth: layers,
    };

    // The signable hash is the canonical prefix hash — the C++ caller's
    // `get_transaction_prefix_hash(tx)` (blockchain.cpp:3372, threaded to
    // the verify at :3849).
    match proof::verify(
        &fcmp_proof,
        &key_images,
        &prunable.pseudo_outs,
        &pqc_hashes,
        tree_root,
        layers,
        parsed.tx.prefix_hash(),
    ) {
        Ok(true) => Ok(()),
        // `verify` never returns `Ok(false)` today (failures are `Err`);
        // treat it as the deterministic-reject arm if it ever does.
        Ok(false) => Err(VerifyFailure::Malformed),
        // Snapshot-tree inconsistencies a rebuild against a fresh root
        // fixes (the VerifyFailure::StaleRoot contract): the depth cap and
        // a root the tree codec cannot deserialize at the claimed layer
        // count. Everything else — proof bytes, counts, batch failure —
        // is deterministic for these bytes against this root.
        Err(VerifyError::TreeDepthTooLarge(_) | VerifyError::InvalidTreeRoot) => {
            Err(VerifyFailure::StaleRoot)
        }
        Err(_) => Err(VerifyFailure::Malformed),
    }
}

/// K13 proper: the `verify_transaction_pqc_auth` battery
/// (`tx_pqc_verify.cpp:154-248`), natively.
///
/// Per auth: version pin, zero flags, known scheme id, the FCMP++
/// scheme-id **consistency** rule (all inputs agree with input 0 —
/// PQC_MULTISIG.md §16.3 defense-in-depth; the C++ derives
/// `expected_scheme_id` from `pqc_auths[0]`), per-scheme key-blob length
/// bounds, then the hybrid Ed25519+ML-DSA (or M-of-N multisig container)
/// verification over the per-input signing-preimage hash — computed by
/// `shekyl-wire`'s [`pqc_signing_payload_hashes`], the pinned Rust twin of
/// C++ `get_transaction_signed_payload`.
///
/// [`pqc_signing_payload_hashes`]: shekyl_wire::transaction::Transaction::pqc_signing_payload_hashes
fn verify_pqc_auths(parsed: &ParsedSubmission, pqc_auths: &[PqcAuth]) -> Result<(), VerifyFailure> {
    // Arity (`:159-163`): one auth per input, non-empty. Structural for a
    // validate()d spend; kept as a loud refusal, not an assumption.
    if pqc_auths.is_empty() || pqc_auths.len() != parsed.tx.prefix.inputs.len() {
        return Err(VerifyFailure::Malformed);
    }
    let payload_hashes = parsed.tx.pqc_signing_payload_hashes();
    if payload_hashes.len() != pqc_auths.len() {
        return Err(VerifyFailure::Malformed);
    }
    let expected_scheme = pqc_auths[0].scheme_id;

    for (auth, payload_hash) in pqc_auths.iter().zip(&payload_hashes) {
        if auth.auth_version != 1 || auth.flags != 0 {
            return Err(VerifyFailure::Malformed);
        }
        if auth.scheme_id != PQC_SCHEME_SINGLE && auth.scheme_id != PQC_SCHEME_MULTISIG {
            return Err(VerifyFailure::Malformed);
        }
        if auth.scheme_id != expected_scheme {
            return Err(VerifyFailure::Malformed);
        }
        if auth.hybrid_public_key.is_empty() {
            return Err(VerifyFailure::Malformed);
        }
        match auth.scheme_id {
            PQC_SCHEME_SINGLE => {
                if auth.hybrid_public_key.len() != PQC_HYBRID_SINGLE_KEY_LEN {
                    return Err(VerifyFailure::Malformed);
                }
                let Ok(public_key) = HybridPublicKey::from_canonical_bytes(&auth.hybrid_public_key)
                else {
                    return Err(VerifyFailure::Malformed);
                };
                let Ok(signature) = HybridSignature::from_canonical_bytes(&auth.hybrid_signature)
                else {
                    return Err(VerifyFailure::Malformed);
                };
                if !matches!(
                    HybridEd25519MlDsa.verify(&public_key, payload_hash, &signature),
                    Ok(true)
                ) {
                    return Err(VerifyFailure::Malformed);
                }
            }
            PQC_SCHEME_MULTISIG => {
                if auth.hybrid_public_key.len() < MULTISIG_KEY_HEADER_LEN
                    || auth.hybrid_public_key.len() > PQC_MAX_PUBLIC_KEY_BLOB
                {
                    return Err(VerifyFailure::Malformed);
                }
                // Group-id binding is not on this path (the C++ battery
                // calls `shekyl_pqc_verify`, the no-group-id entry point).
                if !matches!(
                    verify_multisig(
                        auth.scheme_id,
                        &auth.hybrid_public_key,
                        &auth.hybrid_signature,
                        payload_hash,
                        None,
                    ),
                    Ok(true)
                ) {
                    return Err(VerifyFailure::Malformed);
                }
            }
            // Excluded by the closed-set check above.
            _ => return Err(VerifyFailure::Malformed),
        }
    }
    Ok(())
}
