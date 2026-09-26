//! Core signing logic for FCMP++ transactions.
//!
//! The signing pipeline has two phases:
//!
//! 1. [`sign_transaction`] — Generates Bulletproof+ range proofs, FCMP++
//!    membership proofs, ECDH-encoded amounts, and pseudo-output commitments.
//!    Returns [`SignedProofs`] with an empty `pqc_auths` vector.
//!
//! 2. [`sign_pqc_auths`] — Given per-input PQC payload hashes (computed by the
//!    caller after inserting proofs into the transaction), produces hybrid
//!    Ed25519 + ML-DSA-65 signatures.
//!
//! This two-phase design avoids a circular dependency: the PQC payload hash
//! includes the serialized proofs, so the proofs must exist before signing.

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use zeroize::Zeroizing;

use shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf;
use shekyl_crypto_pq::output::EncryptedOutputField;
use shekyl_ct_balance::{verify_ct_balance, InputTerm, OutputTerm};
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::proof::{self, BranchLayer, ProveInput};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_types::{PrefixHash, SigningPayloadHash};

use crate::error::TxBuilderError;
use crate::types::{OutputInfo, PqcAuth, SignedProofs, SpendInput, TreeContext};
use crate::validate::validate_inputs;

/// Construct the proof portion of an FCMP++ transaction.
///
/// Generates Bulletproof+ range proofs over output commitments, FCMP++
/// full-chain membership proofs for all inputs, ECDH-encoded amounts,
/// and pseudo-output commitments. The returned [`SignedProofs`] has an
/// empty `pqc_auths` — call [`sign_pqc_auths`] after inserting the proofs
/// into the transaction and computing per-input PQC payload hashes.
///
/// # Errors
///
/// Returns [`TxBuilderError`] with a descriptive variant if any validation
/// check fails or a cryptographic operation errors.
///
/// # Panics
///
/// Never — all errors are returned via `Result`.
///
/// # Security
///
/// - All intermediate secret material (masks, blindings) is wrapped in
///   [`Zeroizing`] and wiped on drop.
/// - Randomness comes from [`OsRng`] (OS-provided CSPRNG).
/// - [`TreeContext::tree_root`] is a [`shekyl_types::CurveTreeRoot`] (the
///   header field). The proof crate takes those bytes at this call; a
///   [`shekyl_types::BlockHash`] cannot be passed in its place.
pub fn sign_transaction(
    tx_prefix_hash: PrefixHash,
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: shekyl_units::AtomicUnits,
    tree: &TreeContext,
) -> Result<SignedProofs, TxBuilderError> {
    // The common transfer path carries no extra cleartext balance terms.
    sign_transaction_with_terms(tx_prefix_hash, inputs, outputs, fee, &[], &[], tree)
}

/// Construct the proof portion of an FCMP++ transaction that carries extra
/// cleartext balance terms (e.g. an archival bond's `bond_credit`).
///
/// Identical to [`sign_transaction`] except for the single-sourced
/// [`InputTerm`] / [`OutputTerm`] slices, which are cleartext `amount * H`
/// contributions on the input / output side of the balance — the same terms the
/// verify side checks (`shekyl-ct-balance`). Because each rides with implicit
/// mask 0 (like `fee`), they affect only the funds-sufficiency validation, not
/// the pseudo-output mask balancing or the Bulletproof+ range proofs (which
/// cover only the real output commitments). The caller is responsible for
/// making the amount balance *exact* (typically via a change output) so the
/// consensus equality
/// `sum(pseudoOuts) + extra_inputs = sum(out_masks) + fee + extra_outputs`
/// holds; this builder enforces only sufficiency.
///
/// This crate stays bond-agnostic: it never names "bond", it consumes generic
/// typed-side terms (`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §7.2).
pub fn sign_transaction_with_terms(
    tx_prefix_hash: PrefixHash,
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: shekyl_units::AtomicUnits,
    extra_inputs: &[InputTerm],
    extra_outputs: &[OutputTerm],
    tree: &TreeContext,
) -> Result<SignedProofs, TxBuilderError> {
    // ── 1. Validate ──────────────────────────────────────────────────
    validate_inputs(inputs, outputs, fee, extra_inputs, extra_outputs, tree)?;

    let n_in = inputs.len();
    let n_out = outputs.len();

    // ── 2. Bulletproofs+ range proof ─────────────────────────────────
    // Use HKDF-derived commitment masks from OutputInfo (pre-derived by construct_output).
    let mut masks = Zeroizing::new(Vec::with_capacity(n_out));
    let commitments_for_bp: Vec<Commitment> = outputs
        .iter()
        .map(|out| {
            let mask = Scalar::from_canonical_bytes(out.commitment_mask)
                .expect("commitment_mask is not a valid scalar");
            masks.push(mask);
            Commitment::new(mask, out.amount.to_raw())
        })
        .collect();

    let bp = shekyl_bulletproofs::Bulletproof::prove_plus(&mut OsRng, commitments_for_bp)
        .map_err(|e| TxBuilderError::BulletproofError(e.to_string()))?;

    let mut bp_bytes = Vec::new();
    bp.write(&mut bp_bytes)
        .map_err(|e| TxBuilderError::BulletproofError(format!("serialization: {e}")))?;

    // ── 3. Output commitments (real C = mask*G + amount*H) ───────────
    // `outPk[i].mask` carries the real Pedersen commitment, matching the C++
    // consensus convention `rv.outPk[i].mask = scalarmult8(bp.V[i])` (the BP+
    // V is the C/8 form, so scalarmult8 recovers the real C) and the
    // pseudo-out side `genC(...)` (also real C). The balance check
    // `sum(pseudoOuts) == sum(outPk) + fee*H` (`verCtSemanticsSimple`) sums
    // these points directly, so both sides must be the real ×1 commitment;
    // `pseudo_outs` below are `C_tilde = a*G + amount_in*H` (real ×1), so the
    // output side must not be cofactor-scaled.
    let out_commitments: Vec<[u8; 32]> = outputs
        .iter()
        .zip(masks.iter())
        .map(|(out, mask)| {
            let c = Commitment::new(*mask, out.amount.to_raw());
            c.calculate().compress().to_bytes()
        })
        .collect();

    // ── 4. Pre-computed encrypted amounts (HKDF k_amount XOR + tag) ─
    // Carried as `EncryptedOutputField`, not unwrapped to `[u8; 9]`. This was
    // where the guarantee used to end: everything downstream took raw arrays, so
    // safe in-process Rust could hand the encoder nine chosen bytes without ever
    // constructing the type. The bytes are now taken out only inside the private
    // wire assembly, at the point they become wire.
    let enc_amounts: Vec<EncryptedOutputField> = outputs.iter().map(|out| out.enc_amount).collect();
    let enc_labels: Vec<EncryptedOutputField> = outputs.iter().map(|out| out.enc_label).collect();

    // ── 5. Pseudo-output balancing ───────────────────────────────────
    // Generate random blindings for all-but-last input; the last mask is
    // constrained so that: sum(pseudo_masks) == sum(output_masks) + 0 (fee
    // is committed with mask 0: fee*H).
    let mut pseudo_masks = Zeroizing::new(Vec::with_capacity(n_in));
    let sum_out_masks: Scalar = masks.iter().copied().sum();

    for i in 0..n_in {
        if i < n_in - 1 {
            pseudo_masks.push(Scalar::random(&mut OsRng));
        } else {
            let sum_pseudo: Scalar = pseudo_masks.iter().copied().sum();
            pseudo_masks.push(sum_out_masks - sum_pseudo);
        }
    }

    // ── 6. Build ProveInput for FCMP++ ───────────────────────────────
    let prove_inputs: Vec<ProveInput> = inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| prove_input_from_spend(i, inp, pseudo_masks[i].to_bytes()))
        .collect::<Result<_, _>>()?;

    // ── 7. FCMP++ prove ──────────────────────────────────────────────
    let prove_result = proof::prove(
        &prove_inputs,
        // Proof-crate boundary: both the root and the signable hash are
        // bytes here (RAW_TYPE_NEWTYPE_MIGRATION.md original PR E).
        tree.tree_root.as_bytes(),
        tree.tree_depth,
        tx_prefix_hash.to_bytes(),
    )
    .map_err(|e| TxBuilderError::FcmpProveError(e.to_string()))?;

    // ── 8. Construct-side balance self-verify ────────────────────────
    // Run the *same* commitment-sum balance equation the daemon runs, over the
    // commitments we just built, under the identical single-home code
    // (`shekyl_ct_balance::verify_ct_balance`) with the identical terms construct
    // was handed. `validate_inputs` (step 1) only checks amount-level funds
    // sufficiency in cleartext; it cannot see a masking bug where the amounts are
    // correct but the blinding factors don't balance on the curve. That bug would
    // otherwise surface only as a daemon rejection after sign + broadcast (wasted
    // round-trip, a malformed tx briefly on the wire). Catch it here — locally,
    // fail-fast — realizing the single-home guarantee symmetrically: construct
    // proves its own output balances under the same definitions verify uses.
    // Pure and synchronous (a few point ops), so it is a direct call, not an
    // actor round-trip.
    // `?` maps `CtBalanceError` into `TxBuilderError::BalanceSelfCheck` via its
    // `#[from]`; this is the only `CtBalanceError` source in the function.
    verify_ct_balance(
        prove_result.pseudo_outs.as_flattened(),
        out_commitments.as_flattened(),
        fee,
        extra_inputs,
        extra_outputs,
    )?;

    // ── 9. Assemble SignedProofs ──────────────────────────────────────
    Ok(SignedProofs {
        bulletproof_plus: bp_bytes,
        commitments: out_commitments,
        enc_amounts,
        enc_labels,
        pseudo_outs: prove_result.pseudo_outs,
        fcmp_proof: prove_result.proof.data,
        pqc_auths: Vec::new(),
        reference_block: tree.reference_block,
        tree_depth: tree.tree_depth,
    })
}

/// Produce PQC authentication signatures for each input.
///
/// This is Phase 2 of the signing pipeline. The caller must:
/// 1. Insert the proofs from [`sign_transaction`] into the transaction
/// 2. Compute `get_transaction_signed_payload` for each input
/// 3. Hash each payload with Keccak-256 to get `payload_hashes`
/// 4. Call this function with those hashes and the corresponding secret keys
///
/// # Errors
///
/// Returns [`TxBuilderError::PqcSignError`] if any individual signing
/// operation fails (e.g., malformed secret key).
pub fn sign_pqc_auths(
    payload_hashes: &[SigningPayloadHash],
    inputs: &[SpendInput],
) -> Result<Vec<PqcAuth>, TxBuilderError> {
    use shekyl_crypto_pq::output::sign_pqc_auth_for_output;

    if payload_hashes.len() != inputs.len() {
        return Err(TxBuilderError::PqcSignError {
            index: 0,
            reason: format!(
                "payload_hashes length {} != inputs length {}",
                payload_hashes.len(),
                inputs.len()
            ),
        });
    }

    let mut auths = Vec::with_capacity(inputs.len());

    for (i, (hash, inp)) in payload_hashes.iter().zip(inputs.iter()).enumerate() {
        if inp.combined_ss.len() != 64 {
            return Err(TxBuilderError::PqcSignError {
                index: i,
                reason: format!(
                    "combined_ss length {} != 64 for input {}",
                    inp.combined_ss.len(),
                    i
                ),
            });
        }
        let mut ss = [0u8; 64];
        ss.copy_from_slice(&inp.combined_ss);

        let auth_sig = sign_pqc_auth_for_output(
            &ss,
            inp.output_index,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
            hash.as_bytes(),
        )
        .map_err(|e| TxBuilderError::PqcSignError {
            index: i,
            reason: format!("sign_pqc_auth_for_output failed: {e}"),
        })?;

        auths.push(PqcAuth {
            auth_version: 1,
            signature: auth_sig.signature,
            public_key: auth_sig.hybrid_public_key,
        });
    }

    Ok(auths)
}

/// A membership-only FCMP++ backing proof for a
/// `txin_archival_reward_emission` (`REWARD_EMISSION_LEG.md` §7).
///
/// The prover half's output, shaped for the emission vin's
/// `MembershipOnlyBacking` fields: the proof blob, the single rerandomized
/// pseudo-out `C~`, and the tree depth the proof spans.
#[derive(Debug)]
pub struct MembershipOnlyProof {
    /// Serialized `FcmpMembershipOnly` proof bytes.
    pub proof: Vec<u8>,
    /// The backing's rerandomized commitment `C~` (real ×1 form).
    pub pseudo_out: [u8; 32],
    /// Tree depth the proof spans (copied from the `TreeContext`).
    pub tree_depth: u8,
}

/// Prove a **membership-only** backing for a reward-emission vin.
///
/// The thin boundary over `shekyl_fcmp::proof::prove_membership_only`: this
/// crate is engine-core's single production route into the FCMP++ prover
/// (`shekyl-fcmp` is not a direct production dependency of engine-core), so the
/// membership-only leg enters here alongside [`sign_transaction_with_terms`].
///
/// The `SpendInput → ProveInput` conversion is the same as the full-path
/// signer's step 6, except `pseudo_out_blind` is zero: the membership-only
/// prover derives its pseudo-out from the context-bound rerandomization and
/// never reads a caller-supplied blind (no commitment-blind arithmetic on this
/// path). The rerandomization context is pinned to `tree.tree_root` here —
/// baked in, not a caller parameter — so every emission proof binds to the
/// reference block's root (gate-6 §9.6) and a caller cannot pass an
/// inconsistent context.
///
/// # Errors
///
/// [`TxBuilderError::FcmpProveError`] on any prover failure (invalid
/// points/scalars, missing tree path, upstream prove error).
pub fn prove_backing_membership(
    input: &SpendInput,
    tree: &TreeContext,
    signable_tx_hash: PrefixHash,
) -> Result<MembershipOnlyProof, TxBuilderError> {
    // The blind is not read on the membership-only path: pseudo-out blinds
    // are a full-path (key-image) concern; the membership-only pseudo-out
    // comes from the context-bound rerandomization inside the prover.
    let prove_input = prove_input_from_spend(0, input, [0u8; 32])?;

    let result = proof::prove_membership_only(
        &[prove_input],
        tree.tree_root.as_bytes(),
        tree.tree_depth,
        signable_tx_hash.to_bytes(),
        tree.tree_root.as_bytes(),
    )
    .map_err(|e| TxBuilderError::FcmpProveError(e.to_string()))?;

    // Exactly one pseudo-out for the one input — enforced, not `.first()`:
    // a prover regression that returned extras would otherwise be silently
    // truncated here and surface as an unexplained daemon rejection.
    let [pseudo_out] = result.pseudo_outs.as_slice() else {
        return Err(TxBuilderError::FcmpProveError(format!(
            "membership-only prover returned {} pseudo-outs for one input",
            result.pseudo_outs.len()
        )));
    };

    Ok(MembershipOnlyProof {
        proof: result.proof.data,
        pseudo_out: *pseudo_out,
        tree_depth: tree.tree_depth,
    })
}

/// The `SpendInput → ProveInput` field conversion — one definition for the
/// full-path signer (step 6, per-input balanced blind) and the
/// membership-only backing leg (zero blind), so the leaf-chunk/branch-layer
/// marshaling cannot drift between the two proving paths.
///
/// Re-derives the input's own PQC leaf commitment and blind (`PL-D3`) from
/// `combined_ss` / `output_index` — the derivation that produced the
/// output's `0x07` entry — and refuses with
/// [`TxBuilderError::PqcLeafMismatch`] when the chain's leaf (this output's
/// entry in `leaf_chunk`) is not that derivation: a proof over an unopenable
/// leaf would only fail later, at the verifier, with no diagnosis.
pub(crate) fn prove_input_from_spend(
    index: usize,
    input: &SpendInput,
    pseudo_out_blind: [u8; 32],
) -> Result<ProveInput, TxBuilderError> {
    let combined64: Zeroizing<[u8; 64]> = Zeroizing::new(
        input
            .combined_ss
            .get(..64)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| TxBuilderError::PqcLeafDerivation {
                index,
                detail: format!(
                    "combined_ss must be at least 64 bytes, got {}",
                    input.combined_ss.len()
                ),
            })?,
    );
    let pqc_leaf = derive_pqc_leaf(&combined64, input.output_index).map_err(|e| {
        TxBuilderError::PqcLeafDerivation {
            index,
            detail: e.to_string(),
        }
    })?;
    let derived_x = PqcLeafScalar::from_commitment_point(&pqc_leaf.point).ok_or_else(|| {
        TxBuilderError::PqcLeafDerivation {
            index,
            detail: "derived commitment is not a decompressible point".into(),
        }
    })?;
    // Consensus does not forbid duplicate (O, C) pairs in a chunk; only
    // `CM.x` names the spent leaf. Prefer the matching opening, and only
    // then fall back to "present but unopenable".
    let mut saw_output = false;
    let mut saw_openable = false;
    for e in &input.leaf_chunk {
        if e.output_key == input.output_key && e.commitment == input.commitment {
            saw_output = true;
            if e.cm_x == derived_x.0 {
                saw_openable = true;
                break;
            }
        }
    }
    if !saw_output {
        return Err(TxBuilderError::SpentOutputNotInLeafChunk { index });
    }
    if !saw_openable {
        return Err(TxBuilderError::PqcLeafMismatch { index });
    }

    let leaf_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])> = input
        .leaf_chunk
        .iter()
        .map(|e| (e.output_key, e.key_image_gen, e.commitment))
        .collect();
    let leaf_cm_x: Vec<[u8; 32]> = input.leaf_chunk.iter().map(|e| e.cm_x).collect();

    let c1_branch_layers: Vec<BranchLayer> = input
        .c1_layers
        .iter()
        .map(|siblings| BranchLayer {
            siblings: siblings.clone(),
        })
        .collect();
    let c2_branch_layers: Vec<BranchLayer> = input
        .c2_layers
        .iter()
        .map(|siblings| BranchLayer {
            siblings: siblings.clone(),
        })
        .collect();

    Ok(ProveInput {
        output_key: input.output_key,
        key_image_gen: compute_key_image_gen(&input.output_key),
        commitment: input.commitment,
        pqc_leaf_commitment: pqc_leaf.point,
        pqc_leaf_blind: pqc_leaf.blind,
        spend_key_x: input.spend_key_x,
        spend_key_y: input.spend_key_y,
        commitment_mask: input.commitment_mask,
        pseudo_out_blind,
        leaf_chunk_outputs: leaf_outputs,
        leaf_chunk_cm_x: leaf_cm_x,
        c1_branch_layers,
        c2_branch_layers,
    })
}

/// Compute the key image generator Hp(O) for a given output key O.
///
/// Uses `biased_hash_to_point(O)` which matches the C++ `hash_to_p3(O)`.
/// This is the same deterministic hash-to-curve used in leaf construction.
fn compute_key_image_gen(output_key: &[u8; 32]) -> [u8; 32] {
    shekyl_curve_generators::biased_hash_to_point(*output_key)
        .compress()
        .to_bytes()
}
