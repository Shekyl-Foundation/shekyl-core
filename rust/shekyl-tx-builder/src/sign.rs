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
//! [`crate::open_spend`] is that second phase for a spend that may also carry
//! non-spend prefix inputs: it hashes every auth slot, signs the spend slots,
//! and leaves each extra slot for the caller to seal.
//!
//! This two-phase design avoids a circular dependency: the PQC payload hash
//! includes the serialized proofs, so the proofs must exist before signing.

use std::num::NonZeroUsize;

use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroizing;

use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf;
use shekyl_crypto_pq::output::spend_key_image;
use shekyl_crypto_pq::output::EncryptedOutputField;
use shekyl_ct_balance::{verify_ct_balance, InputTerm, OutputTerm, PseudoOutBlinds};
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::proof::{self, BranchLayer, KeyImage, ProveError, ProveInput, ProveResult};
use shekyl_fcmp::{PqcKeyScalar, PqcLeafScalar};
use shekyl_network::NetworkId;
use shekyl_types::{BlockHash, CurveTreeRoot, PrefixHash, SigningPayloadHash, TxSignableHash};
use shekyl_wire::CtBase;

use crate::error::TxBuilderError;
use crate::types::{
    OutputInfo, PqcAuth, PqcScheme, SignedProofs, SpendInput, TreeContext, PQC_AUTH_VERSION,
};
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
    network_id: &NetworkId,
    tx_prefix_hash: PrefixHash,
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: shekyl_units::AtomicUnits,
    tree: &TreeContext,
) -> Result<SignedProofs, TxBuilderError> {
    // The common transfer path carries no extra cleartext balance terms.
    sign_transaction_with_terms(
        network_id,
        tx_prefix_hash,
        inputs,
        outputs,
        fee,
        &[],
        &[],
        tree,
    )
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
#[allow(
    clippy::too_many_arguments,
    reason = "the signing boundary: each argument is a distinct typed part of the message or the balance"
)]
pub fn sign_transaction_with_terms(
    network_id: &NetworkId,
    tx_prefix_hash: PrefixHash,
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: shekyl_units::AtomicUnits,
    extra_inputs: &[InputTerm],
    extra_outputs: &[OutputTerm],
    tree: &TreeContext,
) -> Result<SignedProofs, TxBuilderError> {
    sign_with(
        &mut OsRng,
        PseudoOutBlinds::random,
        proof::prove,
        &SignRequest {
            network_id,
            tx_prefix_hash,
            inputs,
            outputs,
            fee,
            extra_inputs,
            extra_outputs,
            tree,
        },
    )
}

/// The seeds of one spend's proofs, one per source of randomness
/// (`CHAIN_FORGE.md` §5.2): the Bulletproofs+ range proof (S1), the
/// pseudo-out blinds of every input but the last (S2), and the FCMP++
/// membership proof (S3). Apart, so a chain can draw each from its own
/// stream, and the forge's determinism check can swap one of them for the
/// OS's randomness and leave the other two as they were. Only under the
/// TEST_ONLY `seeded-rng` feature (`CF-R9`).
#[cfg(feature = "seeded-rng")]
pub struct ProofSeeds {
    /// The range proof's stream.
    pub range: Zeroizing<[u8; 32]>,
    /// The pseudo-out blinds' stream.
    pub blinds: Zeroizing<[u8; 32]>,
    /// The membership proof's stream.
    pub membership: Zeroizing<[u8; 32]>,
}

/// [`sign_transaction_with_terms`] with every random value drawn from
/// `seeds`: the range proof from `seeds.range`, the pseudo-out blinds from
/// `seeds.blinds`, the membership proof from `seeds.membership`. The same
/// seeds give the same proofs byte for byte. For the chain forge's
/// reproducible chains (`CHAIN_FORGE.md` §5.3, seam T2); only under the
/// TEST_ONLY `seeded-rng` feature, which no build that ships enables
/// (`CF-R9`).
///
/// # Errors
///
/// As [`sign_transaction_with_terms`].
#[cfg(feature = "seeded-rng")]
#[allow(
    clippy::too_many_arguments,
    reason = "sign_transaction_with_terms's signing boundary, plus the seeds"
)]
pub fn sign_transaction_with_terms_seeded(
    seeds: &ProofSeeds,
    network_id: &NetworkId,
    tx_prefix_hash: PrefixHash,
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: shekyl_units::AtomicUnits,
    extra_inputs: &[InputTerm],
    extra_outputs: &[OutputTerm],
    tree: &TreeContext,
) -> Result<SignedProofs, TxBuilderError> {
    let mut prover_rng = seeded::stream(&seeds.membership);
    sign_with(
        &mut seeded::stream(&seeds.range),
        |inputs, outputs| PseudoOutBlinds::seeded(&seeds.blinds, inputs, outputs),
        |inputs, root, depth, hash| {
            proof::prove_with_rng(&mut prover_rng, inputs, root, depth, hash)
        },
        &SignRequest {
            network_id,
            tx_prefix_hash,
            inputs,
            outputs,
            fee,
            extra_inputs,
            extra_outputs,
            tree,
        },
    )
}

/// The parts of a spend [`sign_transaction_with_terms`] signs, as one value
/// for the signing body its production and seeded entry points share.
struct SignRequest<'a> {
    network_id: &'a NetworkId,
    tx_prefix_hash: PrefixHash,
    inputs: &'a [SpendInput],
    outputs: &'a [OutputInfo],
    fee: shekyl_units::AtomicUnits,
    extra_inputs: &'a [InputTerm],
    extra_outputs: &'a [OutputTerm],
    tree: &'a TreeContext,
}

/// [`sign_transaction_with_terms`]'s body. `range_rng` draws the range
/// proof's randomness; `blinds` makes the pseudo-out blinds for the input
/// count and the outputs' openings, balanced by construction
/// ([`PseudoOutBlinds::random`] in production, the seeded form for the
/// forge); `prove` makes the membership proof (production's
/// [`proof::prove`], over the OS, or the seeded prover). Private: no build
/// that ships has a signer that takes its caller's randomness
/// (`CHAIN_FORGE.md` `CF-R9`).
fn sign_with<R: RngCore + CryptoRng>(
    range_rng: &mut R,
    blinds: impl FnOnce(NonZeroUsize, &[Commitment]) -> PseudoOutBlinds,
    prove: impl FnOnce(
        &[ProveInput],
        &CurveTreeRoot,
        u8,
        TxSignableHash,
    ) -> Result<ProveResult, ProveError>,
    req: &SignRequest<'_>,
) -> Result<SignedProofs, TxBuilderError> {
    let SignRequest {
        network_id,
        tx_prefix_hash,
        inputs,
        outputs,
        fee,
        extra_inputs,
        extra_outputs,
        tree,
    } = *req;
    // ── 1. Validate ──────────────────────────────────────────────────
    let input_count = validate_inputs(inputs, outputs, fee, extra_inputs, extra_outputs, tree)?;

    // ── 2. Bulletproofs+ range proof ─────────────────────────────────
    // Each output's opening is its derived mask at its amount. The mask is
    // already a scalar; nothing here reads its bytes.
    let commitments_for_bp: Vec<Commitment> = outputs
        .iter()
        .map(|out| out.commitment_mask.opening(out.amount.to_raw()))
        .collect();
    // The pseudo-out blinds balance these openings (step 5); the range
    // proof consumes them.
    let pseudo_out_blinds = blinds(input_count, &commitments_for_bp).into_bytes();

    let bp = shekyl_bulletproofs::Bulletproof::prove_plus(&mut *range_rng, commitments_for_bp)
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
    let out_commitments: Vec<[u8; 32]> = outputs.iter().map(output_commitment).collect();

    // ── 4. Pre-computed encrypted amounts (HKDF k_amount XOR + tag) ─
    // Carried as `EncryptedOutputField`, not unwrapped to `[u8; 9]`. This was
    // where the guarantee used to end: everything downstream took raw arrays, so
    // safe in-process Rust could hand the encoder nine chosen bytes without ever
    // constructing the type. The bytes are now taken out only inside the private
    // wire assembly, at the point they become wire.
    let enc_amounts: Vec<EncryptedOutputField> = outputs.iter().map(|out| out.enc_amount).collect();
    let enc_labels: Vec<EncryptedOutputField> = outputs.iter().map(|out| out.enc_label).collect();

    // ── 5. Build ProveInput for FCMP++ ───────────────────────────────
    let prove_inputs: Vec<ProveInput> = inputs
        .iter()
        .zip(&pseudo_out_blinds)
        .enumerate()
        .map(|(i, (inp, blind))| prove_input_from_spend(i, inp, **blind))
        .collect::<Result<_, _>>()?;

    // ── 6. FCMP++ prove ──────────────────────────────────────────────
    // Over `tx_signable`: the prefix and the base just built (the outputs'
    // commitments, encrypted amounts and labels, the fee and the reference
    // block), framed under the network's id (the signing envelope §2.2).
    let tx_signable = signable_of(
        network_id,
        tx_prefix_hash,
        fee,
        &tree.reference_block,
        &out_commitments,
        &enc_amounts,
        &enc_labels,
    );
    let prove_result = prove(&prove_inputs, &tree.tree_root, tree.tree_depth, tx_signable)
        .map_err(|e| TxBuilderError::FcmpProveError(e.to_string()))?;

    // ── 7. Construct-side balance self-verify ────────────────────────
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

    // ── 8. Construct-side membership self-verify ─────────────────────
    // The FCMP++ prover checks almost none of its own work in a release
    // build, and it takes the tree root without reading it: a proof over a
    // path that does not reach `tree.tree_root`, or any prover fault, would
    // otherwise surface only as the daemon's CEN-I15 refusal after the
    // spend is on the wire. Verify it here with the daemon's verifier, over
    // the operands the daemon will use: each input's key image `x·Hp(O)`
    // (what the prefix carries, held to it in `open_spend`), the PQC key
    // scalar from the spend slot's hybrid public key, the root and the layer
    // count the proof was made for, and `tx_signable`.
    let key_images = own_key_images(inputs)?;
    verify_own_membership(&prove_result, &key_images, inputs, tree, tx_signable)?;

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
        tx_signable,
        key_images,
    })
}

/// Each input's key image `I = x·Hp(O)`, in input order: the images the
/// membership proof's linkability binds and the spend's prefix must carry.
fn own_key_images(inputs: &[SpendInput]) -> Result<Vec<KeyImage>, TxBuilderError> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            spend_key_image(
                &input.spend_key_x,
                &compute_key_image_gen(&input.output_key),
            )
            .map_err(|e| {
                TxBuilderError::MembershipSelfCheck(format!("input {index}: key image: {e}"))
            })
        })
        .collect()
}

/// Step 8 of [`sign_with`]: `proved` verifies under
/// [`shekyl_fcmp::proof::verify`], the function CEN-I15 and the submit
/// verifier call, against `key_images`, each spend slot's PQC key scalar
/// (`PqcKeyScalar::from_pqc_auth` over the hybrid public key the slot will
/// carry, as the consensus verifiers derive it), `tree`'s root and layer
/// count, and `tx_signable`.
fn verify_own_membership(
    proved: &ProveResult,
    key_images: &[KeyImage],
    inputs: &[SpendInput],
    tree: &TreeContext,
    tx_signable: TxSignableHash,
) -> Result<(), TxBuilderError> {
    let pqc_keys = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let combined_ss: &[u8; 64] = input.combined_ss[..].try_into().map_err(|_| {
                TxBuilderError::InvalidCombinedSsLength {
                    index,
                    len: input.combined_ss.len(),
                }
            })?;
            let public_key =
                derive_pqc_public_key(combined_ss, input.output_index).map_err(|e| {
                    TxBuilderError::MembershipSelfCheck(format!(
                        "input {index}: PQC public key: {e}"
                    ))
                })?;
            PqcKeyScalar::from_pqc_auth(PqcScheme::Single.id(), &public_key).ok_or_else(|| {
                TxBuilderError::MembershipSelfCheck(format!(
                    "input {index}: the PQC public key is not a well-formed single-signer key"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    match proof::verify(
        &proved.proof,
        key_images,
        &proved.pseudo_outs,
        &pqc_keys,
        &tree.tree_root,
        tree.tree_depth,
        tx_signable,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(TxBuilderError::MembershipSelfCheck(
            "the proof does not verify against the root, key images and message it was made for"
                .into(),
        )),
        Err(e) => Err(TxBuilderError::MembershipSelfCheck(format!(
            "the verifier refused the proof: {e}"
        ))),
    }
}

/// An output's real commitment, `C = mask*G + amount*H` (compressed, no
/// cofactor scaling): the form [`sign_transaction_with_terms`] writes into
/// the base and [`tx_signable_for`] frames.
fn output_commitment(out: &OutputInfo) -> [u8; 32] {
    out.commitment_mask
        .opening(out.amount.to_raw())
        .calculate()
        .compress()
        .to_bytes()
}

/// `tx_signable` from its parts: the base assembled as the wire will carry
/// it and hashed by `shekyl-wire`'s own base serializer
/// ([`shekyl_wire::fcmp_base_hash`]), then framed with the prefix hash.
fn signable_of(
    network_id: &NetworkId,
    prefix_hash: PrefixHash,
    fee: shekyl_units::AtomicUnits,
    reference_block: &BlockHash,
    commitments: &[[u8; 32]],
    enc_amounts: &[EncryptedOutputField],
    enc_labels: &[EncryptedOutputField],
) -> TxSignableHash {
    let base = CtBase {
        enc_amounts: enc_amounts.iter().map(|f| f.to_bytes()).collect(),
        enc_labels: enc_labels.iter().map(|f| f.to_bytes()).collect(),
        commitments: commitments.to_vec(),
    };
    shekyl_wire::tx_signable(
        network_id,
        prefix_hash,
        shekyl_wire::fcmp_base_hash(fee.to_raw(), reference_block, &base),
    )
}

/// The transaction's `tx_signable` (the signing envelope §2.2) before it
/// is proved: what [`sign_transaction_with_terms`] proves the spend inputs
/// over, for a caller that proves something else over the same message
/// first (an emission's backing proof). `prefix_hash` is the prefix the
/// message covers; the base is `outputs`' commitments and encrypted
/// fields with `fee` and `reference_block`.
#[must_use]
pub fn tx_signable_for(
    network_id: &NetworkId,
    prefix_hash: PrefixHash,
    fee: shekyl_units::AtomicUnits,
    reference_block: &BlockHash,
    outputs: &[OutputInfo],
) -> TxSignableHash {
    let commitments: Vec<[u8; 32]> = outputs.iter().map(output_commitment).collect();
    let enc_amounts: Vec<EncryptedOutputField> = outputs.iter().map(|o| o.enc_amount).collect();
    let enc_labels: Vec<EncryptedOutputField> = outputs.iter().map(|o| o.enc_label).collect();
    signable_of(
        network_id,
        prefix_hash,
        fee,
        reference_block,
        &commitments,
        &enc_amounts,
        &enc_labels,
    )
}

/// Produce PQC authentication signatures for each input.
///
/// This is Phase 2 of the signing pipeline. The caller must:
/// 1. Insert the proofs from [`sign_transaction`] into the transaction
/// 2. Derive every input's signing hash with
///    [`crate::phase1_payload_hashes`] (`shekyl_wire::PqcSigningPreimage`'s
///    `signed_hash(i)`, one [`SigningPayloadHash`] per input)
/// 3. Call this function with those hashes and the corresponding secret keys
///
/// # Errors
///
/// Returns [`TxBuilderError::PqcSignError`] if any individual signing
/// operation fails (e.g., malformed secret key).
pub fn sign_pqc_auths(
    payload_hashes: &[SigningPayloadHash],
    inputs: &[SpendInput],
) -> Result<Vec<PqcAuth>, TxBuilderError> {
    sign_pqc_auths_with(payload_hashes, inputs, |ss, output_index, message| {
        shekyl_crypto_pq::output::sign_pqc_auth_for_output(
            ss,
            output_index,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
            message,
        )
    })
}

/// [`sign_pqc_auths`] with each signature's ML-DSA randomness drawn from
/// `seed`, one 32-byte nonce seed per input in input order, so one seed gives
/// the same signatures byte for byte (`CHAIN_FORGE.md` §5.3, seams T2 and T3).
/// Only under the TEST_ONLY `seeded-rng` feature.
///
/// # Errors
///
/// As [`sign_pqc_auths`].
#[cfg(feature = "seeded-rng")]
pub fn sign_pqc_auths_seeded(
    seed: &[u8; 32],
    payload_hashes: &[SigningPayloadHash],
    inputs: &[SpendInput],
) -> Result<Vec<PqcAuth>, TxBuilderError> {
    let mut nonces = seeded::stream(seed);
    sign_pqc_auths_with(payload_hashes, inputs, |ss, output_index, message| {
        let mut ml_dsa_seed =
            Zeroizing::new([0u8; shekyl_crypto_pq::signature::ML_DSA_SIGNING_SEED_LEN]);
        nonces.fill_bytes(&mut *ml_dsa_seed);
        shekyl_crypto_pq::output::sign_pqc_auth_for_output_with_ml_dsa_seed(
            ss,
            output_index,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
            message,
            &ml_dsa_seed,
        )
    })
}

/// [`sign_pqc_auths`]'s body, over `sign` (production's OS-drawn signer, or
/// the seeded one).
fn sign_pqc_auths_with(
    payload_hashes: &[SigningPayloadHash],
    inputs: &[SpendInput],
    mut sign: impl FnMut(
        &[u8; 64],
        u64,
        &[u8],
    ) -> Result<
        shekyl_crypto_pq::output::PqcAuthSignature,
        shekyl_crypto_pq::CryptoError,
    >,
) -> Result<Vec<PqcAuth>, TxBuilderError> {
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
        // The combined shared secret, copied once into memory that wipes on
        // drop (rule 35).
        let mut ss = Zeroizing::new([0u8; 64]);
        ss.copy_from_slice(&inp.combined_ss);

        let auth_sig = sign(&ss, inp.output_index, hash.as_bytes()).map_err(|e| {
            TxBuilderError::PqcSignError {
                index: i,
                reason: format!("sign_pqc_auth_for_output failed: {e}"),
            }
        })?;

        auths.push(PqcAuth {
            auth_version: PQC_AUTH_VERSION,
            scheme: crate::types::PqcScheme::Single,
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
    tx_signable: TxSignableHash,
) -> Result<MembershipOnlyProof, TxBuilderError> {
    prove_backing_membership_with(input, tree, tx_signable, proof::prove_membership_only)
}

/// [`prove_backing_membership`] with the prover's randomness drawn from
/// `seed`, so one seed gives the same backing proof byte for byte
/// (`CHAIN_FORGE.md` §5.3, seam T2). Only under the TEST_ONLY `seeded-rng`
/// feature.
///
/// # Errors
///
/// As [`prove_backing_membership`].
#[cfg(feature = "seeded-rng")]
pub fn prove_backing_membership_seeded(
    seed: &[u8; 32],
    input: &SpendInput,
    tree: &TreeContext,
    tx_signable: TxSignableHash,
) -> Result<MembershipOnlyProof, TxBuilderError> {
    let mut rng = seeded::stream(seed);
    prove_backing_membership_with(
        input,
        tree,
        tx_signable,
        |inputs, root, depth, hash, context| {
            proof::prove_membership_only_with_rng(&mut rng, inputs, root, depth, hash, context)
        },
    )
}

/// [`prove_backing_membership`]'s body, over `prove` (production's prover
/// over the OS, or the seeded one).
fn prove_backing_membership_with(
    input: &SpendInput,
    tree: &TreeContext,
    tx_signable: TxSignableHash,
    prove: impl FnOnce(
        &[ProveInput],
        &CurveTreeRoot,
        u8,
        TxSignableHash,
        &[u8],
    ) -> Result<ProveResult, ProveError>,
) -> Result<MembershipOnlyProof, TxBuilderError> {
    // The blind is not read on the membership-only path: pseudo-out blinds
    // are a full-path (key-image) concern; the membership-only pseudo-out
    // comes from the context-bound rerandomization inside the prover.
    let prove_input = prove_input_from_spend(0, input, [0u8; 32])?;

    let result = prove(
        &[prove_input],
        &tree.tree_root,
        tree.tree_depth,
        tx_signable,
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

/// The generators the seeded entry points draw from (`seeded-rng` only).
#[cfg(feature = "seeded-rng")]
pub(crate) mod seeded {
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// One ChaCha20 stream over `seed`.
    pub(crate) fn stream(seed: &[u8; 32]) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(*seed)
    }
}
