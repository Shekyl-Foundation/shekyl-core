// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FCMP++ proof construction and verification with PQC commitment binding.
//!
//! The Shekyl proof extends upstream FCMP++ by including `H(pqc_pk)` as
//! a public input verified in-circuit against the 4th leaf scalar.

use crate::leaf::PqcLeafScalar;
use crate::{MAX_INPUTS, MAX_TREE_DEPTH};
use thiserror::Error;
use zeroize::Zeroize;

use ciphersuite::{
    group::{
        ff::{Field, PrimeField},
        Group, GroupEncoding,
    },
    Ciphersuite,
};
use dalek_ff_group::{Ed25519, EdwardsPoint, Scalar};
use ec_divisors::ScalarDecomposition;
use helioselene::{Helios, Selene};
use rand_core::OsRng;

use shekyl_fcmp_plus_plus::{
    fcmps::{
        BranchBlind, Branches, CBlind, Fcmp, IBlind, IBlindBlind, OBlind, OutputBlinds, Path,
        TreeRoot,
    },
    sal::{OpenedInputTuple, RerandomizedOutput, SpendAuthAndLinkability},
    Curves, FcmpPlusPlus, Output, FCMP_PARAMS, HELIOS_FCMP_GENERATORS, SELENE_FCMP_GENERATORS,
};
use shekyl_generators::{FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V, T};

/// Errors during FCMP++ proof construction.
#[derive(Debug, Error)]
pub enum ProveError {
    #[error("too many inputs: {0} exceeds maximum {MAX_INPUTS}")]
    TooManyInputs(usize),

    #[error("empty inputs")]
    EmptyInputs,

    #[error("PQC hash mismatch at input {input_index}")]
    PqcHashMismatch { input_index: usize },

    #[error("tree path unavailable for input {0}")]
    TreePathUnavailable(usize),

    #[error("invalid Ed25519 point at input {input_index}: {field}")]
    InvalidPoint {
        input_index: usize,
        field: &'static str,
    },

    #[error("invalid scalar at input {input_index}: {field}")]
    InvalidScalar {
        input_index: usize,
        field: &'static str,
    },

    #[error("scalar decomposition failed (zero blinding factor)")]
    ScalarDecompositionFailed,

    #[error("upstream proof generation failed: {0}")]
    UpstreamError(String),
}

/// Errors during FCMP++ proof verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("proof deserialization failed")]
    DeserializationFailed,

    #[error("invalid tree root")]
    InvalidTreeRoot,

    #[error("PQC commitment mismatch at input {0}")]
    PqcCommitmentMismatch(usize),

    #[error("key image count mismatch: expected {expected}, got {got}")]
    KeyImageCountMismatch { expected: usize, got: usize },

    #[error("upstream verification failed: {0}")]
    UpstreamError(String),

    #[error("batch verification failed")]
    BatchVerificationFailed,

    #[error("tree depth {0} exceeds maximum {MAX_TREE_DEPTH}")]
    TreeDepthTooLarge(u8),
}

impl VerifyError {
    /// FFI-stable discriminant for crossing the C ABI boundary.
    ///
    /// Codes 1-7 map to the enum variants in declaration order.
    /// Code 0 is reserved for success (not an error).
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::DeserializationFailed => 1,
            Self::InvalidTreeRoot => 2,
            Self::PqcCommitmentMismatch(_) => 3,
            Self::KeyImageCountMismatch { .. } => 4,
            Self::UpstreamError(_) => 5,
            Self::BatchVerificationFailed => 6,
            Self::TreeDepthTooLarge(_) => 7,
        }
    }
}

/// A serialized FCMP++ proof blob (opaque to C++ callers).
#[derive(Clone, Debug, Zeroize)]
pub struct ShekylFcmpProof {
    pub data: Vec<u8>,
    pub num_inputs: u32,
    pub tree_depth: u8,
}

/// A branch layer in the Merkle path (sibling hashes at one tree level).
#[derive(Clone, Debug)]
pub struct BranchLayer {
    pub siblings: Vec<[u8; 32]>,
}

/// Full witness data for one input in an FCMP++ proof.
///
/// The C++ wallet constructs this from the output being spent, the
/// per-output key derivation, and the Merkle path from `get_curve_tree_path`.
#[derive(Clone, Debug)]
pub struct ProveInput {
    /// Compressed Ed25519 output public key O.
    pub output_key: [u8; 32],
    /// Compressed Ed25519 key image generator I = Hp(O).
    pub key_image_gen: [u8; 32],
    /// Compressed Ed25519 Pedersen commitment C.
    pub commitment: [u8; 32],
    /// H(pqc_pk) for this output's 4th leaf scalar.
    pub h_pqc: PqcLeafScalar,

    /// Spend secret key x where O = xG + yT.
    pub spend_key_x: [u8; 32],
    /// SAL output-key secret y where O = xG + yT.
    /// For legacy one-time addresses this is 0 (O = xG).
    /// For future two-component addresses this will be a non-trivial secret.
    pub spend_key_y: [u8; 32],
    /// Pedersen commitment mask z where C = zG + amount*H.
    /// This is independent of the SAL y: the commitment blinding factor
    /// is NOT the same scalar as the output-key T-component.
    pub commitment_mask: [u8; 32],
    /// Desired pseudo-out blinding factor `a_i`.
    ///
    /// The commitment rerandomization scalar is computed as `r_c = a_i - z`
    /// so that `C_tilde = (z + r_c)*G + amount*H = a_i*G + amount*H`,
    /// ensuring the sum of pseudo-out blinding factors matches the sum of
    /// output masks for the balance equation.
    pub pseudo_out_blind: [u8; 32],

    /// Sibling outputs in the same leaf chunk (compressed Ed25519 points).
    /// Each entry is (O, I, C) as 3x32 bytes.
    pub leaf_chunk_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])>,
    /// H(pqc_pk) for each output in the chunk, parallel to `leaf_chunk_outputs`.
    pub leaf_chunk_h_pqc: Vec<[u8; 32]>,

    /// Selene (C1) branch layers, bottom to top.
    pub c1_branch_layers: Vec<BranchLayer>,
    /// Helios (C2) branch layers, bottom to top.
    pub c2_branch_layers: Vec<BranchLayer>,
}

/// Result of FCMP++ proof construction.
pub struct ProveResult {
    /// The serialized proof blob.
    pub proof: ShekylFcmpProof,
    /// Per-input pseudo-outs (C_tilde compressed), needed by the wallet for balance proof.
    pub pseudo_outs: Vec<[u8; 32]>,
}

/// Construct an FCMP++ proof for a set of inputs.
///
/// Performs full rerandomization and SAL (spend-auth-and-linkability) proof
/// generation. Returns the proof blob and the per-input pseudo-outs
/// (rerandomized commitments).
#[allow(non_snake_case)]
pub fn prove(
    inputs: &[ProveInput],
    _tree_root: &[u8; 32],
    tree_depth: u8,
    signable_tx_hash: [u8; 32],
) -> Result<ProveResult, ProveError> {
    if inputs.is_empty() {
        return Err(ProveError::EmptyInputs);
    }
    if inputs.len() > MAX_INPUTS {
        return Err(ProveError::TooManyInputs(inputs.len()));
    }

    let mut sal_pairs = Vec::with_capacity(inputs.len());
    let mut output_blinds_list = Vec::with_capacity(inputs.len());
    let mut paths = Vec::with_capacity(inputs.len());
    let mut pseudo_outs = Vec::with_capacity(inputs.len());

    for (idx, input) in inputs.iter().enumerate() {
        let O = decompress_ed25519(&input.output_key).ok_or(ProveError::InvalidPoint {
            input_index: idx,
            field: "output_key",
        })?;
        let I = decompress_ed25519(&input.key_image_gen).ok_or(ProveError::InvalidPoint {
            input_index: idx,
            field: "key_image_gen",
        })?;
        let C = decompress_ed25519(&input.commitment).ok_or(ProveError::InvalidPoint {
            input_index: idx,
            field: "commitment",
        })?;

        let output = Output::new(O, I, C)
            .map_err(|e| ProveError::UpstreamError(format!("Output::new at input {idx}: {e:?}")))?;

        let x =
            deserialize_ed25519_scalar(&input.spend_key_x).ok_or(ProveError::InvalidScalar {
                input_index: idx,
                field: "spend_key_x",
            })?;
        let y =
            deserialize_ed25519_scalar(&input.spend_key_y).ok_or(ProveError::InvalidScalar {
                input_index: idx,
                field: "spend_key_y",
            })?;
        let z = deserialize_ed25519_scalar(&input.commitment_mask).ok_or(
            ProveError::InvalidScalar {
                input_index: idx,
                field: "commitment_mask",
            },
        )?;
        let a = deserialize_ed25519_scalar(&input.pseudo_out_blind).ok_or(
            ProveError::InvalidScalar {
                input_index: idx,
                field: "pseudo_out_blind",
            },
        )?;

        let r_c = a - z;

        let rerand = RerandomizedOutput::with_commitment_blind(&mut OsRng, output, r_c);
        let crate_input = rerand.input();
        let c_tilde_bytes: [u8; 32] = crate_input.C_tilde().to_bytes();

        pseudo_outs.push(c_tilde_bytes);

        let opening = OpenedInputTuple::open(&rerand, &x, &y).ok_or(ProveError::UpstreamError(
            format!("OpenedInputTuple::open failed at input {idx}"),
        ))?;
        let (_, sal) = SpendAuthAndLinkability::prove(&mut OsRng, signable_tx_hash, &opening);
        sal_pairs.push((crate_input, sal));

        // Build OutputBlinds from rerandomization
        let output_blind = OutputBlinds::new(
            OBlind::new(
                EdwardsPoint(*T),
                ScalarDecomposition::new(rerand.o_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
            IBlind::new(
                EdwardsPoint(*FCMP_PLUS_PLUS_U),
                EdwardsPoint(*FCMP_PLUS_PLUS_V),
                ScalarDecomposition::new(rerand.i_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
            IBlindBlind::new(
                EdwardsPoint(*T),
                ScalarDecomposition::new(rerand.i_blind_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
            CBlind::new(
                EdwardsPoint::generator(),
                ScalarDecomposition::new(rerand.c_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
        );
        output_blinds_list.push(output_blind);

        // Build the leaf chunk
        if input.leaf_chunk_outputs.is_empty() {
            return Err(ProveError::TreePathUnavailable(idx));
        }

        let mut chunk_outputs = Vec::with_capacity(input.leaf_chunk_outputs.len());
        let mut chunk_extra = Vec::with_capacity(input.leaf_chunk_outputs.len());
        for (j, (o, i, c)) in input.leaf_chunk_outputs.iter().enumerate() {
            let lo = decompress_ed25519(o).ok_or(ProveError::InvalidPoint {
                input_index: idx,
                field: "leaf_O",
            })?;
            let li = decompress_ed25519(i).ok_or(ProveError::InvalidPoint {
                input_index: idx,
                field: "leaf_I",
            })?;
            let lc = decompress_ed25519(c).ok_or(ProveError::InvalidPoint {
                input_index: idx,
                field: "leaf_C",
            })?;
            chunk_outputs.push(Output::new(lo, li, lc).map_err(|e| {
                ProveError::UpstreamError(format!(
                    "leaf Output::new at input {idx}, leaf {j}: {e:?}"
                ))
            })?);

            let h_pqc = deserialize_selene_scalar(&input.leaf_chunk_h_pqc[j]).ok_or(
                ProveError::InvalidScalar {
                    input_index: idx,
                    field: "leaf_h_pqc",
                },
            )?;
            chunk_extra.push(vec![h_pqc]);
        }

        let output_h_pqc =
            deserialize_selene_scalar(&input.h_pqc.0).ok_or(ProveError::InvalidScalar {
                input_index: idx,
                field: "h_pqc",
            })?;

        // Build C1/C2 branch layers
        let mut c1_layers = Vec::new();
        for layer in &input.c1_branch_layers {
            let scalars: Vec<<Selene as Ciphersuite>::F> = layer
                .siblings
                .iter()
                .map(deserialize_selene_scalar)
                .collect::<Option<Vec<_>>>()
                .ok_or(ProveError::InvalidScalar {
                    input_index: idx,
                    field: "c1_branch",
                })?;
            c1_layers.push(scalars);
        }
        let mut c2_layers = Vec::new();
        for layer in &input.c2_branch_layers {
            let scalars: Vec<<Helios as Ciphersuite>::F> = layer
                .siblings
                .iter()
                .map(deserialize_helios_scalar)
                .collect::<Option<Vec<_>>>()
                .ok_or(ProveError::InvalidScalar {
                    input_index: idx,
                    field: "c2_branch",
                })?;
            c2_layers.push(scalars);
        }

        paths.push(Path::<Curves> {
            output,
            output_extra_scalars: vec![output_h_pqc],
            leaves: chunk_outputs,
            leaves_extra_scalars: chunk_extra,
            curve_2_layers: c2_layers,
            curve_1_layers: c1_layers,
        });
    }

    // Build branches, generate blinds, and produce the proof
    let branches =
        Branches::new(paths).ok_or(ProveError::UpstreamError("Branches::new failed".into()))?;

    let c1_blind_count = branches.necessary_c1_blinds();
    let c2_blind_count = branches.necessary_c2_blinds();

    let c1_h = SELENE_FCMP_GENERATORS.generators.h();
    let c2_h = HELIOS_FCMP_GENERATORS.generators.h();

    let c1_blinds: Vec<_> = (0..c1_blind_count)
        .map(|_| {
            Ok(BranchBlind::<<Selene as Ciphersuite>::G>::new(
                c1_h,
                ScalarDecomposition::new(<Selene as Ciphersuite>::F::random(&mut OsRng))
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ))
        })
        .collect::<Result<_, ProveError>>()?;
    let c2_blinds: Vec<_> = (0..c2_blind_count)
        .map(|_| {
            Ok(BranchBlind::<<Helios as Ciphersuite>::G>::new(
                c2_h,
                ScalarDecomposition::new(<Helios as Ciphersuite>::F::random(&mut OsRng))
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ))
        })
        .collect::<Result<_, ProveError>>()?;

    let blinded = branches
        .blind(output_blinds_list, c1_blinds, c2_blinds)
        .map_err(|e| ProveError::UpstreamError(format!("blind: {e:?}")))?;

    let fcmp = Fcmp::prove(&mut OsRng, &*FCMP_PARAMS, blinded)
        .map_err(|e| ProveError::UpstreamError(format!("Fcmp::prove: {e:?}")))?;

    let fcmp_pp = FcmpPlusPlus::new(sal_pairs, fcmp);

    let mut data = Vec::new();
    fcmp_pp
        .write(&mut data)
        .map_err(|e| ProveError::UpstreamError(format!("write: {e}")))?;

    #[allow(clippy::cast_possible_truncation)]
    let num_inputs = inputs.len() as u32;
    Ok(ProveResult {
        proof: ShekylFcmpProof {
            data,
            num_inputs,
            tree_depth,
        },
        pseudo_outs,
    })
}

/// Construct an FCMP++ proof using pre-aggregated SAL proofs (multisig flow).
///
/// Unlike `prove()`, this function accepts already-computed
/// `(Input, SpendAuthAndLinkability)` pairs from the FROST threshold signing
/// protocol. It skips the single-signer `OpenedInputTuple::open()` and
/// `SpendAuthAndLinkability::prove()` steps.
///
/// `original_outputs`: the non-rerandomized `Output` for each input (needed
/// for the `Path.output` field).
/// `rerands`: the `RerandomizedOutput` per input for blind derivation.
/// `leaf_chunks`: per-input leaf chunk and branch data.
#[cfg(feature = "multisig")]
#[allow(non_snake_case)]
pub fn prove_with_sal(
    sal_pairs: Vec<(shekyl_fcmp_plus_plus::Input, SpendAuthAndLinkability)>,
    original_outputs: &[Output],
    rerands: &[shekyl_fcmp_plus_plus::sal::RerandomizedOutput],
    leaf_chunks: &[ProveInputLeafChunk],
    tree_depth: u8,
) -> Result<ProveResult, ProveError> {
    if sal_pairs.is_empty() {
        return Err(ProveError::EmptyInputs);
    }
    if sal_pairs.len() > MAX_INPUTS {
        return Err(ProveError::TooManyInputs(sal_pairs.len()));
    }
    if sal_pairs.len() != original_outputs.len()
        || sal_pairs.len() != rerands.len()
        || sal_pairs.len() != leaf_chunks.len()
    {
        return Err(ProveError::UpstreamError(
            "sal_pairs/original_outputs/rerands/leaf_chunks length mismatch".into(),
        ));
    }

    let mut paired = Vec::with_capacity(sal_pairs.len());
    let mut output_blinds_list = Vec::with_capacity(sal_pairs.len());
    let mut paths = Vec::with_capacity(sal_pairs.len());
    let mut pseudo_outs = Vec::with_capacity(sal_pairs.len());

    for (idx, (((input, sal), orig_output), rerand)) in sal_pairs
        .into_iter()
        .zip(original_outputs.iter())
        .zip(rerands.iter())
        .enumerate()
    {
        pseudo_outs.push(input.C_tilde().to_bytes());
        paired.push((input, sal));

        // Build OutputBlinds from rerandomization
        let output_blind = OutputBlinds::new(
            OBlind::new(
                EdwardsPoint(*T),
                ScalarDecomposition::new(rerand.o_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
            IBlind::new(
                EdwardsPoint(*FCMP_PLUS_PLUS_U),
                EdwardsPoint(*FCMP_PLUS_PLUS_V),
                ScalarDecomposition::new(rerand.i_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
            IBlindBlind::new(
                EdwardsPoint(*T),
                ScalarDecomposition::new(rerand.i_blind_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
            CBlind::new(
                EdwardsPoint::generator(),
                ScalarDecomposition::new(rerand.c_blind())
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ),
        );
        output_blinds_list.push(output_blind);

        // Build the leaf chunk and branch layers
        let chunk = &leaf_chunks[idx];
        if chunk.leaf_outputs.is_empty() {
            return Err(ProveError::TreePathUnavailable(idx));
        }

        let mut chunk_outputs = Vec::with_capacity(chunk.leaf_outputs.len());
        let mut chunk_extra = Vec::with_capacity(chunk.leaf_outputs.len());
        for (j, (o, i, c)) in chunk.leaf_outputs.iter().enumerate() {
            let lo = decompress_ed25519(o).ok_or(ProveError::InvalidPoint {
                input_index: idx,
                field: "leaf_O",
            })?;
            let li = decompress_ed25519(i).ok_or(ProveError::InvalidPoint {
                input_index: idx,
                field: "leaf_I",
            })?;
            let lc = decompress_ed25519(c).ok_or(ProveError::InvalidPoint {
                input_index: idx,
                field: "leaf_C",
            })?;
            chunk_outputs.push(Output::new(lo, li, lc).map_err(|e| {
                ProveError::UpstreamError(format!(
                    "leaf Output::new at input {idx}, leaf {j}: {e:?}"
                ))
            })?);
            let h = deserialize_selene_scalar(&chunk.leaf_h_pqc[j]).ok_or(
                ProveError::InvalidScalar {
                    input_index: idx,
                    field: "leaf_h_pqc",
                },
            )?;
            chunk_extra.push(vec![h]);
        }

        let output_h_pqc =
            deserialize_selene_scalar(&chunk.output_h_pqc.0).ok_or(ProveError::InvalidScalar {
                input_index: idx,
                field: "h_pqc",
            })?;

        let mut c1_layers = Vec::new();
        for layer in &chunk.c1_branch_layers {
            let scalars: Vec<<Selene as Ciphersuite>::F> = layer
                .siblings
                .iter()
                .map(deserialize_selene_scalar)
                .collect::<Option<Vec<_>>>()
                .ok_or(ProveError::InvalidScalar {
                    input_index: idx,
                    field: "c1_branch",
                })?;
            c1_layers.push(scalars);
        }
        let mut c2_layers = Vec::new();
        for layer in &chunk.c2_branch_layers {
            let scalars: Vec<<Helios as Ciphersuite>::F> = layer
                .siblings
                .iter()
                .map(deserialize_helios_scalar)
                .collect::<Option<Vec<_>>>()
                .ok_or(ProveError::InvalidScalar {
                    input_index: idx,
                    field: "c2_branch",
                })?;
            c2_layers.push(scalars);
        }

        paths.push(Path::<Curves> {
            output: *orig_output,
            output_extra_scalars: vec![output_h_pqc],
            leaves: chunk_outputs,
            leaves_extra_scalars: chunk_extra,
            curve_2_layers: c2_layers,
            curve_1_layers: c1_layers,
        });
    }

    let branches =
        Branches::new(paths).ok_or(ProveError::UpstreamError("Branches::new failed".into()))?;

    let c1_blind_count = branches.necessary_c1_blinds();
    let c2_blind_count = branches.necessary_c2_blinds();

    let c1_h = SELENE_FCMP_GENERATORS.generators.h();
    let c2_h = HELIOS_FCMP_GENERATORS.generators.h();

    let c1_blinds: Vec<_> = (0..c1_blind_count)
        .map(|_| {
            Ok(BranchBlind::<<Selene as Ciphersuite>::G>::new(
                c1_h,
                ScalarDecomposition::new(<Selene as Ciphersuite>::F::random(&mut OsRng))
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ))
        })
        .collect::<Result<_, ProveError>>()?;
    let c2_blinds: Vec<_> = (0..c2_blind_count)
        .map(|_| {
            Ok(BranchBlind::<<Helios as Ciphersuite>::G>::new(
                c2_h,
                ScalarDecomposition::new(<Helios as Ciphersuite>::F::random(&mut OsRng))
                    .ok_or(ProveError::ScalarDecompositionFailed)?,
            ))
        })
        .collect::<Result<_, ProveError>>()?;

    let blinded = branches
        .blind(output_blinds_list, c1_blinds, c2_blinds)
        .map_err(|e| ProveError::UpstreamError(format!("blind: {e:?}")))?;

    let fcmp = Fcmp::prove(&mut OsRng, &*FCMP_PARAMS, blinded)
        .map_err(|e| ProveError::UpstreamError(format!("Fcmp::prove: {e:?}")))?;

    let fcmp_pp = FcmpPlusPlus::new(paired, fcmp);

    let mut data = Vec::new();
    fcmp_pp
        .write(&mut data)
        .map_err(|e| ProveError::UpstreamError(format!("write: {e}")))?;

    #[allow(clippy::cast_possible_truncation)]
    let num_inputs = pseudo_outs.len() as u32;
    Ok(ProveResult {
        proof: ShekylFcmpProof {
            data,
            num_inputs,
            tree_depth,
        },
        pseudo_outs,
    })
}

/// Leaf chunk and branch data for `prove_with_sal()`.
#[cfg(feature = "multisig")]
#[derive(Clone, Debug)]
pub struct ProveInputLeafChunk {
    pub output_h_pqc: PqcLeafScalar,
    pub leaf_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])>,
    pub leaf_h_pqc: Vec<[u8; 32]>,
    pub c1_branch_layers: Vec<BranchLayer>,
    pub c2_branch_layers: Vec<BranchLayer>,
}

/// Verify an FCMP++ proof against public inputs.
///
/// Uses batch verification for efficiency. Checks:
/// 1. Proof deserialization
/// 2. SAL (spend-auth-and-linkability) proof per input
/// 3. FCMP circuit proof (tree membership + H(pqc_pk) binding)
/// 4. Finalizes batch verifiers (Ed25519, Selene, Helios)
pub fn verify(
    proof: &ShekylFcmpProof,
    key_images: &[[u8; 32]],
    pseudo_outs: &[[u8; 32]],
    pqc_pk_hashes: &[PqcLeafScalar],
    tree_root: &[u8; 32],
    tree_depth: u8,
    signable_tx_hash: [u8; 32],
) -> Result<bool, VerifyError> {
    let num_inputs = proof.num_inputs as usize;
    if key_images.len() != num_inputs {
        return Err(VerifyError::KeyImageCountMismatch {
            expected: num_inputs,
            got: key_images.len(),
        });
    }
    if pseudo_outs.len() != num_inputs {
        return Err(VerifyError::KeyImageCountMismatch {
            expected: num_inputs,
            got: pseudo_outs.len(),
        });
    }
    if pqc_pk_hashes.len() != num_inputs {
        return Err(VerifyError::PqcCommitmentMismatch(pqc_pk_hashes.len()));
    }
    if proof.tree_depth != tree_depth {
        return Err(VerifyError::InvalidTreeRoot);
    }
    if tree_depth > MAX_TREE_DEPTH {
        return Err(VerifyError::TreeDepthTooLarge(tree_depth));
    }

    let layers = tree_depth as usize;

    let tree = deserialize_tree_root(tree_root, layers).ok_or(VerifyError::InvalidTreeRoot)?;

    let ki_points: Vec<<Ed25519 as Ciphersuite>::G> = key_images
        .iter()
        .map(decompress_ed25519)
        .collect::<Option<Vec<_>>>()
        .ok_or(VerifyError::DeserializationFailed)?;

    let pqc_selene: Vec<<Selene as Ciphersuite>::F> = pqc_pk_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| deserialize_selene_scalar(&h.0).ok_or(VerifyError::PqcCommitmentMismatch(i)))
        .collect::<Result<Vec<_>, _>>()?;

    let fcmp_pp = FcmpPlusPlus::read(pseudo_outs, layers, &mut proof.data.as_slice())
        .map_err(|_| VerifyError::DeserializationFailed)?;

    let mut ed_verifier = multiexp::BatchVerifier::new(num_inputs);
    let mut c1_verifier = generalized_bulletproofs::Generators::batch_verifier();
    let mut c2_verifier = generalized_bulletproofs::Generators::batch_verifier();

    fcmp_pp
        .verify(
            &mut OsRng,
            &mut ed_verifier,
            &mut c1_verifier,
            &mut c2_verifier,
            tree,
            layers,
            signable_tx_hash,
            ki_points,
            pqc_selene,
        )
        .map_err(|e| VerifyError::UpstreamError(format!("{e:?}")))?;

    let ed_ok = ed_verifier.verify_vartime();
    let c1_ok = SELENE_FCMP_GENERATORS.generators.verify(c1_verifier);
    let c2_ok = HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier);

    if !ed_ok || !c1_ok || !c2_ok {
        tracing::debug!(ed_ok, c1_ok, c2_ok, "batch check failed");
        return Err(VerifyError::BatchVerificationFailed);
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Deserialization helpers
// ---------------------------------------------------------------------------

fn decompress_ed25519(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let ct = <EdwardsPoint as GroupEncoding>::from_bytes(bytes);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn deserialize_ed25519_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let ct = Scalar::from_repr(*bytes);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn deserialize_selene_scalar(bytes: &[u8; 32]) -> Option<<Selene as Ciphersuite>::F> {
    let ct = <Selene as Ciphersuite>::F::from_repr(*bytes);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn deserialize_helios_scalar(bytes: &[u8; 32]) -> Option<<Helios as Ciphersuite>::F> {
    let ct = <Helios as Ciphersuite>::F::from_repr(*bytes);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn deserialize_tree_root(bytes: &[u8; 32], layers: usize) -> Option<TreeRoot<Selene, Helios>> {
    if layers % 2 == 1 {
        let ct = <Selene as Ciphersuite>::G::from_bytes(bytes);
        if bool::from(ct.is_some()) {
            Some(TreeRoot::C1(ct.unwrap()))
        } else {
            None
        }
    } else {
        let ct = <Helios as Ciphersuite>::G::from_bytes(bytes);
        if bool::from(ct.is_some()) {
            Some(TreeRoot::C2(ct.unwrap()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_rejects_too_many_inputs() {
        let inputs: Vec<ProveInput> = (0..9).map(|_| dummy_prove_input()).collect();
        let result = prove(&inputs, &[0; 32], 8, [0; 32]);
        assert!(matches!(result, Err(ProveError::TooManyInputs(9))));
    }

    #[test]
    fn prove_rejects_empty_inputs() {
        let result = prove(&[], &[0; 32], 8, [0; 32]);
        assert!(matches!(result, Err(ProveError::EmptyInputs)));
    }

    #[test]
    fn verify_rejects_input_count_mismatch() {
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 2,
            tree_depth: 8,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32], [0; 32]],
            &[PqcLeafScalar([0; 32]), PqcLeafScalar([0; 32])],
            &[0; 32],
            8,
            [0; 32],
        );
        assert!(matches!(
            result,
            Err(VerifyError::KeyImageCountMismatch { .. })
        ));
    }

    #[test]
    fn verify_rejects_wrong_tree_depth() {
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 1,
            tree_depth: 8,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32]],
            &[PqcLeafScalar([0; 32])],
            &[0; 32],
            10,
            [0; 32],
        );
        assert!(matches!(result, Err(VerifyError::InvalidTreeRoot)));
    }

    fn dummy_prove_input() -> ProveInput {
        ProveInput {
            output_key: [0; 32],
            key_image_gen: [0; 32],
            commitment: [0; 32],
            h_pqc: PqcLeafScalar([0; 32]),
            spend_key_x: [0; 32],
            spend_key_y: [0; 32],
            commitment_mask: [0; 32],
            pseudo_out_blind: [0; 32],
            leaf_chunk_outputs: vec![],
            leaf_chunk_h_pqc: vec![],
            c1_branch_layers: vec![],
            c2_branch_layers: vec![],
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn prove_verify_roundtrip() {
        use ec_divisors::DivisorCurve;
        use multiexp::multiexp_vartime;
        use shekyl_generators::SELENE_HASH_INIT;

        let tree_depth: u8 = 1;
        let signable_tx_hash = [0xABu8; 32];

        let x = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let O = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
        let I = EdwardsPoint::random(&mut OsRng);
        let C = EdwardsPoint::random(&mut OsRng);

        let L = I * x;

        let h_pqc_field = <Selene as Ciphersuite>::F::random(&mut OsRng);
        let h_pqc_bytes: [u8; 32] = h_pqc_field.to_repr();

        let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
        let tree_root_point: <Selene as Ciphersuite>::G = *SELENE_HASH_INIT
            + multiexp_vartime(&[
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(O).unwrap().0,
                    generators[0],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(I).unwrap().0,
                    generators[1],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(C).unwrap().0,
                    generators[2],
                ),
                (h_pqc_field, generators[3]),
            ]);
        let tree_root: [u8; 32] = tree_root_point.to_bytes();

        let o_bytes = O.to_bytes();
        let i_bytes = I.to_bytes();
        let c_bytes = C.to_bytes();

        let z = Scalar::random(&mut OsRng);
        let a = Scalar::random(&mut OsRng);
        let input = ProveInput {
            output_key: o_bytes,
            key_image_gen: i_bytes,
            commitment: c_bytes,
            h_pqc: PqcLeafScalar(h_pqc_bytes),
            spend_key_x: x.to_repr(),
            spend_key_y: y.to_repr(),
            commitment_mask: z.to_repr(),
            pseudo_out_blind: a.to_repr(),
            leaf_chunk_outputs: vec![(o_bytes, i_bytes, c_bytes)],
            leaf_chunk_h_pqc: vec![h_pqc_bytes],
            c1_branch_layers: vec![],
            c2_branch_layers: vec![],
        };

        let result = prove(&[input], &tree_root, tree_depth, signable_tx_hash)
            .expect("prove should succeed");

        let key_images = [L.to_bytes()];

        let ok = verify(
            &result.proof,
            &key_images,
            &result.pseudo_outs,
            &[PqcLeafScalar(h_pqc_bytes)],
            &tree_root,
            tree_depth,
            signable_tx_hash,
        )
        .expect("verify should succeed");
        assert!(ok, "valid proof must verify");

        // Tampered key image must fail
        let mut bad_ki = key_images[0];
        bad_ki[0] ^= 0xFF;
        let tampered = verify(
            &result.proof,
            &[bad_ki],
            &result.pseudo_outs,
            &[PqcLeafScalar(h_pqc_bytes)],
            &tree_root,
            tree_depth,
            signable_tx_hash,
        );
        assert!(
            tampered.is_err() || matches!(tampered, Ok(false)),
            "tampered key image must not verify"
        );

        // Wrong tree root must fail
        let mut bad_root = tree_root;
        bad_root[0] ^= 0xFF;
        let wrong_root = verify(
            &result.proof,
            &key_images,
            &result.pseudo_outs,
            &[PqcLeafScalar(h_pqc_bytes)],
            &bad_root,
            tree_depth,
            signable_tx_hash,
        );
        assert!(
            wrong_root.is_err() || matches!(wrong_root, Ok(false)),
            "wrong tree root must not verify"
        );
    }

    #[test]
    fn prove_rejects_max_plus_one_inputs() {
        let inputs: Vec<ProveInput> = (0..=MAX_INPUTS).map(|_| dummy_prove_input()).collect();
        let result = prove(&inputs, &[0; 32], 8, [0; 32]);
        assert!(matches!(result, Err(ProveError::TooManyInputs(_))));
    }

    #[test]
    fn prove_at_max_inputs_count() {
        let inputs: Vec<ProveInput> = (0..MAX_INPUTS).map(|_| dummy_prove_input()).collect();
        let result = prove(&inputs, &[0; 32], 8, [0; 32]);
        assert!(
            !matches!(result, Err(ProveError::TooManyInputs(_))),
            "MAX_INPUTS should be accepted (may fail for other reasons)"
        );
    }

    #[test]
    fn prove_rejects_missing_tree_path() {
        let mut input = dummy_prove_input();
        input.spend_key_x = Scalar::random(&mut OsRng).to_repr();
        input.spend_key_y = Scalar::random(&mut OsRng).to_repr();
        let result = prove(&[input], &[0; 32], 8, [0; 32]);
        assert!(
            result.is_err(),
            "input with empty leaf_chunk_outputs should fail"
        );
    }

    #[test]
    fn verify_rejects_empty_proof_data() {
        let proof = ShekylFcmpProof {
            data: vec![],
            num_inputs: 1,
            tree_depth: 8,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32]],
            &[PqcLeafScalar([0; 32])],
            &[0; 32],
            8,
            [0; 32],
        );
        assert!(result.is_err(), "empty proof data should be rejected");
    }

    #[test]
    fn verify_rejects_pseudo_out_count_mismatch() {
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 1,
            tree_depth: 8,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32], [0; 32]],
            &[PqcLeafScalar([0; 32])],
            &[0; 32],
            8,
            [0; 32],
        );
        assert!(
            result.is_err(),
            "mismatched pseudo_outs count should be rejected"
        );
    }

    #[test]
    fn verify_rejects_pqc_leaf_count_mismatch() {
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 1,
            tree_depth: 8,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32]],
            &[PqcLeafScalar([0; 32]), PqcLeafScalar([0; 32])],
            &[0; 32],
            8,
            [0; 32],
        );
        assert!(
            result.is_err(),
            "mismatched PQC leaf count should be rejected"
        );
    }

    #[test]
    fn verify_rejects_zero_tree_depth() {
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 1,
            tree_depth: 0,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32]],
            &[PqcLeafScalar([0; 32])],
            &[0; 32],
            0,
            [0; 32],
        );
        assert!(result.is_err(), "tree depth 0 should be rejected");
    }

    #[test]
    fn verify_rejects_tree_depth_above_max() {
        let bad_depth = MAX_TREE_DEPTH + 1;
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 1,
            tree_depth: bad_depth,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32]],
            &[PqcLeafScalar([0; 32])],
            &[0; 32],
            bad_depth,
            [0; 32],
        );
        assert!(
            matches!(result, Err(VerifyError::TreeDepthTooLarge(d)) if d == bad_depth),
            "tree depth {bad_depth} should be rejected as exceeding MAX_TREE_DEPTH ({MAX_TREE_DEPTH})",
        );
    }

    #[test]
    fn verify_rejects_all_zero_key_images() {
        let proof = ShekylFcmpProof {
            data: vec![0; 100],
            num_inputs: 1,
            tree_depth: 8,
        };
        let result = verify(
            &proof,
            &[[0; 32]],
            &[[0; 32]],
            &[PqcLeafScalar([0; 32])],
            &[0; 32],
            8,
            [0; 32],
        );
        assert!(
            result.is_err() || matches!(result, Ok(false)),
            "all-zero key images should not verify"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn prove_verify_wrong_signable_tx_hash_fails() {
        use ec_divisors::DivisorCurve;
        use multiexp::multiexp_vartime;
        use shekyl_generators::SELENE_HASH_INIT;

        let tree_depth: u8 = 1;
        let signable_tx_hash = [0xABu8; 32];

        let x = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let O = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
        let I = EdwardsPoint::random(&mut OsRng);
        let C = EdwardsPoint::random(&mut OsRng);
        let L = I * x;

        let h_pqc_field = <Selene as Ciphersuite>::F::random(&mut OsRng);
        let h_pqc_bytes: [u8; 32] = h_pqc_field.to_repr();

        let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
        let tree_root_point: <Selene as Ciphersuite>::G = *SELENE_HASH_INIT
            + multiexp_vartime(&[
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(O).unwrap().0,
                    generators[0],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(I).unwrap().0,
                    generators[1],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(C).unwrap().0,
                    generators[2],
                ),
                (h_pqc_field, generators[3]),
            ]);
        let tree_root: [u8; 32] = tree_root_point.to_bytes();

        let o_bytes = O.to_bytes();
        let i_bytes = I.to_bytes();
        let c_bytes = C.to_bytes();

        let z2 = Scalar::random(&mut OsRng);
        let a2 = Scalar::random(&mut OsRng);
        let input = ProveInput {
            output_key: o_bytes,
            key_image_gen: i_bytes,
            commitment: c_bytes,
            h_pqc: PqcLeafScalar(h_pqc_bytes),
            spend_key_x: x.to_repr(),
            spend_key_y: y.to_repr(),
            commitment_mask: z2.to_repr(),
            pseudo_out_blind: a2.to_repr(),
            leaf_chunk_outputs: vec![(o_bytes, i_bytes, c_bytes)],
            leaf_chunk_h_pqc: vec![h_pqc_bytes],
            c1_branch_layers: vec![],
            c2_branch_layers: vec![],
        };

        let result = prove(&[input], &tree_root, tree_depth, signable_tx_hash)
            .expect("prove should succeed");

        let different_hash = [0xCDu8; 32];
        let wrong_hash = verify(
            &result.proof,
            &[L.to_bytes()],
            &result.pseudo_outs,
            &[PqcLeafScalar(h_pqc_bytes)],
            &tree_root,
            tree_depth,
            different_hash,
        );
        assert!(
            wrong_hash.is_err() || matches!(wrong_hash, Ok(false)),
            "wrong signable_tx_hash must not verify"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn legacy_single_component_key_with_mask_as_y_must_fail() {
        use ec_divisors::DivisorCurve;
        use multiexp::multiexp_vartime;
        use shekyl_generators::SELENE_HASH_INIT;

        let tree_depth: u8 = 1;
        let signable_tx_hash = [0xBBu8; 32];

        let x = Scalar::random(&mut OsRng);
        let mask = Scalar::random(&mut OsRng);

        let O = EdwardsPoint::generator() * x;
        let I = EdwardsPoint::random(&mut OsRng);
        let C = EdwardsPoint::random(&mut OsRng);

        let h_pqc_field = <Selene as Ciphersuite>::F::random(&mut OsRng);
        let h_pqc_bytes: [u8; 32] = h_pqc_field.to_repr();

        let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
        let tree_root_point: <Selene as Ciphersuite>::G = *SELENE_HASH_INIT
            + multiexp_vartime(&[
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(O).unwrap().0,
                    generators[0],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(I).unwrap().0,
                    generators[1],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(C).unwrap().0,
                    generators[2],
                ),
                (h_pqc_field, generators[3]),
            ]);
        let tree_root: [u8; 32] = tree_root_point.to_bytes();

        let o_bytes = O.to_bytes();
        let i_bytes = I.to_bytes();
        let c_bytes = C.to_bytes();

        let a = Scalar::random(&mut OsRng);
        let input = ProveInput {
            output_key: o_bytes,
            key_image_gen: i_bytes,
            commitment: c_bytes,
            h_pqc: PqcLeafScalar(h_pqc_bytes),
            spend_key_x: x.to_repr(),
            spend_key_y: mask.to_repr(),
            commitment_mask: mask.to_repr(),
            pseudo_out_blind: a.to_repr(),
            leaf_chunk_outputs: vec![(o_bytes, i_bytes, c_bytes)],
            leaf_chunk_h_pqc: vec![h_pqc_bytes],
            c1_branch_layers: vec![],
            c2_branch_layers: vec![],
        };

        let result = prove(&[input], &tree_root, tree_depth, signable_tx_hash);
        assert!(
            result.is_err(),
            "O=xG with y=mask (nonzero) must fail at OpenedInputTuple::open"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn two_component_key_with_real_y_must_succeed() {
        use ec_divisors::DivisorCurve;
        use multiexp::multiexp_vartime;
        use shekyl_generators::SELENE_HASH_INIT;

        let tree_depth: u8 = 1;
        let signable_tx_hash = [0xCCu8; 32];

        let x = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let z = Scalar::random(&mut OsRng);

        let O = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
        let I = EdwardsPoint::random(&mut OsRng);
        let C = EdwardsPoint::random(&mut OsRng);
        let L = I * x;

        let h_pqc_field = <Selene as Ciphersuite>::F::random(&mut OsRng);
        let h_pqc_bytes: [u8; 32] = h_pqc_field.to_repr();

        let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
        let tree_root_point: <Selene as Ciphersuite>::G = *SELENE_HASH_INIT
            + multiexp_vartime(&[
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(O).unwrap().0,
                    generators[0],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(I).unwrap().0,
                    generators[1],
                ),
                (
                    <EdwardsPoint as DivisorCurve>::to_xy(C).unwrap().0,
                    generators[2],
                ),
                (h_pqc_field, generators[3]),
            ]);
        let tree_root: [u8; 32] = tree_root_point.to_bytes();

        let o_bytes = O.to_bytes();
        let i_bytes = I.to_bytes();
        let c_bytes = C.to_bytes();

        let a = Scalar::random(&mut OsRng);
        let input = ProveInput {
            output_key: o_bytes,
            key_image_gen: i_bytes,
            commitment: c_bytes,
            h_pqc: PqcLeafScalar(h_pqc_bytes),
            spend_key_x: x.to_repr(),
            spend_key_y: y.to_repr(),
            commitment_mask: z.to_repr(),
            pseudo_out_blind: a.to_repr(),
            leaf_chunk_outputs: vec![(o_bytes, i_bytes, c_bytes)],
            leaf_chunk_h_pqc: vec![h_pqc_bytes],
            c1_branch_layers: vec![],
            c2_branch_layers: vec![],
        };

        let result = prove(&[input], &tree_root, tree_depth, signable_tx_hash)
            .expect("prove with O=xG+yT and real y must succeed");

        let key_images = [L.to_bytes()];
        let ok = verify(
            &result.proof,
            &key_images,
            &result.pseudo_outs,
            &[PqcLeafScalar(h_pqc_bytes)],
            &tree_root,
            tree_depth,
            signable_tx_hash,
        )
        .expect("verify must not error");
        assert!(ok, "valid two-component proof must verify");
    }
}
