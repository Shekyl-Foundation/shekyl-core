// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FCMP++ prove/verify and related leaf/auth FFI.

use super::legacy_types::*;
use super::legacy_util::*;

// ─── FCMP++: Generators ─────────────────────────────────────────────────────

/// Write the compressed Ed25519 bytes of generator T to `out_ptr` (32 bytes).
///
/// T = hash_to_point(keccak256("Monero Generator T")) — the generator used
/// to blind the key-image commitment in two-component output keys: O = xG + yT.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generator_T(out_ptr: *mut u8) {
    use ciphersuite::group::GroupEncoding;
    if out_ptr.is_null() {
        return;
    }
    let t_bytes: [u8; 32] = shekyl_curve_generators::T.to_bytes();
    std::ptr::copy_nonoverlapping(t_bytes.as_ptr(), out_ptr, 32);
}

// ─── FCMP++: Proof and Tree Operations ──────────────────────────────────────

/// Compute H(pqc_pk) leaf scalar for a PQC public key.
///
/// Writes 32 bytes to `out_ptr`. Returns true on success.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_pqc_leaf_hash(
    pqc_pk_ptr: *const u8,
    pqc_pk_len: usize,
    out_ptr: *mut u8,
) -> bool {
    let Some(pk_bytes) = (unsafe { slice_from_ptr(pqc_pk_ptr, pqc_pk_len) }) else {
        return false;
    };
    if out_ptr.is_null() {
        return false;
    }
    let hash = shekyl_crypto_pq::derivation::hash_pqc_public_key(pk_bytes);
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, 32);
    true
}

/// Derive `h_pqc = H(hybrid_public_key)` from combined shared secret and output
/// index. Secret key is derived internally, used for public key derivation only,
/// and zeroized immediately. No secret material crosses this boundary.
///
/// # Safety
/// - `combined_ss_ptr` must point to 64 bytes.
/// - `h_pqc_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_pqc_leaf_hash(
    combined_ss_ptr: *const u8,
    output_index: u64,
    h_pqc_out: *mut u8,
) -> bool {
    if combined_ss_ptr.is_null() || h_pqc_out.is_null() {
        return false;
    }
    let mut ss = [0u8; 64];
    std::ptr::copy_nonoverlapping(combined_ss_ptr, ss.as_mut_ptr(), 64);

    match shekyl_crypto_pq::derivation::derive_pqc_leaf_hash(&ss, output_index) {
        Ok(hash) => {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), h_pqc_out, 32);
            true
        }
        Err(_) => false,
    }
}

/// Derive the canonical hybrid public key bytes from combined shared secret and
/// output index. No secret material crosses this boundary.
///
/// # Safety
/// - `combined_ss_ptr` must point to 64 bytes.
/// - Returns a heap-allocated ShekylBuffer that must be freed with `shekyl_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_pqc_public_key(
    combined_ss_ptr: *const u8,
    output_index: u64,
) -> ShekylBuffer {
    if combined_ss_ptr.is_null() {
        return ShekylBuffer::null();
    }
    let mut ss = [0u8; 64];
    std::ptr::copy_nonoverlapping(combined_ss_ptr, ss.as_mut_ptr(), 64);

    match shekyl_crypto_pq::derivation::derive_pqc_public_key(&ss, output_index) {
        Ok(pk) => ShekylBuffer::from_vec(pk),
        Err(_) => ShekylBuffer::null(),
    }
}

/// Derive all per-output secrets from the combined KEM shared secret.
///
/// Writes to 7 output pointers: ho(32), y(32), z(32), k_amount(32),
/// view_tag_combined(1), amount_tag(1), ml_dsa_seed(32). All pointers must be
/// non-null and point to writable memory of the stated size.
///
/// Returns true on success, false if any pointer is null.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_output_secrets(
    combined_ss_ptr: *const u8,
    combined_ss_len: u32,
    output_index: u64,
    out_ho: *mut u8,
    out_y: *mut u8,
    out_z: *mut u8,
    out_k_amount: *mut u8,
    out_view_tag_combined: *mut u8,
    out_amount_tag: *mut u8,
    out_ml_dsa_seed: *mut u8,
) -> bool {
    if combined_ss_ptr.is_null()
        || out_ho.is_null()
        || out_y.is_null()
        || out_z.is_null()
        || out_k_amount.is_null()
        || out_view_tag_combined.is_null()
        || out_amount_tag.is_null()
        || out_ml_dsa_seed.is_null()
    {
        return false;
    }

    let ss = std::slice::from_raw_parts(combined_ss_ptr, combined_ss_len as usize);

    let secrets = shekyl_crypto_pq::derivation::derive_output_secrets(ss, output_index);

    std::ptr::copy_nonoverlapping(secrets.ho.as_ptr(), out_ho, 32);
    std::ptr::copy_nonoverlapping(secrets.y.as_ptr(), out_y, 32);
    std::ptr::copy_nonoverlapping(secrets.z.as_ptr(), out_z, 32);
    std::ptr::copy_nonoverlapping(secrets.k_amount.as_ptr(), out_k_amount, 32);
    *out_view_tag_combined = secrets.view_tag_combined;
    *out_amount_tag = secrets.amount_tag;
    std::ptr::copy_nonoverlapping(secrets.ml_dsa_seed.as_ptr(), out_ml_dsa_seed, 32);

    true
}

/// Derive the ML-KEM-keyed view-tag pre-filter byte (FA-6).
///
/// `ml_kem_ss_ptr` must point to exactly 32 bytes. Returns the 1-byte wire tag.
/// Returns 0 if the pointer is null (callers should check for null separately).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_view_tag_prefilter(
    ml_kem_ss_ptr: *const u8,
    output_index: u64,
) -> u8 {
    if ml_kem_ss_ptr.is_null() {
        return 0;
    }
    let ss: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ml_kem_ss_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    shekyl_crypto_pq::derivation::derive_view_tag_prefilter(&ss, output_index)
}

// Witness parsing exists for one consumer: the FROST multisig coordinator
// in `legacy_frost`, whose entire surface is `feature = "multisig"`. The
// same cfg here is the compiler-enforced statement of that: the default
// build has no witness reader because nothing in it reads a witness.
#[cfg(feature = "multisig")]
/// Parse the serialized FCMP++ prove witness into typed prove inputs.
///
/// This function owns the witness wire format. It is consumed by the FROST
/// multisig coordinator (`shekyl_frost_coordinator_aggregate_and_prove`),
/// which is the only remaining reader; the C-ABI writer for the fixed header
/// is `shekyl_fcmp_build_witness_header`, and the two are pinned against each
/// other by `witness_header_build_then_parse_roundtrip` over
/// `docs/test_vectors/WITNESS_HEADER.json`.
///
/// Wire format (all multi-byte integers are little-endian):
///
/// ```text
/// For each of `num_inputs` inputs, sequentially:
///   Fixed header (SHEKYL_PROVE_WITNESS_HEADER_BYTES = 256 bytes, 8 fields):
///     [O:32][I:32][C:32][h_pqc:32][spend_x:32][spend_y:32][z:32][a:32]
///     O, I, C are compressed Ed25519 output points.
///     z is the Pedersen commitment mask.
///     a is the desired blinding factor for this input's pseudo-out
///       commitment (r_c = a - spend_y).
///   Leaf chunk (variable):
///     leaf_chunk_count: u32
///     For each entry (128 bytes):
///       [O:32][I:32][C:32][h_pqc:32]  (compressed Ed25519 points + PQC hash)
///   C1 (Selene) branch layers (variable):
///     c1_layer_count: u32
///     For each layer:
///       sibling_count: u32
///       siblings: sibling_count * 32 bytes (Selene scalars)
///   C2 (Helios) branch layers (variable):
///     c2_layer_count: u32
///     For each layer:
///       sibling_count: u32
///       siblings: sibling_count * 32 bytes (Helios scalars)
/// ```
///
/// The field list is the authority for `ProveInputFields` and for the JSON
/// vectors; all three must agree, and the round-trip test is what makes a
/// disagreement fail rather than silently misalign every subsequent input.
pub(crate) fn parse_prove_witness(
    data: &[u8],
    num_inputs: usize,
) -> Option<Vec<shekyl_fcmp::proof::ProveInput>> {
    let mut offset = 0usize;
    let mut inputs = Vec::with_capacity(num_inputs);

    for _ in 0..num_inputs {
        if offset + SHEKYL_PROVE_WITNESS_HEADER_BYTES > data.len() {
            return None;
        }

        let mut output_key = [0u8; 32];
        let mut key_image_gen = [0u8; 32];
        let mut commitment = [0u8; 32];
        let mut h_pqc = [0u8; 32];
        let mut spend_key_x = [0u8; 32];
        let mut spend_key_y = [0u8; 32];
        let mut commitment_mask = [0u8; 32];
        let mut pseudo_out_blind = [0u8; 32];

        output_key.copy_from_slice(&data[offset..offset + 32]);
        key_image_gen.copy_from_slice(&data[offset + 32..offset + 64]);
        commitment.copy_from_slice(&data[offset + 64..offset + 96]);
        h_pqc.copy_from_slice(&data[offset + 96..offset + 128]);
        spend_key_x.copy_from_slice(&data[offset + 128..offset + 160]);
        spend_key_y.copy_from_slice(&data[offset + 160..offset + 192]);
        commitment_mask.copy_from_slice(&data[offset + 192..offset + 224]);
        pseudo_out_blind
            .copy_from_slice(&data[offset + 224..offset + SHEKYL_PROVE_WITNESS_HEADER_BYTES]);
        offset += SHEKYL_PROVE_WITNESS_HEADER_BYTES;

        let (leaf_chunk_outputs, leaf_chunk_h_pqc) = parse_leaf_chunks(data, &mut offset)?;
        let c1_branch_layers = parse_branch_layers(data, &mut offset)?;
        let c2_branch_layers = parse_branch_layers(data, &mut offset)?;

        inputs.push(shekyl_fcmp::proof::ProveInput {
            output_key,
            key_image_gen,
            commitment,
            h_pqc: shekyl_fcmp::leaf::PqcLeafScalar(h_pqc),
            spend_key_x,
            spend_key_y,
            commitment_mask,
            pseudo_out_blind,
            leaf_chunk_outputs,
            leaf_chunk_h_pqc,
            c1_branch_layers,
            c2_branch_layers,
        });
    }

    Some(inputs)
}

#[cfg(feature = "multisig")]
fn read_u32_le(data: &[u8], offset: &mut usize) -> Option<usize> {
    let bytes = data.get(*offset..*offset + 4)?;
    *offset += 4;
    Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize)
}

#[cfg(feature = "multisig")]
type LeafChunkOutput = ([u8; 32], [u8; 32], [u8; 32]);

#[cfg(feature = "multisig")]
fn parse_leaf_chunks(
    data: &[u8],
    offset: &mut usize,
) -> Option<(Vec<LeafChunkOutput>, Vec<[u8; 32]>)> {
    let chunk_count = read_u32_le(data, offset)?;
    let remaining = data.len() - *offset;
    let mut outputs = bounded_capacity(chunk_count, 128, remaining)?;
    let mut h_pqc = bounded_capacity(chunk_count, 128, remaining)?;
    for _ in 0..chunk_count {
        let chunk = data.get(*offset..*offset + 128)?;
        let mut lo = [0u8; 32];
        let mut li = [0u8; 32];
        let mut lc = [0u8; 32];
        let mut lh = [0u8; 32];
        lo.copy_from_slice(&chunk[..32]);
        li.copy_from_slice(&chunk[32..64]);
        lc.copy_from_slice(&chunk[64..96]);
        lh.copy_from_slice(&chunk[96..128]);
        outputs.push((lo, li, lc));
        h_pqc.push(lh);
        *offset += 128;
    }
    Some((outputs, h_pqc))
}

/// C1 and C2 branch layers share a wire shape: a u32 layer count, then
/// per layer a u32 sibling count and that many 32-byte scalars. One
/// parser so the sibling-count reserve goes through [`bounded_capacity`].
#[cfg(feature = "multisig")]
fn parse_branch_layers(
    data: &[u8],
    offset: &mut usize,
) -> Option<Vec<shekyl_fcmp::proof::BranchLayer>> {
    let count = read_u32_le(data, offset)?;
    // Protocol ceiling, not just a backing bound: a layer costs only a
    // 4-byte header on the wire but a `BranchLayer` plus per-layer padding
    // work in `prove` — so a genuinely BACKED blob could otherwise buy
    // ~2.5M empty layers per 10 MiB (memory/CPU amplification). No valid
    // witness has more branch layers per curve than the tree's maximum
    // depth; the exact C1/C2 alternation split stays the proof library's
    // contract (`prove` validates the path), not re-derived here.
    if count > shekyl_fcmp::MAX_TREE_DEPTH as usize {
        return None;
    }
    let remaining = data.len() - *offset;
    let mut layers = bounded_capacity(count, 4, remaining)?;
    for _ in 0..count {
        let sib_count = read_u32_le(data, offset)?;
        let remaining = data.len() - *offset;
        let mut siblings = bounded_capacity(sib_count, 32, remaining)?;
        for _ in 0..sib_count {
            let bytes = data.get(*offset..*offset + 32)?;
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(bytes);
            siblings.push(scalar);
            *offset += 32;
        }
        layers.push(shekyl_fcmp::proof::BranchLayer { siblings });
    }
    Some(layers)
}

/// Verify an FCMP++ proof with batch verification.
///
/// Returns 0 on success, or a nonzero `VerifyError` discriminant (1-7) on failure:
///   1=DeserializationFailed, 2=InvalidTreeRoot, 3=PqcCommitmentMismatch,
///   4=KeyImageCountMismatch, 5=UpstreamError, 6=BatchVerificationFailed,
///   7=TreeDepthTooLarge
///
/// `signable_tx_hash_ptr`: 32-byte hash that binds the proof to the transaction.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_verify(
    proof_ptr: *const u8,
    proof_len: usize,
    key_images_ptr: *const u8,
    ki_count: usize,
    pseudo_outs_ptr: *const u8,
    po_count: usize,
    pqc_pk_hashes_ptr: *const u8,
    pqc_hash_count: usize,
    tree_root_ptr: *const u8,
    tree_depth: u8,
    signable_tx_hash_ptr: *const u8,
) -> u8 {
    // Mirror of the membership-only entry point's hardening (PR #229 r2): reject
    // count mismatches and out-of-range arity BEFORE slicing or allocating, and
    // guard the ×32 byte-length multiplies against usize overflow. All reject
    // paths keep this function's existing invalid-parameters code (1), so the
    // error surface is unchanged.
    if ki_count != po_count || ki_count != pqc_hash_count {
        return 1; // DeserializationFailed (invalid parameters)
    }
    if ki_count == 0 || ki_count > shekyl_fcmp::MAX_INPUTS {
        return 1;
    }
    let (Some(ki_len), Some(po_len), Some(ph_len)) = (
        ki_count.checked_mul(32),
        po_count.checked_mul(32),
        pqc_hash_count.checked_mul(32),
    ) else {
        return 1;
    };
    let Some(proof_bytes) = (unsafe { slice_from_ptr(proof_ptr, proof_len) }) else {
        return 1; // DeserializationFailed
    };
    let Some(ki_bytes) = (unsafe { slice_from_ptr(key_images_ptr, ki_len) }) else {
        return 1;
    };
    let Some(po_bytes) = (unsafe { slice_from_ptr(pseudo_outs_ptr, po_len) }) else {
        return 1;
    };
    let Some(ph_bytes) = (unsafe { slice_from_ptr(pqc_pk_hashes_ptr, ph_len) }) else {
        return 1;
    };
    if tree_root_ptr.is_null() || signable_tx_hash_ptr.is_null() {
        return 1;
    }
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let signable_tx_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(signable_tx_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    // The `tree_depth` parameter is the upstream library's `layers` count,
    // not the LMDB tree depth: callers convert with `layers = lmdb_depth + 1`
    // before calling. Stated here rather than cross-referenced -- this was the
    // convention's only remaining statement after the legacy prove entry point
    // that used to document it was deleted.

    let proof = shekyl_fcmp::proof::ShekylFcmpProof {
        data: proof_bytes.to_vec(),
        #[allow(clippy::cast_possible_truncation)]
        num_inputs: ki_count as u32,
        tree_depth,
    };

    let mut key_images: Vec<shekyl_fcmp::proof::KeyImage> = Vec::with_capacity(ki_count);
    let mut pseudo_outs = Vec::with_capacity(po_count);
    let mut pqc_hashes = Vec::with_capacity(pqc_hash_count);

    for i in 0..ki_count {
        let mut ki = [0u8; 32];
        ki.copy_from_slice(&ki_bytes[i * 32..(i + 1) * 32]);
        key_images.push(shekyl_fcmp::proof::KeyImage::from_canonical_bytes(ki));

        let mut po = [0u8; 32];
        po.copy_from_slice(&po_bytes[i * 32..(i + 1) * 32]);
        pseudo_outs.push(po);

        let mut ph = [0u8; 32];
        ph.copy_from_slice(&ph_bytes[i * 32..(i + 1) * 32]);
        pqc_hashes.push(shekyl_fcmp::leaf::PqcLeafScalar(ph));
    }

    match shekyl_fcmp::proof::verify(
        &proof,
        &key_images,
        &pseudo_outs,
        &pqc_hashes,
        &tree_root,
        tree_depth,
        signable_tx_hash,
    ) {
        Ok(true) => 0,
        Ok(false) => 6, // BatchVerificationFailed
        Err(e) => {
            tracing::debug!(error = ?e, tree_depth, "verify error");
            e.discriminant()
        }
    }
}

/// Verify a **membership-only** FCMP++ proof (reward-emission backing; **no key
/// image**). Mirror of [`shekyl_fcmp_verify`] with the key-image array removed — the
/// ABI the C++ emission-vin shim (PR-E3) calls. Returns `0` on success, else the
/// [`shekyl_fcmp::proof::VerifyError`] discriminant: `1=Deserialization` (also a null
/// pointer, a count that is `0` or exceeds [`shekyl_fcmp::MAX_INPUTS`], or a `× 32`
/// byte-length `usize` overflow), `2=InvalidTreeRoot`, `3=PqcCommitmentMismatch`,
/// `5=UpstreamError`, `6=BatchVerificationFailed`, `7=TreeDepthTooLarge`,
/// `8=InputCountMismatch` (`po_count != pqc_hash_count`, checked before any slicing). Never
/// `4` (`KeyImageCountMismatch`) — this path has no key images. Anti-replay is the
/// emission per-epoch dedup, not a key image; the hybrid leaf-gated auth check is
/// step 8 of the coarse `shekyl_emission_vin_verify` call
/// (`shekyl_archival_retention::emission_verify::emission_vin_verify_auth`).
///
/// # Safety
/// Every pointer must be valid for its stated length; `tree_root_ptr` and
/// `signable_tx_hash_ptr` must each point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_membership_only_verify(
    proof_ptr: *const u8,
    proof_len: usize,
    pseudo_outs_ptr: *const u8,
    po_count: usize,
    pqc_pk_hashes_ptr: *const u8,
    pqc_hash_count: usize,
    tree_root_ptr: *const u8,
    tree_depth: u8,
    signable_tx_hash_ptr: *const u8,
) -> u8 {
    // Reject a per-input count mismatch up front — before slicing either buffer, so a mismatch
    // never touches the (attacker-controlled, potentially large) `pqc_pk_hashes_ptr` buffer.
    if po_count != pqc_hash_count {
        return 8; // VerifyError::InputCountMismatch
    }
    // Cap the per-input arity at MAX_INPUTS: a valid proof never
    // exceeds it, so this rejects an oversized attacker-controlled count before any allocation,
    // bounds the `.collect()`s below, and makes `po_count as u32` a lossless narrowing (no
    // truncation). `po_count == pqc_hash_count` is already established, so this bounds both.
    if po_count == 0 || po_count > shekyl_fcmp::MAX_INPUTS {
        return 1; // DeserializationFailed — malformed / oversized request
    }
    // Byte-length multiply is now bounded (<= MAX_INPUTS * 32); keep the checked form as
    // defense-in-depth against a future cap change.
    let (Some(po_len), Some(ph_len)) = (po_count.checked_mul(32), pqc_hash_count.checked_mul(32))
    else {
        return 1;
    };
    let Some(proof_bytes) = (unsafe { slice_from_ptr(proof_ptr, proof_len) }) else {
        return 1;
    };
    let Some(po_bytes) = (unsafe { slice_from_ptr(pseudo_outs_ptr, po_len) }) else {
        return 1;
    };
    let Some(ph_bytes) = (unsafe { slice_from_ptr(pqc_pk_hashes_ptr, ph_len) }) else {
        return 1;
    };
    if tree_root_ptr.is_null() || signable_tx_hash_ptr.is_null() {
        return 1;
    }
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let signable_tx_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(signable_tx_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let proof = shekyl_fcmp::proof::ShekylFcmpProof {
        data: proof_bytes.to_vec(),
        #[allow(clippy::cast_possible_truncation)]
        num_inputs: po_count as u32,
        tree_depth,
    };

    // `po_count == pqc_hash_count` and each slice is exactly that many 32-byte chunks, so
    // `chunks_exact` consumes them fully — no manual indexing, no out-of-bounds risk.
    let pseudo_outs: Vec<[u8; 32]> = po_bytes
        .chunks_exact(32)
        .map(|c| {
            let mut b = [0u8; 32];
            b.copy_from_slice(c);
            b
        })
        .collect();
    let pqc_hashes: Vec<shekyl_fcmp::leaf::PqcLeafScalar> = ph_bytes
        .chunks_exact(32)
        .map(|c| {
            let mut b = [0u8; 32];
            b.copy_from_slice(c);
            shekyl_fcmp::leaf::PqcLeafScalar(b)
        })
        .collect();

    match shekyl_fcmp::proof::verify_membership_only(
        &proof,
        &pseudo_outs,
        &pqc_hashes,
        &tree_root,
        tree_depth,
        signable_tx_hash,
    ) {
        Ok(true) => 0,
        // `verify_membership_only` returns `Ok(true)` or `Err`, so `Ok(false)` is
        // unreachable today; mapped defensively to a non-success code (never 0) so a
        // future `Ok(false)` outcome can never be read as acceptance.
        Ok(false) => 6,
        Err(e) => {
            tracing::debug!(error = ?e, tree_depth, "membership-only verify error");
            e.discriminant()
        }
    }
}

/// Convert raw output data into serialized 4-scalar leaves.
///
/// `outputs_ptr`: packed tuples of `{O.x[32], I.x[32], C.x[32], pqc_pk_hash[32]}`,
/// each 128 bytes. `count` = number of outputs.
///
/// Returns a ShekylBuffer containing the serialized leaves (same format, but validated).
#[no_mangle]
pub extern "C" fn shekyl_fcmp_outputs_to_leaves(
    outputs_ptr: *const u8,
    count: usize,
) -> ShekylBuffer {
    // `count` is the ABI-declared element count of the caller's buffer; the
    // multiply must not wrap (a wrap-scale count would desync the declared
    // byte length from the element count below — the checked-mul guard every
    // other ptr+len count in this crate already carries).
    let Some(total) = count.checked_mul(128) else {
        return ShekylBuffer::null();
    };
    let Some(bytes) = (unsafe { slice_from_ptr(outputs_ptr, total) }) else {
        return ShekylBuffer::null();
    };

    let mut leaves = Vec::with_capacity(count);
    for i in 0..count {
        let chunk: &[u8; 128] = bytes[i * 128..(i + 1) * 128].try_into().unwrap();
        leaves.push(shekyl_fcmp::leaf::ShekylLeaf::from_bytes(chunk));
    }

    let serialized = shekyl_fcmp::tree::leaves_to_bytes(&leaves);
    ShekylBuffer::from_vec(serialized)
}

// Both tests here exercise `parse_prove_witness`, so they carry its feature:
// the hostile-count attack surface exists exactly where the parser does.
#[cfg(all(test, feature = "multisig"))]
mod tests {
    use super::*;

    /// A hostile count field must be refused BEFORE any reservation:
    /// wire counts (`chunk_count`, `c1_count`, `c2_count`, and nested
    /// `sib_count`) go through `bounded_capacity`. Pre-cap a 4-byte
    /// `u32::MAX` drove `Vec::with_capacity` reservations of up to
    /// ~412 GB — allocation failure aborts the whole C++ host process.
    /// Post-cap, a count the remaining bytes cannot back is malformed
    /// input and parses to `None` like every other truncation.
    #[test]
    fn hostile_witness_counts_are_refused_before_any_reservation() {
        // Leaf-chunk count claims u32::MAX with zero backing bytes.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_prove_witness(&blob, 1).is_none());

        // Valid empty leaf chunk, hostile C1 layer count.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_prove_witness(&blob, 1).is_none());

        // Valid empty leaf chunk, one C1 layer, hostile sibling count.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_prove_witness(&blob, 1).is_none());

        // Valid empty leaf chunk + C1, hostile C2 layer count.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_prove_witness(&blob, 1).is_none());

        // Control: the same three counts at 0 with no further bytes parse
        // (structurally empty input set is the caller's concern, not a
        // truncation) — proves the caps refuse the COUNT, not the shape.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_prove_witness(&blob, 1).is_some());
    }

    /// A layer count above `MAX_TREE_DEPTH` is refused even when every
    /// 4-byte header is genuinely BACKED by blob bytes: a layer costs 4
    /// wire bytes but a `BranchLayer` + per-layer prove work, so backing
    /// alone still buys ~2.5M empty layers per 10 MiB (the amplification
    /// this cap closes). Boundary-controlled: exactly `MAX_TREE_DEPTH`
    /// empty layers (all zero sib counts, fully backed) still parse —
    /// the cap is the protocol ceiling, not an off-by-one.
    #[test]
    fn backed_layer_counts_above_max_tree_depth_are_refused() {
        let depth = u32::from(shekyl_fcmp::MAX_TREE_DEPTH);

        // C1 leg: count = MAX_TREE_DEPTH + 1, every header backed.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes()); // chunk_count = 0
        blob.extend_from_slice(&(depth + 1).to_le_bytes());
        for _ in 0..=depth {
            blob.extend_from_slice(&0u32.to_le_bytes()); // backed sib headers
        }
        assert!(parse_prove_witness(&blob, 1).is_none());

        // C2 leg: valid empty C1, hostile-but-backed C2.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes()); // chunk_count = 0
        blob.extend_from_slice(&0u32.to_le_bytes()); // c1_count = 0
        blob.extend_from_slice(&(depth + 1).to_le_bytes());
        for _ in 0..=depth {
            blob.extend_from_slice(&0u32.to_le_bytes());
        }
        assert!(parse_prove_witness(&blob, 1).is_none());

        // Boundary control: exactly MAX_TREE_DEPTH backed empty layers on
        // both curves parse.
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        blob.extend_from_slice(&0u32.to_le_bytes()); // chunk_count = 0
        blob.extend_from_slice(&depth.to_le_bytes());
        for _ in 0..depth {
            blob.extend_from_slice(&0u32.to_le_bytes());
        }
        blob.extend_from_slice(&depth.to_le_bytes());
        for _ in 0..depth {
            blob.extend_from_slice(&0u32.to_le_bytes());
        }
        assert!(parse_prove_witness(&blob, 1).is_some());
    }
}
