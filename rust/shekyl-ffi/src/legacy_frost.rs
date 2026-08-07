// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FROST/SAL threshold signing FFI.

#[cfg(feature = "multisig")]
/// Create a new FROST SAL session for one input.
///
/// `output_key_ptr`, `key_image_gen_ptr`, `commitment_ptr`: 32-byte compressed
/// Ed25519 points. `spend_key_x_ptr`, `signable_tx_hash_ptr`: 32 bytes each.
///
/// Returns an opaque session handle, or null on failure.
/// The returned pseudo-out (32 bytes) is written to `pseudo_out_ptr`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_sal_session_new(
    output_key_ptr: *const u8,
    key_image_gen_ptr: *const u8,
    commitment_ptr: *const u8,
    spend_key_x_ptr: *const u8,
    signable_tx_hash_ptr: *const u8,
    pseudo_out_ptr: *mut u8,
) -> *mut ShekylFrostSalSession {
    if output_key_ptr.is_null()
        || key_image_gen_ptr.is_null()
        || commitment_ptr.is_null()
        || spend_key_x_ptr.is_null()
        || signable_tx_hash_ptr.is_null()
        || pseudo_out_ptr.is_null()
    {
        return std::ptr::null_mut();
    }

    let read32 = |ptr: *const u8| -> [u8; 32] {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let input_data = shekyl_fcmp::frost_sal::FrostSalInput {
        output_key: read32(output_key_ptr),
        key_image_gen: read32(key_image_gen_ptr),
        commitment: read32(commitment_ptr),
        spend_key_x: read32(spend_key_x_ptr),
        signable_tx_hash: read32(signable_tx_hash_ptr),
    };

    match shekyl_fcmp::frost_sal::FrostSalSession::new(&input_data) {
        Ok(session) => {
            std::ptr::copy_nonoverlapping(session.pseudo_out().as_ptr(), pseudo_out_ptr, 32);
            Box::into_raw(Box::new(ShekylFrostSalSession(session)))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(feature = "multisig")]
/// Get the serialized `RerandomizedOutput` from a FROST SAL session.
///
/// Returns a buffer that can be deserialized by peers to reconstruct
/// the rerandomized tuple for signing. The caller must free the buffer.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_sal_get_rerand(
    session: *const ShekylFrostSalSession,
) -> ShekylBuffer {
    if session.is_null() {
        return ShekylBuffer::null();
    }
    let session = &*session;
    let mut data = Vec::new();
    if session.0.rerandomized_output().write(&mut data).is_err() {
        return ShekylBuffer::null();
    }
    ShekylBuffer::from_vec(data)
}

// ─── FROST Signing Coordinator FFI ───────────────────────────────────────────

#[cfg(feature = "multisig")]
#[cfg(feature = "multisig")]
/// Feed one participant's nonce commitments to the coordinator.
///
/// `participant`: 1-based participant index.
/// `data_ptr`: `num_inputs` contiguous 32-byte compressed point commitments.
/// Returns true on success.
///
/// # Safety
/// `coord` must be a valid handle. `data_ptr` must point to `num_inputs * 32` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_add_preprocesses(
    coord: *mut ShekylFrostCoordinator,
    participant: u16,
    data_ptr: *const u8,
    num_inputs: u32,
) -> bool {
    if coord.is_null() || data_ptr.is_null() {
        return false;
    }
    let Some(p) = modular_frost::Participant::new(participant) else {
        return false;
    };
    let coord = &mut *coord;
    let n = num_inputs as usize;

    let mut preprocesses = Vec::with_capacity(n);
    for i in 0..n {
        let offset = i * 32;
        let slice = std::slice::from_raw_parts(data_ptr.add(offset), 32);
        preprocesses.push(shekyl_fcmp::frost_sal::FrostPreprocessResult {
            nonce_commitments: slice.to_vec(),
            addendum: Vec::new(),
        });
    }

    coord.0.collect_preprocesses(p, preprocesses).is_ok()
}

#[cfg(feature = "multisig")]
/// Get aggregated nonce sums from the coordinator.
///
/// Returns a `ShekylBuffer` with `num_inputs * 32` bytes (one 32-byte nonce sum per input).
/// Caller must free via `shekyl_buffer_free`.
///
/// # Safety
/// `coord` must be a valid handle with all preprocesses collected.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_nonce_sums(
    coord: *mut ShekylFrostCoordinator,
) -> ShekylBuffer {
    if coord.is_null() {
        return ShekylBuffer::null();
    }
    let coord = &mut *coord;
    match coord.0.nonce_sums_bytes() {
        Ok(per_input) => {
            let mut flat = Vec::new();
            for bytes in per_input {
                flat.extend_from_slice(&bytes);
            }
            ShekylBuffer::from_vec(flat)
        }
        Err(_) => ShekylBuffer::null(),
    }
}

#[cfg(feature = "multisig")]
/// Feed one participant's partial shares to the coordinator.
///
/// `data_ptr`: `num_inputs` contiguous 32-byte scalar shares.
///
/// # Safety
/// `coord` must be a valid handle. `data_ptr` must point to `num_inputs * 32` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_add_shares(
    coord: *mut ShekylFrostCoordinator,
    participant: u16,
    data_ptr: *const u8,
    num_inputs: u32,
) -> bool {
    if coord.is_null() || data_ptr.is_null() {
        return false;
    }
    let Some(p) = modular_frost::Participant::new(participant) else {
        return false;
    };
    let coord = &mut *coord;
    let n = num_inputs as usize;

    let mut shares = Vec::with_capacity(n);
    for i in 0..n {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(data_ptr.add(i * 32), buf.as_mut_ptr(), 32);
        shares.push(shekyl_fcmp::frost_sal::FrostSignShareResult { share: buf });
    }

    coord.0.collect_shares(p, &shares).is_ok()
}

#[cfg(feature = "multisig")]
/// Aggregate all inputs: consume sessions + coordinator, produce FCMP++ proof.
///
/// `session_ptrs`: `num_inputs` session handles. Consumed on success.
/// `group_key_ptr`: 32-byte Ed25519T group public key.
/// `witness_ptr/witness_len`: full witness blob for `prove_with_sal`.
/// `tree_depth`: curve tree depth.
///
/// # Safety
/// All sessions and the coordinator are consumed on success and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_aggregate_and_prove(
    coord: *mut ShekylFrostCoordinator,
    session_ptrs: *const *mut ShekylFrostSalSession,
    num_inputs: u32,
    group_key_ptr: *const u8,
    witness_ptr: *const u8,
    witness_len: usize,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylFcmpProveResult {
    let fail = ShekylFcmpProveResult {
        proof: ShekylBuffer::null(),
        pseudo_outs: ShekylBuffer::null(),
        success: false,
    };

    if coord.is_null()
        || session_ptrs.is_null()
        || group_key_ptr.is_null()
        || witness_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return fail;
    }

    let n = num_inputs as usize;
    if n == 0 || n > shekyl_fcmp::MAX_INPUTS {
        return fail;
    }

    let read32 = |ptr: *const u8| -> [u8; 32] {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let group_key_bytes = read32(group_key_ptr);
    let Some(witness) = (unsafe { slice_from_ptr(witness_ptr, witness_len) }) else {
        return fail;
    };

    use ciphersuite::group::GroupEncoding;
    let gk_ct = <dalek_ff_group::EdwardsPoint as GroupEncoding>::from_bytes(&group_key_bytes);
    if bool::from(gk_ct.is_none()) {
        return fail;
    }
    let group_key: dalek_ff_group::EdwardsPoint = gk_ct.unwrap();

    let Some(prove_inputs) = parse_prove_witness(witness, n) else {
        return fail;
    };

    let mut coord_box = Box::from_raw(coord);

    let mut sessions: Vec<shekyl_fcmp::frost_sal::FrostSalSession> = Vec::with_capacity(n);
    for i in 0..n {
        let ptr = *session_ptrs.add(i);
        if ptr.is_null() {
            return fail;
        }
        sessions.push(unsafe { Box::from_raw(ptr) }.0);
    }

    let original_outputs: Vec<_> = sessions.iter().map(|s| *s.original_output()).collect();
    let rerands: Vec<_> = sessions
        .iter()
        .map(|s| s.rerandomized_output().clone())
        .collect();
    let pseudo_outs_flat: Vec<u8> = sessions
        .iter()
        .flat_map(|s| s.pseudo_out().iter().copied())
        .collect();

    let leaf_chunks: Vec<_> = prove_inputs
        .iter()
        .map(|pi| shekyl_fcmp::proof::ProveInputLeafChunk {
            output_h_pqc: pi.h_pqc,
            leaf_outputs: pi.leaf_chunk_outputs.clone(),
            leaf_h_pqc: pi.leaf_chunk_h_pqc.clone(),
            c1_branch_layers: pi.c1_branch_layers.clone(),
            c2_branch_layers: pi.c2_branch_layers.clone(),
        })
        .collect();

    let Ok(sal_pairs) = coord_box.0.aggregate_all(sessions, group_key) else {
        return fail;
    };

    match shekyl_fcmp::proof::prove_with_sal(
        sal_pairs,
        &original_outputs,
        &rerands,
        &leaf_chunks,
        tree_depth,
    ) {
        Ok(result) => ShekylFcmpProveResult {
            proof: ShekylBuffer::from_vec(result.proof.data),
            pseudo_outs: ShekylBuffer::from_vec(pseudo_outs_flat),
            success: true,
        },
        Err(_) => fail,
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST signing coordinator handle.
///
/// # Safety
/// `coord` must be a valid handle or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_free(coord: *mut ShekylFrostCoordinator) {
    if !coord.is_null() {
        drop(Box::from_raw(coord));
    }
}

// ─── FROST Signer FFI ───────────────────────────────────────────────────────

#[cfg(feature = "multisig")]
/// Signer-side: preprocess a session to generate nonce commitments.
///
/// `session`: a FROST SAL session handle.
/// `keys_handle`: threshold keys handle.
///
/// Returns nonce commitments (32 bytes for SalAlgorithm) as a `ShekylBuffer`.
///
/// # Safety
/// Both handles must be valid.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_signer_preprocess(
    session: *mut ShekylFrostSalSession,
    keys_handle: *const ShekylFrostThresholdKeys,
) -> ShekylBuffer {
    if session.is_null() || keys_handle.is_null() {
        return ShekylBuffer::null();
    }
    let session = &mut *session;
    let keys_handle = &*keys_handle;

    let Ok(keys) = keys_handle.0.deserialize() else {
        return ShekylBuffer::null();
    };

    match session.0.preprocess(&keys) {
        Ok(result) => ShekylBuffer::from_vec(result.nonce_commitments),
        Err(_) => ShekylBuffer::null(),
    }
}

#[cfg(feature = "multisig")]
/// Signer-side: produce a partial signature share for one input.
///
/// `session`: FROST SAL session (must have been preprocessed).
/// `keys_handle`: threshold keys.
/// `included_ptr`: array of participant indices in the signing set.
/// `num_included`: number of participants.
/// `nonce_sums_ptr`: 32 bytes of aggregated nonce sums for this input.
///
/// Returns 32-byte partial share as a `ShekylBuffer`.
///
/// # Safety
/// All pointers must be valid. `included_ptr` must have `num_included` u16 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_signer_sign(
    session: *mut ShekylFrostSalSession,
    keys_handle: *const ShekylFrostThresholdKeys,
    included_ptr: *const u16,
    num_included: u32,
    nonce_sums_ptr: *const u8,
) -> ShekylBuffer {
    if session.is_null()
        || keys_handle.is_null()
        || included_ptr.is_null()
        || nonce_sums_ptr.is_null()
    {
        return ShekylBuffer::null();
    }

    let session = &mut *session;
    let keys_handle = &*keys_handle;

    let Ok(keys) = keys_handle.0.deserialize() else {
        return ShekylBuffer::null();
    };

    let included: Vec<modular_frost::Participant> = (0..num_included as usize)
        .filter_map(|i| {
            let idx = *included_ptr.add(i);
            modular_frost::Participant::new(idx)
        })
        .collect();

    let view = keys.view(included).unwrap();

    let mut nonce_sum_bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(nonce_sums_ptr, nonce_sum_bytes.as_mut_ptr(), 32);

    use ciphersuite::group::GroupEncoding;
    let nonce_sum_ct =
        <dalek_ff_group::EdwardsPoint as GroupEncoding>::from_bytes(&nonce_sum_bytes);
    if bool::from(nonce_sum_ct.is_none()) {
        return ShekylBuffer::null();
    }
    let nonce_sums = vec![vec![nonce_sum_ct.unwrap()]];

    match session.0.sign_share(&view, &nonce_sums) {
        Ok(result) => ShekylBuffer::from_vec(result.share.to_vec()),
        Err(_) => ShekylBuffer::null(),
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST SAL session handle.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_sal_session_free(session: *mut ShekylFrostSalSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

// ─── FCMP++: FROST DKG Key Management ───────────────────────────────────────

#[cfg(feature = "multisig")]
#[cfg(feature = "multisig")]
/// Export FROST threshold keys as a serialized blob.
/// Returns a ShekylBuffer with the serialized data, or empty on failure.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_export(
    handle: *const ShekylFrostThresholdKeys,
) -> ShekylBuffer {
    let fail = ShekylBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    if handle.is_null() {
        return fail;
    }
    let keys = &*handle;
    let bytes = keys.0.as_bytes().to_vec();
    let len = bytes.len();
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
    ShekylBuffer { ptr, len }
}

#[cfg(feature = "multisig")]
/// Get the 32-byte group public key from threshold keys.
/// Writes 32 bytes to `out_ptr`. Returns true on success.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_group_key(
    handle: *const ShekylFrostThresholdKeys,
    out_ptr: *mut u8,
) -> bool {
    if handle.is_null() || out_ptr.is_null() {
        return false;
    }
    let keys_handle = &*handle;
    match keys_handle.0.deserialize() {
        Ok(keys) => {
            let gk = shekyl_fcmp::frost_dkg::group_key_bytes(&keys);
            std::ptr::copy_nonoverlapping(gk.as_ptr(), out_ptr, 32);
            true
        }
        Err(_) => false,
    }
}

#[cfg(feature = "multisig")]
/// Validate that threshold keys match expected M-of-N parameters.
/// Returns true if valid.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_validate(
    handle: *const ShekylFrostThresholdKeys,
    expected_m: u16,
    expected_n: u16,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let keys_handle = &*handle;
    match keys_handle.0.deserialize() {
        Ok(keys) => shekyl_fcmp::frost_dkg::validate_keys(&keys, expected_m, expected_n).is_ok(),
        Err(_) => false,
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST threshold keys handle.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_free(handle: *mut ShekylFrostThresholdKeys) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Opaque handle for the FROST signing coordinator.
#[cfg(feature = "multisig")]
pub struct ShekylFrostCoordinator(shekyl_fcmp::frost_sal::FrostSigningCoordinator);

#[cfg(feature = "multisig")]
/// Create a FROST signing coordinator for `num_inputs` inputs.
///
/// `included_ptr`: array of `num_included` u16 participant indices.
/// Returns an opaque handle, or null on failure.
///
/// # Safety
/// `included_ptr` must point to `num_included` valid u16 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_new(
    num_inputs: u32,
    included_ptr: *const u16,
    num_included: u32,
) -> *mut ShekylFrostCoordinator {
    if included_ptr.is_null() || num_included == 0 || num_inputs == 0 {
        return std::ptr::null_mut();
    }

    let included: Vec<modular_frost::Participant> = (0..num_included as usize)
        .filter_map(|i| {
            let idx = *included_ptr.add(i);
            modular_frost::Participant::new(idx)
        })
        .collect();

    if included.len() != num_included as usize {
        return std::ptr::null_mut();
    }

    match shekyl_fcmp::frost_sal::FrostSigningCoordinator::new_for_sal(
        num_inputs as usize,
        included,
    ) {
        Ok(c) => Box::into_raw(Box::new(ShekylFrostCoordinator(c))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Opaque handle for stored FROST threshold keys.
#[cfg(feature = "multisig")]
pub struct ShekylFrostThresholdKeys(shekyl_fcmp::frost_dkg::SerializedThresholdKeys);

#[cfg(feature = "multisig")]
/// Import FROST threshold keys from a serialized blob.
/// Returns an opaque handle, or NULL if deserialization fails.
/// The caller must later free the handle with `shekyl_frost_keys_free`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_import(
    data_ptr: *const u8,
    data_len: usize,
) -> *mut ShekylFrostThresholdKeys {
    if data_ptr.is_null() || data_len == 0 {
        return std::ptr::null_mut();
    }
    let data = std::slice::from_raw_parts(data_ptr, data_len);
    let serialized = shekyl_fcmp::frost_dkg::SerializedThresholdKeys::from_bytes(data);
    if serialized.deserialize().is_err() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(ShekylFrostThresholdKeys(serialized)))
}
