// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction sign, construct-output, and merged-scan FFI.
//!
//! Key images, proof secrets, output labels, and wallet-cache AEAD are Rust
//! functions (`shekyl-crypto-pq`, `shekyl-engine-core`, `shekyl-chacha`).
//! The C exports that only forwarded to them are gone. `shekyl_fcmp_build_witness_header`
//! stays: it is the witness-header writer, not a forwarder, and it is pinned
//! to `parse_prove_witness` under `feature = "multisig"`.

use super::legacy_types::*;
use super::legacy_util::*;

fn tx_builder_error_code(e: &shekyl_tx_builder::TxBuilderError) -> i32 {
    use shekyl_tx_builder::TxBuilderError;
    match e {
        TxBuilderError::NoInputs => -10,
        TxBuilderError::TooManyInputs(_) => -11,
        TxBuilderError::NoOutputs => -12,
        TxBuilderError::TooManyOutputs(_) => -13,
        TxBuilderError::ZeroInputAmount { .. } => -14,
        TxBuilderError::ZeroOutputAmount { .. } => -15,
        TxBuilderError::InputAmountOverflow => -16,
        TxBuilderError::OutputAmountOverflow => -17,
        TxBuilderError::InsufficientFunds { .. } => -18,
        TxBuilderError::EmptyLeafChunk { .. } => -19,
        TxBuilderError::LeafChunkTooLarge { .. } => -20,
        TxBuilderError::ZeroTreeDepth => -21,
        TxBuilderError::BranchLayerMismatch { .. } => -22,
        TxBuilderError::InvalidCombinedSsLength { .. } => -23,
        TxBuilderError::BulletproofError(_) => -24,
        TxBuilderError::FcmpProveError(_) => -25,
        TxBuilderError::PqcSignError { .. } => -26,
        TxBuilderError::TreeDepthTooLarge(_) => -27,
        TxBuilderError::WireError(_) => -28,
        // Appended (codes are a stable C++-facing contract; never renumber).
        TxBuilderError::TreeTooShallow { .. } => -29,
        TxBuilderError::BalanceSelfCheck(_) => -30,
        TxBuilderError::SpentOutputNotInLeafChunk { .. } => -31,
        // PL-D3: the chain's leaf for this input is not the wallet's derivation
        // — received but unspendable (rule 82: a typed refusal, not a proof error).
        TxBuilderError::PqcLeafMismatch { .. } => -32,
        TxBuilderError::PqcLeafDerivation { .. } => -33,
    }
}

// ─── Collapsed FCMP++ Signing (PR-wallet Phase 1b) ───────────────────────────

/// Input struct for collapsed signing. C++ passes `combined_ss` + `output_index`
/// instead of `spend_key_x` / `spend_key_y`. Rust derives those internally.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FcmpSignInput {
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    ki: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_blob")]
    combined_ss: Vec<u8>,
    output_index: u64,
    // No `hp_of_O`: the key-image generator is Rust's to derive from the
    // output key (`biased_hash_to_point`); the leaf chunk carries it as
    // `key_image_gen`. The former field's only consumer was the removed
    // `h_pqc` aliasing (census `d-2`), so it left the contract with it.
    amount: u64,
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    commitment_mask: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    commitment: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    output_key: [u8; 32],
    // No `h_pqc` / leaf-opening field: the signer re-derives the input's own
    // PQC leaf commitment and blind from `combined_ss` + `output_index`
    // (`PL-D3`) and checks it against `leaf_chunk` before proving.
    leaf_chunk: Vec<shekyl_tx_builder::LeafEntry>,
    #[serde(with = "shekyl_tx_builder::types::hex_layers")]
    c1_layers: Vec<Vec<[u8; 32]>>,
    #[serde(with = "shekyl_tx_builder::types::hex_layers")]
    c2_layers: Vec<Vec<[u8; 32]>>,
}

impl Drop for FcmpSignInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.combined_ss.zeroize();
        self.commitment_mask.zeroize();
    }
}

/// Collapsed FCMP++ signing: Rust owns all witness assembly.
///
/// C++ passes the wallet master spend key `b` (one value) plus per-input data
/// that includes `combined_ss` + `output_index`. Rust derives `ho` from HKDF,
/// computes `x = ho + b` and `y` internally, then builds `SpendInput` and
/// calls `sign_transaction`. C++ never touches `x`.
///
/// # Safety
/// - `spend_secret_ptr`, `tx_prefix_hash_ptr`: 32 bytes each.
/// - `reference_block_ptr`, `tree_root_ptr`: 32 bytes each.
/// - JSON pointers: valid for their documented lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_fcmp_transaction(
    spend_secret_ptr: *const u8,
    tx_prefix_hash_ptr: *const u8,
    inputs_json_ptr: *const u8,
    inputs_json_len: usize,
    outputs_json_ptr: *const u8,
    outputs_json_len: usize,
    fee: u64,
    reference_block_ptr: *const u8,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylSignResult {
    if spend_secret_ptr.is_null()
        || tx_prefix_hash_ptr.is_null()
        || inputs_json_ptr.is_null()
        || outputs_json_ptr.is_null()
        || reference_block_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return ShekylSignResult::err(-1, "null pointer argument".into());
    }

    let spend_secret: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(spend_secret_ptr, buf.as_mut_ptr(), 32);
        buf
    });
    let tx_prefix_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tx_prefix_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let reference_block: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(reference_block_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let Some(inputs_json) = (unsafe { slice_from_ptr(inputs_json_ptr, inputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid inputs_json pointer".into());
    };
    let Some(outputs_json) = (unsafe { slice_from_ptr(outputs_json_ptr, outputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid outputs_json pointer".into());
    };

    let collapsed_inputs: Vec<FcmpSignInput> = match serde_json::from_slice(inputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("inputs JSON parse error: {e}")),
    };
    let outputs: Vec<shekyl_tx_builder::OutputInfo> = match serde_json::from_slice(outputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("outputs JSON parse error: {e}")),
    };

    use shekyl_crypto_pq::derivation::derive_output_secrets;
    use zeroize::Zeroize;

    let Some(mut b_scalar) = curve25519_scalar_from_bytes(&spend_secret) else {
        return ShekylSignResult::err(-5, "invalid spend secret key".into());
    };

    let mut spend_inputs: Vec<shekyl_tx_builder::SpendInput> =
        Vec::with_capacity(collapsed_inputs.len());
    for inp in &collapsed_inputs {
        if inp.combined_ss.len() != 64 {
            drop(spend_inputs);
            return ShekylSignResult::err(
                -5,
                format!(
                    "combined_ss must be 64 bytes, got {}",
                    inp.combined_ss.len()
                ),
            );
        }
        let mut ss = [0u8; 64];
        ss.copy_from_slice(&inp.combined_ss);
        let secrets = derive_output_secrets(&ss, inp.output_index);
        ss.zeroize();

        let Some(ho_scalar) = curve25519_scalar_from_bytes(&secrets.ho) else {
            drop(spend_inputs);
            return ShekylSignResult::err(-5, "invalid ho scalar".into());
        };
        let x = ho_scalar + b_scalar;
        let mut x_bytes = x.to_bytes();

        spend_inputs.push(shekyl_tx_builder::SpendInput {
            output_key: inp.output_key,
            commitment: inp.commitment,
            amount: shekyl_units::AtomicUnits::from_raw(inp.amount),
            spend_key_x: x_bytes,
            spend_key_y: secrets.y,
            commitment_mask: inp.commitment_mask,
            combined_ss: inp.combined_ss.clone(),
            output_index: inp.output_index,
            leaf_chunk: inp.leaf_chunk.clone(),
            c1_layers: inp.c1_layers.clone(),
            c2_layers: inp.c2_layers.clone(),
        });

        x_bytes.zeroize();
    }

    // ABI `tree_depth` is the LMDB depth. The builder wants layers (depth + 1).
    // The C++ wallet that used to pass this is gone; remaining callers are tests.
    let layers = tree_depth.saturating_add(1);
    let tree = shekyl_tx_builder::TreeContext {
        // The C ABI stays raw (rule 40); the typed world begins here.
        reference_block: shekyl_types::BlockHash::from_bytes(reference_block),
        tree_root: shekyl_types::CurveTreeRoot::from_bytes(tree_root),
        tree_depth: layers,
    };

    let result = match shekyl_tx_builder::sign_transaction(
        shekyl_types::PrefixHash::from_bytes(tx_prefix_hash),
        &spend_inputs,
        &outputs,
        shekyl_units::AtomicUnits::from_raw(fee),
        &tree,
    ) {
        Ok(proofs) => match serde_json::to_vec(&proofs) {
            Ok(json) => ShekylSignResult::ok(json),
            Err(e) => ShekylSignResult::err(-3, format!("result serialization error: {e}")),
        },
        Err(e) => {
            let code = tx_builder_error_code(&e);
            ShekylSignResult::err(code, e.to_string())
        }
    };

    drop(spend_inputs);
    b_scalar.zeroize();
    result
}

fn curve25519_scalar_from_bytes(bytes: &[u8; 32]) -> Option<curve25519_dalek::Scalar> {
    Option::from(curve25519_dalek::Scalar::from_canonical_bytes(*bytes))
}

// ─── Output Construction / Scanning / PQC Signing ────────────────────────────

// Writer half of the witness seam. Its reader (`parse_prove_witness`) serves
// only the multisig coordinator, so both sit under the same feature: a default
// build exporting a writer would offer to produce bytes nothing in that build
// can consume.
#[cfg(feature = "multisig")]
/// Build the 288-byte witness header from a typed struct.
///
/// # Safety
/// - `input` must point to a valid `ProveInputFields`.
/// - `out_buf` must point to at least 288 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_build_witness_header(
    input: *const ProveInputFields,
    out_buf: *mut u8,
) -> bool {
    if input.is_null() || out_buf.is_null() {
        return false;
    }
    let inp = &*input;
    let buf = std::slice::from_raw_parts_mut(out_buf, SHEKYL_PROVE_WITNESS_HEADER_BYTES);
    buf[0..32].copy_from_slice(&inp.output_key);
    buf[32..64].copy_from_slice(&inp.key_image_gen);
    buf[64..96].copy_from_slice(&inp.commitment);
    buf[96..128].copy_from_slice(&inp.pqc_leaf_commitment);
    buf[128..160].copy_from_slice(&inp.pqc_leaf_blind);
    buf[160..192].copy_from_slice(&inp.spend_key_x);
    buf[192..224].copy_from_slice(&inp.spend_key_y);
    buf[224..256].copy_from_slice(&inp.commitment_mask);
    buf[256..288].copy_from_slice(&inp.pseudo_out_blind);
    true
}

/// Construct a two-component output via the unified HKDF path.
///
/// # Safety
/// - `tx_key_secret_ptr` must point to 32 bytes (sender's tx secret key).
/// - `x25519_pk` must point to 32 bytes.
/// - `ml_kem_ek` must point to `ml_kem_ek_len` bytes (expected: 1184).
/// - `spend_key` must point to 32 bytes (compressed Edwards point B).
/// - The returned `ShekylOutputData` owns its buffer fields; free them
///   with `shekyl_buffer_free` when done.
#[no_mangle]
pub unsafe extern "C" fn shekyl_construct_output(
    tx_key_secret_ptr: *const u8,
    x25519_pk: *const u8,
    ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    spend_key: *const u8,
    amount: u64,
    output_index: u64,
) -> ShekylOutputData {
    let fail = ShekylOutputData {
        output_key: [0; 32],
        commitment: [0; 32],
        enc_amount: [0; 8],
        amount_tag: 0,
        enc_label: [0; 8],
        label_tag: 0,
        view_tag_prefilter: 0,
        kem_ciphertext_x25519: [0; 32],
        kem_ciphertext_ml_kem: ShekylBuffer::null(),
        pqc_public_key: ShekylBuffer::null(),
        pqc_leaf: [0; 64],
        y: [0; 32],
        z: [0; 32],
        k_amount: [0; 32],
        success: false,
    };

    let Some(tx_key) = arr32_from_ptr(tx_key_secret_ptr) else {
        return fail;
    };
    let Some(x_pk) = arr32_from_ptr(x25519_pk) else {
        return fail;
    };
    let Some(sk) = arr32_from_ptr(spend_key) else {
        return fail;
    };
    let Some(ek) = (unsafe { slice_from_ptr(ml_kem_ek, ml_kem_ek_len) }) else {
        return fail;
    };

    use shekyl_crypto_pq::output::construct_output;
    match construct_output(&tx_key, &x_pk, ek, &sk, amount, output_index) {
        Ok(mut out) => {
            let kem_ciphertext_ml_kem = std::mem::take(&mut out.kem_ciphertext_ml_kem);
            let pqc_public_key = std::mem::take(&mut out.pqc_public_key);
            ShekylOutputData {
                output_key: out.output_key,
                commitment: out.commitment,
                enc_amount: out.enc_amount_bytes(),
                amount_tag: out.amount_tag(),
                enc_label: out.enc_label_bytes(),
                label_tag: out.label_tag(),
                view_tag_prefilter: out.view_tag_prefilter,
                kem_ciphertext_x25519: out.kem_ciphertext_x25519,
                kem_ciphertext_ml_kem: ShekylBuffer::from_vec(kem_ciphertext_ml_kem),
                pqc_public_key: ShekylBuffer::from_vec(pqc_public_key),
                pqc_leaf: out.pqc_leaf.entry_bytes(),
                y: out.y,
                z: out.z,
                k_amount: out.k_amount,
                success: true,
            }
        }
        Err(_) => fail,
    }
}

/// Free a ShekylOutputData's heap-allocated buffer fields.
///
/// # Safety
/// Only call once per ShekylOutputData returned from `shekyl_construct_output`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_output_data_free(data: *mut ShekylOutputData) {
    if data.is_null() {
        return;
    }
    let d = &mut *data;
    // Wipe secret fields
    use zeroize::Zeroize;
    d.y.zeroize();
    d.z.zeroize();
    d.k_amount.zeroize();
    if !d.kem_ciphertext_ml_kem.ptr.is_null() {
        shekyl_buffer_free(d.kem_ciphertext_ml_kem.ptr, d.kem_ciphertext_ml_kem.len);
        d.kem_ciphertext_ml_kem = ShekylBuffer::null();
    }
    if !d.pqc_public_key.ptr.is_null() {
        shekyl_buffer_free(d.pqc_public_key.ptr, d.pqc_public_key.len);
        d.pqc_public_key = ShekylBuffer::null();
    }
}

/// Sign a message using the HKDF-derived hybrid PQC keypair for an output.
/// ML-DSA secret key never crosses this boundary — it lives and dies in Rust.
///
/// # Safety
/// - `combined_ss` must point to 64 bytes.
/// - `message` must point to `message_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_pqc_auth(
    combined_ss: *const u8,
    output_index: u64,
    message: *const u8,
    message_len: usize,
) -> ShekylPqcAuthResult {
    let fail = ShekylPqcAuthResult {
        hybrid_public_key: ShekylBuffer::null(),
        signature: ShekylBuffer::null(),
        success: false,
    };

    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return fail,
    };
    let Some(msg) = (unsafe { slice_from_ptr(message, message_len) }) else {
        return fail;
    };

    use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
    match sign_pqc_auth_for_output(
        &ss,
        output_index,
        shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
        msg,
    ) {
        Ok(auth) => ShekylPqcAuthResult {
            hybrid_public_key: ShekylBuffer::from_vec(auth.hybrid_public_key),
            signature: ShekylBuffer::from_vec(auth.signature),
            success: true,
        },
        Err(_) => fail,
    }
}

/// Free a ShekylPqcAuthResult's heap-allocated fields.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pqc_auth_result_free(result: *mut ShekylPqcAuthResult) {
    if result.is_null() {
        return;
    }
    let r = &mut *result;
    if !r.hybrid_public_key.ptr.is_null() {
        shekyl_buffer_free(r.hybrid_public_key.ptr, r.hybrid_public_key.len);
        r.hybrid_public_key = ShekylBuffer::null();
    }
    if !r.signature.ptr.is_null() {
        shekyl_buffer_free(r.signature.ptr, r.signature.len);
        r.signature = ShekylBuffer::null();
    }
}

// ─── Merged scan + key image ─────────────────────────────────────────────────

/// Merged scan + key image computation.
///
/// Scans an output and writes the recovered secrets, including the key image,
/// into caller-provided buffers. Production scan does not use this export:
/// `shekyl-scanner` calls `scan_output_recover_with_ml_kem_dk` and
/// `compute_output_key_image`. The remaining callers are tests. `transfer_details`
/// is gone with the C++ wallet.
///
/// # Safety
/// - All pointer parameters must be valid for reads/writes of their documented sizes.
/// - `ho_out`, `y_out`, `z_out`, `k_amount_out`: 32 writable bytes each.
/// - `key_image_out`: 32 writable bytes.
/// - `recovered_spend_key_out`: 32 writable bytes.
/// - `combined_ss_out`: 64 writable bytes if `persist_combined_ss` is true, or nullptr.
/// - `spend_secret_key`: 32 bytes (wallet master spend key `b`).
/// - `hp_of_O`: 32 bytes (`Hp(O)`, supplied by the caller).
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_scan_and_recover(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    enc_label: *const u8,
    label_tag_on_chain: u8,
    view_tag_on_chain: u8,
    output_index: u64,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    persist_combined_ss: bool,
    ho_out: *mut u8,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    recovered_spend_key_out: *mut u8,
    key_image_out: *mut u8,
    combined_ss_out: *mut u8,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    leaf_entry_out: *mut [u8; 64],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let el = match unsafe { slice_from_ptr(enc_label, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let have_spend_key = !spend_secret_key.is_null() && !hp_of_O.is_null();

    if ho_out.is_null()
        || y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || recovered_spend_key_out.is_null()
        || key_image_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || leaf_entry_out.is_null()
    {
        return false;
    }
    if persist_combined_ss && combined_ss_out.is_null() {
        return false;
    }

    use shekyl_crypto_pq::output::{compute_output_key_image_from_ho, scan_output_recover};

    let Ok(recovered) = scan_output_recover(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        &el,
        label_tag_on_chain,
        view_tag_on_chain,
        output_index,
    ) else {
        return false;
    };

    std::ptr::copy_nonoverlapping(recovered.ho.as_ptr(), ho_out, 32);
    std::ptr::copy_nonoverlapping(recovered.y.as_ptr(), y_out, 32);
    std::ptr::copy_nonoverlapping(recovered.z.as_ptr(), z_out, 32);
    std::ptr::copy_nonoverlapping(recovered.k_amount.as_ptr(), k_amount_out, 32);
    *amount_out = recovered.amount;
    std::ptr::copy_nonoverlapping(
        recovered.recovered_spend_key.as_ptr(),
        recovered_spend_key_out,
        32,
    );
    *pqc_pk_out = ShekylBuffer::from_vec(recovered.pqc_public_key.clone());
    *pqc_sk_out = ShekylBuffer::from_vec(recovered.pqc_secret_key.clone());
    *leaf_entry_out = recovered.pqc_leaf.entry_bytes();

    if have_spend_key {
        let b_key = &*(spend_secret_key as *const [u8; 32]);
        let hp = &*(hp_of_O as *const [u8; 32]);
        let Ok(ki_result) = compute_output_key_image_from_ho(&recovered.ho, b_key, hp) else {
            return false;
        };
        std::ptr::copy_nonoverlapping(ki_result.key_image.as_bytes().as_ptr(), key_image_out, 32);
    } else {
        std::ptr::write_bytes(key_image_out, 0, 32);
    }

    if persist_combined_ss {
        std::ptr::copy_nonoverlapping(recovered.combined_ss.as_ptr(), combined_ss_out, 64);
    }

    true
}
