// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared C-ABI types for the legacy monofile FFI surface.

/// Fixed-size witness header per input in the FCMP++ prove/verify FFI.
/// Layout: [O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]
///   x, y = SAL spend secrets (O = xG + yT)
///   z    = Pedersen commitment mask (C = zG + amount*H)
///   a    = pseudo-out blinding factor (r_c = a - z)
#[repr(C)]
pub struct ShekylBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

// Part of the witness seam, not a general constant: every reference to it —
// parser, writer, tests — is multisig-gated, so it carries the same cfg.
// This replaces an allow(dead_code): a suppression that hides the fact was
// worse than a cfg that states it, and the pin documents the seam as gated.
#[cfg(feature = "multisig")]
pub const SHEKYL_PROVE_WITNESS_HEADER_BYTES: usize = 256;

/// Typed struct for passing FCMP++ prover inputs across FFI.
/// C++ fills named fields instead of writing at hand-counted byte offsets.
#[cfg(feature = "multisig")]
#[repr(C)]
pub struct ProveInputFields {
    pub output_key: [u8; 32],
    pub key_image_gen: [u8; 32],
    pub commitment: [u8; 32],
    pub h_pqc: [u8; 32],
    pub spend_key_x: [u8; 32],
    pub spend_key_y: [u8; 32],
    pub commitment_mask: [u8; 32],
    pub pseudo_out_blind: [u8; 32],
}

/// Result struct for construct_output FFI.
#[repr(C)]
pub struct ShekylOutputData {
    pub output_key: [u8; 32],
    pub commitment: [u8; 32],
    pub enc_amount: [u8; 8],
    pub amount_tag: u8,
    pub enc_label: [u8; 8],
    pub label_tag: u8,
    pub view_tag_prefilter: u8,
    pub kem_ciphertext_x25519: [u8; 32],
    pub kem_ciphertext_ml_kem: ShekylBuffer,
    pub pqc_public_key: ShekylBuffer,
    pub h_pqc: [u8; 32],
    pub y: [u8; 32],
    pub z: [u8; 32],
    pub k_amount: [u8; 32],
    pub success: bool,
}

/// Result struct for scan_output FFI.
#[repr(C)]
pub struct ShekylScannedOutput {
    pub y: [u8; 32],
    pub z: [u8; 32],
    pub k_amount: [u8; 32],
    pub amount: u64,
    pub amount_tag: u8,
    pub pqc_public_key: ShekylBuffer,
    pub pqc_secret_key: ShekylBuffer,
    pub h_pqc: [u8; 32],
    pub success: bool,
}

/// Result struct for sign_pqc_auth FFI.
#[repr(C)]
pub struct ShekylPqcAuthResult {
    pub hybrid_public_key: ShekylBuffer,
    pub signature: ShekylBuffer,
    pub success: bool,
}

#[repr(C)]
pub struct ShekylPqcKeypair {
    pub public_key: ShekylBuffer,
    pub secret_key: ShekylBuffer,
    pub success: bool,
}

#[repr(C)]
pub struct ShekylPqcSignatureResult {
    pub signature: ShekylBuffer,
    pub success: bool,
}

/// MSW-1 cross-language consistency: the canonical PQC multisig wire lengths,
/// owned by `shekyl-crypto-pq`. The C++ `cryptonote_config.h` twins are pinned
/// equal to these by `tests/unit_tests/fcmp.cpp` — the only mechanism that
/// catches C++ and Rust drifting from each other (F-1: each side internally
/// consistent, disagreeing across the FFI, which no single-language assert sees).
#[repr(C)]
pub struct ShekylPqcCanonicalLens {
    pub single_key_len: usize,
    pub single_sig_len: usize,
    pub spend_auth_pubkey_len: usize,
    pub max_multisig_participants: usize,
    pub max_public_key_blob: usize,
    pub max_signature_blob: usize,
}

/// Opaque result struct for the fee burn split, readable from C++.
#[repr(C)]
pub struct ShekylBurnSplit {
    pub miner_fee_income: u64,
    pub staker_pool_amount: u64,
    pub actually_destroyed: u64,
}

/// Split block emission between miner and staker pool.
#[repr(C)]
pub struct ShekylEmissionSplit {
    pub miner_emission: u64,
    pub staker_emission: u64,
}

/// FCMP++ proof construction result.
#[repr(C)]
pub struct ShekylFcmpProveResult {
    pub proof: ShekylBuffer,
    pub pseudo_outs: ShekylBuffer,
    pub success: bool,
}

/// Result of `shekyl_sign_transaction`.
///
/// On success, `success` is true and `proofs_json` contains a JSON-encoded
/// `SignedProofs` (BP+, FCMP++, ECDH, pseudo-outs, tree metadata).
/// On failure, `success` is false, `error_code` classifies the error, and
/// `error_message` contains a human-readable description.
///
/// The caller must free `proofs_json` and `error_message` via `shekyl_buffer_free`.
#[repr(C)]
pub struct ShekylSignResult {
    pub proofs_json: ShekylBuffer,
    pub success: bool,
    pub error_code: i32,
    pub error_message: ShekylBuffer,
}

impl ShekylSignResult {
    pub(crate) fn ok(json: Vec<u8>) -> Self {
        ShekylSignResult {
            proofs_json: ShekylBuffer::from_vec(json),
            success: true,
            error_code: 0,
            error_message: ShekylBuffer::null(),
        }
    }

    pub(crate) fn err(code: i32, message: String) -> Self {
        ShekylSignResult {
            proofs_json: ShekylBuffer::null(),
            success: false,
            error_code: code,
            error_message: ShekylBuffer::from_vec(message.into_bytes()),
        }
    }
}
