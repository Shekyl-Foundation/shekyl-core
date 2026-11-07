// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared C-ABI types for the legacy monofile FFI surface.

/// Heap-allocated `(ptr, len)` byte buffer handed across the C ABI; freed
/// with `shekyl_buffer_free`.
#[repr(C)]
pub struct ShekylBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/// Fixed-size witness header per input in the FCMP++ prove/verify FFI.
/// Layout: [O:32][I:32][C:32][CM:32][r:32][x:32][y:32][z:32][a:32]
///   CM, r = the input's PQC leaf commitment point and its blind (PL-D3)
///   x, y = SAL spend secrets (O = xG + yT)
///   z    = Pedersen commitment mask (C = zG + amount*H)
///   a    = pseudo-out blinding factor (r_c = a - z)
///
/// Part of the witness seam, not a general constant: every reference to it —
/// parser, writer, tests — is multisig-gated, so it carries the same cfg.
/// This replaces an allow(dead_code): a suppression that hides the fact was
/// worse than a cfg that states it, and the pin documents the seam as gated.
#[cfg(feature = "multisig")]
pub const SHEKYL_PROVE_WITNESS_HEADER_BYTES: usize = 288;

/// Typed struct for passing FCMP++ prover inputs across the C ABI.
/// A caller fills named fields instead of writing at hand-counted byte
/// offsets. No C++ caller remains — the C++ declaration went with the legacy
/// prove seam — so this serves the multisig witness seam only.
#[cfg(feature = "multisig")]
#[repr(C)]
pub struct ProveInputFields {
    pub output_key: [u8; 32],
    pub key_image_gen: [u8; 32],
    pub commitment: [u8; 32],
    pub pqc_leaf_commitment: [u8; 32],
    pub pqc_leaf_blind: [u8; 32],
    pub spend_key_x: [u8; 32],
    pub spend_key_y: [u8; 32],
    pub commitment_mask: [u8; 32],
    pub pseudo_out_blind: [u8; 32],
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
    /// The output's 64-byte `tx_extra 0x07` entry `CM ‖ record`, re-derived.
    pub pqc_leaf: [u8; 64],
    pub success: bool,
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
