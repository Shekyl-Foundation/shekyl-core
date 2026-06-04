// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Entitlement Fiat–Shamir challenge preimage — anti-splicing layout (decision 3).
//!
//! [`CONFIDENTIAL_STAKING.md`](../../../docs/design/CONFIDENTIAL_STAKING.md)
//! §6.4.1 decision 3 pins one shared binding root for the four claim
//! components (membership, ClaimLinkability, entitlement Schnorr, folded
//! remainder range proof): every component absorbs `μ_claim = signable_tx_hash`,
//! so no component is valid under any other claim.
//!
//! For the **entitlement** Schnorr, the challenge follows the reserve-DLEQ shape
//! `c = H(domain ‖ bases ‖ points ‖ msg)`
//! ([`FCMP_PLUS_PLUS.md`](../../../docs/FCMP_PLUS_PLUS.md) §"Reserve proofs and
//! the DLEQ requirement"):
//!
//! ```text
//! c = keccak256_to_scalar(
//!       "shekyl-stake-entitlement-v1" ‖ G ‖ H ‖ N_le ‖ D_le
//!       ‖ C~ ‖ C_claim ‖ C_ρ ‖ R ‖ μ_claim )
//! ```
//!
//! This module is **not** the hash — Keccak-to-scalar and the curve points are
//! the C++/FFI verifier's job. It locks the one thing the prover and verifier
//! must agree on byte-for-byte: **which fields are absorbed, and in what order.**
//! Dropping any public input — or `μ_claim` — is precisely the splicing hole the
//! layout forecloses, so the field set/order is consensus-critical and KAT-locked
//! here rather than left to two hand-matched serializers. No curve or hash
//! dependency is introduced (`17-dependency-discipline.mdc`): the caller passes
//! the canonical 32-byte encodings it already holds.

/// Fiat–Shamir domain separator for the entitlement Schnorr. Distinct from
/// `shekyl-reserve-proof-dleq-v1` — sharing a transcript domain across two
/// statements is a soundness footgun (§6.4.1).
pub const ENTITLEMENT_FS_DOMAIN: &[u8] = b"shekyl-stake-entitlement-v1";

/// Size of each non-domain field in the preimage: 32-byte compressed Ed25519
/// points and 32-byte little-endian scalars alike.
pub const FIELD_LEN: usize = 32;

/// Number of fixed-size 32-byte fields following the domain separator:
/// `G, H, N_le, D_le, C~, C_claim, C_ρ, R, μ_claim`.
pub const FIELD_COUNT: usize = 9;

/// Total preimage length: domain ‖ nine 32-byte fields.
pub const PREIMAGE_LEN: usize = ENTITLEMENT_FS_DOMAIN.len() + FIELD_COUNT * FIELD_LEN;

/// Byte offset (past the domain) of a field, for KAT / verifier cross-checks.
/// The order is the consensus-critical part of decision 3.
pub mod offset {
    use super::{ENTITLEMENT_FS_DOMAIN, FIELD_LEN};

    /// First field starts immediately after the domain separator.
    pub const DOMAIN_END: usize = ENTITLEMENT_FS_DOMAIN.len();
    /// `G` — first generator base.
    pub const G: usize = DOMAIN_END;
    /// `H` — second generator base.
    pub const H: usize = G + FIELD_LEN;
    /// `N_le` — public multiplier numerator, 32-byte little-endian scalar.
    pub const N_LE: usize = H + FIELD_LEN;
    /// `D_le` — public denominator `D = 2^(k+1)`, 32-byte little-endian scalar.
    pub const D_LE: usize = N_LE + FIELD_LEN;
    /// `C~` — rerandomized membership commitment (pseudo-out).
    pub const C_TILDE: usize = D_LE + FIELD_LEN;
    /// `C_claim` — reward output commitment.
    pub const C_CLAIM: usize = C_TILDE + FIELD_LEN;
    /// `C_ρ` — committed remainder.
    pub const C_RHO: usize = C_CLAIM + FIELD_LEN;
    /// `R` — Schnorr nonce commitment on the residual `G`-exponent.
    pub const R: usize = C_RHO + FIELD_LEN;
    /// `μ_claim` — the shared binding root (`signable_tx_hash`).
    pub const MU_CLAIM: usize = R + FIELD_LEN;
}

/// Public inputs to the entitlement Schnorr challenge, as the canonical 32-byte
/// encodings the prover/verifier already hold.
///
/// Field order here mirrors the wire order in [`offset`] and
/// [`EntitlementChallengeInputs::preimage`]; reordering the struct does **not**
/// change the preimage (the builder fixes the order), but keeping them aligned
/// keeps the layout legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntitlementChallengeInputs {
    /// Generator `G` (the `⟨G⟩` subgroup base the residual lands in).
    pub g: [u8; FIELD_LEN],
    /// Generator `H` (the value base; commitments are `mask·G + amount·H`).
    pub h: [u8; FIELD_LEN],
    /// `N = tier_num_reduced·Σ_S K_S_scaled`, 32-byte little-endian.
    pub n_le: [u8; FIELD_LEN],
    /// `D = D_TIER·SCALE_rate = 2^(k+1)`, 32-byte little-endian.
    pub d_le: [u8; FIELD_LEN],
    /// `C~` — rerandomized membership commitment.
    pub c_tilde: [u8; FIELD_LEN],
    /// `C_claim` — reward output commitment.
    pub c_claim: [u8; FIELD_LEN],
    /// `C_ρ` — committed remainder.
    pub c_rho: [u8; FIELD_LEN],
    /// `R` — Schnorr nonce commitment.
    pub r: [u8; FIELD_LEN],
    /// `μ_claim = signable_tx_hash` — the shared anti-splicing binding root.
    pub mu_claim: [u8; FIELD_LEN],
}

impl EntitlementChallengeInputs {
    /// Assemble the canonical challenge preimage:
    /// `domain ‖ G ‖ H ‖ N_le ‖ D_le ‖ C~ ‖ C_claim ‖ C_ρ ‖ R ‖ μ_claim`.
    ///
    /// The verifier feeds this to `keccak256_to_scalar` to obtain `c`. The
    /// **order and completeness** of the fields are the consensus-critical
    /// invariant (decision 3); the hash itself is out of scope here.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREIMAGE_LEN);
        out.extend_from_slice(ENTITLEMENT_FS_DOMAIN);
        out.extend_from_slice(&self.g);
        out.extend_from_slice(&self.h);
        out.extend_from_slice(&self.n_le);
        out.extend_from_slice(&self.d_le);
        out.extend_from_slice(&self.c_tilde);
        out.extend_from_slice(&self.c_claim);
        out.extend_from_slice(&self.c_rho);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&self.mu_claim);
        debug_assert_eq!(out.len(), PREIMAGE_LEN);
        out
    }
}

#[cfg(test)]
mod tests;
