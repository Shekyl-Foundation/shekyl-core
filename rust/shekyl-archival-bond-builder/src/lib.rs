// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic construction of JoinMarket archival bond posts.
//!
//! This crate is the **construct** side of the archival bond, the mirror of the
//! `shekyl-archival-retention` **verify** side. It is deterministic, holds no
//! async runtime, and runs no actor: it builds the bond-post `vin`, signs it
//! with the `P` identity hybrid key, and supplies the single-sourced
//! [`OutputTerm`] for the RCT balance. Funding selection, standoff timing, and
//! broadcast live in the `StakeEngine` (PR 2);
//! `docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §5 / §7.
//!
//! ## What this crate produces (PR 1)
//!
//! 1. [`ArchivalBondPostVin`] for [`BondPostKind::JoinMarket`] with
//!    `bonded_total_atomic == bond_credit == bond_floor(holdings)` and
//!    `bond_debit == 0` (§7.1), and the hybrid signature over its
//!    [`ArchivalBondPostVin::signature_preimage`] under the `P` identity key
//!    (JoinMarket is a credit path; credit paths authorize against `P_pubkey`).
//! 2. The credit balance term: `bond_credit = floor` rides the **output** side
//!    as an [`OutputTerm`] (the single-sourced cleartext term, §7.2), fed to
//!    `shekyl-tx-builder::sign_transaction_with_terms` by the engine.
//! 3. The credit funding rule: a credit path's committed funding must exceed
//!    `outputs + fee` by exactly `bond_credit` ([`verify_credit_funding`], §7.3).
//!
//! ## What this crate does NOT do
//!
//! The masked RCT commitments (`pseudoOuts`, output commitments) and the FCMP++
//! membership proofs are produced by the prover
//! (`shekyl-tx-builder::sign_transaction_with_terms`) over the curve tree, not
//! re-derived here — re-deriving them would be a second construction path for a
//! genesis-frozen commitment, the divergence single-sourcing exists to prevent.
//! The full prover round-trip against a synthetic tree, and against the real
//! `CurveTreeClient` (CT-5), are PR 2 / separate-series work (§3, §8).

#![deny(unsafe_code)]

mod error;

pub use error::BondBuildError;

use shekyl_archival_retention::{
    bond_floor, p_canonical_id_from_hybrid_pubkey, ArchivalBondPostVin, BondPostKind,
    HoldingsDescriptor,
};
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSignature, SignatureScheme};
use shekyl_rct_balance::OutputTerm;
use shekyl_units::AtomicUnits;

/// A constructed, signed JoinMarket bond-post `vin`.
///
/// The signature covers [`ArchivalBondPostVin::signature_preimage`] (which binds
/// `tx_prefix_hash`, the canonical id, holdings, and the cleartext terms) under
/// the `P` identity hybrid key.
#[derive(Clone, Debug)]
pub struct JoinMarketVin {
    /// The bond-post input, ready for wire encoding / verify.
    pub vin: ArchivalBondPostVin,
    /// Hybrid (Ed25519 + ML-DSA-65) signature over the post preimage.
    pub signature: HybridSignature,
}

impl JoinMarketVin {
    /// The cleartext balance term for this post's `bond_credit`, on the output
    /// side. Feed alongside the funding inputs / outputs to
    /// `shekyl-tx-builder::sign_transaction_with_terms` as the sole
    /// `extra_outputs` entry; `tx-builder` never learns the word "bond" (§7.2).
    #[must_use]
    pub fn credit_term(&self) -> OutputTerm {
        OutputTerm::new(AtomicUnits::from_raw(self.vin.bond_credit))
    }
}

/// Build and sign a JoinMarket bond-post `vin` for persona `P` over the holdings
/// being bonded (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.1).
///
/// `tx_prefix_hash` is the 32-byte prefix hash of the transaction the post rides
/// in; it binds the signature to that transaction. The constructed `vin` is
/// accepted by [`shekyl_archival_retention::verify_join_market_bond_post`] with
/// `record_exists == false` by construction.
///
/// # Errors
///
/// - [`BondBuildError::BondFloorZero`] if `holdings` are structurally invalid.
/// - [`BondBuildError::IdentityEncode`] if the identity key fails to serialize.
/// - [`BondBuildError::Sign`] if hybrid signing fails.
pub fn build_join_market_vin(
    keys: &ArchivalPKeys,
    holdings: HoldingsDescriptor,
    tx_prefix_hash: &[u8; 32],
) -> Result<JoinMarketVin, BondBuildError> {
    let floor = bond_floor(&holdings);
    if floor == 0 {
        return Err(BondBuildError::BondFloorZero);
    }

    // Identity = P_pubkey; the canonical id is derived from it, never carried
    // independently (`ARCHIVAL_FIREWALL_GATE6.md` §9.4 / id::* over the same
    // canonical bytes the verify side recomputes).
    let hybrid_public_key = keys
        .hybrid_bond_id()
        .to_canonical_bytes()
        .map_err(BondBuildError::IdentityEncode)?;
    let p_canonical_id = p_canonical_id_from_hybrid_pubkey(&hybrid_public_key);

    // JoinMarket is a pure credit path: bonded_total == bond_credit == floor,
    // bond_debit == 0 (the verify side pins this in verify_join_market_bond_post).
    let vin = ArchivalBondPostVin {
        hybrid_public_key,
        p_canonical_id,
        post_kind: BondPostKind::JoinMarket,
        holdings,
        bonded_total_atomic: floor,
        bond_credit: floor,
        bond_debit: 0,
    };

    let preimage = vin.signature_preimage(tx_prefix_hash);
    let signature = HybridEd25519MlDsa
        .sign(&keys.hybrid_sign_sk, &preimage)
        .map_err(BondBuildError::Sign)?;

    Ok(JoinMarketVin { vin, signature })
}

/// Check the credit-path funding rule for a JoinMarket post (§7.3).
///
/// A credit path's funding inputs must commit to exactly `outputs + fee +
/// bond_credit`, so that after the cleartext `bond_credit` term is added on the
/// output side the RCT balance closes
/// (`sum(pseudoOuts) = sum(out_masks) + fee + bond_credit`). This is the
/// amount-level invariant the engine enforces when selecting funding, *before*
/// the prover builds the masked commitments. All arithmetic is checked.
///
/// # Errors
///
/// - [`BondBuildError::NotCreditPath`] if `vin` is not a JoinMarket post or
///   carries a non-zero `bond_debit` (the credit rule does not apply).
/// - [`BondBuildError::AmountOverflow`] if `outputs + fee + bond_credit`
///   overflows `u64`.
/// - [`BondBuildError::CreditImbalance`] if `funding_total` does not equal that
///   sum.
///
/// Amounts are [`AtomicUnits`] so the funds path stays checked end-to-end
/// (rule 20); the raw `u64` is derived only at the error boundary.
pub fn verify_credit_funding(
    funding_total: AtomicUnits,
    output_total: AtomicUnits,
    fee: AtomicUnits,
    vin: &ArchivalBondPostVin,
) -> Result<(), BondBuildError> {
    // The credit funding equation `funding == outputs + fee + bond_credit`
    // assumes the only extra balance term is `bond_credit` on the output side.
    // A non-JoinMarket kind or a non-zero `bond_debit` (an input-side term)
    // would make this check a false "OK"; reject it loudly instead.
    if vin.post_kind != BondPostKind::JoinMarket || vin.bond_debit != 0 {
        return Err(BondBuildError::NotCreditPath {
            post_kind: vin.post_kind,
            bond_debit: vin.bond_debit,
        });
    }

    let bond_credit = AtomicUnits::from_raw(vin.bond_credit);
    let required = output_total
        .checked_add(fee)
        .and_then(|s| s.checked_add(bond_credit))
        .ok_or(BondBuildError::AmountOverflow)?;
    if funding_total != required {
        return Err(BondBuildError::CreditImbalance {
            funding: funding_total.to_raw(),
            outputs: output_total.to_raw(),
            fee: fee.to_raw(),
            floor: vin.bond_credit,
        });
    }
    Ok(())
}
