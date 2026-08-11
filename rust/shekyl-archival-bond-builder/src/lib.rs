// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic construction of JoinMarket archival bond posts.
//!
//! This crate is the **construct** side of the archival bond, the mirror of the
//! `shekyl-archival-retention` **verify** side. It is deterministic, holds no
//! async runtime, and runs no actor: it builds the bond-post `vin` (no on-vin
//! signature — SA-2b) and supplies the single-sourced [`OutputTerm`] for the
//! CT balance. Surface-A signing of the whole-tx payload happens later in the
//! assemble path. Funding selection, standoff timing, and broadcast live in
//! the `StakeEngine` (PR 2); `docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §5 / §7.
//!
//! ## What this crate produces (PR 1)
//!
//! 1. [`ArchivalBondPostVin`] for [`BondPostKind::JoinMarket`] with
//!    `bonded_total_atomic == bond_credit == bond_floor(holdings)` and
//!    `bond_debit == 0` (§7.1). The vin carries no signature: its on-chain
//!    authorization is the transaction-level `pqc_auths` slot (surface A), not
//!    an on-vin blob (ARCHIVAL_BOND_GATE4.md §3.4.1; SA-2b, SIGNATURE_ALIGNMENT.md §2.2).
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
use shekyl_crypto_pq::archival_p::BondPostKeys;
use shekyl_ct_balance::OutputTerm;
use shekyl_units::AtomicUnits;

/// A constructed JoinMarket bond-post `vin`.
///
/// The vin carries no signature — its on-chain authorization is the
/// transaction-level `pqc_auths` slot aligned with it (surface A), signed by P's
/// identity key over the whole-tx payload hash.
///
/// Fields are private: a `JoinMarketVin` can be produced **only** by
/// [`build_join_market_vin`], which establishes the genesis-frozen JoinMarket
/// invariants (`post_kind == JoinMarket`, `bond_debit == 0`,
/// `bonded_total_atomic == bond_credit == bond_floor(holdings) != 0`). Consumers
/// that hold one therefore have a structural witness those invariants hold,
/// without re-validating them — the same property the verify side
/// (`verify_join_market_bond_post`) checks for a decoded wire vin.
#[derive(Clone, Debug)]
pub struct JoinMarketVin {
    vin: ArchivalBondPostVin,
}

impl JoinMarketVin {
    /// The bond-post input, ready for wire encoding / verify.
    #[must_use]
    pub fn vin(&self) -> &ArchivalBondPostVin {
        &self.vin
    }

    /// The cleartext balance term for this post's `bond_credit`, on the output
    /// side. Feed alongside the funding inputs / outputs to
    /// `shekyl-tx-builder::sign_transaction_with_terms` as the sole
    /// `extra_outputs` entry; `tx-builder` never learns the word "bond" (§7.2).
    #[must_use]
    pub fn credit_term(&self) -> OutputTerm {
        OutputTerm::new(AtomicUnits::from_raw(self.vin.bond_credit))
    }
}

/// Build a JoinMarket bond-post `vin` for persona `P` over the holdings being
/// bonded (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.1).
///
/// `keys` pairs P's public identity (`hybrid_bond_id` / `hybrid_sign_pk`) with
/// the GF-1 debit authorizer; its only producer is
/// `ArchivalPKeys::bond_post_keys`, so the two roles are same-persona and
/// un-transposable by construction. No secret is required — this constructor
/// does not sign (surface-A signing is the assemble path).
///
/// The constructed `vin` is accepted by
/// [`shekyl_archival_retention::verify_join_market_bond_post`] with
/// `record_exists == false` by construction. On-chain authorization is the
/// caller's surface-A `pqc_auths` slot over the whole-tx payload (SA-2b).
///
/// # Errors
///
/// - [`BondBuildError::BondFloorZero`] if `holdings` are structurally invalid.
/// - [`BondBuildError::IdentityEncode`] /
///   [`BondBuildError::BondSpendEncode`] if the named public key fails to
///   serialize.
pub fn build_join_market_vin(
    keys: BondPostKeys<'_>,
    holdings: HoldingsDescriptor,
) -> Result<JoinMarketVin, BondBuildError> {
    let floor = bond_floor(&holdings);
    if floor == 0 {
        return Err(BondBuildError::BondFloorZero);
    }

    // Identity = P_pubkey; the canonical id is derived from it, never carried
    // independently (`ARCHIVAL_FIREWALL_GATE6.md` §9.4 / id::* over the same
    // canonical bytes the verify side recomputes). Public keys only — this
    // constructor does not sign (SA-2b / rule 36).
    let hybrid_public_key = keys
        .identity_pk()
        .to_canonical_bytes()
        .map_err(BondBuildError::IdentityEncode)?;
    // The producer returns the `PCanonicalId` domain newtype; the wire vin stores
    // the raw `[u8; 32]`, so lift it out at this wire-construction edge.
    let p_canonical_id = p_canonical_id_from_hybrid_pubkey(&hybrid_public_key).to_bytes();

    // The GF-1 debit authorizer, JoinMarket-coupled on the wire (§9.11) and
    // committed into the record at connect. It rides the signed tx prefix, so
    // P's surface-A `pqc_auths` signature binds it (SA-2b).
    let bond_spend_pk = keys
        .bond_spend_pk()
        .to_canonical_bytes()
        .map_err(BondBuildError::BondSpendEncode)?;

    // JoinMarket is a pure credit path: bonded_total == bond_credit == floor,
    // bond_debit == 0 (the verify side pins this in verify_join_market_bond_post).
    //
    // The bond vin carries no signature. Its on-chain authorization is the
    // transaction-level `pqc_auths` slot aligned with this vin, signed by P's
    // identity key over the whole-tx payload hash (surface A,
    // `SCHEME_DOMAIN_PQC_AUTH_TX`) — which binds a strict superset of the fields
    // a bond-specific preimage would (including `bond_spend_pk`, in the signed
    // prefix), and the vin type tag distinguishes it from every other P-auth
    // context. See ARCHIVAL_BOND_GATE4.md §3.4.1 ("not an on-vin signature blob")
    // and the SA-2b reconciliation ruling (SIGNATURE_ALIGNMENT.md §2.2).
    let vin = ArchivalBondPostVin {
        hybrid_public_key,
        p_canonical_id,
        post_kind: BondPostKind::JoinMarket,
        bond_spend_pk,
        holdings,
        bonded_total_atomic: floor,
        bond_credit: floor,
        bond_debit: 0,
    };

    Ok(JoinMarketVin { vin })
}

/// Check the credit-path funding rule for a JoinMarket post (§7.3).
///
/// A credit path's funding inputs must commit to exactly `outputs + fee +
/// bond_credit`, so that after the cleartext `bond_credit` term is added on the
/// output side the CT balance closes
/// (`sum(pseudoOuts) = sum(out_masks) + fee + bond_credit`). This is the
/// amount-level invariant the engine enforces when selecting funding, *before*
/// the prover builds the masked commitments. All arithmetic is checked.
///
/// Takes a [`JoinMarketVin`] rather than a bare `ArchivalBondPostVin`: the
/// `bond_credit` this rule depends on is then the constructed floor by
/// type (`bonded_total == bond_credit == bond_floor != 0`, `bond_debit == 0`),
/// so the precheck cannot return a false "OK" for a malformed post. The
/// JoinMarket invariants are not re-validated here — they are guaranteed by the
/// only constructor, [`build_join_market_vin`].
///
/// # Errors
///
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
    post: &JoinMarketVin,
) -> Result<(), BondBuildError> {
    let bond_credit = AtomicUnits::from_raw(post.vin.bond_credit);
    let required = output_total
        .checked_add(fee)
        .and_then(|s| s.checked_add(bond_credit))
        .ok_or(BondBuildError::AmountOverflow)?;
    if funding_total != required {
        return Err(BondBuildError::CreditImbalance {
            funding: funding_total.to_raw(),
            outputs: output_total.to_raw(),
            fee: fee.to_raw(),
            floor: post.vin.bond_credit,
        });
    }
    Ok(())
}
