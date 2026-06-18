//! Bond-post RCT balance equation (ARCHIVAL_BOND_GATE4.md §3.2).
//!
//! Verifies `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`
//! over curve25519 commitments. The commitment-sum arithmetic and the
//! typed-side cleartext terms are **single-sourced** in
//! [`shekyl_rct_balance`](shekyl_rct_balance) (the same definitions construct
//! uses, so construct and verify cannot diverge —
//! `docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §7.2 / §11.1 Q2). This module
//! adds only the bond-specific term rigidity: exactly one of `bond_credit` /
//! `bond_debit` is non-zero, mapped to the matching typed side. Bulletproof+
//! verification remains in C++ (`rctSigs`).

#![deny(unsafe_code)]

use shekyl_rct_balance::{verify_rct_balance, InputTerm, OutputTerm, RctBalanceError};
use shekyl_units::AtomicUnits;

/// Bond-post balance sum failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondRctBalanceError {
    /// Vin may not carry both `bond_credit` and `bond_debit` (§3.2).
    BothTermsNonzero,
    /// Bond-post must carry exactly one direction term (credit xor debit; §3.2).
    NoBondTerm,
    /// Malformed flat buffer or a pseudo-out / output mask is not a valid prime-order point.
    InvalidPoint,
    /// Left and right commitment sums differ.
    SumMismatch,
}

impl From<RctBalanceError> for BondRctBalanceError {
    fn from(e: RctBalanceError) -> Self {
        match e {
            RctBalanceError::InvalidPoint => Self::InvalidPoint,
            RctBalanceError::SumMismatch => Self::SumMismatch,
        }
    }
}

/// Verify the bond-post RCT balance equation for flattened `N × 32` commitment keys.
///
/// Enforces the bond term rigidity (exactly one of `bond_credit` / `bond_debit`
/// non-zero — §3.2) and then delegates the commitment-sum balance to the
/// single-sourced [`verify_rct_balance`], mapping `bond_credit` to an
/// [`OutputTerm`] and `bond_debit` to an [`InputTerm`]. That side mapping is the
/// genesis-frozen `bond_credit -> extra_outputs`, `bond_debit -> extra_inputs`
/// relationship; construct builds the same typed terms, so the two cannot pick
/// opposite sides.
pub fn verify_bond_post_rct_balance(
    pseudo_outs_flat: &[u8],
    out_masks_flat: &[u8],
    txn_fee: u64,
    bond_credit: u64,
    bond_debit: u64,
) -> Result<(), BondRctBalanceError> {
    if bond_credit > 0 && bond_debit > 0 {
        return Err(BondRctBalanceError::BothTermsNonzero);
    }
    if bond_credit == 0 && bond_debit == 0 {
        return Err(BondRctBalanceError::NoBondTerm);
    }

    // Exactly one direction term is non-zero; place it on its fixed side.
    let extra_inputs = [InputTerm::new(AtomicUnits::from_raw(bond_debit))];
    let extra_outputs = [OutputTerm::new(AtomicUnits::from_raw(bond_credit))];

    verify_rct_balance(
        pseudo_outs_flat,
        out_masks_flat,
        AtomicUnits::from_raw(txn_fee),
        &extra_inputs,
        &extra_outputs,
    )
    .map_err(BondRctBalanceError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
    use shekyl_rct_balance::amount_commitment;

    fn commit(amount: u64, mask: Scalar) -> [u8; 32] {
        (mask * G + amount_commitment(AtomicUnits::from_raw(amount)))
            .compress()
            .to_bytes()
    }

    fn h_only(amount: u64) -> [u8; 32] {
        amount_commitment(AtomicUnits::from_raw(amount))
            .compress()
            .to_bytes()
    }

    #[test]
    fn rejects_neither_bond_term() {
        assert_eq!(
            verify_bond_post_rct_balance(&[], &[], 0, 0, 0),
            Err(BondRctBalanceError::NoBondTerm)
        );
    }

    #[test]
    fn rejects_both_bond_terms() {
        let pseudo = h_only(1);
        assert_eq!(
            verify_bond_post_rct_balance(&pseudo, &[], 0, 1, 1),
            Err(BondRctBalanceError::BothTermsNonzero)
        );
    }

    #[test]
    fn credit_term_balances_without_outputs() {
        const BOND_CREDIT: u64 = 750_000_000;
        let pseudo = h_only(BOND_CREDIT);
        assert!(verify_bond_post_rct_balance(&pseudo, &[], 0, BOND_CREDIT, 0).is_ok());
        assert_eq!(
            verify_bond_post_rct_balance(&pseudo, &[], 0, BOND_CREDIT - 1, 0),
            Err(BondRctBalanceError::SumMismatch)
        );
        assert_eq!(
            verify_bond_post_rct_balance(&pseudo, &[], 0, 0, BOND_CREDIT),
            Err(BondRctBalanceError::SumMismatch)
        );
    }

    #[test]
    fn debit_term_balances_with_output_mask() {
        const BOND_DEBIT: u64 = 500_000_000;
        let mask_scalar = Scalar::from_bytes_mod_order([7u8; 32]);
        let out_mask = commit(BOND_DEBIT, mask_scalar);
        let pseudo = commit(0, mask_scalar);
        assert!(verify_bond_post_rct_balance(&pseudo, &out_mask, 0, 0, BOND_DEBIT).is_ok());
        assert_eq!(
            verify_bond_post_rct_balance(&pseudo, &out_mask, 0, BOND_DEBIT, 0),
            Err(BondRctBalanceError::SumMismatch)
        );
        assert_eq!(
            verify_bond_post_rct_balance(&pseudo, &out_mask, 0, 0, BOND_DEBIT - 1),
            Err(BondRctBalanceError::SumMismatch)
        );
    }

    #[test]
    fn rejects_small_order_commitment() {
        let torsion: [u8; 32] = {
            let mut b = [0u8; 32];
            let hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa";
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                b[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
            }
            b
        };
        assert_eq!(
            verify_bond_post_rct_balance(&torsion, &[], 0, 1, 0),
            Err(BondRctBalanceError::InvalidPoint)
        );
    }
}
