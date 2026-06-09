//! Bond-post RCT balance equation (ARCHIVAL_BOND_GATE4.md §3.2).
//!
//! Verifies `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`
//! over curve25519 commitments. Bulletproof+ verification remains in C++ (`rctSigs`).

#![deny(unsafe_code)]

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use shekyl_generators::H as H_POINT_LAZY;

/// Bond-post balance sum failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondRctBalanceError {
    /// Vin may not carry both `bond_credit` and `bond_debit` (§3.2).
    BothTermsNonzero,
    /// Bond-post must carry exactly one direction term (credit xor debit; §3.2).
    NoBondTerm,
    /// A pseudo-out or output mask is not a valid curve point.
    InvalidPoint,
    /// Left and right commitment sums differ.
    SumMismatch,
}

/// Amount encoding for `scalarmultH`: zero-padded 32-byte LE `u64` (Monero `d2h`).
fn d2h_scalar(amount: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&amount.to_le_bytes());
    Scalar::from_bytes_mod_order(bytes)
}

fn amount_h(amount: u64) -> EdwardsPoint {
    d2h_scalar(amount) * *H_POINT_LAZY
}

fn decompress_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, BondRctBalanceError> {
    let point = CompressedEdwardsY::from_slice(bytes)
        .map_err(|_| BondRctBalanceError::InvalidPoint)?
        .decompress()
        .ok_or(BondRctBalanceError::InvalidPoint)?;
    if !point.is_torsion_free() {
        return Err(BondRctBalanceError::InvalidPoint);
    }
    Ok(point)
}

fn sum_commitments_flat(flat: &[u8]) -> Result<EdwardsPoint, BondRctBalanceError> {
    if !flat.len().is_multiple_of(32) {
        return Err(BondRctBalanceError::InvalidPoint);
    }
    let mut sum = EdwardsPoint::default();
    for chunk in flat.chunks_exact(32) {
        let key: &[u8; 32] = chunk
            .try_into()
            .map_err(|_| BondRctBalanceError::InvalidPoint)?;
        sum += decompress_point(key)?;
    }
    Ok(sum)
}

/// Verify the bond-post RCT balance equation for flattened `N × 32` commitment keys.
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

    let mut sum_out = sum_commitments_flat(out_masks_flat)?;
    sum_out += amount_h(txn_fee);
    sum_out += amount_h(bond_credit);

    let mut sum_pseudo = sum_commitments_flat(pseudo_outs_flat)?;
    sum_pseudo += amount_h(bond_debit);

    if sum_pseudo == sum_out {
        Ok(())
    } else {
        Err(BondRctBalanceError::SumMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};

    fn commit(amount: u64, mask: Scalar) -> [u8; 32] {
        (mask * G + amount_h(amount)).compress().to_bytes()
    }

    fn h_only(amount: u64) -> [u8; 32] {
        amount_h(amount).compress().to_bytes()
    }

    #[test]
    fn rejects_neither_bond_term() {
        assert_eq!(
            verify_bond_post_rct_balance(&[], &[], 0, 0, 0),
            Err(BondRctBalanceError::NoBondTerm)
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
