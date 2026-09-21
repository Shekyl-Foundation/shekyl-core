//! Bond-post CT balance equation (ARCHIVAL_BOND_GATE4.md §3.2).
//!
//! Verifies `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`
//! over curve25519 commitments. The commitment-sum arithmetic and the
//! typed-side cleartext terms are **single-sourced** in
//! [`shekyl_ct_balance`](shekyl_ct_balance) (the same definitions construct
//! uses, so construct and verify cannot diverge —
//! `docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §7.2 / §11.1 Q2). This module
//! adds only the bond-specific term posture, and encodes it in a type: the
//! [`BondTerm`] enum makes "credit, debit, or unmoved" a compile-time
//! property, so the verify function is total. Bulletproof+ verification remains
//! in C++ (`ct_semantics`).

#![deny(unsafe_code)]

use shekyl_ct_balance::{verify_ct_balance, CtBalanceError, InputTerm, OutputTerm};
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

/// The collateral-movement posture a bond-post vin carries (§3.2).
///
/// JoinMarket credits a floor, Release debits the whole balance, and Reinstate
/// moves nothing (immutable-bond, 2026-09-20). Both-terms is unrepresentable:
/// the direction is the enum tag. Directed amounts are [`NonZeroAtomicUnits`],
/// so a `Credit(0)` / `Debit(0)` no-op cannot disguise itself as a directed
/// term. Zero-money is the named [`Self::Unmoved`] variant — Reinstate's CT
/// posture — rather than a pair of zeros smuggled through a directed arm.
///
/// Each directed variant fixes the genesis-frozen side —
/// `Credit -> extra_outputs`, `Debit -> extra_inputs` — so construct and verify
/// cannot pick opposite sides. `Unmoved` places nothing on either side: the
/// ordinary input/output/fee equation must close on its own.
///
/// The C++ ABI hands the two directions as separate `u64`s;
/// [`BondTerm::from_credit_debit`] is the single conversion (both-nonzero is
/// [`BondTermError::BothTerms`]; zero/zero is `Unmoved`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondTerm {
    /// A non-zero `bond_credit`, contributing `amount * H` to the output side.
    Credit(NonZeroAtomicUnits),
    /// A non-zero `bond_debit`, contributing `amount * H` to the input side.
    Debit(NonZeroAtomicUnits),
    /// No collateral moves. Reinstate's CT posture: extra_inputs and
    /// extra_outputs are both empty.
    Unmoved,
}

/// Failure of [`BondTerm::from_credit_debit`] at an untrusted `(credit, debit)` edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondTermError {
    /// Both directions non-zero — a credit and a debit on the same post.
    BothTerms,
}

impl BondTerm {
    /// Convert the untrusted `(credit, debit)` pair into a term.
    ///
    /// Zero/zero is [`Self::Unmoved`]. A single non-zero direction is
    /// [`Self::Credit`] or [`Self::Debit`]. Both non-zero is
    /// [`BondTermError::BothTerms`].
    pub fn from_credit_debit(credit: u64, debit: u64) -> Result<Self, BondTermError> {
        match (
            NonZeroAtomicUnits::new(AtomicUnits::from_raw(credit)),
            NonZeroAtomicUnits::new(AtomicUnits::from_raw(debit)),
        ) {
            (None, None) => Ok(Self::Unmoved),
            (Some(c), None) => Ok(Self::Credit(c)),
            (None, Some(d)) => Ok(Self::Debit(d)),
            (Some(_), Some(_)) => Err(BondTermError::BothTerms),
        }
    }
}

/// Bond-post balance sum failure modes.
///
/// Only the two failures the balance equation itself can produce — the term
/// rigidity is now enforced by [`BondTerm`]'s type, not a runtime variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondCtBalanceError {
    /// Malformed flat buffer or a pseudo-out / output mask is not a valid prime-order point.
    InvalidPoint,
    /// Left and right commitment sums differ.
    SumMismatch,
}

impl From<CtBalanceError> for BondCtBalanceError {
    fn from(e: CtBalanceError) -> Self {
        match e {
            CtBalanceError::InvalidPoint => Self::InvalidPoint,
            CtBalanceError::SumMismatch => Self::SumMismatch,
        }
    }
}

/// Verify the bond-post CT balance equation for flattened `N × 32` commitment keys.
///
/// A directed [`BondTerm`] places its amount on the genesis-frozen side
/// (`Credit -> extra_outputs`, `Debit -> extra_inputs`); [`BondTerm::Unmoved`]
/// places nothing on either side. The commitment-sum balance is delegated to
/// the single-sourced [`verify_ct_balance`]. Total — the only failures are
/// [`BondCtBalanceError`].
pub fn verify_bond_post_ct_balance(
    pseudo_outs_flat: &[u8],
    out_masks_flat: &[u8],
    txn_fee: u64,
    term: BondTerm,
) -> Result<(), BondCtBalanceError> {
    let fee = AtomicUnits::from_raw(txn_fee);
    let result = match term {
        BondTerm::Credit(amount) => verify_ct_balance(
            pseudo_outs_flat,
            out_masks_flat,
            fee,
            &[],
            &[OutputTerm::new(amount.get())],
        ),
        BondTerm::Debit(amount) => verify_ct_balance(
            pseudo_outs_flat,
            out_masks_flat,
            fee,
            &[InputTerm::new(amount.get())],
            &[],
        ),
        BondTerm::Unmoved => verify_ct_balance(pseudo_outs_flat, out_masks_flat, fee, &[], &[]),
    };
    result.map_err(BondCtBalanceError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
    use shekyl_ct_balance::amount_commitment;

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

    fn nz(v: u64) -> NonZeroAtomicUnits {
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(v)).expect("test bond amount is non-zero")
    }

    #[test]
    fn from_credit_debit_maps_the_three_postures() {
        assert_eq!(BondTerm::from_credit_debit(0, 0), Ok(BondTerm::Unmoved));
        assert_eq!(
            BondTerm::from_credit_debit(7, 0),
            Ok(BondTerm::Credit(nz(7)))
        );
        assert_eq!(
            BondTerm::from_credit_debit(0, 3),
            Ok(BondTerm::Debit(nz(3)))
        );
        assert_eq!(
            BondTerm::from_credit_debit(1, 1),
            Err(BondTermError::BothTerms)
        );
    }

    #[test]
    fn unmoved_term_closes_empty_commitments() {
        assert!(verify_bond_post_ct_balance(&[], &[], 0, BondTerm::Unmoved).is_ok());
        let leftover = h_only(1);
        assert_eq!(
            verify_bond_post_ct_balance(&leftover, &[], 0, BondTerm::Unmoved),
            Err(BondCtBalanceError::SumMismatch)
        );
    }

    #[test]
    fn credit_term_balances_without_outputs() {
        const BOND_CREDIT: u64 = 750_000_000;
        let pseudo = h_only(BOND_CREDIT);
        assert!(
            verify_bond_post_ct_balance(&pseudo, &[], 0, BondTerm::Credit(nz(BOND_CREDIT))).is_ok()
        );
        assert_eq!(
            verify_bond_post_ct_balance(&pseudo, &[], 0, BondTerm::Credit(nz(BOND_CREDIT - 1))),
            Err(BondCtBalanceError::SumMismatch)
        );
        // The credit amount placed on the wrong (debit) side no longer balances.
        assert_eq!(
            verify_bond_post_ct_balance(&pseudo, &[], 0, BondTerm::Debit(nz(BOND_CREDIT))),
            Err(BondCtBalanceError::SumMismatch)
        );
    }

    #[test]
    fn debit_term_balances_with_output_mask() {
        const BOND_DEBIT: u64 = 500_000_000;
        let mask_scalar = Scalar::from_bytes_mod_order([7u8; 32]);
        let out_mask = commit(BOND_DEBIT, mask_scalar);
        let pseudo = commit(0, mask_scalar);
        assert!(verify_bond_post_ct_balance(
            &pseudo,
            &out_mask,
            0,
            BondTerm::Debit(nz(BOND_DEBIT))
        )
        .is_ok());
        // The debit amount placed on the wrong (credit) side no longer balances.
        assert_eq!(
            verify_bond_post_ct_balance(&pseudo, &out_mask, 0, BondTerm::Credit(nz(BOND_DEBIT))),
            Err(BondCtBalanceError::SumMismatch)
        );
        assert_eq!(
            verify_bond_post_ct_balance(&pseudo, &out_mask, 0, BondTerm::Debit(nz(BOND_DEBIT - 1))),
            Err(BondCtBalanceError::SumMismatch)
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
            verify_bond_post_ct_balance(&torsion, &[], 0, BondTerm::Credit(nz(1))),
            Err(BondCtBalanceError::InvalidPoint)
        );
    }
}
