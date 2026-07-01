//! Bond-post CT balance equation (ARCHIVAL_BOND_GATE4.md §3.2).
//!
//! Verifies `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`
//! over curve25519 commitments. The commitment-sum arithmetic and the
//! typed-side cleartext terms are **single-sourced** in
//! [`shekyl_ct_balance`](shekyl_ct_balance) (the same definitions construct
//! uses, so construct and verify cannot diverge —
//! `docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §7.2 / §11.1 Q2). This module
//! adds only the bond-specific term rigidity, and encodes it in a type: the
//! [`BondTerm`] enum makes "exactly one of credit / debit" a compile-time
//! property, so the verify function is total. Bulletproof+ verification remains
//! in C++ (`rctSigs`).

#![deny(unsafe_code)]

use shekyl_ct_balance::{verify_ct_balance, CtBalanceError, InputTerm, OutputTerm};
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

/// The single non-zero bond direction term a bond-post vin carries (§3.2).
///
/// "Exactly one **non-zero** direction (credit xor debit)" is a *type* property
/// here: both-terms, neither-term, **and zero-amount** posts are all
/// **unrepresentable** — the direction is the enum tag (so both/neither cannot
/// exist) and the amount is a [`NonZeroAtomicUnits`] (so a `Credit(0)` /
/// `Debit(0)` no-op — a "neither" state in disguise — cannot exist either), while
/// keeping the `AtomicUnits` money type rather than a bare integer. So
/// [`verify_bond_post_ct_balance`] is total (its only failures are a bad point or
/// a sum mismatch). Each variant fixes the genesis-frozen side —
/// `Credit -> extra_outputs`, `Debit -> extra_inputs` — so construct and verify
/// cannot pick opposite sides. The C++ ABI hands the two directions as separate
/// `u64`s; that `(credit, debit) -> BondTerm` conversion, including the
/// both/neither/zero rejection, lives at the FFI boundary (`shekyl-ffi`) where the
/// untrusted values enter — not in this consensus core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondTerm {
    /// A non-zero `bond_credit`, contributing `amount * H` to the output side.
    Credit(NonZeroAtomicUnits),
    /// A non-zero `bond_debit`, contributing `amount * H` to the input side.
    Debit(NonZeroAtomicUnits),
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
/// The [`BondTerm`] places exactly one direction amount on its genesis-frozen
/// side (`Credit -> extra_outputs`, `Debit -> extra_inputs`); the commitment-sum
/// balance is delegated to the single-sourced [`verify_ct_balance`]. Total — the
/// only failures are [`BondCtBalanceError`].
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

    // The both-terms / neither-term rejections are no longer expressible here —
    // `BondTerm` makes them unrepresentable. They are enforced (and tested) at the
    // `(credit, debit) -> BondTerm` FFI conversion in `shekyl-ffi`.

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
