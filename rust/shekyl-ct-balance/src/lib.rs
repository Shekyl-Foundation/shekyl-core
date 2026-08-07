// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Single-sourced CT cleartext balance equation and typed-side terms.
//!
//! The consensus balance an CT transaction must satisfy over curve25519
//! Pedersen commitments is
//!
//! ```text
//! sum(pseudoOuts) + extra_inputs = sum(out_masks) + fee + extra_outputs
//! ```
//!
//! where the *extra* terms are cleartext `amount * H` contributions of the same
//! kind as `fee` (today: `bond_credit -> extra_outputs`, `bond_debit ->
//! extra_inputs`). This crate is the **single home** for that equation and for
//! the typed-side cleartext terms; it is imported by both `shekyl-tx-builder`
//! (construct) and `shekyl-archival-retention` (verify) so the two cannot
//! diverge on a genesis-frozen consensus rule
//! (`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §7.2 / §11.1 Q2). The verify
//! equation previously lived in `shekyl-archival-retention::bond_ct_balance`
//! and migrated here; that module now wraps this crate with the bond-specific
//! term rigidity.
//!
//! Bulletproof+ range-proof verification remains in C++ (`rctSigs`); this crate
//! is only the commitment-sum balance.
//!
//! The crate is also the single home for the §2.3 **output-point validity**
//! rule ([`check_output_keys`] / [`check_commitment_masks`]): the same
//! canonical-prime-order gate the balance equation applies to its commitments,
//! extended to the output points the balance equation never sees (output
//! public keys, and coinbase `outPk` masks under `CTTypeNull`).

#![deny(unsafe_code)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use shekyl_curve_generators::H as H_POINT_LAZY;
use shekyl_units::AtomicUnits;

/// A cleartext balance term contributing `amount * H` to the **input** side of
/// the balance (the `sum(pseudoOuts) + extra_inputs` side).
///
/// The side is encoded in the *type*, not a runtime tag: a term that belongs on
/// the input side can only be built as an [`InputTerm`], so a wrong-side term is
/// *unrepresentable* rather than caught at verify
/// (`ARCHIVAL_BOND_CONSTRUCTION.md` §11.1 Q2). The amount is an [`AtomicUnits`],
/// carrying the checked-only money discipline of `shekyl-units`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputTerm(AtomicUnits);

/// A cleartext balance term contributing `amount * H` to the **output** side of
/// the balance (the `sum(out_masks) + fee + extra_outputs` side).
///
/// See [`InputTerm`] for the side-as-type rationale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputTerm(AtomicUnits);

impl InputTerm {
    /// A new input-side term for `amount`.
    #[must_use]
    pub const fn new(amount: AtomicUnits) -> Self {
        Self(amount)
    }

    /// The term's amount.
    #[must_use]
    pub const fn amount(self) -> AtomicUnits {
        self.0
    }
}

impl OutputTerm {
    /// A new output-side term for `amount`.
    #[must_use]
    pub const fn new(amount: AtomicUnits) -> Self {
        Self(amount)
    }

    /// The term's amount.
    #[must_use]
    pub const fn amount(self) -> AtomicUnits {
        self.0
    }
}

/// CT balance failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtBalanceError {
    /// A flat commitment buffer was not a multiple of 32, or a key was not a
    /// canonical torsion-free prime-order point.
    InvalidPoint,
    /// The input-side and output-side commitment sums differ.
    SumMismatch,
}

impl core::fmt::Display for CtBalanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CtBalanceError::InvalidPoint => {
                "a commitment is not a canonical, torsion-free prime-order point"
            }
            CtBalanceError::SumMismatch => "input-side and output-side commitment sums differ",
        })
    }
}

impl std::error::Error for CtBalanceError {}

/// Amount encoding for `scalarmultH`: zero-padded 32-byte LE `u64` (Monero
/// `d2h`). The `mod_order` reduction is a no-op for any `u64` (far below `L`).
fn d2h_scalar(amount: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&amount.to_le_bytes());
    Scalar::from_bytes_mod_order(bytes)
}

/// The cleartext commitment `amount * H` for a balance term or fee.
///
/// This is the single definition of the `amount * H` mapping shared by every
/// construct and verify site, so the two cannot pick different encodings of a
/// cleartext amount.
#[must_use]
pub fn amount_commitment(amount: AtomicUnits) -> EdwardsPoint {
    d2h_scalar(amount.to_raw()) * *H_POINT_LAZY
}

fn decompress_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, CtBalanceError> {
    let point = CompressedEdwardsY::from_slice(bytes)
        .map_err(|_| CtBalanceError::InvalidPoint)?
        .decompress()
        .ok_or(CtBalanceError::InvalidPoint)?;
    // Canonical-encoding check (`GENESIS_TX_WIRE_FORMAT.md` §2.3). `decompress`
    // reduces the y-coordinate mod the field prime `p`, so a non-canonical
    // encoding — `y = p + k`, or a set sign bit over `x = 0` — decodes *silently*
    // to a valid point. The C++<->Rust differential corpus caught exactly this:
    // Rust accepted `y = p + 1` (the identity) where C++ `ge_frombytes_vartime`
    // rejects it, a residual second-serialization (tx-malleability) surface.
    // Reject any input that does not round-trip through `compress()`.
    // Adversarial-only: honest `compress()` output is always canonical, so no
    // valid commitment is affected.
    let canonical = point.compress();
    if canonical.as_bytes() != bytes {
        return Err(CtBalanceError::InvalidPoint);
    }
    if !point.is_torsion_free() {
        return Err(CtBalanceError::InvalidPoint);
    }
    Ok(point)
}

fn sum_commitments_flat(flat: &[u8]) -> Result<EdwardsPoint, CtBalanceError> {
    if !flat.len().is_multiple_of(32) {
        return Err(CtBalanceError::InvalidPoint);
    }
    let mut sum = EdwardsPoint::default();
    for chunk in flat.chunks_exact(32) {
        let key: &[u8; 32] = chunk.try_into().map_err(|_| CtBalanceError::InvalidPoint)?;
        sum += decompress_point(key)?;
    }
    Ok(sum)
}

/// Verify the CT cleartext balance over flattened `N x 32` commitment keys.
///
/// Checks
/// `sum(pseudoOuts) + sum(extra_inputs) = sum(out_masks) + fee + sum(extra_outputs)`
/// where each `extra_*` term and the `fee` contribute `amount * H`
/// ([`amount_commitment`]). The typed slices make the per-term side a
/// compile-time property; this function never has to ask which side a term is
/// on. The caller is responsible for any domain-specific rigidity on the terms
/// (e.g. the bond credit-xor-debit rule lives in
/// `shekyl-archival-retention::bond_ct_balance`).
pub fn verify_ct_balance(
    pseudo_outs_flat: &[u8],
    out_masks_flat: &[u8],
    fee: AtomicUnits,
    extra_inputs: &[InputTerm],
    extra_outputs: &[OutputTerm],
) -> Result<(), CtBalanceError> {
    let mut left = sum_commitments_flat(pseudo_outs_flat)?;
    for term in extra_inputs {
        left += amount_commitment(term.amount());
    }

    let mut right = sum_commitments_flat(out_masks_flat)?;
    right += amount_commitment(fee);
    for term in extra_outputs {
        right += amount_commitment(term.amount());
    }

    if left == right {
        Ok(())
    } else {
        Err(CtBalanceError::SumMismatch)
    }
}

/// Output-point validity failure modes (`GENESIS_TX_WIRE_FORMAT.md` §2.3,
/// output-point rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPointsError {
    /// An output public key was not a canonical, torsion-free, non-identity
    /// prime-order point (or the flat buffer was not a multiple of 32).
    InvalidOutputKey,
    /// A commitment mask was not a canonical, torsion-free prime-order point
    /// (or the flat buffer was not a multiple of 32).
    InvalidMask,
    /// A commitment mask took a trivial, amount-leaking form: the identity
    /// (`mask=0, amount=0`), bare `G` (`mask=1, amount=0`), or — coinbase only —
    /// `zeroCommit(amount) = G + amount*H` (`mask=1`, public amount).
    TrivialMask,
}

impl core::fmt::Display for OutputPointsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            OutputPointsError::InvalidOutputKey => {
                "an output public key is not a canonical, torsion-free, \
                 non-identity prime-order point"
            }
            OutputPointsError::InvalidMask => {
                "a commitment mask is not a canonical, torsion-free prime-order point"
            }
            OutputPointsError::TrivialMask => {
                "a commitment mask uses a trivial amount-leaking form (identity, G, \
                 or coinbase zeroCommit)"
            }
        })
    }
}

impl std::error::Error for OutputPointsError {}

/// Check every output public key `O` in a flattened `N × 32` buffer against the
/// §2.3 output-point rule: canonical encoding, prime-order (torsion-free), and
/// not the identity.
///
/// The identity is rejected on top of the canonical/torsion gates because the
/// FCMP++ leaf builder cannot represent it (Wei25519 `to_xy` has no affine form
/// for the point at infinity), so an identity `O` accepted at admission would be
/// a permanently skipped tree leaf — exactly the silent-skip hole this rule
/// closes. Honest output keys (`O = ho·G + B + y·T`, torsion-checked at
/// creation) are never affected; the rule is adversarial-only.
pub fn check_output_keys(flat: &[u8]) -> Result<(), OutputPointsError> {
    if !flat.len().is_multiple_of(32) {
        return Err(OutputPointsError::InvalidOutputKey);
    }
    for chunk in flat.chunks_exact(32) {
        let key: &[u8; 32] = chunk
            .try_into()
            .map_err(|_| OutputPointsError::InvalidOutputKey)?;
        let point = decompress_point(key).map_err(|_| OutputPointsError::InvalidOutputKey)?;
        if point.is_identity() {
            return Err(OutputPointsError::InvalidOutputKey);
        }
    }
    Ok(())
}

/// Check every commitment mask (`outPk[i].mask`) in a flattened `N × 32` buffer
/// against the §2.3 output-point rule plus the trivial-mask fingerprint guards.
///
/// Structural gates (every mask): canonical encoding and prime-order
/// (torsion-free), rejected as [`OutputPointsError::InvalidMask`].
/// For non-coinbase txs these are redundant with the balance equation's own
/// point gate; applying them here keeps the rule uniform and covers coinbase
/// (`CTTypeNull`), which has no balance equation.
///
/// Trivial-form gates (every mask): the identity (`mask=0, amount=0`) and bare
/// `G` (`mask=1, amount=0`) → [`OutputPointsError::TrivialMask`] — defense in
/// depth against construction bugs.
///
/// Coinbase fingerprint gate: when `coinbase_amounts` is `Some`, mask `i` (for
/// `i < coinbase_amounts.len()`) must not equal
/// `zeroCommit(amount) = G + amount*H` — the trivially-computable commitment
/// that leaks the confidential-coinbase amount to any observer. Pass `None` for
/// non-coinbase txs.
pub fn check_commitment_masks(
    flat: &[u8],
    coinbase_amounts: Option<&[u64]>,
) -> Result<(), OutputPointsError> {
    if !flat.len().is_multiple_of(32) {
        return Err(OutputPointsError::InvalidMask);
    }
    for (i, chunk) in flat.chunks_exact(32).enumerate() {
        let key: &[u8; 32] = chunk
            .try_into()
            .map_err(|_| OutputPointsError::InvalidMask)?;
        let point = decompress_point(key).map_err(|_| OutputPointsError::InvalidMask)?;
        if point.is_identity() || point == ED25519_BASEPOINT_POINT {
            return Err(OutputPointsError::TrivialMask);
        }
        if let Some(amounts) = coinbase_amounts {
            if let Some(&amount) = amounts.get(i) {
                let trivial =
                    ED25519_BASEPOINT_POINT + amount_commitment(AtomicUnits::from_raw(amount));
                if point == trivial {
                    return Err(OutputPointsError::TrivialMask);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;

    fn au(v: u64) -> AtomicUnits {
        AtomicUnits::from_raw(v)
    }

    fn commit(amount: u64, mask: Scalar) -> [u8; 32] {
        (mask * G + amount_commitment(au(amount)))
            .compress()
            .to_bytes()
    }

    fn h_only(amount: u64) -> [u8; 32] {
        amount_commitment(au(amount)).compress().to_bytes()
    }

    #[test]
    fn empty_balance_with_zero_fee_is_ok() {
        assert!(verify_ct_balance(&[], &[], AtomicUnits::ZERO, &[], &[]).is_ok());
    }

    #[test]
    fn fee_only_requires_matching_input() {
        const FEE: u64 = 12_345;
        // pseudoOut carries FEE*H so input == out_masks(empty) + fee.
        let pseudo = h_only(FEE);
        assert!(verify_ct_balance(&pseudo, &[], au(FEE), &[], &[]).is_ok());
        assert_eq!(
            verify_ct_balance(&pseudo, &[], au(FEE - 1), &[], &[]),
            Err(CtBalanceError::SumMismatch)
        );
    }

    #[test]
    fn output_term_balances_without_real_outputs() {
        // bond_credit case: pseudoOut = credit*H, single OutputTerm = credit.
        const CREDIT: u64 = 750_000_000;
        let pseudo = h_only(CREDIT);
        assert!(verify_ct_balance(
            &pseudo,
            &[],
            AtomicUnits::ZERO,
            &[],
            &[OutputTerm::new(au(CREDIT))]
        )
        .is_ok());
        // Same amount on the wrong side does not balance.
        assert_eq!(
            verify_ct_balance(
                &pseudo,
                &[],
                AtomicUnits::ZERO,
                &[InputTerm::new(au(CREDIT))],
                &[]
            ),
            Err(CtBalanceError::SumMismatch)
        );
    }

    #[test]
    fn input_term_balances_with_output_mask() {
        // bond_debit case: out_mask = commit(debit, m), pseudoOut = commit(0, m),
        // single InputTerm = debit closes the balance.
        const DEBIT: u64 = 500_000_000;
        let mask = Scalar::from_bytes_mod_order([7u8; 32]);
        let out_mask = commit(DEBIT, mask);
        let pseudo = commit(0, mask);
        assert!(verify_ct_balance(
            &pseudo,
            &out_mask,
            AtomicUnits::ZERO,
            &[InputTerm::new(au(DEBIT))],
            &[]
        )
        .is_ok());
        assert_eq!(
            verify_ct_balance(
                &pseudo,
                &out_mask,
                AtomicUnits::ZERO,
                &[],
                &[OutputTerm::new(au(DEBIT))]
            ),
            Err(CtBalanceError::SumMismatch)
        );
    }

    #[test]
    fn rejects_non_multiple_of_32() {
        assert_eq!(
            verify_ct_balance(&[0u8; 31], &[], AtomicUnits::ZERO, &[], &[]),
            Err(CtBalanceError::InvalidPoint)
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
            verify_ct_balance(
                &torsion,
                &[],
                AtomicUnits::ZERO,
                &[],
                &[OutputTerm::new(au(1))]
            ),
            Err(CtBalanceError::InvalidPoint)
        );
    }

    // A known curve25519 small-order (8-torsion) point, shared with
    // `rejects_small_order_commitment`.
    const TORSION: [u8; 32] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ];

    /// `y = p + 1`: a non-canonical encoding of the identity.
    fn non_canonical_identity() -> [u8; 32] {
        let mut b = [0xffu8; 32];
        b[0] = 0xee;
        b[31] = 0x7f;
        b
    }

    #[test]
    fn output_keys_accept_honest_points() {
        // G and a generic multiple of G are canonical prime-order non-identity.
        let mut flat = Vec::new();
        flat.extend_from_slice(G.compress().as_bytes());
        flat.extend_from_slice(
            (Scalar::from_bytes_mod_order([9u8; 32]) * G)
                .compress()
                .as_bytes(),
        );
        assert!(check_output_keys(&flat).is_ok());
        assert!(check_output_keys(&[]).is_ok());
    }

    #[test]
    fn output_keys_reject_torsion_identity_and_non_canonical() {
        assert_eq!(
            check_output_keys(&TORSION),
            Err(OutputPointsError::InvalidOutputKey)
        );
        // Canonical identity: decompresses fine, is torsion-free — the explicit
        // identity gate is what rejects it (no Wei25519 affine form => no leaf).
        let identity = EdwardsPoint::default().compress().to_bytes();
        assert_eq!(
            check_output_keys(&identity),
            Err(OutputPointsError::InvalidOutputKey)
        );
        assert_eq!(
            check_output_keys(&non_canonical_identity()),
            Err(OutputPointsError::InvalidOutputKey)
        );
        assert_eq!(
            check_output_keys(&[0u8; 31]),
            Err(OutputPointsError::InvalidOutputKey)
        );
    }

    #[test]
    fn masks_reject_torsion_and_non_canonical_as_invalid() {
        assert_eq!(
            check_commitment_masks(&TORSION, None),
            Err(OutputPointsError::InvalidMask)
        );
        assert_eq!(
            check_commitment_masks(&non_canonical_identity(), None),
            Err(OutputPointsError::InvalidMask)
        );
        assert_eq!(
            check_commitment_masks(&[0u8; 33], None),
            Err(OutputPointsError::InvalidMask)
        );
    }

    #[test]
    fn masks_reject_trivial_forms() {
        let identity = EdwardsPoint::default().compress().to_bytes();
        assert_eq!(
            check_commitment_masks(&identity, None),
            Err(OutputPointsError::TrivialMask)
        );
        let g = G.compress().to_bytes();
        assert_eq!(
            check_commitment_masks(&g, None),
            Err(OutputPointsError::TrivialMask)
        );
    }

    #[test]
    fn coinbase_masks_reject_zero_commit_of_amount() {
        const AMOUNT: u64 = 600_000_000_000;
        // zeroCommit(amount) = G + amount*H — the amount-leaking fingerprint.
        let zero_commit = (G + amount_commitment(au(AMOUNT))).compress().to_bytes();
        assert_eq!(
            check_commitment_masks(&zero_commit, Some(&[AMOUNT])),
            Err(OutputPointsError::TrivialMask)
        );
        // Same point with a different claimed amount is not the fingerprint.
        assert!(check_commitment_masks(&zero_commit, Some(&[AMOUNT + 1])).is_ok());
        // And without the coinbase amounts it is just a well-formed mask.
        assert!(check_commitment_masks(&zero_commit, None).is_ok());
    }

    #[test]
    fn honest_masks_accept() {
        let mask = commit(42, Scalar::from_bytes_mod_order([3u8; 32]));
        assert!(check_commitment_masks(&mask, None).is_ok());
        assert!(check_commitment_masks(&mask, Some(&[42])).is_ok());
        assert!(check_commitment_masks(&[], None).is_ok());
    }

    #[test]
    fn rejects_non_canonical_encoding() {
        // `y = p + 1` (bytes `ee ff..ff 7f`) is a non-canonical encoding: dalek's
        // `decompress` reduces it mod `p` to `y = 1` (the identity) and accepts it,
        // but the canonical round-trip check rejects the non-canonical bytes. The
        // C++ `ge_frombytes_vartime` rejects the same encoding (differential corpus,
        // `tests/unit_tests/ct_balance_differential.cpp`).
        let mut y_p_plus_1 = [0xffu8; 32];
        y_p_plus_1[0] = 0xee;
        y_p_plus_1[31] = 0x7f;
        assert_eq!(
            verify_ct_balance(&y_p_plus_1, &[], AtomicUnits::ZERO, &[], &[]),
            Err(CtBalanceError::InvalidPoint)
        );
    }
}
