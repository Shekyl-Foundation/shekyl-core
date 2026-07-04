// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-floor arithmetic — the Rust port of `Blockchain::check_fee`'s
//! acceptance gate (`blockchain.cpp:3913-3936`; parity row P2 of
//! `docs/design/DAEMON_SUBMIT_VERDICT.md` §8.6).
//!
//! The **parameters** (`fee_per_byte`, quantization mask) are Phase-B
//! snapshot facts computed C++-side — this module ports only the gate
//! arithmetic that consumes them:
//!
//! ```text
//! needed  = tx_weight × fee_per_byte
//! needed  = ⌈needed / mask⌉ × mask          (quantization)
//! accept  ⇔ fee ≥ needed − needed / 50      (2% acceptance buffer)
//! ```
//!
//! Because the floor is per-block dynamic (F34), the same arithmetic runs
//! twice: Phase C against the snapshot params, and again over the **fresh**
//! params when a Phase-D race returns them (the commit shim re-runs the C++
//! `check_fee` under the lock; Rust re-runs this arithmetic to *classify*).
//! Cross-language parity is KAT-pinned per §10 (the C++ oracle side lands
//! with the functional harness); the unit vectors here pin the Rust
//! arithmetic shape itself.

/// The quantized fee floor **before** the 2% acceptance buffer, or `None`
/// when the multiply overflows `u64` — an astronomically-high floor no fee
/// can meet, which callers treat as "below floor".
///
/// C++ performs these multiplies unchecked (`tx_weight * fee_per_byte`
/// wraps on overflow); per rule 20 §4 the Rust side is checked, and the
/// overflow disposition (reject) is strictly safer than the wrapped C++
/// value. A zero mask cannot occur (`get_fee_quantization_mask` returns
/// ≥ 1); it is normalized to 1 here so a shim contract violation cannot
/// panic the engine on a division by zero.
fn quantized_floor(tx_weight: u64, fee_per_byte: u64, quantization_mask: u64) -> Option<u64> {
    let mask = quantization_mask.max(1);
    let needed = tx_weight.checked_mul(fee_per_byte)?;
    needed.div_ceil(mask).checked_mul(mask)
}

/// Whether `fee` clears the dynamic floor for `tx_weight` under the given
/// snapshot parameters — the exact acceptance predicate of
/// `Blockchain::check_fee` (2% buffer included).
pub fn fee_meets_floor(
    tx_weight: u64,
    fee: u64,
    fee_per_byte: u64,
    quantization_mask: u64,
) -> bool {
    match quantized_floor(tx_weight, fee_per_byte, quantization_mask) {
        Some(needed) => fee >= needed - needed / 50,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors mirror the C++ arithmetic by hand-evaluation; the
    // cross-language KAT against a live `check_fee` lands with the
    // functional harness (§10 item 7).

    #[test]
    fn exact_multiple_of_mask_needs_no_rounding() {
        // needed = 1500 × 8000 = 12_000_000, already a multiple of 10_000.
        // buffer: 12_000_000 − 240_000 = 11_760_000.
        assert!(fee_meets_floor(1500, 11_760_000, 8000, 10_000));
        assert!(!fee_meets_floor(1500, 11_759_999, 8000, 10_000));
    }

    #[test]
    fn quantization_rounds_up_to_mask_multiple() {
        // needed = 1501 × 8000 = 12_008_000 → ⌈/10_000⌉×10_000 = 12_010_000.
        // buffer: 12_010_000 − 240_200 = 11_769_800.
        assert!(fee_meets_floor(1501, 11_769_800, 8000, 10_000));
        assert!(!fee_meets_floor(1501, 11_769_799, 8000, 10_000));
    }

    #[test]
    fn mask_one_disables_quantization() {
        // needed = 7 × 3 = 21; buffer: 21 − 0 = 21 (21/50 == 0).
        assert!(fee_meets_floor(7, 21, 3, 1));
        assert!(!fee_meets_floor(7, 20, 3, 1));
    }

    #[test]
    fn zero_fee_fails_any_positive_floor() {
        // The C++ floor is never zero (get_dynamic_base_fee returns ≥ 1),
        // so a zero-fee tx — including the fee-only serve-credit shape,
        // which consensus pins to fee 0 — fails the pool fee gate. Parity
        // with add_tx today (tx_pool.cpp:176-192); the serve-credit
        // submission contradiction is recorded in FOLLOWUPS, not resolved
        // here.
        assert!(!fee_meets_floor(300, 0, 1, 1));
    }

    #[test]
    fn multiply_overflow_rejects_instead_of_wrapping() {
        assert!(!fee_meets_floor(u64::MAX, u64::MAX, u64::MAX, 10_000));
    }

    #[test]
    fn zero_mask_normalizes_instead_of_panicking() {
        // Shim contract violation (mask is always ≥ 1 C++-side): the
        // engine must not be panickable from a marshalling bug.
        assert!(fee_meets_floor(10, 100, 10, 0));
    }
}
