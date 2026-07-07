// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Serve-credit settlement-epoch eligibility (gate-4 §2.2 `E_first`).

/// Lower bound only: first claimable/serve epoch is `E_join + 1` (gate-4 §2.2).
///
/// Upper bounds (`good_through`, credit-window `H_close`, W-forfeiture on emission)
/// are enforced elsewhere in consensus — not co-located with this predicate.
#[must_use]
pub fn serve_credit_epoch_ok(settlement_epoch: u64, join_settlement_epoch: u64) -> bool {
    match join_settlement_epoch.checked_add(1) {
        Some(e_first) => settlement_epoch >= e_first,
        // No representable E_first when join epoch is u64::MAX.
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_epoch_e_join() {
        assert!(!serve_credit_epoch_ok(0, 0));
    }

    #[test]
    fn accepts_epoch_e_first() {
        assert!(serve_credit_epoch_ok(1, 0));
    }

    #[test]
    fn accepts_later_epochs() {
        assert!(serve_credit_epoch_ok(5, 3));
    }

    #[test]
    fn accepts_exactly_e_first() {
        assert!(!serve_credit_epoch_ok(3, 3));
        assert!(serve_credit_epoch_ok(4, 3));
    }

    #[test]
    fn no_e_first_when_join_epoch_is_u64_max() {
        assert!(!serve_credit_epoch_ok(u64::MAX, u64::MAX));
        assert!(serve_credit_epoch_ok(u64::MAX, u64::MAX - 1));
    }
}
