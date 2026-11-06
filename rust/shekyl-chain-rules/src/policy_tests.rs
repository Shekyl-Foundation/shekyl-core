// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `policy_form` — the pool door's third call. Each row passes at its
//! boundary and refuses one past it, the first refusal in census order is
//! the answer, a pass records exactly the three rows, and a zero-fee
//! transaction is M3's (CEN-M11's job, deleted).

use shekyl_wire::transaction::{Transaction, MAX_TX_EXTRA};

use super::{policy_form, PolicyRefused};
use crate::census::PolicyRow;
use crate::harness::fixture::{listed, paying_fee, paying_its_floor};
use crate::rule_set::AdmissionPolicy;

/// A floor of one atomic unit per weight unit: the requirement is the
/// weight rounded up to the fee lattice.
const FLOORS: [u64; 1] = [1];

fn fee_of(tx: &Transaction) -> u64 {
    match &tx.ct {
        shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
        shekyl_wire::transaction::Ct::Null(_) => 0,
    }
}

fn paying_the_floor() -> Transaction {
    paying_its_floor(&listed([0x11; 32]), FLOORS[0])
}

fn refused(tx: &Transaction, floors: &[u64]) -> Option<PolicyRow> {
    policy_form(tx, &AdmissionPolicy::GENESIS, floors)
        .err()
        .map(|PolicyRefused { rule }| rule)
}

#[test]
fn a_transaction_at_every_bound_passes_and_records_the_three_rows() {
    let tx = paying_the_floor();
    let coverage =
        policy_form(&tx, &AdmissionPolicy::GENESIS, &FLOORS).expect("at the floor admits");
    for row in [PolicyRow::M3, PolicyRow::M4, PolicyRow::M5] {
        assert!(coverage.contains(row), "{row} recorded");
    }
    assert!(!coverage.contains(PolicyRow::M1), "only the rows judged");
}

/// M3: one atomic unit below the requirement refuses; the window's
/// minimum is the floor; an empty window refuses.
#[test]
fn m3_refuses_below_the_floor_and_reads_the_windows_minimum() {
    let tx = paying_the_floor();
    let short = paying_fee(listed([0x11; 32]), fee_of(&tx) - 1);
    assert_eq!(refused(&short, &FLOORS), Some(PolicyRow::M3));
    // A higher floor beside the low one does not raise the requirement.
    assert_eq!(refused(&tx, &[5, 1, 9]), None);
    assert_eq!(
        refused(&tx, &[]),
        Some(PolicyRow::M3),
        "no floor is not zero"
    );
}

/// CEN-M11 is gone because M3 already refuses a zero-fee transaction: the
/// one mechanism for the job.
#[test]
fn a_zero_fee_transaction_is_m3s_refusal() {
    assert_eq!(refused(&listed([0x11; 32]), &FLOORS), Some(PolicyRow::M3));
}

#[test]
fn m4_admits_the_cap_and_refuses_one_byte_past_it() {
    let mut at_cap = listed([0x11; 32]);
    at_cap.prefix.extra.resize(MAX_TX_EXTRA, 0);
    let at_cap = paying_its_floor(&at_cap, FLOORS[0]);
    assert_eq!(refused(&at_cap, &FLOORS), None);
    let mut over = listed([0x11; 32]);
    over.prefix.extra.resize(MAX_TX_EXTRA + 1, 0);
    let over = paying_its_floor(&over, FLOORS[0]);
    assert_eq!(refused(&over, &FLOORS), Some(PolicyRow::M4));
}

#[test]
fn m5_refuses_any_nonzero_unlock_time() {
    for unlock in [1, 1_000, u64::MAX] {
        // Priced after the change: `unlock_time` is a varint, so a wide one
        // moves the weight, and M3 must not answer first.
        let mut tx = listed([0x11; 32]);
        tx.prefix.unlock_time = unlock;
        let tx = paying_its_floor(&tx, FLOORS[0]);
        assert_eq!(
            refused(&tx, &FLOORS),
            Some(PolicyRow::M5),
            "unlock {unlock}"
        );
    }
}

/// Census order: a transaction wrong on M3 and M5 is named by M3.
#[test]
fn the_first_refusal_in_census_order_is_the_answer() {
    let mut tx = listed([0x11; 32]);
    tx.prefix.unlock_time = 7;
    assert_eq!(refused(&tx, &FLOORS), Some(PolicyRow::M3));
}
