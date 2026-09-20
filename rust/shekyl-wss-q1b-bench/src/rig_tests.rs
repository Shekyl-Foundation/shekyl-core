// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

fn rig_machine() -> Environment {
    Environment {
        arch: "aarch64",
        pointer_width_bits: 64,
        total_ram_bytes: Some(8_000_000_000),
        cpu_model: Some("Cortex-A72".to_string()),
        kernel: Some("6.6.0".to_string()),
        git_revision: None,
    }
}

// ── The grading-mode refusal red-bite ───────────────────────────────────────

#[test]
fn grading_is_refused_on_a_machine_that_is_not_the_rig() {
    // The bite: a dev box asks to grade and is refused BY ARCHITECTURE, not by
    // an operator remembering not to pass the flag.
    let dev_box = Environment {
        arch: "x86_64",
        ..rig_machine()
    };
    let err = decide(&dev_box, true, Some(StorageAttestation::UsbSsd), true)
        .expect_err("an x86_64 box must not grade");
    assert!(
        err.unmet.iter().any(|u| u.contains("x86_64")),
        "the refusal must name what was wrong: {err}"
    );
}

#[test]
fn grading_is_refused_on_a_thirty_two_bit_userland() {
    // Rule 76's floor is a device class; §6.3.4 adds the userland, because "a
    // 32-bit userland on the same board is a different machine for this work".
    let board = Environment {
        pointer_width_bits: 32,
        ..rig_machine()
    };
    let err = decide(&board, true, Some(StorageAttestation::UsbSsd), true)
        .expect_err("a 32-bit userland must not grade");
    assert!(err.unmet.iter().any(|u| u.contains("32-bit")));
}

#[test]
fn an_unreadable_ram_figure_refuses_rather_than_assumes() {
    // Rule 47: absence of signal is first evidence the subject is absent. A
    // gate that treated "could not read" as "fine" would pass for the wrong
    // reason -- the exact shape this module exists to avoid.
    let unknown = Environment {
        total_ram_bytes: None,
        ..rig_machine()
    };
    let err = decide(&unknown, true, Some(StorageAttestation::UsbSsd), true)
        .expect_err("unknown RAM must not grade");
    assert!(err.unmet.iter().any(|u| u.contains("could not be read")));
}

#[test]
fn every_unmet_pin_is_reported_not_just_the_first() {
    let wrong = Environment {
        arch: "x86_64",
        pointer_width_bits: 32,
        total_ram_bytes: Some(2_000_000_000),
        ..rig_machine()
    };
    let err = wrong.check_enforceable().expect_err("three pins are unmet");
    assert_eq!(err.unmet.len(), 3, "got {:?}", err.unmet);
}

// ── The attestation split ───────────────────────────────────────────────────

#[test]
fn grading_needs_the_attestations_the_process_cannot_observe() {
    let missing_storage = decide(&rig_machine(), true, None, true)
        .expect_err("storage is unobservable, so it must be attested");
    assert!(missing_storage
        .unmet
        .iter()
        .any(|u| u.contains("--attest-storage")));

    let missing_thermal = decide(
        &rig_machine(),
        true,
        Some(StorageAttestation::UsbSsd),
        false,
    )
    .expect_err("thermal steady state is unobservable, so it must be attested");
    assert!(missing_thermal
        .unmet
        .iter()
        .any(|u| u.contains("--attest-thermal-steady")));
}

#[test]
fn an_attestation_that_contradicts_the_pin_refuses() {
    let err = decide(
        &rig_machine(),
        true,
        Some(StorageAttestation::MicroSd),
        true,
    )
    .expect_err("microSD is not the rig pin");
    assert!(err.unmet.iter().any(|u| u.contains("microsd")));
}

#[test]
fn a_complete_rig_grades_and_separates_enforced_from_attested() {
    let verdict = decide(&rig_machine(), true, Some(StorageAttestation::UsbSsd), true)
        .expect("the pinned rig grades");
    assert!(verdict.grading);
    // The whole point of the split: a reader can tell machine evidence from a
    // human's word.
    assert_eq!(verdict.enforced.len(), 3);
    assert_eq!(verdict.attested.len(), 2);
}

#[test]
fn measurement_is_never_refused() {
    // A dev-box run must still produce numbers -- otherwise the schema's first
    // review happens on the rig, which is the worst place to discover it.
    let dev_box = Environment {
        arch: "x86_64",
        ..rig_machine()
    };
    let verdict = decide(&dev_box, false, None, false).expect("measurement is always allowed");
    assert!(!verdict.grading);
}
