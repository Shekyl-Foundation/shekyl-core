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
        // The BOARD, as `/proc/cpuinfo`'s `Model` line gives it -- not the
        // core. `Cortex-A72` used to sit here and used to pass, which is the
        // same confusion the marker list carried.
        cpu_model: Some("Raspberry Pi 4 Model B Rev 1.4".to_string()),
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
        cpu_model: Some("11th Gen Intel(R) Core(TM) i9".to_string()),
        ..rig_machine()
    };
    let err = wrong.check_enforceable().expect_err("every pin is unmet");
    assert_eq!(err.unmet.len(), 4, "got {:?}", err.unmet);
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
    // human's word. Named, not just counted -- a count alone would survive one
    // pin being swapped for another.
    assert_eq!(verdict.enforced.len(), 4);
    assert!(verdict.enforced.iter().any(|e| e.contains("arch")));
    assert!(verdict.enforced.iter().any(|e| e.contains("64-bit")));
    assert!(verdict.enforced.iter().any(|e| e.contains("RAM")));
    assert!(verdict.enforced.iter().any(|e| e.contains("device")));
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

// ── The device pin ──────────────────────────────────────────────────────────

#[test]
fn an_aarch64_host_that_is_not_the_pinned_board_is_refused() {
    // The hole this closes: arch, userland and RAM all passing made any
    // aarch64 box with 7.5 GB "the pinned rig", though §6.3.4 names a Pi 4.
    let other_board = Environment {
        cpu_model: Some("Neoverse-N1".to_string()),
        ..rig_machine()
    };
    let err = other_board
        .check_enforceable()
        .expect_err("a different aarch64 board is not the rig");
    assert!(err.unmet.iter().any(|u| u.contains("Neoverse")), "{err}");
}

#[test]
fn an_unreadable_device_model_refuses_rather_than_assumes() {
    let unknown = Environment {
        cpu_model: None,
        ..rig_machine()
    };
    let err = unknown
        .check_enforceable()
        .expect_err("unknown device must not grade");
    assert!(err.unmet.iter().any(|u| u.contains("device model")));
}

#[test]
fn each_pinned_device_marker_is_accepted_on_its_own() {
    // The kernel answers with different fields on different boards, so any one
    // marker identifies the board. A test per marker keeps a future edit from
    // silently dropping the one this rig actually reports.
    for marker in REQUIRED_DEVICE_MARKERS {
        let board = Environment {
            cpu_model: Some(format!("something {marker} something")),
            ..rig_machine()
        };
        assert!(
            board.check_enforceable().is_ok(),
            "marker {marker} should identify the pinned board"
        );
    }
}

// ── Posture ─────────────────────────────────────────────────────────────────

#[test]
fn loopback_endpoints_are_recognised_and_others_are_not() {
    for url in [
        "http://127.0.0.1:18081",
        "http://localhost:18081",
        "http://[::1]:18081",
        "http://127.2.3.4:28591/json_rpc",
        "localhost:18081",
    ] {
        assert!(rig_is_loopback(url), "{url} should be loopback");
    }
    for url in [
        "http://192.168.1.10:18081",
        "http://daemon.example:18081",
        "http://10.0.0.1",
        // The trap a substring check would fall into: loopback in the PATH,
        // not the host.
        "http://evil.example/127.0.0.1",
        // The trap a PREFIX check falls into, and the one the hand-rolled
        // version actually fell into: a remote hostname that begins with the
        // loopback digits. `is_loopback_host` parses an IP literal first, so a
        // name that is not an address cannot pass.
        "http://127.0.0.1.evil.com:18081",
        "http://127evil.com",
    ] {
        assert!(!rig_is_loopback(url), "{url} should not be loopback");
    }
}

fn rig_is_loopback(url: &str) -> bool {
    super::is_loopback_endpoint(url)
}

#[test]
fn a_cortex_a72_core_string_alone_no_longer_grades() {
    // The hole the marker list reopened: the A72 is a CPU CORE shipped in many
    // aarch64 boards, so accepting it graded any of them as the pinned Pi 4.
    // §6.3.4 pins the board.
    let other_board_same_core = Environment {
        cpu_model: Some("ARMv8 Processor rev 3 Cortex-A72".to_string()),
        ..rig_machine()
    };
    assert!(
        other_board_same_core.check_enforceable().is_err(),
        "a core name must not stand in for a board"
    );
}
