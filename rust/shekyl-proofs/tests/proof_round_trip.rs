// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! EXIT CRITERION: tx_proof V3 10-point round-trip.
//!
//! These 10 tests must ALL pass before the Keccak Eviction sprint is declared
//! done. Each test is a `todo!()` stub locked by `#[ignore]` during Phases 1-4.
//! Phase 5 fills in the implementations and removes `#[ignore]`.
//!
//! Tests 1-8: Pure Rust, exercising the proof crate directly.
//! Tests 9-10: Wallet-state tests. Stubbed here for checklist completeness;
//! the definitive implementations are C++/FFI core_tests that exercise
//! wallet2's tx_key absence error paths.
//!
//! Wire format size assertions (Phase 5):
//!   outbound: 101 + 128*N bytes  (header: version[1]+tx_key[32]+schnorr[64]+count[4]; per-output: ho, y, z, k_amount)
//!   inbound:   69 + 128*N bytes  (header: version[1]+schnorr[64]+count[4]; per-output: ho, y, z, k_amount)
//!   reserve:   69 + 192*N bytes  (header: version[1]+schnorr[64]+count[4]; per-output: ho, y, k_amount, key_image, DLEQ)

// --------------------------------------------------------------------------
// Test 1: Construct V3 tx, generate outbound proof, third-party verifies.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_01_outbound_proof_round_trip() {
    // Construct a V3 tx with known sender/recipient (both with PQC keys).
    // Generate outbound proof from sender.
    // Third-party verifier verifies -- returns (recipient_address, amount).
    todo!("Phase 5: outbound proof generate + verify round trip");
}

// --------------------------------------------------------------------------
// Test 2: Generate inbound proof from recipient, verifier confirms.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_02_inbound_proof_round_trip() {
    // Same V3 tx as test 1.
    // Recipient generates inbound proof.
    // Same verifier verifies -- returns same (recipient_address, amount).
    todo!("Phase 5: inbound proof generate + verify round trip");
}

// --------------------------------------------------------------------------
// Test 3: Inbound proof returns same result as outbound proof.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_03_outbound_inbound_consistency() {
    // After tests 1 and 2, the (recipient_address, amount) pairs must match.
    todo!("Phase 5: outbound and inbound proofs yield identical verification result");
}

// --------------------------------------------------------------------------
// Test 4: Reserve proof round-trip.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_04_reserve_proof_round_trip() {
    // Construct multiple V3 outputs for the same recipient.
    // Generate reserve proof.
    // Verifier confirms ownership and total amount.
    todo!("Phase 5: reserve proof generate + verify round trip");
}

// --------------------------------------------------------------------------
// Test 5: Tampered ProofSecrets (flip one bit in ho) -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_05_tampered_proof_secrets_rejected() {
    // Generate valid outbound proof.
    // Flip one bit in ProofSecrets.ho in the proof blob.
    // Verifier must reject (output key mismatch or signature invalid).
    todo!("Phase 5: tampered ProofSecrets detected by verifier");
}

// --------------------------------------------------------------------------
// Test 6: Swapped ProofSecrets between two outputs -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_06_swapped_proof_secrets_rejected() {
    // Tx with >=2 outputs to the same recipient.
    // Generate valid outbound proof.
    // Swap ProofSecrets[0] and ProofSecrets[1] in the proof blob.
    // Verifier must reject (per-output domain separation in HKDF).
    todo!("Phase 5: swapped ProofSecrets between outputs detected");
}

// --------------------------------------------------------------------------
// Test 7: Valid proof for tx A replayed against tx B -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_07_cross_tx_replay_rejected() {
    // Generate valid proof for tx A.
    // Verify against tx B's prefix_hash.
    // Verifier must reject (prefix_hash binding).
    todo!("Phase 5: cross-tx replay detected by prefix_hash binding");
}

// --------------------------------------------------------------------------
// Test 8: Inbound proof signed with wrong view key -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: awaiting shekyl-proofs implementation"]
fn test_08_wrong_view_key_inbound_rejected() {
    // Generate inbound proof signed with an unrelated view_secret_key.
    // Verifier checks against the actual recipient's view_public_key.
    // Signature check must fail.
    todo!("Phase 5: inbound proof with wrong view key rejected");
}

// --------------------------------------------------------------------------
// Test 9: Watch-only wallet attempts outbound proof -> human-readable error.
//
// NOTE: This is a wallet-state test. The definitive implementation is a
// C++/FFI core_test that exercises wallet2's m_tx_keys absence path.
// Stubbed here to lock in the exit criterion checklist.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: C++/FFI test -- wallet2 tx_key absence (watch-only)"]
fn test_09_watch_only_outbound_proof_error() {
    // Watch-only wallet has no tx_key in m_tx_keys.
    // Attempting outbound proof must produce:
    //   "Cannot generate outbound proof: tx_key not available for this
    //    transaction. If you are the recipient, use get_tx_proof with your
    //    own address to generate an inbound proof instead."
    // NOT a cryptic key-not-found or empty-buffer error.
    todo!("Phase 5 C++: watch-only wallet outbound proof → clear error message");
}

// --------------------------------------------------------------------------
// Test 10: Restored wallet attempts outbound proof on pre-restore tx -> error.
//
// NOTE: Same as test 9 -- wallet-state, C++/FFI definitive implementation.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: C++/FFI test -- wallet2 tx_key absence (restored)"]
fn test_10_restored_wallet_outbound_proof_error() {
    // Wallet restored from seed has no m_tx_keys for pre-restore txs.
    // Same error as test 9, with suggestion to use inbound proof.
    todo!("Phase 5 C++: restored wallet outbound proof → clear error, suggest inbound");
}
