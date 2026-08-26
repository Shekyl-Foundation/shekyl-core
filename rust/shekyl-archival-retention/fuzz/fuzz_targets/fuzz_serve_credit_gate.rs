// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fuzz the wide D-SC-B gate mirror (`serve_credit_gate_decision`) over
//! arbitrary marshaled inputs (ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md §5
//! fuzz plan). Invariants hunted — deliberately *not* a re-implementation of
//! the predicate chain (a duplicated oracle can drift in lockstep with the
//! mirror; the branch-level ground truth is the standing KAT's authored
//! reason column):
//!
//! - **Totality + determinism:** no panic on any input shape; same inputs,
//!   same verdict.
//! - **Reason soundness:** a reported reason's own predicate is actually red
//!   in the inputs (a reject never names a green predicate).
//! - **First-failure ordering:** from any *accepting* input, flipping exactly
//!   one marshaled field to red yields a reject naming exactly that
//!   predicate; flipping a second, later field must not change the reported
//!   (earlier) reason.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_archival_retention::challenge;
use shekyl_archival_retention::challenge_leaf_chunk_bounds;
use shekyl_archival_retention::challenge_seal_on_chain;
use shekyl_archival_retention::serve_credit_decisions::{
    serve_credit_gate_decision, GateReject, GateVerdict, ServeCreditGateInputs,
};
use shekyl_archival_retention::serve_credit_epoch_ok;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    fn u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        for byte in &mut bytes {
            *byte = self.u8();
        }
        u64::from_le_bytes(bytes)
    }

    fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    fn arr32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for byte in &mut out {
            *byte = self.u8();
        }
        out
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let seal_hash = if c.bool() { Some(c.arr32()) } else { None };

    let inputs = ServeCreditGateInputs {
        p_canonical_id: c.arr32(),
        shard_id: c.u64(),
        settlement_epoch: c.u64(),
        vin_parsed: c.bool(),
        pruned_record_in_bounds: c.bool(),
        preblock_present: c.bool(),
        bond_substrate_present: c.bool(),
        join_epoch: c.u64(),
        good_through: c.bool(),
        current_height: c.u64(),
        h_open: c.u64(),
        h_close: c.u64(),
        seal_hash,
        held_at_fire: c.bool(),
        registry_present_at_fire: c.bool(),
        segment_leaf_count: c.u64(),
        // PC-D3: drawn from the corpus like every other input, so the fuzzer
        // reaches the all-zero sentinel the gate refuses as well as the
        // populated hashes it derives from.
        prev_block_hash: c.arr32(),
        leaf_chunk_ok: c.bool(),
        verify_ok: c.bool(),
    };

    let verdict = serve_credit_gate_decision(&inputs);

    // Totality is implicit (we got here); determinism:
    assert_eq!(verdict, serve_credit_gate_decision(&inputs));

    if let GateVerdict::Reject(reason) = verdict {
        assert_reason_is_red(&inputs, reason);
    }

    if verdict == GateVerdict::Accept {
        single_flip_first_failure(&inputs);
    }
});

/// Reason soundness: the named predicate must actually be red in the inputs.
/// (Only field-shaped predicates are checked; derivation-shaped ones —
/// fire-height, chunk bounds — are covered by the mirror's unit tests and
/// the standing KAT's authored vectors.)
fn assert_reason_is_red(i: &ServeCreditGateInputs, reason: GateReject) {
    match reason {
        GateReject::VinUnparseable => assert!(!i.vin_parsed),
        GateReject::PrunedRecordSizeOutOfBounds => assert!(!i.pruned_record_in_bounds),
        GateReject::DuplicatePreBlock => assert!(i.preblock_present),
        GateReject::BondSubstrateMissing => assert!(!i.bond_substrate_present),
        GateReject::EpochBeforeEFirst => {
            assert!(!serve_credit_epoch_ok(i.settlement_epoch, i.join_epoch));
        }
        GateReject::NotGoodThrough => assert!(!i.good_through),
        GateReject::PastCreditDeadline => assert!(i.current_height > i.h_close),
        GateReject::SealBlockNotYetCommitted => {
            assert!(!challenge_seal_on_chain(i.h_open, i.current_height));
        }
        GateReject::SealHashUnavailable => assert!(i.seal_hash.is_none()),
        GateReject::ShardNotHeldAtFire => assert!(!i.held_at_fire),
        GateReject::ShardRegistryUnavailableAtFire => assert!(!i.registry_present_at_fire),
        GateReject::LeafIndexDerivationRefused => {
            // One reason, two red predicates: the gate reports zero geometry
            // AND the all-zero prev-hash sentinel (PC-D3) through the single
            // C++ "leaf index derivation refused" branch, so soundness here
            // is the disjunction — at least one arm must be red.
            assert!(i.segment_leaf_count == 0 || i.prev_block_hash == [0u8; 32]);
        }
        GateReject::LeafIndexOutOfSegmentRange => {
            // Derivation-shaped: assert through the production predicates,
            // like the epoch-ok and seal-on-chain arms — a hand-derived
            // necessary condition drifted here once already (it claimed
            // `segment_leaf_count > SEGMENT_LEAF_COUNT`, missing the
            // global-position u64 overflow arm a far-end `shard_id` trips).
            // This still catches misattribution: any other red predicate
            // reported under this reason fails the is_none below.
            let leaf_index = challenge::challenge_leaf_index(
                &i.p_canonical_id,
                i.shard_id,
                i.settlement_epoch,
                &i.prev_block_hash,
                i.segment_leaf_count,
            );
            assert!(challenge_leaf_chunk_bounds(i.shard_id, u64::from(leaf_index)).is_none());
        }
        GateReject::LeafChunkReadFailed => assert!(!i.leaf_chunk_ok),
        GateReject::FfiVerifyFailed => assert!(!i.verify_ok),
    }
}

/// From an accepting input, each single red flip must reject with exactly
/// that predicate's reason, and adding a *later* red flip must not displace
/// an earlier one (first-failure ordering).
fn single_flip_first_failure(green: &ServeCreditGateInputs) {
    // (mutator, expected reason), in gate order.
    type Flip = (fn(&mut ServeCreditGateInputs), GateReject);
    let flips: &[Flip] = &[
        (|i| i.vin_parsed = false, GateReject::VinUnparseable),
        (
            |i| i.pruned_record_in_bounds = false,
            GateReject::PrunedRecordSizeOutOfBounds,
        ),
        (|i| i.preblock_present = true, GateReject::DuplicatePreBlock),
        (
            |i| i.bond_substrate_present = false,
            GateReject::BondSubstrateMissing,
        ),
        (|i| i.good_through = false, GateReject::NotGoodThrough),
        (
            // h_close is only consumed at step 6 and later; steps 0–5 stay
            // green, and the reject at step 6 shields the later consumers —
            // red regardless of the green input's heights.
            |i| {
                i.h_close = 0;
                i.current_height = 1;
            },
            GateReject::PastCreditDeadline,
        ),
        (|i| i.held_at_fire = false, GateReject::ShardNotHeldAtFire),
        (
            |i| i.registry_present_at_fire = false,
            GateReject::ShardRegistryUnavailableAtFire,
        ),
        (
            |i| i.segment_leaf_count = 0,
            GateReject::LeafIndexDerivationRefused,
        ),
        (
            // PC-D3: the all-zero prev-hash sentinel is the refusal's second
            // arm, checked by the gate right after the zero-geometry arm. An
            // accepting input's hash is necessarily nonzero, so this is a
            // genuine single red flip.
            |i| i.prev_block_hash = [0u8; 32],
            GateReject::LeafIndexDerivationRefused,
        ),
        (|i| i.leaf_chunk_ok = false, GateReject::LeafChunkReadFailed),
        (|i| i.verify_ok = false, GateReject::FfiVerifyFailed),
    ];

    for (idx, (flip, want)) in flips.iter().enumerate() {
        let mut flipped = green.clone();
        flip(&mut flipped);
        assert_eq!(
            serve_credit_gate_decision(&flipped),
            GateVerdict::Reject(*want),
            "single flip must reject with its own reason"
        );

        // First-failure ordering: also flip every later predicate — the
        // earlier reason must still win.
        let mut double = flipped.clone();
        for (later_flip, _) in &flips[idx + 1..] {
            later_flip(&mut double);
        }
        assert_eq!(
            serve_credit_gate_decision(&double),
            GateVerdict::Reject(*want),
            "earlier red predicate must win over later ones"
        );
    }
}
