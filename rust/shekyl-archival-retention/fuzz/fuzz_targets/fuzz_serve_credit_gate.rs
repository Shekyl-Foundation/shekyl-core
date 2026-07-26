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
use shekyl_archival_retention::serve_credit_decisions::{
    serve_credit_gate_decision, GateReject, GateVerdict, ServeCreditGateInputs,
};
use shekyl_archival_retention::challenge_seal_on_chain;
use shekyl_archival_retention::serve_credit_epoch_ok;
use shekyl_archival_retention::wire::{MAX_BRANCH_SCALARS, MAX_PATH_LAYERS_PER_KIND};
use shekyl_archival_retention::VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE;

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

    /// Length 0..=80 of counts 0..=300 — straddles both step-1 bounds
    /// (`MAX_PATH_LAYERS_PER_KIND` = 64 layers, `MAX_BRANCH_SCALARS` = 256
    /// scalars) from both sides; retune these ranges if those bounds move.
    fn counts(&mut self) -> Vec<usize> {
        let len = usize::from(self.u8()) % 81;
        (0..len)
            .map(|_| usize::from(self.u8()) + usize::from(self.u8() % 45))
            .collect()
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let c1 = c.counts();
    let c2 = c.counts();
    let seal_hash = if c.bool() { Some(c.arr32()) } else { None };
    let wire_first_byte = if c.bool() { Some(c.u8()) } else { None };

    let inputs = ServeCreditGateInputs {
        p_canonical_id: c.arr32(),
        shard_id: c.u64(),
        settlement_epoch: c.u64(),
        c1_branch_scalar_counts: &c1,
        c2_branch_scalar_counts: &c2,
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
        leaf_index_in_segment: c.u64(),
        leaf_chunk_ok: c.bool(),
        wire_serialize_ok: c.bool(),
        wire_first_byte,
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
fn assert_reason_is_red(i: &ServeCreditGateInputs<'_>, reason: GateReject) {
    match reason {
        GateReject::PathLayerCountExceedsBound => {
            assert!(
                i.c1_branch_scalar_counts.len() > MAX_PATH_LAYERS_PER_KIND
                    || i.c2_branch_scalar_counts.len() > MAX_PATH_LAYERS_PER_KIND
            );
        }
        GateReject::C1BranchScalarCountExceedsBound => {
            assert!(i
                .c1_branch_scalar_counts
                .iter()
                .any(|&n| n > MAX_BRANCH_SCALARS));
        }
        GateReject::C2BranchScalarCountExceedsBound => {
            assert!(i
                .c2_branch_scalar_counts
                .iter()
                .any(|&n| n > MAX_BRANCH_SCALARS));
        }
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
        GateReject::LeafChunkReadFailed => assert!(!i.leaf_chunk_ok),
        GateReject::VinSerializeFailed => assert!(!i.wire_serialize_ok),
        GateReject::UnexpectedVinWireTag => {
            assert_ne!(
                i.wire_first_byte,
                Some(VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE)
            );
        }
        GateReject::FfiVerifyFailed => assert!(!i.verify_ok),
        GateReject::LeafIndexOutOfSegmentRange => {}
    }
}

/// From an accepting input, each single red flip must reject with exactly
/// that predicate's reason, and adding a *later* red flip must not displace
/// an earlier one (first-failure ordering).
fn single_flip_first_failure(green: &ServeCreditGateInputs<'_>) {
    // (mutator, expected reason), in gate order.
    type Flip = (fn(&mut ServeCreditGateInputs<'_>), GateReject);
    let flips: &[Flip] = &[
        (|i| i.preblock_present = true, GateReject::DuplicatePreBlock),
        (
            |i| i.bond_substrate_present = false,
            GateReject::BondSubstrateMissing,
        ),
        (|i| i.good_through = false, GateReject::NotGoodThrough),
        (
            // h_close is only consumed at step 6 and later; steps 1–5 stay
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
        (|i| i.leaf_chunk_ok = false, GateReject::LeafChunkReadFailed),
        (
            |i| i.wire_serialize_ok = false,
            GateReject::VinSerializeFailed,
        ),
        (
            |i| i.wire_first_byte = None,
            GateReject::UnexpectedVinWireTag,
        ),
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
