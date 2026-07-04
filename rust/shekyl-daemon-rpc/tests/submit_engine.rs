// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit-engine control-flow and race-classification tests — the
//! deterministic-mock race suite (`docs/design/DAEMON_SUBMIT_VERDICT.md`
//! §10 item 2). Every §3.1 race interleaving is scripted as a Phase-D
//! `Raced{fresh}` and the classifier's most-terminal-first order asserted,
//! including the multi-premise races where the order is load-bearing.

mod submit_fixtures;

use std::sync::Arc;

use shekyl_daemon_rpc::submit::{
    parse_submission, CommitOutcome, EngineFault, KeyImageConflict, SubmitCaller, SubmitEngine,
    SubmitFacts, VerifyFailure,
};
use shekyl_rpc_types::{RejectCause, SubmitVerdict};
use shekyl_types::BlockHeight;
use submit_fixtures::{
    admitting_facts, hexify, serve_credit_tx, spend_tx, MockShim, MockVerifier, FIXTURE_ROOT,
};

type MockEngine = SubmitEngine<Arc<MockShim>, Arc<MockVerifier>>;

/// Engine over scripted facts + commit outcome, single-permit gate.
fn engine(
    facts: SubmitFacts,
    outcome: CommitOutcome,
) -> (MockEngine, Arc<MockShim>, Arc<MockVerifier>) {
    let shim = MockShim::new(facts, outcome);
    let verifier = MockVerifier::passing();
    let engine = SubmitEngine::new(Arc::clone(&shim), Arc::clone(&verifier));
    (engine, shim, verifier)
}

fn spend_hex() -> String {
    hexify(&spend_tx(1_000_000))
}

fn base_facts() -> SubmitFacts {
    let parsed = parse_submission(&spend_hex()).expect("fixture spend parses");
    admitting_facts(&parsed)
}

fn rejected(cause: RejectCause) -> SubmitVerdict {
    SubmitVerdict::Rejected { cause }
}

// ── Phase A short-circuit ───────────────────────────────────────────────

#[test]
fn phase_a_failure_never_touches_the_shim() {
    let (engine, shim, verifier) = engine(base_facts(), CommitOutcome::Committed);
    let verdict = engine
        .submit("not hex at all", SubmitCaller::Owner)
        .expect("verdict, not fault");
    assert_eq!(verdict, rejected(RejectCause::Malformed));
    assert_eq!(shim.snapshot_count(), 0, "Phase A is FFI-free (§3.1)");
    assert_eq!(shim.commit_count(), 0);
    assert_eq!(verifier.call_count(), 0);
}

// ── Phase B identity short-circuits ─────────────────────────────────────

#[test]
fn already_in_chain_outranks_in_pool() {
    let mut facts = base_facts();
    facts.in_chain = true;
    facts.in_pool = true; // transiently both, just-mined: settled fact wins
    let (engine, shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::AlreadyInChain
    );
    assert_eq!(verifier.call_count(), 0, "identity precedes verification");
    assert_eq!(shim.commit_count(), 0);
}

#[test]
fn already_in_pool_short_circuits() {
    let mut facts = base_facts();
    facts.in_pool = true;
    let (engine, shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::AlreadyInPool
    );
    assert_eq!(verifier.call_count(), 0);
    assert_eq!(shim.commit_count(), 0);
}

#[test]
fn snapshot_key_image_conflict_is_not_a_verdict() {
    // Defect 0.4's regression: a Phase-B key-image hit is a re-check input,
    // never a verdict. With the commit clean, the submit must proceed to
    // Accepted — the snapshot's `Other` may have been a raced observation
    // of a tx that got evicted/mined before our commit lock.
    let mut facts = base_facts();
    facts.key_image_conflicts = vec![KeyImageConflict::Other, KeyImageConflict::Free];
    let (engine, shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::Accepted
    );
    assert_eq!(verifier.call_count(), 1, "verification still runs");
    assert_eq!(shim.commit_count(), 1, "commit decides, not the snapshot");
}

// ── Phase C policy gates ────────────────────────────────────────────────

#[test]
fn unknown_reference_block_rejects_reference_not_found() {
    let mut facts = base_facts();
    facts.reference = None;
    let (engine, shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::ReferenceNotFound)
    );
    assert_eq!(verifier.call_count(), 0, "no crypto on an unanchored proof");
    assert_eq!(shim.commit_count(), 0);
}

#[test]
fn too_recent_reference_rejects_reference_too_recent() {
    // chain_height 200, MIN_AGE 5: admissible ref heights are <= 195.
    let mut facts = base_facts();
    facts.reference.as_mut().unwrap().height = BlockHeight::from_raw(196);
    let (engine, _shim, _verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::ReferenceTooRecent)
    );
}

#[test]
fn young_chain_rejects_reference_too_recent() {
    // chain_height below MIN_AGE: every reference is too recent (the C++
    // comparison shape, blockchain.cpp:3745-3754).
    let mut facts = base_facts();
    facts.chain_height = BlockHeight::from_raw(3);
    facts.reference.as_mut().unwrap().height = BlockHeight::from_raw(0);
    let (engine, _shim, _verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::ReferenceTooRecent)
    );
}

#[test]
fn aged_out_reference_rejects_stale_root() {
    // chain_height 200, MAX_AGE 100: admissible ref heights are >= 100.
    let mut facts = base_facts();
    facts.reference.as_mut().unwrap().height = BlockHeight::from_raw(99);
    let (engine, _shim, _verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::StaleRoot)
    );
}

#[test]
fn age_window_boundaries_admit() {
    // Exactly MAX_AGE old (height 100 at chain 200) and exactly MIN_AGE
    // old (height 195 at chain 200) are both in-window.
    for ref_height in [100u64, 195] {
        let mut facts = base_facts();
        facts.reference.as_mut().unwrap().height = BlockHeight::from_raw(ref_height);
        let (engine, _shim, _verifier) = engine(facts, CommitOutcome::Committed);
        assert_eq!(
            engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
            SubmitVerdict::Accepted,
            "ref height {ref_height} must be in-window"
        );
    }
}

#[test]
fn tree_depth_out_of_range_rejects_stale_root() {
    // Fixture tx carries tree_depth 3; a snapshot depth of 2 makes the
    // proof's depth out of range (row K10).
    let mut facts = base_facts();
    facts.reference.as_mut().unwrap().tree_depth = 2;
    let (engine, _shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::StaleRoot)
    );
    assert_eq!(verifier.call_count(), 0);
}

#[test]
fn weight_over_limit_rejects_malformed() {
    // Deterministic for the bytes → Malformed, decided before the fee gate
    // (C++ order: Rule 4 weight precedes add_tx's fee check).
    let mut facts = base_facts();
    facts.weight_limit = 100;
    facts.fee_per_byte = u64::MAX; // fee would also fail: weight must win
    let (engine, _shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::Malformed)
    );
    assert_eq!(verifier.call_count(), 0);
}

#[test]
fn fee_below_floor_rejects_fee_too_low() {
    let mut facts = base_facts();
    facts.fee_per_byte = 1_000_000; // floor far above the 1e6 fixture fee
    let (engine, shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::FeeTooLow)
    );
    assert_eq!(
        verifier.call_count(),
        0,
        "fee gate precedes the crypto battery"
    );
    assert_eq!(shim.commit_count(), 0);
}

#[test]
fn serve_credit_terminates_at_the_fee_floor() {
    // SP-T4a parity: consensus pins serve-credit fee to 0; the pool floor
    // is never 0; the non-spending arm therefore terminates FeeTooLow —
    // and its (unconsulted) reference must NOT surface ReferenceNotFound
    // (the C++ oracle never checks referenceBlock on this arm).
    let hex = hexify(&serve_credit_tx(0));
    let parsed = parse_submission(&hex).expect("serve-credit parses");
    let mut facts = admitting_facts(&parsed);
    facts.reference = None; // would be ReferenceNotFound on a spending arm
    let (engine, _shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&hex, SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::FeeTooLow)
    );
    assert_eq!(verifier.call_count(), 0);
}

#[test]
fn verifier_failures_map_to_their_causes() {
    for (failure, cause) in [
        (VerifyFailure::Malformed, RejectCause::Malformed),
        (VerifyFailure::StaleRoot, RejectCause::StaleRoot),
        (
            VerifyFailure::DoubleSpendConflict,
            RejectCause::DoubleSpendConflict,
        ),
    ] {
        let shim = MockShim::new(base_facts(), CommitOutcome::Committed);
        let verifier = MockVerifier::failing(failure);
        let engine = SubmitEngine::new(Arc::clone(&shim), Arc::clone(&verifier));
        assert_eq!(
            engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
            rejected(cause)
        );
        assert_eq!(
            shim.commit_count(),
            0,
            "a failed verification never commits"
        );
    }
}

// ── Phase D: commit outcomes ────────────────────────────────────────────

#[test]
fn committed_accepts_relays_and_binds_the_certificate() {
    let (engine, shim, _verifier) = engine(base_facts(), CommitOutcome::Committed);
    let parsed = parse_submission(&spend_hex()).unwrap();

    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::Accepted
    );

    // Relay nudge fired for exactly this txid (§4.3).
    assert_eq!(*shim.relays.lock().unwrap(), vec![parsed.txid]);

    // The commit saw the exact blob, the engine txid, the meta, and a
    // certificate minted for this txid against the snapshot's root at the
    // snapshot's reference height (§3.3 / §3.5 binding).
    let commits = shim.commits.lock().unwrap();
    let record = &commits[0];
    assert_eq!(record.blob, parsed.blob);
    assert_eq!(record.txid, parsed.txid);
    assert_eq!(record.cert_txid, parsed.txid);
    assert_eq!(record.cert_reference_block, parsed.reference_block);
    assert_eq!(record.cert_ref_height, BlockHeight::from_raw(150));
    assert_eq!(record.cert_root, FIXTURE_ROOT);
    assert_eq!(record.meta.weight, parsed.weight);
    assert_eq!(record.meta.fee, parsed.fee);
    assert_eq!(
        record.expected,
        base_facts(),
        "commit re-checks against the B snapshot"
    );
}

#[test]
fn pruned_on_insert_rejects_fee_too_low() {
    // F23 / defect 0.7: admitted then evicted by the tail's prune().
    let (engine, shim, _verifier) = engine(base_facts(), CommitOutcome::PrunedOnInsert);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::FeeTooLow)
    );
    assert_eq!(shim.relay_count(), 0, "an evicted tx must not be nudged");
}

#[test]
fn internal_fault_is_a_fault_not_a_verdict() {
    let (engine, shim, _verifier) = engine(base_facts(), CommitOutcome::InternalFault);
    assert_eq!(
        engine
            .submit(&spend_hex(), SubmitCaller::Owner)
            .unwrap_err(),
        EngineFault::CommitFault
    );
    assert_eq!(shim.relay_count(), 0);
}

#[test]
fn snapshot_fault_is_a_fault_not_a_verdict() {
    // §3.4's loud-failure gate on the Phase-B side: a shim that cannot
    // produce facts (DB exception, marshalling fault) must surface as the
    // transport Err arm, never as a verdict — and verification never runs.
    struct FaultingShim;
    impl shekyl_daemon_rpc::submit::SubmitStateShim for FaultingShim {
        fn snapshot_facts(
            &self,
            _txid: &shekyl_types::TxHash,
            _key_images: &[[u8; 32]],
            _reference_block: &shekyl_types::BlockHash,
        ) -> Result<SubmitFacts, shekyl_daemon_rpc::submit::ShimFault> {
            Err(shekyl_daemon_rpc::submit::ShimFault)
        }
        fn commit(
            &self,
            _blob: &[u8],
            _txid: &shekyl_types::TxHash,
            _meta: &shekyl_daemon_rpc::submit::TxMeta,
            _cert: &shekyl_daemon_rpc::submit::VerificationCertificate,
            _expected: &SubmitFacts,
        ) -> CommitOutcome {
            panic!("commit must be unreachable after a snapshot fault");
        }
        fn relay(&self, _txid: &shekyl_types::TxHash) {
            panic!("relay must be unreachable after a snapshot fault");
        }
    }

    let verifier = MockVerifier::passing();
    let engine = SubmitEngine::new(FaultingShim, Arc::clone(&verifier));
    assert_eq!(
        engine
            .submit(&spend_hex(), SubmitCaller::Owner)
            .unwrap_err(),
        EngineFault::SnapshotFault
    );
    assert_eq!(verifier.call_count(), 0);
}

// ── Phase D: race classification, most-terminal-first (§3.1) ────────────

#[test]
fn raced_in_chain_wins_over_every_other_premise() {
    // A reorg landed our tx AND a conflicting spend appeared AND the root
    // moved: the settled fact must win (order is load-bearing — StaleRoot
    // here would send the wallet through a wasted rebuild).
    let mut fresh = base_facts();
    fresh.in_chain = true;
    fresh.key_image_conflicts = vec![KeyImageConflict::Other, KeyImageConflict::Free];
    fresh.reference = None;
    fresh.fee_per_byte = u64::MAX;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::AlreadyInChain
    );
}

#[test]
fn raced_in_pool_classifies_already_in_pool() {
    // Defect 0.4's self-duplicate race: a concurrent submit of the same
    // bytes won the commit.
    let mut fresh = base_facts();
    fresh.in_pool = true;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::AlreadyInPool
    );
}

#[test]
fn raced_key_image_conflict_beats_stale_root() {
    // Competing spend AND root drift in the same race window: the terminal
    // fact must win — StaleRoot would cost the wallet a proof rebuild and
    // a resubmit just to hear DoubleSpendConflict.
    let mut fresh = base_facts();
    fresh.key_image_conflicts = vec![KeyImageConflict::Free, KeyImageConflict::Other];
    fresh.reference = None;
    fresh.fee_per_byte = u64::MAX;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::DoubleSpendConflict)
    );
}

#[test]
fn raced_own_tx_key_image_is_not_a_conflict() {
    // `OwnTx` is identity, not conflict — it can classify AlreadyInPool
    // via the identity premise but never DoubleSpendConflict. Paired here
    // with a root drift: StaleRoot must win because no *foreign* spender
    // exists.
    let mut fresh = base_facts();
    fresh.key_image_conflicts = vec![KeyImageConflict::OwnTx, KeyImageConflict::OwnTx];
    fresh.reference = None;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::StaleRoot)
    );
}

#[test]
fn raced_reference_gone_classifies_stale_root() {
    // The reference existed at B (it anchored the certificate) and is gone
    // at D: a reorg — rebuild against a fresh root.
    let mut fresh = base_facts();
    fresh.reference = None;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::StaleRoot)
    );
}

#[test]
fn raced_root_mismatch_classifies_stale_root() {
    // Same height, different root: root-table motion / reorg to an
    // equal-height alternative — the certificate's root premise failed.
    let mut fresh = base_facts();
    fresh.reference.as_mut().unwrap().root = [0xBB; 32];
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::StaleRoot)
    );
}

#[test]
fn raced_reference_aged_out_classifies_stale_root() {
    // Blocks landed during Phase C and pushed the reference past MAX_AGE:
    // fresh height 251 with ref at 150 (MAX_AGE 100) is out of window.
    let mut fresh = base_facts();
    fresh.chain_height = BlockHeight::from_raw(251);
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::StaleRoot)
    );
}

#[test]
fn raced_fee_floor_rise_classifies_fee_too_low() {
    // F34: the floor moved during Phase C with everything else stable —
    // the exact zombie-Accepted shape the redesign abolishes.
    let mut fresh = base_facts();
    fresh.fee_per_byte = 1_000_000;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        rejected(RejectCause::FeeTooLow)
    );
}

#[test]
fn raced_with_no_changed_premise_is_a_shim_contract_fault() {
    // `Raced` whose fresh facts re-classify nothing is a shim defect —
    // loud fault, never a guessed verdict.
    let fresh = base_facts();
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert!(matches!(
        engine
            .submit(&spend_hex(), SubmitCaller::Owner)
            .unwrap_err(),
        EngineFault::ShimContract(_)
    ));
}

// ── §3.1 identity-category pin: the foreign-disclosure boundary ─────────
//
// `in_pool` (relay_category::all) is the internal presence truth; a foreign
// caller (restricted/public endpoint) may learn only `in_pool_broadcast`
// (relay_category::legacy). Disclosing embargoed presence to a foreigner
// would turn POST /submit_transaction into a Dandelion++ stem-presence
// oracle, so an embargoed pool-resident tx is concealed — verified in full
// and reported Accepted, indistinguishable from a fresh submission.

#[test]
fn foreign_embargoed_presence_is_concealed_at_phase_b() {
    // Pool-resident at `all` but not broadcast-visible (embargoed). A
    // foreign caller must NOT get a fast AlreadyInPool: it runs the full
    // battery and (clean commit) reports Accepted.
    let mut facts = base_facts();
    facts.in_pool = true;
    facts.in_pool_broadcast = false;
    let (engine, shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Foreign).unwrap(),
        SubmitVerdict::Accepted
    );
    assert_eq!(
        verifier.call_count(),
        1,
        "foreign caller pays full verification — no early identity leak"
    );
    assert_eq!(shim.commit_count(), 1);
}

#[test]
fn foreign_broadcast_presence_reveals_already_in_pool() {
    // Already fluffed (broadcast-visible): no embargo secret, so disclosing
    // AlreadyInPool to a foreign caller is safe — exactly what the legacy
    // `relay_category::legacy` identity check disclosed.
    let mut facts = base_facts();
    facts.in_pool = true;
    facts.in_pool_broadcast = true;
    let (engine, _shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Foreign).unwrap(),
        SubmitVerdict::AlreadyInPool
    );
    assert_eq!(
        verifier.call_count(),
        0,
        "broadcast-visible presence short-circuits"
    );
}

#[test]
fn owner_embargoed_presence_reveals_already_in_pool() {
    // The owner (unrestricted endpoint) keeps the F31 resubmit-as-status
    // query: an embargoed self-tx returns AlreadyInPool immediately.
    let mut facts = base_facts();
    facts.in_pool = true;
    facts.in_pool_broadcast = false;
    let (engine, _shim, verifier) = engine(facts, CommitOutcome::Committed);
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Owner).unwrap(),
        SubmitVerdict::AlreadyInPool
    );
    assert_eq!(verifier.call_count(), 0);
}

#[test]
fn foreign_raced_embargoed_duplicate_conceals_as_accepted() {
    // A foreign caller whose commit raced against an embargoed pool-resident
    // tx is told Accepted (it is in the pool and will relay), never
    // AlreadyInPool — the race outcome must not be an oracle either.
    let mut fresh = base_facts();
    fresh.in_pool = true;
    fresh.in_pool_broadcast = false;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Foreign).unwrap(),
        SubmitVerdict::Accepted
    );
}

#[test]
fn foreign_raced_broadcast_duplicate_reveals_already_in_pool() {
    // Broadcast-visible at the race window: safe to disclose AlreadyInPool.
    let mut fresh = base_facts();
    fresh.in_pool = true;
    fresh.in_pool_broadcast = true;
    let (engine, _shim, _verifier) = engine(base_facts(), CommitOutcome::Raced(fresh));
    assert_eq!(
        engine.submit(&spend_hex(), SubmitCaller::Foreign).unwrap(),
        SubmitVerdict::AlreadyInPool
    );
}
