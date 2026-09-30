// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival shard partition's **domain** — `SHT-Q1` RULED (Rick,
//! 2026-09-27, design-owner lane), recorded in
//! [`ARCHIVAL_SHARD_T_DERIVATION.md`](../../../../docs/design/ARCHIVAL_SHARD_T_DERIVATION.md)
//! §2.
//!
//! The ruling defines the domain by a **property**: a transaction is in it iff
//! it carries archival good — a non-empty prunable region, or a `pqc_auths`
//! component — decidable from skeleton data alone
//! ([`shekyl_wire::carries_archival_good`]). The implementation reads
//! `cumulative_tx_count`, which counts **non-coinbase** transactions. Those two
//! are equal today only because every non-coinbase class carries good and the
//! coinbase carries none, and the ruling records that equality as an
//! **invariant, not a definition**.
//!
//! This module is the test that fails the day it breaks. Three legs:
//!
//! 1. [`the_domain_is_every_non_coinbase_class`] — an **exhaustive `match` over
//!    [`TxClass`] with no wildcard arm**, so adding a class cannot compile until
//!    someone decides whether it carries good. A runtime assertion alone would
//!    let a new class through.
//! 2. [`the_coinbase_carries_no_good_however_large_its_extra`] — the coinbase
//!    leg, including a maximal-attestation coinbase: those records live in
//!    `extra`, which is skeleton, not in a prunable region.
//! 3. [`the_counter_equals_the_predicate_over_a_mixed_chain`] — boundaries
//!    derived from `cumulative_tx_count` equal boundaries from counting the
//!    predicate directly, over a synthetic chain mixing every class with empty
//!    blocks. This is the leg that fails on divergence.

use super::*;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{coinbase, coinbase_extra, listed, point};
use crate::verdict::TxSlot;
use shekyl_wire::{
    carries_archival_good, BondPost, BondPostKind, Ct, Holdings, Input, Prunable, Transaction,
};

/// The fixture spend's key image, as `tx_tests` picks it.
const KI: [u8; 32] = point(9);

/// The class a transaction derives to **at the slot it is judged**, through the
/// production path. The slot is not decoration: a `gen` input outside the
/// coinbase position is refused by **CEN-H5**, so the coinbase classifies at
/// `TxSlot::Miner` and a listed transaction at its own position. Deriving the
/// coinbase at `Lone` refuses with `H5` — which is the rule working, not a
/// fixture problem.
fn class_at(tx: &Transaction, slot: TxSlot) -> TxClass {
    let mut coverage = RuleCoverage::EMPTY;
    TxContext::derive(tx, slot, &mut coverage)
        .expect("the fixtures are well-formed shapes at the slot judged")
        .class
}

/// The predicate over a **whole body's** digests — what this module's legs 1 and 2
/// assert the *definition* against.
///
/// This is not the production path and must not become one: on a body whose
/// regions have been discarded, `txid_parts()` recomputes `keccak256("")` and
/// `None`, so a pruned node would read its discarded spends as carrying no good.
/// The production path reads the permanent rows —
/// `shekyl-chain-store`'s `tx_carries_archival_good`, pinned across a prune by
/// `the_predicate_survives_a_prune_on_the_stored_rows`.
fn in_domain(tx: &Transaction) -> bool {
    let parts = tx.txid_parts();
    carries_archival_good(parts.pqc_auth_hash, parts.prunable_hash)
}

// ---- per-class bodies -------------------------------------------------------
//
// `tx_tests`' class fixtures vary only the *inputs*; the domain is a property of
// the **ct**, so these carry the ct each class's rules actually require.

/// `TxClass::Spend` — the fixture spend: `pqc_auths` per input, prunable present.
fn spend_body() -> Transaction {
    listed(KI)
}

fn spend_input(k: usize) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: point(k),
    }
}

fn bond_post_input() -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: Vec::new(),
        p_canonical_id: shekyl_types::PCanonicalId::from_bytes([0xB0; 32]),
        kind: BondPostKind::Other(2),
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    }))
}

/// `tx` with `inputs`, and `pqc_auths` grown to one slot per input — the arity
/// **CEN-H21** and **CEN-H22** both require (`rules/tx.rs`, `H21::check` /
/// `H22::check`).
fn with_inputs_and_auths(mut tx: Transaction, inputs: Vec<Input>) -> Transaction {
    let n = inputs.len();
    tx.prefix.inputs = inputs;
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        let filler = pqc_auths
            .first()
            .cloned()
            .expect("the spend fixture carries one auth to clone");
        pqc_auths.clear();
        for _ in 0..n {
            pqc_auths.push(filler.clone());
        }
    }
    tx
}

/// `TxClass::BondPost` — one post with its funding spend. **CEN-H21 requires
/// `spends >= 1`**, a prunable region and a non-empty FCMP++ proof, so this
/// class cannot be shaped without good.
fn bond_post_body() -> Transaction {
    with_inputs_and_auths(listed(KI), vec![spend_input(11), bond_post_input()])
}

/// `TxClass::Emission` with fee inputs — prunable present.
fn emission_body_with_fees() -> Transaction {
    with_inputs_and_auths(
        listed(KI),
        vec![
            spend_input(11),
            Input::ArchivalRewardEmission {
                canonical_bytes: Vec::new(),
            },
        ],
    )
}

/// `TxClass::Emission` **without** fee inputs — CEN-H22 makes the FCMP++ proof
/// present *iff* fee inputs are, so the prunable region goes away and the good
/// is the `pqc_auths` component alone. The case that would break a
/// prunable-only predicate.
fn emission_body_no_fees() -> Transaction {
    let mut tx = with_inputs_and_auths(
        listed(KI),
        vec![Input::ArchivalRewardEmission {
            canonical_bytes: Vec::new(),
        }],
    );
    if let Ct::Fcmp { prunable, .. } = &mut tx.ct {
        *prunable = None;
    }
    tx.prefix.outputs = Vec::new();
    tx
}

/// `TxClass::ServeCreditOnly` in its **`RF-D1`** shape: empty `pqc_auths`, no
/// outputs, and a prunable region holding exactly one non-empty pruned pass
/// record per serve-credit vin and nothing else. The good here is the pass
/// record — the case that would break a `pqc_auths`-only predicate.
///
/// Built here rather than taken from `harness::fixture::serve_credit_only`,
/// which still carries the **pre-`RF-D1`** shape (`prunable: None`) and is
/// refused by `Transaction::validate_context_free_pruned` — verified, and
/// recorded as `SHT-9`.
fn serve_credit_body() -> Transaction {
    let mut canonical_bytes = vec![shekyl_wire::transaction::TAG_INPUT_SERVE_CREDIT];
    canonical_bytes.extend_from_slice(&[0x11; 32]);
    let mut tx = listed(KI);
    tx.prefix.inputs = vec![Input::ServeCredit { canonical_bytes }];
    tx.prefix.outputs = Vec::new();
    if let Ct::Fcmp {
        pqc_auths,
        prunable,
        ..
    } = &mut tx.ct
    {
        pqc_auths.clear();
        *prunable = Some(Prunable {
            bulletproofs: Vec::new(),
            tree_depth: 0,
            fcmp_proof: Vec::new(),
            pseudo_outs: Vec::new(),
            serve_credit_pruned: vec![vec![0xAB; 8]],
        });
    }
    tx
}

// ---- leg 1: the class equivalence, exhaustive at compile time ---------------

/// **The invariant the ruling records:** the domain *is* every non-coinbase
/// class. The `match` has **no wildcard arm**, so a new `TxClass` variant fails
/// to build until its author decides which side it falls on — the compile-time
/// half of the guarantee, which no runtime assertion can give.
#[test]
#[expect(
    clippy::match_same_arms,
    reason = "one arm per class, each carrying its own justification: collapsing \
              them would put four classes' reasoning on one line and make a class \
              changing sides an invisible edit"
)]
fn the_domain_is_every_non_coinbase_class() {
    for (tx, slot) in [
        (spend_body(), TxSlot::Lone),
        (bond_post_body(), TxSlot::Lone),
        (emission_body_with_fees(), TxSlot::Lone),
        (emission_body_no_fees(), TxSlot::Lone),
        (serve_credit_body(), TxSlot::Lone),
        (coinbase(1), TxSlot::Miner),
    ] {
        let class = class_at(&tx, slot);
        let expected_in_domain = match class {
            // Every non-coinbase class carries good. Each arm names why, so a
            // change to that class's rules has to come past this line.
            //
            // `Spend`: a key-imaged input with no prunable is refused at
            // `shekyl-wire/src/transaction.rs:2056-2060` ("key-image input(s)
            // but no prunable proof").
            TxClass::Spend { .. } => true,
            // `BondPost`: CEN-H21 requires `prunable: Some`, `pqc_auths ==
            // nvin`, `spends >= 1` and a non-empty `fcmp_proof`
            // (`rules/tx.rs`, `H21::check`).
            TxClass::BondPost { .. } => true,
            // `Emission`: CEN-H22 pins `pqc_auths == vin count`, and the vin is
            // non-empty, so the component exists even when the FCMP++ proof
            // does not (`rules/tx.rs`, `H22::check`).
            TxClass::Emission { .. } => true,
            // `ServeCreditOnly`: the `RF-D1` shape carries one non-empty pruned
            // pass record per credit vin, length-checked by
            // `check_serve_credit_pruned_blob`
            // (`shekyl-wire/src/transaction.rs:592-600`).
            TxClass::ServeCreditOnly { .. } => true,
            // The coinbase is outside the domain **by the definition**: `Ct::Null`
            // writes no prunable region and carries no `pqc_auths`.
            TxClass::Coinbase => false,
        };
        assert_eq!(
            in_domain(&tx),
            expected_in_domain,
            "class {class:?} disagrees with the domain invariant"
        );
        // SHT-Q2's pinned invariant: a transaction has archival length iff
        // it carries archival good, so the length partition and the domain
        // are one set. The length is what places a shard boundary; a class
        // with good and no length (or length and no good) would sit in the
        // domain without moving the cut, or move it from outside.
        assert_eq!(
            tx.archival_len().to_raw() > 0,
            expected_in_domain,
            "class {class:?}: archival_len > 0 must be carries_archival_good"
        );
    }
}

/// The two legs of the predicate are **independently** load-bearing: the
/// fee-less emission has the `pqc_auths` component and no prunable region, the
/// serve-credit form has the region and no component. A predicate written with
/// either leg alone would put one of them outside the domain.
#[test]
fn each_leg_of_the_predicate_is_the_only_good_some_class_has() {
    let emission = emission_body_no_fees();
    let parts = emission.txid_parts();
    assert!(parts.pqc_auth_hash.is_some(), "the emission's leg");
    assert_eq!(
        parts.prunable_hash,
        shekyl_wire::empty_region_prunable_hash(),
        "the fee-less emission has no prunable region"
    );
    assert!(in_domain(&emission));

    let credit = serve_credit_body();
    let parts = credit.txid_parts();
    assert!(
        parts.pqc_auth_hash.is_none(),
        "the serve-credit form is 3-part"
    );
    assert_ne!(
        parts.prunable_hash,
        shekyl_wire::empty_region_prunable_hash(),
        "the serve-credit form's good is its pass record"
    );
    assert!(in_domain(&credit));
}

// ---- leg 2: the coinbase, and the digest the predicate compares against -----

/// `keccak256("")` is the row of a body with no prunable region — **not** the
/// null hash. Pinned against the coinbase's own row, because a predicate
/// written against "non-null prunable hash" would read every coinbase as
/// carrying good and the equivalence would be false at landing.
#[test]
fn the_empty_region_digest_is_the_coinbases_row() {
    assert_eq!(
        coinbase(1).txid_parts().prunable_hash,
        shekyl_wire::empty_region_prunable_hash()
    );
    assert_ne!(
        shekyl_wire::empty_region_prunable_hash().to_bytes(),
        [0u8; 32],
        "the empty-region digest is keccak256(\"\"), not the null hash"
    );
}

/// The coinbase carries no good **however large its `extra` grows**: attestation
/// records live in `extra`, which is skeleton and is never discarded, not in a
/// prunable region. Run at one output and at the largest the grammar builds, so
/// the claim is about the ct and not about the fixture's size.
#[test]
fn the_coinbase_carries_no_good_however_large_its_extra() {
    let small = coinbase(1);
    assert!(!in_domain(&small));
    let baseline_extra = small.prefix.extra.len();

    let mut maximal = coinbase(1);
    maximal.prefix.extra = coinbase_extra(256);
    assert!(
        maximal.prefix.extra.len() > baseline_extra,
        "the maximal-attestation extra must actually be larger"
    );
    assert!(matches!(maximal.ct, Ct::Null(_)), "still a Null ct");
    assert!(
        !in_domain(&maximal),
        "a coinbase's attestation records are extra, not archival good"
    );
    assert_eq!(
        maximal.txid_parts().prunable_hash,
        shekyl_wire::empty_region_prunable_hash()
    );
}

// ---- leg 3: the counter equals the predicate --------------------------------

/// **The divergence test.** Over a synthetic chain mixing every class with empty
/// blocks, the shard boundaries derived from `cumulative_tx_count` — what the
/// implementation reads — equal the boundaries from counting the predicate
/// directly, which is what the ruling defines. The day a class stops carrying
/// good, or the coinbase starts, this fails.
///
/// `cumulative_tx_count` is the running count of **non-coinbase** transactions
/// (`shekyl-chain-store/src/store/prune.rs:421-428`, `listed_before`); the
/// predicate count is the running count of transactions in the domain. Both are
/// folded here over the same chain and compared **per transaction**, not only at
/// the end, so an offsetting pair of errors cannot cancel.
#[test]
fn the_counter_equals_the_predicate_over_a_mixed_chain() {
    // Each inner vector is one block: the coinbase first, then its listed
    // transactions. Two blocks are empty (coinbase only) — the case that
    // produces a coinbase-only shard under the storage-id domain.
    let chain: Vec<Vec<Transaction>> = vec![
        vec![coinbase(0)],
        vec![coinbase(1), spend_body(), bond_post_body()],
        vec![coinbase(2)],
        vec![
            coinbase(3),
            serve_credit_body(),
            emission_body_no_fees(),
            emission_body_with_fees(),
        ],
        vec![coinbase(4)],
        vec![coinbase(5), spend_body()],
    ];

    // `T` small enough that the chain crosses several boundaries.
    const T: u64 = 3;

    let mut listed_count = 0u64;
    let mut domain_count = 0u64;
    let mut crossings = 0usize;

    for block in &chain {
        let (miner, listed_txs) = block.split_first().expect("every block has a coinbase");
        assert_eq!(class_at(miner, TxSlot::Miner), TxClass::Coinbase);
        assert!(!in_domain(miner), "the coinbase is never in the domain");

        for (idx, tx) in listed_txs.iter().enumerate() {
            assert_ne!(
                class_at(tx, TxSlot::Listed(idx)),
                TxClass::Coinbase,
                "a listed transaction is never the coinbase class"
            );
            listed_count += 1;
            if in_domain(tx) {
                domain_count += 1;
            }
            // The equivalence, per transaction: the counter the implementation
            // reads and the count the definition names are the same number, so
            // the shard each transaction lands in is the same under both.
            assert_eq!(
                listed_count, domain_count,
                "cumulative_tx_count diverged from the domain count"
            );
            assert_eq!(
                (listed_count - 1) / T,
                (domain_count - 1) / T,
                "the shard boundary diverged"
            );
            if (listed_count - 1).is_multiple_of(T) && listed_count > 1 {
                crossings += 1;
            }
        }
    }

    assert!(
        domain_count > 0 && crossings > 0,
        "the fixture chain must cross at least one shard boundary \
         (listed {listed_count}, crossings {crossings})"
    );
}
