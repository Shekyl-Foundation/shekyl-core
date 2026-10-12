// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle rule against the fixture view (`harness::bundle`).
//!
//! # What these tests bite against, and what they do not cover
//!
//! They bite against the verifier's own logic: the order of §9.1's checks,
//! each refusal's arm and census row, the window and bitmap arithmetic,
//! and the three verifications — the `0x0C` opening, the witness
//! signature and each receipt — over real scheme-3 keys and signatures
//! made by the production signer.
//!
//! They do **not** cover the facts the view serves. A draw count, a
//! commitment, a visibly-short flag and a snapshot are whatever a test
//! wrote into `FixtureBundleView`; that a store derives them correctly
//! is `SO-D12`'s to witness with real blocks. The rule is tested for its
//! logic and untested for parity until then (`50-testing.mdc`).
//!
//! Every test names the edit that turns it red.

use std::path::Path;

use shekyl_archival_retention::{
    bundle_root, section_budget, BundleBody, BundleRecord, BundleRef, DrawablePair, EpochSnapshot,
    PassBitmap, BUNDLE_RECORD_LEN, BUNDLE_SECTION_BUDGET_MULTIPLE, BUNDLE_WITNESS_KEY_LEN,
    BUNDLE_WITNESS_LEN, CHALLENGE_READS, PASS_COUNTERSIGNATURE_MESSAGE_LEN,
};
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use super::*;
use crate::harness::bundle::{fixture_block_hash, BundleRead, BundleReadFaulted, BundleWorld};
use crate::rule_set::{FakechainSchedule, SettlementEpochBlocks};

type Judged = Result<Admitted, BundleRefused<BundleReadFaulted>>;

/// Judge at `h + 1` under the genesis rule set.
fn judge(world: &BundleWorld, reference: &BundleRef, body: &BundleBody) -> Judged {
    judge_at(world, reference, body, world.h.to_raw() + 1)
}

fn judge_at(world: &BundleWorld, reference: &BundleRef, body: &BundleBody, h_incl: u64) -> Judged {
    verify_bundle(
        reference,
        body,
        BlockHeight::from_raw(h_incl),
        &world.view,
        &RuleSet::GENESIS,
    )
}

fn invalid(why: BundleInvalid) -> Judged {
    Err(BundleRefused::Invalid(why))
}

/// The same body under a reference whose prunable hash is recomputed: what
/// a block that committed to the mutated bytes would carry.
fn rehashed(reference: &BundleRef, bytes: &[u8]) -> (BundleRef, BundleBody) {
    let body = BundleBody::decode(bytes).expect("a body of whole records");
    let reference = BundleRef::new(
        *reference.seed(),
        reference.h(),
        reference.bitmap_bytes(),
        body.prunable_hash(),
    )
    .expect("a short bitmap");
    (reference, body)
}

fn unhex(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

// ------------------------------------------------------------- admission

/// A bundle with some passes and some misses admits, and returns every
/// draw of `h`: `count(h)` entries, each the pair the production selection
/// names at that `j`, each `passed` as its bit says (`SCS-P37`). Red
/// edits: derive only the set bits (`draws.len()` is 3); read `passed`
/// from the record index instead of the bit.
#[test]
fn a_bundle_with_passes_and_misses_admits_with_every_draw_derived() {
    let world = BundleWorld::new(10);
    let passes = [1u32, 4, 9];
    let (reference, body) = world.bundle(&passes);
    assert_eq!(reference.bitmap_bytes(), [0x12, 0x02], "draws 1, 4 and 9");
    assert_eq!(body.record_count(), 3);

    let admitted = judge(&world, &reference, &body).expect("an honest bundle admits");
    assert_eq!(admitted.kept, reference.kept(10).expect("ten bits"));
    assert_eq!(admitted.kept.h, world.h);
    assert_eq!(admitted.kept.seed, world.seed);
    assert_eq!(admitted.draws.len(), 10);
    for (j, draw) in admitted.draws.iter().enumerate() {
        let j = u32::try_from(j).expect("ten draws");
        assert_eq!(draw.index, world.selected(j), "draw {j}'s index");
        assert_eq!(
            Some(draw.pair),
            world.snapshot().pair(draw.index),
            "draw {j}'s pair is the snapshot's at that index"
        );
        assert_eq!(draw.passed, passes.contains(&j), "draw {j}'s bit");
    }
    // The fixture's draws are not all one pair: the assertion above would
    // hold vacuously over a constant selection.
    let distinct: std::collections::BTreeSet<u64> =
        admitted.draws.iter().map(|d| d.index).collect();
    assert!(distinct.len() > 1, "the ten draws name more than one pair");
}

/// A bundle with no passes is valid: it is what issues `h`'s misses
/// (§7.1). Red edit: refuse an empty record list (the carrier's `n ≥ 1`).
#[test]
fn an_all_miss_bundle_admits_and_issues_every_draw_as_a_miss() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[]);
    assert_eq!(body.record_count(), 0);
    let admitted = judge(&world, &reference, &body).expect("an all-miss bundle admits");
    assert_eq!(admitted.draws.len(), 10);
    assert!(admitted.draws.iter().all(|d| !d.passed));
}

/// A block with no draws has a bundle with an empty bitmap: valid, issues
/// nothing (`SCS-P33`), and reads neither a snapshot nor a block hash.
/// Red edit: refuse `count(h) = 0`, or read the snapshot before the
/// early return — the read log then holds `Snapshot`.
#[test]
fn a_bundle_for_a_block_with_no_draws_admits_and_returns_none() {
    let world = BundleWorld::new(0);
    let (reference, body) = world.bundle(&[]);
    assert!(reference.bitmap_bytes().is_empty());
    world.view.take_reads();
    let admitted = judge(&world, &reference, &body).expect("an empty bundle admits");
    assert!(admitted.draws.is_empty());
    assert_eq!(admitted.kept.passes.count(), 0);
    assert_eq!(
        world.view.take_reads(),
        [
            BundleRead::Revealed,
            BundleRead::DrawCount,
            BundleRead::DrawCommitment
        ]
    );
}

/// The reads of an admitted bundle, in §9.1's order: the one-per-`h` rule
/// and the count (step 3), the commitment (4), then the snapshot, `h`'s
/// hash and the issued counts (6), then each record's anchor hash (8).
/// Red edit: hoist any later read above an earlier step.
#[test]
fn the_view_is_read_in_the_order_of_the_checks() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4]);
    world.view.take_reads();
    judge(&world, &reference, &body).expect("admits");
    let reads = world.view.take_reads();
    assert_eq!(
        reads[..5],
        [
            BundleRead::Revealed,
            BundleRead::DrawCount,
            BundleRead::DrawCommitment,
            BundleRead::Snapshot,
            BundleRead::BlockHash,
        ]
    );
    let tail: Vec<BundleRead> = reads[5..]
        .iter()
        .copied()
        .skip_while(|r| *r == BundleRead::VisiblyShort)
        .collect();
    assert!(reads.len() > 5 + tail.len(), "the selection asked the view");
    assert_eq!(
        tail,
        [BundleRead::BlockHash, BundleRead::BlockHash],
        "one anchor hash per record, after every draw is derived"
    );
}

// ------------------------------------------------------------ the vectors

/// The specification's §4.5 selection vectors, re-pinned through the
/// verifier: `seed = 0x11 × 32`, `block_hash(h) = 0x22 × 32`, `D` = 8,
/// draws 0 to 5, for three issued states. The expected indices are the
/// table's, written here as numbers; `select_draw` is not called by this
/// test. **Oracle tier: external** — the table is the specification's,
/// computed by its author's standalone cSHAKE256, and was reproduced by a
/// second standalone implementation before this test was written.
///
/// Bites against the verifier feeding the selection anything but
/// `(seed, block_hash(h), j, D, the view's visibly_short at h)`. Does not
/// cover the cap vector (`j` = 28,409,462): a block has no such draw, and
/// `secret_draw`'s own test holds it.
///
/// Red edits: pass `h_incl`'s hash, or the anchor's, to the selection;
/// ask `visibly_short` at `h_incl` instead of `h`; pass a `D` other than
/// the snapshot's length.
#[test]
fn kat_the_verifier_derives_the_specifications_selection() {
    type State = (&'static str, fn(u64) -> bool, [u64; 6]);
    let table: [State; 3] = [
        ("indices 0 to 3 short", |i| i <= 3, [3, 2, 3, 2, 0, 2]),
        ("none short", |_| false, [3, 4, 1, 2, 7, 4]),
        ("all short", |_| true, [3, 2, 3, 4, 0, 5]),
    ];
    for (state, short, expected) in table {
        let mut world = BundleWorld::with(BundleWorld::H, [0x11; 32], 6, &RuleSet::GENESIS);
        world
            .view
            .hashes
            .insert(world.h, BlockHash::from_bytes([0x22; 32]));
        for index in (0..8).filter(|i| short(*i)) {
            world.view.short.insert((world.h, index));
            // The same pair short at another height is not short at `h`.
            world
                .view
                .short
                .remove(&(BlockHeight::from_raw(world.h.to_raw() + 1), index));
        }
        let (reference, body) = world.bundle(&[]);
        let admitted = judge(&world, &reference, &body).expect("an all-miss bundle admits");
        let derived: Vec<u64> = admitted.draws.iter().map(|d| d.index).collect();
        assert_eq!(derived, expected, "{state}");
    }
}

/// The specification's §5.2 nonce vectors, re-pinned through the
/// verifier. Each record is signed over a transcript whose nonce is the
/// table's hex, not `challenge_nonce`'s output; the bundle admits only if
/// the verifier recomputes that nonce from `(seed, block_hash(h), j,
/// attempt)`. The signer for draw `j` is the pair §4.5's table names with
/// none short (index 3 for `j` = 0, index 4 for `j` = 1). **Oracle tier:
/// external**, as the selection's.
///
/// Red edits: drop the `attempt` byte from the nonce; take `j` from the
/// record's position instead of its bit; hash `h_incl`'s block hash.
#[test]
fn kat_the_verifier_recomputes_the_specifications_nonces() {
    let rows: [(u32, u64, u8, &str); 4] = [
        (
            0,
            3,
            0,
            "b9601207ca7b74d36da0ee2402b83418e94408a7815e33d318db0ff783da45dc",
        ),
        (
            0,
            3,
            1,
            "61a3796f42ab53642e53458b5b6012c6102aacbce03c9ea20796407776df2248",
        ),
        (
            0,
            3,
            2,
            "f8bfae392e076cf3415bd37f1584a48abefbae56cb6fe89329b98955cc1b76d4",
        ),
        (
            1,
            4,
            0,
            "65bf6d43f77b2e7f71e2ff7a5e3a570257be3ce73f8760a76152f92773bdb31b",
        ),
    ];
    let mut world = BundleWorld::with(BundleWorld::H, [0x11; 32], 6, &RuleSet::GENESIS);
    world
        .view
        .hashes
        .insert(world.h, BlockHash::from_bytes([0x22; 32]));
    let anchor = world.honest_anchor();
    for (draw, index, attempt, nonce) in rows {
        let record = world.record_signed_over(index, attempt, anchor, &unhex(nonce));
        let passes = PassBitmap::from_passes(6, [draw]).expect("in range");
        let (reference, body) = world.assemble(passes, &[record]);
        let admitted = judge(&world, &reference, &body)
            .unwrap_or_else(|e| panic!("draw {draw} attempt {attempt}: {e:?}"));
        assert_eq!(admitted.draws[draw as usize].index, index);
        assert!(admitted.draws[draw as usize].passed);
    }
    // The control: a receipt over attempt 1's nonce, filed as attempt 0,
    // is a receipt for another read. One receipt cannot serve two.
    let mut wrong = world.record_signed_over(3, 1, anchor, &unhex(rows[1].3));
    wrong.attempt = 0;
    let passes = PassBitmap::from_passes(6, [0]).expect("in range");
    let (reference, body) = world.assemble(passes, &[wrong]);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Receipt { draw: 0 })
    );
    // And over draw 1's nonce, filed at draw 0.
    let other_draw = world.record_signed_over(3, 0, anchor, &unhex(rows[3].3));
    let passes = PassBitmap::from_passes(6, [0]).expect("in range");
    let (reference, body) = world.assemble(passes, &[other_draw]);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Receipt { draw: 0 })
    );
}

/// The receipt's transcript is `SF-D8`'s 112 bytes (§6.1). Red edit: add
/// or drop a field of `pass_countersignature_message`.
#[test]
fn the_receipts_transcript_is_112_bytes() {
    assert_eq!(PASS_COUNTERSIGNATURE_MESSAGE_LEN, 112);
}

// ------------------------------------------- step 3: window, one per `h`

/// `h < h_incl ≤ h + W₂`, with `W₂` = 500 under the genesis schedule: the
/// including block may be `h + 1` through `h + 500`, and not `h`, not
/// below it, and not `h + 501`. Red edits: `≤` for the lower bound admits
/// `h_incl = h`; `<` for the upper refuses `h + 500`.
#[test]
fn the_window_is_above_h_and_within_w2() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1]);
    let h = world.h.to_raw();
    assert!(judge_at(&world, &reference, &body, h + 1).is_ok());
    assert!(judge_at(&world, &reference, &body, h + 500).is_ok());
    for h_incl in [h + 501, h, h - 1, 0, u64::MAX] {
        assert_eq!(
            judge_at(&world, &reference, &body, h_incl),
            invalid(BundleInvalid::OutsideWindow),
            "h_incl = {h_incl}"
        );
    }
}

/// `W₂` is the rule set's, not a constant: under a 100-block epoch it is
/// 5, and under a 10-block epoch there is no window and nothing is inside
/// it. Red edit: read `CHALLENGE_RESPONSE_BLOCKS`; `h + 6` then admits.
#[test]
fn the_window_is_read_off_the_rule_set() {
    let short_epoch = |blocks: u64, cap: u64| {
        RuleSet::fakechain(
            None,
            FakechainSchedule::new(
                SettlementEpochBlocks::new(blocks).expect("non-zero"),
                BlockCount::from_raw(cap),
            )
            .expect("0 < cap < SEB"),
        )
    };
    let hundred = short_epoch(100, 5);
    let h = BlockHeight::from_raw(1_050);
    let world = BundleWorld::with(h, BundleWorld::SEED, 10, &hundred);
    let (reference, body) = world.bundle(&[1]);
    let at = |h_incl: u64, rule_set: &RuleSet| {
        verify_bundle(
            &reference,
            &body,
            BlockHeight::from_raw(h_incl),
            &world.view,
            rule_set,
        )
    };
    assert!(at(1_051, &hundred).is_ok());
    assert!(at(1_055, &hundred).is_ok());
    assert_eq!(at(1_056, &hundred), invalid(BundleInvalid::OutsideWindow));

    // Ten blocks per epoch: `SEB / 20` is zero, and zero is not a window.
    let ten = short_epoch(10, 5);
    assert_eq!(
        ten.settlement_schedule().challenge_response_blocks(),
        None,
        "the fixture's premise"
    );
    assert_eq!(at(1_051, &ten), invalid(BundleInvalid::OutsideWindow));
}

/// A chain admits at most one bundle for `h`. Red edit: skip the
/// `revealed` read.
#[test]
fn a_second_bundle_for_a_revealed_block_refuses() {
    let mut world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1]);
    assert!(judge(&world, &reference, &body).is_ok());
    world.view.revealed.insert(world.h);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::AlreadyRevealed)
    );
    // Another block's reveal is not this one's.
    world.view.revealed.clear();
    world
        .view
        .revealed
        .insert(BlockHeight::from_raw(world.h.to_raw() - 1));
    assert!(judge(&world, &reference, &body).is_ok());
}

/// A bundle for a block the chain does not have is refused. Red edit:
/// treat a missing count as zero — the bundle would then be judged
/// against an empty bitmap and refused as `Bitmap`.
#[test]
fn a_bundle_for_a_block_the_chain_does_not_have_refuses() {
    let mut world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1]);
    world.view.counts.remove(&world.h);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::UnknownBlock)
    );
}

// --------------------------------------- step 3: bitmap and record count

/// The bitmap is exactly `count(h)` bits: a count with another byte
/// length refuses, and so does a count that leaves a set bit in the
/// padding. Red edit: read the bitmap against its own length in bits
/// (`8 · len`) instead of the chain's count.
#[test]
fn a_bitmap_that_is_not_count_bits_refuses() {
    let mut world = BundleWorld::new(10);
    // Draw 9 passes: with a count of 9 its bit is padding.
    let (reference, body) = world.bundle(&[1, 9]);
    assert!(judge(&world, &reference, &body).is_ok());
    for chain_count in [9u32, 8, 0, 17, 300] {
        world.view.counts.insert(world.h, chain_count);
        assert_eq!(
            judge(&world, &reference, &body),
            invalid(BundleInvalid::Bitmap),
            "chain count {chain_count}"
        );
    }
    // The same two bytes are a bitmap of 16 bits. The bundle then fails
    // further on, at the witness signature: the commitment covers the
    // count.
    world.view.counts.insert(world.h, 16);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::WitnessSignature)
    );
}

/// Red edit 1 of the specification's §11: **a bundle missing one record's
/// draw.** A set bit with no record, and a record with no set bit, are
/// both refused before anything is opened. Red edit to the code: drop the
/// popcount comparison — the zip of bits and records then silently stops
/// at the shorter, and a pass with no receipt is admitted.
#[test]
fn a_set_bit_without_a_record_and_a_record_without_a_bit_refuse() {
    let world = BundleWorld::new(10);
    let records: Vec<BundleRecord> = [1u32, 4, 9].map(|j| world.record(j, 0)).to_vec();
    let bits = |passes: &[u32]| PassBitmap::from_passes(10, passes.iter().copied()).expect("ok");

    // The control: three bits, three records.
    let (reference, body) = world.assemble(bits(&[1, 4, 9]), &records);
    assert!(judge(&world, &reference, &body).is_ok());

    // Three bits, two records: draw 9 claims a pass and carries none.
    let (reference, body) = world.assemble(bits(&[1, 4, 9]), &records[..2]);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::RecordCount)
    );
    // Two bits, three records: a record for a clear bit.
    let (reference, body) = world.assemble(bits(&[1, 4]), &records);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::RecordCount)
    );
    // No bits, one record.
    let (reference, body) = world.assemble(bits(&[]), &records[..1]);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::RecordCount)
    );
}

/// The same count of records, for the wrong draws: a record's draw is the
/// position of its bit, so draw 8's receipt filed under draw 9's bit is a
/// receipt over another nonce and, usually, another pair. Red edit: carry
/// `j` in the record and trust it.
#[test]
fn a_record_filed_under_another_draws_bit_refuses_at_its_receipt() {
    let world = BundleWorld::new(10);
    let records = [world.record(1, 0), world.record(4, 0), world.record(8, 0)];
    let passes = PassBitmap::from_passes(10, [1, 4, 9]).expect("in range");
    let (reference, body) = world.assemble(passes, &records);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Receipt { draw: 9 })
    );
}

// ------------------------------------------------- step 4: the commitment

/// The witness key and the seed open `h`'s `0x0C`, or the bundle is
/// refused: another seed, another witness key, a block with no `0x0C`.
/// Red edit: skip the comparison — the second case, a bundle wholly
/// authored and signed by a key the producer never committed to, admits.
#[test]
fn a_bundle_that_does_not_open_the_commitment_refuses() {
    let mut world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4]);
    assert!(judge(&world, &reference, &body).is_ok());

    // Another seed in the kept part.
    let mut seed = world.seed;
    seed[7] ^= 0x40;
    let other_seed = BundleRef::new(
        seed,
        reference.h(),
        reference.bitmap_bytes(),
        *reference.prunable_hash(),
    )
    .expect("short");
    assert_eq!(
        judge(&world, &other_seed, &body),
        invalid(BundleInvalid::Commitment)
    );

    // Another author: a self-consistent bundle for the same seed, signed
    // by a witness key that is not the one in the coinbase.
    let mut forger = BundleWorld::new(10);
    let (forger_public, forger_secret) =
        HybridEd25519FnDsa::keypair_from_seeds(&[0xF1; 32], &[0xF2; 32]).expect("keygen");
    forger.witness_public_key = forger_public
        .to_canonical_bytes()
        .try_into()
        .expect("the canonical key length");
    forger.witness_secret_key = forger_secret;
    let (forged_ref, forged_body) = forger.bundle(&[1, 4]);
    assert_eq!(
        judge(&world, &forged_ref, &forged_body),
        invalid(BundleInvalid::Commitment)
    );
    // The forger's bundle is valid on a chain that committed to its key:
    // the refusal above is the commitment's and nothing else's.
    forger.view.commitments.insert(
        forger.h,
        shekyl_archival_retention::draw_commit(&forger.witness_public_key, &forger.seed),
    );
    assert!(judge(&forger, &forged_ref, &forged_body).is_ok());

    // A block with no `0x0C` has nothing to open.
    world.view.commitments.remove(&world.h);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Commitment)
    );
}

// ------------------------------------------ step 5: the witness signature

/// After the reveal the seed and the witness key are public, so anyone can
/// build a body that opens the commitment. What stops it is the witness
/// signature, checked next and before any receipt: a body the producer did
/// not sign costs one signature verification, no snapshot read and no
/// receipt verification (§9.1). Red edits: verify receipts first (the read
/// log gains `Snapshot`); verify under `SCHEME_DOMAIN_WITNESS_CARRIER`.
#[test]
fn a_body_the_producer_did_not_sign_refuses_before_any_receipt() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4, 9]);

    // The forger keeps the witness key and signature, drops draw 9's
    // record and clears its bit: a pair's pass turned into a miss.
    let kept_records = &body.as_bytes()[..BUNDLE_WITNESS_LEN + 2 * BUNDLE_RECORD_LEN];
    let forged_body = BundleBody::decode(kept_records).expect("two records");
    let forged_ref = BundleRef::new(
        *reference.seed(),
        reference.h(),
        PassBitmap::from_passes(10, [1, 4])
            .expect("in range")
            .as_bytes(),
        forged_body.prunable_hash(),
    )
    .expect("short");
    world.view.take_reads();
    assert_eq!(
        judge(&world, &forged_ref, &forged_body),
        invalid(BundleInvalid::WitnessSignature)
    );
    assert_eq!(
        world.view.take_reads(),
        [
            BundleRead::Revealed,
            BundleRead::DrawCount,
            BundleRead::DrawCommitment
        ],
        "no snapshot, no block hash, no issued count: nothing of steps 6 to 8"
    );

    // A pass moved from draw 4 to draw 5 with the records untouched: the
    // popcount holds, the commitment opens, and the signature does not
    // cover this bitmap.
    let moved = BundleRef::new(
        *reference.seed(),
        reference.h(),
        PassBitmap::from_passes(10, [1, 5, 9])
            .expect("in range")
            .as_bytes(),
        *reference.prunable_hash(),
    )
    .expect("short");
    assert_eq!(
        judge(&world, &moved, &body),
        invalid(BundleInvalid::WitnessSignature)
    );
}

/// One flipped byte anywhere in the prunable part refuses the bundle, and
/// which check refuses depends on where: without the reference's hash
/// recomputed, the body is not the reference's at all; with it, a flip in
/// the witness key fails the `0x0C` opening (the key is half of what was
/// committed) and a flip anywhere else — the witness signature, or any
/// field of any record — fails the witness signature, which covers every
/// byte of every record. A flip in the kept seed fails the opening. Red
/// edit: leave any field out of `bundle_commitment`.
#[test]
fn a_flipped_byte_refuses_and_the_region_decides_which_check() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4, 9]);
    let record = |n: usize| BUNDLE_WITNESS_LEN + n * BUNDLE_RECORD_LEN;
    let cases: [(&str, usize, BundleInvalid); 13] = [
        ("witness key, header", 1, BundleInvalid::Commitment),
        ("witness key, Ed25519 half", 20, BundleInvalid::Commitment),
        ("witness key, FN-DSA half", 900, BundleInvalid::Commitment),
        (
            "witness signature, header",
            BUNDLE_WITNESS_KEY_LEN,
            BundleInvalid::WitnessSignature,
        ),
        (
            "witness signature, Ed25519 half",
            BUNDLE_WITNESS_KEY_LEN + 30,
            BundleInvalid::WitnessSignature,
        ),
        (
            "witness signature, FN-DSA half",
            BUNDLE_WITNESS_KEY_LEN + 500,
            BundleInvalid::WitnessSignature,
        ),
        (
            "first record, attempt",
            record(0),
            BundleInvalid::WitnessSignature,
        ),
        (
            "first record, anchor height",
            record(0) + 1,
            BundleInvalid::WitnessSignature,
        ),
        (
            "first record, delivery digest",
            record(0) + 9,
            BundleInvalid::WitnessSignature,
        ),
        (
            "first record, receipt",
            record(0) + 41 + 700,
            BundleInvalid::WitnessSignature,
        ),
        (
            "second record, receipt header",
            record(1) + 41,
            BundleInvalid::WitnessSignature,
        ),
        (
            "last record, delivery digest",
            record(2) + 40,
            BundleInvalid::WitnessSignature,
        ),
        (
            "last record, last byte",
            record(3) - 1,
            BundleInvalid::WitnessSignature,
        ),
    ];
    for (region, at, expected) in cases {
        let mut bytes = body.as_bytes().to_vec();
        bytes[at] ^= 0x01;
        // As a peer would serve it for the honest reference.
        let mutated = BundleBody::decode(&bytes).expect("whole records");
        assert_eq!(
            judge(&world, &reference, &mutated),
            Err(BundleRefused::BodyNotReferenced),
            "{region}, under the honest reference"
        );
        // As a block that committed to the mutated bytes would carry it.
        let (rehashed_ref, mutated) = rehashed(&reference, &bytes);
        assert_eq!(
            judge(&world, &rehashed_ref, &mutated),
            invalid(expected),
            "{region}, under its own hash"
        );
    }

    // The seed is kept, not prunable: a flip there fails the opening.
    for at in [0usize, 13, 31] {
        let mut seed = *reference.seed();
        seed[at] ^= 0x01;
        let flipped = BundleRef::new(
            seed,
            reference.h(),
            reference.bitmap_bytes(),
            *reference.prunable_hash(),
        )
        .expect("short");
        assert_eq!(
            judge(&world, &flipped, &body),
            invalid(BundleInvalid::Commitment),
            "seed byte {at}"
        );
    }
}

// -------------------------------------------------- step 7: `attempt < K`

/// `attempt` is below `K` = 3: a third read (`attempt` = 2) admits, a
/// fourth refuses and names its draw. Red edit: `>` for `>=`.
#[test]
fn a_record_from_a_read_past_the_last_refuses() {
    assert_eq!(CHALLENGE_READS, 3, "K (SCS-P13)");
    let world = BundleWorld::new(10);
    let bundle_with = |attempt: u8| {
        let records = [world.record(1, 0), world.record(4, attempt)];
        world.assemble(PassBitmap::from_passes(10, [1, 4]).expect("ok"), &records)
    };
    for attempt in 0..3 {
        let (reference, body) = bundle_with(attempt);
        assert!(
            judge(&world, &reference, &body).is_ok(),
            "attempt {attempt}"
        );
    }
    for attempt in [3u8, 4, 255] {
        let (reference, body) = bundle_with(attempt);
        assert_eq!(
            judge(&world, &reference, &body),
            invalid(BundleInvalid::Attempt { draw: 4 }),
            "attempt {attempt}"
        );
    }
}

// ------------------------------------------- step 8: anchor, then receipt

/// `anchor_height < h` (`SCS-P32`): `h − 1` admits, `h` and above refuse
/// and name the draw. Red edit: `>` for `>=` admits an anchor at `h`.
#[test]
fn an_anchor_at_or_above_h_refuses() {
    let world = BundleWorld::new(10);
    let h = world.h.to_raw();
    let bundle_with = |anchor: u64| {
        let records = [
            world.record(1, 0),
            world.record_anchored(4, 0, BlockHeight::from_raw(anchor)),
        ];
        world.assemble(PassBitmap::from_passes(10, [1, 4]).expect("ok"), &records)
    };
    for anchor in [h - 1, h - 721, 0] {
        let (reference, body) = bundle_with(anchor);
        assert!(judge(&world, &reference, &body).is_ok(), "anchor {anchor}");
    }
    for anchor in [h, h + 1, h + 500] {
        let (reference, body) = bundle_with(anchor);
        assert_eq!(
            judge(&world, &reference, &body),
            invalid(BundleInvalid::Anchor { draw: 4 }),
            "anchor {anchor}"
        );
    }
}

/// A receipt verifies over exactly the transcript of §6.1, under the
/// derived pair's key: another delivery digest, another anchor than the
/// one signed, a receipt that is not a scheme-3 signature, each refuses
/// and names its draw. Red edit: leave a field out of the transcript.
#[test]
fn a_receipt_that_does_not_cover_its_record_refuses() {
    let world = BundleWorld::new(10);
    let honest = world.record(4, 0);
    let bundle_with = |tampered: BundleRecord| {
        world.assemble(
            PassBitmap::from_passes(10, [1, 4]).expect("ok"),
            &[world.record(1, 0), tampered],
        )
    };
    let refuses = |tampered: BundleRecord, what: &str| {
        let (reference, body) = bundle_with(tampered);
        assert_eq!(
            judge(&world, &reference, &body),
            invalid(BundleInvalid::Receipt { draw: 4 }),
            "{what}"
        );
    };
    let (reference, body) = bundle_with(honest);
    assert!(judge(&world, &reference, &body).is_ok(), "the control");

    let mut digest = honest;
    digest.delivery_digest[0] ^= 1;
    refuses(digest, "another delivery digest");

    let mut anchor = honest;
    anchor.anchor_height = BlockHeight::from_raw(honest.anchor_height.to_raw() - 1);
    refuses(anchor, "another anchor height, so another anchor hash");

    let mut frame = honest;
    frame.receipt[0] = 1;
    refuses(frame, "a version-1 signature header");

    let mut bytes = honest;
    bytes.receipt[400] ^= 1;
    refuses(bytes, "one bit of the receipt");

    // The anchor's hash is the connecting chain's: the same record on a
    // chain with another block at the anchor height is not a receipt.
    let mut forked = BundleWorld::new(10);
    let (reference, body) = forked.bundle(&[1, 4]);
    assert!(judge(&forked, &reference, &body).is_ok());
    forked.view.hashes.insert(
        forked.honest_anchor(),
        fixture_block_hash(BlockHeight::from_raw(1)),
    );
    assert_eq!(
        judge(&forked, &reference, &body),
        invalid(BundleInvalid::Receipt { draw: 1 })
    );
}

/// Red edit 2 of the specification's §11: **a receipt key read from
/// anywhere other than the snapshot.** The view's snapshot holds key A
/// for a persona; the receipt is signed by key B for the same pair, the
/// same transcript. The bundle is refused — and admitted once the
/// snapshot holds B — so the key the verifier used is the snapshot's and
/// no other. Red edit to the code: take the key from any second source
/// (the record, a tip read); this test cannot then tell A from B.
#[test]
fn a_receipt_under_a_key_the_snapshot_does_not_hold_refuses() {
    let mut world = BundleWorld::new(16);
    // A draw whose pair is the first persona's (indices 0 to 2).
    let draw = (0..16)
        .find(|j| world.selected(*j) <= 2)
        .expect("sixteen draws over eight pairs reach the first persona");
    let index = world.selected(draw);
    let pair = world.snapshot().pair(index).expect("in D");
    assert_eq!(pair.p_id, world.personas[0].p_id);

    let (key_b_public, key_b_secret) =
        HybridEd25519FnDsa::keypair_from_seeds(&[0xB0; 32], &[0xB1; 32]).expect("keygen");
    let anchor = world.honest_anchor();
    let nonce = shekyl_archival_retention::challenge_nonce(
        &world.seed,
        fixture_block_hash(world.h).as_bytes(),
        draw,
        0,
    );
    let signed_by_b = world.record_signed_by(&key_b_secret, pair.shard_id, 0, anchor, &nonce);
    let passes = PassBitmap::from_passes(16, [draw]).expect("in range");
    let (reference, body) = world.assemble(passes, &[signed_by_b]);

    // The snapshot holds key A.
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Receipt { draw })
    );

    // The same bundle against a snapshot that holds key B for the persona.
    let epoch = world.snapshot().epoch();
    let pairs: Vec<DrawablePair> = (0..world.snapshot().len())
        .map(|i| world.snapshot().pair(i).expect("in D"))
        .collect();
    let keys: Vec<([u8; 32], Vec<u8>)> = world
        .personas
        .iter()
        .enumerate()
        .map(|(n, p)| {
            let key = if n == 0 {
                key_b_public.to_canonical_bytes()
            } else {
                p.receipt_public_key.clone()
            };
            (p.p_id, key)
        })
        .collect();
    world.view.snapshots.insert(
        epoch,
        EpochSnapshot::new(epoch, keys, pairs).expect("every pair has a key"),
    );
    assert!(judge(&world, &reference, &body).is_ok());
    // And the honest bundle, signed by key A, is now the one refused.
    let (honest_ref, honest_body) = world.bundle(&[draw]);
    assert_eq!(
        judge(&world, &honest_ref, &honest_body),
        invalid(BundleInvalid::Receipt { draw })
    );
}

// ------------------------------------------------------ order of refusals

/// §9.1: the order of the checks decides which refusal is observed. Each
/// case carries two defects and is refused for the earlier. Red edit:
/// reorder any two steps of `verify_bundle`.
#[test]
fn of_two_defects_the_earlier_check_refuses() {
    let h = BundleWorld::H.to_raw();

    // The body's hash before everything: a body that is not the
    // reference's, in a block outside the window.
    let world = BundleWorld::new(10);
    let (reference, _) = world.bundle(&[1, 4]);
    let (_, other_body) = world.bundle(&[1]);
    assert_eq!(
        judge_at(&world, &reference, &other_body, h + 501),
        Err(BundleRefused::BodyNotReferenced)
    );

    // Window before one-per-`h`.
    let mut world = BundleWorld::new(10);
    let (reference, body_ok) = world.bundle(&[1, 4]);
    world.view.revealed.insert(world.h);
    assert_eq!(
        judge_at(&world, &reference, &body_ok, h + 501),
        invalid(BundleInvalid::OutsideWindow)
    );
    // One-per-`h` before the bitmap.
    world.view.counts.insert(world.h, 300);
    assert_eq!(
        judge(&world, &reference, &body_ok),
        invalid(BundleInvalid::AlreadyRevealed)
    );
    // The bitmap before the record count: a bundle one record short is
    // refused for that against the count it was built for, and for its
    // bitmap against a chain count of 3, which two bytes are not.
    world.view.revealed.clear();
    world.view.counts.insert(world.h, 10);
    let records = [world.record(1, 0)];
    let (short_ref, short_body) =
        world.assemble(PassBitmap::from_passes(10, [1, 4]).expect("ok"), &records);
    assert_eq!(
        judge(&world, &short_ref, &short_body),
        invalid(BundleInvalid::RecordCount)
    );
    world.view.counts.insert(world.h, 3);
    assert_eq!(
        judge(&world, &short_ref, &short_body),
        invalid(BundleInvalid::Bitmap)
    );
    // The record count before the commitment.
    world.view.counts.insert(world.h, 10);
    world.view.commitments.insert(world.h, [0; 32]);
    assert_eq!(
        judge(&world, &short_ref, &short_body),
        invalid(BundleInvalid::RecordCount)
    );
    // The commitment before the witness signature: a body nobody signed,
    // on a chain whose `0x0C` it does not open.
    let mut unsigned = body_ok.as_bytes().to_vec();
    unsigned[BUNDLE_WITNESS_KEY_LEN + 500] ^= 1;
    let (unsigned_ref, unsigned_body) = rehashed(&reference, &unsigned);
    assert_eq!(
        judge(&world, &unsigned_ref, &unsigned_body),
        invalid(BundleInvalid::Commitment)
    );

    // The witness signature before `attempt`: an unsigned body whose
    // first record claims a fourth read.
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4]);
    let mut bytes = body.as_bytes().to_vec();
    bytes[BUNDLE_WITNESS_LEN] = 3;
    let (bad_ref, bad_body) = rehashed(&reference, &bytes);
    assert_eq!(
        judge(&world, &bad_ref, &bad_body),
        invalid(BundleInvalid::WitnessSignature)
    );

    // `attempt` before any receipt, across records: draw 1's receipt does
    // not verify and draw 9's record claims a fourth read. Step 7 runs
    // over every record before step 8 runs over any.
    let mut bad_receipt = world.record(1, 0);
    bad_receipt.delivery_digest[0] ^= 1;
    let records = [bad_receipt, world.record(4, 0), world.record(9, 3)];
    let passes = PassBitmap::from_passes(10, [1, 4, 9]).expect("ok");
    let (reference, body) = world.assemble(passes.clone(), &records);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Attempt { draw: 9 })
    );

    // Within step 8, records in ascending `j`, each anchor before its own
    // receipt: draw 1's bad receipt before draw 4's anchor at `h`...
    let anchored_at_h = world.record_anchored(4, 0, world.h);
    let records = [bad_receipt, anchored_at_h, world.record(9, 0)];
    let (reference, body) = world.assemble(passes.clone(), &records);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Receipt { draw: 1 })
    );
    // ...and draw 4's anchor before draw 9's bad receipt, and before its
    // own: a record anchored at `h` whose receipt is also wrong.
    let mut both = anchored_at_h;
    both.delivery_digest[0] ^= 1;
    let mut bad_nine = world.record(9, 0);
    bad_nine.delivery_digest[0] ^= 1;
    let records = [world.record(1, 0), both, bad_nine];
    let (reference, body) = world.assemble(passes, &records);
    assert_eq!(
        judge(&world, &reference, &body),
        invalid(BundleInvalid::Anchor { draw: 4 })
    );
}

// ----------------------------------------------- the three non-verdicts

/// Red edit 4 of the specification's §11: **a reference whose prunable
/// hash does not match its body.** It is refused, and it is not a
/// verdict: the block committed to the reference, and these bytes are
/// some other body. Red edit to the code: drop the hash comparison — the
/// body of another bundle for the same `h` would then be judged, and
/// admitted, under a reference the header root never covered.
#[test]
fn a_body_that_is_not_the_references_is_refused_and_is_not_a_verdict() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4]);
    let mut hash = *reference.prunable_hash();
    hash[0] ^= 1;
    let wrong = BundleRef::new(
        *reference.seed(),
        reference.h(),
        reference.bitmap_bytes(),
        hash,
    )
    .expect("short");
    let refused = judge(&world, &wrong, &body).expect_err("another body's hash");
    assert_eq!(refused, BundleRefused::BodyNotReferenced);
    assert_eq!(refused.verdict(), None, "nothing was judged");
    world.view.take_reads();
    assert!(judge(&world, &wrong, &body).is_err());
    assert!(
        world.view.take_reads().is_empty(),
        "refused before the chain is read"
    );
    // The control: the body under its own reference.
    assert!(judge(&world, &reference, &body).is_ok());
}

/// `open_body`: bytes are checked by hash before they are parsed, and
/// bytes that do hash to the reference and are not a body are a verdict —
/// the block committed to them. Red edit: parse first; the second case
/// then reads `BodyMalformed` for bytes no block committed to.
#[test]
fn a_fetched_body_is_checked_by_hash_and_then_parsed() {
    let world = BundleWorld::new(10);
    let (reference, body) = world.bundle(&[1, 4]);
    let open =
        |reference: &BundleRef, bytes: &[u8]| open_body::<BundleReadFaulted>(reference, bytes);
    assert_eq!(open(&reference, body.as_bytes()), Ok(body.clone()));

    // One byte too many, under the honest reference: not its body.
    let mut long = body.as_bytes().to_vec();
    long.push(0);
    assert_eq!(
        open(&reference, &long),
        Err(BundleRefused::BodyNotReferenced)
    );
    // The same bytes under a reference that commits to them.
    let committed = BundleRef::new(
        *reference.seed(),
        reference.h(),
        reference.bitmap_bytes(),
        shekyl_archival_retention::bundle_prunable_hash(&long),
    )
    .expect("short");
    let refused = open(&committed, &long).expect_err("not whole records");
    assert_eq!(
        refused,
        BundleRefused::Invalid(BundleInvalid::BodyMalformed)
    );
    assert_eq!(refused.verdict().map(BundleInvalid::row), Some(CenRow::J32));
}

/// A view that answered for `h` and then has no snapshot, the wrong
/// epoch's snapshot, no hash for `h`, or an empty drawable set under a
/// block that has draws: none is a verdict. A conforming view presents
/// none of these, and a refusal here would make a store's hole into a
/// consensus rule. Red edit: map any of them to a `BundleInvalid`.
#[test]
fn a_view_with_a_hole_is_unanswered_and_never_a_verdict() {
    let fresh = || {
        let world = BundleWorld::new(10);
        let bundle = world.bundle(&[1, 4]);
        (world, bundle)
    };
    let epoch = RuleSet::GENESIS
        .settlement_schedule()
        .epoch_at(BundleWorld::H);
    let unanswered = |world: &BundleWorld, bundle: &(BundleRef, BundleBody)| {
        let refused = judge(world, &bundle.0, &bundle.1).expect_err("a hole");
        assert_eq!(refused.verdict(), None, "{refused:?} is not a verdict");
        refused
    };

    let (mut world, bundle) = fresh();
    world.view.snapshots.clear();
    assert_eq!(
        unanswered(&world, &bundle),
        BundleRefused::Unanswered(BundleUnanswered::Snapshot { epoch })
    );

    // Another epoch's snapshot under this epoch's key.
    let (mut world, bundle) = fresh();
    let pairs: Vec<DrawablePair> = (0..8)
        .map(|i| world.snapshot().pair(i).expect("in D"))
        .collect();
    let keys: Vec<([u8; 32], Vec<u8>)> = world
        .personas
        .iter()
        .map(|p| (p.p_id, p.receipt_public_key.clone()))
        .collect();
    let other_epoch = shekyl_types::SettlementEpoch::from_raw(epoch.to_raw() + 1);
    world.view.snapshots.insert(
        epoch,
        EpochSnapshot::new(other_epoch, keys, pairs).expect("keyed"),
    );
    assert_eq!(
        unanswered(&world, &bundle),
        BundleRefused::Unanswered(BundleUnanswered::Snapshot { epoch })
    );

    let (mut world, bundle) = fresh();
    world.view.tip = BlockHeight::from_raw(world.h.to_raw() - 1);
    assert_eq!(
        unanswered(&world, &bundle),
        BundleRefused::Unanswered(BundleUnanswered::BlockHash { height: world.h })
    );

    let (mut world, bundle) = fresh();
    world.view.snapshots.insert(
        epoch,
        EpochSnapshot::new(epoch, Vec::<([u8; 32], Vec<u8>)>::new(), []).expect("empty"),
    );
    assert_eq!(
        unanswered(&world, &bundle),
        BundleRefused::Unanswered(BundleUnanswered::Draw { draw: 0 })
    );
}

/// A view fault is the fault, whichever read raised it — never a verdict,
/// and never an admission. The `VisiblyShort` case is the one a plain
/// predicate could swallow: the selection asks through `Fn(u64) -> bool`.
/// Red edit: answer `false` on a faulted `visibly_short` and carry on —
/// the bundle then admits over a selection the chain never made.
#[test]
fn a_view_fault_surfaces_as_itself_from_every_read() {
    for read in [
        BundleRead::Revealed,
        BundleRead::DrawCount,
        BundleRead::DrawCommitment,
        BundleRead::Snapshot,
        BundleRead::BlockHash,
        BundleRead::VisiblyShort,
    ] {
        let mut world = BundleWorld::new(10);
        let (reference, body) = world.bundle(&[1, 4]);
        assert!(judge(&world, &reference, &body).is_ok(), "the control");
        world.view.fault = Some(read);
        let refused = judge(&world, &reference, &body).expect_err("a faulting view");
        assert_eq!(
            refused,
            BundleRefused::View(BundleReadFaulted(read)),
            "{read:?}"
        );
        assert_eq!(refused.verdict(), None);
    }
}

// ------------------------------------------------------------- the section

fn reference_at(h: u64, bitmap: &[u8]) -> BundleRef {
    BundleRef::new([0x5E; 32], BlockHeight::from_raw(h), bitmap, [0xAB; 32]).expect("short")
}

/// The count a section test gives a reference: eight bits per bitmap
/// byte. `check_section` takes the count from its caller; this stands in.
fn bits_of(reference: &BundleRef) -> u32 {
    u32::try_from(reference.bitmap_bytes().len() * 8).expect("short")
}

/// References are in strictly ascending `h`, so none repeats. Red edit:
/// `>` for `>=` admits two references to one `h`.
#[test]
fn a_section_out_of_order_or_repeating_an_h_refuses() {
    let a = reference_at(100, &[0x01]);
    let b = reference_at(101, &[0x02]);
    let c = reference_at(250, &[]);
    let root = |refs: &[BundleRef]| bundle_root(refs);
    let check = |refs: &[BundleRef]| check_section(refs, &root(refs), None, bits_of);

    assert_eq!(check(&[]), Ok(()));
    assert_eq!(check(std::slice::from_ref(&a)), Ok(()));
    assert_eq!(check(&[a.clone(), b.clone(), c.clone()]), Ok(()));

    assert_eq!(
        check(&[a.clone(), a.clone()]),
        Err(SectionRefused::OutOfOrder { position: 1 }),
        "one h twice"
    );
    // Two different bundles for one `h` are still one `h` twice.
    let a_other = reference_at(100, &[0x03]);
    assert_eq!(
        check(&[a.clone(), a_other]),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    assert_eq!(
        check(&[b.clone(), a.clone(), c.clone()]),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    assert_eq!(
        check(&[a, c, b]),
        Err(SectionRefused::OutOfOrder { position: 2 })
    );
}

/// The header root recomputes from the references. Red edit: skip the
/// comparison; or compare against the root of the references sorted.
#[test]
fn a_section_whose_root_does_not_recompute_refuses() {
    let a = reference_at(100, &[0x01]);
    let b = reference_at(101, &[0x02]);
    let refs = [a.clone(), b.clone()];
    let root = bundle_root(&refs);
    assert_eq!(check_section(&refs, &root, None, bits_of), Ok(()));

    let mut wrong = root;
    wrong[5] ^= 1;
    assert_eq!(
        check_section(&refs, &wrong, None, bits_of),
        Err(SectionRefused::Root)
    );
    // The root of a section that omits a reference, or adds one.
    assert_eq!(
        check_section(&refs, &bundle_root(std::slice::from_ref(&a)), None, bits_of),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section(std::slice::from_ref(&a), &root, None, bits_of),
        Err(SectionRefused::Root)
    );
    // One field of one reference: a different prunable hash.
    let b_other = BundleRef::new(*b.seed(), b.h(), b.bitmap_bytes(), [0xAC; 32]).expect("short");
    assert_eq!(
        check_section(&[a, b_other], &root, None, bits_of),
        Err(SectionRefused::Root)
    );
    // An empty section commits the empty root, and no other.
    assert_eq!(check_section(&[], &bundle_root(&[]), None, bits_of), Ok(()));
    assert_eq!(
        check_section(&[], &[0; 32], None, bits_of),
        Err(SectionRefused::Root)
    );
}

/// Red edit 3 of the specification's §11: **a budget sum one over.** The
/// counts of a section sum to at most `c · (⌊9·D / SEB⌋ + 1)`: exactly at
/// the budget admits, one over refuses — at the count cap of a large `D`,
/// and at a `D` so small that `⌊9·D / SEB⌋` is zero and the budget is the
/// `+ 1` alone (`SCS-P33`). Red edits: `>=` for `>` refuses a section at
/// its budget; drop the `+ 1` and the small network's budget is zero.
#[test]
fn a_section_at_its_budget_admits_and_one_over_refuses() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let c = BUNDLE_SECTION_BUDGET_MULTIPLE;
    let section = |counts: &[u32]| -> (Vec<BundleRef>, Vec<u32>) {
        let refs: Vec<BundleRef> = counts
            .iter()
            .enumerate()
            .map(|(n, count)| {
                reference_at(100 + n as u64, &vec![0u8; PassBitmap::byte_len(*count)])
            })
            .collect();
        (refs, counts.to_vec())
    };
    let check = |counts: &[u32], budget: u64| {
        let (refs, counts) = section(counts);
        let count_of =
            |r: &BundleRef| counts[usize::try_from(r.h().to_raw() - 100).expect("a short section")];
        check_section(&refs, &bundle_root(&refs), Some(budget), count_of)
    };

    // `D` = 8: `⌊72 / 10,000⌋` is zero, the count cap is 1, the budget 2.
    let small = section_budget(c, 8, seb);
    assert_eq!(small, 2);
    assert_eq!(check(&[1, 1], small), Ok(()));
    assert_eq!(check(&[2], small), Ok(()));
    assert_eq!(
        check(&[0, 1, 0, 1, 0], small),
        Ok(()),
        "empty bundles are free"
    );
    assert_eq!(
        check(&[1, 2], small),
        Err(SectionRefused::OverBudget {
            draws: 3,
            budget: 2
        })
    );
    assert_eq!(
        check(&[1, 1, 1], small),
        Err(SectionRefused::OverBudget {
            draws: 3,
            budget: 2
        })
    );

    // `D` = 324,000: the count cap is 292 and the budget two of them.
    let large = section_budget(c, 324_000, seb);
    assert_eq!(large, 584);
    assert_eq!(check(&[292, 292], large), Ok(()));
    assert_eq!(check(&[100, 192, 292], large), Ok(()));
    assert_eq!(
        check(&[292, 293], large),
        Err(SectionRefused::OverBudget {
            draws: 585,
            budget: 584
        })
    );
}

/// With no budget the counts are not asked: `D` is not known where an
/// alternative block arrives above the fork point, and the budget waits
/// for the switch (`SCS-P23`). Red edit: sum unconditionally — the
/// closure here panics.
#[test]
fn a_section_with_no_budget_asks_for_no_count() {
    let refs = [
        reference_at(100, &[0xFF; 40]),
        reference_at(101, &[0xFF; 40]),
    ];
    let never = |_: &BundleRef| -> u32 { panic!("no budget, no count") };
    assert_eq!(
        check_section(&refs, &bundle_root(&refs), None, never),
        Ok(())
    );
}

/// The section's checks in §9.1's order: form (order, then root) before
/// budget. Red edit: check the budget first.
#[test]
fn of_two_section_defects_the_earlier_check_refuses() {
    let a = reference_at(100, &[0x01]);
    let b = reference_at(101, &[0x02]);
    let swapped = [b.clone(), a.clone()];
    // Out of order, a wrong root, and over budget at once.
    assert_eq!(
        check_section(&swapped, &[0; 32], Some(0), bits_of),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    // In order, a wrong root, and over budget.
    assert_eq!(
        check_section(&[a.clone(), b.clone()], &[0; 32], Some(0), bits_of),
        Err(SectionRefused::Root)
    );
    let refs = [a, b];
    assert_eq!(
        check_section(&refs, &bundle_root(&refs), Some(15), bits_of),
        Err(SectionRefused::OverBudget {
            draws: 16,
            budget: 15
        })
    );
}

// -------------------------------------------------------- rows and staging

/// Every refusal names its census row, and a record's refusal its draw.
/// Red edit: move an arm to another row in `BundleInvalid::row`.
#[test]
fn every_refusal_names_its_census_row() {
    use BundleInvalid as B;
    assert_eq!(
        SectionRefused::OutOfOrder { position: 1 }.row(),
        CenRow::J29
    );
    assert_eq!(SectionRefused::Root.row(), CenRow::J29);
    assert_eq!(
        SectionRefused::OverBudget {
            draws: 3,
            budget: 2
        }
        .row(),
        CenRow::J30
    );
    let rows: [(B, CenRow, Option<u32>); 11] = [
        (B::OutsideWindow, CenRow::J31, None),
        (B::AlreadyRevealed, CenRow::J31, None),
        (B::UnknownBlock, CenRow::J31, None),
        (B::BodyMalformed, CenRow::J32, None),
        (B::Bitmap, CenRow::J32, None),
        (B::RecordCount, CenRow::J32, None),
        (B::Commitment, CenRow::J33, None),
        (B::WitnessSignature, CenRow::J34, None),
        (B::Attempt { draw: 7 }, CenRow::J35, Some(7)),
        (B::Anchor { draw: 8 }, CenRow::J36, Some(8)),
        (B::Receipt { draw: 9 }, CenRow::J37, Some(9)),
    ];
    for (refusal, row, draw) in rows {
        assert_eq!(refusal.row(), row, "{refusal:?}");
        assert_eq!(refusal.draw(), draw, "{refusal:?}");
        assert!(
            refusal.to_string().starts_with(row.as_str()),
            "{refusal}: the message leads with the row"
        );
    }
}

/// The rows are registered `pending`: in the denominator and bound to no
/// rule type, so no verdict's coverage holds them. Red edit: flip one to `implemented(...)`
/// without wiring it — and this test is then the cutover's to delete,
/// with the next one.
#[test]
fn the_bundle_rows_are_pending_until_the_cutover() {
    use crate::census::RowStatus;
    for row in [
        CenRow::J29,
        CenRow::J30,
        CenRow::J31,
        CenRow::J32,
        CenRow::J33,
        CenRow::J34,
        CenRow::J35,
        CenRow::J36,
        CenRow::J37,
    ] {
        assert_eq!(row.status(), RowStatus::Pending, "{row}");
    }
}

/// **The falsifier of this module's STAGED disposition** (rule 23): no
/// file on the connect path names the bundle verifier. It reads the
/// sources of `form` / `validate`, the block types and every rule, and
/// fails when one of them mentions `verify_bundle`, `check_section`,
/// `open_body` or `BundleView`.
///
/// Bites against the verifier being wired into a block path without the
/// module's banner, the census rows' status and the specification's §2
/// moving with it. Does not cover a caller outside this crate: the store
/// and the ingest driver are other crates, and `SO-D12`'s cutover is where
/// they change. The cutover deletes this test in the change that wires
/// the rule.
#[test]
fn nothing_on_the_connect_path_calls_the_bundle_verifier() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src.join("validate.rs"), src.join("block.rs")];
    for entry in std::fs::read_dir(src.join("rules")).expect("src/rules is a directory") {
        let path = entry.expect("a directory entry").path();
        let is_rule_source = path.extension().is_some_and(|e| e == "rs")
            && !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("_tests.rs"));
        if is_rule_source {
            files.push(path);
        }
    }
    // Rule 47: the subject exists. An empty walk would pass vacuously.
    assert!(files.len() > 15, "the rules tree was not found: {files:?}");
    let validate = std::fs::read_to_string(src.join("validate.rs")).expect("validate.rs");
    assert!(
        validate.contains("pub fn validate"),
        "validate.rs is not where `validate` lives any more; repoint this test"
    );
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a readable source file");
        for name in ["verify_bundle", "check_section", "open_body", "BundleView"] {
            assert!(
                !text.contains(name),
                "{} names `{name}`: the bundle rule is no longer staged. Move the module \
                 banner, the census rows and this test in the same change.",
                file.display()
            );
        }
    }
}
