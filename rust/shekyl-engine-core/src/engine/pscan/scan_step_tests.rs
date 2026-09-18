// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for `pscan/scan_step.rs` — the dual extractor's funding, bond-post,
//! lineage and spent-funding arms.
//!
//! Extracted to a `#[path]` sibling so the engine-decomposition ratchet
//! measures the production module alone; `use super::*` still resolves the
//! module's private items because this file is its child module.

use super::*;

use shekyl_archival_retention::{
    HoldingsDescriptor, HoldingsKind, MembershipOnlyBacking, ShardSet, ShardWorkEntry,
    WorkEpochClaim,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::kem::HybridKemPublicKey;
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_scanner::bench_fixtures::{
    build_typical_case_scannable_block, scannable_block_for_recipient,
};
use shekyl_wire::transaction::{BondPost, BondPostKind};
use shekyl_wire::Holdings;

use crate::engine::pscan::persona_scanner::guaranteed_scanner_for_persona;

const SEED: [u8; MASTER_SEED_BYTES] = [0x07u8; MASTER_SEED_BYTES];

fn persona(slot: u32) -> ArchivalPKeys {
    derive_archival_p_keys(&SEED, DerivationNetwork::Fakechain, SeedFormat::Raw32, slot)
        .expect("derive a test persona")
}

/// The cleartext canonical id the way an on-chain bond-post carries it.
fn canonical_id(p: &ArchivalPKeys) -> PCanonicalId {
    let bytes = p
        .hybrid_bond_id()
        .to_canonical_bytes()
        .expect("hybrid id encodes");
    p_canonical_id_from_hybrid_pubkey(&bytes)
}

/// A block carrying one output addressed to `recipient`.
fn funding_block(recipient: &ArchivalPKeys) -> ScannableBlock {
    let kem = HybridKemPublicKey {
        x25519: recipient.x25519_pk,
        ml_kem: recipient.ml_kem_ek.to_vec(),
    };
    scannable_block_for_recipient(1, &kem, recipient.spend_pk.as_canonical_bytes())
}

/// A JoinMarket bond-post for persona `p`.
fn bond_post_for(p: &ArchivalPKeys) -> BondPost {
    BondPost {
        hybrid_public_key: p.hybrid_bond_id().to_canonical_bytes().expect("encode"),
        p_canonical_id: canonical_id(p),
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: Vec::new(),
            endpoint: [0xEE; 32],
        },
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 1_000,
        bond_credit: 1_000,
        bond_debit: 0,
    }
}

/// A structurally-valid emission vin naming persona `p` as claimant — the
/// §8.0.2 field set with dummy proof/auth bytes (the rung-1 pre-pass
/// parses structure; it does not verify proofs or auths, which is the
/// daemon's C-1 gate). `p_pubkey` is `p`'s real canonical hybrid key so
/// the §6.1 `p_canonical_id` derivation matches the id the bond post
/// published.
fn emission_vin_for(p: &ArchivalPKeys) -> ArchivalRewardEmissionVin {
    ArchivalRewardEmissionVin {
        p_pubkey: p.hybrid_bond_id().to_canonical_bytes().expect("encode"),
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        },
        settlement_epochs: vec![11],
        work_claim: vec![WorkEpochClaim {
            epoch: 11,
            shard_entries: vec![ShardWorkEntry {
                shard_id: 7,
                serve_credit_bit: true,
                scarcity_micro: 850_000,
            }],
        }],
        backing: MembershipOnlyBacking {
            proof: vec![0xEE; 128],
            pseudo_out: [0x22; 32],
            backing_pubkey: vec![0xB2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: vec![1_000_000],
        auth_backing: vec![0xC3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xD4; SINGLE_SIG_CANONICAL_LEN],
    }
}

/// The wire input carrying `p`'s emission vin (canonical blob, leading
/// `0x04` tag included — the shape `shekyl-wire` transports opaquely).
fn emission_input_for(p: &ArchivalPKeys) -> Input {
    Input::ArchivalRewardEmission {
        canonical_bytes: emission_vin_for(p).serialize().expect("serialize"),
    }
}

fn range(start: u64, end: u64) -> BlockRange {
    BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end)).expect("range")
}

#[test]
fn block_range_is_non_empty_by_construction() {
    // The invariant the cover-discovery gate (and the scan loop) rely on: a `BlockRange`
    // always covers at least one block. Empty (`start == end`) and inverted
    // (`start > end`) both fail closed to `None`, so no empty range can ever reach a
    // consumer — there is no empty-window edge to re-guard downstream.
    assert!(
        BlockRange::new(BlockHeight::from_raw(5), BlockHeight::from_raw(5)).is_none(),
        "empty range rejected"
    );
    assert!(
        BlockRange::new(BlockHeight::from_raw(6), BlockHeight::from_raw(5)).is_none(),
        "inverted range rejected"
    );
    let r = BlockRange::new(BlockHeight::from_raw(5), BlockHeight::from_raw(6))
        .expect("single-block range is valid");
    assert_eq!(r.block_count(), 1);
}

#[test]
fn funding_sums_owned_outputs_at_the_range_epoch() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    // Height 20_001 → settlement epoch 2 (SETTLEMENT_EPOCH_BLOCKS = 10_000).
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        &[funding_block(&p)],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    assert_eq!(res.funding.len(), 1, "one epoch touched");
    assert_eq!(res.funding[0].epoch, SettlementEpoch::from_raw(2));
    assert!(
        res.funding[0].amount > AtomicUnits::ZERO,
        "the persona's own output was summed into the epoch delta"
    );
    assert!(res.bond_post_matches.is_empty());
}

/// [`funding_block`] with one byte of the `0x07` entry's record half
/// flipped; the KEM ciphertexts and tx pubkey are reused so the output
/// still recovers — received but unspendable (PL-D3 §6.2).
fn tampered_funding_block(p: &ArchivalPKeys) -> ScannableBlock {
    use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
    use shekyl_scanner::extra::Extra;

    let mut block = funding_block(p);
    {
        let tx = &mut block.transactions[0];
        let extra = Extra::read(&mut tx.prefix.extra.as_slice()).expect("fixture extra");
        let (keys, _) = extra.keys().expect("fixture tx pubkey");
        let kem_cts: Vec<Vec<u8>> = extra
            .pqc_kem_ciphertext()
            .expect("fixture 0x06")
            .chunks(HYBRID_KEM_CT_LEN)
            .map(<[u8]>::to_vec)
            .collect();
        let mut leaf_blob = extra.pqc_leaf_entries().expect("fixture 0x07").to_vec();
        leaf_blob[63] ^= 0x01;
        let mut tampered = Extra::for_hybrid_transfer(keys[0], kem_cts);
        tampered.push_pqc_leaf_entries(leaf_blob);
        tx.prefix.extra = tampered.serialize();
    }
    block
}

/// PL-D3 §6.2 on the persona path: an owned output whose published `0x07`
/// entry does not open to the persona's derivation is received but
/// unspendable — it contributes neither an epoch delta nor a funding
/// record.
#[test]
fn unspendable_persona_output_is_not_funding() {
    let p = persona(0);
    let block = tampered_funding_block(&p);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;
    assert!(
        res.funding.is_empty(),
        "an unspendable output is not funding"
    );
    assert!(
        res.funding_outputs.is_empty(),
        "an unspendable output leaves no funding record"
    );
}

/// D-A1 / rule-82 reconciliation pin (the log-channel sibling of
/// [`funding_output_match_debug_is_redacted`]): the unspendable-output warn
/// must stay **loud** — deleting it would go unnoticed by the redaction
/// half alone — while carrying **no** persona- or tx-identifying field. Any
/// sender can mint an output that trips the branch against a suspected
/// persona, so a warn naming the slot or transaction would hand the log
/// channel the persona↔funding-tx association D-A1 redacts everywhere else;
/// the wallet ledger row carries those specifics instead.
#[test]
fn unspendable_warn_is_loud_but_names_no_persona_or_tx() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// Shared in-memory sink for the fmt subscriber.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let p = persona(0);
    let block = tampered_funding_block(&p);
    // The identifiers the warn must NOT carry: every tx hash the block
    // holds (computed from the fixture, not pattern-matched generically).
    let mut forbidden_hashes: Vec<String> = block
        .block
        .transaction_hashes
        .iter()
        .map(hex::encode)
        .collect();
    forbidden_hashes.extend(block.transactions.iter().map(|tx| hex::encode(tx.hash())));
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");

    let sink = SharedBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        // Two passes, because tracing caches per-callsite interest globally
        // and computes it on the thread that hits a callsite FIRST
        // (`Rebuilder::JustOne` → `dispatcher::get_default`, tracing-core
        // 0.1.36): the sibling test drives the same `warn!` with no
        // subscriber, and when it wins that race the callsite is cached
        // `Interest::never` — sticky, so the event is skipped before
        // dispatch and this capture stays empty. The first pass guarantees
        // the callsite is registered no matter who won; the rebuild then
        // recomputes its interest from THIS thread, whose default is the
        // capturing subscriber; the second pass is therefore delivered
        // deterministically.
        let first = run_dual_extractor(
            vec![(0, guaranteed_scanner_for_persona(&p).expect("scanner"))],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[tampered_funding_block(&p)],
            &KeyImageWatchSet::new(),
        )
        .expect("extract")
        .result;
        assert!(first.funding.is_empty(), "the output was quarantined");
        tracing::callsite::rebuild_interest_cache();
        let res = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[block],
            &KeyImageWatchSet::new(),
        )
        .expect("extract")
        .result;
        assert!(res.funding.is_empty(), "the output was quarantined");
    });

    let text = String::from_utf8(sink.0.lock().expect("buffer lock").clone())
        .expect("fmt output is UTF-8");
    // (1) Loud: the warn fired.
    assert!(
        text.contains("failed the PL-D3 leaf-commitment check"),
        "the quarantine warn must fire; captured log: {text:?}"
    );
    // (2) Redacted: neither the slot field nor any of the block's tx hashes.
    assert!(
        !text.contains("p_slot"),
        "the warn must not name the persona slot; captured log: {text:?}"
    );
    for hash in &forbidden_hashes {
        assert!(
            !text.contains(hash.as_str()),
            "the warn must not name a transaction hash; captured log: {text:?}"
        );
    }
}

/// D-A1 consistency gate (WI-2): the per-output funding records and the
/// per-epoch deltas are two views of the same recovered set — the records'
/// per-epoch amount sums must equal the deltas exactly, and each record
/// carries the tagging slot plus a complete public identity.
#[test]
fn funding_records_sum_to_the_epoch_deltas_and_carry_the_slot_tag() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(7, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        &[funding_block(&p)],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    assert!(
        !res.funding_outputs.is_empty(),
        "the recovered output produced a per-output record"
    );
    // sum(records) per epoch == the epoch delta, exactly.
    let mut by_epoch: BTreeMap<SettlementEpoch, AtomicUnits> = BTreeMap::new();
    for rec in &res.funding_outputs {
        let acc = by_epoch.entry(rec.epoch).or_insert(AtomicUnits::ZERO);
        *acc = acc.checked_add(rec.amount).expect("no overflow in test");
    }
    assert_eq!(by_epoch.len(), res.funding.len());
    for delta in &res.funding {
        assert_eq!(by_epoch.get(&delta.epoch), Some(&delta.amount));
    }
    for rec in &res.funding_outputs {
        assert_eq!(
            rec.p_slot,
            shekyl_types::PSlot::from_raw(7),
            "record carries the scanner's slot tag"
        );
        assert_eq!(rec.height, BlockHeight::from_raw(20_001));
        assert_ne!(rec.output_key, [0u8; 32], "output key populated");
        assert_ne!(rec.commitment, [0u8; 32], "commitment populated");
        assert!(
            !rec.ciphertext_ml_kem.is_empty(),
            "hybrid ciphertext ML-KEM half preserved for re-derivation"
        );
    }
}

/// D-A1 redaction gate: a funding record is a row of `P`'s funding history —
/// its `Debug` must render the constant placeholder, never fields.
#[test]
fn funding_output_match_debug_is_redacted() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        &[funding_block(&p)],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;
    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        format!("{rec:?}"),
        "FundingOutputMatch(<redacted funding-history>)"
    );
}

#[test]
fn bond_post_matches_only_known_canonical_ids() {
    let mine = persona(0);
    let other = persona(1);

    // A foreign block (no outputs we own) carrying two bond-posts: ours + a
    // stranger's. Adding inputs to an existing tx keeps its Ct valid.
    let mut block = build_typical_case_scannable_block(1);
    let tx = block.transactions.get_mut(0).expect("a non-miner tx");
    tx.prefix
        .inputs
        .push(Input::BondPost(Box::new(bond_post_for(&mine))));
    tx.prefix
        .inputs
        .push(Input::BondPost(Box::new(bond_post_for(&other))));

    let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&mine), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    assert_eq!(
        res.bond_post_matches.len(),
        1,
        "only our canonical id matches; the stranger's post is ignored"
    );
    assert_eq!(res.bond_post_matches[0].p_canonical_id, canonical_id(&mine));
    assert_eq!(res.bond_post_matches[0].height, BlockHeight::from_raw(5));
    assert_eq!(res.bond_post_matches[0].post_kind, 0, "JoinMarket tag");
    assert!(
        res.funding.is_empty(),
        "no outputs we own in a foreign block"
    );
}

/// The Release-detection seam (2d-1 DQ8): the extractor carries the wire kind
/// byte unchanged, and that byte equals the consensus `Release` discriminant the
/// task's `record_releases` matches on. Pins the cross-crate byte equivalence
/// (`shekyl-wire` `Other(b)` ↔ `archival_retention::BondPostKind::Release`)
/// end-to-end so it cannot drift before the wire format freezes — the seam was
/// otherwise only covered by tests that hand-set `post_kind`.
#[test]
fn extractor_carries_the_consensus_release_byte() {
    let release_byte = shekyl_archival_retention::BondPostKind::Release as u8;
    assert_eq!(release_byte, 2, "genesis-frozen Release discriminant");

    let mine = persona(0);
    let mut block = build_typical_case_scannable_block(1);
    let tx = block.transactions.get_mut(0).expect("a non-miner tx");
    // A Release bond-post: the consensus Release byte on the wire as `Other(b)`
    // (genesis wire is JoinMarket-only, so this models the post-genesis form).
    let mut post = bond_post_for(&mine);
    post.kind = BondPostKind::Other(release_byte);
    tx.prefix.inputs.push(Input::BondPost(Box::new(post)));

    let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&mine), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    assert_eq!(res.bond_post_matches.len(), 1);
    assert_eq!(
        res.bond_post_matches[0].post_kind, release_byte,
        "the extractor carries the wire kind byte unchanged through to record_releases"
    );
}

#[test]
fn dual_extracts_funding_and_bond_post_in_one_block() {
    let p = persona(0);
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::BondPost(Box::new(bond_post_for(&p))));

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(7, 8),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    assert_eq!(res.funding.len(), 1, "funding recovered");
    assert_eq!(res.bond_post_matches.len(), 1, "bond-post matched");
}

#[test]
fn rejects_a_range_block_count_mismatch() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    // Range covers 3 blocks; only 1 supplied.
    let err = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(0, 3),
        &[funding_block(&p)],
        &KeyImageWatchSet::new(),
    )
    .expect_err("mismatch must fail closed");
    assert!(matches!(
        err,
        DualExtractError::RangeBlockMismatch {
            range_block_count: 3,
            blocks: 1
        }
    ));
}

#[test]
fn rejects_a_step_over_the_dq6_bound() {
    // A range past the bound fails closed before any block work — the guard is
    // on the range size, so no oversized block vec is needed to exercise it.
    let err = run_dual_extractor(
        Vec::new(),
        &BTreeMap::new(),
        range(0, MAX_SCAN_STEP_BLOCKS + 1),
        &[],
        &KeyImageWatchSet::new(),
    )
    .expect_err("an oversized step must fail closed");
    assert!(matches!(
        err,
        DualExtractError::StepTooLarge { block_count, max }
            if block_count == MAX_SCAN_STEP_BLOCKS + 1 && max == MAX_SCAN_STEP_BLOCKS
    ));
}

// ---- GF-4b lineage-classification KATs (§3.3 / §4 item 1) ----

/// Rung 2: the carrying tx bears the recovered output's **own** persona's
/// `BondPost`, so the output classifies `BondPostChange`.
#[test]
fn lineage_bond_post_change_for_own_bond_post_tx() {
    let p = persona(0);
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::BondPost(Box::new(bond_post_for(&p))));

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(rec.lineage, MintLineageOutput::BondPostChange);
}

/// Fail-toward-the-forbidden-rung: a plain transfer (no `BondPost` at
/// all) classifies `ExternalTransfer` — rung 3, never backing-eligible.
#[test]
fn lineage_fails_toward_forbidden_for_plain_transfer() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(5, 6),
        &[funding_block(&p)],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(rec.lineage, MintLineageOutput::ExternalTransfer);
}

/// Owning-persona attribution (§3.3): a `BondPost` from a *different*
/// held persona in the carrying tx does **not** lift this persona's
/// output off rung 3 — the structural proof must be the owner's own
/// bond post, not any bond post we recognize.
#[test]
fn lineage_fails_toward_forbidden_for_another_personas_bond_post() {
    let mine = persona(0);
    let other = persona(1);
    let mut block = funding_block(&mine);
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::BondPost(Box::new(bond_post_for(&other))));

    let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&mine), 0), (canonical_id(&other), 1)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.lineage,
        MintLineageOutput::ExternalTransfer,
        "another persona's bond post is not a structural proof for this output"
    );
}

// ---- GF-4b rung-1 (`EmissionReward`) KATs (C-1, §5 item 2) ----
//
// Paired positive/negative coverage for the fail-toward-forbidden
// acceptance criterion (GF4b-4): the own-vin case lifts to rung 1, and
// *each* non-own case — foreign claimant, another held persona's vin, an
// unparseable blob, a non-canonical (trailing-bytes) blob, a different tx
// in the same block, a missing tx hash — stays rung 3. The dangerous
// failure is a classifier that lifts a non-own case, and only the
// negative arms catch it.

/// Rung 1 positive: the carrying tx bears the recovered output's **own**
/// persona's emission vin, so the output classifies `EmissionReward` —
/// the reserved variant's first constructor site.
#[test]
fn lineage_emission_reward_for_own_emission_vin_tx() {
    let p = persona(0);
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(emission_input_for(&p));

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(rec.lineage, MintLineageOutput::EmissionReward);
}

/// Fail-toward-forbidden: a **foreign** emission vin (claimant not among
/// our personas at all) in the carrying tx does not lift our output —
/// it proves someone else's claim, never ours.
#[test]
fn lineage_fails_toward_forbidden_for_foreign_emission_vin() {
    let mine = persona(0);
    let stranger = persona(2);
    let mut block = funding_block(&mine);
    block.transactions[0]
        .prefix
        .inputs
        .push(emission_input_for(&stranger));

    let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&mine), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.lineage,
        MintLineageOutput::ExternalTransfer,
        "a stranger's emission vin is not a structural proof for this output"
    );
}

/// Owning-persona attribution (same rule as the bond-post arm): an
/// emission vin of a *different* held persona in the carrying tx does
/// **not** lift this persona's output off rung 3 — the structural proof
/// must be the owner's own vin, not any vin we recognize.
#[test]
fn lineage_fails_toward_forbidden_for_another_personas_emission_vin() {
    let mine = persona(0);
    let other = persona(1);
    let mut block = funding_block(&mine);
    block.transactions[0]
        .prefix
        .inputs
        .push(emission_input_for(&other));

    let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&mine), 0), (canonical_id(&other), 1)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.lineage,
        MintLineageOutput::ExternalTransfer,
        "another persona's emission vin is not a structural proof for this output"
    );
}

/// Fail-toward-forbidden on parse failure, premise-asserted: the *same*
/// own-vin blob classifies rung 1 intact (premise — so the corruption is
/// the only variable), and truncated it classifies rung 3. A pre-pass
/// that "recovered" a claimant id from a blob the validator-crate reader
/// rejects would fail this arm.
#[test]
fn lineage_fails_toward_forbidden_for_unparseable_emission_blob() {
    let p = persona(0);
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let intact = emission_vin_for(&p).serialize().expect("serialize");

    // Premise: the intact blob lifts to rung 1.
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::ArchivalRewardEmission {
            canonical_bytes: intact.clone(),
        });
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;
    assert_eq!(
        res.funding_outputs.first().expect("one record").lineage,
        MintLineageOutput::EmissionReward,
        "premise: the uncorrupted blob must lift to rung 1, so truncation \
         is the only variable in the negative arm"
    );

    // Negative: the truncated blob fails the parse and stays rung 3.
    let mut truncated = intact;
    truncated.truncate(truncated.len() - 1);
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::ArchivalRewardEmission {
            canonical_bytes: truncated,
        });
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;
    assert_eq!(
        res.funding_outputs.first().expect("one record").lineage,
        MintLineageOutput::ExternalTransfer,
        "an unparseable emission blob is not a structural proof"
    );
}

/// Fail-toward-forbidden on a non-canonical blob: trailing bytes after a
/// successful field parse stay rung 3. This is the arm the plain reader
/// would miss (`ArchivalRewardEmissionVin::read` stops at the last
/// field); it proves the pre-pass's exact-parse discipline is armed.
#[test]
fn lineage_fails_toward_forbidden_for_trailing_bytes_in_emission_blob() {
    let p = persona(0);
    let mut padded = emission_vin_for(&p).serialize().expect("serialize");
    padded.push(0x00);
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::ArchivalRewardEmission {
            canonical_bytes: padded,
        });

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.lineage,
        MintLineageOutput::ExternalTransfer,
        "a trailing-bytes blob is not the canonical vin encoding"
    );
}

/// Per-tx keying: our own emission vin in a *different* tx of the same
/// block does not lift an output of this tx — the structural proof is
/// "the carrying tx bears the vin", never "the block contains one".
#[test]
fn lineage_fails_toward_forbidden_for_emission_vin_in_a_different_tx() {
    let p = persona(0);
    // Tx 0 carries our funding output; a second, foreign tx carries our
    // emission vin. Appending keeps tx 0's outputs and gindexes intact.
    let mut block = funding_block(&p);
    let mut emission_tx = build_typical_case_scannable_block(1)
        .transactions
        .first()
        .expect("a non-miner tx")
        .clone();
    emission_tx.prefix.inputs.push(emission_input_for(&p));
    let emission_tx_hash = emission_tx.hash();
    block.transactions.push(emission_tx);
    block.block.transaction_hashes.push(emission_tx_hash);

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(5, 6),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.lineage,
        MintLineageOutput::ExternalTransfer,
        "an emission vin elsewhere in the block is not a structural proof \
         for this tx's outputs"
    );
}

/// The missing-tx-hash arm, at the classifier seam: a tx whose hash is
/// absent from `transaction_hashes` cannot be keyed, so its outputs
/// classify rung 3. Tested at the helper because the end-to-end path is
/// doubly guarded upstream — the scanner refuses a mispaired block
/// outright (`ScanError::InvalidScannableBlock`) and
/// `run_dual_extractor`'s debug tripwire fires in test builds — leaving
/// this arm as the innermost, release-mode defense.
#[test]
fn emission_classifier_missing_tx_hash_yields_no_lift() {
    let p = persona(0);
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let mut tx = funding_block(&p).transactions.remove(0);
    tx.prefix.inputs.push(emission_input_for(&p));

    // Premise: with its hash present, the tx classifies to our slot —
    // and the memoized second query agrees (the lazy path's cache arm).
    let hash = tx.hash();
    let txs = std::slice::from_ref(&tx);
    let hashes = [hash];
    let mut slots = OwnEmissionSlots::new(txs, &hashes, &known);
    assert!(
        slots.contains(hash, 0),
        "premise: the hash-paired tx classifies, so the missing hash is \
         the only variable in the negative arm"
    );
    assert!(slots.contains(hash, 0), "memoized re-query agrees");

    // Negative: no hash, no classification — nothing to lift.
    let mut slots = OwnEmissionSlots::new(txs, &[], &known);
    assert!(
        !slots.contains(hash, 0),
        "a hash-less tx must not classify (fail toward rung 3)"
    );
}

// ---- GF4b-6 spendable-height KATs (§3.6 / §4 item 1) ----

/// A plain transfer's `spendable_height` is the shared X5 computation's
/// baseline — `height + SPENDABLE_AGE` — pinned against the *shared
/// function itself* so the seam cannot drift to a local formula.
#[test]
fn spendable_height_plain_transfer_is_the_shared_baseline() {
    use shekyl_engine_state::transfer::SPENDABLE_AGE;

    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        &[funding_block(&p)],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.spendable_height,
        BlockHeight::from_raw(20_001) + SPENDABLE_AGE
    );
    assert_eq!(
        rec.spendable_height,
        eligible_height(BlockHeight::from_raw(20_001), shekyl_types::Timelock::None),
        "the seam stores literally the shared eligible_height result"
    );
}

/// A coinbase-shaped recovery (`unlock_time = height + 60`, the
/// consensus-enforced coinbase shape) floors `spendable_height` at the
/// timelock — the channel through which coinbase maturity reaches the
/// sweep filter (no miner-tx arm exists).
#[test]
fn spendable_height_coinbase_shaped_timelock_floors() {
    let p = persona(0);
    let mut block = funding_block(&p);
    block.transactions[0].prefix.unlock_time = 20_001 + 60;

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let rec = res.funding_outputs.first().expect("one record");
    assert_eq!(
        rec.spendable_height,
        BlockHeight::from_raw(20_061),
        "coinbase-shaped timelock floors above the +SPENDABLE_AGE baseline"
    );
}

/// Both new fields survive the rule-18 transform↔state seam round-trip
/// (the `From` impls are exhaustive struct literals; this pins the
/// values, not just the compile).
#[test]
fn lineage_and_spendable_height_round_trip_the_state_seam() {
    let p = persona(0);
    let mut block = funding_block(&p);
    block.transactions[0].prefix.unlock_time = 20_001 + 60;
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::BondPost(Box::new(bond_post_for(&p))));

    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let known = BTreeMap::from([(canonical_id(&p), 0)]);
    let res = run_dual_extractor(
        vec![(0, scanner)],
        &known,
        range(20_001, 20_002),
        &[block],
        &KeyImageWatchSet::new(),
    )
    .expect("extract")
    .result;

    let m = res.funding_outputs.first().expect("one record");
    let persisted = PFundingOutputRecord::from(m);
    assert_eq!(persisted.lineage, MintLineageOutput::BondPostChange);
    assert_eq!(persisted.spendable_height, BlockHeight::from_raw(20_061));
    let back = FundingOutputMatch::from(&persisted);
    assert_eq!(&back, m, "state→transform restores the exact match");
}

/// Arm (c): a `ToKey` input whose key image is in the watch-set yields a
/// spent match carrying the watched gindex and the spend height; an
/// unwatched key image yields nothing.
#[test]
fn arm_c_matches_watched_key_images_only() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let ki = [0xABu8; 32];
    let mut block = funding_block(&p);
    block.transactions[0]
        .prefix
        .inputs
        .push(shekyl_wire::transaction::Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: ki,
        });
    let gindex = shekyl_types::GlobalOutputIndex::from_raw(42);
    let mut watch = KeyImageWatchSet::new();
    watch.insert(ki, gindex);
    let out = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        std::slice::from_ref(&block),
        &watch,
    )
    .expect("extract");
    assert_eq!(out.result.spent_funding.len(), 1, "watched spend matches");
    assert_eq!(out.result.spent_funding[0].gindex, gindex);

    // Same block, empty watch: no match, and — because the block also
    // discovers a funding output at the same height — no trailing entry
    // either (same-height create-and-spend is impossible; inputs are
    // processed before the block's outputs are discovered).
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let out = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_002),
        std::slice::from_ref(&block),
        &KeyImageWatchSet::new(),
    )
    .expect("extract");
    assert!(
        out.result.spent_funding.is_empty(),
        "unwatched spend ignored"
    );
    assert!(
        out.trailing_key_images.is_empty(),
        "no trailing entries at or before the first discovery height"
    );
}

/// Arm (c): spends observed at heights after an in-step discovery are
/// collected as trailing key images (regardless of watch membership) —
/// the handler's material for closing the in-step blind spot.
#[test]
fn trailing_key_images_collect_after_an_in_step_discovery() {
    let p = persona(0);
    let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
    let ki = [0xCDu8; 32];
    // A distinctive spend AT the discovery height — the window-bound
    // probe: it must not be collected (collection starts strictly after
    // the first discovery's height).
    let ki_at_discovery = [0xABu8; 32];
    let mut discovery = funding_block(&p);
    discovery.transactions[0]
        .prefix
        .inputs
        .push(shekyl_wire::transaction::Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: ki_at_discovery,
        });
    let mut later = funding_block(&persona(9)); // not ours — filler carrier
    later.transactions[0]
        .prefix
        .inputs
        .push(shekyl_wire::transaction::Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: ki,
        });
    let out = run_dual_extractor(
        vec![(0, scanner)],
        &BTreeMap::new(),
        range(20_001, 20_003),
        &[discovery, later],
        &KeyImageWatchSet::new(),
    )
    .expect("extract");
    assert_eq!(out.result.funding_outputs.len(), 1, "one discovery");
    // The guarantee is containment (the injected post-discovery spend is
    // collected) plus the window bound (the injected at-discovery-height
    // spend is not).
    assert!(
        out.trailing_key_images.contains(&ki),
        "the post-discovery spend is collected for the handler's pass"
    );
    assert!(
        !out.trailing_key_images.contains(&ki_at_discovery),
        "trailing collection starts strictly after the discovery height"
    );
}

/// DQ-A structural-containment tripwire (self-parsing, the
/// `SpentRecordsDurablyPruned` idiom): the watch-set must never gain a
/// `Serialize`/`Deserialize` impl or derive — it is a correlated
/// fingerprint of `P`'s live UTXO and must be unable to persist or cross
/// a wire. The redacting `Debug` must stay hand-written.
///
/// Fail-closed grep, not a needle list: rather than enumerating serde
/// impl spellings (which a path-qualified `impl ::serde::Serialize`, an
/// aliased `use ... as S; impl S`, or a `Deserialize` form would slip
/// past), every trait-impl coupling to the type name must be on the
/// allowlist below, and every attribute in the contiguous block above the
/// struct (not just the last `#[derive]` line — a stacked second derive
/// attribute is still an attribute here) is checked. Scope: this file —
/// which is where the field lives, so any impl needing the map is here or
/// doesn't compile.
#[test]
fn watch_set_has_no_serialize_impl() {
    let src = include_str!("scan_step.rs");
    // Needles are assembled at runtime so this test's own source cannot
    // false-positive the grep.
    let ty = "KeyImageWatchSet";
    let coupling = format!("for {ty}");
    let allowed = [
        format!("impl std::fmt::Debug for {ty}"),
        format!("impl Clone for {ty}"), // documented rule-35 snapshot exception
    ];
    for (idx, _) in src.match_indices(&coupling) {
        let line_start = src[..idx].rfind('\n').map_or(0, |p| p + 1);
        let line = src[line_start..].lines().next().unwrap_or("");
        assert!(
            allowed.iter().any(|a| line.contains(a)),
            "unlisted trait impl coupled to {ty} (DQ-A allowlist): {line}"
        );
    }
    // Every attribute of the contiguous doc/attribute block directly
    // above the struct declaration — a second stacked `#[derive]` (or a
    // `#[serde(...)]`) evades a last-derive-line check but not this one.
    let decl = format!("pub(crate) struct {ty}");
    let prefix = &src[..src.find(&decl).expect("struct decl present")];
    let attr_block: Vec<&str> = prefix
        .lines()
        .rev()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("#[") || t.starts_with("///") || t.starts_with("//")
        })
        .filter(|l| l.trim_start().starts_with("#["))
        .collect();
    for attr in &attr_block {
        assert!(
            !attr.contains("Serialize") && !attr.contains("Deserialize") && !attr.contains("serde"),
            "KeyImageWatchSet's attributes must never include serde (DQ-A): {attr}"
        );
        assert!(
            !attr.contains("Debug"),
            "KeyImageWatchSet must never derive Debug (the redaction would be lost): {attr}"
        );
        assert!(
            !attr.contains("Clone"),
            "KeyImageWatchSet must never derive Clone — the rule-35 exception is the \
             documented hand-written impl: {attr}"
        );
    }
    // The wipe-on-drop leg of the containment (rule 35) stays structural
    // too: removing the zeroizing derive must trip, not slip by review.
    assert!(
        attr_block.iter().any(|a| a.contains("ZeroizeOnDrop")),
        "KeyImageWatchSet must keep its structural wipe-on-drop (rule 35 / DQ-A)"
    );
    // The Debug impl must stay hand-written-and-redacting. Assert the
    // invariants (a manual impl exists; it emits the redaction constant),
    // not the exact formatting — rustfmt churn must not fail a live
    // tripwire.
    assert!(
        src.contains(&format!("impl std::fmt::Debug for {ty}")),
        "KeyImageWatchSet's Debug must stay a hand-written impl"
    );
    assert!(
        src.contains("KeyImageWatchSet(<redacted live-utxo-fingerprint>)"),
        "KeyImageWatchSet's Debug must emit the redaction constant"
    );
}
