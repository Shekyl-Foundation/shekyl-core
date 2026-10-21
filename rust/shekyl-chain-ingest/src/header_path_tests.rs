// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header path agrees with `validate` (CS-1).
//!
//! A header is judged by the validator's own header rules, from the header
//! alone, and the verdict is the one `validate` would give that header.
//! Coinbase rows are not on the header path. A body binds with the row
//! `validate` would name.

#![cfg(test)]

use std::io::Cursor;
use std::num::NonZeroU128;

use shekyl_chain_rules::harness::fixture::{coinbase_extra, TWO_G};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{
    bind_body, form, form_header, judge_header, judge_header_cheap, seed_height, target_claim,
    validate, AtHeight, Candidate, CenRow, ChainView, Fault, FormAttempt, HeaderView, OpenHeader,
    ProspectFault, ReferenceClaims, ReleaseAnchors, RuleSet, Stale, Target, Trust,
};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{StoreError, WriteBatch};
use shekyl_difficulty::{CumulativeDifficulty, FTL_SECONDS};
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::transaction::Input;
use shekyl_wire::{BlockBody, PowBlob, SkeletonTx, TxBody};

use crate::corpus::CorpusReader;
use crate::source::{IngestEvent, Source};
use crate::test_support::{cleanup, open_store_under, tmp};
use crate::vectors_tests::replay::rules_for;
use crate::vectors_tests::{captured_chains, mock_with_the_real_clock, UntilRetiredJoin};

/// What a path concluded. A stale claim is the world having moved, not a row.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Said {
    Accepted(CumulativeDifficulty),
    Refused(CenRow),
    StaleSeed,
    StaleTarget,
}

fn load(dir: &std::path::Path, shape: &str) -> Vec<Candidate> {
    let bytes = std::fs::read(dir.join("corpus.e2")).expect("read corpus");
    let mut reader = UntilRetiredJoin::new(
        CorpusReader::open(Cursor::new(bytes.as_slice())).expect("open corpus"),
    );
    let mut blocks = Vec::new();
    while let Some(sequenced) = reader.next().expect("corpus reads") {
        if let IngestEvent::Extend(candidate) = sequenced.event {
            blocks.push(*candidate);
        }
    }
    reader.finish(shape);
    assert!(!blocks.is_empty(), "{shape}: the corpus has no blocks");
    blocks
}

fn seed_of<'id, V: HeaderView<'id>>(view: &V, height: BlockHeight) -> BlockHash
where
    V::Fault: std::fmt::Debug,
{
    match seed_height(height) {
        None => BlockHash::NULL,
        Some(at) => match view.header_at(at).expect("the seed read") {
            AtHeight::Recorded(record) => record.hash,
            AtHeight::AboveTip => panic!("seed height {at} is above the tip"),
        },
    }
}

fn target_of<'id, V: HeaderView<'id>>(view: &V, height: BlockHeight, rule_set: &RuleSet) -> Target
where
    V::Fault: std::fmt::Debug,
{
    match target_claim(view, height, rule_set).expect("the target read") {
        Ok(target) => target,
        Err(refused) => panic!("the target claim was refused: {refused:?}"),
    }
}

fn connecting<'id, V: HeaderView<'id>>(view: &V) -> BlockHeight
where
    V::Fault: std::fmt::Debug,
{
    match view.tip().expect("the tip") {
        None => BlockHeight::ZERO,
        Some(tip) => tip
            .height
            .checked_add(BlockCount::ONE)
            .expect("the chain has a next height"),
    }
}

fn stale<E: std::fmt::Debug>(fault: &Fault<E>) -> Said {
    match fault {
        Fault::Stale(Stale::Seed { .. }) => Said::StaleSeed,
        Fault::Stale(Stale::Target { .. }) => Said::StaleTarget,
        other => panic!("not a stale claim: {other:?}"),
    }
}

fn header_said<'id, V: HeaderView<'id>>(
    candidate: &Candidate,
    view: &V,
    rule_set: &RuleSet,
    trust: &Trust,
    substrate: &MockSubstrate,
    seed: BlockHash,
    target: Target,
) -> Said
where
    V::Fault: std::fmt::Debug,
{
    let pow = PowBlob::read(&candidate.block.pow_blob()).expect("the preimage parses");
    match form_header(&pow, rule_set, substrate, seed, target).expect("the mock answers") {
        Err(refused) => Said::Refused(refused.rule),
        Ok(formed) => match judge_header(&formed, view, rule_set, trust) {
            Err(fault) => stale(&fault),
            Ok(Err(refused)) => Said::Refused(refused.rule),
            Ok(Ok(judged)) => Said::Accepted(judged.cumulative_difficulty),
        },
    }
}

fn validate_said<'id, V: ChainView<'id, Fault = StoreError>>(
    candidate: Candidate,
    view: &V,
    rule_set: &RuleSet,
    trust: &Trust,
    substrate: &MockSubstrate,
    seed: BlockHash,
    target: Target,
) -> Said {
    let references =
        ReferenceClaims::from_headers(view, connecting(view), &candidate).expect("references");
    match form(
        candidate,
        rule_set,
        substrate,
        seed,
        target,
        &references,
        FormAttempt::FIRST,
    )
    .expect("the mock answers")
    {
        Err(refused) => Said::Refused(refused.rule),
        Ok(formed) => match validate(formed, view, rule_set, trust) {
            Err(fault) => stale(&fault),
            Ok(Err(refused)) => Said::Refused(refused.rule),
            Ok(Ok(valid)) => Said::Accepted(valid.block().cumulative_difficulty()),
        },
    }
}

fn cheap_said<'id, V: HeaderView<'id>>(
    candidate: &Candidate,
    view: &V,
    rule_set: &RuleSet,
    trust: &Trust,
    substrate: &MockSubstrate,
    seed: BlockHash,
    target: Target,
) -> Said
where
    V::Fault: std::fmt::Debug,
{
    let pow = PowBlob::read(&candidate.block.pow_blob()).expect("the preimage parses");
    let open = OpenHeader::from_pow(&pow, seed, target);
    match judge_header_cheap(&open, view, rule_set, trust, substrate) {
        Err(ProspectFault::Substrate(_)) => panic!("the mock clock faulted"),
        Err(ProspectFault::Chain(fault)) => stale(&fault),
        Ok(Err(refused)) => Said::Refused(refused.rule),
        Ok(Ok(prospect)) => Said::Accepted(prospect.cumulative_difficulty),
    }
}

fn same<'id, V: ChainView<'id, Fault = StoreError>>(
    candidate: &Candidate,
    view: &V,
    rule_set: &RuleSet,
    trust: &Trust,
    substrate: &MockSubstrate,
    seed: BlockHash,
    target: Target,
) -> Said {
    let header = header_said(candidate, view, rule_set, trust, substrate, seed, target);
    let validated = validate_said(
        candidate.clone(),
        view,
        rule_set,
        trust,
        substrate,
        seed,
        target,
    );
    assert_eq!(header, validated, "the header path and validate disagree");
    header
}

/// Every captured block is accepted from its header alone, and the work is
/// the work `validate` records.
#[test]
fn the_header_path_agrees_with_validate_on_every_captured_block() {
    let substrate = mock_with_the_real_clock();
    let mut blocks = 0u64;
    for (dir, manifest) in captured_chains() {
        let chain = load(&dir, &manifest.shape);
        let rules = rules_for(&manifest);
        let trust = rules.trust();
        let path = tmp(&format!("header-path-{}", manifest.shape));
        let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
        store
            .write(|batch| -> Result<(), StoreError> {
                for candidate in &chain {
                    let view = batch.chain_view();
                    let height = connecting(&view);
                    let rule_set = rules.in_force(height);
                    let seed = seed_of(&view, height);
                    let target = target_of(&view, height, &rule_set);
                    let said = header_said(
                        candidate,
                        &view,
                        &rule_set,
                        &trust,
                        substrate.as_ref(),
                        seed,
                        target,
                    );
                    let references = ReferenceClaims::from_headers(&view, height, candidate)
                        .expect("references");
                    let formed = form(
                        candidate.clone(),
                        &rule_set,
                        substrate.as_ref(),
                        seed,
                        target,
                        &references,
                        FormAttempt::FIRST,
                    )
                    .expect("the mock answers")
                    .unwrap_or_else(|refused| {
                        panic!("{} {height}: form refused {}", manifest.shape, refused.rule)
                    });
                    let valid = validate(formed, &view, &rule_set, &trust)
                        .unwrap_or_else(|fault| panic!("{fault:?}"))
                        .unwrap_or_else(|refused| {
                            panic!(
                                "{} {height}: validate refused {}",
                                manifest.shape, refused.rule
                            )
                        });
                    let cheap = cheap_said(
                        candidate,
                        &view,
                        &rule_set,
                        &trust,
                        substrate.as_ref(),
                        seed,
                        target,
                    );
                    match said {
                        Said::Accepted(work) => {
                            assert_eq!(
                                work,
                                valid.block().cumulative_difficulty(),
                                "{}",
                                manifest.shape
                            );
                            assert_eq!(
                                cheap, said,
                                "{} {height}: the cheap path and judge_header disagree",
                                manifest.shape
                            );
                            let pow = PowBlob::read(&candidate.block.pow_blob()).expect("preimage");
                            let open = OpenHeader::from_pow(&pow, seed, target);
                            let prospect = judge_header_cheap(
                                &open,
                                &view,
                                &rule_set,
                                &trust,
                                substrate.as_ref(),
                            )
                            .expect("clock")
                            .expect("the cheap path accepts");
                            assert_eq!(prospect.connecting, height);
                        }
                        other => panic!("{} {height}: header path {other:?}", manifest.shape),
                    }
                    drop(view);
                    batch.connect(valid, rule_set)?;
                    blocks += 1;
                }
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{}: {e}", manifest.shape));
        cleanup(&path);
    }
    assert!(blocks > 0, "no captured block was judged");
}

fn at_first_later_block(
    body: impl FnOnce(
        &Candidate,
        &WriteBatch<'_, '_>,
        &RuleSet,
        &Trust,
        &MockSubstrate,
        BlockHash,
        Target,
    ),
) {
    let (dir, manifest) = captured_chains().into_iter().next().expect("a chain");
    let chain = load(&dir, &manifest.shape);
    let rules = rules_for(&manifest);
    let trust = rules.trust();
    let substrate = mock_with_the_real_clock();
    let path = tmp("header-path-mutations");
    let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
    store
        .write(|batch| -> Result<(), StoreError> {
            for candidate in &chain {
                let view = batch.chain_view();
                let height = connecting(&view);
                let rule_set = rules.in_force(height);
                let seed = seed_of(&view, height);
                let target = target_of(&view, height, &rule_set);
                if !height.is_zero() {
                    body(
                        candidate,
                        batch,
                        &rule_set,
                        &trust,
                        substrate.as_ref(),
                        seed,
                        target,
                    );
                    return Ok(());
                }
                let references =
                    ReferenceClaims::from_headers(&view, height, candidate).expect("references");
                let formed = form(
                    candidate.clone(),
                    &rule_set,
                    substrate.as_ref(),
                    seed,
                    target,
                    &references,
                    FormAttempt::FIRST,
                )
                .expect("mock")
                .expect("genesis forms");
                let valid = validate(formed, &view, &rule_set, &trust)
                    .expect("mock")
                    .expect("genesis validates");
                drop(view);
                batch.connect(valid, rule_set)?;
            }
            panic!("the chain has no block after genesis");
        })
        .expect("write");
    cleanup(&path);
}

/// Header mutations refuse on the same row on both paths. A wrong seed and
/// a wrong target are stale claims, not refusals. A nonce change at this
/// chain's difficulty is not a refusal, and neither path invents one.
#[test]
fn header_mutations_agree_with_validate() {
    let mut ran = false;
    at_first_later_block(
        |candidate, batch, rule_set, trust, substrate, seed, target| {
            let view = batch.chain_view();
            let mut major = candidate.clone();
            major.block.header.major_version = major.block.header.major_version.saturating_add(1);
            assert_eq!(
                same(&major, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::B1)
            );

            let mut minor = candidate.clone();
            minor.block.header.minor_version = minor.block.header.minor_version.saturating_add(1);
            assert_eq!(
                same(&minor, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::B2)
            );

            let mut orphan = candidate.clone();
            orphan.block.header.previous = BlockHash::from_bytes([0xee; 32]);
            assert_eq!(
                same(&orphan, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::A2)
            );
            assert_eq!(
                cheap_said(&orphan, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::A2)
            );

            let mut stale_time = candidate.clone();
            stale_time.block.header.timestamp = 0;
            assert_eq!(
                same(&stale_time, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::C2)
            );
            assert_eq!(
                cheap_said(&stale_time, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::C2)
            );

            let mut future = candidate.clone();
            future.block.header.timestamp =
                substrate.clock.to_raw().saturating_add(FTL_SECONDS + 1);
            assert_eq!(
                same(&future, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::C1)
            );
            assert_eq!(
                cheap_said(&future, &view, rule_set, trust, substrate, seed, target),
                Said::Refused(CenRow::C1)
            );

            let mut nonce = candidate.clone();
            nonce.block.header.nonce = nonce.block.header.nonce.wrapping_add(1);
            assert!(matches!(
                same(&nonce, &view, rule_set, trust, substrate, seed, target),
                Said::Accepted(_)
            ));

            let wrong_seed = BlockHash::from_bytes([0x5a; 32]);
            assert_eq!(
                same(candidate, &view, rule_set, trust, substrate, wrong_seed, target),
                Said::StaleSeed
            );
            let wrong_target = Target::for_tests(
                NonZeroU128::new(target.difficulty().to_raw().saturating_add(1).max(2))
                    .expect("non-zero"),
            );
            assert_eq!(
                same(
                    candidate,
                    &view,
                    rule_set,
                    trust,
                    substrate,
                    seed,
                    wrong_target
                ),
                Said::StaleTarget
            );
            ran = true;
        },
    );
    assert!(ran, "no block after genesis was judged");
}

/// A coinbase defect is `validate`'s and not the header path's.
#[test]
fn coinbase_rows_are_not_on_the_header_path() {
    at_first_later_block(
        |candidate, batch, rule_set, trust, substrate, seed, target| {
            let view = batch.chain_view();
            let mut two = candidate.clone();
            let extra = two.block.miner_transaction.prefix.outputs[0].clone();
            two.block.miner_transaction.prefix.outputs.push(extra);
            if let shekyl_wire::transaction::Ct::Null(base) = &mut two.block.miner_transaction.ct {
                base.commitments.push(TWO_G);
                base.enc_amounts.push([0x55; 9]);
                base.enc_labels.push([0x66; 9]);
            }
            two.block.miner_transaction.prefix.extra = coinbase_extra(2);
            let header = header_said(&two, &view, rule_set, trust, substrate, seed, target);
            let validated = validate_said(two, &view, rule_set, trust, substrate, seed, target);
            assert!(
                matches!(header, Said::Accepted(_)),
                "F4 is not a header row: {header:?}"
            );
            assert_eq!(validated, Said::Refused(CenRow::F4));

            let mut height = candidate.clone();
            match &mut height.block.miner_transaction.prefix.inputs[..] {
                [Input::Gen(claimed)] => *claimed = claimed.wrapping_add(1),
                _ => panic!("the coinbase has a gen input"),
            }
            let header = header_said(&height, &view, rule_set, trust, substrate, seed, target);
            let validated = validate_said(height, &view, rule_set, trust, substrate, seed, target);
            assert!(
                matches!(header, Said::Accepted(_)),
                "F5 is not a header row: {header:?}"
            );
            assert_eq!(validated, Said::Refused(CenRow::F5));

            let mut unlock = candidate.clone();
            unlock.block.miner_transaction.prefix.unlock_time = unlock
                .block
                .miner_transaction
                .prefix
                .unlock_time
                .wrapping_add(1);
            let header = header_said(&unlock, &view, rule_set, trust, substrate, seed, target);
            let validated = validate_said(unlock, &view, rule_set, trust, substrate, seed, target);
            assert!(
                matches!(header, Said::Accepted(_)),
                "F6 is not a header row: {header:?}"
            );
            assert_eq!(validated, Said::Refused(CenRow::F6));
        },
    );
}

fn body_of(candidate: &Candidate) -> BlockBody {
    let mut block = Vec::new();
    candidate.block.write(&mut block).expect("write");
    let txs = candidate
        .transactions
        .iter()
        .map(|tx| {
            let mut bytes = Vec::new();
            tx.write(&mut bytes).expect("write");
            TxBody::Full(bytes)
        })
        .collect();
    BlockBody {
        block,
        txs,
        attestation_witness: candidate
            .attestation_witness
            .as_ref()
            .map(|w| w.as_bytes().to_vec())
            .unwrap_or_default(),
    }
}

fn formed_header(
    candidate: &Candidate,
    rule_set: &RuleSet,
    substrate: &MockSubstrate,
    seed: BlockHash,
    target: Target,
) -> shekyl_chain_rules::FormedHeader {
    let pow = PowBlob::read(&candidate.block.pow_blob()).expect("preimage");
    form_header(&pow, rule_set, substrate, seed, target)
        .expect("mock")
        .expect("the header forms")
}

/// A substituted transaction, a reordered pair and a substituted witness
/// are refused by `bind_body` with the row `validate` gives. The unchanged
/// body passes both. A skeleton binds to its txid.
#[test]
fn bind_body_agrees_with_validate() {
    let mut substituted = false;
    let mut reordered = false;
    let mut skeleton = false;
    let mut witnessed = false;
    let substrate = mock_with_the_real_clock();
    for (dir, manifest) in captured_chains() {
        if substituted && reordered && skeleton && witnessed {
            break;
        }
        let chain = load(&dir, &manifest.shape);
        let rules = rules_for(&manifest);
        let trust = rules.trust();
        let path = tmp(&format!("header-path-bind-{}", manifest.shape));
        let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
        store
            .write(|batch| -> Result<(), StoreError> {
                for candidate in &chain {
                    let view = batch.chain_view();
                    let height = connecting(&view);
                    let rule_set = rules.in_force(height);
                    let seed = seed_of(&view, height);
                    let target = target_of(&view, height, &rule_set);
                    let header =
                        formed_header(candidate, &rule_set, substrate.as_ref(), seed, target);
                    let intact = body_of(candidate);
                    assert_eq!(bind_body(&header, &intact), Ok(()));

                    if let Some(tx) = candidate.transactions.first() {
                        let mut changed = tx.clone();
                        changed.prefix.unlock_time = changed.prefix.unlock_time.wrapping_add(1);
                        let mut bad = intact.clone();
                        let mut bytes = Vec::new();
                        changed.write(&mut bytes).expect("write");
                        bad.txs[0] = TxBody::Full(bytes);
                        assert_eq!(
                            bind_body(&header, &bad).map_err(|e| e.rule),
                            Err(CenRow::G2)
                        );
                        let mut replaced = candidate.clone();
                        replaced.transactions[0] = changed;
                        assert_eq!(
                            validate_said(
                                replaced,
                                &view,
                                &rule_set,
                                &trust,
                                substrate.as_ref(),
                                seed,
                                target,
                            ),
                            Said::Refused(CenRow::G2)
                        );
                        substituted = true;

                        let segments = tx.write_segments().expect("segments");
                        let archival_len = segments.archival_len();
                        let sk = SkeletonTx {
                            unprunable: segments.pruned,
                            prunable_hash: tx.prunable_hash(),
                            pqc_auth_hash: tx.pqc_auth_hash(),
                            archival_len,
                        };
                        let mut with_skeleton = intact.clone();
                        with_skeleton.txs[0] = TxBody::Skeleton(sk);
                        assert_eq!(bind_body(&header, &with_skeleton), Ok(()));
                        skeleton = true;
                    }
                    if candidate.transactions.len() >= 2 {
                        let mut swapped_body = intact.clone();
                        swapped_body.txs.swap(0, 1);
                        assert_eq!(
                            bind_body(&header, &swapped_body).map_err(|e| e.rule),
                            Err(CenRow::G2)
                        );
                        let mut swapped = candidate.clone();
                        swapped.transactions.swap(0, 1);
                        assert_eq!(
                            validate_said(
                                swapped,
                                &view,
                                &rule_set,
                                &trust,
                                substrate.as_ref(),
                                seed,
                                target,
                            ),
                            Said::Refused(CenRow::G2)
                        );
                        reordered = true;
                    }
                    let mut bad_witness = intact;
                    bad_witness.attestation_witness = vec![0xff];
                    let mut with_witness = candidate.clone();
                    with_witness.attestation_witness =
                        Some(AttestationWitness::new(vec![0xff]).expect("within the cap"));
                    assert_eq!(
                        bind_body(&header, &bad_witness).map_err(|e| e.rule),
                        Err(CenRow::B4)
                    );
                    assert_eq!(
                        validate_said(
                            with_witness,
                            &view,
                            &rule_set,
                            &trust,
                            substrate.as_ref(),
                            seed,
                            target,
                        ),
                        Said::Refused(CenRow::B4)
                    );
                    witnessed = true;

                    let references = ReferenceClaims::from_headers(&view, height, candidate)
                        .expect("references");
                    let formed = form(
                        candidate.clone(),
                        &rule_set,
                        substrate.as_ref(),
                        seed,
                        target,
                        &references,
                        FormAttempt::FIRST,
                    )
                    .expect("mock")
                    .expect("forms");
                    let valid = validate(formed, &view, &rule_set, &trust)
                        .expect("mock")
                        .expect("validates");
                    drop(view);
                    batch.connect(valid, rule_set)?;
                    if substituted && reordered && skeleton && witnessed {
                        break;
                    }
                }
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{}: {e}", manifest.shape));
        cleanup(&path);
    }
    assert!(substituted, "no listed transaction to substitute");
    assert!(reordered, "no block listed two transactions");
    assert!(skeleton, "no skeleton was bound");
    assert!(witnessed, "no witness was substituted");
}

/// A block at an anchored height whose hash is not the anchor's is CEN-E1
/// on both paths.
#[test]
fn an_anchored_height_with_the_wrong_hash_is_e1_on_both_paths() {
    let (dir, manifest) = captured_chains().into_iter().next().expect("a chain");
    let chain = load(&dir, &manifest.shape);
    let rules = rules_for(&manifest);
    let anchors = ReleaseAnchors::for_tests(Some(BlockHash::from_bytes([0xab; 32])), &[]);
    let trust = Trust::full(anchors);
    let substrate = mock_with_the_real_clock();
    let path = tmp("header-path-anchor");
    let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
    store
        .inspect(|batch| -> Result<(), StoreError> {
            let view = batch.chain_view();
            let rule_set = rules.in_force(BlockHeight::ZERO);
            let seed = seed_of(&view, BlockHeight::ZERO);
            let target = target_of(&view, BlockHeight::ZERO, &rule_set);
            assert_eq!(
                same(
                    &chain[0],
                    &view,
                    &rule_set,
                    &trust,
                    substrate.as_ref(),
                    seed,
                    target
                ),
                Said::Refused(CenRow::E1)
            );
            assert_eq!(
                cheap_said(
                    &chain[0],
                    &view,
                    &rule_set,
                    &trust,
                    substrate.as_ref(),
                    seed,
                    target
                ),
                Said::Refused(CenRow::E1)
            );
            Ok(())
        })
        .expect("inspect");
    cleanup(&path);
}

/// Bytes after a full transaction, or after a skeleton's pruned base, do
/// not bind. `validate` parses a full transaction with exact consumption,
/// and the skeleton is that same rule on the pruned segment: the extra
/// byte is not the transaction.
#[test]
fn appended_bytes_are_not_the_transaction() {
    let substrate = mock_with_the_real_clock();
    let (dir, manifest) = captured_chains()
        .into_iter()
        .find(|(_, manifest)| manifest.shape == "spend-1in-2out")
        .expect("the spend chain");
    let chain = load(&dir, &manifest.shape);
    let rules = rules_for(&manifest);
    let path = tmp("header-path-trailing");
    let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
    let mut pinned = false;
    store
        .write(|batch| -> Result<(), StoreError> {
            for candidate in &chain {
                let view = batch.chain_view();
                let height = connecting(&view);
                let rule_set = rules.in_force(height);
                let seed = seed_of(&view, height);
                let target = target_of(&view, height, &rule_set);
                if let Some(tx) = candidate.transactions.first() {
                    let header =
                        formed_header(candidate, &rule_set, substrate.as_ref(), seed, target);
                    let mut full = body_of(candidate);
                    let trailing = {
                        let TxBody::Full(bytes) = &mut full.txs[0] else {
                            panic!("body_of writes a full transaction");
                        };
                        bytes.push(0xff);
                        bytes.clone()
                    };
                    assert_eq!(
                        bind_body(&header, &full).map_err(|e| e.rule),
                        Err(CenRow::G2),
                        "a byte after a full transaction"
                    );
                    assert!(
                        shekyl_wire::Transaction::from_bytes(&trailing).is_err(),
                        "validate's parser accepts a trailing byte"
                    );
                    let segments = tx.write_segments().expect("segments");
                    let archival_len = segments.archival_len();
                    let mut unprunable = segments.pruned.clone();
                    unprunable.push(0xff);
                    let mut skeleton = body_of(candidate);
                    skeleton.txs[0] = TxBody::Skeleton(SkeletonTx {
                        unprunable,
                        prunable_hash: tx.prunable_hash(),
                        pqc_auth_hash: tx.pqc_auth_hash(),
                        archival_len,
                    });
                    assert_eq!(
                        bind_body(&header, &skeleton).map_err(|e| e.rule),
                        Err(CenRow::G2),
                        "a byte after the pruned base"
                    );
                    // The whole encoding parses under Transaction::read and
                    // its txid matches, which is what the old skeleton parser
                    // bound. The pruned reader stops at the base.
                    let whole = tx.serialize();
                    let mut cursor = whole.as_slice();
                    let read = shekyl_wire::Transaction::read(&mut cursor).expect("read");
                    assert!(cursor.is_empty());
                    assert_eq!(
                        read.hash_with_supplied_components(
                            tx.pqc_auth_hash(),
                            tx.prunable_hash(),
                            archival_len,
                        ),
                        tx.hash()
                    );
                    assert!(shekyl_wire::Transaction::from_pruned_bytes(&whole).is_err());
                    skeleton.txs[0] = TxBody::Skeleton(SkeletonTx {
                        unprunable: whole,
                        prunable_hash: tx.prunable_hash(),
                        pqc_auth_hash: tx.pqc_auth_hash(),
                        archival_len,
                    });
                    assert_eq!(
                        bind_body(&header, &skeleton).map_err(|e| e.rule),
                        Err(CenRow::G2),
                        "the whole transaction presented as the pruned segment"
                    );
                    let parsed = validate_said(
                        {
                            let mut replaced = candidate.clone();
                            replaced.transactions[0] = read;
                            replaced
                        },
                        &view,
                        &rule_set,
                        &rules.trust(),
                        substrate.as_ref(),
                        seed,
                        target,
                    );
                    let honest = validate_said(
                        candidate.clone(),
                        &view,
                        &rule_set,
                        &rules.trust(),
                        substrate.as_ref(),
                        seed,
                        target,
                    );
                    assert_eq!(
                        parsed, honest,
                        "the whole encoding is the transaction validate accepts"
                    );
                    assert!(
                        matches!(honest, Said::Accepted(_)),
                        "validate refused the transaction: {honest:?}"
                    );
                    pinned = true;
                    break;
                }
                let references =
                    ReferenceClaims::from_headers(&view, height, candidate).expect("references");
                let formed = form(
                    candidate.clone(),
                    &rule_set,
                    substrate.as_ref(),
                    seed,
                    target,
                    &references,
                    FormAttempt::FIRST,
                )
                .expect("mock")
                .expect("form");
                let valid = validate(formed, &view, &rule_set, &rules.trust())
                    .expect("view")
                    .expect("validate");
                drop(view);
                batch.connect(valid, rule_set)?;
            }
            Ok(())
        })
        .expect("write");
    cleanup(&path);
    assert!(pinned, "the chain listed no transaction");
}

/// B1 is a cheap check, and the cheap checks do not hash. A header whose
/// major version is wrong is refused before any longhash; a header the
/// longhash would have to refuse is still accepted here.
#[test]
fn the_cheap_checks_name_the_version_and_do_not_hash() {
    let (dir, manifest) = captured_chains().into_iter().next().expect("a chain");
    let chain = load(&dir, &manifest.shape);
    let rules = rules_for(&manifest);
    let trust = rules.trust();
    let mut substrate = *mock_with_the_real_clock();
    substrate.longhash = MockSubstrate::must_not_hash;
    let path = tmp("header-path-cheap");
    let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
    store
        .inspect(|batch| -> Result<(), StoreError> {
            let view = batch.chain_view();
            let height = BlockHeight::ZERO;
            let rule_set = rules.in_force(height);
            let seed = seed_of(&view, height);
            let target = target_of(&view, height, &rule_set);
            let pow = PowBlob::read(&chain[0].block.pow_blob()).expect("preimage");
            let open = OpenHeader::from_pow(&pow, seed, target);
            let prospect = judge_header_cheap(&open, &view, &rule_set, &trust, &substrate)
                .expect("the cheap path does not hash")
                .expect("the genesis header passes the cheap checks");
            assert!(prospect.coverage.contains(CenRow::B1));
            assert!(prospect.coverage.contains(CenRow::B2));
            let mut bad = pow.clone();
            bad.header.major_version = bad.header.major_version.saturating_add(1);
            let open = OpenHeader::from_pow(&bad, seed, target);
            match judge_header_cheap(&open, &view, &rule_set, &trust, &substrate).expect("clock") {
                Err(refused) => assert_eq!(refused.rule, CenRow::B1),
                Ok(_) => panic!("a wrong major version passed the cheap checks"),
            }
            Ok(())
        })
        .expect("inspect");
    cleanup(&path);
}

/// All-ones under difficulty 2 fails CEN-D1. `form_header` and `form` both
/// name that row. The zero hash would not: it satisfies every target.
#[test]
fn a_longhash_the_target_refuses_is_d1_on_both_paths() {
    let (dir, manifest) = captured_chains().into_iter().next().expect("a chain");
    let chain = load(&dir, &manifest.shape);
    let rules = rules_for(&manifest);
    let mut substrate = *mock_with_the_real_clock();
    substrate.longhash = MockSubstrate::all_ones;
    let target = Target::for_tests(NonZeroU128::new(2).expect("two"));
    let path = tmp("header-path-d1");
    let store = open_store_under(&path, &rules.in_force(BlockHeight::ZERO), ApplyPolicy::Full);
    store
        .inspect(|batch| -> Result<(), StoreError> {
            let view = batch.chain_view();
            let height = BlockHeight::ZERO;
            let rule_set = rules.in_force(height);
            let seed = seed_of(&view, height);
            let pow = PowBlob::read(&chain[0].block.pow_blob()).expect("preimage");
            match form_header(&pow, &rule_set, &substrate, seed, target).expect("the mock answers")
            {
                Err(refused) => assert_eq!(refused.rule, CenRow::D1),
                Ok(_) => panic!("form_header accepted a longhash the target refuses"),
            }
            let references =
                ReferenceClaims::from_headers(&view, height, &chain[0]).expect("references");
            match form(
                chain[0].clone(),
                &rule_set,
                &substrate,
                seed,
                target,
                &references,
                FormAttempt::FIRST,
            )
            .expect("the mock answers")
            {
                Err(refused) => assert_eq!(refused.rule, CenRow::D1),
                Ok(_) => panic!("form accepted a longhash the target refuses"),
            }
            Ok(())
        })
        .expect("inspect");
    cleanup(&path);
}
