// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block path, driven synchronously, for the instruction-count benches
//! (`benches/block_path_iai.rs`; `BENCHMARK_ALIGNMENT.md` BA-T2 and the
//! `PB-D1` terms of `DAEMON_REDB_STORE.md` §1.3a).
//!
//! # What this is and is not
//!
//! The daemon connects a block through the connector actor: `form` off the
//! actor, then `validate` and `connect` inside one write closure
//! (`connector.rs`, `Apply`). An instruction count wants one thread and no
//! mailbox, so [`BlockPath`] makes the same three calls in the same order on
//! the caller's thread: `shekyl_chain_rules::form`, then
//! `validate_with_memo` and `WriteBatch::connect` inside
//! `ChainStore::write`. Nothing here is a second implementation of any of
//! them. What it leaves out is the actor's bookkeeping around them (the
//! reply, the tip watch), which is not a term of the budget.
//!
//! The chain is regtest at fixed difficulty one under the harness longhash
//! ([`FixedClock`]): every target is satisfied and no RandomX cache exists.
//! One block's proof-of-work is its own row
//! (`shekyl-pow-randomx` `benches/verify_header_iai.rs`), so a block row
//! here is the block without its hash.
//!
//! # The fixture
//!
//! A fixture is a corpus file ([`crate::corpus`]): a short history of
//! coinbase-only blocks and then the one block the bench measures, every
//! transaction in it a real spend built by the harness spender and admitted
//! by the validator when the fixture was generated
//! (`bench_fixture_tests.rs`). [`BlockPath::replayed`] connects the history
//! into a fresh store, outside the measured region, and hands the last
//! block back unconnected.
//!
//! Behind `bench-internals` with `harness`; the fixture tests compile it
//! under `cfg(test)`.

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};

use shekyl_chain_rules::{
    form, seed_height, validate_with_memo, Candidate, DrawableMemo, FormAttempt, FormClaims,
    ReferenceClaims, RuleSet, StructurallyValid, Substrate, Target,
};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, Horizons};
use shekyl_types::{BlockHash, BlockHeight, PowHash, Timestamp};

use crate::corpus::CorpusReader;
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, Source};
use crate::target::TargetLedger;

/// The rules a fixture chain is mined and replayed under: regtest at fixed
/// difficulty one, held to no genesis pin because the chain mines its own
/// block 0. The scenario driver's rules are this constant.
pub const RULES: ChainRules = ChainRules::harness_regtest(
    Some(std::num::NonZeroU128::MIN),
    shekyl_chain_rules::CappedEpoch::PRODUCTION,
);

/// The harness longhash under a clock the driver sets to each block's own
/// timestamp, so a replayed block is judged at the instant it was mined.
pub struct FixedClock(AtomicU64);

impl FixedClock {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::Relaxed);
    }
}

impl crate::pow::Fixture for FixedClock {}

impl Substrate for FixedClock {
    type Fault = std::convert::Infallible;

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(Timestamp::from_raw(self.0.load(Ordering::Relaxed)))
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<PowHash, Self::Fault> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

/// What the caller says about the chain a block joins: `form`'s claims,
/// read off the header ledger and the connected blocks' identities before the
/// measured call.
pub struct Claimed {
    /// The height the block connects at.
    pub height: BlockHeight,
    rule_set: RuleSet,
    seed: BlockHash,
    target: Target,
    references: ReferenceClaims,
}

/// A store with a chain connected into it, and what the next block's
/// claims are read from.
pub struct BlockPath {
    store: ChainStore,
    targets: TargetLedger,
    /// The connected blocks' identities by height: the next height and
    /// the seed claim, without a store read.
    hashes: Vec<BlockHash>,
    clock: FixedClock,
    memo: DrawableMemo,
    /// Last, so the store is dropped before its directory.
    _dir: tempfile::TempDir,
}

impl BlockPath {
    /// Connect every block of `corpus` but the last into a fresh store and
    /// return the driver with that last block, unconnected.
    ///
    /// # Panics
    ///
    /// The corpus is not a finished extend-only corpus of at least two
    /// blocks, or a block of its history does not connect: a stale fixture,
    /// which `bench_fixture_tests.rs` regenerates.
    #[must_use]
    pub fn replayed(corpus: &[u8]) -> (Self, Candidate) {
        let mut blocks = blocks_of(corpus);
        let subject = blocks.pop().expect("a fixture holds its subject block");
        assert!(!blocks.is_empty(), "a fixture holds a history");

        let dir = tempfile::Builder::new()
            .prefix("shekyl-block-path-")
            .tempdir()
            .expect("a bench directory");
        let horizons = Horizons::under(&RULES.in_force(BlockHeight::ZERO))
            .expect("a well-formed rule set's pair is a store schedule");
        let store =
            ChainStore::with_horizons(dir.path().join("chain.redb"), ApplyPolicy::Full, horizons)
                .expect("a fresh store");
        let mut path = Self {
            store,
            targets: TargetLedger::new(),
            hashes: Vec::new(),
            clock: FixedClock::new(),
            memo: DrawableMemo::new(),
            _dir: dir,
        };
        path.connect_history(blocks);
        (path, subject)
    }

    /// The history, in one write and one commit: the connector's `Apply`
    /// for a run of blocks. A commit per block made the replay most of a
    /// row's setup under callgrind.
    fn connect_history(&mut self, blocks: Vec<Candidate>) {
        let trust = RULES.trust();
        let Self {
            store,
            targets,
            hashes,
            clock,
            memo,
            ..
        } = self;
        store
            .write(
                |batch| -> Result<(), shekyl_chain_store::store::StoreError> {
                    for candidate in blocks {
                        let claimed = claims_over(targets, hashes, clock, &candidate);
                        let formed = formed_under(clock, candidate, &claimed);
                        let view = batch.chain_view();
                        let valid = judged(
                            validate_with_memo(
                                formed,
                                &view,
                                &claimed.rule_set,
                                &trust,
                                Some(memo),
                            ),
                            claimed.height,
                        );
                        let block = valid.block().block().clone();
                        batch.connect(valid, claimed.rule_set)?;
                        record(targets, hashes, &claimed, &block);
                    }
                    Ok(())
                },
            )
            .expect("the bench store connects the history");
    }

    /// The claims for `candidate` connecting at the tip, and the clock set
    /// to its timestamp.
    ///
    /// # Panics
    ///
    /// The header ledger disagrees with the chain.
    #[must_use]
    pub fn claims(&mut self, candidate: &Candidate) -> Claimed {
        claims_over(&self.targets, &self.hashes, &self.clock, candidate)
    }

    /// The stateless stage: `shekyl_chain_rules::form` under `claimed`.
    /// Every listed transaction's form, signatures and membership proof,
    /// and the block's range-proof batch.
    ///
    /// # Panics
    ///
    /// The block is refused: a stale fixture.
    pub fn form(&self, candidate: Candidate, claimed: &Claimed) -> StructurallyValid {
        formed_under(&self.clock, candidate, claimed)
    }

    /// The view-bound stage and the write: `validate_with_memo` over the
    /// batch's view, `WriteBatch::connect`, and the commit, as the
    /// connector's `Apply` runs them, at production durability.
    ///
    /// # Panics
    ///
    /// The block is refused or the store faults: a stale fixture.
    pub fn connect(&mut self, formed: StructurallyValid, claimed: &Claimed) {
        let trust = RULES.trust();
        let memo = &mut self.memo;
        let block = self
            .store
            .write(
                |batch| -> Result<_, shekyl_chain_store::store::StoreError> {
                    let view = batch.chain_view();
                    let valid = judged(
                        validate_with_memo(formed, &view, &claimed.rule_set, &trust, Some(memo)),
                        claimed.height,
                    );
                    let block = valid.block().block().clone();
                    batch.connect(valid, claimed.rule_set)?;
                    Ok(block)
                },
            )
            .expect("the bench store connects the block");
        record(&mut self.targets, &mut self.hashes, claimed, &block);
    }

    /// Pop the tip block in one write closure and its commit, as the
    /// connector's rewind runs it.
    ///
    /// # Panics
    ///
    /// The store faults.
    pub fn pop(&mut self) {
        self.store
            .write(|batch| batch.pop_many(1))
            .expect("the bench store pops its tip");
        self.hashes.pop();
        let tip = self
            .hashes
            .len()
            .checked_sub(1)
            .expect("a history below the popped block");
        self.targets.rewind_to(BlockHeight::from_raw(
            u64::try_from(tip).expect("a short chain"),
        ));
    }

    /// The store, for the read rows.
    #[must_use]
    pub const fn store(&self) -> &ChainStore {
        &self.store
    }

    /// The store, shared, with the file it lives in and the directory
    /// that holds it: what the RPC's store facts are built over. The
    /// directory is returned so the caller keeps it for as long as the
    /// store.
    #[must_use]
    pub fn into_shared(
        self,
    ) -> (
        std::sync::Arc<ChainStore>,
        std::path::PathBuf,
        tempfile::TempDir,
    ) {
        let file = self._dir.path().join("chain.redb");
        (std::sync::Arc::new(self.store), file, self._dir)
    }

    /// The connected blocks' identities, by height.
    #[must_use]
    pub fn hashes(&self) -> &[BlockHash] {
        &self.hashes
    }
}

/// Every block of `corpus`, in chain order: the history and then the
/// subject block.
///
/// # Panics
///
/// The corpus is not a finished extend-only corpus.
#[must_use]
pub fn blocks_of(corpus: &[u8]) -> Vec<Candidate> {
    let mut reader = CorpusReader::open(Cursor::new(corpus)).expect("a corpus header");
    let mut blocks = Vec::new();
    while let Some(event) = reader.next().expect("a finished corpus") {
        match event.event {
            IngestEvent::Extend(candidate) => blocks.push(*candidate),
            other => panic!("a block-path fixture is extend-only, found {other:?}"),
        }
    }
    blocks
}

/// `form`'s claims for `candidate` connecting above `hashes`, read off the
/// header ledger and the connected identities, with the clock set to the
/// block's timestamp.
fn claims_over(
    targets: &TargetLedger,
    hashes: &[BlockHash],
    clock: &FixedClock,
    candidate: &Candidate,
) -> Claimed {
    let height = BlockHeight::from_raw(u64::try_from(hashes.len()).expect("a short chain"));
    let seed = match seed_height(height) {
        None => BlockHash::NULL,
        Some(at) => hashes[usize::try_from(at.to_raw()).expect("a short chain")],
    };
    let rule_set = RULES.in_force(height);
    let target = targets
        .claim(height, &rule_set)
        .unwrap_or_else(|corrupt| panic!("the bench chain is consistent: {corrupt}"));
    let references = match ReferenceClaims::from_headers(targets, height, candidate) {
        Ok(references) => references,
        Err(never) => match never {},
    };
    clock.set(candidate.block.header.timestamp);
    Claimed {
        height,
        rule_set,
        seed,
        target,
        references,
    }
}

/// `shekyl_chain_rules::form` under `claimed`, refusing a refusal.
fn formed_under(clock: &FixedClock, candidate: Candidate, claimed: &Claimed) -> StructurallyValid {
    let formed = form(
        candidate,
        &FormClaims {
            rule_set: &claimed.rule_set,
            seed: claimed.seed,
            target: claimed.target,
            references: &claimed.references,
            network: RULES.trust().network_id(),
        },
        clock,
        FormAttempt::FIRST,
    );
    match formed {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => panic!("form refused the block at {}: {refused:?}", claimed.height),
        Err(never) => match never {},
    }
}

/// `validate`'s verdict, refusing a refusal and a fault: a stale fixture.
fn judged<T, F: core::fmt::Debug>(
    verdict: Result<shekyl_chain_rules::Verdict<T>, F>,
    height: BlockHeight,
) -> T {
    match verdict {
        Ok(Ok(valid)) => valid,
        Ok(Err(refused)) => panic!("validate refused the block at {height}: {refused:?}"),
        Err(fault) => panic!("validate faulted at {height}: {fault:?}"),
    }
}

/// A connected block joins the header ledger and the identities.
fn record(
    targets: &mut TargetLedger,
    hashes: &mut Vec<BlockHash>,
    claimed: &Claimed,
    block: &shekyl_wire::block::Block,
) {
    targets
        .extend(claimed.height, block, claimed.target)
        .unwrap_or_else(|corrupt| panic!("the bench chain is consistent: {corrupt}"));
    targets.forget_below_window_of(claimed.height);
    hashes.push(block.hash());
}
