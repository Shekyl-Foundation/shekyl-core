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
    form, seed_height, validate_with_memo, AtHeight, Candidate, DrawableMemo, FormAttempt,
    FormClaims, ReferenceClaims, RuleSet, StructurallyValid, Substrate, Target,
};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, Horizons};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PowHash, Timestamp};

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

impl Substrate for FixedClock {
    type Fault = std::convert::Infallible;
    type Held = ();

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(Timestamp::from_raw(self.0.load(Ordering::Relaxed)))
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<PowHash, Self::Fault> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

/// What the caller says about the chain a block joins: `form`'s claims,
/// read off the store and the header ledger before the measured call.
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
        let mut reader = CorpusReader::open(Cursor::new(corpus)).expect("a corpus header");
        let mut blocks = Vec::new();
        while let Some(event) = reader.next().expect("a finished corpus") {
            match event.event {
                IngestEvent::Extend(candidate) => blocks.push(*candidate),
                other => panic!("a block-path fixture is extend-only, found {other:?}"),
            }
        }
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
            clock: FixedClock::new(),
            memo: DrawableMemo::new(),
            _dir: dir,
        };
        for candidate in blocks {
            let claimed = path.claims(&candidate);
            let formed = path.form(candidate, &claimed);
            path.connect(formed, &claimed);
        }
        (path, subject)
    }

    /// The claims for `candidate` connecting at the tip, and the clock set
    /// to its timestamp.
    ///
    /// # Panics
    ///
    /// The store cannot be read, or the header ledger disagrees with it.
    #[must_use]
    pub fn claims(&mut self, candidate: &Candidate) -> Claimed {
        let read = self.store.begin_read().expect("a read of the bench store");
        let height = match read.tip().expect("the tip").recorded {
            None => BlockHeight::ZERO,
            Some(tip) => tip
                .height
                .checked_add(BlockCount::ONE)
                .expect("a bench chain is short"),
        };
        let seed = match seed_height(height) {
            None => BlockHash::NULL,
            Some(at) => match read.block_info(at).expect("the seed block") {
                AtHeight::Recorded(info) => info.hash,
                AtHeight::AboveTip => panic!("the seed height is below the tip"),
            },
        };
        let rule_set = RULES.in_force(height);
        let target = self
            .targets
            .claim(height, &rule_set)
            .unwrap_or_else(|corrupt| panic!("the bench chain is consistent: {corrupt}"));
        let references = match ReferenceClaims::from_headers(&self.targets, height, candidate) {
            Ok(references) => references,
            Err(never) => match never {},
        };
        self.clock.set(candidate.block.header.timestamp);
        Claimed {
            height,
            rule_set,
            seed,
            target,
            references,
        }
    }

    /// The stateless stage: `shekyl_chain_rules::form` under `claimed`.
    /// Every listed transaction's form, signatures and membership proof,
    /// and the block's range-proof batch.
    ///
    /// # Panics
    ///
    /// The block is refused: a stale fixture.
    #[must_use]
    pub fn form(&self, candidate: Candidate, claimed: &Claimed) -> StructurallyValid {
        let formed = form(
            candidate,
            &FormClaims {
                rule_set: &claimed.rule_set,
                seed: claimed.seed,
                target: claimed.target,
                references: &claimed.references,
                network: RULES.trust().network_id(),
            },
            &self.clock,
            FormAttempt::FIRST,
        );
        match formed {
            Ok(Ok(formed)) => formed,
            Ok(Err(refused)) => panic!("form refused the block at {}: {refused:?}", claimed.height),
            Err(never) => match never {},
        }
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
            .write(|batch| -> Result<_, shekyl_chain_store::store::StoreError> {
                let view = batch.chain_view();
                let valid =
                    match validate_with_memo(formed, &view, &claimed.rule_set, &trust, Some(memo)) {
                        Ok(Ok(valid)) => valid,
                        Ok(Err(refused)) => {
                            panic!("validate refused the block at {}: {refused:?}", claimed.height)
                        }
                        Err(fault) => panic!("validate faulted at {}: {fault:?}", claimed.height),
                    };
                let block = valid.block().block().clone();
                batch.connect(valid, claimed.rule_set)?;
                Ok(block)
            })
            .expect("the bench store connects the block");
        self.targets
            .extend(claimed.height, &block, claimed.target)
            .unwrap_or_else(|corrupt| panic!("the bench chain is consistent: {corrupt}"));
        self.targets.forget_below_window_of(claimed.height);
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
        let read = self.store.begin_read().expect("a read of the bench store");
        let tip = read
            .tip()
            .expect("the tip")
            .recorded
            .expect("a history below the popped block");
        self.targets.rewind_to(tip.height);
    }

    /// The store, for the read rows.
    #[must_use]
    pub const fn store(&self) -> &ChainStore {
        &self.store
    }
}
