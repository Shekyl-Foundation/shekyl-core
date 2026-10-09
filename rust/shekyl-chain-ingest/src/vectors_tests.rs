// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The captured chains replay — the real-chain witness for the validator's
//! verification-era rows (`CHAIN_RULES_SLICE_6.md` §5.2; `50-testing.mdc`,
//! *a fixture that constructs the state a rule reads back is not a test of
//! the rule*).
//!
//! Each directory under `tests/vectors/` is one regtest chain a live
//! `shekyld` built and accepted, captured whole as the DRS-E2 replay pair
//! by `engine::regtest_e2e::maybe_capture_chain_vector`: `corpus.e2` (every
//! block and every listed transaction's **full** bytes, RD-F15-verified
//! against the headers) and `trace.e2` (the passed-through facts and the
//! daemon's logical-state digest at the tip). These tests connect every
//! chain through `form → validate → connect` against a **real** `redb`
//! store — the same `pipeline::run` the replay binary composes — and hold
//! the store's digest to the daemon's. The spent set, the reference
//! heights, `height_of` are derived by the code that derives them in
//! production; nothing is served to a rule as given.
//!
//! **What the substrate is here, said plainly.** The default lane runs the
//! chains under `MockSubstrate` — the always-satisfying longhash — because
//! RandomX light mode costs ~0.6 s a block and the depth-3 chain is ~750
//! blocks. That mocks exactly one thing: CEN-D2's hash. D1/D2 are **not**
//! this test's subject and are not witnessed by it; their real-substrate
//! witness is `replays_every_captured_chain_under_the_production_substrate`
//! below, `#[ignore]`d for the live lane, and E2's own replay gate. Every
//! other row a captured chain exercises — the whole of 4.A–4.H and, as
//! they land, 4.I — is judged against real state under both.
//!
//! A chain that fails to replay is a **finding**, never a fixture error:
//! either the daemon that built it and this validator disagree (E2's
//! subject — grade it), or a rule landed that the chain's real spend now
//! trips (the cascade slice 5 §5.1 named — the fixture was right; the
//! rule is what moved). The second kind is recorded, not patched: the
//! corpus pins what was true at capture and is not the witness for a rule
//! that landed after it, so the chain replays as far as the rule admits,
//! compares every connected height, and [`PREDATES`] says exactly where it
//! stops and why — until the chain is regenerated against the rule.

// A whole-file test module, gated at `lib.rs` by
// `#[cfg(all(test, feature = "pipeline"))]`. The inner attribute is the
// file's own declaration of the same fact, for the debug-macro lint
// (`build.yml`), which keys on it — the shape `regtest_e2e.rs` uses. The
// replay summary below is a test's report line, not production output.
#![cfg(test)]

use std::num::{NonZeroU128, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{
    CenRow, FakechainSchedule, InvalidBlock, Locus, ReleaseAnchors, SettlementEpochBlocks,
    Substrate, TxSlot,
};
use shekyl_types::{BlockCount, BlockHeight};

use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::mutation::{ArchivalKind, Before, Environment, Mutation, Unmutable};
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, Injection, Source};
use crate::substrate::ProductionSubstrate;
use crate::test_support::h;
use crate::test_support::{cleanup, open_store_under, tmp};
use crate::trace::Trace;
use shekyl_chain_rules::Candidate;
use shekyl_chain_store::apply_policy::{ApplyPolicy, ArchivalFamily};
use shekyl_pow_randomx::CacheStore;
/// `manifest.json`, as the capture writes it (format 4).
#[derive(Deserialize, Debug)]
pub(crate) struct Manifest {
    format_version: u32,
    pub(crate) shape: String,
    generator: String,
    tip_height: u64,
    block_count: u64,
    spend_txid: Option<String>,
    fixed_difficulty: u128,
    /// The `(SEB, cap)` pair the daemon mined this chain under — the
    /// regtest schedule levers when the generator pulled them, the genesis
    /// pair otherwise. The replay judges the chain under a Fakechain rule
    /// set naming exactly this pair and opens its store under the same
    /// (`DRS_E4_ARCHIVAL_WRITER.md` `ARW-15`): a 512-block epoch judged
    /// under the production one refuses the first block past height 511.
    settlement_epoch_blocks: u64,
    reorg_cap_blocks: u64,
    /// The hash of block 0 as the daemon reported it — the operand that
    /// decides what these chains are valid against (§5.2).
    genesis_hash: String,
    /// The `dev` tree the daemon that built the chain was compiled at.
    built_at_dev_sha: String,
    /// Every row in the daemon's state that **no block produced** — a
    /// regtest injector's direct LMDB write. Required, so a manifest asserts
    /// "wholly block-derived" positively (`[]`) rather than by silence: a
    /// block-driven replay cannot reach such a row, and an archival digest
    /// over the chain diverges by construction at exactly the height a
    /// writer bug would (`DRS_E4_ARCHIVAL_WRITER.md` ARW-1). Format 4: each
    /// row is the injector's receipt in the corpus's one spelling, so the
    /// corpus's `Inject` records can be held to it.
    out_of_band_writes: Vec<OutOfBandWrite>,
}

/// One `out_of_band_writes` row: what kind of row, and the receipt the
/// fetch was given for it (`Injection`'s spelling — the credit and the
/// height the daemon attributed it to).
#[derive(Deserialize, Debug)]
struct OutOfBandWrite {
    kind: String,
    receipt: Injection,
}

/// The one row kind the corpus admits out of band (DRS-E4 §3.8 item 3).
const OUT_OF_BAND_KIND: &str = "archival_serve_credit";

/// The one captured chain whose state is not wholly block-derived: the
/// serve credit `emission-claim`'s claim is priced on was injected
/// (`regtest_e2e.rs`, step A2). Enumerated, not discovered: a new capture
/// that injects must be added here **and** in its manifest, and a chain
/// listed here that stops injecting must leave.
const CHAINS_WITH_OUT_OF_BAND_WRITES: [&str; 1] = ["emission-claim"];

/// The corpus says which of its rows no block produced, and it is exactly
/// the one chain the pre-flight found (ARW-1). Both directions: a chain
/// that injects and does not say so mislabels the corpus; a chain listed as
/// injecting that does not is a stale claim about the data. And the two
/// halves of the capture agree: the manifest's receipts are exactly the
/// `Inject` records the corpus carries, at exactly those heights — the
/// trace half of §3.8 item 3's "present iff the manifest names one".
#[test]
fn only_the_named_chains_carry_out_of_band_writes_and_the_corpus_carries_exactly_those() {
    for (dir, manifest) in captured_chains() {
        let expected = CHAINS_WITH_OUT_OF_BAND_WRITES.contains(&manifest.shape.as_str());
        assert_eq!(
            !manifest.out_of_band_writes.is_empty(),
            expected,
            "{}: out_of_band_writes = {:?}; CHAINS_WITH_OUT_OF_BAND_WRITES says {expected}",
            dir.display(),
            manifest.out_of_band_writes
        );
        for row in &manifest.out_of_band_writes {
            assert_eq!(
                row.kind,
                OUT_OF_BAND_KIND,
                "{}: the only out-of-band row kind the corpus admits is the injected serve credit",
                dir.display()
            );
        }
        let in_manifest: Vec<Injection> = manifest
            .out_of_band_writes
            .iter()
            .map(|r| r.receipt)
            .collect();
        assert_eq!(
            corpus_injections(&dir),
            in_manifest,
            "{}: the corpus's Inject records and the manifest's out_of_band_writes disagree",
            dir.display()
        );
    }
}

/// Every `Inject` record in a captured corpus, with the height it sits
/// at — the one the corpus law held to the tip when it was written.
fn corpus_injections(dir: &Path) -> Vec<Injection> {
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut tip: Option<BlockHeight> = None;
    let mut found = Vec::new();
    while let Some(event) = reader.next().expect("corpus reads") {
        match event.event {
            IngestEvent::Extend(_) => {
                tip = Some(tip.map_or(reader.first_height(), |t| {
                    t.checked_add(BlockCount::ONE)
                        .expect("a captured chain is short")
                }));
            }
            IngestEvent::Rewind { to } => tip = Some(to),
            IngestEvent::Inject(credit) => found.push(Injection {
                at: tip.expect("the corpus law refuses an inject before any block"),
                credit,
            }),
        }
    }
    found
}

/// Every captured chain, in name order. **Fails on an empty set** (rule
/// 47): a directory that vanished, or a rename that no longer matches,
/// must not read as "every chain replays".
pub(crate) fn captured_chains() -> Vec<(PathBuf, Manifest)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut found: Vec<(PathBuf, Manifest)> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("tests/vectors/ must exist: {e}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.join("manifest.json").is_file())
        .map(|p| {
            let text = std::fs::read_to_string(p.join("manifest.json")).expect("read manifest");
            let manifest: Manifest = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{}: manifest does not parse: {e}", p.display()));
            assert_eq!(
                manifest.format_version,
                4,
                "{}: capture format {} is not the one this test reads",
                p.display(),
                manifest.format_version
            );
            (p, manifest)
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    // The witness's subject is these four shapes, not "whatever is in the
    // directory": a capture that fails to land, or a directory that is
    // renamed or pruned, would otherwise shrink the corpus and the test
    // would pass over the remainder (rule 47 — assert the subject exists).
    for want in CAPTURED_SHAPES {
        assert!(
            found.iter().any(|(_, m)| m.shape == want),
            "captured chain `{want}` is missing under {} (present: {:?})",
            root.display(),
            found
                .iter()
                .map(|(_, m)| m.shape.as_str())
                .collect::<Vec<_>>()
        );
    }
    found
}

/// The shapes `regtest_e2e.rs` captures, by the names its `maybe_capture_chain_vector`
/// calls write into `manifest.json` (§5.2). Adding a capture there adds a
/// name here; the corpus is enumerated, not discovered.
const CAPTURED_SHAPES: [&str; 6] = [
    "bond-post",
    "emission-claim",
    "limit-full",
    "median-full",
    "spend-1in-2out",
    "spend-depth3",
];

/// Replay one captured chain through the production pipeline against a
/// fresh store; return the report.
async fn replay<S>(dir: &Path, manifest: &Manifest, substrate: Arc<S>) -> RunReport
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + std::fmt::Debug + 'static,
{
    replay_under(dir, manifest, substrate, ApplyPolicy::Full)
        .await
        .unwrap_or_else(|e| panic!("{}: the captured chain must replay: {e:?}", manifest.shape))
}

/// [`replay`] with the store's archival [`ApplyPolicy`] chosen by the
/// caller, and the run's failure returned rather than panicked: the
/// sufficiency stamp (`archival_sufficiency_tests.rs`) replays each chain
/// with one family's writer stubbed and needs to see *how* the run went
/// red — a diverged snapshot, or a connect that could not proceed without
/// the rows.
pub(crate) async fn replay_under<S>(
    dir: &Path,
    manifest: &Manifest,
    substrate: Arc<S>,
    policy: ApplyPolicy,
) -> Result<RunReport, String>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + std::fmt::Debug + 'static,
{
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let trace = std::fs::read(dir.join("trace.e2")).expect("read trace.e2");
    let mut source =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let trace = Arc::new(Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace"));
    let schedule = FakechainSchedule::new(
        SettlementEpochBlocks::new(manifest.settlement_epoch_blocks)
            .expect("a captured chain's epoch is non-zero"),
        BlockCount::from_raw(manifest.reorg_cap_blocks),
    )
    .unwrap_or_else(|e| {
        panic!(
            "{}: the manifest's pair is not a schedule: {e}",
            manifest.shape
        )
    });
    let rules = ChainRules::Regtest {
        fixed_difficulty: Some(
            NonZeroU128::new(manifest.fixed_difficulty).expect("a regtest difficulty is non-zero"),
        ),
        schedule,
    };
    let path = tmp(&format!(
        "vectors-{}-{}",
        manifest.shape,
        policy_tag(policy)
    ));
    // The store runs the pair the chain was mined under, read off the same
    // rule set `connect` judges by — not the production epoch the other
    // tests' stores pin, which `connect` would refuse at block 0.
    let store = open_store_under(&path, &rules.in_force(BlockHeight::from_raw(0)), policy);
    let report = run(
        &mut source,
        substrate,
        Arc::new(Metrics::new()),
        rules,
        store,
        trace,
        PipelineConfig {
            window: NonZeroUsize::new(64).expect("non-zero"),
            hashers: NonZeroUsize::new(4).expect("non-zero"),
        },
    )
    .await
    .map_err(|e| format!("{e:?}"));
    cleanup(&path);
    report
}

/// A path-safe spelling of the policy, so two replays of one chain under
/// different policies do not share a store directory.
fn policy_tag(policy: ApplyPolicy) -> String {
    match policy {
        ApplyPolicy::Full => "full".to_owned(),
        ApplyPolicy::StubbedFamilies(set) => ArchivalFamily::ALL
            .iter()
            .filter(|f| set.contains(**f))
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join("-"),
    }
}

/// The mock substrate with the **real** clock: these blocks were mined in
/// 2026 and CEN-C1 refuses a future-dated block, so the mock's 2023 default
/// (`MockSubstrate::CLOCK`, chosen for hand-built fixture headers) cannot
/// judge them. Only the hash is mocked.
pub(crate) fn mock_with_the_real_clock() -> Arc<MockSubstrate> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    Arc::new(MockSubstrate {
        clock: shekyl_types::Timestamp::from_raw(now),
        longhash: MockSubstrate::always_satisfies,
    })
}

/// A captured chain that **predates a rule**: a row landed after the
/// capture and refuses one of its blocks, so the chain replays short and
/// says why. The corpus pins what was true at capture — the daemon's
/// roots, weights, accumulator and digest — and is not the witness for a
/// rule that landed later; the rule's witness is the driven scenario
/// (`scenario_archival_tests.rs`) or its unit test. A short replay still
/// compares every connected height against the trace, so the pin holds
/// over the blocks the rule admits.
///
/// Enumerated, not discovered: the refusal is pinned exactly — height,
/// row, locus — and `hold` asserts it, so a chain refused anywhere else is
/// still the finding the module doc names, and a regenerated chain that
/// replays whole fails here with "the record is stale" rather than quietly
/// outgrowing it. Each record is deleted the day its chain is regenerated.
#[derive(Debug)]
pub(crate) struct Predates {
    pub(crate) shape: &'static str,
    /// The refusal, exactly.
    pub(crate) refused: (BlockHeight, InvalidBlock),
    /// What the chain does that the rule refuses, and what a capture that
    /// replays whole does instead.
    pub(crate) why: &'static str,
}

/// The chains that predate a rule, as of E6 slice 8 row 6 (2026-10-06).
pub(crate) const PREDATES: [Predates; 1] = [Predates {
    shape: "emission-claim",
    refused: (
        BlockHeight::from_raw(98),
        InvalidBlock::new(
            CenRow::J15,
            Locus::Input {
                slot: TxSlot::Listed(0),
                input: 1,
            },
        ),
    ),
    why: "the market bond at 98 joins shard `SHARD_ID` compact, and CEN-J15 (slice 8 row 6) \
          admits a compact join only onto a shard that is closed, final and priced at the \
          parent; this chain fills no shard (`regtest_e2e.rs`, `market_holdings`). The C++ \
          daemon that built it marshals a presence bit and no closure, so it accepted the \
          join — permissive, not divergent (DAEMON_REDB_STORE.md §12). A regeneration that \
          replays whole fills the shard, lets it close, and prices it before the join.",
}];

/// The record for a captured chain, if it predates a rule.
pub(crate) fn predates(shape: &str) -> Option<&'static Predates> {
    PREDATES.iter().find(|p| p.shape == shape)
}

/// Every `PREDATES` record names a captured chain. The other direction —
/// a chain refused without a record — is `hold`'s first assertion.
#[test]
fn every_predates_record_names_a_captured_chain() {
    let shapes: Vec<String> = captured_chains()
        .into_iter()
        .map(|(_, m)| m.shape)
        .collect();
    for record in &PREDATES {
        assert!(
            shapes.iter().any(|s| s == record.shape),
            "PREDATES names `{}`, which is not captured — the chain was deleted or renamed; \
             delete the record",
            record.shape
        );
    }
}

/// What every replay must show, whichever substrate judged the hashes.
fn hold(dir: &Path, manifest: &Manifest, report: &RunReport) {
    // How far the chain replays: whole, or exactly as far as the rule it
    // predates admits.
    let expected_connected = match predates(&manifest.shape) {
        None => {
            assert!(
                report.refused.is_none(),
                "{} ({}): the daemon accepted every block of this chain and the validator \
                 refused one — {:?}. A finding: either E2's subject (the two disagree; grade \
                 it) or a rule landed that the chain's real spend trips (slice 5 §5.1's \
                 cascade — the rule moved, not the fixture). If it is the latter and the \
                 refusal is the rule's, record it in `PREDATES` with its why",
                manifest.shape,
                manifest.generator,
                report.refused
            );
            manifest.block_count
        }
        Some(record) => {
            assert_eq!(
                report.refused,
                Some(record.refused),
                "{} ({}): PREDATES says this chain is refused at {:?} by {:?}, and the replay \
                 says {:?}. A different refusal is a finding (grade it); none is a chain that \
                 no longer predates the rule — the record is stale, delete it. Why the record \
                 exists: {}",
                manifest.shape,
                manifest.generator,
                record.refused.0,
                record.refused.1,
                report.refused,
                record.why
            );
            record.refused.0.to_raw()
        }
    };
    assert_eq!(
        report.connected.len() as u64,
        expected_connected,
        "{}: connected {} of {} blocks (tip {}; expected to connect {}) — {}",
        manifest.shape,
        report.connected.len(),
        manifest.block_count,
        manifest.tip_height,
        expected_connected,
        dir.display()
    );
    // CTW-5 (DRS-E3): the derived root is held to the trace's recorded
    // root at **every** connected height, never a sample. The count is
    // asserted first (rule 47): a comparison that ran over nothing is not
    // a comparison.
    assert_eq!(
        report.roots.compared(),
        expected_connected,
        "{}: {} of {} connected heights had a recorded root to compare against",
        manifest.shape,
        report.roots.compared(),
        expected_connected
    );
    let diverged: Vec<_> = report.roots.diverged().collect();
    assert!(
        diverged.is_empty(),
        "{} ({}): the derived curve-tree root differs from the daemon's at {} height(s), first at \
         {:?} — a FINDING, adjudicated against the spec (E2 §0), never a fixture problem: the \
         chain is one the C++ accepted and the root is the validator's derivation",
        manifest.shape,
        manifest.generator,
        diverged.len(),
        diverged.first()
    );
    // CEN-G6/G6b (slice 7 commit 4): the verdict's weight, long-term
    // weight and long-term effective median are held to the C++'s two
    // recorded columns and the exporter's re-derived median at **every**
    // connected height — the medians' parity pin over a chain the C++
    // built, taken while the LMDB trace exists. Same discipline as the
    // root: count first, then no divergence, and a divergence is a
    // finding about the derivation, never a fixture to patch.
    assert_eq!(
        report.weights.compared(),
        expected_connected,
        "{}: {} of {} connected heights had recorded weights to compare against",
        manifest.shape,
        report.weights.compared(),
        expected_connected
    );
    let diverged: Vec<_> = report.weights.diverged().collect();
    assert!(
        diverged.is_empty(),
        "{} ({}): a derived weight value differs from the daemon's at {} height(s), first at \
         {:?} — a FINDING about CEN-G6/G6b's derivation, adjudicated against the spec, never a \
         fixture problem",
        manifest.shape,
        manifest.generator,
        diverged.len(),
        diverged.first()
    );
    // CEN-F14b / G12 (slice 7 commit 5): the verdict's accumulator against
    // the C++'s `block_info.bi_coins` at every connected height — the paid
    // reward at each height by difference, so the penalty curve is held
    // wherever a captured block is over the median (`median-full`, 211).
    // The expected value is Shekyl's ratified composition (FL-R12′: the
    // release-modulated, tail-floored emission under C2-R2 Q4's penalty,
    // `paid_block_reward`), which the C++ marshals; the C++ is the oracle
    // only insofar as it agrees with that. CEN-F17 / G11 (wave B): the
    // verdict's burn against the C++'s `block_burn` at the same heights —
    // the fee split over the FL-R16c supply and the escalation operand,
    // held wherever a captured block carries a fee. And every one of these
    // coinbases connected under CEN-F18: the C++ paid exactly what the
    // Rust derives it owed.
    assert_eq!(
        report.emission.compared(),
        expected_connected,
        "{}: {} of {} connected heights had a recorded accumulator and burn to compare against",
        manifest.shape,
        report.emission.compared(),
        expected_connected
    );
    let diverged: Vec<_> = report.emission.diverged().collect();
    assert!(
        diverged.is_empty(),
        "{} ({}): the derived accumulator or burn differs from the daemon's at {} height(s), \
         first at {:?} — a FINDING about CEN-F14b / G12 or CEN-F17 / G11's derivation, \
         adjudicated against the ratified composition, never a fixture problem",
        manifest.shape,
        manifest.generator,
        diverged.len(),
        diverged.first()
    );
    let (h0, connected_genesis) = report.connected[0];
    assert_eq!(h0, BlockHeight::from_raw(0));
    assert_eq!(
        hex_of(connected_genesis.as_bytes()),
        manifest.genesis_hash,
        "{}: the corpus's block 0 is not the genesis the manifest names",
        manifest.shape
    );
    // DRS-E4 §3.8 item 3: the replay applied exactly the injections the
    // manifest names, each at the height the daemon attributed it to — the
    // report's half of the out-of-band contract (the corpus's half is
    // `only_the_named_chains_carry_out_of_band_writes_and_the_corpus_carries_exactly_those`).
    // A chain that predates a rule applies exactly those attributed below
    // the refusal — none, on the one such chain today — and the rest wait
    // on the regeneration with the tip.
    let named: Vec<Injection> = manifest
        .out_of_band_writes
        .iter()
        .map(|r| r.receipt)
        .filter(|r| r.at.to_raw() < expected_connected)
        .collect();
    assert_eq!(
        report.injected, named,
        "{}: the replay's committed injections are not the manifest's receipts below height {}",
        manifest.shape, expected_connected
    );
    if let Some(txid) = &manifest.spend_txid {
        assert_eq!(
            txid.len(),
            64,
            "{}: spend_txid is a 32-byte hex hash",
            manifest.shape
        );
    }
    // The view-bound 4.I rows a real spend exercises, recorded on this
    // chain. The **witness** for each is the admission above — every
    // connected block passed with the row live, so the wallet-built spends
    // it carries passed it (for CEN-I18: a signature made with a real
    // HKDF-derived key over I17's derivation verified, which no harness
    // fixture can show, its keys being derived from the image rather than
    // the image from the key; for CEN-I13/I15: a declared depth and a
    // proof built over the tree at the reference, admitted and verified
    // there — slice 6 row 6's flip). This assertion is the weaker half: the
    // row was *run* here. It cannot say the row judged rather than recorded
    // vacuous (slice 5 Q2 — one bit per row, by design), which is why it is
    // paired with the refusal check rather than standing for it.
    for row in [
        "CEN-I7", "CEN-I10", "CEN-I11", "CEN-I12", "CEN-I13", "CEN-I15", "CEN-I17", "CEN-I18",
    ] {
        assert!(
            report.exercised.contains(row),
            "{}: {row} was not recorded on a chain carrying a real spend",
            manifest.shape
        );
    }
    // The tip-anchored comparisons: the daemon's digest and `0x04` record
    // are recorded at the chain's tip, so a chain that predates a rule has
    // nothing to compare them against — the run ended below the covered
    // height, and the report says so with `None` for both (**not
    // compared**, never identical). The pin over this chain's tip resumes
    // when the chain is regenerated.
    if let Some(record) = predates(&manifest.shape) {
        assert!(
            report.checkpoint.is_none() && report.archival.is_none(),
            "{}: refused at {:?} and yet compared at the tip — the trace's covered height is \
             below the refusal, or the report compared a tip it did not reach",
            manifest.shape,
            record.refused.0
        );
        return;
    }
    let checkpoint = report.checkpoint.as_ref().unwrap_or_else(|| {
        panic!(
            "{}: the trace carries the daemon's digest at the tip",
            manifest.shape
        )
    });
    assert!(
        checkpoint.identical(),
        "{}: the store's logical state after height {} differs from the daemon's — DIVERGE, \
         ours {:?} theirs {:?}",
        manifest.shape,
        checkpoint.at,
        checkpoint.ours,
        checkpoint.theirs
    );
    // The archival snapshot (§3.8.1) was COMPARED at the tip — the run
    // reached the covered height with a `0x04` record there — and it is
    // IDENTICAL, every family (the oracle, §6 row 8). A silent `None`
    // cannot read as agreement, and a diverged family is named, with its
    // row counts, so the message says which writer disagrees about what.
    // `ARW-26` (the slash-log key, `ARW-Q17`) does not reach this corpus:
    // no captured chain slashes (`ARW-13`), which `archival_sufficiency
    // _tests.rs` pre-declares rather than lets this line imply.
    let archival = report.archival.as_ref().unwrap_or_else(|| {
        panic!(
            "{}: the trace carries the daemon's archival snapshot at the tip",
            manifest.shape
        )
    });
    assert_eq!(archival.at, checkpoint.at);
    assert!(
        archival.identical(),
        "{}: the archival snapshot after height {} differs from the daemon's — DIVERGE:{}",
        manifest.shape,
        archival.at,
        archival
            .diff
            .diverged()
            .map(|d| {
                format!(
                    " {:?} ({} unequal, {} ours-only, {} theirs-only)",
                    d.family,
                    d.unequal.len(),
                    d.only_ours.len(),
                    d.only_theirs.len()
                )
            })
            .collect::<String>()
    );
}

/// **The consensus pin, made visible.** These blobs are valid against one
/// genesis and one rule set; a change of TXE-Q6′'s class — a grammar
/// closure, a constant regeneration, a row that alters what a valid block
/// is — invalidates all four chains at once, and without this check the
/// failure would arrive as 1,979 blocks refusing at block 1 for a reason
/// that reads as a validator bug. So the manifest carries the genesis the
/// chain was built from, and this holds it — before any block is judged —
/// to the genesis the **current build** pins: Fakechain is mainnet's
/// config (`cryptonote_config.h`: `case FAKECHAIN: return mainnet`), so
/// the pin is `ReleaseAnchors::MAINNET`'s, which slice 4 verifies by
/// equality against the C++ `GENESIS_TX`. A regeneration fails HERE with
/// "these vectors predate the current genesis", not at block 1.
fn genesis_is_the_current_builds(manifest: &Manifest) {
    let pinned = ReleaseAnchors::for_network(shekyl_address::Network::Mainnet)
        .expected_at(BlockHeight::from_raw(0))
        .expect("the release pins mainnet's genesis, which Fakechain shares");
    assert_eq!(
        manifest.genesis_hash,
        hex_of(pinned.as_bytes()),
        "{}: these vectors predate the current genesis — captured from a chain whose block 0 \
         is {} (built at dev {}), but this build pins {}. A TXE-Q6′-class change regenerated \
         genesis; re-capture every chain against a daemon built at the current tree \
         (SHEKYL_CAPTURE_CHAIN_VECTORS=1, the generators named in each manifest).",
        manifest.shape,
        manifest.genesis_hash,
        manifest.built_at_dev_sha,
        hex_of(pinned.as_bytes())
    );
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every captured chain connects whole against a real store and matches the
/// daemon's digest at its tip — under the mock longhash (D2 is not this
/// test's subject; see the module doc).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_captured_chain_replays_and_matches_the_daemons_digest() {
    // CEN-C1 refused block 1 as future-dated the first time this ran under
    // the mock's 2023 clock; the clock here is the REAL one — only the hash
    // is mocked, and the doc above says so.
    let substrate = mock_with_the_real_clock();
    for (dir, manifest) in captured_chains() {
        genesis_is_the_current_builds(&manifest);
        let report = replay(&dir, &manifest, Arc::clone(&substrate)).await;
        hold(&dir, &manifest, &report);
        let tip = match (&report.archival, predates(&manifest.shape)) {
            (Some(archival), _) => format!(
                "digest MATCH at {}, archival snapshot MATCH at {} ({} rows equal)",
                manifest.tip_height,
                archival.at,
                archival.diff.rows_equal()
            ),
            (None, Some(record)) => format!(
                "PREDATES {:?}: refused at {:?} as recorded, tip {} not compared",
                record.refused.1.rule, record.refused.0, manifest.tip_height
            ),
            (None, None) => unreachable!("held above"),
        };
        eprintln!(
            "{}: {} blocks connected, {tip}, roots MATCH at all {} heights, weights MATCH at \
             all {} heights, accumulator and burn MATCH at all {} heights, {} injection(s) \
             applied, rows exercised: {}",
            manifest.shape,
            report.connected.len(),
            report.roots.compared(),
            report.weights.compared(),
            report.emission.compared(),
            report.injected.len(),
            report.exercised.len()
        );
    }
}

/// The same, with RandomX judging every block — the D1/D2 witness. Slow
/// (~0.6 s a block in light mode; the depth-3 chain alone is minutes), so
/// it runs in the live lane, not on every `cargo test`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real RandomX over every captured chain; minutes. Run in the live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored replays_every_captured_chain_under_the_production_substrate"]
async fn replays_every_captured_chain_under_the_production_substrate() {
    let metrics = Arc::new(Metrics::new());
    let substrate = Arc::new(ProductionSubstrate::new(
        Arc::new(CacheStore::new()),
        Arc::clone(&metrics),
    ));
    for (dir, manifest) in captured_chains() {
        genesis_is_the_current_builds(&manifest);
        let report = replay(&dir, &manifest, substrate.clone()).await;
        hold(&dir, &manifest, &report);
    }
}

/// What one mutation can do on one captured chain: apply at some height,
/// or report why it cannot at every height.
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// The first height the mutation applies at.
    Applies { first: u64 },
    /// Every distinct cause the corpus reported, over every height, in
    /// first-seen order.
    Unmutable(Vec<Unmutable>),
}

fn note(causes: &mut Vec<Unmutable>, cause: Unmutable) {
    if !causes.contains(&cause) {
        causes.push(cause);
    }
}
/// Every candidate of one captured chain in connect order, with what the
/// chain strictly below it established (`Before`: the key images spent,
/// the first listed body) — the operands `Mutation::apply` takes. A
/// `Rewind` truncates, as the pipeline would, and the state after it is
/// the retained tip's **post-block** state: its `before` plus its own
/// contribution (the first cut took `spent_before` alone, which would have
/// called a `DoubleSpend` of the retained tip's image `NothingSpentBefore`
/// — Copilot on #880; no captured chain rewinds, so the census's answer
/// did not move).
fn corpus_candidates(dir: &Path) -> Vec<(u64, Candidate, Before)> {
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut height = reader.first_height().to_raw();
    let mut chain: Vec<(u64, Candidate, Before)> = Vec::new();
    let mut below = Before::default();
    while let Some(event) = reader.next().expect("corpus reads") {
        match event.event {
            IngestEvent::Extend(candidate) => {
                let before = below.clone();
                below.remember(&candidate);
                chain.push((height, *candidate, before));
                height += 1;
            }
            IngestEvent::Rewind { to } => {
                chain.truncate(usize::try_from(to.to_raw() + 1).expect("small"));
                below = match chain.last() {
                    None => Before::default(),
                    Some((_, tip, before)) => {
                        let mut after = before.clone();
                        after.remember(tip);
                        after
                    }
                };
                height = to.to_raw() + 1;
            }
            // An inject occupies no height and lists no body: nothing a
            // block mutation could take as an operand.
            IngestEvent::Inject(_) => {}
        }
    }
    chain
}

/// E6 slice 7 commit 2 (d): **the `Unmutable` census** (`CHAIN_RULES_SLICE_7.md`
/// §3.7). The E2 family is judged over the harness chain, never over these
/// captured chains; this test asks, for every mutation and every captured
/// chain, whether the mutation *could* apply there at all — and holds the
/// answer, so a mutation that is `Unmutable` on every chain in the corpus
/// is a recorded fact about the corpus's shape rather than a status a
/// reader mistakes for coverage.
///
/// Two causes are not the corpus's and are named apart: `PowUnderWrongSeed`
/// needs a PoW environment this census does not supply, and `DoubleSpend`
/// at a chain's first spend has nothing spent before it (it applies from
/// the second). Everything else that is `Unmutable` everywhere is a hole in
/// what the corpus carries.
#[test]
fn the_family_over_the_corpus_names_what_it_cannot_reach() {
    let chains = captured_chains();
    // A corpus chain brings no spare bodies and no twins, and the bound
    // is the validator's: the weight and the signed-twin mutation are
    // `Unmutable` here by construction, and the census says so below.
    let env = Environment {
        clock: MockSubstrate::CLOCK,
        pow: None,
        overweight: None,
        twins: &[],
    };
    // Per mutation (by its position in `Mutation::ALL`): `Some(causes)`
    // while it has been unreachable on every chain so far, `None` once one
    // chain carried it.
    let mut everywhere_unmutable: Vec<Option<Vec<Unmutable>>> =
        vec![Some(Vec::new()); Mutation::ALL.len()];
    let mut table = String::new();
    for (dir, manifest) in &chains {
        let candidates = corpus_candidates(dir);
        assert!(
            !candidates.is_empty(),
            "{}: the corpus has blocks",
            manifest.shape
        );
        for (i, mutation) in Mutation::ALL.into_iter().enumerate() {
            let mut causes = Vec::new();
            let mut reach = None;
            for (height, candidate, before) in &candidates {
                match mutation.apply(candidate.clone(), &env, before, h(*height)) {
                    Ok(_) => {
                        reach = Some(Reach::Applies { first: *height });
                        break;
                    }
                    Err(cause) => note(&mut causes, cause),
                }
            }
            let reach = reach.unwrap_or(Reach::Unmutable(causes));
            use std::fmt::Write as _;
            writeln!(
                table,
                "{:<16} {:<22} {reach:?}",
                manifest.shape,
                format!("{mutation:?}")
            )
            .expect("String write");
            match (reach, &mut everywhere_unmutable[i]) {
                (Reach::Unmutable(causes), Some(all)) => {
                    for cause in causes {
                        note(all, cause);
                    }
                }
                (Reach::Applies { .. }, slot) => *slot = None,
                (Reach::Unmutable(_), None) => {}
            }
        }
    }
    eprintln!(
        "Unmutable census over {} captured chains:\n{table}",
        chains.len()
    );

    let unreachable: Vec<(Mutation, Vec<Unmutable>)> = Mutation::ALL
        .into_iter()
        .zip(everywhere_unmutable)
        .filter_map(|(m, causes)| causes.map(|c| (m, c)))
        .collect();
    // Four entries, and the census says whose — the environment's or the
    // corpus's, never the family's. `PowUnderWrongSeed`: this census
    // carries no PoW leg. `OverweightBlock`: no body supply — the corpus
    // census judges captured blocks as they are. `DuplicateBondPost`: this
    // census supplies no twins, and the *other* cause —
    // `NoArchivalBodyToDuplicate` — is the heights that carry no post,
    // which is a reading of the corpus: the bond-post capture does carry
    // the body, so a twin supply would reach it. (`DuplicateClaim` was the
    // fifth until slice 8 row 9 retired it to the driver — `Mutation`
    // docs.) `DuplicateServeCredit` needs no supply (its
    // twin is the body itself) and is unreachable on the corpus alone: no
    // captured chain carries a serve credit. `ReorderedBodies` was the
    // corpus's until 2026-09-28 — every captured block listed at most one
    // body (slice 6 §5 row 8 measured it; slice 7 §3.7 names the class) —
    // and is reachable since the `median-full` capture (slice 7 commit
    // 4 (c)): its block 211 lists 23 bodies, so the mutations that need two
    // have a corpus witness there. A change here is a change in the
    // corpus's shape or in the family, and §3.7 moves with it.
    assert_eq!(
        unreachable,
        vec![
            (
                Mutation::PowUnderWrongSeed,
                vec![Unmutable::NoPowEnvironment]
            ),
            (
                Mutation::DuplicateServeCredit,
                vec![Unmutable::NoArchivalBodyToDuplicate {
                    kind: ArchivalKind::ServeCredit
                }]
            ),
            (
                Mutation::DuplicateBondPost,
                vec![
                    Unmutable::NoArchivalBodyToDuplicate {
                        kind: ArchivalKind::BondPost
                    },
                    Unmutable::NoTwinSupplied {
                        kind: ArchivalKind::BondPost
                    },
                ]
            ),
            (Mutation::OverweightBlock, vec![Unmutable::NoBodySupply]),
        ],
        "the mutations no captured chain can carry, with why"
    );
}
