// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival oracle's **sufficiency stamp** (`DRS_E4_ARCHIVAL_WRITER.md`
//! §3.8 item 2, §6 row 8).
//!
//! `vectors_tests.rs` asserts the redb archival rows are *identical* to
//! the daemon's at every captured tip. On its own that is the weak claim:
//! a comparator that is blind to a family is identical on it forever. The
//! stamp is the two halves that make the claim strong, and the one that
//! says, family by family, where it is not:
//!
//! 1. **Census.** Which families the corpus actually exercises, per chain,
//!    read off the six committed `0x04` records and asserted in **both**
//!    directions against the table pre-declared in E4 §6 row 8 before this
//!    ran. A family the table says is exercised and is not, or one that is
//!    and the table omits, fails here — the corpus is enumerated, not
//!    discovered.
//! 2. **Stub.** For every family the corpus witnesses, the witness chain is
//!    replayed with that family's writer stubbed ([`ApplyPolicy::stubbed`]),
//!    and the run must go red — by the oracle naming that family, or by a
//!    connect that could not proceed without the rows (a cascade, recorded
//!    as the outcome rather than hidden behind "not green"). A stub the
//!    oracle shrugs at is a family the identical-assertion cannot see.
//!
//! The families the corpus does **not** witness are the stamp's declared
//! red, enumerated by the exhaustive [`witness`] match so a family added to
//! the X-macro without a witness does not compile: the slash families
//! (`ARW-13`: no capture slashes, which is §6.2 item 5's decision point,
//! posed as `ARW-Q18`) and the attestation witness. For them this module
//! asserts the *absence* — zero rows on every chain — so the empty slash
//! rows of every `0x04` record are a pre-declared fact of the corpus, not a
//! silence the oracle happens to agree with. One cell cuts across that
//! line and the first census run found it: the slash **watermark** is the
//! deadline scan's progress, not a slash, and the epoch-crossing chain
//! carries it — so the `SlashLog` *gate* has a stub witness through the
//! watermark while the slash *rows* have none.

use std::collections::BTreeMap;
use std::sync::Arc;

use shekyl_chain_store::apply_policy::{ApplyPolicy, ArchivalFamily};
use shekyl_chain_store::archival_snapshot::{disposition, Disposition, SnapshotFamily};

use crate::trace::Trace;
use crate::vectors_tests::{captured_chains, mock_with_the_real_clock, replay_under, Manifest};

/// What stands behind a family's `identical` at the captured tips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Witness {
    /// A captured chain whose `0x04` record carries rows of this family;
    /// the stub half replays it.
    Corpus {
        shape: &'static str,
        rows: SnapshotFamily,
    },
    /// The snapshot would carry it and no captured chain writes it — the
    /// declared red. The census asserts zero rows on every chain.
    Unwitnessed {
        rows: SnapshotFamily,
        why: &'static str,
    },
    /// Not in the snapshot (§3.8.1 "Not in the snapshot"); the stamp has
    /// nothing to compare. The reason is [`disposition`]'s.
    Excluded(&'static str),
}

/// The witness table, exhaustive over the X-macro. Pre-declared in E4 §6
/// row 8 (2026-10-02) before the census ran.
const fn witness(family: ArchivalFamily) -> Witness {
    match family {
        ArchivalFamily::Bond => Witness::Corpus {
            shape: "bond-post",
            rows: SnapshotFamily::Bond,
        },
        // The one chain that crosses an epoch (SEB 512) and carries the one
        // out-of-band credit: the close and everything it writes live here.
        ArchivalFamily::ServeCredit => Witness::Corpus {
            shape: "emission-claim",
            rows: SnapshotFamily::ServeCredit,
        },
        ArchivalFamily::RMarket => Witness::Corpus {
            shape: "emission-claim",
            rows: SnapshotFamily::RMarket,
        },
        ArchivalFamily::SigmaWork => Witness::Corpus {
            shape: "emission-claim",
            rows: SnapshotFamily::SigmaWork,
        },
        ArchivalFamily::Budget => Witness::Corpus {
            shape: "emission-claim",
            rows: SnapshotFamily::Budget,
        },
        // Every chain carries the open epoch's one accruing row; the
        // smallest is the witness.
        ArchivalFamily::BudgetAccrual => Witness::Corpus {
            shape: "spend-1in-2out",
            rows: SnapshotFamily::BudgetAccruing,
        },
        ArchivalFamily::AttestationWitness => Witness::Unwitnessed {
            rows: SnapshotFamily::AttestationWitness,
            why: "no captured chain carries an attestation transaction; the serve credit the \
                  corpus has is injected (`IngestEvent::Inject`), not attested",
        },
        ArchivalFamily::SlashLog => Witness::Unwitnessed {
            rows: SnapshotFamily::SlashLog,
            why: "ARW-13: no capture slashes — E4 §6.2 item 5's deferred slash-bearing \
                  capture, posed as ARW-Q18; the m-of-n fixture is evidence of the two \
                  writers' disagreement (ARW-26 / ARW-Q17), not a corpus witness. The \
                  family's *gate* is seen through the watermark cell \
                  (`stubbing_the_slash_log_is_noticed_through_the_watermark_alone`); its \
                  rows are not",
        },
        ArchivalFamily::SlashApplied => Witness::Unwitnessed {
            rows: SnapshotFamily::SlashApplied,
            why: "ARW-13: no capture slashes (as SlashLog)",
        },
        ArchivalFamily::Settlement
        | ArchivalFamily::AltAttestationWitness
        | ArchivalFamily::ShardSegment
        | ArchivalFamily::EmissionClaimLog
        | ArchivalFamily::BondUnbondLog
        | ArchivalFamily::BondHoldingsUpdateLog
        | ArchivalFamily::BondReinstateLog
        | ArchivalFamily::EpochCloseLog => match disposition(family) {
            Disposition::Excluded(why) => Witness::Excluded(why),
            // Unreachable by the table above; spelled so a disposition
            // change here is a compile-time question, not a silent one.
            Disposition::Rows(_) => Witness::Excluded("disposition moved: re-witness this family"),
        },
    }
}

/// The census pre-declared in E4 §6 row 8: which snapshot families carry
/// rows on which captured chain.
///
/// `LastSlashEpoch` has no X-macro family. The pre-declaration (written
/// before this ran) put it with the slash rows — on no chain — and the
/// first census run refuted that: the watermark is the **deadline scan's
/// progress**, moved when an epoch's slash deadline passes whether or not
/// anything was slashed, so `emission-claim` (the one chain that crosses
/// an epoch) carries it with no slash behind it. Corrected 2026-10-02 in
/// E4 §6 row 8; the slash *rows* stay on no chain, as pre-declared.
fn expected_census() -> BTreeMap<&'static str, Vec<SnapshotFamily>> {
    use SnapshotFamily::{
        Bond, Budget, BudgetAccruing, LastSlashEpoch, RMarket, ServeCredit, SigmaWork,
    };
    BTreeMap::from([
        ("bond-post", vec![Bond, BudgetAccruing]),
        (
            "emission-claim",
            vec![
                Bond,
                ServeCredit,
                RMarket,
                SigmaWork,
                Budget,
                BudgetAccruing,
                LastSlashEpoch,
            ],
        ),
        ("limit-full", vec![BudgetAccruing]),
        ("median-full", vec![BudgetAccruing]),
        ("spend-1in-2out", vec![BudgetAccruing]),
        ("spend-depth3", vec![BudgetAccruing]),
    ])
}

/// The daemon's `0x04` record at a captured chain's tip, read from the
/// committed trace — no replay; the census is a fact about the corpus.
fn captured_snapshot(dir: &std::path::Path, manifest: &Manifest) -> Vec<SnapshotFamily> {
    let trace = std::fs::read(dir.join("trace.e2")).expect("read trace.e2");
    let trace = Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace");
    let (_, theirs) = trace
        .archival_snapshot()
        .unwrap_or_else(|| panic!("{}: the trace carries a 0x04 record", manifest.shape));
    SnapshotFamily::ALL
        .into_iter()
        .filter(|f| !theirs.value().rows(*f).is_empty())
        .collect()
}

/// The witness table agrees with the snapshot's disposition table, family
/// by family: a corpus or no-corpus witness names exactly the snapshot
/// family the disposition carries, and an exclusion is the disposition's.
#[test]
fn every_family_has_a_witness_that_matches_its_disposition() {
    for family in ArchivalFamily::ALL {
        match (witness(family), disposition(family)) {
            (Witness::Corpus { rows, .. } | Witness::Unwitnessed { rows, .. }, d) => {
                assert_eq!(
                    d,
                    Disposition::Rows(rows),
                    "{family:?}: the witness names {rows:?}, the snapshot's disposition is {d:?}"
                );
            }
            (Witness::Excluded(why), Disposition::Excluded(reason)) => {
                assert_eq!(why, reason, "{family:?}");
            }
            (Witness::Excluded(why), Disposition::Rows(rows)) => {
                panic!("{family:?}: excluded from the stamp ({why}) but the snapshot carries it as {rows:?}");
            }
        }
    }
    // Every snapshot family but the watermark cell is some X-macro
    // family's witness target; the cell rides `SlashLog`'s gate and has
    // its own census row and stub test below.
    for rows in SnapshotFamily::ALL {
        if rows == SnapshotFamily::LastSlashEpoch {
            continue;
        }
        assert!(
            ArchivalFamily::ALL.into_iter().any(|f| matches!(
                witness(f),
                Witness::Corpus { rows: r, .. } | Witness::Unwitnessed { rows: r, .. } if r == rows
            )),
            "{rows:?} is carried by the snapshot and witnessed by no family"
        );
    }
}

/// Census, both directions: the six committed `0x04` records carry rows of
/// exactly the families E4 §6 row 8 pre-declared, chain by chain; every
/// corpus witness is on its named chain; every no-corpus family is empty
/// everywhere — the slash rows of all six are empty, as pre-declared.
#[test]
fn the_corpus_exercises_exactly_the_predeclared_families() {
    let expected = expected_census();
    let chains = captured_chains();
    assert_eq!(
        chains.len(),
        expected.len(),
        "the census table names every captured chain"
    );
    let mut actual: BTreeMap<String, Vec<SnapshotFamily>> = BTreeMap::new();
    for (dir, manifest) in &chains {
        let families = captured_snapshot(dir, manifest);
        let want = expected
            .get(manifest.shape.as_str())
            .unwrap_or_else(|| panic!("{}: not in the pre-declared census", manifest.shape));
        let mut want = want.clone();
        want.sort();
        assert_eq!(
            families, want,
            "{}: the 0x04 record's non-empty families are not the pre-declared ones (left: \
             captured, right: E4 §6 row 8)",
            manifest.shape
        );
        eprintln!("{}: rows in {:?}", manifest.shape, families);
        actual.insert(manifest.shape.clone(), families);
    }
    for family in ArchivalFamily::ALL {
        match witness(family) {
            Witness::Corpus { shape, rows } => assert!(
                actual[shape].contains(&rows),
                "{family:?}: its witness chain `{shape}` carries no {rows:?} rows"
            ),
            Witness::Unwitnessed { rows, why } => {
                for (shape, families) in &actual {
                    assert!(
                        !families.contains(&rows),
                        "{family:?}: declared without a corpus witness ({why}), but `{shape}` \
                         carries {rows:?} rows — the declaration is stale; witness it"
                    );
                }
            }
            Witness::Excluded(_) => {}
        }
    }
    // The watermark cell sits exactly where a slash deadline passed and
    // nowhere a slash happened: on the epoch-crossing chain alone, beside
    // empty slash rows. A watermark on a chain whose epoch never closed, or
    // a slash row anywhere, is a corpus change this table must learn first.
    let with_watermark: Vec<&String> = actual
        .iter()
        .filter(|(_, f)| f.contains(&SnapshotFamily::LastSlashEpoch))
        .map(|(shape, _)| shape)
        .collect();
    assert_eq!(
        with_watermark,
        vec!["emission-claim"],
        "the slash watermark is the deadline scan's progress, carried by the one chain that \
         crosses an epoch"
    );
}

/// The watermark's stub witness. `LastSlashEpoch` is a `properties` cell
/// with no X-macro family; its write is gated by `SlashLog`'s apply
/// (`archival_write.rs` `write_slashes`: `if log_applies`). So the
/// `SlashLog` *gate* has a corpus witness even though the slash *rows* do
/// not — stubbing `SlashLog` on `emission-claim` must go red on the
/// watermark and on nothing else, which is the exact shape of the declared
/// red: the gate is seen, the rows are not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stubbing_the_slash_log_is_noticed_through_the_watermark_alone() {
    let substrate = mock_with_the_real_clock();
    let chains = captured_chains();
    let (dir, manifest) = chains
        .iter()
        .find(|(_, m)| m.shape == "emission-claim")
        .expect("emission-claim is captured");
    let policy = ApplyPolicy::stubbed(&[ArchivalFamily::SlashLog]).expect("non-empty");
    let report = replay_under(dir, manifest, substrate, policy)
        .await
        .expect("no row the chain's blocks need is behind the slash log's gate");
    assert!(report.refused.is_none(), "{:?}", report.refused);
    let archival = report.archival.as_ref().expect("the tip was compared");
    let diverged: Vec<SnapshotFamily> = archival.diff.diverged().map(|d| d.family).collect();
    assert_eq!(
        diverged,
        vec![SnapshotFamily::LastSlashEpoch],
        "SlashLog stubbed on `emission-claim`: the watermark is the one row the corpus has \
         behind this gate"
    );
}

/// How a stubbed replay went red.
#[derive(Debug)]
enum Red {
    /// The run reached the tip and the oracle named these families.
    Diverged(Vec<SnapshotFamily>),
    /// The run ended before the tip: a refusal at the height, or a store
    /// fault — a cascade of the missing rows, recorded as such.
    Cascade(String),
}

/// Stub half: each corpus-witnessed family's writer, stubbed on its
/// witness chain, is noticed — by the oracle naming the family, or by a
/// cascade. A stubbed family the run stays green on is a family the
/// identical-assertion in `vectors_tests.rs` cannot see.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stubbing_each_witnessed_family_is_noticed() {
    let substrate = mock_with_the_real_clock();
    let chains = captured_chains();
    for family in ArchivalFamily::ALL {
        let Witness::Corpus { shape, rows } = witness(family) else {
            continue;
        };
        let (dir, manifest) = chains
            .iter()
            .find(|(_, m)| m.shape == shape)
            .unwrap_or_else(|| panic!("{family:?}: witness chain `{shape}` is captured"));
        let policy = ApplyPolicy::stubbed(&[family]).expect("one family is not empty");
        let red = match replay_under(dir, manifest, Arc::clone(&substrate), policy).await {
            Err(fault) => Red::Cascade(fault),
            Ok(report) => match (&report.refused, &report.archival) {
                (Some(refused), _) => Red::Cascade(format!("refused: {refused:?}")),
                // Neither red nor compared is not a stub's doing — the
                // trace or the run lost the tip. A finding, not an outcome.
                (None, None) => panic!(
                    "{family:?} stubbed on `{shape}`: the run connected every block and \
                     compared no snapshot"
                ),
                (None, Some(archival)) => {
                    Red::Diverged(archival.diff.diverged().map(|d| d.family).collect())
                }
            },
        };
        match &red {
            Red::Diverged(diverged) => {
                eprintln!("{family:?} stubbed on `{shape}`: the oracle diverged on {diverged:?}");
                assert!(
                    diverged.contains(&rows),
                    "{family:?} stubbed on `{shape}`: the oracle diverged on {diverged:?} and \
                     not on {rows:?} — the comparator does not see this family"
                );
            }
            Red::Cascade(how) => {
                eprintln!("{family:?} stubbed on `{shape}`: cascade before the tip — {how}");
            }
        }
    }
}
