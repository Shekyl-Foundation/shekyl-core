// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The forge's determinism check (`CHAIN_FORGE.md` §9, `CF-1c`).
//!
//! The small plan (`plans/small.toml`) is forged twice, in two processes
//! that differ in everything a forging must not depend on: the runtime's
//! thread count and the trace's hasher count, the working directory, the
//! time zone and the locale. The two outputs must be the same byte for
//! byte, and the committed `blocks.txt` and manifest
//! (`chains/small/`) must be what both wrote. The manifest pins the corpus
//! and the trace by SHA-256, so holding it holds them. Each architecture's
//! CI leg runs this against the same committed files, so the two legs
//! agree only if both forge the committed chain.
//!
//! Two processes, not one: a value memoized in a process (the rules
//! fixture's signatures, `CHAIN_FORGE.md` §5.2) is the same twice in one
//! process and differs across two.
//!
//! The check proves it can fail. Its selftest flips one byte of each file a
//! forging wrote and holds the comparison red, naming the file. Each source
//! of randomness has a negative control: forged again with that one source
//! drawing from the OS, the chain must differ from the committed ledger, at
//! the first block the source reaches (the forging stops there). A control
//! that stayed green would be a source the plan never reached, or a seam
//! that ignored its seed.
//!
//! The forgings are minutes of proofs, so every test here is ignored in
//! the workspace run and run by `chain-forge.yml`, in release.

#[allow(
    dead_code,
    reason = "each test-kind target uses part of the executor; this one forges in child processes"
)]
#[path = "../executor/mod.rs"]
mod executor;

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;

use executor::seeds::Source;
use executor::{forge, Options, Outcome, BLOCKS_FILE, FILES, MANIFEST_FILE};
use shekyl_chain_forge::{sha256_hex, BlocksTxt, Manifest, Plan, PlanRef};
use shekyl_corpus::CORPUS_FORMAT_VERSION;

/// The plan, from the crate's directory.
const PLAN: &str = "plans/small.toml";
/// The committed `blocks.txt` and manifest, from the crate's directory.
const COMMITTED: &str = "chains/small";
/// The hosted shard-fill chain: its name, plan and committed ledger.
const SHARD_FILL: &str = "shard-fill";
const SHARD_FILL_PLAN: &str = "plans/shard-fill.toml";
const SHARD_FILL_COMMITTED: &str = "chains/shard-fill";
/// Chain L (`CF-4b`): hosted like the shard-fill chain.
const CHAIN_L: &str = "chain-l";
const CHAIN_L_PLAN: &str = "plans/chain-l.toml";
const CHAIN_L_COMMITTED: &str = "chains/chain-l";

/// The child process's switches: the directory it writes, the sources it
/// swaps, and the ledger it stops at.
const CHILD_OUT: &str = "SHEKYL_FORGE_CHILD_OUT";
const CHILD_SWAP: &str = "SHEKYL_FORGE_CHILD_SWAP";
const CHILD_STOP_AT: &str = "SHEKYL_FORGE_CHILD_STOP_AT";
const CHILD_HASHERS: &str = "SHEKYL_FORGE_CHILD_HASHERS";
/// The plan the child forges, from the crate's directory; the small plan
/// when unset.
const CHILD_PLAN: &str = "SHEKYL_FORGE_CHILD_PLAN";
/// The producer's start spread, in milliseconds.
const CHILD_SPREAD_MS: &str = "SHEKYL_FORGE_CHILD_SPREAD_MS";
/// Where the small plan's test keeps one forging, when set: the nightly
/// replays it with `shekyl-chain-replay` (chain-forge.yml).
const KEEP_SMALL: &str = "SHEKYL_FORGE_KEEP_SMALL";
/// What the child wrote when it stopped at a difference.
const STOPPED_FILE: &str = "stopped.txt";

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The environments the two forgings run in. Everything here is a reason a
/// forged chain might differ, and must not.
struct Environment {
    name: &'static str,
    tokio_threads: &'static str,
    hashers: &'static str,
    time_zone: &'static str,
    locale: &'static str,
}

const ENVIRONMENTS: [Environment; 2] = [
    Environment {
        name: "one-thread-utc-c",
        tokio_threads: "1",
        hashers: "2",
        time_zone: "UTC",
        locale: "C",
    },
    Environment {
        name: "many-threads-chatham-turkish",
        tokio_threads: "7",
        hashers: "4",
        // UTC+12:45, and a locale whose case mapping of `i` is not ASCII's.
        time_zone: "Pacific/Chatham",
        locale: "tr_TR.UTF-8",
    },
];

/// Run this test binary's [`child_forge`] in its own process, under `env`,
/// writing to `out`, from a working directory of its own.
fn spawn_child(
    env: &Environment,
    out: &Path,
    swap: Option<Source>,
    stop_at: Option<&Path>,
) -> std::process::ExitStatus {
    let mut vars: Vec<(&str, String)> = Vec::new();
    if let Some(source) = swap {
        vars.push((CHILD_SWAP, source.name().to_owned()));
    }
    if let Some(ledger) = stop_at {
        vars.push((CHILD_STOP_AT, ledger.display().to_string()));
    }
    let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
    spawn_child_with(env, out, &vars)
}

/// [`spawn_child`] with the child's switches as `vars`.
fn spawn_child_with(
    env: &Environment,
    out: &Path,
    vars: &[(&str, &str)],
) -> std::process::ExitStatus {
    let cwd = tempfile::Builder::new()
        .prefix(&format!("forge-cwd-{}-", env.name))
        .tempdir()
        .expect("a working directory");
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args([
            "child_forge",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(cwd.path())
        .env(CHILD_OUT, out)
        .env(CHILD_HASHERS, env.hashers)
        .env("TOKIO_WORKER_THREADS", env.tokio_threads)
        .env("TZ", env.time_zone)
        .env("LC_ALL", env.locale)
        .env("LANG", env.locale);
    for (name, value) in vars {
        command.env(name, value);
    }
    command.status().expect("the child forging runs")
}

/// The forging a parent test runs in a child process. Without the parent's
/// switches it does nothing: it is not a test of its own.
#[test]
#[ignore = "the child process of the determinism check; run by its parent"]
fn child_forge() {
    let Some(out) = std::env::var_os(CHILD_OUT).map(PathBuf::from) else {
        return;
    };
    let plan_name = std::env::var(CHILD_PLAN).unwrap_or_else(|_| PLAN.to_owned());
    let plan_path = crate_dir().join(&plan_name);
    let bytes = std::fs::read(&plan_path).expect("the plan reads");
    let plan = Plan::parse(std::str::from_utf8(&bytes).expect("utf-8")).expect("the plan parses");
    let plan_ref = PlanRef {
        path: format!("rust/shekyl-chain-forge/{plan_name}"),
        sha256: sha256_hex(&bytes),
    };
    let swapped: BTreeSet<Source> = std::env::var(CHILD_SWAP)
        .ok()
        .map(|name| Source::named(&name).expect("a source the parent named"))
        .into_iter()
        .collect();
    let stop_at_difference = std::env::var_os(CHILD_STOP_AT).map(|path| {
        BlocksTxt::parse(&std::fs::read_to_string(path).expect("the ledger reads"))
            .expect("the committed ledger parses")
    });
    let hashers: NonZeroUsize = std::env::var(CHILD_HASHERS)
        .expect("the parent names the hashers")
        .parse()
        .expect("a count");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = runtime
        .block_on(forge(
            &plan,
            plan_ref,
            &out,
            Options {
                swapped,
                stop_at_difference,
                hashers,
                producer: executor::ProducerOptions {
                    live: false,
                    start_spread: std::env::var(CHILD_SPREAD_MS).ok().map(|ms| {
                        std::time::Duration::from_millis(
                            ms.parse().expect("a count of milliseconds"),
                        )
                    }),
                },
            },
        ))
        .expect("the forging finishes");
    match outcome {
        Outcome::Forged(forged) => {
            assert_eq!(
                forged.blocks.lines().len(),
                usize::try_from(forged.manifest.blocks).expect("fits")
            );
        }
        Outcome::Differed { blocks, difference } => {
            std::fs::write(
                out.join(STOPPED_FILE),
                format!("{} {difference}\n", blocks.lines().len()),
            )
            .expect("the stop is recorded");
        }
    }
}

/// The first difference between two forgings' directories, naming the file
/// and, for `blocks.txt`, the first differing block; `None` when every file
/// is the same.
fn first_difference(a: &Path, b: &Path) -> Option<String> {
    for file in FILES {
        let left = std::fs::read(a.join(file)).unwrap_or_default();
        let right = std::fs::read(b.join(file)).unwrap_or_default();
        if left == right {
            continue;
        }
        if file == BLOCKS_FILE {
            let parse = |bytes: &[u8]| {
                BlocksTxt::parse(std::str::from_utf8(bytes).unwrap_or_default()).ok()
            };
            if let (Some(l), Some(r)) = (parse(&left), parse(&right)) {
                if let Some(difference) = l.first_difference(&r) {
                    return Some(format!("{file}: {difference}"));
                }
            }
        }
        let at = left
            .iter()
            .zip(&right)
            .position(|(l, r)| l != r)
            .unwrap_or(left.len().min(right.len()));
        return Some(format!(
            "{file}: first differing byte at {at} ({} bytes against {})",
            left.len(),
            right.len()
        ));
    }
    None
}

/// The two-process check, the committed ledger and manifest, and the
/// selftest that a one-byte change in any file is red.
#[test]
#[ignore = "minutes of proofs; run in release by chain-forge.yml"]
fn the_small_plan_forges_the_same_bytes_in_two_processes() {
    let outs = forge_in_two_processes("small", PLAN);
    let (a, b) = (outs[0].path(), outs[1].path());
    if let Some(difference) = first_difference(a, b) {
        panic!("two forgings of one plan at one commit differ: {difference}");
    }

    // Both are the committed chain.
    let committed = crate_dir().join(COMMITTED);
    for file in [BLOCKS_FILE, MANIFEST_FILE] {
        let ours = std::fs::read_to_string(a.join(file)).expect("forged");
        let theirs = std::fs::read_to_string(committed.join(file))
            .unwrap_or_else(|e| panic!("{}: {e}", committed.join(file).display()));
        if file == BLOCKS_FILE {
            let ours = BlocksTxt::parse(&ours).expect("parses");
            let theirs = BlocksTxt::parse(&theirs).expect("the committed ledger parses");
            if let Some(difference) = ours.first_difference(&theirs) {
                panic!(
                    "the forged chain is not the committed one (ours, committed): {difference}. \
                     A change that moves a forged block regenerates the committed files in the \
                     same pull request (CHAIN_FORGE.md §9)"
                );
            }
        }
        assert_eq!(
            ours, theirs,
            "{file} is not the committed one; regenerate it in this pull request (§9)"
        );
    }
    let manifest = Manifest::parse(&std::fs::read_to_string(a.join(MANIFEST_FILE)).expect("read"))
        .expect("the manifest parses");
    for (file, pinned) in [
        ("corpus.e2", &manifest.corpus_sha256),
        ("trace.e2", &manifest.trace_sha256),
    ] {
        assert_eq!(
            &sha256_hex(&std::fs::read(a.join(file)).expect("forged")),
            pinned,
            "the manifest pins {file}"
        );
    }

    // The nightly replays this forging with the standalone replay binary
    // and holds its switch to the manifest (chain-forge.yml); a run that
    // names a directory here keeps one forging for it.
    if let Some(keep) = std::env::var_os(KEEP_SMALL).filter(|dir| !dir.is_empty()) {
        let keep = PathBuf::from(keep);
        std::fs::create_dir_all(&keep).expect("the kept forging's directory");
        for file in FILES {
            std::fs::copy(a.join(file), keep.join(file)).expect("the forging kept");
        }
    }

    // The selftest: one flipped byte in any file is red, and names it.
    let flipped = tempfile::tempdir().expect("a directory");
    for file in FILES {
        for other in FILES {
            std::fs::copy(b.join(other), flipped.path().join(other)).expect("copied");
        }
        let path = flipped.path().join(file);
        let mut bytes = std::fs::read(&path).expect("read");
        let middle = bytes.len() / 2;
        // A digit stays a digit and a hex digit stays one, so the ledger
        // still parses and its comparison names the block.
        bytes[middle] = match bytes[middle] {
            b'0' => b'1',
            b'\n' | b' ' => bytes[middle],
            byte => byte ^ 0x01,
        };
        if bytes == std::fs::read(&path).expect("read") {
            bytes[middle - 1] ^= 0x01;
        }
        std::fs::write(&path, &bytes).expect("written");
        let difference = first_difference(a, flipped.path())
            .unwrap_or_else(|| panic!("a flipped byte in {file} is not seen"));
        assert!(
            difference.starts_with(file),
            "the flip in {file} is named: {difference}"
        );
    }
}

/// Where `source` first moves the chain, as lines of `blocks.txt` (from 1):
/// above the first and at most the second. Read off the committed
/// manifest's events, so a plan that moves its events moves these with it.
/// A source swapped to the OS must change the first block that draws from
/// it, and none before: a control that differs earlier is one source's
/// swap moving another's bytes, which `seed_for`'s roles exist to prevent.
fn first_moves(source: Source, manifest: &Manifest) -> (usize, usize) {
    let line = |name: &str| {
        let event = manifest
            .events
            .iter()
            .find(|event| event.name == name)
            .unwrap_or_else(|| panic!("the committed manifest indexes {name}"));
        usize::try_from(event.record).expect("fits") + 1
    };
    let at = |line: usize| (line - 1, line);
    match source {
        // The plan's first spend, two inputs: its range proof, its first
        // input's blind, its membership proof, its slots.
        Source::S1 | Source::S2 | Source::S3 | Source::S5 => at(line("first-spend-2in")),
        // The shard fill's spends, after the first spend.
        Source::S9 => (line("first-spend-2in"), line("shard-0-closed")),
        // The block after the join commits the served epoch's first draw.
        Source::S7 => at(line("first-compact-join") + 1),
        // The first bundle, filed for a drawing block and carried by the
        // next block, inside the served epoch.
        Source::S8 => (line("first-compact-join") + 1, line("first-serve-credit")),
        // The claim's backing proof.
        Source::S4 => at(line("first-claim")),
    }
}

/// One negative control per source of randomness: that source swapped to
/// the OS's, the forging differs from the committed ledger, at the first
/// block that draws from it.
#[test]
#[ignore = "a forging per source, up to the source's first block; run by chain-forge.yml"]
fn each_source_drawn_from_the_os_moves_the_chain() {
    let committed = crate_dir().join(COMMITTED);
    let ledger_path = committed.join(BLOCKS_FILE);
    let ledger = BlocksTxt::parse(&std::fs::read_to_string(&ledger_path).expect("committed"))
        .expect("the committed ledger parses");
    let manifest = Manifest::parse(
        &std::fs::read_to_string(committed.join(MANIFEST_FILE)).expect("committed"),
    )
    .expect("the committed manifest parses");
    for source in Source::ALL {
        let out = tempfile::tempdir().expect("a directory");
        let started = std::time::Instant::now();
        let status = spawn_child(
            &ENVIRONMENTS[0],
            out.path(),
            Some(source),
            Some(&ledger_path),
        );
        assert!(
            status.success(),
            "the {} control failed: {status}",
            source.name()
        );
        let stopped = std::fs::read_to_string(out.path().join(STOPPED_FILE)).unwrap_or_else(|_| {
            panic!(
                "{} drawn from the OS forged the committed chain: the check cannot see it",
                source.name()
            )
        });
        eprintln!(
            "{}: red at {} ({:.1} s)",
            source.name(),
            stopped.trim(),
            started.elapsed().as_secs_f64()
        );
        let line: usize = stopped
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .expect("the stop names its line");
        assert!(
            line <= ledger.lines().len(),
            "{} stopped inside the chain",
            source.name()
        );
        let (after, through) = first_moves(source, &manifest);
        assert!(
            after < line && line <= through,
            "{} first moved the chain at line {line}, not in ({after}, {through}]",
            source.name()
        );
    }
}

/// The producer plan (`CHAIN_FORGE.md` §4, `CF-R18` (1)): forged in two
/// processes, at the plan's start spread, the same bytes. Every input the
/// producer audit classes as drawn comes from the plan's seed through the
/// production seams, and the spread is the plan's too: the producer draws
/// its start delays from the stream its read plans come from, so the
/// spread is an input to the bytes, not only to the timing. Timing itself,
/// the spread varied and every drawn input the OS's, is `CF-R18` (3)'s, and
/// is held on settlement state (`producer_audit.rs`).
#[test]
#[ignore = "two producer-plan forgings, minutes each; run by chain-forge.yml's nightly"]
fn the_producer_plan_forges_the_same_bytes_in_two_processes() {
    let outs = forge_in_two_processes("producer", "plans/producer.toml");
    if let Some(difference) = first_difference(outs[0].path(), outs[1].path()) {
        panic!("two forgings of the producer plan differ: {difference}");
    }
}

/// The shard-fill plan's two forgings, in the two environments, and each the
/// pinned hosted chain (`CHAIN_FORGE.md` §9, §10.4): its `blocks.txt` is the
/// committed one and every layer is its pin's, size and SHA-256. Nightly at
/// `dev`'s head this is the regeneration check: red means a merged change
/// moved the chain without re-publishing it and moving the pin.
#[test]
#[ignore = "two shard-fill forgings, minutes each; run by chain-forge.yml's nightly"]
fn the_shard_fill_plan_forges_its_pinned_chain_in_two_processes() {
    forges_its_pinned_chain(SHARD_FILL, SHARD_FILL_PLAN, SHARD_FILL_COMMITTED);
}

/// [`the_shard_fill_plan_forges_its_pinned_chain_in_two_processes`] for
/// Chain L (`CF-4b`).
#[test]
#[ignore = "two Chain L forgings, minutes each; run by chain-forge.yml's nightly"]
fn the_chain_l_plan_forges_its_pinned_chain_in_two_processes() {
    forges_its_pinned_chain(CHAIN_L, CHAIN_L_PLAN, CHAIN_L_COMMITTED);
}

/// `plan`'s two forgings, in the two environments, and each hosted `chain`
/// as pinned: its committed `blocks.txt`, every layer its pin's.
fn forges_its_pinned_chain(chain: &str, plan: &str, committed: &str) {
    let outs = forge_in_two_processes(chain, plan);
    let a = outs[0].path();
    if let Some(difference) = first_difference(a, outs[1].path()) {
        panic!("two forgings of the {chain} plan differ: {difference}");
    }
    let committed = crate_dir().join(committed).join(BLOCKS_FILE);
    let ours = BlocksTxt::parse(&std::fs::read_to_string(a.join(BLOCKS_FILE)).expect("forged"))
        .expect("parses");
    let theirs = BlocksTxt::parse(
        &std::fs::read_to_string(&committed)
            .unwrap_or_else(|e| panic!("{}: {e}", committed.display())),
    )
    .expect("the committed ledger parses");
    if let Some(difference) = ours.first_difference(&theirs) {
        panic!(
            "the forged {chain} chain is not the committed one (ours, committed): {difference}. \
             A change that moves it regenerates blocks.txt, re-publishes the chain and moves its \
             pin in the same pull request (CHAIN_FORGE.md §9)"
        );
    }
    let pin = shekyl_chain_forge::Pins::load()
        .and_then(|pins| pins.chain(chain).cloned())
        .unwrap_or_else(|fault| panic!("{fault}"));
    shekyl_chain_forge::hosted::open_in(a, pin).unwrap_or_else(|fault| {
        panic!(
            "forging the {chain} plan here does not give its pinned artifact: {fault}. A merged \
             change moved the chain without re-publishing it (CHAIN_FORGE.md §9)"
        )
    });
}

/// Each hosted layer's media type names the format version its bytes are
/// written in, so a layout change cannot ship under the old type (§10.4).
#[test]
fn the_hosted_media_types_name_the_formats_they_carry() {
    use shekyl_chain_forge::hosted::{CORPUS_MEDIA_TYPE, TRACE_MEDIA_TYPE};
    assert!(
        CORPUS_MEDIA_TYPE.ends_with(&format!(".v{CORPUS_FORMAT_VERSION}")),
        "{CORPUS_MEDIA_TYPE} names corpus layout {CORPUS_FORMAT_VERSION}"
    );
    assert!(
        TRACE_MEDIA_TYPE.ends_with(&format!(".v{}", shekyl_chain_ingest::trace::TRACE_VERSION)),
        "{TRACE_MEDIA_TYPE} names trace version {}",
        shekyl_chain_ingest::trace::TRACE_VERSION
    );
}

/// `plan`, forged once in each of [`ENVIRONMENTS`] by a child process,
/// each into its own directory.
fn forge_in_two_processes(label: &str, plan: &str) -> Vec<tempfile::TempDir> {
    let outs: Vec<tempfile::TempDir> = ENVIRONMENTS
        .iter()
        .map(|env| {
            tempfile::Builder::new()
                .prefix(&format!("forge-{label}-{}-", env.name))
                .tempdir()
                .expect("an output directory")
        })
        .collect();
    for (env, out) in ENVIRONMENTS.iter().zip(&outs) {
        let started = std::time::Instant::now();
        let status = spawn_child_with(env, out.path(), &[(CHILD_PLAN, plan)]);
        assert!(
            status.success(),
            "the {} forging of the {label} plan failed: {status}",
            env.name
        );
        eprintln!(
            "forged the {label} plan under {} in {:.1} s",
            env.name,
            started.elapsed().as_secs_f64()
        );
    }
    outs
}
