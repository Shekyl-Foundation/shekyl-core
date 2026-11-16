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

/// The plan, from the crate's directory.
const PLAN: &str = "plans/small.toml";
/// The committed `blocks.txt` and manifest, from the crate's directory.
const COMMITTED: &str = "chains/small";

/// The child process's switches: the directory it writes, the sources it
/// swaps, and the ledger it stops at.
const CHILD_OUT: &str = "SHEKYL_FORGE_CHILD_OUT";
const CHILD_SWAP: &str = "SHEKYL_FORGE_CHILD_SWAP";
const CHILD_STOP_AT: &str = "SHEKYL_FORGE_CHILD_STOP_AT";
const CHILD_HASHERS: &str = "SHEKYL_FORGE_CHILD_HASHERS";
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
        hashers: "1",
        time_zone: "UTC",
        locale: "C",
    },
    Environment {
        name: "many-threads-chatham-turkish",
        tokio_threads: "7",
        hashers: "3",
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
    if let Some(source) = swap {
        command.env(CHILD_SWAP, source.name());
    }
    if let Some(ledger) = stop_at {
        command.env(CHILD_STOP_AT, ledger);
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
    let plan_path = crate_dir().join(PLAN);
    let bytes = std::fs::read(&plan_path).expect("the plan reads");
    let plan = Plan::parse(std::str::from_utf8(&bytes).expect("utf-8")).expect("the plan parses");
    let plan_ref = PlanRef {
        path: format!("rust/shekyl-chain-forge/{PLAN}"),
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
    let outs: Vec<tempfile::TempDir> = ENVIRONMENTS
        .iter()
        .map(|env| {
            tempfile::Builder::new()
                .prefix(&format!("forge-out-{}-", env.name))
                .tempdir()
                .expect("an output directory")
        })
        .collect();
    for (env, out) in ENVIRONMENTS.iter().zip(&outs) {
        let started = std::time::Instant::now();
        let status = spawn_child(env, out.path(), None, None);
        assert!(
            status.success(),
            "the {} forging failed: {status}",
            env.name
        );
        eprintln!(
            "forged the small plan under {} in {:.1} s",
            env.name,
            started.elapsed().as_secs_f64()
        );
    }
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

/// One negative control per source of randomness: that source swapped to
/// the OS's, the forging differs from the committed ledger.
#[test]
#[ignore = "a forging per source, up to the source's first block; run by chain-forge.yml"]
fn each_source_drawn_from_the_os_moves_the_chain() {
    let committed = crate_dir().join(COMMITTED).join(BLOCKS_FILE);
    let ledger = BlocksTxt::parse(&std::fs::read_to_string(&committed).expect("committed"))
        .expect("the committed ledger parses");
    for source in Source::ALL {
        let out = tempfile::tempdir().expect("a directory");
        let started = std::time::Instant::now();
        let status = spawn_child(&ENVIRONMENTS[0], out.path(), Some(source), Some(&committed));
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
        let blocks: usize = stopped
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .expect("the stop names its block count");
        assert!(
            blocks <= ledger.lines().len(),
            "{} stopped inside the committed chain",
            source.name()
        );
    }
}
