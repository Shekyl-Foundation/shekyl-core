// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PWD-A1 under RT-W12: every production bond, claim, drain and release
//! dispatch uses the wallet's configured daemon through its checked submitter.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The tests-module marker the engine's source gates split on.
const TESTS_MARKER: &str = "\n#[cfg(test)]\nmod tests {";

const SUBMISSION_SITES: &[&str] = &[
    "engine/claim_dispatch.rs",
    "engine/drain_dispatch.rs",
    "engine/release_dispatch.rs",
    "engine/pscan/start.rs",
];

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `src`, mapped to its **production** code: the text
/// ahead of the tests-module marker, with comment-only lines dropped.
///
/// A `#[cfg(test)] #[path]` sibling is the tests half. The marker above only
/// sees an inline `mod tests { ... }`. The compiler drops the sibling from a
/// production build, and so does this sweep. A file that is not declared that
/// way is read whole: a test-only file that acquired a needle and was not
/// wired under `#[cfg(test)]` trips the census, which is the review signal.
///
/// Comment-*only* lines are dropped rather than truncating each line at
/// `//`, so a `//` inside a string literal can never delete live code from
/// the text being judged.
fn production_sources() -> BTreeMap<String, String> {
    let root = src_root();
    let skip = test_path_siblings(&root);
    let mut out = BTreeMap::new();
    collect(&root, &root, &skip, &mut out);
    out
}

/// Files the compiler builds only as part of a `#[cfg(test)]` module reached
/// by `#[path]`. Includes siblings of those files: a path declared inside a
/// test-only file is test-only too.
fn test_path_siblings(root: &Path) -> BTreeSet<String> {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    collect_text(root, root, &mut files);
    let mut skip = BTreeSet::new();
    let mut queue: Vec<String> = files
        .iter()
        .flat_map(|(rel, text)| cfg_test_paths(rel, text))
        .collect();
    while let Some(rel) = queue.pop() {
        if !skip.insert(rel.clone()) {
            continue;
        }
        if let Some(text) = files.get(&rel) {
            queue.extend(every_path(&rel, text));
        }
    }
    skip
}

/// `#[path]` targets on items whose attribute block carries `#[cfg(test)]`,
/// plus every `#[path]` that sits inside the inline tests module.
fn cfg_test_paths(from_rel: &str, text: &str) -> Vec<String> {
    let (production, tests_body) = match text.split_once(TESTS_MARKER) {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };
    let mut found = paths_whose_item_is_cfg_test(from_rel, production);
    if let Some(tail) = tests_body {
        found.extend(every_path(from_rel, tail));
    }
    found
}

fn paths_whose_item_is_cfg_test(from_rel: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(target) = path_attr_target(line) else {
            continue;
        };
        if item_is_cfg_test(&lines, idx) {
            found.push(resolve_rel(from_rel, target));
        }
    }
    found
}

fn every_path(from_rel: &str, text: &str) -> Vec<String> {
    text.lines()
        .filter_map(path_attr_target)
        .map(|target| resolve_rel(from_rel, target))
        .collect()
}

/// `#[cfg(test)]` on this item. Attributes stack in either order until the
/// item, and a blank or a `//` line does not end the stack.
fn item_is_cfg_test(lines: &[&str], attr_idx: usize) -> bool {
    let is_stack = |line: &str| {
        let trimmed = line.trim();
        trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[")
    };
    let mut lo = attr_idx;
    while lo > 0 && is_stack(lines[lo - 1]) {
        lo -= 1;
    }
    let mut hi = attr_idx;
    while hi + 1 < lines.len() && is_stack(lines[hi + 1]) {
        hi += 1;
    }
    (lo..=hi).any(|i| lines[i].trim() == "#[cfg(test)]")
}

fn path_attr_target(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.starts_with("//") {
        return None;
    }
    let after = trimmed.strip_prefix("#[path = \"")?;
    let end = after.find('"')?;
    Some(&after[..end])
}

/// `#[path]` is relative to the file that writes it. The census's keys are
/// relative to `src/`.
fn resolve_rel(from_rel: &str, path_attr: &str) -> String {
    let dir = Path::new(from_rel).parent().unwrap_or(Path::new(""));
    let mut parts = Vec::new();
    for component in dir.join(path_attr).components() {
        match component {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::Normal(segment) => {
                parts.push(segment.to_string_lossy().into_owned());
            }
            std::path::Component::CurDir
            | std::path::Component::Prefix(_)
            | std::path::Component::RootDir => {}
        }
    }
    parts.join("/")
}

fn collect_text(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_text(&path, root, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        out.insert(rel, text);
    }
}

fn collect(dir: &Path, root: &Path, skip: &BTreeSet<String>, out: &mut BTreeMap<String, String>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect(&path, root, skip, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if skip.contains(&rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if text.lines().any(|line| line.trim() == "#![cfg(test)]") {
            continue;
        }
        let production = text
            .split(TESTS_MARKER)
            .next()
            .expect("split always yields a first piece")
            .to_owned();
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        out.insert(rel, code);
    }
}

#[test]
fn each_dispatch_uses_the_wallet_node() {
    let sources = production_sources();
    let expected: BTreeSet<_> = SUBMISSION_SITES.iter().copied().collect();
    let actual: BTreeSet<_> = sources
        .iter()
        .filter(|(_, code)| code.contains("BroadcastSubmitter::for_wallet("))
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(actual, expected);
    for path in SUBMISSION_SITES {
        assert!(sources[*path].contains(".submit_bound("), "{path}");
    }
    let submitter = &sources["engine/transaction_submitter.rs"];
    assert!(submitter.contains("pub(crate) struct BroadcastSubmitter"));
    assert!(submitter.contains("self.daemon.submit(tx)"));
    for (path, code) in sources {
        for legacy in ["PTransactionSubmitter", "BroadcastPosture", "PTorClient"] {
            assert!(!code.contains(legacy), "{path} reintroduced {legacy}");
        }
    }
}
