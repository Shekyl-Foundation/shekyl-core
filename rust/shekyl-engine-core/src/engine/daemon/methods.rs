// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every daemon method the engine calls through [`super::DaemonClient`].
//!
//! A wallet that talks to a node over a bounded connection (the GUI's own
//! node holds the view listener's grants) can only use the engine if the
//! node admits each of these. The list is the engine's side of that check:
//! the GUI's grant-reach test holds every row here, and its own calls,
//! against the connection it opens. A test below holds the list to the
//! engine's code, so a new daemon call with no row fails here, in the PR
//! that adds it.

use shekyl_rpc_client::wire;
use shekyl_rpc_types::method::Row;

/// The daemon methods the engine's production code calls, directly
/// (`call::<M>`, the version handshake) or through `shekyl-rpc-client`'s
/// helpers (`get_height`, `get_block_hash`, `publish_transaction`).
pub const DAEMON_METHODS: &[Row] = &[
    // The identity handshake, before any other request (`VC-4`).
    Row::of::<wire::Version>(),
    // Health, the synced chain facts, the stake engine's tip.
    Row::of::<wire::DaemonStatus>(),
    // The scan's tip (`get_height`) and its blocks.
    Row::of::<wire::ChainHeight>(),
    Row::of::<wire::BlockShow>(),
    // A block's hash (`get_block_hash`): reorg checks, proof anchors.
    Row::of::<wire::BlockHeaderShow>(),
    // Fees and submission.
    Row::of::<wire::Fee>(),
    Row::of::<wire::TxSubmit>(),
    // Proofs: a transaction's record and a key image's state.
    Row::of::<wire::TxList>(),
    Row::of::<wire::ChainSpent>(),
    // The emission source's settled claims.
    Row::of::<wire::ArchivalClaimShow>(),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::DAEMON_METHODS;
    use shekyl_rpc_client::{wire, RpcMethod};

    /// A module declaration: the paths it may load, and whether it is
    /// compiled only under test.
    type Declaration = (Vec<PathBuf>, bool);

    /// A file's module declarations: each target path (a `#[path]` resolves
    /// against the file's own directory), and whether a `#[cfg(...test...)]`
    /// attribute stands on it.
    fn declarations(file: &Path) -> Vec<Declaration> {
        let text = std::fs::read_to_string(file).expect("a source file");
        let parent = file.parent().expect("a parent");
        let stem = file.file_stem().and_then(|s| s.to_str()).expect("a stem");
        let base = if matches!(stem, "mod" | "lib" | "main") {
            parent.to_path_buf()
        } else {
            parent.join(stem)
        };
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let declared = line
                .strip_prefix("pub(crate) mod ")
                .or_else(|| line.strip_prefix("pub(super) mod "))
                .or_else(|| line.strip_prefix("pub mod "))
                .or_else(|| line.strip_prefix("mod "))
                .and_then(|rest| rest.strip_suffix(';'));
            let Some(name) = declared else { continue };
            let attrs: Vec<&str> = lines[..i]
                .iter()
                .rev()
                .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
                .copied()
                .collect();
            let test_only = attrs
                .iter()
                .any(|l| l.starts_with("#[cfg(") && l.contains("test"));
            let targets = match attrs
                .iter()
                .find_map(|l| l.strip_prefix("#[path = \"")?.strip_suffix("\"]"))
            {
                Some(path) => vec![parent.join(path)],
                None => vec![base.join(format!("{name}.rs")), base.join(name)],
            };
            out.push((targets, test_only));
        }
        out
    }

    /// The source of every module of `dir` that is compiled outside test: a
    /// module declared under a `#[cfg(...test...)]` attribute is skipped,
    /// with every module it declares in turn, and so is the text of each
    /// file's own inline test module (from its `#[cfg(test)]` before `mod`).
    fn production_sources(dir: &Path) -> Vec<(PathBuf, String)> {
        let mut files = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).expect("a source directory") {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    files.push(path);
                }
            }
        }
        let declared: Vec<(PathBuf, Vec<Declaration>)> =
            files.iter().map(|f| (f.clone(), declarations(f))).collect();
        let skipped = |skip: &BTreeSet<PathBuf>, file: &Path| {
            skip.iter()
                .any(|s| file == s || (s.extension().is_none() && file.starts_with(s)))
        };
        let mut skip: BTreeSet<PathBuf> = declared
            .iter()
            .flat_map(|(_, decls)| decls.iter().filter(|(_, t)| *t))
            .flat_map(|(targets, _)| targets.iter().cloned())
            .collect();
        // Everything a skipped module declares is test-only too.
        loop {
            let before = skip.len();
            for (file, decls) in &declared {
                if skipped(&skip, file) {
                    skip.extend(decls.iter().flat_map(|(t, _)| t.iter().cloned()));
                }
            }
            if skip.len() == before {
                break;
            }
        }
        files
            .into_iter()
            .filter(|file| !skipped(&skip, file))
            .map(|file| {
                let text = std::fs::read_to_string(&file).expect("a source file");
                let production = text
                    .find("#[cfg(test)]\nmod ")
                    .map_or(text.as_str(), |at| &text[..at])
                    .to_owned();
                (file, production)
            })
            .collect()
    }

    /// The type named after `marker` in `text`, by its last path segment.
    fn named_after(text: &str, marker: &str, end: char) -> Vec<String> {
        text.match_indices(marker)
            .filter_map(|(at, _)| {
                let rest = &text[at + marker.len()..];
                let name = rest[..rest.find(end)?].rsplit("::").next()?.trim();
                let ident =
                    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                (ident && name != "M").then(|| name.to_owned())
            })
            .collect()
    }

    /// `shekyl-rpc-client`'s helpers, each with the method it calls, read
    /// from that crate's source: every `fn` whose body makes one typed call.
    fn client_helpers() -> Vec<(String, String)> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../shekyl-rpc-client/src/lib.rs");
        let text = std::fs::read_to_string(&path).expect("shekyl-rpc-client's source");
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut helpers = Vec::new();
        let starts: Vec<usize> = code.match_indices("fn ").map(|(at, _)| at).collect();
        for (i, &at) in starts.iter().enumerate() {
            let body = &code[at..starts.get(i + 1).copied().unwrap_or(code.len())];
            let Some(name) = body[3..]
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
            else {
                continue;
            };
            if let Some(method) = named_after(body, "call::<", '>').into_iter().next() {
                helpers.push((name.to_owned(), method));
            }
        }
        helpers
    }

    /// The methods the engine's production code calls, from its source.
    fn called_by_the_engine() -> BTreeSet<String> {
        let helpers = client_helpers();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = BTreeSet::new();
        for (_, text) in production_sources(&src) {
            found.extend(named_after(&text, "call::<", '>'));
            // `<wire::M as RpcMethod>::NAME`: a request built by hand, as the
            // version handshake is.
            for (at, _) in text.match_indices(" as RpcMethod>") {
                let head = &text[..at];
                let Some(open) = head.rfind('<') else {
                    continue;
                };
                let name = head[open + 1..].rsplit("::").next().unwrap_or("").trim();
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    found.insert(name.to_owned());
                }
            }
            for (helper, method) in &helpers {
                if text.contains(&format!(".{helper}(")) {
                    found.insert(method.clone());
                }
            }
        }
        found
    }

    /// The type name of each listed row, by its wire name.
    fn listed() -> BTreeSet<String> {
        let by_name: Vec<(&str, &str)> = vec![
            (<wire::Version as RpcMethod>::NAME, "Version"),
            (<wire::DaemonStatus as RpcMethod>::NAME, "DaemonStatus"),
            (<wire::ChainHeight as RpcMethod>::NAME, "ChainHeight"),
            (<wire::BlockShow as RpcMethod>::NAME, "BlockShow"),
            (
                <wire::BlockHeaderShow as RpcMethod>::NAME,
                "BlockHeaderShow",
            ),
            (<wire::Fee as RpcMethod>::NAME, "Fee"),
            (<wire::TxSubmit as RpcMethod>::NAME, "TxSubmit"),
            (<wire::TxList as RpcMethod>::NAME, "TxList"),
            (<wire::ChainSpent as RpcMethod>::NAME, "ChainSpent"),
            (
                <wire::ArchivalClaimShow as RpcMethod>::NAME,
                "ArchivalClaimShow",
            ),
        ];
        DAEMON_METHODS
            .iter()
            .map(|row| {
                by_name
                    .iter()
                    .find(|(name, _)| *name == row.name)
                    .unwrap_or_else(|| panic!("{} has no type name in this test", row.name))
                    .1
                    .to_owned()
            })
            .collect()
    }

    /// The list is the engine's daemon calls: a new call with no row fails,
    /// and so does a row whose last call is gone. Red edit: a
    /// `call::<wire::PeerConnections>` in a production module (`scan_floor.rs`),
    /// with no row.
    #[test]
    fn the_list_is_the_engine_s_daemon_calls() {
        assert_eq!(
            called_by_the_engine(),
            listed(),
            "DAEMON_METHODS must name exactly the daemon methods the engine calls"
        );
    }

    /// The scan reads the helpers it maps calls through, so a renamed helper
    /// is a failure, not a call that silently drops out.
    #[test]
    fn the_client_helpers_the_engine_uses_are_read() {
        let helpers = client_helpers();
        for name in ["get_height", "get_block_hash", "publish_transaction"] {
            assert!(
                helpers.iter().any(|(helper, _)| helper == name),
                "shekyl-rpc-client has no helper `{name}` making a typed call: {helpers:?}"
            );
        }
    }
}
