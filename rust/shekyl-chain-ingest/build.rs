// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stamp `shekyl-chain-replay` with the checkout it was built from.
//!
//! cmake's `SHEKYL_VERSION_FULL` reaches `shekyl-cli` and
//! `shekyl-wallet-rpc` only. This binary is cargo-built, so a capture that
//! trusted the daemon's sha alone could write a trace from a stale replay
//! binary and stamp it with the daemon's commit. The sha printed by
//! `--version` is what the capture holds to `HEAD`.
//!
//! The stamp is rebuilt when the commit moves. On an attached branch `HEAD`
//! stays `ref: refs/heads/<name>` and the branch ref is the file that
//! changes; a packed branch has no loose ref, so `packed-refs` is watched
//! too. `git rev-parse --git-path` resolves a worktree, whose `.git` is a
//! file.

use std::process::Command;

fn main() {
    let sha = git(&["rev-parse", "--short=9", "HEAD"])
        .filter(|sha| sha.len() == 9 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SHEKYL_REPLAY_GIT_SHA={sha}");

    // Naming any path opts out of "rebuild when any file in the package
    // changes." The script itself stays on the list so editing it still
    // rebuilds.
    println!("cargo:rerun-if-changed=build.rs");
    for path in ["HEAD", "packed-refs"] {
        if let Some(resolved) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
    if let Some(branch) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(resolved) = git(&["rev-parse", "--git-path", &branch]) {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}
