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

use std::process::Command;

fn main() {
    let sha = git(&["rev-parse", "--short=9", "HEAD"])
        .filter(|sha| sha.len() == 9 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SHEKYL_REPLAY_GIT_SHA={sha}");

    // Rebuild when HEAD moves. `--git-path` resolves a worktree, whose
    // `.git` is a file, to the real HEAD. Declaring the script itself keeps
    // cargo from re-running this on every other file in the package.
    println!("cargo:rerun-if-changed=build.rs");
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
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
