// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stamp the build's git revision into the binary.
//!
//! `WALLET_SIDE_STORE.md` §6.3.4 requires a **re-grade on a material
//! prover-pin change**, and the run record carries a `prover_pin` so a later
//! reader can tell whether an old record still applies. Without this the
//! revision field is `None` and the pin is decorative — it names the crate
//! version, which moves far more slowly than the prover does.
//!
//! ## Watching the right files, which is not `.git/HEAD`
//!
//! Two things make the obvious `rerun-if-changed=../../.git/HEAD` wrong here,
//! and the second makes it inert rather than merely weak:
//!
//! 1. **`HEAD` does not change when you commit on the branch it names.** It
//!    holds `ref: refs/heads/<branch>` while that ref's *target* moves, so a
//!    commit would leave a stale stamp behind.
//! 2. **In a git worktree `.git` is a FILE, not a directory** — and this
//!    project mandates worktrees ([rule 08](../../.cursor/rules/08-worktree-hygiene.mdc)).
//!    A relative `.git/HEAD` path therefore names nothing at all in the setup
//!    every lane uses.
//!
//! So the paths are resolved through `git rev-parse --git-path`, which is
//! worktree-aware, and both `HEAD` and the branch ref are watched — plus
//! `packed-refs`, since a packed branch has no loose ref file to watch.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SHEKYL_GIT_REVISION");

    if std::env::var("SHEKYL_GIT_REVISION").is_ok() {
        // An explicit override wins: a reproducible build sets it, and this
        // script must not silently disagree with it.
        return;
    }

    // `--git-path` resolves against the real gitdir, so this is correct in a
    // worktree, a submodule, and a plain clone alike.
    for path in ["HEAD", "packed-refs"] {
        if let Some(resolved) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
    if let Some(branch_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        // The ref whose TARGET moves on every commit to this branch.
        if let Some(resolved) = git(&["rev-parse", "--git-path", &branch_ref]) {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }

    let Some(rev) = git(&["rev-parse", "--short=9", "HEAD"]) else {
        // Absence of signal is first evidence the subject is absent (rule 47):
        // say the revision is unknown rather than leaving the record implying
        // a clean unnamed build.
        println!("cargo:rustc-env=SHEKYL_GIT_REVISION=unknown");
        return;
    };
    let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
    let suffix = if dirty { "-dirty" } else { "" };
    println!("cargo:rustc-env=SHEKYL_GIT_REVISION={rev}{suffix}");
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if s.is_empty() {
        return None;
    }
    Some(s)
}
