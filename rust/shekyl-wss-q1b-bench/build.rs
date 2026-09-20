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
//! A dirty tree is marked, because a record produced from uncommitted changes
//! names a revision that does not describe what ran.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves; `.git/HEAD` covers commits and branch switches.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=SHEKYL_GIT_REVISION");

    if std::env::var("SHEKYL_GIT_REVISION").is_ok() {
        // An explicit override wins: a reproducible build sets it, and this
        // script must not silently disagree with it.
        return;
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
    Some(String::from_utf8(out.stdout).ok()?.trim().to_owned())
}
