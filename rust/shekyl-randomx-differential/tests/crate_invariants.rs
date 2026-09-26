// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cargo-test wrapper for the RandomX v2 differential-harness
//! crate-invariant gates.
//!
//! Per [`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
//! §5.5.4 + §6.6 (T13, T14) + §6.7 (T15) + R1-D13: this file
//! anchors three independent invariants the per-PR CI gate
//! asserts against this crate and the workspace.
//!
//! - **T13** (`crate_invariant_script_coverage`): invokes
//!   `scripts/ci/check_randomx_crate_invariants.sh` and asserts
//!   the extended script returns clean across the three RandomX
//!   v2 Rust crates (`shekyl-pow-randomx`, `randomx-v2-sys`,
//!   `shekyl-randomx-differential`) with the §5.5.4 Pattern-C
//!   exemption for `randomx-v2-sys` in effect. Mirrors the
//!   existing
//!   [`rust/shekyl-pow-randomx/tests/crate_invariants.rs`](../../shekyl-pow-randomx/tests/crate_invariants.rs)
//!   wrapper shape (Phase 2F §6.2 T-CI-1/2/3).
//!
//! - **T14** (`randomx_v2_sys_sole_consumer`): invokes
//!   `cargo metadata --format-version 1 --no-deps`, parses the
//!   workspace package list, and asserts that exactly one
//!   workspace member declares a dependency on `randomx-v2-sys`
//!   (which must be `shekyl-randomx-differential`). Any
//!   additional consumer is a Phase 2F Decision-#5-by-precedent
//!   violation (the harness's FFI bindings exist solely for the
//!   differential harness) and fails the invariant.
//!
//! - **T15** (`randomx_v2_sys_signature_audit_pin`): reads the
//!   `[package.metadata.shekyl] fork-pin-sha = "…"` value from
//!   [`rust/randomx-v2-sys/Cargo.toml`](../../randomx-v2-sys/Cargo.toml)
//!   and asserts it against the superproject gitlink
//!   `HEAD:external/randomx-v2` (the pin the superproject records).
//!   `git -C external/randomx-v2 rev-parse HEAD` is the wrong
//!   instrument: an empty checkout walks up and reports the
//!   superproject HEAD. Three assertions, in order: the directory
//!   is populated; the gitlink equals the pin; on-disk HEAD equals
//!   the pin iff `external/randomx-v2/.git` exists (guarded by
//!   `--show-toplevel`). Not-initialized and SHA-mismatch messages
//!   are textually distinguishable. A gitlink mismatch indicates
//!   the submodule advanced without an `extern "C"` re-audit
//!   per [§1.7 + R1-D2](../../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md);
//!   the fork-pin-bump PR (separate scope) is the disposition.
//!
//! # Portability
//!
//! The wrapper is `#![cfg(unix)]`: T13 invokes a bash script
//! (`#!/usr/bin/env bash`); T14 + T15 shell out to `cargo` and
//! `git` respectively. None of the three are meaningful on
//! Windows. Gating the file at module level keeps `cargo test -p
//! shekyl-randomx-differential` portable on Windows runners (the
//! integration target compiles to nothing). Per §5.5.1 the
//! per-PR CI runner pin is `ubuntu-latest` exclusively, so the
//! security property holds at the project level.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve the workspace root from this crate's manifest dir.
/// `CARGO_MANIFEST_DIR` is set by Cargo to the directory
/// containing `Cargo.toml` for the crate being built. The
/// integration test binary runs with its CWD set to the crate
/// root (`<workspace>/rust/shekyl-randomx-differential/`); walking
/// up two levels (out of the crate, out of `rust/`) reaches the
/// workspace root that holds `scripts/`, `external/`, and
/// `.git/`.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("..").join("..")
}

fn script_path() -> PathBuf {
    workspace_root()
        .join("scripts")
        .join("ci")
        .join("check_randomx_crate_invariants.sh")
}

// ---------------------------------------------------------------------------
// T13: extended crate-invariant script returns clean
// ---------------------------------------------------------------------------

#[test]
fn t13_crate_invariant_script_coverage() {
    let script = script_path();
    assert!(
        script.exists(),
        "{} not found (CARGO_MANIFEST_DIR walk failed?)",
        script.display()
    );
    let status = Command::new(&script)
        .current_dir(workspace_root())
        .status()
        .expect("failed to invoke crate-invariants script");
    assert!(
        status.success(),
        "scripts/ci/check_randomx_crate_invariants.sh failed; \
         see stderr for the matched lines. Per §5.5.4 + R1-D13 \
         the gate enforces Pattern A/B against all three RandomX \
         v2 Rust crates and Pattern C against the verifier + \
         differential-harness crates (randomx-v2-sys exempted)",
    );
}

// ---------------------------------------------------------------------------
// T14: randomx-v2-sys sole-consumer invariant
// ---------------------------------------------------------------------------

#[test]
fn t14_randomx_v2_sys_sole_consumer() {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(workspace_root().join("rust").join("Cargo.toml"))
        .output()
        .expect("failed to invoke cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata output not valid JSON");

    let packages = metadata
        .get("packages")
        .and_then(|p| p.as_array())
        .expect("cargo metadata missing `packages` array");

    let mut consumers: Vec<String> = Vec::new();
    for pkg in packages {
        let pkg_name = pkg
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unknown>")
            .to_string();
        let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) else {
            continue;
        };
        for dep in deps {
            let dep_name = dep.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if dep_name == "randomx-v2-sys" {
                consumers.push(pkg_name.clone());
                break;
            }
        }
    }

    assert_eq!(
        consumers.len(),
        1,
        "randomx-v2-sys must have exactly one workspace consumer per §5.2.5 + R1-D13; \
         found {} consumers: {:?}. The harness's FFI bindings are sole-consumer-locked \
         to shekyl-randomx-differential per Phase 2F Decision #5 (FFI exports live in \
         shekyl-ffi; randomx-v2-sys is a differential-harness-only FFI surface). Any \
         additional consumer requires a plan-doc amendment per §5.7 drift-prevention.",
        consumers.len(),
        consumers,
    );
    assert_eq!(
        consumers[0], "shekyl-randomx-differential",
        "randomx-v2-sys's sole consumer must be shekyl-randomx-differential; \
         found {:?}",
        consumers[0],
    );
}

// ---------------------------------------------------------------------------
// T15: randomx-v2-sys fork-pin SHA matches superproject gitlink
// ---------------------------------------------------------------------------

fn dir_is_populated(path: &Path) -> bool {
    // Fail closed on I/O: a directory we cannot read is not a pin we
    // can attest. Ignore `.git` — a gitfile/gitdir leftover from an
    // interrupted `submodule update` is not RandomX source. CMake
    // `file(GLOB … /*)` *includes* dotfiles; both CMake populate
    // checks filter `.git` the same way (`dir_populated_ignoring_git`).
    let entries = std::fs::read_dir(path).unwrap_or_else(|e| {
        panic!(
            "read_dir {}: {e} (fail closed — cannot attest population)",
            path.display()
        )
    });
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|e| panic!("read_dir entry {}: {e} (fail closed)", path.display()));
        if entry.file_name() != ".git" {
            return true;
        }
    }
    false
}

fn git_rev_parse(cwd: &Path, spec: &str) -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", spec])
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("failed to invoke git rev-parse: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[test]
fn t15_randomx_v2_sys_signature_audit_pin() {
    let manifest_path = workspace_root()
        .join("rust")
        .join("randomx-v2-sys")
        .join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {}", manifest_path.display(), e));

    // Find `fork-pin-sha = "<sha>"` inside the
    // `[package.metadata.shekyl]` section. The format is stable
    // per §1.7 + R1-D2; a regex would be overkill. We scan
    // line-by-line for the prefix.
    let pin = manifest
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let prefix = "fork-pin-sha = \"";
            if let Some(rest) = line.strip_prefix(prefix) {
                rest.strip_suffix('"').map(str::to_string)
            } else {
                None
            }
        })
        .expect(
            "randomx-v2-sys/Cargo.toml missing [package.metadata.shekyl] fork-pin-sha \
             entry; required by §6.7 T15",
        );

    let submodule_dir = workspace_root().join("external").join("randomx-v2");

    // 1. Populated: non-empty directory. An empty checkout is not a
    // SHA mismatch — `git -C` that path walks up and reports the
    // superproject HEAD.
    assert!(
        dir_is_populated(&submodule_dir),
        "external/randomx-v2 is not initialized (missing or empty directory). \
         `git -C external/randomx-v2 rev-parse HEAD` walks up and reports \
         the superproject SHA, which is not the pin. Initialize with: \
         `git submodule update --init external/randomx-v2`. Never pass \
         `--exclude` for this crate. Worktrees inherit gitlinks but not \
         submodule working trees; re-run the same init in the worktree. \
         Default daemon CMake does not need this tree; the differential \
         harness and T15 do. See CLAUDE.md checkout hygiene.",
    );

    let root = workspace_root()
        .canonicalize()
        .expect("workspace root canonicalize");
    let submodule_dir = root.join("external").join("randomx-v2");

    // 2. Gitlink == pin. `HEAD:external/randomx-v2` is recorded in the
    // superproject and cannot walk into an empty dir.
    let gitlink = git_rev_parse(&root, "HEAD:external/randomx-v2").unwrap_or_else(|err| {
        panic!(
            "git rev-parse HEAD:external/randomx-v2 failed in {}: {err}",
            root.display()
        )
    });
    assert_eq!(
        pin, gitlink,
        "SHA mismatch: randomx-v2-sys fork-pin-sha does not match the \
         superproject gitlink HEAD:external/randomx-v2. Cargo.toml pin: \
         {pin}; gitlink: {gitlink}. Per §1.7 + R1-D2 + T15 a mismatch \
         indicates the submodule advanced without re-auditing the \
         `extern \"C\"` declarations in randomx-v2-sys/src/lib.rs. The \
         fork-pin-bump procedure is a separate-scope PR per §5.7 \
         drift-prevention discipline.",
    );

    // 3. On-disk HEAD == pin, only if the checkout has its own .git
    // (file or directory) whose `--show-toplevel` is the submodule
    // itself. T15 is a git-checkout test: `HEAD:external/randomx-v2`
    // already required the superproject `.git`, so a source tarball
    // with no git metadata fails at step 2 — there is no tarball skip
    // contract. Guard `--show-toplevel` so a leftover `.git` that
    // still walks up is not treated as a submodule HEAD.
    let git_marker = submodule_dir.join(".git");
    if git_marker.exists() {
        let toplevel = git_rev_parse(&submodule_dir, "--show-toplevel").unwrap_or_else(|err| {
            panic!(
                "git rev-parse --show-toplevel failed in {}: {err}",
                submodule_dir.display()
            )
        });
        let toplevel_path = PathBuf::from(&toplevel)
            .canonicalize()
            .unwrap_or_else(|e| panic!("canonicalize show-toplevel {toplevel}: {e}"));
        assert_eq!(
            toplevel_path, submodule_dir,
            "external/randomx-v2/.git exists but git rev-parse --show-toplevel \
             is {toplevel_path:?}, not the submodule directory. Refusing to \
             compare on-disk HEAD (walk-up).",
        );
        let on_disk = git_rev_parse(&submodule_dir, "HEAD").unwrap_or_else(|err| {
            panic!(
                "git rev-parse HEAD failed in {}: {err}",
                submodule_dir.display()
            )
        });
        assert_eq!(
            pin, on_disk,
            "SHA mismatch: external/randomx-v2 on-disk HEAD does not match \
             fork-pin-sha. Cargo.toml pin: {pin}; on-disk HEAD: {on_disk}. \
             The gitlink matches the pin; the working tree is checked out at \
             a different commit. `git submodule update --init external/randomx-v2` \
             to reset it.",
        );
    }
}
