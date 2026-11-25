// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The processes the xtask runs.
//!
//! Every spawn is in this file. `cargo` receives one plan and nothing
//! else: its arguments, its variables and the variables it removes are the
//! plan's. The rustc and git probes take their arguments from [`RustcProbe`]
//! and [`GitQuery`]. The release gate reads those words.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::plan::{self, Plan};

/// A question for `rustc`. The word is the argument.
#[derive(Clone, Copy)]
pub enum RustcProbe {
    /// `rustc -vV`, whose `host:` line is this machine's triple.
    Verbose,
    /// `rustc --version`, compared with the pinned channel.
    Version,
}

/// A question for `git`. The words are the arguments.
#[derive(Clone, Copy)]
pub enum GitQuery {
    /// `rev-parse --short=9 HEAD`.
    Commit,
    /// `tag -l --points-at HEAD`.
    Tags,
    /// `rev-parse --git-dir`.
    GitDir,
}

impl GitQuery {
    fn args(self) -> &'static [&'static str] {
        match self {
            Self::Commit => &["rev-parse", "--short=9", "HEAD"],
            Self::Tags => &["tag", "-l", "--points-at", "HEAD"],
            Self::GitDir => &["rev-parse", "--git-dir"],
        }
    }
}

/// Runs `probe` with `rust/` as its directory and returns its stdout.
pub fn rustc(root: &Path, probe: RustcProbe) -> Result<String, String> {
    match probe {
        RustcProbe::Verbose => text(
            Command::new("rustc")
                .arg("-vV")
                .current_dir(root.join("rust")),
        ),
        RustcProbe::Version => text(
            Command::new("rustc")
                .arg("--version")
                .current_dir(root.join("rust")),
        ),
    }
}

fn git_command(root: &Path, args: &[&str]) -> Command {
    let mut git = Command::new("git");
    git.args(args).current_dir(root);
    git
}

/// Runs `query` in `root` and returns its stdout, trimmed.
pub fn git(root: &Path, query: GitQuery) -> Result<String, String> {
    let args = query.args();
    let mut git = git_command(root, args);
    let out = git.output().map_err(|e| {
        format!("cannot run git ({e}); a source archive is built with --version-override <version>")
    })?;
    if !out.status.success() {
        return Err(format!(
            "`git {}` failed ({}): {}; a source archive is built with --version-override <version>",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| format!("`git {}` printed bytes that are not UTF-8", args.join(" ")))
}

/// Where `root`'s git directory is, when git can say. `configure` runs
/// after the arguments are set and before the process starts, so a test
/// can hide the repositories above a scratch tree. A failure to run or a
/// non-zero status is `None`: the caller treats that as no history.
pub fn git_dir(root: &Path, configure: impl FnOnce(&mut Command)) -> Option<String> {
    let mut git = git_command(root, GitQuery::GitDir.args());
    configure(&mut git);
    let out = git.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Runs the plan's cargo from `rust/`, the directory cargo reads its
/// config from. The plan is the whole command: this function adds no
/// argument and names no variable of its own, other than removing the
/// library path `cargo run` added for the xtask.
pub fn cargo(root: &Path, plan: &Plan) -> Result<(), String> {
    let (program, args) = plan.args.split_first().ok_or("an empty command")?;
    let mut command = Command::new(program);
    command.args(args).current_dir(root.join("rust"));
    for (name, _) in std::env::vars_os() {
        if let Some(text) = name.to_str() {
            if plan
                .unset
                .iter()
                .any(|pattern| plan::matches_pattern(pattern, text))
            {
                command.env_remove(&name);
            }
        }
    }
    if let Some(cleaned) = library_path_without_cargo_run(root) {
        if cleaned.is_empty() {
            command.env_remove(LIBRARY_PATH);
        } else {
            command.env(LIBRARY_PATH, cleaned);
        }
    }
    for (name, value) in &plan.env {
        command.env(name, value);
    }
    let status = command
        .status()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo failed ({status})"))
    }
}

/// The variable `cargo run` puts library directories in for the program it
/// runs: the xtask's own, which a direct cargo build never had.
#[cfg(target_os = "macos")]
const LIBRARY_PATH: &str = "DYLD_FALLBACK_LIBRARY_PATH";
#[cfg(windows)]
const LIBRARY_PATH: &str = "PATH";
#[cfg(not(any(target_os = "macos", windows)))]
const LIBRARY_PATH: &str = "LD_LIBRARY_PATH";

/// [`LIBRARY_PATH`] without the directories `cargo run` added for the
/// xtask: those under the workspace's target directory and, except on
/// Windows where the toolchain's directory is how rustup runs cargo at all,
/// under rustup's toolchains. What the caller set is kept. `None` when the
/// variable is unset; an empty value when nothing of the caller's is left,
/// and the caller then removes it, as a direct cargo build never had it.
fn library_path_without_cargo_run(root: &Path) -> Option<OsString> {
    let current = std::env::var_os(LIBRARY_PATH)?;
    let target = root.join("rust/target");
    let rustup = if cfg!(windows) {
        None
    } else {
        std::env::var_os("RUSTUP_HOME").map(|home| PathBuf::from(home).join("toolchains"))
    };
    let kept: Vec<PathBuf> = std::env::split_paths(&current)
        .filter(|path| {
            !path.starts_with(&target)
                && !rustup.as_ref().is_some_and(|home| path.starts_with(home))
        })
        .collect();
    std::env::join_paths(kept).ok()
}

fn text(command: &mut Command) -> Result<String, String> {
    let Output {
        status,
        stdout,
        stderr,
    } = command
        .output()
        .map_err(|e| format!("cannot run {:?}: {e}", command.get_program()))?;
    if !status.success() {
        return Err(format!(
            "{:?} failed ({status}): {}",
            command.get_program(),
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    String::from_utf8(stdout).map_err(|_| "a tool printed bytes that are not UTF-8".to_owned())
}
