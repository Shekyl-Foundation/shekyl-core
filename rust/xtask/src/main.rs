// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `cargo xtask`: the release build.
//!
//! ```text
//! cargo xtask dist --host <depends host> [--out DIR] [--measurement-spans] [--version-override V]
//! cargo xtask build [--out DIR] [--measurement-spans] [--version-override V]
//! cargo xtask plan (--host <depends host> | --native)
//! ```
//!
//! `dist` builds a release host from depends' environment file
//! (`contrib/depends/<host>/share/toolchain.env`) and stages the binaries and
//! the files the archive carries; gitian then adds Tor and packs. `build` is
//! a native release build of this machine's triple. `plan` prints what
//! either would run, and runs nothing. Every variable and argument comes
//! from `rust/xtask/matrix.toml`.

mod matrix;
mod plan;
mod version;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use matrix::Matrix;
use plan::{DependsEnv, Fill, Plan};
use version::{GitHead, Identity};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("xtask: {why}");
            ExitCode::FAILURE
        }
    }
}

/// The parsed command line.
#[derive(Debug, Default)]
struct Options {
    command: String,
    host: Option<String>,
    native: bool,
    out: Option<PathBuf>,
    measurement: bool,
    version_override: Option<String>,
}

const USAGE: &str = "usage:\n  \
    cargo xtask dist --host <depends host> [--out DIR] [--measurement-spans] [--version-override V]\n  \
    cargo xtask build [--out DIR] [--measurement-spans] [--version-override V]\n  \
    cargo xtask plan (--host <depends host> | --native)";

fn parse(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter();
    let command = it.next().ok_or(USAGE)?.clone();
    if !matches!(command.as_str(), "dist" | "build" | "plan") {
        return Err(format!("{command:?} is not a command\n{USAGE}"));
    }
    let mut o = Options {
        command,
        ..Options::default()
    };
    while let Some(arg) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value\n{USAGE}"))
        };
        match arg.as_str() {
            "--host" => o.host = Some(value()?),
            "--out" => o.out = Some(PathBuf::from(value()?)),
            "--version-override" => o.version_override = Some(value()?),
            "--measurement-spans" => o.measurement = true,
            "--native" => o.native = true,
            other => return Err(format!("{other:?} is not an option\n{USAGE}")),
        }
    }
    let fits = match o.command.as_str() {
        "dist" => o.host.is_some() && !o.native,
        "build" => o.host.is_none() && !o.native,
        _ => {
            (o.host.is_some() != o.native)
                && o.out.is_none()
                && !o.measurement
                && o.version_override.is_none()
        }
    };
    if !fits {
        return Err(format!("these options do not fit `{}`\n{USAGE}", o.command));
    }
    Ok(o)
}

fn run(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    let root = repository_root()?;
    let matrix = Matrix::load(&root.join("rust/xtask/matrix.toml"))?;
    let target_dir = root.join(&matrix.build.target_dir);

    // `--host` is a release host built from depends; without it, this
    // machine's own triple.
    let (host, invocation, depends, files) = if let Some(name) = &options.host {
        let (host, dist) = matrix.dist_host(name)?;
        let env_file = root
            .join("contrib/depends")
            .join(name)
            .join("share/toolchain.env");
        let depends = DependsEnv::read(&env_file)?;
        (host, &dist.invocation, Some(depends), &dist.files[..])
    } else {
        let triple = host_triple(&root)?;
        let (host, invocation) = matrix.native_host(&triple)?;
        (host, invocation, None, &[][..])
    };

    if options.command == "plan" {
        let fill = Fill {
            depends,
            target_dir,
            identity: Some(Identity {
                full: "{version_full}".to_owned(),
                release_name: "{release_name}".to_owned(),
                is_release: false,
            }),
        };
        let plan = plan::plan(
            &matrix,
            host,
            invocation,
            &fill,
            false,
            std::env::var_os("PATH").as_deref(),
        )?;
        print_plan(&plan, &mut std::io::stdout());
        return Ok(());
    }

    refuse_build_machine_settings(&matrix)?;
    check_toolchain(&root, &matrix)?;
    let identity = identity(&root, &matrix, &options)?;
    if options.measurement {
        eprintln!("xtask: warning: {}", matrix.measurement.warning);
    }

    let fill = Fill {
        depends,
        target_dir,
        identity: Some(identity.clone()),
    };
    let plan = plan::plan(
        &matrix,
        host,
        invocation,
        &fill,
        options.measurement,
        std::env::var_os("PATH").as_deref(),
    )?;
    eprintln!("xtask: {} ({}), {}", host.name, host.triple, identity.full);
    print_plan(&plan, &mut std::io::stderr());
    execute(&root, &plan)?;

    let out = options.out.unwrap_or_else(|| root.join("build/bin"));
    stage(&root, &plan, files, &out)?;
    eprintln!("xtask: staged in {}", out.display());
    Ok(())
}

/// The repository root: two levels above this crate's manifest.
fn repository_root() -> Result<PathBuf, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or("the xtask's manifest directory has no grandparent")?;
    if !root.join("rust/rust-toolchain.toml").is_file() {
        return Err(format!("{} is not the repository root", root.display()));
    }
    Ok(root.to_path_buf())
}

/// This machine's triple, as rustc reports it.
fn host_triple(root: &Path) -> Result<String, String> {
    let text = output(
        Command::new("rustc")
            .arg("-vV")
            .current_dir(root.join("rust")),
    )?;
    text.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV printed no host line".to_owned())
}

/// The build machine's own rustflags, profile overrides, target and
/// incremental setting are refused, each by name: they would change the
/// code with nothing in the repository saying so.
fn refuse_build_machine_settings(matrix: &Matrix) -> Result<(), String> {
    let mut found = Vec::new();
    for (name, value) in std::env::vars_os() {
        let Some(name) = name.to_str() else { continue };
        if matrix.build.refused.iter().any(|p| matches_name(p, name)) {
            found.push(name.to_owned());
        }
        for (refused, at) in &matrix.build.refused_values {
            if refused == name && value.to_str() == Some(at.as_str()) {
                found.push(format!("{name}={at}"));
            }
        }
    }
    if found.is_empty() {
        Ok(())
    } else {
        found.sort();
        Err(format!(
            "refusing to build while the environment sets {}: a release build takes its \
             flags from rust/xtask/matrix.toml only; unset it and run again",
            found.join(", ")
        ))
    }
}

/// `pattern` with at most one `*`, which matches any run of characters.
fn matches_name(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.len() >= head.len() + tail.len() && name.starts_with(head) && name.ends_with(tail)
        }
    }
}

/// rustc must be the channel `rust/rust-toolchain.toml` pins.
fn check_toolchain(root: &Path, matrix: &Matrix) -> Result<(), String> {
    let file = root.join(&matrix.build.toolchain_file);
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e| format!("{}: {e}", file.display()))?;
    let channel = table
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("{} has no [toolchain] channel", file.display()))?;
    let reported = output(
        Command::new("rustc")
            .arg("--version")
            .current_dir(root.join("rust")),
    )?;
    let version = reported.split_whitespace().nth(1).unwrap_or("");
    if version == channel {
        Ok(())
    } else {
        Err(format!(
            "rustc is {:?}, not the channel {} pins ({channel})",
            reported.trim(),
            matrix.build.toolchain_file
        ))
    }
}

fn identity(root: &Path, matrix: &Matrix, options: &Options) -> Result<Identity, String> {
    let defaults = &matrix.version;
    let (identity, tagged) = match &options.version_override {
        Some(v) => (version::from_override(v, &defaults.release_name)?, true),
        None => {
            let head = GitHead::read(root)?;
            let tagged = head.is_tagged();
            (
                version::from_git(&head, &defaults.default, &defaults.release_name),
                tagged,
            )
        }
    };
    if options.measurement && options.command == "dist" && tagged {
        return Err(format!(
            "--measurement-spans at a release ({}): a measurement build is never a release archive",
            identity.full
        ));
    }
    Ok(identity)
}

fn print_plan(plan: &Plan, w: &mut impl std::io::Write) {
    // A failed write to the console is not worth stopping a build for.
    let mut line = |s: String| {
        let _written = writeln!(w, "{s}");
    };
    for name in &plan.unset {
        line(format!("  unset {name}"));
    }
    for (name, value) in &plan.env {
        line(format!("  {name}={value}"));
    }
    line(format!("  {}", plan.args.join(" ")));
}

/// Runs the plan from `rust/`, the directory cargo reads its config from.
fn execute(root: &Path, plan: &Plan) -> Result<(), String> {
    let (program, args) = plan.args.split_first().ok_or("an empty command")?;
    let mut command = Command::new(program);
    command.args(args).current_dir(root.join("rust"));
    for (name, _) in std::env::vars_os() {
        if let Some(n) = name.to_str() {
            if plan.unset.iter().any(|p| matches_name(p, n)) {
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
        std::env::var_os("RUSTUP_HOME").map(|r| PathBuf::from(r).join("toolchains"))
    };
    let kept: Vec<PathBuf> = std::env::split_paths(&current)
        .filter(|p| !p.starts_with(&target) && !rustup.as_ref().is_some_and(|r| p.starts_with(r)))
        .collect();
    std::env::join_paths(kept).ok()
}

/// Copies the binaries (mode 755) and the host's files into `out`.
fn stage(root: &Path, plan: &Plan, files: &[matrix::StagedFile], out: &Path) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    for built in &plan.outputs {
        let name = built
            .file_name()
            .ok_or_else(|| format!("{} has no file name", built.display()))?;
        copy(built, &out.join(name), 0o755)?;
    }
    for file in files {
        copy(&root.join(&file.source), &out.join(&file.staged), file.mode)?;
    }
    Ok(())
}

fn copy(from: &Path, to: &Path, mode: u32) -> Result<(), String> {
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // A staged file from an earlier run may be read-only (the rc.d
    // scripts are 555): replace it rather than write into it.
    if to.exists() {
        std::fs::remove_file(to).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    std::fs::copy(from, to).map_err(|e| format!("{} -> {}: {e}", from.display(), to.display()))?;
    set_mode(to, mode)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Windows has no mode bits; the archive's zip carries none.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // the unix twin can fail
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn output(command: &mut Command) -> Result<String, String> {
    let out = command
        .output()
        .map_err(|e| format!("cannot run {:?}: {e}", command.get_program()))?;
    if !out.status.success() {
        return Err(format!(
            "{:?} failed ({}): {}",
            command.get_program(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "a tool printed bytes that are not UTF-8".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn patterns_match_exact_prefix_and_infix_names() {
        assert!(matches_name("RUSTFLAGS", "RUSTFLAGS"));
        assert!(!matches_name("RUSTFLAGS", "RUSTFLAGS_X"));
        assert!(matches_name(
            "CARGO_PROFILE_*",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL"
        ));
        assert!(matches_name(
            "CARGO_TARGET_*_RUSTFLAGS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"
        ));
        assert!(!matches_name(
            "CARGO_TARGET_*_RUSTFLAGS",
            "CARGO_TARGET_DIR"
        ));
    }

    #[test]
    fn every_refused_setting_named_in_the_brief_is_in_the_matrix() {
        let m =
            Matrix::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("matrix.toml")).expect("m");
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_BUILD_TARGET",
        ] {
            assert!(
                m.build.refused.iter().any(|p| matches_name(p, name)),
                "{name}"
            );
        }
        assert!(m
            .build
            .refused_values
            .iter()
            .any(|(n, v)| n == "CARGO_INCREMENTAL" && v == "1"));
    }

    #[test]
    fn the_command_line_is_checked() {
        assert!(parse(&args("dist --host x86_64-linux-gnu")).is_ok());
        assert!(parse(&args("dist")).is_err());
        assert!(parse(&args("build --host x86_64-linux-gnu")).is_err());
        assert!(parse(&args("plan --native")).is_ok());
        assert!(parse(&args("plan --native --host x")).is_err());
        assert!(parse(&args("plan --native --measurement-spans")).is_err());
        assert!(parse(&args("build --frobnicate")).is_err());
        assert!(parse(&args("install")).is_err());
    }
}
