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
//! cargo xtask triple --host <depends host>
//! cargo xtask archive-version [--version-override V]
//! ```
//!
//! `dist` builds a release host from depends' environment file
//! (`contrib/depends/<host>/share/toolchain.env`) and stages the binaries and
//! the files the archive carries; gitian then adds Tor and packs. `build` is
//! a native release build of this machine's triple. `plan` prints what
//! either would run, and runs nothing; the three version placeholders stay
//! written out, because a plan does not read the tag. `triple` prints a
//! host's Rust triple, for the toolchain's `rustup target add`, and
//! `archive-version` the version a release archive is named with. Every
//! variable comes from `rust/xtask/matrix.toml`. The arguments a plan appends
//! are [`plan::PlanFlag`].

mod matrix;
mod plan;
mod spawn;
mod version;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use matrix::Matrix;
use plan::{DependsEnv, Fill, Plan, VersionFill};
use spawn::RustcProbe;
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

/// What `cargo xtask` was asked to do. A variant carries only the options
/// that command accepts.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// `dist --host <host>`: a release host, from depends.
    Dist {
        host: String,
        out: Option<PathBuf>,
        measurement: bool,
        version_override: Option<String>,
    },
    /// `build`: this machine's triple.
    Build {
        out: Option<PathBuf>,
        measurement: bool,
        version_override: Option<String>,
    },
    /// `plan`: print the command. One subject, and no other option.
    Plan(Subject),
    /// `triple --host <host>`: the host's Rust triple.
    Triple { host: String },
    /// `archive-version`: the version a release archive is named with.
    ArchiveVersion { version_override: Option<String> },
}

/// Whose build a command describes.
#[derive(Debug, PartialEq, Eq)]
enum Subject {
    /// A release host, built from depends.
    Host(String),
    /// This machine's triple.
    Native,
}

/// One option, before a command decides whether it accepts it.
enum Flag {
    Host(String),
    Out(PathBuf),
    VersionOverride(String),
    Measurement,
    Native,
}

/// A subdirectory of the staged tree.
const STAGED_DIR_MODE: u32 = 0o755;

const USAGE: &str = "usage:\n  \
    cargo xtask dist --host <depends host> [--out DIR] [--measurement-spans] [--version-override V]\n  \
    cargo xtask build [--out DIR] [--measurement-spans] [--version-override V]\n  \
    cargo xtask plan (--host <depends host> | --native)\n  \
    cargo xtask triple --host <depends host>\n  \
    cargo xtask archive-version [--version-override V]";

fn parse(args: &[String]) -> Result<Command, String> {
    let mut it = args.iter();
    match it.next().ok_or(USAGE)?.as_str() {
        "dist" => parse_dist(&mut it),
        "build" => parse_build(&mut it),
        "plan" => parse_plan(&mut it),
        "triple" => parse_triple(&mut it),
        "archive-version" => parse_archive_version(&mut it),
        other => Err(format!("{other:?} is not a command\n{USAGE}")),
    }
}

fn next_flag(it: &mut std::slice::Iter<'_, String>) -> Result<Option<Flag>, String> {
    let Some(arg) = it.next() else {
        return Ok(None);
    };
    let mut value = || {
        it.next()
            .cloned()
            .ok_or_else(|| format!("{arg} needs a value\n{USAGE}"))
    };
    Ok(Some(match arg.as_str() {
        "--host" => Flag::Host(value()?),
        "--out" => Flag::Out(PathBuf::from(value()?)),
        "--version-override" => Flag::VersionOverride(value()?),
        "--measurement-spans" => Flag::Measurement,
        "--native" => Flag::Native,
        other => return Err(format!("{other:?} is not an option\n{USAGE}")),
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("`{name}` is given twice\n{USAGE}"));
    }
    *slot = Some(value);
    Ok(())
}

fn set_switch(slot: &mut bool, name: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("`{name}` is given twice\n{USAGE}"));
    }
    *slot = true;
    Ok(())
}

fn reject(command: &str) -> Result<Command, String> {
    Err(format!("these options do not fit `{command}`\n{USAGE}"))
}

fn parse_dist(it: &mut std::slice::Iter<'_, String>) -> Result<Command, String> {
    let mut host = None;
    let mut out = None;
    let mut measurement = false;
    let mut version_override = None;
    while let Some(flag) = next_flag(it)? {
        match flag {
            Flag::Host(value) => set_once(&mut host, value, "--host")?,
            Flag::Out(value) => set_once(&mut out, value, "--out")?,
            Flag::VersionOverride(value) => {
                set_once(&mut version_override, value, "--version-override")?;
            }
            Flag::Measurement => set_switch(&mut measurement, "--measurement-spans")?,
            Flag::Native => return reject("dist"),
        }
    }
    let host = host.ok_or_else(|| format!("`dist` needs `--host`\n{USAGE}"))?;
    Ok(Command::Dist {
        host,
        out,
        measurement,
        version_override,
    })
}

fn parse_build(it: &mut std::slice::Iter<'_, String>) -> Result<Command, String> {
    let mut out = None;
    let mut measurement = false;
    let mut version_override = None;
    while let Some(flag) = next_flag(it)? {
        match flag {
            Flag::Out(value) => set_once(&mut out, value, "--out")?,
            Flag::VersionOverride(value) => {
                set_once(&mut version_override, value, "--version-override")?;
            }
            Flag::Measurement => set_switch(&mut measurement, "--measurement-spans")?,
            Flag::Host(_) | Flag::Native => return reject("build"),
        }
    }
    Ok(Command::Build {
        out,
        measurement,
        version_override,
    })
}

fn parse_plan(it: &mut std::slice::Iter<'_, String>) -> Result<Command, String> {
    let mut host = None;
    let mut native = false;
    while let Some(flag) = next_flag(it)? {
        match flag {
            Flag::Host(value) => set_once(&mut host, value, "--host")?,
            Flag::Native => set_switch(&mut native, "--native")?,
            Flag::Out(_) | Flag::VersionOverride(_) | Flag::Measurement => return reject("plan"),
        }
    }
    match (host, native) {
        (Some(host), false) => Ok(Command::Plan(Subject::Host(host))),
        (None, true) => Ok(Command::Plan(Subject::Native)),
        _ => Err(format!("`plan` needs `--host` or `--native`\n{USAGE}")),
    }
}

fn parse_triple(it: &mut std::slice::Iter<'_, String>) -> Result<Command, String> {
    let mut host = None;
    while let Some(flag) = next_flag(it)? {
        match flag {
            Flag::Host(value) => set_once(&mut host, value, "--host")?,
            Flag::Out(_) | Flag::VersionOverride(_) | Flag::Measurement | Flag::Native => {
                return reject("triple");
            }
        }
    }
    let host = host.ok_or_else(|| format!("`triple` needs `--host`\n{USAGE}"))?;
    Ok(Command::Triple { host })
}

fn parse_archive_version(it: &mut std::slice::Iter<'_, String>) -> Result<Command, String> {
    let mut version_override = None;
    while let Some(flag) = next_flag(it)? {
        match flag {
            Flag::VersionOverride(value) => {
                set_once(&mut version_override, value, "--version-override")?;
            }
            Flag::Host(_) | Flag::Out(_) | Flag::Measurement | Flag::Native => {
                return reject("archive-version");
            }
        }
    }
    Ok(Command::ArchiveVersion { version_override })
}

fn run(args: &[String]) -> Result<(), String> {
    let command = parse(args)?;
    let root = repository_root()?;
    let matrix = Matrix::load(&root.join("rust/xtask/matrix.toml"))?;
    match command {
        Command::Triple { host } => {
            println!("{}", matrix.dist_host(&host)?.0.triple);
            Ok(())
        }
        Command::ArchiveVersion { version_override } => {
            let identity = identity(&root, &matrix, version_override.as_deref())?;
            println!("{}", identity.archive_version()?);
            Ok(())
        }
        Command::Plan(subject) => {
            let resolved = resolve(&root, &matrix, &subject)?;
            let plan = make_plan(&root, &matrix, &resolved, VersionFill::Shown, false)?;
            print_plan(&plan, &mut std::io::stdout());
            Ok(())
        }
        Command::Dist {
            host,
            out,
            measurement,
            version_override,
        } => release(
            &root,
            &matrix,
            &Subject::Host(host),
            out,
            measurement,
            version_override.as_deref(),
        ),
        Command::Build {
            out,
            measurement,
            version_override,
        } => release(
            &root,
            &matrix,
            &Subject::Native,
            out,
            measurement,
            version_override.as_deref(),
        ),
    }
}

/// A host and the invocation the matrix gives it, with the files a dist
/// stages. A native build has no depends file and stages nothing of its own.
struct Resolved<'a> {
    host: &'a matrix::Host,
    invocation: &'a matrix::Invocation,
    depends: Option<DependsEnv>,
    binary_mode: Option<u32>,
    files: &'a [matrix::StagedFile],
}

fn resolve<'a>(root: &Path, matrix: &'a Matrix, subject: &Subject) -> Result<Resolved<'a>, String> {
    match subject {
        Subject::Host(name) => {
            let (host, dist) = matrix.dist_host(name)?;
            let env_file = root
                .join("contrib/depends")
                .join(name)
                .join("share/toolchain.env");
            Ok(Resolved {
                host,
                invocation: &dist.invocation,
                depends: Some(DependsEnv::read(&env_file)?),
                binary_mode: dist.binary_mode,
                files: &dist.files,
            })
        }
        Subject::Native => {
            let triple = host_triple(root)?;
            let (host, invocation) = matrix.native_host(&triple)?;
            Ok(Resolved {
                host,
                invocation,
                depends: None,
                binary_mode: None,
                files: &[],
            })
        }
    }
}

fn make_plan(
    root: &Path,
    matrix: &Matrix,
    resolved: &Resolved<'_>,
    version: VersionFill,
    measurement: bool,
) -> Result<Plan, String> {
    let fill = Fill {
        depends: resolved.depends.clone(),
        target_dir: root.join(&matrix.build.target_dir),
        version,
        macos: resolved.host.macos.clone(),
    };
    plan::plan(
        matrix,
        resolved.host,
        resolved.invocation,
        &fill,
        measurement,
        std::env::var_os("PATH").as_deref(),
    )
}

/// Builds `subject` and stages what the matrix says the archive carries.
fn release(
    root: &Path,
    matrix: &Matrix,
    subject: &Subject,
    out: Option<PathBuf>,
    measurement: bool,
    version_override: Option<&str>,
) -> Result<(), String> {
    refuse_build_machine_settings(matrix)?;
    check_toolchain(root, matrix)?;
    let identity = identity(root, matrix, version_override)?;
    if measurement && matches!(subject, Subject::Host(_)) && identity.is_release {
        return Err(format!(
            "--measurement-spans at a release ({}): a measurement build is never a release archive",
            identity.full
        ));
    }
    if measurement {
        eprintln!("xtask: warning: {}", matrix.measurement.warning);
    }
    let resolved = resolve(root, matrix, subject)?;
    let plan = make_plan(
        root,
        matrix,
        &resolved,
        VersionFill::Resolved(identity.clone()),
        measurement,
    )?;
    eprintln!(
        "xtask: {} ({}), {}",
        resolved.host.name, resolved.host.triple, identity.full
    );
    print_plan(&plan, &mut std::io::stderr());
    spawn::cargo(root, &plan)?;
    let out = out.unwrap_or_else(|| root.join("build/bin"));
    stage(root, &plan, resolved.binary_mode, resolved.files, &out)?;
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
    let text = spawn::rustc(root, RustcProbe::Verbose)?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: "))
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
        if matrix
            .build
            .refused
            .iter()
            .any(|pattern| plan::matches_pattern(pattern, name))
        {
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
    let reported = spawn::rustc(root, RustcProbe::Version)?;
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

fn identity(
    root: &Path,
    matrix: &Matrix,
    version_override: Option<&str>,
) -> Result<Identity, String> {
    let defaults = &matrix.version;
    match version_override {
        Some(version) => version::from_override_at(root, version, &defaults.release_name),
        None => version::from_git(
            &GitHead::read(root)?,
            &defaults.default,
            &defaults.release_name,
        ),
    }
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

/// Copies the binaries and the host's files into `out`. A directory the
/// files need under `out` is 755 (FreeBSD's `rc.d`).
fn stage(
    root: &Path,
    plan: &Plan,
    binary_mode: Option<u32>,
    files: &[matrix::StagedFile],
    out: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    for built in &plan.outputs {
        let name = built
            .file_name()
            .ok_or_else(|| format!("{} has no file name", built.display()))?;
        copy(built, &out.join(name), binary_mode)?;
    }
    for file in files {
        let to = out.join(&file.staged);
        copy(&root.join(&file.source), &to, file.mode)?;
        if let Some(dir) = to.parent().filter(|dir| *dir != out) {
            set_mode(dir, STAGED_DIR_MODE)?;
        }
    }
    Ok(())
}

/// Copies `from` to `to`. `std::fs::copy` carries the source's permission
/// bits, which is what `None` keeps.
fn copy(from: &Path, to: &Path, mode: Option<u32>) -> Result<(), String> {
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // A staged file from an earlier run may be read-only (the rc.d
    // scripts are 555): replace it rather than write into it.
    if to.exists() {
        std::fs::remove_file(to).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    std::fs::copy(from, to).map_err(|e| format!("{} -> {}: {e}", from.display(), to.display()))?;
    match mode {
        Some(mode) => set_mode(to, mode),
        None => Ok(()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
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
                m.build
                    .refused
                    .iter()
                    .any(|pattern| plan::matches_pattern(pattern, name)),
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
        assert!(parse(&args("triple --host x86_64-linux-gnu")).is_ok());
        assert!(parse(&args("triple")).is_err());
        assert!(parse(&args("triple --host x --out y")).is_err());
        assert!(parse(&args("archive-version")).is_ok());
        assert!(parse(&args("archive-version --version-override 3.1.0")).is_ok());
        assert!(parse(&args("archive-version --host x")).is_err());
    }
}
