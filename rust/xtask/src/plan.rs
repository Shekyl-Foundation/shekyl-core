// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cargo invocation for one host: the matrix's values with their
//! placeholders filled, and nothing else. Every variable and argument the
//! build is given comes from `matrix.toml`; this module only substitutes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::matrix::{Build, Host, Invocation, MacosMinimum, Matrix};
use crate::version::Identity;

/// What the run is given and what it leaves.
#[derive(Debug)]
pub struct Plan {
    /// Set, in this order, after the removals.
    pub env: Vec<(String, String)>,
    /// Removed: exact names, and prefixes ending in `*`.
    pub unset: Vec<String>,
    /// `cargo` and its arguments.
    pub args: Vec<String>,
    /// The built binaries, where cargo leaves them.
    pub outputs: Vec<PathBuf>,
}

/// The values a placeholder can take.
#[derive(Debug, Default)]
pub struct Fill {
    /// `{prefix}`, `{cc}`, `{ar}`: from depends' environment file.
    pub depends: Option<DependsEnv>,
    /// `{target_dir}` as an absolute path.
    pub target_dir: PathBuf,
    pub identity: Option<Identity>,
    /// `{macos_minimum}`, `{macos_minimum_depends}`: the host's.
    pub macos: Option<MacosMinimum>,
}

/// `contrib/depends/<host>/share/toolchain.env`: the prefix and the
/// compiler and archiver depends built for the host.
#[derive(Debug, Clone)]
pub struct DependsEnv {
    pub prefix: String,
    pub cc: String,
    pub ar: String,
}

impl DependsEnv {
    /// Reads the file: `NAME=value` lines, `#` comments; PREFIX, CC and AR
    /// each exactly once and nothing else.
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "{}: cannot read ({e}); build depends for this host first \
                 (make -C contrib/depends HOST=<host>)",
                path.display()
            )
        })?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut seen = BTreeMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: not NAME=value", n + 1))?;
            if !matches!(name, "PREFIX" | "CC" | "AR") {
                return Err(format!("line {}: {name} is not PREFIX, CC or AR", n + 1));
            }
            if seen.insert(name.to_owned(), value.to_owned()).is_some() {
                return Err(format!("{name} is set twice"));
            }
        }
        let mut get = |name: &str| {
            seen.remove(name)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{name} is missing or empty"))
        };
        Ok(Self {
            prefix: get("PREFIX")?,
            cc: get("CC")?,
            ar: get("AR")?,
        })
    }
}

/// The plan for `host` run with `invocation`.
pub fn plan(
    matrix: &Matrix,
    host: &Host,
    invocation: &Invocation,
    fill: &Fill,
    measurement: bool,
    path_var: Option<&std::ffi::OsStr>,
) -> Result<Plan, String> {
    let build: &Build = &matrix.build;
    let mut env = Vec::new();
    for (name, value) in build.env.iter().chain(&invocation.env) {
        env.push((name.clone(), substitute(value, fill, path_var)?));
    }

    let mut args = vec!["cargo".to_owned()];
    args.extend(build.cargo_args.iter().cloned());
    if invocation.target {
        args.push("--target".to_owned());
        args.push(host.triple.clone());
    }
    for bin in &host.binaries {
        args.push("-p".to_owned());
        args.push(bin.clone());
    }
    if measurement {
        args.push("--features".to_owned());
        args.push(matrix.measurement.features.join(","));
    }

    let mut dir = fill.target_dir.clone();
    if invocation.target {
        dir.push(&host.triple);
    }
    dir.push(&build.profile_dir);
    let suffix = if host.triple.contains("-windows-") {
        ".exe"
    } else {
        ""
    };
    let outputs = host
        .binaries
        .iter()
        .map(|b| dir.join(format!("{b}{suffix}")))
        .collect();

    Ok(Plan {
        env,
        unset: build.unset.clone(),
        args,
        outputs,
    })
}

/// Fills every `{…}` in `value`. An unknown or unavailable placeholder is an
/// error, never an empty string.
fn substitute(
    value: &str,
    fill: &Fill,
    path_var: Option<&std::ffi::OsStr>,
) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after
            .find('}')
            .ok_or_else(|| format!("{value:?}: a `{{` with no `}}`"))?;
        let key = &after[..close];
        out.push_str(&resolve(key, fill, path_var).map_err(|e| format!("{value:?}: {e}"))?);
        rest = &after[close + 1..];
    }
    if rest.contains('}') {
        return Err(format!("{value:?}: a `}}` with no `{{`"));
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve(key: &str, fill: &Fill, path_var: Option<&std::ffi::OsStr>) -> Result<String, String> {
    let depends = || {
        fill.depends.as_ref().ok_or_else(|| {
            format!("{{{key}}} needs depends' environment file, and this build has none")
        })
    };
    let identity = || {
        fill.identity
            .as_ref()
            .ok_or_else(|| format!("{{{key}}} needs the build identity"))
    };
    let macos = || {
        fill.macos
            .as_ref()
            .ok_or_else(|| format!("{{{key}}} is for a macOS host"))
    };
    Ok(match key {
        "prefix" => depends()?.prefix.clone(),
        // The compiler: the first word, found on PATH. A
        // depends CC of `gcc -m64` gave cargo `/usr/bin/gcc`.
        "cc" => which(first_word(&depends()?.cc), path_var)?,
        "ar" => which(first_word(&depends()?.ar), path_var)?,
        "target_dir" => target_dir_value(
            fill.target_dir
                .to_str()
                .ok_or("the target directory is not UTF-8")?,
            cfg!(windows),
        ),
        "version_full" => identity()?.full.clone(),
        "release_name" => identity()?.release_name.clone(),
        "is_release" => if identity()?.is_release {
            "true"
        } else {
            "false"
        }
        .to_owned(),
        "macos_minimum" => macos()?.value.clone(),
        "macos_minimum_depends" => macos()?.depends_spelling.clone(),
        other => match other.strip_prefix("which:") {
            Some(name) => which(name, path_var)?,
            None => return Err(format!("{{{other}}} is not a placeholder the xtask fills")),
        },
    })
}

/// The target directory as cargo is given it. On Windows it is written with
/// forward slashes, the form this build has always passed: build scripts'
/// output paths are compiled into the binaries (`include!` of `OUT_DIR`), so
/// the separator is part of the daemon's bytes.
fn target_dir_value(path: &str, windows: bool) -> String {
    if windows {
        path.replace('\\', "/")
    } else {
        path.to_owned()
    }
}

fn first_word(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

/// `name` if it is a path, else its first match on `PATH`.
fn which(name: &str, path_var: Option<&std::ffi::OsStr>) -> Result<String, String> {
    if name.is_empty() {
        return Err("an empty program name".to_owned());
    }
    let as_path = Path::new(name);
    if as_path.components().count() > 1 {
        return if as_path.is_file() {
            Ok(name.to_owned())
        } else {
            Err(format!("{name} does not exist"))
        };
    }
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(path_var.ok_or("PATH is not set")?) {
        for ext in exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return candidate
                    .to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{} is not UTF-8", candidate.display()));
            }
        }
    }
    Err(format!("{name} is not on PATH"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn matrix() -> Matrix {
        Matrix::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("matrix.toml")).expect("matrix")
    }

    /// A file that exists on every build machine, standing for the compiler
    /// and the archiver: found by name on [`tool_path`], as a real one is.
    const TOOL: &str = "matrix.toml";

    /// The `PATH` the fixture's tool is on.
    fn tool_path() -> OsString {
        OsString::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn fill() -> Fill {
        Fill {
            depends: Some(DependsEnv {
                prefix: "/d/x86_64-apple-darwin11".to_owned(),
                cc: format!("{TOOL} -m64"),
                ar: TOOL.to_owned(),
            }),
            target_dir: PathBuf::from("/r/rust/target"),
            identity: Some(Identity {
                full: "3.1.0-842d36361".to_owned(),
                release_name: "Shekyl NG".to_owned(),
                is_release: false,
            }),
            macos: Some(MacosMinimum {
                value: "11.0".to_owned(),
                depends_spelling: "10.16".to_owned(),
            }),
        }
    }

    #[test]
    fn the_macos_minimum_has_one_value_and_one_compiler_spelling() {
        let m = matrix();
        let (host, dist) = m.dist_host("aarch64-apple-darwin11").expect("host");
        let p = plan(&m, host, &dist.invocation, &fill(), false, None).expect("plan");
        let get = |n: &str| &p.env.iter().find(|(k, _)| k == n).expect(n).1;
        assert_eq!(get("MACOSX_DEPLOYMENT_TARGET"), "10.16");
        assert!(get("CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS")
            .ends_with("-C link-arg=-mmacosx-version-min=10.16"));
        assert_eq!(
            substitute("{macos_minimum}", &fill(), None).as_deref(),
            Ok("11.0")
        );
        assert!(substitute("{macos_minimum}", &Fill::default(), None).is_err());
    }

    #[test]
    fn a_dist_plan_fills_every_placeholder_and_names_the_target() {
        let m = matrix();
        let (host, dist) = m.dist_host("x86_64-apple-darwin11").expect("host");
        let p = plan(&m, host, &dist.invocation, &fill(), false, None).expect("plan");
        assert!(p.env.iter().all(|(_, v)| !v.contains('{')), "{:?}", p.env);
        let sdk = p.env.iter().find(|(n, _)| n == "SDKROOT").expect("SDKROOT");
        assert_eq!(sdk.1, "/d/x86_64-apple-darwin11/native/SDK/");
        assert!(p
            .args
            .windows(2)
            .any(|w| w == ["--target", "x86_64-apple-darwin"]));
        assert_eq!(
            p.outputs[0],
            PathBuf::from("/r/rust/target/x86_64-apple-darwin/release/shekyld")
        );
        assert!(!p.args.iter().any(|a| a == "--features"));
    }

    #[test]
    fn cc_is_the_first_word_of_depends_cc() {
        let m = matrix();
        let (host, dist) = m.dist_host("x86_64-linux-gnu").expect("host");
        let path = tool_path();
        let p = plan(&m, host, &dist.invocation, &fill(), false, Some(&path)).expect("plan");
        let cc = p
            .env
            .iter()
            .find(|(n, _)| n == "CC_x86_64_unknown_linux_gnu")
            .expect("CC");
        let found = Path::new(env!("CARGO_MANIFEST_DIR")).join(TOOL);
        assert_eq!(Path::new(&cc.1), found);
    }

    #[test]
    fn the_measurement_build_adds_exactly_the_three_features() {
        let m = matrix();
        let (host, dist) = m.dist_host("x86_64-linux-gnu").expect("host");
        let path = tool_path();
        let p = plan(&m, host, &dist.invocation, &fill(), true, Some(&path)).expect("plan");
        let at = p
            .args
            .iter()
            .position(|a| a == "--features")
            .expect("features");
        assert_eq!(p.args[at + 1], m.measurement.features.join(","));
    }

    #[test]
    fn windows_binaries_carry_exe() {
        let m = matrix();
        let (host, dist) = m.dist_host("x86_64-w64-mingw32").expect("host");
        let path = tool_path();
        let p = plan(&m, host, &dist.invocation, &fill(), false, Some(&path)).expect("plan");
        assert!(p
            .outputs
            .iter()
            .all(|o| o.extension().is_some_and(|e| e == "exe")));
    }

    #[test]
    fn an_unknown_placeholder_is_an_error() {
        let err = substitute("x{opt_level}", &fill(), None).expect_err("unknown");
        assert!(err.contains("opt_level"), "{err}");
        assert!(substitute("{prefix", &fill(), None).is_err());
    }

    #[test]
    fn the_target_dir_keeps_forward_slashes_on_windows() {
        assert_eq!(
            target_dir_value(r"C:\Users\s\src\rust/target", true),
            "C:/Users/s/src/rust/target"
        );
        assert_eq!(target_dir_value(r"/r/a\b/target", false), r"/r/a\b/target");
    }

    #[test]
    fn a_native_plan_has_no_depends_values() {
        let err = substitute("{prefix}", &Fill::default(), None).expect_err("no depends");
        assert!(err.contains("depends"), "{err}");
    }

    #[test]
    fn the_depends_file_takes_exactly_three_names() {
        let ok = DependsEnv::parse("# x\nPREFIX=/p\nCC=gcc -m64\nAR=ar\n").expect("ok");
        assert_eq!(ok.cc, "gcc -m64");
        assert!(DependsEnv::parse("PREFIX=/p\nCC=gcc\nAR=ar\nRUSTFLAGS=x\n").is_err());
        assert!(DependsEnv::parse("PREFIX=/p\nCC=gcc\n").is_err());
        assert!(DependsEnv::parse("PREFIX=/p\nCC=gcc\nCC=cc\nAR=ar\n").is_err());
    }
}
