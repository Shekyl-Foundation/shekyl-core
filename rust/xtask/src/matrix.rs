// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `rust/xtask/matrix.toml`, read strictly: an unknown key is an error, so
//! a setting the xtask would ignore cannot sit in the file looking applied.

use std::collections::BTreeSet;
use std::path::Path;

use toml::{Table, Value};

/// The whole file.
#[derive(Debug)]
pub struct Matrix {
    pub build: Build,
    pub version: VersionDefaults,
    pub measurement: Measurement,
    pub hosts: Vec<Host>,
}

/// `[build]`: what every build is given.
#[derive(Debug)]
pub struct Build {
    pub toolchain_file: String,
    pub cargo_args: Vec<String>,
    pub target_dir: String,
    pub profile_dir: String,
    pub env: Vec<(String, String)>,
    pub unset: Vec<String>,
    pub refused: Vec<String>,
    pub refused_values: Vec<(String, String)>,
}

/// `[version]`.
#[derive(Debug)]
pub struct VersionDefaults {
    pub default: String,
    pub release_name: String,
}

/// `[measurement]`.
#[derive(Debug)]
pub struct Measurement {
    pub features: Vec<String>,
    pub warning: String,
}

/// One `[[host]]`.
#[derive(Debug)]
pub struct Host {
    /// The depends host (`x86_64-linux-gnu`), or the triple for a host with
    /// no depends recipe.
    pub name: String,
    pub triple: String,
    pub binaries: Vec<String>,
    /// A macOS host's minimum, and how depends' compiler must spell it.
    pub macos: Option<MacosMinimum>,
    pub dist: Option<Dist>,
    pub native: Option<Invocation>,
}

/// One minimum macOS per host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosMinimum {
    /// `macos_minimum`.
    pub value: String,
    /// `macos_minimum_depends`, or the value when the compiler accepts it.
    pub depends_spelling: String,
}

/// How cargo is run for one host and mode.
#[derive(Debug)]
pub struct Invocation {
    /// Whether `--target <triple>` is passed.
    pub target: bool,
    pub env: Vec<(String, String)>,
}

/// `[host.dist]`: the invocation, and what the archive carries beside the
/// binaries.
#[derive(Debug)]
pub struct Dist {
    pub invocation: Invocation,
    /// The staged binaries' permission bits; `None` keeps what the build left.
    pub binary_mode: Option<u32>,
    pub files: Vec<StagedFile>,
}

/// A file staged beside the binaries.
#[derive(Debug)]
pub struct StagedFile {
    /// Relative to the repository root.
    pub source: String,
    /// Relative to the staging directory.
    pub staged: String,
    /// Its permission bits; `None` keeps the source file's.
    pub mode: Option<u32>,
}

impl Matrix {
    /// Reads and checks the file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: cannot read ({e})", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Parses the text of the file.
    pub fn parse(text: &str) -> Result<Self, String> {
        let root: Table = text.parse().map_err(|e| format!("not TOML: {e}"))?;
        let mut root = Fields::new("the file", root);
        let build = Build::parse(root.table("build")?)?;
        let version = {
            let mut t = root.table("version")?;
            let v = VersionDefaults {
                default: t.string("default")?,
                release_name: t.string("release_name")?,
            };
            t.done()?;
            v
        };
        let measurement = {
            let mut t = root.table("measurement")?;
            let m = Measurement {
                features: t.strings("features")?,
                warning: t.string("warning")?,
            };
            t.done()?;
            m
        };
        let mut hosts = Vec::new();
        for (i, value) in root.array("host")?.into_iter().enumerate() {
            let Value::Table(table) = value else {
                return Err(format!("[[host]] {i} is not a table"));
            };
            hosts.push(Host::parse(Fields::new(&format!("[[host]] {i}"), table))?);
        }
        root.done()?;

        let mut names = BTreeSet::new();
        let mut triples = BTreeSet::new();
        for host in &hosts {
            if !names.insert(host.name.as_str()) {
                return Err(format!("host {} is listed twice", host.name));
            }
            if host.native.is_some() && !triples.insert(host.triple.as_str()) {
                return Err(format!("two hosts build natively for {}", host.triple));
            }
        }
        Ok(Self {
            build,
            version,
            measurement,
            hosts,
        })
    }

    /// The host `cargo xtask dist --host <name>` names.
    pub fn dist_host(&self, name: &str) -> Result<(&Host, &Dist), String> {
        let host = self.hosts.iter().find(|h| h.name == name).ok_or_else(|| {
            format!(
                "{name} is not a host in the matrix; the hosts are {}",
                self.names(|h| h.dist.is_some())
            )
        })?;
        let dist = host
            .dist
            .as_ref()
            .ok_or_else(|| format!("{name} has no release archive (no [host.dist])"))?;
        Ok((host, dist))
    }

    /// The host whose triple is this machine's.
    pub fn native_host(&self, triple: &str) -> Result<(&Host, &Invocation), String> {
        self.hosts
            .iter()
            .find_map(|h| {
                h.native
                    .as_ref()
                    .filter(|_| h.triple == triple)
                    .map(|n| (h, n))
            })
            .ok_or_else(|| {
                format!(
                    "this machine's triple {triple} has no native build in the matrix; \
                     the native triples are {}",
                    self.triples()
                )
            })
    }

    fn names(&self, keep: impl Fn(&Host) -> bool) -> String {
        let names: Vec<&str> = self
            .hosts
            .iter()
            .filter(|h| keep(h))
            .map(|h| h.name.as_str())
            .collect();
        names.join(", ")
    }

    fn triples(&self) -> String {
        let triples: Vec<&str> = self
            .hosts
            .iter()
            .filter(|h| h.native.is_some())
            .map(|h| h.triple.as_str())
            .collect();
        triples.join(", ")
    }
}

impl Build {
    fn parse(mut t: Fields) -> Result<Self, String> {
        let build = Self {
            toolchain_file: t.string("toolchain_file")?,
            cargo_args: t.strings("cargo_args")?,
            target_dir: t.string("target_dir")?,
            profile_dir: t.string("profile_dir")?,
            env: t.pairs("env")?,
            unset: t.strings("unset")?,
            refused: t.strings("refused")?,
            refused_values: t.pairs("refused_values")?,
        };
        t.done()?;
        Ok(build)
    }
}

impl Host {
    fn parse(mut t: Fields) -> Result<Self, String> {
        let name = t.string("name")?;
        let triple = t.string("triple")?;
        let binaries = t.strings("binaries")?;
        let macos = match t.optional_string("macos_minimum")? {
            Some(value) => {
                let depends_spelling = t
                    .optional_string("macos_minimum_depends")?
                    .unwrap_or_else(|| value.clone());
                Some(MacosMinimum {
                    value,
                    depends_spelling,
                })
            }
            None => None,
        };
        if macos.is_some() != triple.contains("-apple-") {
            return Err(format!(
                "host {name}: macos_minimum is for the macOS hosts, and each must have one"
            ));
        }
        let dist = match t.optional_table("dist")? {
            Some(mut d) => {
                let invocation = Invocation {
                    target: d.boolean("target")?,
                    env: d.pairs("env")?,
                };
                let binary_mode = parse_mode(&d.string("binary_mode")?)
                    .map_err(|e| format!("host {name}: binary_mode: {e}"))?;
                let mut files = Vec::new();
                for row in d.rows("files", 3)? {
                    let [source, staged, mode] = <[String; 3]>::try_from(row)
                        .map_err(|_| format!("host {name}: a files row is not three strings"))?;
                    let mode =
                        parse_mode(&mode).map_err(|e| format!("host {name}: {staged}: {e}"))?;
                    files.push(StagedFile {
                        source,
                        staged,
                        mode,
                    });
                }
                d.done()?;
                Some(Dist {
                    invocation,
                    binary_mode,
                    files,
                })
            }
            None => None,
        };
        let native = match t.optional_table("native")? {
            Some(mut n) => {
                let invocation = Invocation {
                    target: n.boolean("target")?,
                    env: n.pairs("env")?,
                };
                n.done()?;
                Some(invocation)
            }
            None => None,
        };
        t.done()?;
        if dist.is_none() && native.is_none() {
            return Err(format!(
                "host {name} has neither [host.dist] nor [host.native]"
            ));
        }
        if binaries.is_empty() {
            return Err(format!("host {name} builds no binary"));
        }
        Ok(Self {
            name,
            triple,
            binaries,
            macos,
            dist,
            native,
        })
    }
}

/// `644`, `555` or `755`, or `inherit`: leave the bits as the copy made them.
fn parse_mode(text: &str) -> Result<Option<u32>, String> {
    if text == "inherit" {
        return Ok(None);
    }
    u32::from_str_radix(text, 8)
        .ok()
        .filter(|m| matches!(m, 0o644 | 0o555 | 0o755))
        .map(Some)
        .ok_or_else(|| format!("mode {text} is not 644, 555, 755 or inherit"))
}

/// A table being read: each read removes its key, and [`Fields::done`]
/// refuses whatever is left.
struct Fields {
    what: String,
    table: Table,
}

impl Fields {
    fn new(what: &str, table: Table) -> Self {
        Self {
            what: what.to_owned(),
            table,
        }
    }

    fn take(&mut self, key: &str) -> Result<Value, String> {
        self.table
            .remove(key)
            .ok_or_else(|| format!("{} has no `{key}`", self.what))
    }

    fn string(&mut self, key: &str) -> Result<String, String> {
        match self.take(key)? {
            Value::String(s) => Ok(s),
            _ => Err(format!("{}: `{key}` is not a string", self.what)),
        }
    }

    fn optional_string(&mut self, key: &str) -> Result<Option<String>, String> {
        if self.table.contains_key(key) {
            self.string(key).map(Some)
        } else {
            Ok(None)
        }
    }

    fn boolean(&mut self, key: &str) -> Result<bool, String> {
        match self.take(key)? {
            Value::Boolean(b) => Ok(b),
            _ => Err(format!("{}: `{key}` is not true or false", self.what)),
        }
    }

    fn array(&mut self, key: &str) -> Result<Vec<Value>, String> {
        match self.take(key)? {
            Value::Array(a) => Ok(a),
            _ => Err(format!("{}: `{key}` is not an array", self.what)),
        }
    }

    fn strings(&mut self, key: &str) -> Result<Vec<String>, String> {
        let what = format!("{}: `{key}`", self.what);
        self.array(key)?
            .into_iter()
            .map(|v| match v {
                Value::String(s) => Ok(s),
                _ => Err(format!("{what} holds a value that is not a string")),
            })
            .collect()
    }

    fn rows(&mut self, key: &str, width: usize) -> Result<Vec<Vec<String>>, String> {
        let what = format!("{}: `{key}`", self.what);
        self.array(key)?
            .into_iter()
            .map(|row| {
                let Value::Array(cells) = row else {
                    return Err(format!("{what} holds a row that is not an array"));
                };
                if cells.len() != width {
                    return Err(format!(
                        "{what} holds a row of {} cells, not {width}",
                        cells.len()
                    ));
                }
                cells
                    .into_iter()
                    .map(|c| match c {
                        Value::String(s) => Ok(s),
                        _ => Err(format!("{what} holds a cell that is not a string")),
                    })
                    .collect()
            })
            .collect()
    }

    fn pairs(&mut self, key: &str) -> Result<Vec<(String, String)>, String> {
        let what = format!("{}: `{key}`", self.what);
        let rows = self.rows(key, 2)?;
        let mut seen = BTreeSet::new();
        rows.into_iter()
            .map(|row| {
                let [name, value] = <[String; 2]>::try_from(row)
                    .map_err(|_| format!("{what} holds a row that is not a pair"))?;
                if !seen.insert(name.clone()) {
                    return Err(format!("{what} names {name} twice"));
                }
                Ok((name, value))
            })
            .collect()
    }

    fn table(&mut self, key: &str) -> Result<Fields, String> {
        match self.take(key)? {
            Value::Table(t) => Ok(Fields::new(&format!("[{key}]"), t)),
            _ => Err(format!("{}: `{key}` is not a table", self.what)),
        }
    }

    fn optional_table(&mut self, key: &str) -> Result<Option<Fields>, String> {
        if self.table.contains_key(key) {
            let what = format!("{}.{key}", self.what);
            match self.take(key)? {
                Value::Table(t) => Ok(Some(Fields::new(&what, t))),
                _ => Err(format!("{what} is not a table")),
            }
        } else {
            Ok(None)
        }
    }

    fn done(self) -> Result<(), String> {
        match self.table.keys().next() {
            None => Ok(()),
            Some(key) => Err(format!(
                "{}: `{key}` is not a key the xtask reads; remove it or teach the xtask",
                self.what
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committed() -> Matrix {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("matrix.toml");
        Matrix::load(&path).expect("the committed matrix parses")
    }

    #[test]
    fn the_committed_matrix_parses_with_the_six_release_hosts() {
        let m = committed();
        let dist: Vec<&str> = m
            .hosts
            .iter()
            .filter(|h| h.dist.is_some())
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(
            dist,
            [
                "x86_64-linux-gnu",
                "aarch64-linux-gnu",
                "x86_64-w64-mingw32",
                "x86_64-apple-darwin11",
                "aarch64-apple-darwin11",
                "x86_64-unknown-freebsd",
            ]
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let text =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("matrix.toml"))
                .expect("read");
        let planted = text.replacen("[build]\n", "[build]\nopt_level = \"3\"\n", 1);
        let err = Matrix::parse(&planted).expect_err("an unread key is refused");
        assert!(err.contains("opt_level"), "{err}");
    }

    #[test]
    fn each_macos_host_has_one_minimum() {
        let m = committed();
        let of = |name: &str| {
            m.hosts
                .iter()
                .find(|h| h.name == name)
                .and_then(|h| h.macos.clone())
                .expect("a macOS host")
        };
        let x86 = of("x86_64-apple-darwin11");
        assert_eq!(
            (x86.value.as_str(), x86.depends_spelling.as_str()),
            ("10.15", "10.15")
        );
        let arm = of("aarch64-apple-darwin11");
        assert_eq!(
            (arm.value.as_str(), arm.depends_spelling.as_str()),
            ("11.0", "10.16")
        );
        assert!(m
            .hosts
            .iter()
            .filter(|h| !h.triple.contains("-apple-"))
            .all(|h| h.macos.is_none()));
    }

    #[test]
    fn a_macos_host_without_a_minimum_is_refused() {
        let text =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("matrix.toml"))
                .expect("read");
        let err = Matrix::parse(&text.replacen("macos_minimum = \"10.15\"\n", "", 1))
            .expect_err("no minimum");
        assert!(err.contains("macos_minimum"), "{err}");
    }

    #[test]
    fn a_mode_is_one_of_the_named_values() {
        assert_eq!(parse_mode("755"), Ok(Some(0o755)));
        assert_eq!(parse_mode("inherit"), Ok(None));
        assert!(parse_mode("777").is_err());
        assert!(parse_mode("rwx").is_err());
    }

    #[test]
    fn a_host_named_twice_is_refused() {
        let text =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("matrix.toml"))
                .expect("read");
        let extra =
            "\n[[host]]\nname = \"x86_64-linux-gnu\"\ntriple = \"x\"\nbinaries = [\"shekyld\"]\n\
                     [host.dist]\ntarget = true\nenv = []\nbinary_mode = \"755\"\nfiles = []\n";
        let err = Matrix::parse(&format!("{text}{extra}")).expect_err("a second row is refused");
        assert!(err.contains("listed twice"), "{err}");
    }

    #[test]
    fn a_triple_outside_the_matrix_is_refused_natively() {
        let err = committed()
            .native_host("riscv64gc-unknown-linux-gnu")
            .expect_err("no native row");
        assert!(err.contains("riscv64gc-unknown-linux-gnu"), "{err}");
    }
}
