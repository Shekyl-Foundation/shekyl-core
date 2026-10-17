// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed refusals and their one renderer (IG-11).
//!
//! Every refusal is a [`Diagnostic`]: a stable [`Code`], the option it is
//! about, where the value came from ([`Source`]), and named parameters. The
//! code and the parameters are the contract a script reads; [`Diagnostic::render`]
//! is the one place that turns them into English, and the English says what
//! was wrong, where, and what to do (rule 82).

use std::fmt;
use std::path::PathBuf;

/// The stable identity of a refusal. The string [`Code::as_str`] returns is
/// what machine output and logs carry; it never changes meaning once
/// shipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// A command-line token is not `--name` followed by its value.
    CliSyntax,
    /// A command-line argument is not valid UTF-8.
    CliEncoding,
    /// A single-valued option was given twice on the command line.
    CliRepeated,
    /// No option has this name.
    NameUnknown,
    /// The name is a feature the project refuses (a REJECTED row).
    NameRejected,
    /// The name is held for a ruled future option (a RESERVED row).
    NameReserved,
    /// The value is given where its row forbids it (a secret on the command
    /// line, a command-line-only option in the file).
    ValueSurface,
    /// The value does not have its kind's syntax.
    ValueSyntax,
    /// The value has the right syntax and is outside the row's constraint.
    ValueRange,
    /// The quantity's unit is not one the kind accepts.
    ValueUnit,
    /// The value is not one of the row's words.
    ValueWord,
    /// A placeholder in a command is not one the row names.
    ValuePlaceholder,
    /// The option needs another option that is not set.
    ValueRequires,
    /// The option cannot be set together with the value of another.
    ValueConflict,
    /// A development lever is set on a network its row does not name.
    DevNetwork,
    /// A file the operator named does not exist.
    FileMissing,
    /// A file exists and cannot be opened or read.
    FileUnreadable,
    /// A file, or a directory above it, can be written outside the
    /// permitted principals.
    FilePermissions,
    /// A file holding a secret can be read outside the permitted principals.
    FileSecretReadable,
    /// The configuration file is not valid TOML.
    FileSyntax,
    /// A path default needs the account's home and the account has none.
    PathNoHome,
    /// The data directory cannot be created, or is not a directory.
    DataDirUnusable,
    /// Another daemon holds the data directory's lock.
    DataDirLocked,
    /// The data directory's marker names another network.
    MarkerNetwork,
    /// The marker names this network with a different network id.
    MarkerNetworkId,
    /// The data directory holds a daemon store and no marker.
    MarkerMissing,
    /// The marker cannot be read or does not parse.
    MarkerUnreadable,
    /// The log location cannot be written.
    LogUnwritable,
    /// The ban file cannot be read.
    BanFileUnreadable,
    /// A line of the ban file does not parse.
    BanFileLine,
    /// A runtime set names a row that is not marked runtime.
    RuntimeStartupOnly,
    /// A client-mode command has no admin endpoint to reach.
    ClientNoEndpoint,
    /// The service run mode is not available on this platform.
    ServicePlatform,
    /// The service run mode was asked for outside the service manager.
    ServiceNoManager,
    /// The service run mode's machine-wide root is missing, mis-owned, or
    /// writable outside its permitted principals.
    ServiceRoot,
}

impl Code {
    /// The stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CliSyntax => "config.cli.syntax",
            Self::CliEncoding => "config.cli.encoding",
            Self::CliRepeated => "config.cli.repeated",
            Self::NameUnknown => "config.name.unknown",
            Self::NameRejected => "config.name.rejected",
            Self::NameReserved => "config.name.reserved",
            Self::ValueSurface => "config.value.surface",
            Self::ValueSyntax => "config.value.syntax",
            Self::ValueRange => "config.value.range",
            Self::ValueUnit => "config.value.unit",
            Self::ValueWord => "config.value.word",
            Self::ValuePlaceholder => "config.value.placeholder",
            Self::ValueRequires => "config.value.requires",
            Self::ValueConflict => "config.value.conflict",
            Self::DevNetwork => "config.dev.network",
            Self::FileMissing => "config.file.missing",
            Self::FileUnreadable => "config.file.unreadable",
            Self::FilePermissions => "config.file.permissions",
            Self::FileSecretReadable => "config.file.secret-readable",
            Self::FileSyntax => "config.file.syntax",
            Self::PathNoHome => "config.path.no-home",
            Self::DataDirUnusable => "config.data-dir.unusable",
            Self::DataDirLocked => "config.data-dir.locked",
            Self::MarkerNetwork => "config.marker.network",
            Self::MarkerNetworkId => "config.marker.network-id",
            Self::MarkerMissing => "config.marker.missing",
            Self::MarkerUnreadable => "config.marker.unreadable",
            Self::LogUnwritable => "config.log.unwritable",
            Self::BanFileUnreadable => "config.ban-file.unreadable",
            Self::BanFileLine => "config.ban-file.line",
            Self::RuntimeStartupOnly => "config.runtime.startup-only",
            Self::ClientNoEndpoint => "config.client.no-endpoint",
            Self::ServicePlatform => "config.service.platform",
            Self::ServiceNoManager => "config.service.no-manager",
            Self::ServiceRoot => "config.service.root",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a value came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// The command line.
    Cli,
    /// The configuration file, at a 1-based line.
    File {
        /// The file the value was read from.
        path: PathBuf,
        /// The line the key is on.
        line: u32,
    },
    /// The row's default.
    Default,
    /// A runtime change (IG-12).
    Runtime,
    /// Nothing the operator gave: the machine's own state.
    Machine,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli => f.write_str("cli"),
            Self::File { path, line } => write!(f, "file:{}:{line}", path.display()),
            Self::Default => f.write_str("default"),
            Self::Runtime => f.write_str("runtime"),
            Self::Machine => f.write_str("machine"),
        }
    }
}

/// One refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// What kind of refusal this is.
    pub code: Code,
    /// The option it is about, when it is about one.
    pub option: Option<String>,
    /// Where the refused value came from.
    pub source: Source,
    /// Named facts the message is built from, in a stable order.
    pub params: Vec<(&'static str, String)>,
}

impl Diagnostic {
    /// A refusal with no option and no parameters yet.
    #[must_use]
    pub fn new(code: Code, source: Source) -> Self {
        Self {
            code,
            option: None,
            source,
            params: Vec::new(),
        }
    }

    /// The option this refusal is about.
    #[must_use]
    pub fn option(mut self, name: impl Into<String>) -> Self {
        self.option = Some(name.into());
        self
    }

    /// Adds a named parameter.
    #[must_use]
    pub fn param(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.params.push((key, value.into()));
        self
    }

    /// The value of a named parameter, if present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The English message: what was wrong, where, and what to do.
    #[must_use]
    pub fn render(&self) -> String {
        let opt = self.option.as_deref().unwrap_or("");
        let p = |k: &str| self.get(k).unwrap_or("");
        let what = match self.code {
            Code::CliSyntax => format!(
                "the command-line token '{}' is not an option; write options as `--name value`, or `--name` for a switch",
                p("token")
            ),
            Code::CliEncoding => format!(
                "command-line argument {} is not valid UTF-8; options and values must be UTF-8",
                p("index")
            ),
            Code::CliRepeated => format!(
                "`--{opt}` is given more than once; it takes one value, so give it once"
            ),
            Code::NameUnknown => match self.get("nearest") {
                Some(near) => format!("there is no option `{opt}`; did you mean `{near}`?"),
                None => format!("there is no option `{opt}`; `--help` lists the options"),
            },
            Code::NameRejected => format!("`{opt}` is not supported: {}", p("reason")),
            Code::NameReserved => format!(
                "`{opt}` is reserved and not accepted yet: {}",
                p("reason")
            ),
            Code::ValueSurface => format!(
                "`{opt}` cannot be given on {}; give it {}",
                p("given"),
                p("allowed")
            ),
            Code::ValueSyntax => format!(
                "the value '{}' for `{opt}` is not {}",
                p("value"),
                p("expected")
            ),
            Code::ValueRange => format!(
                "the value '{}' for `{opt}` is outside its range: {}",
                p("value"),
                p("rule")
            ),
            Code::ValueUnit => format!(
                "the unit in '{}' for `{opt}` is not accepted; use one of {}",
                p("value"),
                p("units")
            ),
            Code::ValueWord => format!(
                "the value '{}' for `{opt}` is not one of {}",
                p("value"),
                p("words")
            ),
            Code::ValuePlaceholder => format!(
                "the placeholder `{{{}}}` in `{opt}` is not one this command offers; it offers {}",
                p("placeholder"),
                p("offered")
            ),
            Code::ValueRequires => format!("`{opt}` needs {}", p("requires")),
            Code::ValueConflict => format!("`{opt}` cannot be set when {}", p("conflict")),
            Code::DevNetwork => format!(
                "`{opt}` is a development lever accepted only on {}, and this is {}",
                p("networks"),
                p("network")
            ),
            Code::FileMissing => format!(
                "the configuration file {} does not exist; create it, or name an existing file with `--config-file`",
                p("path")
            ),
            Code::FileUnreadable => {
                format!("{} cannot be read: {}", p("path"), p("error"))
            }
            Code::FilePermissions => format!(
                "{} can be written by {}, who is not permitted to change the daemon's configuration; restrict it to {}",
                p("path"),
                p("principal"),
                p("permitted")
            ),
            Code::FileSecretReadable => format!(
                "{} holds the secret `{opt}` and can be read by {}; restrict reading to {}",
                p("path"),
                p("principal"),
                p("permitted")
            ),
            Code::FileSyntax => format!("{} is not valid TOML: {}", p("path"), p("error")),
            Code::PathNoHome => format!(
                "this account has no home directory, so `{opt}` has no default; give it explicitly"
            ),
            Code::DataDirUnusable => format!(
                "the data directory {} cannot be used: {}",
                p("path"),
                p("error")
            ),
            Code::DataDirLocked => format!(
                "another daemon is using the data directory {}; stop it, or give this one a different `--data-dir`",
                p("path")
            ),
            Code::MarkerNetwork => format!(
                "the data directory {} belongs to {}, and this daemon is starting on {}; start it on {}, or give it a different `--data-dir`",
                p("path"),
                p("marked"),
                p("network"),
                p("marked")
            ),
            Code::MarkerNetworkId => format!(
                "the data directory {} holds {} data from an earlier network id; that data is from a release before a regenesis, so give this daemon a fresh `--data-dir`",
                p("path"),
                p("network")
            ),
            Code::MarkerMissing => format!(
                "the data directory {} holds a daemon store with no network marker, so this daemon cannot tell which network it belongs to; give it a fresh `--data-dir`",
                p("path")
            ),
            Code::MarkerUnreadable => format!(
                "the network marker {} cannot be read: {}",
                p("path"),
                p("error")
            ),
            Code::LogUnwritable => format!(
                "the log file {} cannot be written: {}",
                p("path"),
                p("error")
            ),
            Code::BanFileUnreadable => {
                format!("the ban file {} cannot be read: {}", p("path"), p("error"))
            }
            Code::BanFileLine => format!(
                "line {} of the ban file {} is not an address: '{}'",
                p("line"),
                p("path"),
                p("text")
            ),
            Code::RuntimeStartupOnly => format!(
                "`{opt}` can only be set at startup; change it in the configuration file and restart"
            ),
            Code::ClientNoEndpoint => format!(
                "a command needs a daemon to reach, and `{opt}` is `none`; give the daemon's admin endpoint"
            ),
            Code::ServicePlatform => format!(
                "`{opt}` exists only on Windows; on this platform the service manager runs the daemon in the foreground"
            ),
            Code::ServiceNoManager => format!(
                "`{opt}` is for the Windows service manager; install the service and start it with the service manager"
            ),
            Code::ServiceRoot => format!(
                "the service root {} cannot be used: {}; the installer creates it with the right owner and access",
                p("path"),
                p("found")
            ),
        };
        format!("{what} [{} from {}]", self.code, self.source)
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl std::error::Error for Diagnostic {}

/// A value's refusal before it is attached to an option and a source.
///
/// Parsers know what is wrong with a value but not which option or line it
/// came from; the caller turns a `Fault` into a [`Diagnostic`] with
/// [`Fault::at`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    /// What kind of refusal this is.
    pub code: Code,
    /// Named facts the message is built from.
    pub params: Vec<(&'static str, String)>,
}

impl Fault {
    /// A fault with no parameters yet.
    #[must_use]
    pub fn new(code: Code) -> Self {
        Self {
            code,
            params: Vec::new(),
        }
    }

    /// Adds a named parameter.
    #[must_use]
    pub fn param(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.params.push((key, value.into()));
        self
    }

    /// Attaches the option and the source.
    #[must_use]
    pub fn at(self, option: &str, source: Source) -> Diagnostic {
        Diagnostic {
            code: self.code,
            option: Some(option.to_owned()),
            source,
            params: self.params,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_distinct_dotted_spelling_under_config() {
        let all = [
            Code::CliSyntax,
            Code::CliEncoding,
            Code::CliRepeated,
            Code::NameUnknown,
            Code::NameRejected,
            Code::NameReserved,
            Code::ValueSurface,
            Code::ValueSyntax,
            Code::ValueRange,
            Code::ValueUnit,
            Code::ValueWord,
            Code::ValuePlaceholder,
            Code::ValueRequires,
            Code::ValueConflict,
            Code::DevNetwork,
            Code::FileMissing,
            Code::FileUnreadable,
            Code::FilePermissions,
            Code::FileSecretReadable,
            Code::FileSyntax,
            Code::PathNoHome,
            Code::DataDirUnusable,
            Code::DataDirLocked,
            Code::MarkerNetwork,
            Code::MarkerNetworkId,
            Code::MarkerMissing,
            Code::MarkerUnreadable,
            Code::LogUnwritable,
            Code::BanFileUnreadable,
            Code::BanFileLine,
            Code::RuntimeStartupOnly,
            Code::ClientNoEndpoint,
            Code::ServicePlatform,
            Code::ServiceNoManager,
            Code::ServiceRoot,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in all {
            let s = code.as_str();
            assert!(s.starts_with("config."), "{s}");
            assert!(
                s.split('.').all(|seg| !seg.is_empty()
                    && seg.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')),
                "{s} is not dotted lowercase segments"
            );
            assert!(seen.insert(s), "{s} is spelled twice");
        }
    }

    #[test]
    fn a_rendered_refusal_names_its_code_and_where_the_value_came_from() {
        let d = Fault::new(Code::ValueRange)
            .param("value", "0")
            .param("rule", "at least 1")
            .at(
                "dev-difficulty",
                Source::File {
                    path: PathBuf::from("/etc/shekyl/shekyld-regtest.toml"),
                    line: 4,
                },
            );
        let text = d.render();
        assert!(text.contains("`dev-difficulty`"), "{text}");
        assert!(text.contains("at least 1"), "{text}");
        assert!(
            text.ends_with("[config.value.range from file:/etc/shekyl/shekyld-regtest.toml:4]"),
            "{text}"
        );
    }

    #[test]
    fn an_unknown_name_offers_the_nearest_name_only_when_there_is_one() {
        let with = Diagnostic::new(Code::NameUnknown, Source::Cli)
            .option("log-levle")
            .param("nearest", "log-level");
        assert!(with.render().contains("did you mean `log-level`"));
        let without = Diagnostic::new(Code::NameUnknown, Source::Cli).option("xyzzy");
        assert!(without.render().contains("`--help` lists the options"));
    }
}
