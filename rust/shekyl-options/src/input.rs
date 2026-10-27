// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two surfaces' readers.
//!
//! [`read_cli`] turns `argv` into values for live rows and the positional
//! words; [`read_file`] turns a TOML file's text into values for live rows,
//! each with the line it is on. Both report every refusal they find, not
//! only the first, so an operator fixes a file in one pass. Precedence
//! between the two belongs to the binary (`shekyl-daemon-config` for the
//! daemon), not here.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use crate::diagnostic::{Code, Diagnostic, Source};
use crate::kind::Value;
use crate::table::{Row, Table};

/// One row's value with where it came from.
#[derive(Clone, Debug)]
pub struct Given {
    /// The row.
    pub row: &'static Row,
    /// The parsed value.
    pub value: Value,
    /// The command line, or the file and line.
    pub source: Source,
}

/// What the command line gave.
#[derive(Clone, Debug, Default)]
pub struct Cli {
    /// One entry per row given, in the order first seen.
    pub given: Vec<Given>,
    /// The words that are not options (a client-mode command).
    pub positional: Vec<String>,
}

/// Reads `argv` (without the program name) against `table`.
///
/// An option is `--name value`, or `--name` for a switch. A list or a map
/// is the option repeated. Nothing else starts with `-`. A word that is not
/// an option's value is positional.
///
/// # Errors
/// Every refusal found: a malformed token, a non-UTF-8 argument, an unknown,
/// rejected or reserved name, a row that is not accepted on the command
/// line, a missing value, a single-valued option given twice, or a value its
/// kind refuses.
pub fn read_cli<I>(table: &Table, args: I) -> Result<Cli, Vec<Diagnostic>>
where
    I: IntoIterator<Item = OsString>,
{
    let mut faults = Vec::new();
    let mut raw: Vec<(&'static Row, Vec<String>)> = Vec::new();
    let mut positional = Vec::new();
    let mut tokens = Vec::new();
    for (i, arg) in args.into_iter().enumerate() {
        match arg.into_string() {
            Ok(s) => tokens.push(s),
            Err(_) => faults.push(
                Diagnostic::new(Code::CliEncoding, Source::Cli).param("index", (i + 1).to_string()),
            ),
        }
    }
    let mut it = tokens.into_iter();
    while let Some(token) = it.next() {
        let Some(name) = token.strip_prefix("--") else {
            if token.starts_with('-') {
                faults.push(Diagnostic::new(Code::CliSyntax, Source::Cli).param("token", token));
            } else {
                positional.push(token);
            }
            continue;
        };
        if name.is_empty() || name.contains('=') || name.starts_with('-') {
            faults
                .push(Diagnostic::new(Code::CliSyntax, Source::Cli).param("token", token.clone()));
            continue;
        }
        let row = match table.live(name, &Source::Cli) {
            Ok(row) => row,
            Err(d) => {
                faults.push(d);
                continue;
            }
        };
        if !row.surface.cli() || !row.kind.cli_allowed() {
            faults.push(
                Diagnostic::new(Code::ValueSurface, Source::Cli)
                    .option(row.name)
                    .param("given", "the command line")
                    .param("allowed", "in the configuration file"),
            );
            // A file-only row's value, if one follows, is not a positional word.
            let _ = it.next();
            continue;
        }
        let values = if row.kind.is_switch() {
            Vec::new()
        } else {
            match it.next() {
                Some(v) => vec![v],
                None => {
                    faults.push(
                        Diagnostic::new(Code::CliSyntax, Source::Cli)
                            .option(row.name)
                            .param("token", token.clone()),
                    );
                    continue;
                }
            }
        };
        if let Some((_, existing)) = raw.iter_mut().find(|(r, _)| r.name == row.name) {
            if row.kind.is_collection() {
                existing.extend(values);
            } else {
                faults.push(Diagnostic::new(Code::CliRepeated, Source::Cli).option(row.name));
            }
        } else {
            raw.push((row, values));
        }
    }
    let mut given = Vec::with_capacity(raw.len());
    for (row, values) in raw {
        match row.kind.parse_cli(&values) {
            Ok(value) => given.push(Given {
                row,
                value,
                source: Source::Cli,
            }),
            Err(f) => faults.push(f.at(row.name, Source::Cli)),
        }
    }
    if faults.is_empty() {
        Ok(Cli { given, positional })
    } else {
        Err(faults)
    }
}

/// Reads a configuration file's text against `table`. Keys are top-level;
/// a map is a table under its key.
///
/// # Errors
/// The file's syntax error with its line, or every refusal of a name or a
/// value, each with its line.
pub fn read_file(table: &Table, path: &Path, text: &str) -> Result<Vec<Given>, Vec<Diagnostic>> {
    let entries: BTreeMap<String, toml::Spanned<toml::Value>> = match toml::from_str(text) {
        Ok(e) => e,
        Err(e) => {
            let line = e.span().map_or(0, |s| line_of(text, s.start));
            let message = e.message().to_owned();
            return Err(vec![Diagnostic::new(
                Code::FileSyntax,
                Source::File {
                    path: path.to_path_buf(),
                    line,
                },
            )
            .param("path", path.display().to_string())
            .param("error", format!("line {line}: {message}"))]);
        }
    };
    let mut sorted: Vec<(String, toml::Spanned<toml::Value>)> = entries.into_iter().collect();
    sorted.sort_by_key(|(_, v)| v.span().start);
    let mut faults = Vec::new();
    let mut given = Vec::with_capacity(sorted.len());
    for (name, spanned) in sorted {
        let source = Source::File {
            path: path.to_path_buf(),
            line: line_of(text, spanned.span().start),
        };
        let row = match table.live(&name, &source) {
            Ok(row) => row,
            Err(d) => {
                faults.push(d);
                continue;
            }
        };
        if !row.surface.file() {
            faults.push(
                Diagnostic::new(Code::ValueSurface, source)
                    .option(row.name)
                    .param("given", "the configuration file")
                    .param("allowed", "on the command line"),
            );
            continue;
        }
        match row.kind.parse_file(spanned.get_ref()) {
            Ok(value) => given.push(Given { row, value, source }),
            Err(f) => faults.push(f.at(row.name, source)),
        }
    }
    if faults.is_empty() {
        Ok(given)
    } else {
        Err(faults)
    }
}

/// The 1-based line of a byte offset.
fn line_of(text: &str, offset: usize) -> u32 {
    let upto = text.get(..offset).unwrap_or(text);
    let lines = upto.bytes().filter(|b| *b == b'\n').count() + 1;
    u32::try_from(lines).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind::{EndpointRule, Kind};
    use crate::table::{Default, Grant, Surface, Visibility};

    const ENDPOINT: Kind = Kind::Endpoint(EndpointRule::Loopback);
    const ROWS: &[Row] = &[
        Row {
            name: "network",
            kind: Kind::OneOf(&["mainnet", "testnet"]),
            default: Default::Value("mainnet"),
            surface: Surface::Cli,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Public,
            help: "",
        },
        Row {
            name: "console",
            kind: Kind::Switch,
            default: Default::Unset,
            surface: Surface::Cli,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Public,
            help: "",
        },
        Row {
            name: "rpc-admin-listen",
            kind: Kind::List(&ENDPOINT),
            default: Default::Value("127.0.0.1:11029"),
            surface: Surface::Both,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Public,
            help: "",
        },
        Row {
            name: "tor-socks-password",
            kind: Kind::Secret,
            default: Default::Unset,
            surface: Surface::File,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Public,
            help: "",
        },
        Row {
            name: "mine-threads",
            kind: Kind::Integer {
                min: 1,
                keywords: &["auto"],
            },
            default: Default::Value("auto"),
            surface: Surface::Both,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Public,
            help: "",
        },
    ];
    const TABLE: Table = Table {
        binary: "test",
        rows: ROWS,
    };

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn codes(r: Result<Cli, Vec<Diagnostic>>) -> Vec<Code> {
        r.expect_err("expected refusals")
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn options_values_and_positional_words_are_told_apart() {
        let cli = read_cli(
            &TABLE,
            args(&[
                "--network",
                "testnet",
                "--console",
                "--rpc-admin-listen",
                "127.0.0.1:1",
                "--rpc-admin-listen",
                "[::1]:2",
                "status",
            ]),
        )
        .unwrap();
        assert_eq!(cli.positional, vec!["status".to_owned()]);
        assert_eq!(cli.given.len(), 3);
        assert!(matches!(cli.given[2].value, Value::List(ref v) if v.len() == 2));
    }

    #[test]
    fn malformed_tokens_and_repeats_are_refused_together() {
        let got = codes(read_cli(
            &TABLE,
            args(&[
                "-n",
                "--network=testnet",
                "--mine-threads",
                "2",
                "--mine-threads",
                "3",
                "--",
            ]),
        ));
        assert_eq!(
            got,
            vec![
                Code::CliSyntax,
                Code::CliSyntax,
                Code::CliRepeated,
                Code::CliSyntax
            ]
        );
    }

    #[test]
    fn a_missing_value_and_a_file_only_secret_on_the_cli_are_refused() {
        assert_eq!(
            codes(read_cli(&TABLE, args(&["--network"]))),
            vec![Code::CliSyntax]
        );
        assert_eq!(
            codes(read_cli(&TABLE, args(&["--tor-socks-password", "x"]))),
            vec![Code::ValueSurface]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_argument_is_refused_by_position() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0x2d, 0x2d, 0xff]);
        let d = read_cli(&TABLE, vec![bad]).unwrap_err();
        assert_eq!(d[0].code, Code::CliEncoding);
        assert_eq!(d[0].get("index"), Some("1"));
    }

    #[test]
    fn a_file_value_carries_its_line_and_cli_only_rows_are_refused_there() {
        let text =
            "# comment\nmine-threads = 4\n\nnetwork = \"testnet\"\ntor-socks-password = \"pw\"\n";
        let d = read_file(&TABLE, Path::new("/etc/x.toml"), text).unwrap_err();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, Code::ValueSurface);
        assert_eq!(
            d[0].source,
            Source::File {
                path: "/etc/x.toml".into(),
                line: 4
            }
        );
        let ok = read_file(
            &TABLE,
            Path::new("/etc/x.toml"),
            "mine-threads = 4\ntor-socks-password = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(
            ok[1].source,
            Source::File {
                path: "/etc/x.toml".into(),
                line: 2
            }
        );
    }

    #[test]
    fn invalid_toml_and_a_repeated_key_name_their_line() {
        let d = read_file(
            &TABLE,
            Path::new("/x.toml"),
            "mine-threads = 4\nmine-threads = 5\n",
        )
        .unwrap_err();
        assert_eq!(d[0].code, Code::FileSyntax);
        assert_eq!(
            d[0].source,
            Source::File {
                path: "/x.toml".into(),
                line: 2
            }
        );
        let bad = read_file(&TABLE, Path::new("/x.toml"), "mine-threads = [\n").unwrap_err();
        assert_eq!(bad[0].code, Code::FileSyntax);
    }

    #[test]
    fn an_unknown_key_in_the_file_offers_the_nearest_name_with_its_line() {
        let d = read_file(&TABLE, Path::new("/x.toml"), "\nmine-thread = 2\n").unwrap_err();
        assert_eq!(d[0].code, Code::NameUnknown);
        assert_eq!(d[0].get("nearest"), Some("mine-threads"));
        assert!(d[0].render().ends_with("from file:/x.toml:2]"));
    }
}
