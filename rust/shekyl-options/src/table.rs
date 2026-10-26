// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One table per binary (IG-9): the rows, and the name rules every binary
//! shares (IG-1, IG-5, IG-10).

use crate::diagnostic::{Code, Diagnostic, Source};
use crate::kind::Kind;

/// Where a row may be given (IG-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// The command line only: the row chooses which file is read.
    Cli,
    /// The configuration file only: secrets and commands.
    File,
    /// Both; the command line wins per key.
    Both,
}

impl Surface {
    /// Whether the command line may give the row.
    #[must_use]
    pub const fn cli(self) -> bool {
        matches!(self, Self::Cli | Self::Both)
    }

    /// Whether the file may give the row.
    #[must_use]
    pub const fn file(self) -> bool {
        matches!(self, Self::File | Self::Both)
    }
}

/// The grant under which `option show` discloses a row (IG-9, RT-O24): the
/// daemon RPC's own grants (`shekyl-rpc-grants`), one vocabulary for the RPC
/// and the option table. Rows name `Health`, `Status`, `Peers` or `Config`;
/// `Config` is the default.
pub use shekyl_rpc_grants::Grant;

/// Whether a name is live, and how it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Accepted and in help.
    Public,
    /// A development lever (IG-8): accepted only on the named networks,
    /// never on mainnet, hidden from help, announced when set.
    Dev {
        /// The networks the lever is accepted on.
        networks: &'static [&'static str],
    },
    /// A feature deliberately refused (IG-10); never accepted.
    Rejected {
        /// Why, and where that was decided.
        reason: &'static str,
    },
    /// A name held for a ruled future option (IG-10); never accepted.
    Reserved {
        /// What the name is held for, and where that is ruled.
        reason: &'static str,
    },
}

/// A row's default (IG-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Default {
    /// Not given means unset; the row says what unset means.
    Unset,
    /// A value, written as text in the kind's syntax.
    Value(&'static str),
    /// Computed by the row's owner (from the network row, the run mode, the
    /// platform); the text says how.
    Derived(&'static str),
}

/// One option.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    /// The name (IG-1, IG-3).
    pub name: &'static str,
    /// The value's kind and its constraint (IG-6).
    pub kind: Kind,
    /// The default.
    pub default: Default,
    /// Where it may be given.
    pub surface: Surface,
    /// Whether `option set` accepts it (IG-12).
    pub runtime: bool,
    /// The grant that discloses it.
    pub grant: Grant,
    /// Live, development, rejected or reserved.
    pub visibility: Visibility,
    /// The help text.
    pub help: &'static str,
}

impl Row {
    /// Whether a value for the row is accepted at all.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self.visibility, Visibility::Public | Visibility::Dev { .. })
    }
}

/// A binary's table.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    /// The binary the table is for.
    pub binary: &'static str,
    /// Every row: live, development, rejected and reserved.
    pub rows: &'static [Row],
}

/// The furthest an unknown name may be from a live one to be offered as
/// its correction.
const NEAREST_MAX_EDITS: usize = 3;

impl Table {
    /// The row with this name, live or not.
    #[must_use]
    pub fn row(&self, name: &str) -> Option<&'static Row> {
        self.rows.iter().find(|r| r.name == name)
    }

    /// The live row with this name, or the refusal for it: unknown (with
    /// the nearest live name), rejected (with its reason) or reserved
    /// (with what it is held for).
    ///
    /// # Errors
    /// The refusal as a [`Diagnostic`] at `source`.
    pub fn live(&self, name: &str, source: &Source) -> Result<&'static Row, Diagnostic> {
        let Some(row) = self.row(name) else {
            let d = Diagnostic::new(Code::NameUnknown, source.clone()).option(name);
            return Err(match self.nearest(name) {
                Some(near) => d.param("nearest", near),
                None => d,
            });
        };
        match row.visibility {
            Visibility::Public | Visibility::Dev { .. } => Ok(row),
            Visibility::Rejected { reason } => {
                Err(Diagnostic::new(Code::NameRejected, source.clone())
                    .option(name)
                    .param("reason", reason))
            }
            Visibility::Reserved { reason } => {
                Err(Diagnostic::new(Code::NameReserved, source.clone())
                    .option(name)
                    .param("reason", reason))
            }
        }
    }

    /// The public name closest to `name` by edit distance, computed from the
    /// table and never from a hand list (IG-10). Development levers are not
    /// offered: they are hidden from help.
    #[must_use]
    pub fn nearest(&self, name: &str) -> Option<&'static str> {
        self.rows
            .iter()
            .filter(|r| matches!(r.visibility, Visibility::Public))
            .map(|r| (strsim::levenshtein(name, r.name), r.name))
            .filter(|(d, _)| *d <= NEAREST_MAX_EDITS)
            .min()
            .map(|(_, n)| n)
    }

    /// The table's own defects: a malformed name (IG-1), a name defined
    /// twice (IG-5), a switch that is on by default (IG-4), a runtime row
    /// that is a secret or has no default value (IG-12), a development
    /// lever that names no network or names mainnet (IG-8). Empty means the
    /// table is well formed.
    #[must_use]
    pub fn defects(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.rows.is_empty() {
            out.push(format!("{}: the table has no rows", self.binary));
        }
        for (i, row) in self.rows.iter().enumerate() {
            let name = row.name;
            if !lexical(name) {
                out.push(format!(
                    "`{name}` is not lowercase segments joined by single hyphens"
                ));
            }
            if self.rows[..i].iter().any(|r| r.name == name) {
                out.push(format!("`{name}` is defined twice"));
            }
            if !row.is_live() {
                continue;
            }
            if row.kind.is_switch()
                && row.default != Default::Unset
                && row.default != Default::Value("false")
            {
                out.push(format!("switch `{name}` must default to off"));
            }
            if row.runtime {
                if matches!(row.kind, Kind::Secret) {
                    out.push(format!("`{name}` is runtime and a secret"));
                }
                if !matches!(row.default, Default::Value(_)) {
                    out.push(format!(
                        "runtime `{name}` has no default value to return to"
                    ));
                }
            }
            if !row.kind.cli_allowed() && row.surface != Surface::File {
                out.push(format!(
                    "`{name}` is a file-only kind given another surface"
                ));
            }
            if let Visibility::Dev { networks } = row.visibility {
                if !name.starts_with("dev-") {
                    out.push(format!("`{name}` is a development lever not under `dev`"));
                }
                if networks.is_empty() || networks.contains(&"mainnet") {
                    out.push(format!(
                        "development lever `{name}` must name networks, never mainnet"
                    ));
                }
            } else if name.starts_with("dev-") && row.is_live() {
                out.push(format!(
                    "`{name}` is under `dev` and not a development lever"
                ));
            }
            if let Default::Value(text) = row.default {
                if row.kind.is_collection() || matches!(row.kind, Kind::Switch) {
                    if text != "none" && text != "false" {
                        if let Err(f) = row.kind.parse_cli(&[text.to_owned()]) {
                            out.push(format!(
                                "`{name}`'s default '{text}' does not parse: {:?}",
                                f.code
                            ));
                        }
                    }
                } else if let Err(f) = row.kind.parse_text(text) {
                    out.push(format!(
                        "`{name}`'s default '{text}' does not parse: {:?}",
                        f.code
                    ));
                }
            }
        }
        out
    }
}

/// IG-1: `[a-z][a-z0-9]*` segments joined by single hyphens.
#[must_use]
pub fn lexical(name: &str) -> bool {
    !name.is_empty()
        && name.split('-').all(|seg| {
            let mut b = seg.bytes();
            matches!(b.next(), Some(c) if c.is_ascii_lowercase())
                && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROWS: &[Row] = &[
        Row {
            name: "log-level",
            kind: Kind::OneOf(&["error", "warn", "info"]),
            default: Default::Value("warn"),
            surface: Surface::Both,
            runtime: true,
            grant: Grant::Status,
            visibility: Visibility::Public,
            help: "",
        },
        Row {
            name: "dev-difficulty",
            kind: Kind::Integer {
                min: 1,
                keywords: &[],
            },
            default: Default::Unset,
            surface: Surface::Both,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Dev {
                networks: &["regtest"],
            },
            help: "",
        },
        Row {
            name: "detach",
            kind: Kind::Switch,
            default: Default::Unset,
            surface: Surface::Both,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Rejected {
                reason: "the daemon never daemonizes itself",
            },
            help: "",
        },
        Row {
            name: "rpc-listen",
            kind: Kind::Switch,
            default: Default::Unset,
            surface: Surface::Both,
            runtime: false,
            grant: Grant::Config,
            visibility: Visibility::Reserved {
                reason: "the authenticated channel listener (RT-W10)",
            },
            help: "",
        },
    ];
    const TABLE: Table = Table {
        binary: "test",
        rows: ROWS,
    };

    #[test]
    fn the_test_table_is_well_formed() {
        assert_eq!(TABLE.defects(), Vec::<String>::new());
    }

    #[test]
    fn a_misspelled_name_is_refused_with_the_nearest_public_name() {
        let d = TABLE.live("log-levl", &Source::Cli).unwrap_err();
        assert_eq!(d.code, Code::NameUnknown);
        assert_eq!(d.get("nearest"), Some("log-level"));
        let far = TABLE.live("zzzzzzzzzzzz", &Source::Cli).unwrap_err();
        assert_eq!(far.get("nearest"), None);
        // A development lever is hidden from help, so it is not offered.
        let dev = TABLE.live("dev-difficulti", &Source::Cli).unwrap_err();
        assert_eq!(dev.get("nearest"), None);
    }

    #[test]
    fn rejected_and_reserved_names_are_refused_with_their_reasons() {
        let r = TABLE.live("detach", &Source::Cli).unwrap_err();
        assert_eq!(r.code, Code::NameRejected);
        assert!(r.render().contains("never daemonizes"));
        let s = TABLE.live("rpc-listen", &Source::Default).unwrap_err();
        assert_eq!(s.code, Code::NameReserved);
        assert!(s.render().contains("RT-W10"));
    }

    #[test]
    fn the_lexical_rule_is_lowercase_segments_and_single_hyphens() {
        for good in [
            "network",
            "log-level",
            "p2p-upload-max",
            "dev-pow-seed-epoch-lag",
        ] {
            assert!(lexical(good), "{good}");
        }
        for bad in [
            "",
            "Log",
            "log--level",
            "-log",
            "log-",
            "2fa",
            "log_level",
            "p2p-2",
        ] {
            assert!(!lexical(bad), "{bad}");
        }
    }

    #[test]
    fn a_malformed_table_names_each_defect() {
        const BAD: &[Row] = &[
            Row {
                name: "dev-thing",
                kind: Kind::Switch,
                default: Default::Value("true"),
                surface: Surface::Both,
                runtime: false,
                grant: Grant::Config,
                visibility: Visibility::Dev {
                    networks: &["mainnet"],
                },
                help: "",
            },
            Row {
                name: "pw",
                kind: Kind::Secret,
                default: Default::Unset,
                surface: Surface::Both,
                runtime: true,
                grant: Grant::Config,
                visibility: Visibility::Public,
                help: "",
            },
        ];
        let defects = Table {
            binary: "bad",
            rows: BAD,
        }
        .defects();
        let all = defects.join("\n");
        for needle in [
            "must default to off",
            "never mainnet",
            "runtime and a secret",
            "no default value",
            "file-only kind",
        ] {
            assert!(all.contains(needle), "missing '{needle}' in:\n{all}");
        }
    }
}
