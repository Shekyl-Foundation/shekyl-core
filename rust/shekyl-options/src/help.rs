// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--help`, generated from a binary's table (IG-9), one renderer for every
//! binary.

use crate::{Default, Kind, Surface, Table, Visibility};

/// A binary's `--help`, generated from its table (IG-9): every public row
/// with its kind, default and help text, after the binary's `note`.
/// Development, rejected and reserved rows are not shown.
#[must_use]
pub fn help(
    table: &Table,
    program: &str,
    release_name: &str,
    version_full: &str,
    note: &str,
) -> String {
    let mut out = format!(
        "Shekyl '{release_name}' (v{version_full})\n\n\
         Usage: {program} [options]\n\n\
         {note}\n\n"
    );
    for row in table
        .rows
        .iter()
        .filter(|r| matches!(r.visibility, Visibility::Public))
    {
        let value = match row.kind {
            Kind::Switch => String::new(),
            _ => " <value>".to_owned(),
        };
        let default = match row.default {
            Default::Unset => String::new(),
            Default::Value(v) => format!(" [default: {v}]"),
            Default::Derived(d) => format!(" [default: {d}]"),
        };
        let surface = match row.surface {
            Surface::Cli => " (command line only)",
            Surface::File => " (configuration file only)",
            Surface::Both => "",
        };
        out.push_str(&format!(
            "  --{name}{value}\n      {help}{default}{surface}\n",
            name = row.name,
            help = row.help,
        ));
    }
    out
}
