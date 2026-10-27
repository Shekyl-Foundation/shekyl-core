// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--help`, generated from the table (IG-9): every public row with its
//! kind, default and help text. Development, rejected and reserved rows
//! are not shown.

use shekyl_options::{Default, Kind, Surface, Table, Visibility};

/// The help text.
#[must_use]
pub fn render(table: &Table, program: &str, release_name: &str, version_full: &str) -> String {
    let mut out = format!(
        "Shekyl '{release_name}' (v{version_full})\n\nUsage: {program} [options] [command...]\n\n"
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

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_daemon_config::TABLE;

    #[test]
    fn help_lists_every_public_row_and_no_hidden_one() {
        let text = render(&TABLE, "shekyld", "Shekyl NG", "3.1.0-test");
        assert!(text.contains("--log-level <value>"));
        assert!(text.contains("[default: warn]"));
        assert!(text.contains("--network <value>") && text.contains("(command line only)"));
        assert!(!text.contains("dev-difficulty"), "levers are hidden");
        assert!(!text.contains("in-peers"), "rejected rows are hidden");
        assert!(!text.contains("rpc-listen"), "reserved rows are hidden");
    }
}
