// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--help`, generated from the table (IG-9): every public row with its
//! kind, default and help text. Development, rejected and reserved rows
//! are not shown.

use shekyl_options::Table;

/// The daemon's help text: the table's, after the one line the daemon adds.
#[must_use]
pub fn render(table: &Table, program: &str, release_name: &str, version_full: &str) -> String {
    shekyl_options::help(
        table,
        program,
        release_name,
        version_full,
        "Daemon commands are shekyl-cli words.",
    )
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
        assert!(text.contains("Daemon commands are shekyl-cli words."));
        assert!(!text.contains("[command...]"));
        assert!(!text.contains("dev-difficulty"), "levers are hidden");
        assert!(!text.contains("in-peers"), "rejected rows are hidden");
        for row in TABLE.rows {
            if matches!(row.visibility, shekyl_options::Visibility::Reserved { .. }) {
                assert!(
                    !text.contains(row.name),
                    "reserved rows are hidden: {}",
                    row.name
                );
            }
        }
        assert!(
            text.contains("--rpc-listen"),
            "the channel listener is public"
        );
    }
}
