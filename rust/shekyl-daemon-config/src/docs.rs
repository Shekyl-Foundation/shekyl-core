// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The documentation generated from the table (IG-9): the option table the
//! guides embed and the annotated configuration-file example. Both are
//! committed under `docs/generated/` and a test here holds the committed
//! text equal to this rendering, so the guides can only say what the table
//! says. `scripts/ci/check_daemon_option_docs.py` holds the guides equal to
//! the committed fragments.

use shekyl_options::{
    Default, Dimension, EndpointRule, Kind, PeerRule, Surface, Table, Visibility,
};

/// The Markdown table of every public row: name, kind, default, surface,
/// whether `option set` accepts it, and the help text.
#[must_use]
pub fn options_markdown(table: &Table) -> String {
    let mut out = String::from(
        "| Option | Kind | Default | Where | Runtime | Description |\n\
         |--------|------|---------|-------|---------|-------------|\n",
    );
    for row in public(table) {
        out.push_str(&format!(
            "| `{name}` | {kind} | {default} | {surface} | {runtime} | {help} |\n",
            name = row.name,
            kind = kind_text(&row.kind),
            default = default_text(&row.default),
            surface = surface_text(row.surface),
            runtime = if row.runtime { "yes" } else { "no" },
            help = cell(row.help),
        ));
    }
    // The development rows, for the gate that holds every `shekyld` flag
    // in a guide to a live row: live on their networks, absent from
    // `--help` and from the rendered table (IG-9), carried where a reader
    // of the page never sees them.
    let dev: Vec<String> = table
        .rows
        .iter()
        .filter_map(|r| match r.visibility {
            Visibility::Dev { networks } => Some(format!("{} ({})", r.name, networks.join(", "))),
            _ => None,
        })
        .collect();
    if !dev.is_empty() {
        out.push_str(&format!(
            "<!-- development rows, live on the named networks only and not in --help: {} -->\n",
            dev.join("; ")
        ));
    }
    out
}

/// The annotated TOML example: every public row the file accepts, each
/// line commented out so the example parses as the defaults, with the
/// row's help above it and its default or an example value beside it.
#[must_use]
pub fn example_toml(table: &Table) -> String {
    let mut out = String::from(
        "# shekyld configuration file. Every key is an option's name, spelled\n\
         # as on the command line without the leading dashes. The network is\n\
         # always given on the command line, because it chooses the file.\n\
         # Every line below is commented out: uncomment one to set it.\n",
    );
    for row in public(table).filter(|r| !matches!(r.surface, Surface::Cli)) {
        out.push('\n');
        for line in wrap(row.help, 72) {
            out.push_str(&format!("# {line}\n"));
        }
        match &row.default {
            Default::Derived(d) => out.push_str(&format!("# Default: {d}.\n")),
            Default::Unset | Default::Value(_) => {}
        }
        out.push_str(&format!(
            "# {name} = {value}\n",
            name = row.name,
            value = example_value(&row.kind, &row.default)
        ));
    }
    out
}

fn public(table: &Table) -> impl Iterator<Item = &shekyl_options::Row> {
    table
        .rows
        .iter()
        .filter(|r| matches!(r.visibility, Visibility::Public))
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn kind_text(kind: &Kind) -> String {
    match kind {
        Kind::Switch => "switch".to_owned(),
        Kind::OneOf(words) => words
            .iter()
            .map(|w| format!("`{w}`"))
            .collect::<Vec<_>>()
            .join(" / "),
        Kind::Integer { min, keywords } => with_keywords(&format!("integer ≥ {min}"), keywords),
        Kind::Quantity {
            dimension,
            min,
            keywords,
        } => {
            let unit = match dimension {
                Dimension::Bytes => "bytes, such as `512MiB`",
                Dimension::Rate => "rate, such as `1MiB/s`",
                Dimension::Duration => "duration, such as `30s`",
            };
            let base = if *min > 0 {
                format!("{unit} (at least {min})")
            } else {
                unit.to_owned()
            };
            with_keywords(&base, keywords)
        }
        Kind::Endpoint(_) => "IP endpoint (`address:port`)".to_owned(),
        Kind::PeerEndpoint(PeerRule::Any) => "IP endpoint or v3 onion with a port".to_owned(),
        Kind::PeerEndpoint(PeerRule::OnionOnly) => "v3 onion with a port".to_owned(),
        Kind::Address => "Shekyl address".to_owned(),
        Kind::Path => "absolute path".to_owned(),
        Kind::Secret => "secret (file only, never shown)".to_owned(),
        Kind::Command { placeholders } => format!(
            "command (an array of words; placeholders {})",
            placeholders
                .iter()
                .map(|p| format!("`{{{p}}}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Kind::Origin => "web origin".to_owned(),
        Kind::List(item) => format!("list of {} (`none` for empty)", kind_text(item)),
        Kind::Map { value, .. } => format!("map to {}", kind_text(value)),
    }
}

fn with_keywords(base: &str, keywords: &[&str]) -> String {
    if keywords.is_empty() {
        base.to_owned()
    } else {
        format!(
            "{base}, or {}",
            keywords
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(" / ")
        )
    }
}

fn default_text(default: &Default) -> String {
    match default {
        Default::Unset => "—".to_owned(),
        Default::Value(v) => format!("`{v}`"),
        Default::Derived(d) => cell(d),
    }
}

fn surface_text(surface: Surface) -> &'static str {
    match surface {
        Surface::Cli => "command line",
        Surface::File => "file",
        Surface::Both => "both",
    }
}

/// The value the example shows: the default where the row has one, an
/// example of the kind otherwise.
fn example_value(kind: &Kind, default: &Default) -> String {
    if let Default::Value(v) = default {
        return match kind {
            Kind::Switch => v.to_string(),
            Kind::Integer { .. } if v.parse::<u64>().is_ok() => (*v).to_owned(),
            Kind::List(_) if *v == "none" => "\"none\"".to_owned(),
            Kind::List(_) => format!("[\"{v}\"]"),
            _ => format!("\"{v}\""),
        };
    }
    match kind {
        Kind::Switch => "true".to_owned(),
        Kind::OneOf(words) => format!("\"{}\"", words.first().copied().unwrap_or("")),
        Kind::Integer { min, .. } => min.max(&1).to_string(),
        Kind::Quantity { dimension, .. } => match dimension {
            Dimension::Bytes => "\"512MiB\"",
            Dimension::Rate => "\"1MiB/s\"",
            Dimension::Duration => "\"30s\"",
        }
        .to_owned(),
        Kind::Endpoint(EndpointRule::GlobalUnicast) => "\"<public-address>:11021\"".to_owned(),
        Kind::Endpoint(_) => "\"127.0.0.1:11029\"".to_owned(),
        Kind::PeerEndpoint(PeerRule::Any) => "\"203.0.113.10:11021\"".to_owned(),
        Kind::PeerEndpoint(PeerRule::OnionOnly) => "\"<56 characters>.onion:11021\"".to_owned(),
        Kind::Address => "\"<address>\"".to_owned(),
        Kind::Path => "\"/path\"".to_owned(),
        Kind::Secret => "\"<secret>\"".to_owned(),
        Kind::Command { placeholders } => format!(
            "[\"/path/to/command\"{}]",
            placeholders
                .first()
                .map(|p| format!(", \"{{{p}}}\""))
                .unwrap_or_default()
        ),
        Kind::Origin => "\"https://example.org\"".to_owned(),
        Kind::List(item) => format!("[{}]", example_value(item, &Default::Unset)),
        Kind::Map { .. } => "{ }".to_owned(),
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TABLE;
    use std::path::PathBuf;

    fn generated(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/generated")
            .join(name)
    }

    /// A `<…>` string, alone or inside an array: the example's stand-in
    /// for a value only the operator has.
    fn is_placeholder(value: &toml::Value) -> bool {
        match value {
            toml::Value::String(s) => s.starts_with('<'),
            toml::Value::Array(items) => items.iter().any(is_placeholder),
            _ => false,
        }
    }

    const TABLE_FILE: &str = "shekyld_options.md";
    const EXAMPLE_FILE: &str = "shekyld.example.toml";

    /// The subject assertion (rule 47): the rendering is not empty and
    /// names every public row, before anything is compared against it.
    #[test]
    fn the_rendering_names_every_public_row_and_no_hidden_one() {
        let table = options_markdown(&TABLE);
        let example = example_toml(&TABLE);
        let public_rows = TABLE
            .rows
            .iter()
            .filter(|r| matches!(r.visibility, Visibility::Public))
            .count();
        assert!(public_rows > 20, "the table has {public_rows} public rows");
        assert_eq!(
            table.lines().count(),
            public_rows + 3,
            "one table line per public row, the header pair and the development comment"
        );
        assert!(
            table.contains("<!-- development rows") && table.contains("dev-difficulty (regtest)")
        );
        for row in TABLE.rows {
            let named = table.contains(&format!("| `{}` |", row.name));
            assert_eq!(
                named,
                matches!(row.visibility, Visibility::Public),
                "{} in the table",
                row.name
            );
            let in_example = example.contains(&format!("\n# {} = ", row.name));
            assert_eq!(
                in_example,
                matches!(row.visibility, Visibility::Public)
                    && !matches!(row.surface, Surface::Cli),
                "{} in the example",
                row.name
            );
        }
        assert!(!table.contains("| `dev-difficulty` |") && !table.contains("in-peers"));
    }

    /// The example parses as TOML with every line commented (an empty
    /// table), and with every line uncommented it is a file of the
    /// table's rows: each key a live file row, each value its kind's.
    #[test]
    fn the_example_is_a_configuration_file_when_uncommented() {
        let example = example_toml(&TABLE);
        let commented: toml::Table = example.parse().expect("commented example parses");
        assert!(commented.is_empty());
        let active: String = example
            .lines()
            .filter(|l| {
                l.strip_prefix("# ").is_some_and(|rest| {
                    rest.split_once(" = ").is_some_and(|(key, _)| {
                        !key.is_empty()
                            && key
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
                })
            })
            .map(|l| format!("{}\n", &l[2..]))
            .collect();
        let active_table: toml::Table = active.parse().expect("uncommented example parses");
        for (key, value) in &active_table {
            let row = TABLE
                .rows
                .iter()
                .find(|r| r.name == key)
                .unwrap_or_else(|| panic!("{key} is a row"));
            assert!(!matches!(row.surface, Surface::Cli), "{key} is a file row");
            if is_placeholder(value) {
                continue; // a placeholder for a value the example cannot invent
            }
            row.kind
                .parse_file(value)
                .unwrap_or_else(|e| panic!("{key}'s example value is its kind's: {e:?}"));
        }
    }

    /// The committed fragments are this rendering. Regenerate with
    /// `cargo test -p shekyl-daemon-config regenerate_generated_docs -- --ignored`.
    #[test]
    fn the_committed_fragments_are_the_rendering() {
        for (name, text) in [
            (TABLE_FILE, options_markdown(&TABLE)),
            (EXAMPLE_FILE, example_toml(&TABLE)),
        ] {
            let path = generated(name);
            let committed = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} is committed: {e}", path.display()));
            assert_eq!(
                committed,
                text,
                "{} differs from the table's rendering; regenerate it",
                path.display()
            );
        }
    }

    #[test]
    #[ignore = "writes docs/generated/; run on purpose after a table change"]
    fn regenerate_generated_docs() {
        std::fs::write(generated(TABLE_FILE), options_markdown(&TABLE)).expect("write table");
        std::fs::write(generated(EXAMPLE_FILE), example_toml(&TABLE)).expect("write example");
    }
}
