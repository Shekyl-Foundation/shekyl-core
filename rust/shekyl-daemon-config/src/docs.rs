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

use std::net::Ipv4Addr;

use shekyl_network::Network;
use shekyl_options::{Default, Dimension, Kind, PeerRule, Surface, Table, Visibility};

use crate::sections::listen_default;

/// The example for an endpoint no row has given a port. The operator
/// chooses the address and the port (a SOCKS proxy, the forward from the
/// operator's Tor); the example does not invent either.
const CHOSEN_ENDPOINT: &str = "\"<address>:<port>\"";

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
            Visibility::Dev { gate } => Some(format!("{} ({})", r.name, gate.networks())),
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
/// A port in an example is `network`'s and comes from the row: a derived
/// listen shows the address a start on `network` writes, and a row that
/// illustrates a port family shows that port. An endpoint no row has given
/// a port is a placeholder.
#[must_use]
pub fn example_toml(table: &Table, network: Network) -> String {
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
            value = example_value(row.name, &row.kind, &row.default, network)
        ));
    }
    out
}

/// The networks a package ships a settings file for: the public ones.
/// `regtest` is a harness network and gets none (INPUT_GRAMMAR.md IG-Q64).
pub const PACKAGED_NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Stagenet];

/// The settings file a Linux package ships for `network` (INPUT_GRAMMAR.md
/// IG-Q64): a header that says how the packaged unit uses the file, then
/// [`example_toml`] for `network`, every option line commented out. The
/// package installs it as `/usr/share/shekyl/shekyld-<network>.toml` and
/// copies it to `/etc/shekyl/` when no file is there.
#[must_use]
pub fn packaged_toml(table: &Table, network: Network) -> String {
    let n = network.name();
    let mut out = format!(
        "# /etc/shekyl/shekyld-{n}.toml: the settings of shekyld@{n}, the {n}\n\
         # daemon the packaged unit runs (`systemctl enable --now shekyld@{n}`).\n\
         #\n\
         # Before every start the unit checks this file as the daemon's\n\
         # account, with the command line it starts with (its ExecStartPre):\n\
         #   shekyld --service --network {n} --data-dir /var/lib/shekyl/{n} \\\n\
         #     --log-file /var/log/shekyl/{n}/shekyld.log --config-verify\n\
         # The unit sets data-dir and log-file on that command line, and a\n\
         # flag on the command line wins over the same key here. The file is\n\
         # read at start; a runtime option changes while the daemon runs with\n\
         # `shekyl-cli option set`.\n\
         #\n\
         # The package placed this file root:shekyl 0640 and never overwrites\n\
         # it; the shipped copy is /usr/share/shekyl/shekyld-{n}.toml. A secret\n\
         # (a SOCKS password) may be kept here: the daemon refuses the file\n\
         # only when an account other than root and the daemon's can read it,\n\
         # so the daemon's account stays the only member of its group.\n\
         #\n"
    );
    out.push_str(&example_toml(table, network));
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
        Kind::Listen(_) => "IP address, with or without a port (`address[:port]`)".to_owned(),
        Kind::PeerEndpoint(PeerRule::Any) => "IP endpoint or v3 onion with a port".to_owned(),
        Kind::PeerEndpoint(PeerRule::OnionOnly) => "v3 onion with a port".to_owned(),
        Kind::Address => "Shekyl address".to_owned(),
        Kind::Path { keywords } => with_keywords("absolute path", keywords),
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
        Kind::Hash => "64 hexadecimal characters".to_owned(),
        Kind::Name(rule) => format!("name ({})", rule.describe),
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

/// The endpoint an example shows for `name` on `network`, without quotes.
///
/// A derived listen is the address a start writes when that default
/// applies. The other arms are the rows that illustrate one field of
/// [`shekyl_network::Ports`] on a host only the operator has. Any other
/// row has no port to show, so its example is [`CHOSEN_ENDPOINT`].
fn example_endpoint(name: &str, network: Network) -> Option<String> {
    if let Some(addr) = listen_default(name, network) {
        return Some(addr.to_string());
    }
    // The port is the row's. `p2p` is the port peers dial; a row about
    // another field of `Ports` names that field here.
    let ports = network.ports();
    let (host, port) = match name {
        "clearnet-advertise" => ("<public-address>", ports.p2p),
        "tor-onion" => ("<56 characters>.onion", ports.p2p),
        _ => return None,
    };
    Some(format!("{host}:{port}"))
}

/// The value the example shows. A literal default is that default. A row
/// [`example_endpoint`] names shows that endpoint, as a list when the row
/// is one. Anything else is an example of the kind, and an endpoint among
/// those is [`CHOSEN_ENDPOINT`]: the kind does not say which port.
fn example_value(name: &str, kind: &Kind, default: &Default, network: Network) -> String {
    if let Default::Value(v) = default {
        return match kind {
            Kind::Switch => v.to_string(),
            Kind::Integer { .. } if v.parse::<u64>().is_ok() => (*v).to_owned(),
            Kind::List(_) if *v == "none" => "\"none\"".to_owned(),
            Kind::List(_) => format!("[\"{v}\"]"),
            _ => format!("\"{v}\""),
        };
    }
    if let Some(endpoint) = example_endpoint(name, network) {
        return match kind {
            Kind::List(_) => format!("[\"{endpoint}\"]"),
            _ => format!("\"{endpoint}\""),
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
        // The kind is a syntax. Which port a row names, if any, was decided
        // above; an endpoint that reached here has none.
        Kind::Endpoint(_) | Kind::PeerEndpoint(_) => CHOSEN_ENDPOINT.to_owned(),
        // An address, with no port. The view listener takes the network's
        // view port when the operator omits one.
        Kind::Listen(_) => format!("\"{}\"", Ipv4Addr::LOCALHOST),
        Kind::Address => "\"<address>\"".to_owned(),
        Kind::Path { .. } => "\"/path\"".to_owned(),
        Kind::Secret => "\"<secret>\"".to_owned(),
        Kind::Command { placeholders } => format!(
            "[\"/path/to/command\"{}]",
            placeholders
                .first()
                .map(|p| format!(", \"{{{p}}}\""))
                .unwrap_or_default()
        ),
        Kind::Origin => "\"https://example.org\"".to_owned(),
        Kind::Hash => "\"<64 hex characters>\"".to_owned(),
        Kind::Name(_) => "\"<name>\"".to_owned(),
        Kind::List(item) => format!("[{}]", example_value(name, item, &Default::Unset, network)),
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

    /// The example's `/path` values as the host spells an absolute path:
    /// as written on Unix, `C:\path` on Windows, where `/path` is not
    /// absolute and the path kinds refuse it (DC-F40). The example itself
    /// stays the Unix spelling; it is one file for every platform. The
    /// Windows installer puts it beside the binaries (INPUT_GRAMMAR.md
    /// IG-Q64), where every line is a comment and a path value is an
    /// illustration to be respelled, not a default (review 3 §3 of the
    /// Rust-binary PR).
    fn host_absolute(value: &toml::Value) -> toml::Value {
        match value {
            toml::Value::String(s) if cfg!(windows) && s.starts_with('/') => {
                toml::Value::String(format!("C:{}", s.replace('/', "\\")))
            }
            toml::Value::Array(items) => {
                toml::Value::Array(items.iter().map(host_absolute).collect())
            }
            other => other.clone(),
        }
    }

    const TABLE_FILE: &str = "shekyld_options.md";
    const EXAMPLE_FILE: &str = "shekyld.example.toml";
    /// The network the generic example's ports are: the one a run with no
    /// `--network` uses.
    const EXAMPLE_NETWORK: Network = Network::Mainnet;

    /// The settings file a package ships for `network`, in
    /// `contrib/packaging/linux/`.
    fn packaged(network: Network) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contrib/packaging/linux")
            .join(format!("shekyld-{}.toml", network.name()))
    }

    /// The subject assertion (rule 47): the rendering is not empty and
    /// names every public row, before anything is compared against it.
    #[test]
    fn the_rendering_names_every_public_row_and_no_hidden_one() {
        let table = options_markdown(&TABLE);
        let example = example_toml(&TABLE, EXAMPLE_NETWORK);
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
        let example = example_toml(&TABLE, EXAMPLE_NETWORK);
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
                .parse_file(&host_absolute(value))
                .unwrap_or_else(|e| panic!("{key}'s example value is its kind's: {e:?}"));
        }
    }

    /// The generic example's network is the `network` row's default, so the
    /// example shows the ports a run with no `--network` uses.
    #[test]
    fn the_generic_example_is_the_default_networks() {
        let row = TABLE
            .rows
            .iter()
            .find(|r| r.name == "network")
            .expect("the network row");
        assert!(
            matches!(row.default, Default::Value(name) if name == EXAMPLE_NETWORK.name()),
            "the generic example's network is the network row's default"
        );
    }

    /// The value the example assigns to `name` (`# name = …`).
    fn assignment<'a>(text: &'a str, name: &str) -> &'a str {
        let prefix = format!("# {name} = ");
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("{name} is in the example"))
    }

    /// Each row that names a port names its own, and a row with no port
    /// does not borrow one from its kind. A settings file for one network
    /// that shows another's port tells its operator to bind or dial the
    /// wrong one (the alpha.12 testnet file showed mainnet's). Swapping two
    /// rows' ports on the same network fails the assignment, and stamping
    /// the RPC port onto `tor-socks` fails the placeholder.
    #[test]
    fn each_networks_example_names_its_own_ports() {
        for network in Network::ALL {
            let text = example_toml(&TABLE, network);
            let ports = network.ports();
            let name = network.name();
            assert_eq!(
                assignment(&text, "clearnet-listen"),
                format!("[\"0.0.0.0:{}\"]", ports.p2p),
                "{name} clearnet-listen"
            );
            assert_eq!(
                assignment(&text, "rpc-admin-listen"),
                format!("[\"127.0.0.1:{}\"]", ports.rpc),
                "{name} rpc-admin-listen"
            );
            assert_eq!(
                assignment(&text, "clearnet-advertise"),
                format!("[\"<public-address>:{}\"]", ports.p2p),
                "{name} clearnet-advertise"
            );
            assert_eq!(
                assignment(&text, "tor-onion"),
                format!("\"<56 characters>.onion:{}\"", ports.p2p),
                "{name} tor-onion"
            );
            for row in ["tor-socks", "clearnet-socks", "tor-onion-listen"] {
                assert_eq!(
                    assignment(&text, row),
                    CHOSEN_ENDPOINT,
                    "{name} {row} has no default port"
                );
            }
            for other in Network::ALL {
                let theirs = other.ports();
                for port in [theirs.p2p, theirs.rpc, theirs.view] {
                    if [ports.p2p, ports.rpc, ports.view].contains(&port) {
                        continue;
                    }
                    assert!(
                        !text.contains(&format!(":{port}")),
                        "the {name} example names {}'s port {port}",
                        other.name()
                    );
                }
            }
        }
    }

    /// The committed fragments are this rendering. Regenerate with
    /// `cargo test -p shekyl-daemon-config regenerate_generated_docs -- --ignored`.
    #[test]
    fn the_committed_fragments_are_the_rendering() {
        for (name, text) in [
            (TABLE_FILE, options_markdown(&TABLE)),
            (EXAMPLE_FILE, example_toml(&TABLE, EXAMPLE_NETWORK)),
        ] {
            let path = generated(name);
            // A checkout with `core.autocrlf` hands the fragment back with
            // CRLF line ends; the rendering is the bytes between them
            // (DC-F40).
            let committed = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} is committed: {e}", path.display()))
                .replace("\r\n", "\n");
            assert_eq!(
                committed,
                text,
                "{} differs from the table's rendering; regenerate it",
                path.display()
            );
        }
    }

    /// The packaged files are this rendering, one per public network, and
    /// each is the example under its header: every option line commented
    /// out, so a fresh install runs on the defaults. Regenerate with
    /// `cargo test -p shekyl-daemon-config regenerate_generated_docs -- --ignored`.
    #[test]
    fn the_packaged_files_are_the_rendering() {
        for network in PACKAGED_NETWORKS {
            let example = example_toml(&TABLE, network);
            let text = packaged_toml(&TABLE, network);
            assert!(
                text.ends_with(&example),
                "the packaged {} file is the example under its header",
                network.name()
            );
            let parsed: toml::Table = text.parse().expect("the packaged file parses");
            assert!(
                parsed.is_empty(),
                "the packaged {} file sets nothing",
                network.name()
            );
            let path = packaged(network);
            let committed = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} is committed: {e}", path.display()))
                .replace("\r\n", "\n");
            assert_eq!(
                committed,
                text,
                "{} differs from its rendering; regenerate it",
                path.display()
            );
        }
        assert!(
            !PACKAGED_NETWORKS.contains(&Network::Regtest),
            "regtest is a harness network and gets no packaged file"
        );
        // The package ships exactly these files, and the .deb's purge
        // removes exactly these names: one list, held here.
        let dir = packaged(Network::Mainnet)
            .parent()
            .expect("a directory")
            .to_path_buf();
        let mut shipped: Vec<String> = std::fs::read_dir(&dir)
            .expect("contrib/packaging/linux is readable")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.starts_with("shekyld-") && n.ends_with(".toml"))
            .collect();
        shipped.sort();
        let mut want: Vec<String> = PACKAGED_NETWORKS
            .iter()
            .map(|n| format!("shekyld-{}.toml", n.name()))
            .collect();
        want.sort();
        assert_eq!(
            shipped, want,
            "contrib/packaging/linux ships one file per packaged network"
        );
        let purge =
            std::fs::read_to_string(dir.join("deb-after-purge.sh")).expect("the purge script");
        let names = PACKAGED_NETWORKS.map(Network::name).join(" ");
        assert!(
            purge.contains(&format!("for network in {names}; do")),
            "deb-after-purge.sh removes the packaged networks' files: {names}"
        );
    }

    #[test]
    #[ignore = "writes docs/generated/ and contrib/packaging/linux/; run on purpose after a table change"]
    fn regenerate_generated_docs() {
        std::fs::write(generated(TABLE_FILE), options_markdown(&TABLE)).expect("write table");
        std::fs::write(
            generated(EXAMPLE_FILE),
            example_toml(&TABLE, EXAMPLE_NETWORK),
        )
        .expect("write example");
        for network in PACKAGED_NETWORKS {
            std::fs::write(packaged(network), packaged_toml(&TABLE, network))
                .expect("write packaged file");
        }
    }
}
