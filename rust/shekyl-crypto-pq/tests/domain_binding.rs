// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The registry's binding gate (the signing envelope §2.4, §2.5;
//! `NETWORK_IDENTITY.md` §2.4.1).
//!
//! Every production row of `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` declares
//! one of six bindings (`id`, `name`, `input:<type>`, `derived:<CEN rule>`,
//! `local:<why>`, `enclosed-by:<row>`), a width and a role. This test holds
//! the declarations to the code by parsing it (`syn`), not by grepping:
//!
//! 1. every binding, width and role is drawn from its closed list;
//! 2. a cSHAKE row marked `id` or `name` is declared as an `IdDomain` or
//!    `NameDomain` constant of that kind and width, and a constant of either
//!    type has a row marked accordingly;
//! 3. an HKDF row marked `name` is defined beside a call of `salt_for`;
//! 4. both Noise handshakes take their prologue from a `&NetworkId`;
//! 5. an `input:<type>` row's site takes the named type, in a function
//!    parameter or a field of its input struct;
//! 6. `local` is refused on a row whose verification is evidence of who made
//!    something or that it is authentic (role `signed` or `auth`), and
//!    `derived:` names a rule present in `CONSENSUS_RULE_CENSUS.md`;
//! 7. `enclosed-by` is refused on a Shekyl-owned row;
//! 8. a row a post-quantum or hybrid signature signs as its content (role
//!    `signed`) is 64 bytes wide.
//!
//! Rows the code cannot yet meet are listed in
//! `docs/design/DOMAIN_BINDING_RATCHET.tsv`, whose section counts are pinned
//! here: the list only shrinks, and a listed row the gate can already prove
//! is refused until it is removed. A label in the registry's retired section
//! may appear in no Rust source. Each check has a control below that feeds it
//! a bad row or a bad source and asserts the refusal (rule 47).

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use quote::ToTokens;
use syn::visit::Visit;

const REGISTRY: &str = include_str!("../../../docs/design/CRYPTO_DOMAIN_REGISTRY.tsv");
const RATCHET: &str = include_str!("../../../docs/design/DOMAIN_BINDING_RATCHET.tsv");
const CENSUS: &str = include_str!("../../../docs/design/CONSENSUS_RULE_CENSUS.md");

/// The ratchet's pinned section sizes. Lower a pin when a row leaves; a
/// raise is a new hole and needs a ruling.
const INPUT_RAW_EXPECTED: usize = 35;
const UNFRAMED_EXPECTED: usize = 2;
const PENDING_EXPECTED: usize = 7;

/// The two rows that derive the bindings themselves (§2.4): `name_id` from
/// the name, and the network id from the genesis hash.
const BINDING_DERIVATIONS: [&str; 2] = ["shekyl/network-name-v1", "shekyl/p2p-network-id-v1"];

/// The Shekyl-labelled rows `enclosed-by` admits beside the frozen-inherited
/// ones (§2.4, closed): the membership-only SAL's hedged prover nonces.
const HEDGED_NONCES: [&str; 6] = [
    "Shekyl FCMP++ MO nonce r_o v1",
    "Shekyl FCMP++ MO nonce r_i v1",
    "Shekyl FCMP++ MO nonce r_r_i v1",
    "Shekyl FCMP++ MO nonce r_c v1",
    "Shekyl FCMP++ MO nonce alpha v1",
    "Shekyl FCMP++ MO nonce r_y v1",
];

/// `input:<type>` (§2.4, closed) and the Rust type a site must take for it.
/// `None`: no type exists yet, so every such row is in the ratchet.
const INPUT_TYPES: [(&str, Option<&str>); 8] = [
    ("TxSignableHash", Some("TxSignableHash")),
    ("SigningPayloadHash", Some("SigningPayloadHash")),
    ("frame", None),
    ("BlockHash", Some("BlockHash")),
    ("TxId", Some("TxHash")),
    ("TreeRoot", Some("CurveTreeRoot")),
    ("SaltForKey", None),
    ("NoiseMessage", None),
];

/// `local:<why>` (§2.4, closed).
const LOCAL_WHY: [&str; 9] = [
    "wallet-file-key",
    "p-store-key",
    "store-codec",
    "per-output-secret",
    "display-only",
    "process-local",
    "key-intermediate",
    "verifier-randomness",
    "checksum",
];

/// The files holding the two Noise handshakes' initial states.
const HANDSHAKE_FILES: [&str; 2] = [
    "rust/shekyl-p2p-transport/src/noise.rs",
    "rust/shekyl-rpc-channel/src/handshake.rs",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding<'a> {
    Id,
    Name,
    Input(&'a str),
    Derived(&'a str),
    Local(&'a str),
    EnclosedBy(&'a str),
    /// `-`: a production row only while it is in the ratchet's pending section.
    Unbound,
}

#[derive(Debug)]
struct Row<'a> {
    line: usize,
    mech: &'a str,
    literal: &'a str,
    file: &'a str,
    konst: &'a str,
    status: &'a str,
    binding: Binding<'a>,
    width: &'a str,
    role: &'a str,
}

impl Row<'_> {
    fn is_production(&self) -> bool {
        matches!(self.status, "shekyl-live" | "frozen-inherited")
    }
}

fn parse_binding(s: &str) -> Result<Binding<'_>, String> {
    let (kind, arg) = s.split_once(':').unwrap_or((s, ""));
    match (kind, arg) {
        ("id", "") => Ok(Binding::Id),
        ("name", "") => Ok(Binding::Name),
        ("-", "") => Ok(Binding::Unbound),
        ("input", t) if INPUT_TYPES.iter().any(|(name, _)| *name == t) => Ok(Binding::Input(t)),
        ("local", why) if LOCAL_WHY.contains(&why) => Ok(Binding::Local(why)),
        ("derived", rule) if rule.starts_with("CEN-") && rule.len() > 4 => {
            Ok(Binding::Derived(rule))
        }
        ("enclosed-by", row) if !row.is_empty() => Ok(Binding::EnclosedBy(row)),
        _ => Err(format!("binding {s:?} is not on the closed lists")),
    }
}

fn parse_registry(text: &str) -> Result<Vec<Row<'_>>, String> {
    let mut rows = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        // mech literal file const status binding width role key notes
        if f.len() != 10 {
            return Err(format!("line {}: {} columns, expected 10", i + 1, f.len()));
        }
        rows.push(Row {
            line: i + 1,
            mech: f[0],
            literal: f[1],
            file: f[2],
            konst: f[3],
            status: f[4],
            binding: parse_binding(f[5]).map_err(|e| format!("line {}: {e}", i + 1))?,
            width: f[6],
            role: f[7],
        });
    }
    Ok(rows)
}

#[derive(Debug, Default)]
struct Ratchet<'a> {
    input_raw: Vec<&'a str>,
    unframed: Vec<&'a str>,
    pending: Vec<&'a str>,
}

fn parse_ratchet(text: &str) -> Result<Ratchet<'_>, String> {
    let mut out = Ratchet::default();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let (Some(section), Some(literal), Some(_note)) = (f.first(), f.get(1), f.get(2)) else {
            return Err(format!(
                "ratchet line {}: expected section, literal, note",
                i + 1
            ));
        };
        match *section {
            "input-raw" => out.input_raw.push(literal),
            "unframed" => out.unframed.push(literal),
            "pending" => out.pending.push(literal),
            other => return Err(format!("ratchet line {}: unknown section {other:?}", i + 1)),
        }
    }
    Ok(out)
}

/// What one Rust file declares outside its test code.
#[derive(Debug, Default)]
struct Facts {
    /// Constant name → its type, whitespace removed.
    consts: BTreeMap<String, String>,
    /// Every function parameter and struct field type, its tokens spaced.
    param_types: Vec<String>,
    /// Whether the file calls (or defines) `salt_for`.
    salt_for: bool,
    /// The prologue argument of each `Sym::new` / `SymmetricState::new`.
    prologue_args: Vec<String>,
    /// The type of every parameter named `network_id`.
    network_id_types: Vec<String>,
}

fn squash(tokens: impl ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

fn is_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("test") || (a.path().is_ident("cfg") && squash(&a.meta).contains("test"))
    })
}

impl<'ast> Visit<'ast> for Facts {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !is_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if is_test(&f.attrs) {
            return;
        }
        if f.sig.ident == "salt_for" {
            self.salt_for = true;
        }
        syn::visit::visit_item_fn(self, f);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if !is_test(&f.attrs) {
            syn::visit::visit_impl_item_fn(self, f);
        }
    }
    fn visit_item_const(&mut self, c: &'ast syn::ItemConst) {
        self.consts.insert(c.ident.to_string(), squash(&c.ty));
        syn::visit::visit_item_const(self, c);
    }
    fn visit_impl_item_const(&mut self, c: &'ast syn::ImplItemConst) {
        self.consts.insert(c.ident.to_string(), squash(&c.ty));
        syn::visit::visit_impl_item_const(self, c);
    }
    fn visit_pat_type(&mut self, p: &'ast syn::PatType) {
        let ty = spaced(&p.ty);
        if squash(&p.pat) == "network_id" {
            self.network_id_types.push(ty.clone());
        }
        self.param_types.push(ty);
        syn::visit::visit_pat_type(self, p);
    }
    fn visit_field(&mut self, f: &'ast syn::Field) {
        self.param_types.push(spaced(&f.ty));
        syn::visit::visit_field(self, f);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*call.func {
            let segs: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segs.last().is_some_and(|s| s == "salt_for") {
                self.salt_for = true;
            }
            if segs.len() >= 2
                && segs[segs.len() - 1] == "new"
                && matches!(segs[segs.len() - 2].as_str(), "Sym" | "SymmetricState")
            {
                if let Some(arg) = call.args.iter().nth(1) {
                    self.prologue_args.push(squash(arg));
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn facts_of(source: &str) -> Result<Facts, String> {
    let file = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut facts = Facts::default();
    facts.visit_file(&file);
    Ok(facts)
}

/// Whether `ty` (squashed) is the named type, by value or reference, with
/// or without a path.
fn names_type(ty: &str, name: &str) -> bool {
    let bare: String = ty
        .split_whitespace()
        .filter(|t| !matches!(*t, "&" | "mut") && !t.starts_with('\''))
        .collect();
    bare == name || bare.ends_with(&format!("::{name}"))
}

/// A type's tokens, one space apart, so a lifetime stays its own token.
fn spaced(tokens: impl ToTokens) -> String {
    tokens.to_token_stream().to_string()
}

fn domain_kind(ty: &str) -> Option<(&'static str, &'static str)> {
    let (kind, rest) = if let Some(rest) = ty.strip_prefix("IdDomain<") {
        ("id", rest)
    } else if let Some(rest) = ty.strip_prefix("NameDomain<") {
        ("name", rest)
    } else {
        return None;
    };
    Some((kind, if rest.contains("W64") { "64" } else { "32" }))
}

/// Every failure the gate finds. `read` gives a repository file's text.
fn check(
    registry: &str,
    ratchet: &str,
    census: &str,
    read: &dyn Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut bad = Vec::new();
    let rows = match parse_registry(registry) {
        Ok(rows) => rows,
        Err(e) => return vec![e],
    };
    let ratchet = match parse_ratchet(ratchet) {
        Ok(r) => r,
        Err(e) => return vec![e],
    };
    let production: HashSet<&str> = rows
        .iter()
        .filter(|r| r.is_production())
        .map(|r| r.literal)
        .collect();
    let census_rows: HashSet<&str> = census
        .lines()
        .filter_map(|l| l.strip_prefix("| ")?.split(' ').next())
        .filter(|id| id.starts_with("CEN-"))
        .collect();
    let parsed: BTreeMap<&str, Option<Facts>> = rows
        .iter()
        .map(|r| r.file)
        .filter(|f| f.ends_with(".rs"))
        .chain(HANDSHAKE_FILES)
        .map(|f| (f, read(f).and_then(|s| facts_of(&s).ok())))
        .collect();
    let facts = |file: &str| parsed.get(file).and_then(Option::as_ref);

    for literal in ratchet
        .input_raw
        .iter()
        .chain(&ratchet.unframed)
        .chain(&ratchet.pending)
    {
        if !production.contains(literal) {
            bad.push(format!(
                "ratchet names {literal:?}, which is no production row"
            ));
        }
    }

    for row in &rows {
        let at = format!("line {} ({})", row.line, row.literal);
        if row.status == "retired" {
            continue;
        }
        if !row.is_production() {
            if (row.binding, row.width, row.role) != (Binding::Unbound, "-", "-") {
                bad.push(format!(
                    "{at}: a {} row carries no binding, width or role (all \"-\")",
                    row.status
                ));
            }
            continue;
        }
        // 1. Closed lists.
        if !(row.width == "-" || row.width.parse::<u32>().is_ok_and(|w| w > 0)) {
            bad.push(format!(
                "{at}: width {:?} is neither a byte count nor \"-\"",
                row.width
            ));
        }
        if !matches!(row.role, "signed" | "auth" | "plain") {
            bad.push(format!(
                "{at}: role {:?} is not signed, auth or plain",
                row.role
            ));
        }
        let pending = ratchet.pending.contains(&row.literal);
        if (row.binding == Binding::Unbound) != pending {
            bad.push(format!(
                "{at}: binding \"-\" if and only if the row is in the ratchet's pending section"
            ));
        }
        // 8. Signed content is 64 bytes.
        if row.role == "signed" && row.width != "64" {
            bad.push(format!("{at}: signed content of a post-quantum or hybrid signature must be 64 bytes, not {}", row.width));
        }
        let derivation = BINDING_DERIVATIONS.contains(&row.literal);
        match row.binding {
            // 6. local refused on authenticity evidence.
            Binding::Local(_) if matches!(row.role, "signed" | "auth") => {
                bad.push(format!("{at}: local on a row whose verification is evidence of authorship or authenticity"));
            }
            Binding::Derived(rule) if !census_rows.contains(rule) => {
                bad.push(format!(
                    "{at}: derived:{rule} names no row of CONSENSUS_RULE_CENSUS.md"
                ));
            }
            // 7. enclosed-by only on third-party internals and the hedged nonces.
            Binding::EnclosedBy(outer) => {
                if row.status != "frozen-inherited" && !HEDGED_NONCES.contains(&row.literal) {
                    bad.push(format!("{at}: enclosed-by on a Shekyl-owned row"));
                }
                if !production.contains(outer) {
                    bad.push(format!(
                        "{at}: enclosed-by names {outer:?}, which is no production row"
                    ));
                }
            }
            _ => {}
        }
        if !row.file.ends_with(".rs") {
            continue;
        }
        let Some(f) = facts(row.file) else {
            bad.push(format!(
                "{at}: {} does not parse or does not exist",
                row.file
            ));
            continue;
        };
        // 2. cSHAKE id/name rows are envelope domains of their kind and width.
        if row.mech == "1" {
            let declared = f.consts.get(row.konst).and_then(|ty| domain_kind(ty));
            let wants = match row.binding {
                Binding::Id => Some("id"),
                Binding::Name => Some("name"),
                _ => None,
            };
            let unframed = ratchet.unframed.contains(&row.literal);
            match (wants, declared) {
                (Some(kind), Some((got, width))) => {
                    if kind != got {
                        bad.push(format!(
                            "{at}: binding {kind} but {} is a {got} domain",
                            row.konst
                        ));
                    }
                    if width != row.width {
                        bad.push(format!(
                            "{at}: width {} but {} reads {width}",
                            row.width, row.konst
                        ));
                    }
                    if unframed {
                        bad.push(format!("{at}: in the ratchet's unframed section but declared as a domain; remove it"));
                    }
                }
                (Some(kind), None) if !derivation && !unframed => {
                    bad.push(format!(
                        "{at}: binding {kind} but {} is not an IdDomain or NameDomain constant",
                        row.konst
                    ));
                }
                (None, Some((got, _))) => {
                    bad.push(format!(
                        "{at}: {} is a {got} domain but the row's binding is not {got}",
                        row.konst
                    ));
                }
                _ => {}
            }
        }
        // 3. HKDF name rows sit beside salt_for.
        if row.mech == "2" && row.binding == Binding::Name && !f.salt_for {
            bad.push(format!(
                "{at}: binding name but {} neither calls nor defines salt_for",
                row.file
            ));
        }
        // 5. input:<type> rows take the type, or are in the ratchet.
        if let Binding::Input(t) = row.binding {
            if derivation {
                continue;
            }
            let rust = INPUT_TYPES
                .iter()
                .find(|(name, _)| *name == t)
                .and_then(|(_, r)| *r);
            let typed = rust.is_some_and(|r| f.param_types.iter().any(|ty| names_type(ty, r)));
            let listed = ratchet.input_raw.contains(&row.literal);
            if typed && listed {
                bad.push(format!(
                    "{at}: its site takes {t}; remove it from the ratchet"
                ));
            }
            if !typed && !listed {
                bad.push(format!(
                    "{at}: input:{t}, but no site in {} takes it and it is not in the ratchet",
                    row.file
                ));
            }
        }
    }

    // 4. Both handshakes' prologues come from a &NetworkId.
    for file in HANDSHAKE_FILES {
        let Some(f) = facts(file) else {
            bad.push(format!("{file} does not parse or does not exist"));
            continue;
        };
        if f.prologue_args.is_empty() {
            bad.push(format!("{file}: no handshake initial state found"));
        }
        for arg in &f.prologue_args {
            if !matches!(arg.as_str(), "network_id" | "&prologue(network_id)") {
                bad.push(format!(
                    "{file}: a handshake's prologue is {arg}, not built from the network id"
                ));
            }
        }
        for ty in &f.network_id_types {
            if !names_type(ty, "NetworkId") {
                bad.push(format!(
                    "{file}: a network_id parameter is {ty}, not &NetworkId"
                ));
            }
        }
    }
    bad
}

/// Retired labels that appear in a source: `(label, file)`.
fn retired_reuse<'a>(registry: &'a str, sources: &[(String, String)]) -> Vec<(&'a str, String)> {
    let retired: Vec<&str> = registry
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.get(4) == Some(&"retired")).then(|| f[1])
        })
        .collect();
    let mut hits = Vec::new();
    for label in retired {
        let needle = format!("b\"{label}\"");
        for (file, text) in sources {
            if text.contains(&needle) {
                hits.push((label, file.clone()));
            }
        }
    }
    hits
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_tree(file: &str) -> Option<String> {
    std::fs::read_to_string(repo_root().join(file)).ok()
}

fn rust_sources() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if name != "target" && name != ".git" {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.push((path.display().to_string(), text));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_root().join("rust"), &mut out);
    out
}

#[test]
fn every_row_meets_its_binding() {
    let bad = check(REGISTRY, RATCHET, CENSUS, &read_tree);
    assert!(bad.is_empty(), "binding gate:\n  {}", bad.join("\n  "));
}

#[test]
fn the_ratchet_only_shrinks() {
    let r = parse_ratchet(RATCHET).expect("the ratchet parses");
    assert_eq!(
        r.input_raw.len(),
        INPUT_RAW_EXPECTED,
        "input-raw: lower the pin when a row leaves"
    );
    assert_eq!(
        r.unframed.len(),
        UNFRAMED_EXPECTED,
        "unframed: lower the pin when a row leaves"
    );
    assert_eq!(
        r.pending.len(),
        PENDING_EXPECTED,
        "pending: lower the pin when a row leaves"
    );
}

#[test]
fn no_retired_label_is_reused() {
    let sources = rust_sources();
    // Rule 47: the scan must have found the tree.
    assert!(
        sources.len() > 100,
        "found {} Rust files under rust/",
        sources.len()
    );
    let hits = retired_reuse(REGISTRY, &sources);
    assert!(hits.is_empty(), "retired labels reused: {hits:?}");
}

// ---------------------------------------------------------------- controls
//
// Each control feeds `check` the real registry and ratchet with one edit and
// asserts the refusal it must produce. A control that passes on the edit
// proves its check does not bite.

fn refused_with(registry: &str, ratchet: &str, census: &str, needle: &str) {
    let bad = check(registry, ratchet, census, &read_tree);
    assert!(
        bad.iter().any(|b| b.contains(needle)),
        "expected a refusal containing {needle:?}, got {bad:?}"
    );
}

/// Replace the `col`-th column of the row for `literal`.
fn with_column(literal: &str, col: usize, value: &str) -> String {
    REGISTRY
        .lines()
        .map(|l| {
            let mut f: Vec<&str> = l.split('\t').collect();
            if !l.starts_with('#') && f.get(1) == Some(&literal) {
                f[col] = value;
                f.join("\t")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn control_a_binding_off_the_closed_list_is_refused() {
    let reg = with_column("shekyl/tx-signable-v1", 5, "input:BlockHeader");
    refused_with(&reg, RATCHET, CENSUS, "not on the closed lists");
}

#[test]
fn control_an_id_row_that_is_not_a_domain_constant_is_refused() {
    let reg = with_column("shekyl/archival-challenge-nonce-v1", 5, "id");
    refused_with(
        &reg,
        RATCHET,
        CENSUS,
        "is not an IdDomain or NameDomain constant",
    );
}

#[test]
fn control_a_domain_of_the_wrong_kind_or_width_is_refused() {
    refused_with(
        &with_column("shekyl/tx-signable-v1", 5, "name"),
        RATCHET,
        CENSUS,
        "is a id domain",
    );
    refused_with(
        &with_column("shekyl/fcmp-spend-signing-v2", 6, "32"),
        RATCHET,
        CENSUS,
        "reads 64",
    );
}

#[test]
fn control_an_hkdf_name_row_away_from_salt_for_is_refused() {
    let reg = with_column("shekyl-output-x", 5, "name");
    refused_with(&reg, RATCHET, CENSUS, "neither calls nor defines salt_for");
}

#[test]
fn control_a_prologue_not_from_the_network_id_is_refused() {
    let read = |file: &str| {
        let text = read_tree(file)?;
        Some(if file == HANDSHAKE_FILES[0] {
            text.replacen(
                "Sym::new(PROTOCOL_NAME, network_id)",
                "Sym::new(PROTOCOL_NAME, b\"x\")",
                1,
            )
        } else {
            text
        })
    };
    let bad = check(REGISTRY, RATCHET, CENSUS, &read);
    assert!(
        bad.iter()
            .any(|b| b.contains("not built from the network id")),
        "{bad:?}"
    );
}

#[test]
fn control_an_untyped_input_row_outside_the_ratchet_is_refused() {
    let ratchet = RATCHET.replacen("input-raw\tshekyl/archival-draw-v1\t", "#\t", 1);
    refused_with(REGISTRY, &ratchet, CENSUS, "not in the ratchet");
}

#[test]
fn control_a_typed_input_row_left_in_the_ratchet_is_refused() {
    let ratchet = format!("{RATCHET}input-raw\tshekyl/archival-shard-view-hash-v1\tcontrol\n");
    refused_with(REGISTRY, &ratchet, CENSUS, "remove it from the ratchet");
}

#[test]
fn control_local_on_authenticity_evidence_is_refused() {
    let reg = with_column("shekyl/archival-draw-v1", 5, "local:store-codec");
    refused_with(&reg, RATCHET, CENSUS, "local on a row whose verification");
}

#[test]
fn control_derived_without_a_census_rule_is_refused() {
    let census = CENSUS.replace("| CEN-J33 |", "| CEN-XJ33 |");
    refused_with(REGISTRY, RATCHET, &census, "derived:CEN-J33 names no row");
}

#[test]
fn control_enclosed_by_on_a_shekyl_row_is_refused() {
    let reg = with_column(
        "shekyl/archival-draw-v1",
        5,
        "enclosed-by:shekyl/tx-signable-v1",
    );
    refused_with(&reg, RATCHET, CENSUS, "enclosed-by on a Shekyl-owned row");
}

#[test]
fn control_narrow_signed_content_is_refused() {
    let reg = with_column("shekyl/msg-sign-v2", 6, "32");
    refused_with(&reg, RATCHET, CENSUS, "must be 64 bytes");
}

#[test]
fn control_an_unbound_row_outside_pending_is_refused() {
    let reg = with_column("shekyl/archival-draw-v1", 5, "-");
    refused_with(&reg, RATCHET, CENSUS, "pending section");
}

#[test]
fn control_a_retired_label_in_code_is_refused() {
    let reg =
        format!("{REGISTRY}\n1\tshekyl/control-retired-v1\trust/x.rs\tX\tretired\t-\t-\t-\t\t\n");
    let sources = vec![(
        "rust/x.rs".to_owned(),
        "const X: &[u8] = b\"shekyl/control-retired-v1\";".to_owned(),
    )];
    assert_eq!(retired_reuse(&reg, &sources).len(), 1);
    assert!(retired_reuse(REGISTRY, &sources).is_empty());
}
