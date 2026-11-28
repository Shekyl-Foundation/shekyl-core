// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The walk of a table's names through the glossary tree (`INPUT_GRAMMAR.md`
//! IG-3), shared by source with each binary's own `grammar_names` test: the
//! wallet binaries depend on this crate, so this crate's tests cannot name
//! their tables.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use shekyl_options::{Table, Visibility};

const QUALIFIERS: &[&str] = &["max", "min"];

/// term -> parents (`None` in the set marks a root, the document's `—`).
pub fn glossary() -> HashMap<String, HashSet<Option<String>>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/INPUT_GRAMMAR.md");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut terms: HashMap<String, HashSet<Option<String>>> = HashMap::new();
    let mut in_table = false;
    for line in text.lines() {
        if line.starts_with("| Term | Parents |") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with('|') {
            in_table = false;
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 || cells[1].starts_with("---") {
            continue;
        }
        let term = cells[1].trim_matches('`').to_owned();
        let parents: HashSet<Option<String>> = cells[2]
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| {
                if p == "—" {
                    None
                } else {
                    Some(p.trim_matches('`').to_owned())
                }
            })
            .collect();
        assert!(
            !terms.contains_key(&term),
            "the glossary defines `{term}` twice (IG-2: each term is defined once)"
        );
        terms.insert(term, parents);
    }
    assert!(
        terms.len() >= 50,
        "the glossary has {} terms; the table or the pattern moved",
        terms.len()
    );
    terms
}

/// Why a name is not a path through the tree, or `None` when it is.
pub fn fault(name: &str, terms: &HashMap<String, HashSet<Option<String>>>) -> Option<String> {
    let segments: Vec<&str> = name.split('-').collect();
    for (i, seg) in segments.iter().enumerate() {
        let Some(parents) = terms.get(*seg) else {
            return Some(format!("`{seg}` is not a term of the glossary"));
        };
        let qualifier = QUALIFIERS.contains(seg) || parents.contains(&Some("any".to_owned()));
        if qualifier {
            if i + 1 != segments.len() {
                return Some(format!("the qualifier `{seg}` is not last"));
            }
            continue;
        }
        if i == 0 {
            if !parents.contains(&None) {
                return Some(format!("`{seg}` is not a subject (it has parents only)"));
            }
        } else if !parents.contains(&Some(segments[i - 1].to_owned())) {
            return Some(format!(
                "`{}` → `{seg}` is not a parent → child edge of the tree",
                segments[i - 1]
            ));
        }
    }
    None
}

/// Every live and reserved name of `table` that is not a path through the
/// tree, with its fault, and how many names were walked. A rejected row is
/// a refused spelling, exempt by kind (IG-10).
pub fn walk(table: &Table) -> (usize, Vec<String>) {
    let terms = glossary();
    let mut walked = 0;
    let mut faults = Vec::new();
    for row in table.rows {
        if matches!(row.visibility, Visibility::Rejected { .. }) {
            continue;
        }
        walked += 1;
        if let Some(why) = fault(row.name, &terms) {
            faults.push(format!("{}: {why}", row.name));
        }
    }
    (walked, faults)
}
