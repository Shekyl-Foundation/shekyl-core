// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The grammar gate over the daemon's table (`INPUT_GRAMMAR.md` IG-3): every
//! live and reserved name is a path through the glossary tree. It starts at
//! a subject (a term with no parent), each segment is a child of the one
//! before, the qualifiers `max` and `min` end a path and appear nowhere
//! else, and no term is defined twice. A rejected row is a refused spelling,
//! exempt by kind (IG-10).
//!
//! The glossary lives in the design document (IG-15), so this test reads
//! it: the `| Term | Parents | Meaning |` tables of `INPUT_GRAMMAR.md`, Part
//! A's and Part B's. A name the glossary cannot derive fails here, which is
//! what makes a new row a glossary edit and not a local choice (rule 83).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use shekyl_daemon_config::TABLE;
use shekyl_options::Visibility;

const QUALIFIERS: &[&str] = &["max", "min"];

/// term -> parents (`None` in the set marks a root, the document's `—`).
fn glossary() -> HashMap<String, HashSet<Option<String>>> {
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
fn fault(name: &str, terms: &HashMap<String, HashSet<Option<String>>>) -> Option<String> {
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

#[test]
fn every_live_and_reserved_name_is_a_path_through_the_glossary_tree() {
    let terms = glossary();
    let mut walked = 0;
    let mut faults = Vec::new();
    for row in TABLE.rows {
        if matches!(row.visibility, Visibility::Rejected { .. }) {
            continue;
        }
        walked += 1;
        if let Some(why) = fault(row.name, &terms) {
            faults.push(format!("{}: {why}", row.name));
        }
    }
    assert!(walked >= 30, "walked {walked} names; the table moved");
    assert!(
        faults.is_empty(),
        "names that are not paths through the tree:\n{}",
        faults.join("\n")
    );
}

/// The edit that proves the gate can fail (IG-3): `tor-socks-tor` reverses an
/// edge, `tor-max-socks` misplaces a qualifier, `socks` alone is no subject,
/// `tor-sock` is not a term.
#[test]
fn a_name_that_is_not_a_path_is_named_with_its_fault() {
    let terms = glossary();
    assert_eq!(fault("tor-socks-password", &terms), None);
    assert_eq!(fault("log-size-max", &terms), None);
    assert_eq!(fault("dev-clearnet-encrypt", &terms), None);
    assert!(fault("tor-socks-tor", &terms)
        .unwrap()
        .contains("not a parent → child edge"));
    assert!(fault("tor-max-socks", &terms).unwrap().contains("not last"));
    assert!(fault("socks", &terms).unwrap().contains("not a subject"));
    assert!(fault("tor-sock", &terms).unwrap().contains("not a term"));
}
