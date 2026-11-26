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

use shekyl_daemon_config::TABLE;

#[path = "support/grammar_walk.rs"]
mod grammar_walk;
use grammar_walk::{fault, glossary, walk};

#[test]
fn every_live_and_reserved_name_is_a_path_through_the_glossary_tree() {
    let (walked, faults) = walk(&TABLE);
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
