// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The grammar gate over `shekyl-rpc-tunnel`'s table (`INPUT_GRAMMAR.md` IG-3) and
//! its generated option document (IG-9). A name the glossary cannot derive
//! fails here, so a new row is a glossary edit and not a local choice.

use std::path::PathBuf;

use shekyl_rpc_tunnel::table::TABLE;

#[path = "../../shekyl-daemon-config/tests/support/grammar_walk.rs"]
mod grammar_walk;

fn document() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/generated/shekyl-rpc-tunnel_options.md")
}

#[test]
fn every_live_name_is_a_path_through_the_glossary_tree() {
    let (walked, faults) = grammar_walk::walk(&TABLE);
    assert!(walked >= 5, "walked {walked} names; the table moved");
    assert!(
        faults.is_empty(),
        "names that are not paths through the tree:\n{}",
        faults.join("\n")
    );
}

/// The committed document is this table's rendering. After a table change,
/// run the ignored writer below.
#[test]
fn the_committed_option_document_is_the_tables() {
    let committed = std::fs::read_to_string(document()).expect("the committed document");
    assert_eq!(
        committed.replace("\r\n", "\n"),
        shekyl_daemon_config::docs::options_markdown(&TABLE),
        "run: cargo test -p shekyl-rpc-tunnel --test grammar_names -- --ignored write_the"
    );
}

#[test]
#[ignore = "writes docs/generated/; run on purpose after a table change"]
fn write_the_option_document() {
    std::fs::write(
        document(),
        shekyl_daemon_config::docs::options_markdown(&TABLE),
    )
    .expect("write the document");
}
