// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transaction parser, the one that reads untrusted transactions off
//! the wire and out of blocks.
//!
//! The encoding is canonical, so a blob `Transaction::from_bytes` accepts
//! must re-serialize to itself: two byte strings for one transaction would
//! give it two ids. The context-free validation runs on every parse; it
//! may refuse, but it must not panic.
//!
//!   cargo +nightly fuzz run fuzz_tx_parse corpus/fuzz_tx_parse seeds/fuzz_tx_parse

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_wire::Transaction;

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = Transaction::from_bytes(data) else {
        return;
    };
    assert_eq!(tx.serialize(), data, "parse → serialize must be the identity");
    let _ = tx.validate();
});
