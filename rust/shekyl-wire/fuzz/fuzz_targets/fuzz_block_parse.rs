// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block parser, the one that reads untrusted blocks off the wire.
//!
//! `Block::from_bytes` requires exact consumption and the encoding is
//! canonical (a varint with a redundant trailing zero is refused), so a blob
//! that parses must re-serialize to itself: two byte strings for one block
//! would give one block two hashes. The block's hash is taken on every
//! parse.
//!
//!   cargo +nightly fuzz run fuzz_block_parse corpus/fuzz_block_parse seeds/fuzz_block_parse

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_wire::Block;

fuzz_target!(|data: &[u8]| {
    let Ok(block) = Block::from_bytes(data) else {
        return;
    };
    assert_eq!(block.serialize(), data, "parse → serialize must be the identity");
    let _ = block.hash();
});
