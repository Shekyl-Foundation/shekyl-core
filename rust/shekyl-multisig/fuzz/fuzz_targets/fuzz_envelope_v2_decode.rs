// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A ceremony file's plaintext parser (`envelope::parse_plaintext`, through
//! its hidden entry point) never panics and never allocates past its
//! bounds, whatever bytes a member's key opened to.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = shekyl_multisig::envelope::plaintext_parses(data);
});
