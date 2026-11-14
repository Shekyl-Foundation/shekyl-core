// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `HybridSig` body decoder (step 9: a cosigner's hybrid signature per input) never panics and never allocates past
//! its bounds, whatever bytes an envelope opened to; what it accepts it
//! accepts exactly, so re-encoding gives back the same bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shekyl_multisig::ceremony::files::{Body, HybridSig};

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = HybridSig::decode(data) {
        assert_eq!(body.encode(), data);
    }
});
