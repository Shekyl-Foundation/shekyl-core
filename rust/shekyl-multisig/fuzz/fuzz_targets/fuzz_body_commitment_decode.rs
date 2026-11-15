// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `Commitment` body decoder (step 2: a holder's first round per input) never panics and never allocates past
//! its bounds, whatever bytes an envelope opened to; what it accepts it
//! accepts exactly, so re-encoding gives back the same bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shekyl_multisig::ceremony::files::{Body, Commitment};

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = Commitment::decode(data) {
        assert_eq!(body.encode(), data);
    }
});
