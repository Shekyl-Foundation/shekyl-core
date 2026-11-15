// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `FinalTx` body decoder (step 8: the proposal, the signers' keys and the two proofs) never panics and never allocates past
//! its bounds, whatever bytes an envelope opened to; what it accepts it
//! accepts exactly, so re-encoding gives back the same bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shekyl_multisig::ceremony::files::{Body, FinalTx};

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = FinalTx::decode(data) {
        assert_eq!(body.encode(), data);
    }
});
