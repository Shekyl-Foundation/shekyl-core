// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_p2p_transport::Initiator;

fuzz_target!(|data: &[u8]| {
    let Ok((initiator, _)) = Initiator::new(&[0u8; 16]) else {
        return;
    };
    match initiator.read_message2(data) {
        Ok(_) | Err(_) => {}
    }
});
