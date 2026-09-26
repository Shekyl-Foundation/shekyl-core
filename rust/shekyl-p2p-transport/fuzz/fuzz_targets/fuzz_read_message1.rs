// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_p2p_transport::Responder;

fuzz_target!(|data: &[u8]| {
    match Responder::new(&[0u8; 16]).read_message1(data) {
        Ok(_) | Err(_) => {}
    }
});
