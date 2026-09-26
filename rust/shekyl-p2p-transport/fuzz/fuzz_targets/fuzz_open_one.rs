// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_p2p_transport::{Initiator, Responder};

fuzz_target!(|data: &[u8]| {
    let network = [0u8; 16];
    let Ok((initiator, message1)) = Initiator::new(&network) else {
        return;
    };
    let Ok(ready) = Responder::new(&network).read_message1(&message1) else {
        return;
    };
    let Ok((established, message2)) = ready.write_message2() else {
        return;
    };
    if initiator.read_message2(&message2).is_err() {
        return;
    }
    let (_send, mut recv) = established.split();
    match recv.open_one(data) {
        Ok(_) | Err(_) => {}
    }
});
