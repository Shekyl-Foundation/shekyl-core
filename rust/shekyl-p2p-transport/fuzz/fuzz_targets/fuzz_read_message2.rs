// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_p2p_transport::{Initiator, Responder};

fuzz_target!(|data: &[u8]| {
    let network = [0u8; 16];
    // The responder's real message 2: decapsulation and the final tag.
    if let Some((initiator, message2)) = message2(&network) {
        let _ = initiator.read_message2(&message2);
    }
    let Some((initiator, mut message2)) = message2(&network) else {
        return;
    };
    mutate(&mut message2, data);
    let _ = initiator.read_message2(&message2);
});

fn message2(network: &[u8; 16]) -> Option<(Initiator, Vec<u8>)> {
    let (initiator, message1) = Initiator::new(network).ok()?;
    let ready = Responder::new(network).read_message1(&message1).ok()?;
    let (_responder, message2) = ready.write_message2().ok()?;
    Some((initiator, message2))
}

fn mutate(message2: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() || message2.is_empty() {
        message2.clear();
        return;
    }
    match data[0] % 4 {
        0 => {
            message2.clear();
            message2.extend_from_slice(data);
        }
        1 => {
            let n = data.get(1).copied().unwrap_or(0) as usize;
            message2.truncate(n % (message2.len() + 1));
        }
        2 => {
            let i = data.get(1).copied().unwrap_or(0) as usize % message2.len();
            let bit = data.get(2).copied().unwrap_or(1);
            message2[i] ^= bit;
        }
        _ => message2.extend_from_slice(data),
    }
}
