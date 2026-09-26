// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_p2p_transport::{Initiator, RecvHalf, Responder, SendHalf};

fuzz_target!(|data: &[u8]| {
    // Bytes that were never a record: truncation and the first tag failure.
    if let Some((_send, mut recv)) = halves() {
        let _ = recv.open_one(data);
    }
    let Some((mut send, mut recv)) = halves() else {
        return;
    };
    let Ok(frame) = send.seal(data) else {
        return;
    };
    if frame.is_empty() {
        return;
    }
    // Shorter than the length field, so the half stays usable.
    let _ = recv.open_one(&frame[..1]);
    let _ = recv.open_one(&frame);
    let Ok(mut bad) = send.seal(data) else {
        return;
    };
    let i = data.first().copied().unwrap_or(0) as usize % bad.len();
    bad[i] ^= 0xff;
    let _ = recv.open_one(&bad);
});

fn halves() -> Option<(SendHalf, RecvHalf)> {
    let network = [0u8; 16];
    let (initiator, message1) = Initiator::new(&network).ok()?;
    let ready = Responder::new(&network).read_message1(&message1).ok()?;
    let (responder, message2) = ready.write_message2().ok()?;
    let initiator = initiator.read_message2(&message2).ok()?;
    let (send, _recv) = initiator.split();
    let (_send, recv) = responder.split();
    Some((send, recv))
}
