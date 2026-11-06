// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `ClassedOpener` on bytes from anyone (RT-W9 close-out, 2026-10-22).
//!
//! The opener reads the RPC channel's wire before anything about the peer
//! is known. On arbitrary bytes it must not panic, it must fail only as
//! `Truncated`, `Refused` or `Poisoned`, and once it has refused it refuses
//! for good: every later open is `Poisoned`, including of a genuine record.
//! Half the input is read as bare wire bytes, and half is sealed as a
//! genuine record and then cut and flipped where the input says.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_noise::{
    ClassId, ClassTable, ClassedError, ClassedOpener, ClassedSealer, SplitRole, SymmetricState,
};

fn table() -> ClassTable {
    ClassTable::new(&[512, 16_384, 65_535]).expect("the channel's table")
}

fn session() -> (ClassedSealer, ClassedOpener) {
    let state = || {
        let mut s = SymmetricState::new(b"shekyl-noise fuzz", b"");
        s.mix_key(&[0x5a; 32]);
        s
    };
    let (send, _) = state().into_directions(SplitRole::Initiator);
    let (_, recv) = state().into_directions(SplitRole::Responder);
    (
        ClassedSealer::new(send, table()),
        ClassedOpener::new(recv, table()),
    )
}

/// Feed `wire` until it is used up or the opener stops, checking each
/// answer. Returns whether the opener refused.
fn drive(opener: &mut ClassedOpener, mut wire: &[u8]) -> bool {
    loop {
        match opener.open(wire) {
            Ok(opened) => {
                assert!(opened.consumed > 0 && opened.consumed <= wire.len());
                wire = &wire[opened.consumed..];
                if wire.is_empty() {
                    return false;
                }
            }
            Err(ClassedError::Truncated) => return false,
            Err(ClassedError::Refused | ClassedError::Poisoned) => return true,
            Err(other) => panic!("an opener failed as {other:?}"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (cut, rest) = data.split_at(data.len() / 2);

    // Bare bytes as wire.
    let (mut sealer, mut opener) = session();
    if drive(&mut opener, cut) {
        let genuine = sealer.seal(ClassId(0), b"after").expect("seal");
        assert_eq!(opener.open(&genuine), Err(ClassedError::Poisoned));
    }

    // A genuine record of the input, cut and flipped where the input says.
    let (mut sealer, mut opener) = session();
    let class = ClassId(rest.first().copied().unwrap_or(0) % 3);
    let payload = &rest[..rest.len().min(table().max_payload(class).unwrap_or(0))];
    let Ok(mut wire) = sealer.seal(class, payload) else {
        return;
    };
    if let [a, b, ..] = rest {
        let at = usize::from(*a) * 256 + usize::from(*b);
        let at = at % wire.len();
        wire[at] ^= rest.get(2).copied().unwrap_or(1) | 1;
    }
    let len = rest.get(3).map_or(wire.len(), |n| usize::from(*n) * wire.len() / 255);
    let refused = drive(&mut opener, &wire[..len.min(wire.len())]);
    if refused {
        let genuine = sealer.seal(ClassId(0), b"after").expect("seal");
        assert_eq!(opener.open(&genuine), Err(ClassedError::Poisoned));
        let mut again = ClassedOpener::new(opener.into_direction(), table());
        assert_eq!(again.open(&genuine), Err(ClassedError::Poisoned));
    }
});
