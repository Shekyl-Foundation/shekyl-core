// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `BucketReader` on fragment trains from anyone (PWD-B12).
//!
//! The reader takes a peer's bytes before anything about the peer is
//! known. This target frames buckets from the input, so the fuzzer spends
//! its time past the signature check: fragments (first, middle, last),
//! fragments that open with an inner header the input describes, dummies,
//! and ordinary buckets. Each bucket is fed in pieces of a size the input
//! picks, so a header or a body can arrive split anywhere.
//!
//! What it holds, after every bucket the reader took without an error:
//!
//! - the reader does not panic, and after its first error every call
//!   answers `Poisoned`;
//! - a delivered message names a command this protocol defines and its
//!   payload is within that command's cap, whether it came as one bucket
//!   or out of a train;
//! - a train whose first 29 bytes are in has an inner header the reader
//!   was right to accept (a request or a response, a defined command, a
//!   length within the command's cap and the packet limit), and the
//!   reassembly buffer holds fewer bytes than that inner message while
//!   the train is unfinished.
//!
//! The train's own bytes are tracked here beside the reader, from the
//! buckets this target framed. That is a second derivation of the bound,
//! not a copy of the reader's state: the reader's buffer is read only
//! through `buffered_bytes`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_levin::{
    ingress_payload_cap, noise_notify, BucketHead, BucketReader, Command, Error, Flags, Received,
    DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE,
};

/// The input, read front to back. A read past the end answers zero, so
/// every input is a whole script.
struct Script<'a> {
    rest: &'a [u8],
}

impl<'a> Script<'a> {
    fn byte(&mut self) -> u8 {
        match self.rest.split_first() {
            Some((first, rest)) => {
                self.rest = rest;
                *first
            }
            None => 0,
        }
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    /// Up to `len` bytes, fewer when the input ends.
    fn take(&mut self, len: usize) -> &'a [u8] {
        let (taken, rest) = self.rest.split_at(len.min(self.rest.len()));
        self.rest = rest;
        taken
    }

    fn is_done(&self) -> bool {
        self.rest.is_empty()
    }
}

/// The largest fragment or bucket body this target frames. Small, so one
/// input holds many buckets and a train's bound is reached in a few of
/// them, and under the pre-handshake packet limit with room to spare.
const MAX_BODY: usize = 2048;

/// Middle fragments set neither train flag.
const MIDDLE: Flags = Flags::from_bits(0);

fn bucket(command: u32, flags: Flags, expect_response: bool, body: &[u8]) -> Vec<u8> {
    let len = u64::try_from(body.len()).expect("a small body");
    let mut out = BucketHead::make(command, len, flags, expect_response)
        .write()
        .to_vec();
    out.extend_from_slice(body);
    out
}

/// The train this target has framed since the last `BEGIN` or `END`:
/// its first bytes, up to one header, and how many it carried in all.
#[derive(Default)]
struct Train {
    opening: Vec<u8>,
    held: usize,
}

impl Train {
    fn absorb(&mut self, flags: Flags, body: &[u8]) {
        if flags.contains(Flags::BEGIN) {
            *self = Self::default();
        }
        let missing = HEADER_SIZE - self.opening.len();
        self.opening
            .extend_from_slice(&body[..missing.min(body.len())]);
        self.held += body.len();
    }
}

/// Feed one bucket in pieces of `piece` bytes and pull everything it
/// completes. `Err` is the reader's first error.
fn feed(reader: &mut BucketReader, wire: &[u8], piece: usize) -> Result<Vec<Received>, Error> {
    let mut delivered = Vec::new();
    for part in wire.chunks(piece.max(1)) {
        reader.feed(part)?;
        while let Some(message) = reader.next_message()? {
            delivered.push(message);
        }
    }
    Ok(delivered)
}

fn check_delivered(message: &Received) {
    let (command, payload) = match message {
        Received::Notification { command, payload }
        | Received::Request { command, payload }
        | Received::Response { command, payload } => (*command, payload),
    };
    let defined = Command::from_wire(command)
        .unwrap_or_else(|| panic!("a message of undefined command {command} was delivered"));
    let len = u64::try_from(payload.len()).expect("a payload length");
    assert!(
        len <= defined.payload_cap(),
        "command {command} delivered {len} bytes over its cap {}",
        defined.payload_cap()
    );
}

/// What must be true of an unfinished train the reader has not refused.
fn check_unfinished(reader: &BucketReader, train: &Train, packet_limit: u64) {
    let held = u64::try_from(train.held).expect("a small train");
    assert_eq!(
        reader.buffered_bytes(),
        held,
        "whole buckets were fed, so what is buffered is the train"
    );
    let Ok(opening) = <&[u8; HEADER_SIZE]>::try_from(train.opening.as_slice()) else {
        // Less than a header so far: nothing to judge and nothing to bound
        // but the header's own size.
        assert!(train.held < HEADER_SIZE);
        return;
    };
    let inner = BucketHead::read(opening).expect("the reader took a train with a bad inner header");
    assert!(
        inner
            .flags
            .intersects(Flags::REQUEST.union(Flags::RESPONSE)),
        "the reader took a train whose inner message is not a request or response"
    );
    let cap = ingress_payload_cap(inner.command, inner.flags)
        .expect("the reader took a train whose inner header ingress refuses");
    assert!(
        inner.payload_len <= cap.min(packet_limit),
        "the reader took an inner length {} over its limit",
        inner.payload_len
    );
    let inner_len = u64::try_from(HEADER_SIZE).expect("29") + inner.payload_len;
    assert!(
        held < inner_len,
        "an unfinished train holds {held} bytes of a {inner_len}-byte inner message"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut script = Script { rest: data };
    let mut reader = BucketReader::new();
    let mut packet_limit = INITIAL_MAX_PACKET_SIZE;
    if script.byte() & 1 == 1 {
        reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
        packet_limit = DEFAULT_MAX_PACKET_SIZE;
    }
    let mut train = Train::default();

    while !script.is_done() {
        let op = script.byte();
        let piece = usize::from(script.byte()) + 1;
        let train_flags = match script.byte() % 3 {
            0 => Flags::BEGIN,
            1 => MIDDLE,
            _ => Flags::END,
        };
        // The fragment this step feeds, if it feeds one.
        let mut fragment: Option<(Flags, Vec<u8>)> = None;
        let wire = match op % 4 {
            // A fragment of input bytes.
            0 => {
                let len = usize::from(script.byte()) * 8;
                let body = script.take(len.min(MAX_BODY)).to_vec();
                fragment = Some((train_flags, body));
                None
            }
            // A fragment that opens with an inner header the input
            // describes: any command, any flag byte, any length.
            1 => {
                let command = match script.byte() {
                    selector @ 0..=12 => Command::ALL[usize::from(selector)].wire_id(),
                    _ => script.u32(),
                };
                let flags = Flags::from_bits(u32::from(script.byte()));
                let claimed = match script.byte() {
                    // Small lengths, where a train reaches its bound.
                    small @ 0..=199 => u64::from(small) * 16,
                    _ => u64::from(script.u32()),
                };
                let expect_response = script.byte() & 1 == 1;
                let mut body = BucketHead::make(command, claimed, flags, expect_response)
                    .write()
                    .to_vec();
                let len = usize::from(script.byte()) * 8;
                body.extend_from_slice(script.take(len.min(MAX_BODY)));
                fragment = Some((train_flags, body));
                None
            }
            // A dummy: discarded, and no part of any train.
            2 => {
                let size = HEADER_SIZE + usize::from(script.byte()) * 8;
                Some(noise_notify(size).expect("at least a header"))
            }
            // An ordinary bucket, between a train's fragments or alone.
            _ => {
                let command = Command::ALL[usize::from(script.byte()) % Command::ALL.len()];
                let flags = if script.byte() & 1 == 1 {
                    Flags::RESPONSE
                } else {
                    Flags::REQUEST
                };
                let len = usize::from(script.byte()) * 8;
                let body = script.take(len.min(MAX_BODY));
                Some(bucket(command.wire_id(), flags, false, body))
            }
        };
        let wire = match (&fragment, wire) {
            (Some((flags, body)), _) => bucket(0, *flags, false, body),
            (None, Some(wire)) => wire,
            (None, None) => unreachable!("every step frames a bucket"),
        };

        match feed(&mut reader, &wire, piece) {
            Ok(delivered) => {
                for message in &delivered {
                    check_delivered(message);
                }
                if let Some((flags, body)) = &fragment {
                    train.absorb(*flags, body);
                    if flags.contains(Flags::END) {
                        // The train ended and the reader took it: it was
                        // delivered, and nothing of it is left behind.
                        assert_eq!(delivered.len(), 1, "a finished train is one message");
                        assert_eq!(reader.buffered_bytes(), 0);
                        train = Train::default();
                    }
                }
                check_unfinished(&reader, &train, packet_limit);
            }
            Err(_) => {
                // Every framing error is fatal and latches.
                assert_eq!(reader.next_message(), Err(Error::Poisoned));
                assert_eq!(reader.feed(&[0]), Err(Error::Poisoned));
                return;
            }
        }
    }
});
