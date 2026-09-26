// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Private entry points for the C5 bench. The numbers are a run record.
//! They are not a budget.

use crate::aead::{self, HASH_LEN};
use crate::channel::{RecvHalf, SendHalf};
use crate::noise::{Initiator, Responder};
use crate::prefix::NetworkId;

const NID: NetworkId = [0x11; 16];

pub struct OpenInit {
    inner: Initiator,
}

impl OpenInit {
    pub fn message1() -> (Self, Vec<u8>) {
        let (inner, message1) = Initiator::new(&NID).expect("initiator keygen");
        (Self { inner }, message1)
    }

    pub fn finish(self, message2: &[u8]) {
        let established = self.inner.read_message2(message2).expect("message 2");
        std::hint::black_box(established);
    }
}

pub fn responder_message2(message1: &[u8]) -> Vec<u8> {
    let ready = Responder::new(&NID)
        .read_message1(message1)
        .expect("message 1");
    let (established, message2) = ready.write_message2().expect("message 2");
    std::hint::black_box(established);
    message2
}

pub struct Session {
    send: SendHalf,
    recv: RecvHalf,
}

impl Session {
    pub fn connected() -> Self {
        let (init, message1) = Initiator::new(&NID).expect("initiator");
        let ready = Responder::new(&NID)
            .read_message1(&message1)
            .expect("message 1");
        let (responder, message2) = ready.write_message2().expect("message 2");
        let initiator = init.read_message2(&message2).expect("message 2");
        let (send, _init_recv) = initiator.split();
        let (_resp_send, recv) = responder.split();
        Self { send, recv }
    }

    pub fn seal_open(&mut self, plaintext: &[u8]) -> usize {
        let wire = self.send.seal(plaintext).expect("seal");
        let (opened, consumed) = self.recv.open_one(&wire).expect("open");
        debug_assert_eq!(opened.len(), plaintext.len());
        consumed
    }
}

/// One Noise HKDF: three HMAC-BLAKE2s. This is the rekey step.
pub fn rekey_once() {
    let ck = [1u8; HASH_LEN];
    let key = [2u8; HASH_LEN];
    let derived = aead::hkdf(&ck, &key);
    std::hint::black_box(derived);
}
