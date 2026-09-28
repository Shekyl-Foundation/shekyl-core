// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The record layer behind one seam.
//!
//! The session hands this module plaintext. A plain channel writes those
//! bytes. A Noise channel seals them. The socket writer does not match on
//! which one it was given: it writes what [`SeamSend::encode`] returns.
//! The reader does the inverse through [`SeamRecv::push`].

use shekyl_p2p_transport::{RecordError, RecvHalf, SendHalf};

/// What the declaration's plan, and the option-off exception, selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelChoice {
    /// Socket bytes are the session bytes.
    Plain,
    /// [`SendHalf`] / [`RecvHalf`] sit under the session.
    Noise,
}

pub enum SeamSend {
    Plain,
    Noise(SendHalf),
}

pub enum SeamRecv {
    Plain,
    Noise { recv: RecvHalf, pending: Vec<u8> },
}

impl SeamSend {
    pub fn encode(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        match self {
            Self::Plain => Ok(plaintext.to_vec()),
            Self::Noise(send) => send.seal(plaintext),
        }
    }
}

impl SeamRecv {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, RecordError> {
        match self {
            Self::Plain => Ok(vec![bytes.to_vec()]),
            Self::Noise { recv, pending } => {
                pending.extend_from_slice(bytes);
                let mut out = Vec::new();
                loop {
                    match recv.open_one(pending) {
                        Ok((plain, used)) => {
                            pending.drain(..used);
                            if !plain.is_empty() {
                                out.push(plain);
                            }
                        }
                        Err(RecordError::Truncated) => return Ok(out),
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}
