// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The interim record framer. Each record is an encrypted 2-byte length and
//! an encrypted body, two nonces of a [`SendDirection`] or a
//! [`RecvDirection`]. A plaintext longer than
//! [`MAX_BODY`] bytes is several records; the concatenation is the session
//! byte stream.
//!
//! An empty body is rejected: a session write of no bytes is not a record.
//! This framer is the length-prefixed wire the clearnet seam speaks today.
//! It is not the channel's classed records.

use shekyl_noise::{DirectionError, RecvDirection, SendDirection, TAG_LEN};

const MAX_BODY: usize = u16::MAX as usize; // `usize::from` is not const here (E0658).
const LENGTH_WIRE: usize = 2 + TAG_LEN;
const LENGTH_AAD: &[u8] = b"len";
const BODY_AAD: &[u8] = b"body";

#[derive(Debug)]
pub enum RecordError {
    Decrypt,
    Empty,
    Oversize,
    Truncated,
    State,
}

impl From<DirectionError> for RecordError {
    fn from(err: DirectionError) -> Self {
        match err {
            DirectionError::Decrypt => Self::Decrypt,
            // The direction is dead. A later open is `Poisoned`, and that
            // is this half's state: it keeps no death of its own.
            DirectionError::State | DirectionError::Poisoned => Self::State,
        }
    }
}

pub struct SendHalf {
    dir: SendDirection,
}

pub struct RecvHalf {
    dir: RecvDirection,
    /// Length already decrypted. Its nonce is spent; the body nonce is not,
    /// until those bytes arrive or the direction is poisoned.
    pending_body: Option<usize>,
}

/// The two halves of one session. `send` seals what this side sends; `recv`
/// opens what it receives. Each direction already holds its own chaining key.
pub(crate) fn session(send: SendDirection, recv: RecvDirection) -> (SendHalf, RecvHalf) {
    (
        SendHalf { dir: send },
        RecvHalf {
            dir: recv,
            pending_body: None,
        },
    )
}

impl SendHalf {
    #[cfg(test)]
    fn seal_empty_body(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let (len_ct, _) = self.dir.seal(&0u16.to_be_bytes(), LENGTH_AAD).unwrap();
        let (body_ct, _) = self.dir.seal(&[], BODY_AAD).unwrap();
        out.extend_from_slice(&len_ct);
        out.extend_from_slice(&body_ct);
        out
    }

    /// Seal `plaintext` as records. An empty slice is not a record.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for chunk in plaintext.chunks(MAX_BODY) {
            seal_chunk(&mut self.dir, chunk, &mut out)?;
        }
        Ok(out)
    }
}

impl RecvHalf {
    /// Open one record from the front of `buf`.
    ///
    /// [`RecordError::Truncated`] keeps the direction usable: a short read
    /// has not spent the body nonce. Any other error poisons the direction,
    /// and every later open is [`RecordError::State`], a short read included.
    pub fn open_one(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize), RecordError> {
        if self.dir.is_dead() {
            return Err(RecordError::State);
        }
        match open_record(&mut self.dir, &mut self.pending_body, buf) {
            Err(RecordError::Truncated) => Err(RecordError::Truncated),
            Err(e) => {
                self.dir.poison();
                Err(e)
            }
            ok => ok,
        }
    }
}

fn seal_chunk(
    send: &mut SendDirection,
    chunk: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), RecordError> {
    if chunk.is_empty() || chunk.len() > MAX_BODY {
        return Err(RecordError::Oversize);
    }
    let body_len = u16::try_from(chunk.len()).map_err(|_| RecordError::Oversize)?;
    let len_bytes = body_len.to_be_bytes();
    let (len_ct, _) = send.seal(&len_bytes, LENGTH_AAD)?;
    let (body_ct, _) = send.seal(chunk, BODY_AAD)?;
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&body_ct);
    Ok(())
}

fn open_record(
    recv: &mut RecvDirection,
    pending_body: &mut Option<usize>,
    buf: &[u8],
) -> Result<(Vec<u8>, usize), RecordError> {
    let body_len = if let Some(len) = *pending_body {
        len
    } else {
        if buf.len() < LENGTH_WIRE {
            return Err(RecordError::Truncated);
        }
        let (len_pt, _) = recv.open(&buf[..LENGTH_WIRE], LENGTH_AAD)?;
        if len_pt.len() != 2 {
            return Err(RecordError::Decrypt);
        }
        let body_len = usize::from(u16::from_be_bytes([len_pt[0], len_pt[1]]));
        *pending_body = Some(body_len);
        body_len
    };
    let total = LENGTH_WIRE + body_len + TAG_LEN;
    if buf.len() < total {
        return Err(RecordError::Truncated);
    }
    let (body, _) = recv.open(&buf[LENGTH_WIRE..total], BODY_AAD)?;
    if body.len() != body_len {
        return Err(RecordError::Decrypt);
    }
    if body.is_empty() {
        return Err(RecordError::Empty);
    }
    *pending_body = None;
    Ok((body, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{Initiator, Responder};

    /// Two ends of one handshake. The framer sees directions, not keys.
    fn pair() -> (SendHalf, RecvHalf, SendHalf, RecvHalf) {
        let nid = [0x11u8; 16];
        let (ini, m1) = Initiator::new(&nid).unwrap();
        let (resp, m2) = Responder::new(&nid)
            .read_message1(&m1)
            .unwrap()
            .write_message2()
            .unwrap();
        let ini = ini.read_message2(&m2).unwrap();
        let (a_send, a_recv) = ini.split();
        let (b_send, b_recv) = resp.split();
        (a_send, a_recv, b_send, b_recv)
    }

    #[test]
    fn roundtrip() {
        let (mut a_send, _a_recv, _b_send, mut b_recv) = pair();
        let ct = a_send.seal(b"levin").unwrap();
        let (pt, n) = b_recv.open_one(&ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(pt, b"levin");
    }

    #[test]
    fn tamper_and_empty_poison_the_receiver() {
        let (mut a_send, _, _, mut b_recv) = pair();
        let ct = a_send.seal(b"body").unwrap();
        let mut tampered = ct.clone();
        tampered[0] ^= 0xff;
        assert!(b_recv.open_one(&tampered).is_err());
        assert!(matches!(b_recv.open_one(&ct), Err(RecordError::State)));

        let (mut a_send, _, _, mut b_recv) = pair();
        assert!(a_send.seal(&[]).unwrap().is_empty());
        let empty = a_send.seal_empty_body();
        assert!(matches!(b_recv.open_one(&empty), Err(RecordError::Empty)));
        assert!(matches!(b_recv.open_one(&empty), Err(RecordError::State)));
        assert!(
            matches!(b_recv.open_one(&[]), Err(RecordError::State)),
            "a short read after a refusal is not a retry"
        );
    }

    #[test]
    fn length_then_body_split_does_not_desync() {
        let (mut a_send, _, _, mut b_recv) = pair();
        let ct = a_send.seal(b"split-record").unwrap();
        assert!(ct.len() > LENGTH_WIRE);
        assert!(matches!(
            b_recv.open_one(&ct[..LENGTH_WIRE]),
            Err(RecordError::Truncated)
        ));
        let (pt, n) = b_recv.open_one(&ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(pt, b"split-record");
    }

    #[test]
    fn a_write_over_one_body_is_several_records() {
        let (mut a_send, _, _, mut b_recv) = pair();
        let plain = vec![7u8; MAX_BODY + 1];
        let ct = a_send.seal(&plain).unwrap();
        let (first, n) = b_recv.open_one(&ct).unwrap();
        assert_eq!(first.len(), MAX_BODY);
        let (second, _) = b_recv.open_one(&ct[n..]).unwrap();
        assert_eq!(second, &plain[MAX_BODY..]);
    }
}
