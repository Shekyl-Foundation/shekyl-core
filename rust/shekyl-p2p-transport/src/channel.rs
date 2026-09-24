// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Post-`Split` records. Each record is an encrypted 2-byte length and an
//! encrypted body, two nonces. A plaintext longer than [`MAX_BODY`] bytes is
//! several records; the concatenation is the session byte stream.
//!
//! Rekey is `HKDF(ck, k)` after [`REKEY_NONCES`] nonce uses in that direction.
//! The nonce resets. Nothing is written to mark it. An empty body is rejected:
//! a session write of no bytes is not a record.

use zeroize::Zeroizing;

use crate::aead::{self, TAG_LEN};

pub(crate) const REKEY_NONCES: u64 = 1_000;
const MAX_BODY: usize = u16::MAX as usize;
const LENGTH_WIRE: usize = 2 + TAG_LEN;
const LENGTH_AAD: &[u8] = b"len";
const BODY_AAD: &[u8] = b"body";

#[derive(Debug)]
pub(crate) enum RecordError {
    Decrypt,
    Empty,
    Oversize,
    Truncated,
    State,
}

pub(crate) struct Direction {
    ck: Zeroizing<[u8; 32]>,
    k: Zeroizing<[u8; 32]>,
    n: u64,
}

impl Direction {
    fn new(ck: Zeroizing<[u8; 32]>, k: Zeroizing<[u8; 32]>) -> Self {
        Self { ck, k, n: 0 }
    }

    #[cfg(test)]
    fn force_nonce(&mut self, n: u64) {
        self.n = n;
    }

    #[cfg(test)]
    pub(crate) fn ck_and_k(&self) -> ([u8; 32], [u8; 32]) {
        (*self.ck, *self.k)
    }

    fn bump(&mut self) -> Result<(), RecordError> {
        self.n = self.n.checked_add(1).ok_or(RecordError::State)?;
        if self.n == REKEY_NONCES {
            let (ck, k) = aead::hkdf(&self.ck, &self.k[..]);
            self.ck = ck;
            self.k = k;
            self.n = 0;
        }
        Ok(())
    }

    fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RecordError> {
        let ct = aead::seal(&self.k, self.n, ad, plaintext).ok_or(RecordError::State)?;
        self.bump()?;
        Ok(ct)
    }

    fn decrypt(&mut self, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RecordError> {
        let pt = aead::open(&self.k, self.n, ad, ciphertext).ok_or(RecordError::Decrypt)?;
        self.bump()?;
        Ok(pt)
    }
}

pub(crate) struct SendHalf {
    dir: Direction,
}

pub(crate) struct RecvHalf {
    dir: Direction,
    /// Length already decrypted. Its nonce is spent; the body nonce is not,
    /// until those bytes arrive or the half is poisoned.
    pending_body: Option<usize>,
    dead: bool,
}

pub(crate) fn halves(
    ck: Zeroizing<[u8; 32]>,
    send_k: Zeroizing<[u8; 32]>,
    recv_k: Zeroizing<[u8; 32]>,
) -> (SendHalf, RecvHalf) {
    let recv_ck = Zeroizing::new(*ck);
    (
        SendHalf {
            dir: Direction::new(ck, send_k),
        },
        RecvHalf {
            dir: Direction::new(recv_ck, recv_k),
            pending_body: None,
            dead: false,
        },
    )
}

impl SendHalf {
    #[cfg(test)]
    fn seal_empty_body(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let len_ct = self.dir.encrypt(&0u16.to_be_bytes(), LENGTH_AAD).unwrap();
        let body_ct = self.dir.encrypt(&[], BODY_AAD).unwrap();
        out.extend_from_slice(&len_ct);
        out.extend_from_slice(&body_ct);
        out
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for chunk in plaintext.chunks(MAX_BODY) {
            seal_chunk(&mut self.dir, chunk, &mut out)?;
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn force_nonce(&mut self, n: u64) {
        self.dir.force_nonce(n);
    }

    #[cfg(test)]
    pub(crate) fn ck_and_k(&self) -> ([u8; 32], [u8; 32]) {
        self.dir.ck_and_k()
    }
}

impl RecvHalf {
    /// Open one record from the front of `buf`.
    ///
    /// [`RecordError::Truncated`] keeps the half usable: a short read has not
    /// spent the body nonce. Any other error poisons the half.
    pub(crate) fn open_one(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize), RecordError> {
        if self.dead {
            return Err(RecordError::State);
        }
        match open_record(&mut self.dir, &mut self.pending_body, buf) {
            Err(RecordError::Truncated) => Err(RecordError::Truncated),
            Err(e) => {
                self.dead = true;
                Err(e)
            }
            ok => ok,
        }
    }

    #[cfg(test)]
    pub(crate) fn force_nonce(&mut self, n: u64) {
        self.dir.force_nonce(n);
    }

    #[cfg(test)]
    pub(crate) fn ck_and_k(&self) -> ([u8; 32], [u8; 32]) {
        self.dir.ck_and_k()
    }
}

fn seal_chunk(send: &mut Direction, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RecordError> {
    if chunk.is_empty() || chunk.len() > MAX_BODY {
        return Err(RecordError::Oversize);
    }
    let len = (chunk.len() as u16).to_be_bytes();
    let len_ct = send.encrypt(&len, LENGTH_AAD)?;
    let body_ct = send.encrypt(chunk, BODY_AAD)?;
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&body_ct);
    Ok(())
}

fn open_record(
    recv: &mut Direction,
    pending_body: &mut Option<usize>,
    buf: &[u8],
) -> Result<(Vec<u8>, usize), RecordError> {
    let body_len = if let Some(len) = *pending_body {
        len
    } else {
        if buf.len() < LENGTH_WIRE {
            return Err(RecordError::Truncated);
        }
        let len_pt = recv.decrypt(&buf[..LENGTH_WIRE], LENGTH_AAD)?;
        if len_pt.len() != 2 {
            return Err(RecordError::Decrypt);
        }
        let body_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        *pending_body = Some(body_len);
        body_len
    };
    let total = LENGTH_WIRE + body_len + TAG_LEN;
    if buf.len() < total {
        return Err(RecordError::Truncated);
    }
    let body = recv.decrypt(&buf[LENGTH_WIRE..total], BODY_AAD)?;
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

    fn pair() -> (SendHalf, RecvHalf, SendHalf, RecvHalf) {
        let nid = [9u8; 16];
        let (ini, m1) = Initiator::new(&nid).unwrap();
        let ready = Responder::new(&nid).read_message1(&m1).unwrap();
        let (resp, m2) = ready.write_message2().unwrap();
        let est = ini.read_message2(&m2).unwrap();
        let (a_send, a_recv) = est.split();
        let (b_send, b_recv) = resp.split();
        (a_send, a_recv, b_send, b_recv)
    }

    #[test]
    fn roundtrip_and_rekey_boundary() {
        let (mut a_send, _a_recv, _b_send, mut b_recv) = pair();
        let (send_ck, send_k) = a_send.ck_and_k();
        let (recv_ck, recv_k) = b_recv.ck_and_k();
        assert_eq!(send_ck, recv_ck);
        assert_ne!(send_ck, send_k);
        assert_ne!(recv_ck, recv_k);

        let ct = a_send.seal(b"levin").unwrap();
        let (pt, n) = b_recv.open_one(&ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(pt, b"levin");

        a_send.force_nonce(REKEY_NONCES - 1);
        b_recv.force_nonce(REKEY_NONCES - 1);
        let ct = a_send.seal(b"boundary").unwrap();
        assert_eq!(b_recv.open_one(&ct).unwrap().0, b"boundary");
        let ct = a_send.seal(b"after").unwrap();
        assert_eq!(b_recv.open_one(&ct).unwrap().0, b"after");
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
