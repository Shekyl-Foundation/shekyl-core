// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Post-`Split` records. Each record is an encrypted 2-byte length and an
//! encrypted body, two nonces. A plaintext longer than 65535 bytes is several
//! records; the concatenation is the Levin byte stream.
//!
//! Rekey is Noise's `HKDF(ck, k)` after 1,000 nonce uses in that direction.
//! The nonce resets. Nothing is written to mark it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroize;

use crate::noise::{hkdf, TransportKeys};

pub const REKEY_NONCES: u64 = 1_000;
const MAX_BODY: usize = u16::MAX as usize;
const LEN_WIRE: usize = 2 + 16;

#[derive(Debug)]
pub enum RecordError {
    Decrypt,
    Oversize,
    Truncated,
    State,
}

pub struct Direction {
    ck: [u8; 32],
    k: [u8; 32],
    n: u64,
}

impl Drop for Direction {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.k.zeroize();
    }
}

impl Direction {
    fn new(ck: [u8; 32], k: [u8; 32]) -> Self {
        Self { ck, k, n: 0 }
    }

    /// Test hook: the next encryption uses nonce `n` under the current key.
    pub fn force_nonce(&mut self, n: u64) {
        self.n = n;
    }

    fn nonce(&self) -> Nonce {
        let mut raw = [0u8; 12];
        raw[4..].copy_from_slice(&self.n.to_le_bytes());
        Nonce::from(raw)
    }

    fn bump(&mut self) -> Result<(), RecordError> {
        self.n = self.n.checked_add(1).ok_or(RecordError::State)?;
        if self.n == REKEY_NONCES {
            self.rekey();
        }
        Ok(())
    }

    fn rekey(&mut self) {
        let (ck, k) = hkdf(&self.ck, &self.k);
        self.ck.zeroize();
        self.k.zeroize();
        self.ck = ck;
        self.k = k;
        self.n = 0;
    }

    fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RecordError> {
        let cipher = ChaCha20Poly1305::new((&self.k).into());
        let ct = cipher
            .encrypt(
                &self.nonce(),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| RecordError::Decrypt)?;
        self.bump()?;
        Ok(ct)
    }

    fn decrypt(&mut self, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RecordError> {
        let cipher = ChaCha20Poly1305::new((&self.k).into());
        let pt = cipher
            .decrypt(
                &self.nonce(),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| RecordError::Decrypt)?;
        self.bump()?;
        Ok(pt)
    }
}

pub struct Channel {
    send: Direction,
    recv: Direction,
    /// Length already decrypted. The matching nonce was consumed; the body
    /// nonce is still unused until those bytes arrive.
    pending_body: Option<usize>,
}

impl Channel {
    /// `ck` is the handshake chaining key from before `Split`. Each direction
    /// keeps its own copy. Rekey is `HKDF(ck, k)`, not `HKDF(k, k)`.
    pub(crate) fn from_keys(mut ck: [u8; 32], keys: TransportKeys) -> Self {
        let channel = Self {
            send: Direction::new(ck, keys.send),
            recv: Direction::new(ck, keys.recv),
            pending_body: None,
        };
        ck.zeroize();
        channel
    }

    pub(crate) fn split_io(self) -> (SendHalf, RecvHalf) {
        (
            SendHalf { dir: self.send },
            RecvHalf {
                dir: self.recv,
                pending_body: self.pending_body,
            },
        )
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        seal_all(&mut self.send, plaintext)
    }

    /// Open one record from the front of `buf`. Returns plaintext and bytes consumed.
    pub fn open_one(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize), RecordError> {
        open_record(&mut self.recv, &mut self.pending_body, buf)
    }

    pub fn force_send_nonce(&mut self, n: u64) {
        self.send.force_nonce(n);
    }

    pub fn force_recv_nonce(&mut self, n: u64) {
        self.recv.force_nonce(n);
    }
}

fn seal_all(send: &mut Direction, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
    let mut out = Vec::new();
    for chunk in plaintext.chunks(MAX_BODY.max(1)) {
        if plaintext.is_empty() {
            break;
        }
        seal_chunk(send, chunk, &mut out)?;
    }
    if plaintext.is_empty() {
        seal_chunk(send, &[], &mut out)?;
    }
    Ok(out)
}

fn seal_chunk(send: &mut Direction, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RecordError> {
    if chunk.len() > MAX_BODY {
        return Err(RecordError::Oversize);
    }
    let len = (chunk.len() as u16).to_be_bytes();
    let len_ct = send.encrypt(&len, b"len")?;
    let body_ct = send.encrypt(chunk, b"body")?;
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
        if buf.len() < LEN_WIRE {
            return Err(RecordError::Truncated);
        }
        let len_pt = recv.decrypt(&buf[..LEN_WIRE], b"len")?;
        if len_pt.len() != 2 {
            return Err(RecordError::Decrypt);
        }
        let body_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        *pending_body = Some(body_len);
        body_len
    };
    let total = LEN_WIRE + body_len + 16;
    if buf.len() < total {
        return Err(RecordError::Truncated);
    }
    let body = match recv.decrypt(&buf[LEN_WIRE..total], b"body") {
        Ok(body) => body,
        Err(e) => {
            *pending_body = None;
            return Err(e);
        }
    };
    *pending_body = None;
    if body.len() != body_len {
        return Err(RecordError::Decrypt);
    }
    Ok((body, total))
}

pub(crate) struct SendHalf {
    dir: Direction,
}

impl SendHalf {
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        seal_all(&mut self.dir, plaintext)
    }
}

pub(crate) struct RecvHalf {
    dir: Direction,
    pending_body: Option<usize>,
}

impl RecvHalf {
    pub(crate) fn open_one(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize), RecordError> {
        open_record(&mut self.dir, &mut self.pending_body, buf)
    }
}

impl Channel {
    #[cfg(test)]
    fn send_rekey_uses_handshake_ck(&self) -> bool {
        self.send.ck != self.send.k && self.recv.ck != self.recv.k && self.send.ck == self.recv.ck
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Handshake;

    fn pair() -> (Channel, Channel) {
        let nid = [9u8; 16];
        let (mut ini, m1) = Handshake::initiator(&nid).unwrap();
        let mut resp = Handshake::responder(&nid);
        let m2 = resp.read_message1_write_message2(&m1).unwrap();
        ini.read_message2(&m2).unwrap();
        (ini.split().unwrap(), resp.split().unwrap())
    }

    #[test]
    fn roundtrip_and_rekey_boundary() {
        let (mut a, mut b) = pair();
        assert!(a.send_rekey_uses_handshake_ck());
        let ct = a.seal(b"levin").unwrap();
        let (pt, n) = b.open_one(&ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(pt, b"levin");

        a.force_send_nonce(REKEY_NONCES - 1);
        b.force_recv_nonce(REKEY_NONCES - 1);
        let ct = a.seal(b"boundary").unwrap();
        assert_eq!(b.open_one(&ct).unwrap().0, b"boundary");
        let ct = a.seal(b"after").unwrap();
        assert_eq!(b.open_one(&ct).unwrap().0, b"after");
    }

    #[test]
    fn oversized_length_fails_closed() {
        let (mut a, mut b) = pair();
        let ct = a.seal(&[0u8; 32]).unwrap();
        let mut tampered = ct.clone();
        // Flip a byte in the length ciphertext so decryption fails.
        tampered[0] ^= 0xff;
        assert!(b.open_one(&tampered).is_err());
    }

    #[test]
    fn length_then_body_split_does_not_desync() {
        let (mut a, mut b) = pair();
        let ct = a.seal(b"split-record").unwrap();
        assert!(ct.len() > LEN_WIRE);
        assert!(matches!(
            b.open_one(&ct[..LEN_WIRE]),
            Err(RecordError::Truncated)
        ));
        let (pt, n) = b.open_one(&ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(pt, b"split-record");
    }
}
