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
    /// Chaining key carried so rekey stays descended from the handshake.
    send_ck_seed: [u8; 32],
    recv_ck_seed: [u8; 32],
}

impl Channel {
    pub(crate) fn from_keys(keys: TransportKeys) -> Self {
        let send_ck = keys.send;
        let recv_ck = keys.recv;
        Self {
            send: Direction::new(send_ck, keys.send),
            recv: Direction::new(recv_ck, keys.recv),
            send_ck_seed: send_ck,
            recv_ck_seed: recv_ck,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        for chunk in plaintext.chunks(MAX_BODY.max(1)) {
            if plaintext.is_empty() {
                break;
            }
            self.seal_one(chunk, &mut out)?;
        }
        if plaintext.is_empty() {
            self.seal_one(&[], &mut out)?;
        }
        Ok(out)
    }

    fn seal_one(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RecordError> {
        if chunk.len() > MAX_BODY {
            return Err(RecordError::Oversize);
        }
        let len = (chunk.len() as u16).to_be_bytes();
        let len_ct = self.send.encrypt(&len, b"len")?;
        let body_ct = self.send.encrypt(chunk, b"body")?;
        out.extend_from_slice(&len_ct);
        out.extend_from_slice(&body_ct);
        Ok(())
    }

    /// Open one record from the front of `buf`. Returns plaintext and bytes consumed.
    pub fn open_one(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize), RecordError> {
        if buf.len() < LEN_WIRE {
            return Err(RecordError::Truncated);
        }
        let len_pt = self.recv.decrypt(&buf[..LEN_WIRE], b"len")?;
        if len_pt.len() != 2 {
            return Err(RecordError::Decrypt);
        }
        let body_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        let body_wire = body_len + 16;
        let total = LEN_WIRE + body_wire;
        if buf.len() < total {
            return Err(RecordError::Truncated);
        }
        let body = self.recv.decrypt(&buf[LEN_WIRE..total], b"body")?;
        if body.len() != body_len {
            return Err(RecordError::Decrypt);
        }
        Ok((body, total))
    }

    pub fn force_send_nonce(&mut self, n: u64) {
        self.send.force_nonce(n);
    }

    pub fn force_recv_nonce(&mut self, n: u64) {
        self.recv.force_nonce(n);
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.send_ck_seed.zeroize();
        self.recv_ck_seed.zeroize();
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
}
