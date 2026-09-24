// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` (PWD-T1, PWD-T4).
//!
//! Message 1 has no key, so `e` and `e1` are hashed only. Message 2 mixes the
//! X25519 secret at `ee`, encrypts `ekem1` under that key, then mixes the
//! ML-KEM secret, then encrypts the empty payload under the hybrid key.
//! `Split` runs after that payload, so transport keys include both secrets.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::OsRng;
use shekyl_crypto_pq::kem::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::prefix::NetworkId;

pub const PROTOCOL_NAME: &[u8] = b"Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
pub const MESSAGE1_LEN: usize = 32 + ML_KEM_768_EK_LEN;
pub const MESSAGE2_LEN: usize = 32 + ML_KEM_768_CT_LEN + 16 + 16;

const HASH_LEN: usize = 32;
const TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum HandshakeError {
    Prefix,
    Decrypt,
    Kem,
    Length,
    State,
}

pub enum Role {
    Initiator,
    Responder,
}

struct Sym {
    ck: [u8; HASH_LEN],
    h: [u8; HASH_LEN],
    k: Option<[u8; HASH_LEN]>,
    n: u64,
}

impl Drop for Sym {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.h.zeroize();
        if let Some(k) = self.k.as_mut() {
            k.zeroize();
        }
    }
}

impl Sym {
    fn new(prologue: &[u8]) -> Self {
        let mut h = [0u8; HASH_LEN];
        if PROTOCOL_NAME.len() <= HASH_LEN {
            h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
        } else {
            h = hash(PROTOCOL_NAME);
        }
        let ck = h;
        let mut sym = Self {
            ck,
            h,
            k: None,
            n: 0,
        };
        sym.mix_hash(prologue);
        sym
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    fn chaining_key(&self) -> [u8; HASH_LEN] {
        self.ck
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.k.is_none() {
            self.mix_hash(plaintext);
            return Ok(plaintext.to_vec());
        }
        let ct = self.encrypt(plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.k.is_none() {
            self.mix_hash(ciphertext);
            return Ok(ciphertext.to_vec());
        }
        let pt = self.decrypt(ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let key = self.k.ok_or(HandshakeError::State)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ad = self.h;
        let ct = cipher
            .encrypt(
                &nonce(self.n),
                Payload {
                    msg: plaintext,
                    aad: &ad,
                },
            )
            .map_err(|_| HandshakeError::Decrypt)?;
        self.n = self.n.checked_add(1).ok_or(HandshakeError::State)?;
        Ok(ct)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let key = self.k.ok_or(HandshakeError::State)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ad = self.h;
        let pt = cipher
            .decrypt(
                &nonce(self.n),
                Payload {
                    msg: ciphertext,
                    aad: &ad,
                },
            )
            .map_err(|_| HandshakeError::Decrypt)?;
        self.n = self.n.checked_add(1).ok_or(HandshakeError::State)?;
        Ok(pt)
    }
}

fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn hkdf(ck: &[u8; HASH_LEN], ikm: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    let temp = hmac_blake2s(ck, ikm);
    let out1 = hmac_blake2s(&temp, &[0x01]);
    let mut second = out1.to_vec();
    second.push(0x02);
    let out2 = hmac_blake2s(&temp, &second);
    (out1, out2)
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = hash(key);
        k[..HASH_LEN].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn nonce(n: u64) -> Nonce {
    let mut raw = [0u8; 12];
    raw[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(raw)
}

pub struct TransportKeys {
    pub send: [u8; HASH_LEN],
    pub recv: [u8; HASH_LEN],
}

impl Drop for TransportKeys {
    fn drop(&mut self) {
        self.send.zeroize();
        self.recv.zeroize();
    }
}

/// Handshake in progress. Secrets are dropped at [`Handshake::split`].
pub struct Handshake {
    sym: Sym,
    role: Role,
    eph: Option<StaticSecret>,
    dk: Option<ml_kem_768::DecapsKey>,
    remote_e: Option<[u8; 32]>,
    remote_ek: Option<[u8; ML_KEM_768_EK_LEN]>,
    wrote_message1: bool,
}

impl Handshake {
    pub fn initiator(network_id: &NetworkId) -> Result<(Self, Vec<u8>), HandshakeError> {
        let eph = StaticSecret::random_from_rng(OsRng);
        let (ek, dk) =
            ml_kem_768::KG::try_keygen_with_rng(&mut OsRng).map_err(|_| HandshakeError::Kem)?;
        Self::initiator_with(network_id, eph, dk, ek.into_bytes())
    }

    pub fn initiator_with(
        network_id: &NetworkId,
        eph: StaticSecret,
        dk: ml_kem_768::DecapsKey,
        ek: [u8; ML_KEM_768_EK_LEN],
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let mut sym = Sym::new(network_id);
        let mut msg = Vec::with_capacity(MESSAGE1_LEN);
        let epub = PublicKey::from(&eph).to_bytes();
        msg.extend_from_slice(&epub);
        sym.mix_hash(&epub);
        msg.extend_from_slice(&ek);
        sym.mix_hash(&ek);
        let payload = sym.encrypt_and_hash(&[])?;
        if !payload.is_empty() {
            return Err(HandshakeError::State);
        }
        if msg.len() != MESSAGE1_LEN {
            return Err(HandshakeError::Length);
        }
        Ok((
            Self {
                sym,
                role: Role::Initiator,
                eph: Some(eph),
                dk: Some(dk),
                remote_e: None,
                remote_ek: None,
                wrote_message1: true,
            },
            msg,
        ))
    }

    pub fn responder(network_id: &NetworkId) -> Self {
        Self {
            sym: Sym::new(network_id),
            role: Role::Responder,
            eph: None,
            dk: None,
            remote_e: None,
            remote_ek: None,
            wrote_message1: false,
        }
    }

    pub fn chaining_key(&self) -> [u8; HASH_LEN] {
        self.sym.chaining_key()
    }

    /// Responder reads message 1 and writes message 2.
    pub fn read_message1_write_message2(
        &mut self,
        message1: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if message1.len() != MESSAGE1_LEN {
            return Err(HandshakeError::Length);
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&message1[..32]);
        self.sym.mix_hash(&e);
        self.remote_e = Some(e);
        let mut ek = [0u8; ML_KEM_768_EK_LEN];
        ek.copy_from_slice(&message1[32..]);
        self.sym.mix_hash(&ek);
        self.remote_ek = Some(ek);
        let payload = self.sym.decrypt_and_hash(&[])?;
        if !payload.is_empty() {
            return Err(HandshakeError::State);
        }
        self.write_message2()
    }

    fn write_message2(&mut self) -> Result<Vec<u8>, HandshakeError> {
        let remote_e = self.remote_e.ok_or(HandshakeError::State)?;
        let remote_ek = self.remote_ek.ok_or(HandshakeError::State)?;
        let eph = StaticSecret::random_from_rng(OsRng);
        let epub = PublicKey::from(&eph).to_bytes();
        let mut msg = Vec::with_capacity(MESSAGE2_LEN);
        msg.extend_from_slice(&epub);
        self.sym.mix_hash(&epub);
        let shared = eph.diffie_hellman(&PublicKey::from(remote_e));
        self.sym.mix_key(shared.as_bytes());
        let ek =
            ml_kem_768::EncapsKey::try_from_bytes(remote_ek).map_err(|_| HandshakeError::Kem)?;
        let (ss, ct) = ek
            .try_encaps_with_rng(&mut OsRng)
            .map_err(|_| HandshakeError::Kem)?;
        let ct_bytes = ct.into_bytes();
        let encrypted = self.sym.encrypt_and_hash(&ct_bytes)?;
        if encrypted.len() != ML_KEM_768_CT_LEN + TAG_LEN {
            return Err(HandshakeError::Length);
        }
        msg.extend_from_slice(&encrypted);
        let ss_bytes = ss.into_bytes();
        self.sym.mix_key(&ss_bytes);
        let tag = self.sym.encrypt_and_hash(&[])?;
        if tag.len() != TAG_LEN {
            return Err(HandshakeError::Length);
        }
        msg.extend_from_slice(&tag);
        self.eph = Some(eph);
        if msg.len() != MESSAGE2_LEN {
            return Err(HandshakeError::Length);
        }
        Ok(msg)
    }

    /// Initiator reads message 2 and reaches the channel.
    pub fn read_message2(&mut self, message2: &[u8]) -> Result<(), HandshakeError> {
        if message2.len() != MESSAGE2_LEN {
            return Err(HandshakeError::Length);
        }
        let mut re = [0u8; 32];
        re.copy_from_slice(&message2[..32]);
        self.sym.mix_hash(&re);
        let eph = self.eph.take().ok_or(HandshakeError::State)?;
        let shared = eph.diffie_hellman(&PublicKey::from(re));
        self.sym.mix_key(shared.as_bytes());
        let ct_end = 32 + ML_KEM_768_CT_LEN + TAG_LEN;
        let ct_wire = &message2[32..ct_end];
        let ct_plain = self.sym.decrypt_and_hash(ct_wire)?;
        if ct_plain.len() != ML_KEM_768_CT_LEN {
            return Err(HandshakeError::Length);
        }
        let mut ct_bytes = [0u8; ML_KEM_768_CT_LEN];
        ct_bytes.copy_from_slice(&ct_plain);
        let ct =
            ml_kem_768::CipherText::try_from_bytes(ct_bytes).map_err(|_| HandshakeError::Kem)?;
        let dk = self.dk.take().ok_or(HandshakeError::State)?;
        let ss = dk.try_decaps(&ct).map_err(|_| HandshakeError::Kem)?;
        self.sym.mix_key(&ss.into_bytes());
        let tag = &message2[ct_end..];
        let payload = self.sym.decrypt_and_hash(tag)?;
        if !payload.is_empty() {
            return Err(HandshakeError::State);
        }
        Ok(())
    }

    pub fn split(mut self) -> Result<crate::channel::Channel, HandshakeError> {
        let (k_send, k_recv) = hkdf(&self.sym.ck, &[]);
        let keys = match self.role {
            Role::Initiator => TransportKeys {
                send: k_send,
                recv: k_recv,
            },
            Role::Responder => TransportKeys {
                send: k_recv,
                recv: k_send,
            },
        };
        self.sym.ck.zeroize();
        self.sym.h.zeroize();
        if let Some(k) = self.sym.k.as_mut() {
            k.zeroize();
        }
        self.eph = None;
        self.dk = None;
        Ok(crate::channel::Channel::from_keys(keys))
    }

    pub fn wrote_message1(&self) -> bool {
        self.wrote_message1
    }
}

/// Deterministic initiator keys for KATs. `d` and `z` are the ML-KEM seed halves.
pub fn pinned_initiator(
    network_id: &NetworkId,
    x25519: [u8; 32],
    d: &[u8; 32],
    z: &[u8; 32],
) -> Result<(Handshake, Vec<u8>), HandshakeError> {
    let (ek, dk) = ml_kem_768::KG::keygen_from_seed(*d, *z);
    Handshake::initiator_with(network_id, StaticSecret::from(x25519), dk, ek.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid() -> NetworkId {
        [0x11; 16]
    }

    #[test]
    fn protocol_name_is_hashed() {
        assert!(PROTOCOL_NAME.len() > 32);
    }

    #[test]
    fn message_lengths_and_roundtrip() {
        let (mut ini, m1) = Handshake::initiator(&nid()).unwrap();
        assert_eq!(m1.len(), MESSAGE1_LEN);
        let mut resp = Handshake::responder(&nid());
        let m2 = resp.read_message1_write_message2(&m1).unwrap();
        assert_eq!(m2.len(), MESSAGE2_LEN);
        ini.read_message2(&m2).unwrap();
        let mut a = ini.split().unwrap();
        let mut b = resp.split().unwrap();
        let ct = a.seal(b"hello").unwrap();
        let (pt, _) = b.open_one(&ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn wrong_prologue_fails_like_garbage() {
        let (mut ini, m1) = Handshake::initiator(&nid()).unwrap();
        let mut other = Handshake::responder(&[0x22; 16]);
        let m2 = other.read_message1_write_message2(&m1).unwrap();
        let wrong = ini.read_message2(&m2).unwrap_err();
        assert!(matches!(wrong, HandshakeError::Decrypt));
        let (mut ini2, _) = Handshake::initiator(&nid()).unwrap();
        let garbage = vec![0xA5; MESSAGE2_LEN];
        let junk = ini2.read_message2(&garbage).unwrap_err();
        assert!(matches!(junk, HandshakeError::Decrypt));
    }

    #[test]
    fn pinned_message_and_chaining_keys() {
        let mut d = [0x42; 32];
        let mut z = [0x24; 32];
        d[0] = 1;
        z[0] = 2;
        let (hs, m1) = pinned_initiator(&nid(), [0x07; 32], &d, &z).unwrap();
        assert_eq!(m1.len(), MESSAGE1_LEN);
        let ck_after_m1 = hs.chaining_key();
        let mut resp = Handshake::responder(&nid());
        assert_eq!(resp.chaining_key(), ck_after_m1);
        let m2 = resp.read_message1_write_message2(&m1).unwrap();
        assert_eq!(m2.len(), MESSAGE2_LEN);
        assert_ne!(resp.chaining_key(), ck_after_m1);
    }
}
