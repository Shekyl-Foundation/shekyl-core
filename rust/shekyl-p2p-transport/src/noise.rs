// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`.
//!
//! Message 1 has no key, so `e` and `e1` are hashed only. Message 2 mixes the
//! X25519 secret at `ee`, encrypts `ekem1` under that key, mixes the ML-KEM
//! secret, then encrypts the empty payload under the hybrid key. `Split` runs
//! after that payload.
//!
//! The type at each step is the only thing that step can do. Transport keys
//! exist only after message 2.

use blake2::digest::Digest;
use blake2::Blake2s256;
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::OsRng;
#[cfg(test)]
use rand_core::{CryptoRng, RngCore};
use shekyl_crypto_pq::kem::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN};
#[cfg(test)]
use std::cell::Cell;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::aead::{self, HASH_LEN, TAG_LEN};
use crate::channel::{halves, RecvHalf, SendHalf};
use crate::prefix::NetworkId;

pub const PROTOCOL_NAME: &[u8] = b"Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
pub const MESSAGE1_LEN: usize = 32 + ML_KEM_768_EK_LEN;
pub const MESSAGE2_LEN: usize = 32 + ML_KEM_768_CT_LEN + TAG_LEN + TAG_LEN;

// Responder Diffie-Hellman calls on this thread. `read_message1` must not
// move it: a malformed encapsulation key is rejected before any of them.
#[cfg(test)]
thread_local! {
    static RESPONDER_DH: Cell<u64> = const { Cell::new(0) };
}

#[derive(Debug)]
pub(crate) enum HandshakeError {
    Decrypt,
    Kem,
    Length,
    State,
}

struct Sym {
    ck: Zeroizing<[u8; HASH_LEN]>,
    h: [u8; HASH_LEN],
    k: Option<Zeroizing<[u8; HASH_LEN]>>,
    n: u64,
}

impl Sym {
    fn new(name: &[u8], prologue: &[u8]) -> Self {
        let hashed = if name.len() <= HASH_LEN {
            let mut padded = [0u8; HASH_LEN];
            padded[..name.len()].copy_from_slice(name);
            padded
        } else {
            aead::hash(name)
        };
        let mut sym = Self {
            ck: Zeroizing::new(hashed),
            h: hashed,
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
        let (ck, k) = aead::hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
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
        let key = self.k.as_ref().ok_or(HandshakeError::State)?;
        let ct = aead::seal(key, self.n, &self.h, plaintext).ok_or(HandshakeError::Decrypt)?;
        self.n = self.n.checked_add(1).ok_or(HandshakeError::State)?;
        Ok(ct)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let key = self.k.as_ref().ok_or(HandshakeError::State)?;
        let pt = aead::open(key, self.n, &self.h, ciphertext).ok_or(HandshakeError::Decrypt)?;
        self.n = self.n.checked_add(1).ok_or(HandshakeError::State)?;
        Ok(pt)
    }
}

/// Initiator after message 1. The next call reads message 2.
pub(crate) struct Initiator {
    sym: Sym,
    eph: StaticSecret,
    dk: ml_kem_768::DecapsKey,
}

/// Responder before message 1.
pub(crate) struct Responder {
    sym: Sym,
}

/// Responder after message 1. The next call writes message 2.
pub(crate) struct ResponderReady {
    sym: Sym,
    remote_e: [u8; 32],
    remote_ek: [u8; ML_KEM_768_EK_LEN],
}

/// Both messages are done. `INITIATOR` selects which `Split` half is send.
pub(crate) struct Established<const INITIATOR: bool> {
    sym: Sym,
    #[cfg(test)]
    pub(crate) ck_after_ee: Zeroizing<[u8; HASH_LEN]>,
}

impl Initiator {
    pub(crate) fn new(network_id: &NetworkId) -> Result<(Self, Vec<u8>), HandshakeError> {
        let eph = StaticSecret::random_from_rng(OsRng);
        let (ek, dk) =
            ml_kem_768::KG::try_keygen_with_rng(&mut OsRng).map_err(|_| HandshakeError::Kem)?;
        Self::from_parts(network_id, eph, dk, ek.into_bytes())
    }

    fn from_parts(
        network_id: &NetworkId,
        eph: StaticSecret,
        dk: ml_kem_768::DecapsKey,
        ek: [u8; ML_KEM_768_EK_LEN],
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let mut sym = Sym::new(PROTOCOL_NAME, network_id);
        let mut msg = Vec::with_capacity(MESSAGE1_LEN);
        let epub = PublicKey::from(&eph).to_bytes();
        msg.extend_from_slice(&epub);
        sym.mix_hash(&epub);
        msg.extend_from_slice(&ek);
        sym.mix_hash(&ek);
        let payload = sym.encrypt_and_hash(&[])?;
        if !payload.is_empty() || msg.len() != MESSAGE1_LEN {
            return Err(HandshakeError::State);
        }
        Ok((Self { sym, eph, dk }, msg))
    }

    pub(crate) fn read_message2(
        mut self,
        message2: &[u8],
    ) -> Result<Established<true>, HandshakeError> {
        if message2.len() != MESSAGE2_LEN {
            return Err(HandshakeError::Length);
        }
        let mut remote_e = [0u8; 32];
        remote_e.copy_from_slice(&message2[..32]);
        self.sym.mix_hash(&remote_e);
        let shared = self.eph.diffie_hellman(&PublicKey::from(remote_e));
        if !shared.was_contributory() {
            return Err(HandshakeError::Decrypt);
        }
        self.sym.mix_key(shared.as_bytes());
        #[cfg(test)]
        let ck_after_ee = Zeroizing::new(*self.sym.ck);
        let ct_end = 32 + ML_KEM_768_CT_LEN + TAG_LEN;
        let ct_plain = self.sym.decrypt_and_hash(&message2[32..ct_end])?;
        if ct_plain.len() != ML_KEM_768_CT_LEN {
            return Err(HandshakeError::Length);
        }
        let mut ct_bytes = [0u8; ML_KEM_768_CT_LEN];
        ct_bytes.copy_from_slice(&ct_plain);
        let ct =
            ml_kem_768::CipherText::try_from_bytes(ct_bytes).map_err(|_| HandshakeError::Kem)?;
        let ss = self.dk.try_decaps(&ct).map_err(|_| HandshakeError::Kem)?;
        let ss_bytes = Zeroizing::new(ss.into_bytes());
        self.sym.mix_key(&ss_bytes[..]);
        let payload = self.sym.decrypt_and_hash(&message2[ct_end..])?;
        if !payload.is_empty() {
            return Err(HandshakeError::State);
        }
        Ok(Established {
            sym: self.sym,
            #[cfg(test)]
            ck_after_ee,
        })
    }

    #[cfg(test)]
    pub(crate) fn pinned(
        network_id: &NetworkId,
        x25519: [u8; 32],
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(*d, *z);
        Self::from_parts(network_id, StaticSecret::from(x25519), dk, ek.into_bytes())
    }
}

impl Responder {
    pub(crate) fn new(network_id: &NetworkId) -> Self {
        Self {
            sym: Sym::new(PROTOCOL_NAME, network_id),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_protocol_name(name: &[u8], network_id: &NetworkId) -> Self {
        Self {
            sym: Sym::new(name, network_id),
        }
    }

    pub(crate) fn read_message1(
        mut self,
        message1: &[u8],
    ) -> Result<ResponderReady, HandshakeError> {
        if message1.len() != MESSAGE1_LEN {
            return Err(HandshakeError::Length);
        }
        let mut remote_ek = [0u8; ML_KEM_768_EK_LEN];
        remote_ek.copy_from_slice(&message1[32..]);
        // D10.2: the encapsulation-key range check is the third rejection,
        // after the prefix and the length. It runs before the transcript and
        // before the X25519 Diffie-Hellman in `finish`.
        ml_kem_768::EncapsKey::try_from_bytes(remote_ek).map_err(|_| HandshakeError::Kem)?;
        let mut remote_e = [0u8; 32];
        remote_e.copy_from_slice(&message1[..32]);
        self.sym.mix_hash(&remote_e);
        self.sym.mix_hash(&remote_ek);
        let payload = self.sym.decrypt_and_hash(&[])?;
        if !payload.is_empty() {
            return Err(HandshakeError::State);
        }
        Ok(ResponderReady {
            sym: self.sym,
            remote_e,
            remote_ek,
        })
    }

    #[cfg(test)]
    pub(crate) fn chaining_key(&self) -> [u8; HASH_LEN] {
        *self.sym.ck
    }
}

impl ResponderReady {
    pub(crate) fn write_message2(self) -> Result<(Established<false>, Vec<u8>), HandshakeError> {
        self.finish(StaticSecret::random_from_rng(OsRng), &mut OsRng)
    }

    #[cfg(test)]
    pub(crate) fn write_message2_pinned(
        self,
        x25519: [u8; 32],
        encaps_seed: [u8; 32],
    ) -> Result<(Established<false>, Vec<u8>), HandshakeError> {
        self.finish(
            StaticSecret::from(x25519),
            &mut FillRng {
                seed: encaps_seed,
                n: 0,
            },
        )
    }

    fn finish(
        mut self,
        eph: StaticSecret,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Established<false>, Vec<u8>), HandshakeError> {
        let epub = PublicKey::from(&eph).to_bytes();
        let mut msg = Vec::with_capacity(MESSAGE2_LEN);
        msg.extend_from_slice(&epub);
        self.sym.mix_hash(&epub);
        // Already checked in `read_message1`. Parsing again here keeps a
        // bad key from reaching the Diffie-Hellman if that check is skipped.
        let ek = ml_kem_768::EncapsKey::try_from_bytes(self.remote_ek)
            .map_err(|_| HandshakeError::Kem)?;
        #[cfg(test)]
        RESPONDER_DH.with(|count| count.set(count.get() + 1));
        let shared = eph.diffie_hellman(&PublicKey::from(self.remote_e));
        if !shared.was_contributory() {
            return Err(HandshakeError::Decrypt);
        }
        self.sym.mix_key(shared.as_bytes());
        #[cfg(test)]
        let ck_after_ee = Zeroizing::new(*self.sym.ck);
        let (ss, ct) = ek
            .try_encaps_with_rng(rng)
            .map_err(|_| HandshakeError::Kem)?;
        let encrypted = self.sym.encrypt_and_hash(&ct.into_bytes())?;
        if encrypted.len() != ML_KEM_768_CT_LEN + TAG_LEN {
            return Err(HandshakeError::Length);
        }
        msg.extend_from_slice(&encrypted);
        let ss_bytes = Zeroizing::new(ss.into_bytes());
        self.sym.mix_key(&ss_bytes[..]);
        let tag = self.sym.encrypt_and_hash(&[])?;
        if tag.len() != TAG_LEN {
            return Err(HandshakeError::Length);
        }
        msg.extend_from_slice(&tag);
        if msg.len() != MESSAGE2_LEN {
            return Err(HandshakeError::Length);
        }
        Ok((
            Established {
                sym: self.sym,
                #[cfg(test)]
                ck_after_ee,
            },
            msg,
        ))
    }
}

impl<const INITIATOR: bool> Established<INITIATOR> {
    pub(crate) fn split(mut self) -> (SendHalf, RecvHalf) {
        let ck = std::mem::replace(&mut self.sym.ck, Zeroizing::new([0u8; HASH_LEN]));
        let (first, second) = aead::hkdf(&ck, &[]);
        if INITIATOR {
            halves(ck, first, second)
        } else {
            halves(ck, second, first)
        }
    }

    #[cfg(test)]
    pub(crate) fn chaining_key(&self) -> [u8; HASH_LEN] {
        *self.sym.ck
    }
}

#[cfg(test)]
struct FillRng {
    seed: [u8; 32],
    n: usize,
}

#[cfg(test)]
impl RngCore for FillRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.seed[self.n % 32];
            self.n += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
impl CryptoRng for FillRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::hash;
    use crate::channel::REKEY_NONCES;

    fn hex_of(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
        out
    }

    fn nid() -> NetworkId {
        [0x11; 16]
    }

    fn pinned_pair() -> (Established<true>, Established<false>, Vec<u8>, Vec<u8>) {
        let mut d = [0x42; 32];
        let mut z = [0x24; 32];
        d[0] = 1;
        z[0] = 2;
        let (ini, m1) = Initiator::pinned(&nid(), [0x07; 32], &d, &z).unwrap();
        let ready = Responder::new(&nid()).read_message1(&m1).unwrap();
        let (resp, m2) = ready.write_message2_pinned([0x09; 32], [0x33; 32]).unwrap();
        let ini = ini.read_message2(&m2).unwrap();
        (ini, resp, m1, m2)
    }

    #[test]
    fn protocol_name_is_the_initial_chaining_key() {
        assert!(PROTOCOL_NAME.len() > HASH_LEN);
        let ck = Responder::new(&nid()).chaining_key();
        // MixHash(prologue) moves `h` and not `ck`.
        assert_eq!(ck, hash(PROTOCOL_NAME));
        assert_eq!(
            hex_of(&ck),
            "c349a55a6b5c0428654e131abf703a8f9a223cb0512dabbca0187cd23c901bba"
        );
    }

    #[test]
    fn message_lengths_and_roundtrip() {
        let (ini, m1) = Initiator::new(&nid()).unwrap();
        assert_eq!(m1.len(), MESSAGE1_LEN);
        let (resp, m2) = Responder::new(&nid())
            .read_message1(&m1)
            .unwrap()
            .write_message2()
            .unwrap();
        assert_eq!(m2.len(), MESSAGE2_LEN);
        let mut a_send = ini.read_message2(&m2).unwrap().split().0;
        let mut b_recv = resp.split().1;
        let ct = a_send.seal(b"hello").unwrap();
        let (pt, _) = b_recv.open_one(&ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn wrong_prologue_and_wrong_suite_fail_like_garbage() {
        let (ini, m1) = Initiator::new(&nid()).unwrap();
        let (_other, m2) = Responder::new(&[0x22; 16])
            .read_message1(&m1)
            .unwrap()
            .write_message2()
            .unwrap();
        assert!(matches!(
            ini.read_message2(&m2),
            Err(HandshakeError::Decrypt)
        ));

        let (ini, _m1) = Initiator::new(&nid()).unwrap();
        let garbage = vec![0xA5; MESSAGE2_LEN];
        assert!(matches!(
            ini.read_message2(&garbage),
            Err(HandshakeError::Decrypt)
        ));

        let (ini, m1) = Initiator::new(&nid()).unwrap();
        let (_bad, m2) =
            Responder::with_protocol_name(b"Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2b", &nid())
                .read_message1(&m1)
                .unwrap()
                .write_message2()
                .unwrap();
        assert!(matches!(
            ini.read_message2(&m2),
            Err(HandshakeError::Decrypt)
        ));
    }

    #[test]
    fn low_order_x25519_does_not_mix() {
        let (ini, _m1) = Initiator::new(&nid()).unwrap();
        let zeros = vec![0u8; MESSAGE2_LEN];
        assert!(matches!(
            ini.read_message2(&zeros),
            Err(HandshakeError::Decrypt)
        ));

        let forged = vec![0u8; MESSAGE1_LEN];
        let ready = Responder::new(&nid()).read_message1(&forged).unwrap();
        assert!(matches!(
            ready.write_message2(),
            Err(HandshakeError::Decrypt)
        ));
    }

    #[test]
    fn a_malformed_encapsulation_key_is_rejected_before_diffie_hellman() {
        let mut bad = vec![0u8; MESSAGE1_LEN];
        bad[32..].fill(0xff);
        let before = RESPONDER_DH.with(|count| count.get());
        assert!(matches!(
            Responder::new(&nid()).read_message1(&bad),
            Err(HandshakeError::Kem)
        ));
        assert_eq!(
            RESPONDER_DH.with(|count| count.get()),
            before,
            "a rejected key must not reach the responder Diffie-Hellman"
        );
    }

    #[test]
    fn finish_rejects_a_replaced_encapsulation_key_before_diffie_hellman() {
        let (_ini, message1) = Initiator::new(&nid()).unwrap();
        let mut ready = Responder::new(&nid()).read_message1(&message1).unwrap();
        ready.remote_ek.fill(0xff);
        let before = RESPONDER_DH.with(|count| count.get());
        assert!(matches!(ready.write_message2(), Err(HandshakeError::Kem)));
        assert_eq!(
            RESPONDER_DH.with(|count| count.get()),
            before,
            "finish must reject the key before the Diffie-Hellman"
        );
    }

    #[test]
    fn pinned_messages_mix_steps_and_rekey() {
        let (ini, resp, m1, m2) = pinned_pair();
        assert_eq!(m1.len(), MESSAGE1_LEN);
        assert_eq!(m2.len(), MESSAGE2_LEN);
        assert_eq!(ini.ck_after_ee, resp.ck_after_ee);
        assert_eq!(ini.chaining_key(), resp.chaining_key());
        assert_ne!(*ini.ck_after_ee, ini.chaining_key());
        assert_eq!(
            hex_of(&ini.ck_after_ee[..]),
            "02f20a44382bf0d80ba404acaacdebcb82a931e6a0d09d81ecdb8aac201b9236"
        );

        assert_eq!(hex_of(&m1), include_str!("kat_m1.hex").trim());
        assert_eq!(
            hex_of(&ini.chaining_key()),
            "aa12aef4d4c33f500f4798ec3787281d0e236e5dbe3d2711902f635ab7019763"
        );
        assert_eq!(hex_of(&m2), include_str!("kat_m2.hex").trim());

        let (mut a_send, mut a_recv) = ini.split();
        let (mut b_send, mut b_recv) = resp.split();
        let (ck, k) = a_send.ck_and_k();
        assert_eq!(ck, b_recv.ck_and_k().0);
        assert_eq!(k, b_recv.ck_and_k().1);
        assert_ne!(ck, k);
        assert_eq!(
            hex_of(&k),
            "149dfa9c12e1b59a8dd22c9768a9ea3d4821ffb20aff0ddfde5680c886891370"
        );

        for i in 0..REKEY_NONCES / 2 {
            let ct = a_send.seal(&[i as u8]).unwrap();
            assert_eq!(b_recv.open_one(&ct).unwrap().0, vec![i as u8]);
        }
        let (ck_after, k_after) = a_send.ck_and_k();
        assert_ne!(ck_after, ck);
        assert_eq!(ck_after, b_recv.ck_and_k().0);
        assert_eq!(k_after, b_recv.ck_and_k().1);
        for i in 0..REKEY_NONCES / 2 {
            let ct = b_send.seal(&[i as u8]).unwrap();
            assert_eq!(a_recv.open_one(&ct).unwrap().0, vec![i as u8]);
        }
        let (ck_back, k_back) = b_send.ck_and_k();
        assert_eq!(ck_back, a_recv.ck_and_k().0);
        assert_eq!(k_back, a_recv.ck_and_k().1);
        assert_eq!(
            hex_of(&ck_after),
            "65f18eb7ce1929333b118ed5a9d35a6f00857f80e49409598848f2438a4f52c4"
        );
        assert_eq!(
            hex_of(&k_after),
            "50c5ecd6feb1f40d4be1dce0309789c6c2e8a60f2188812090f7c2c56f0b2223"
        );
        assert_eq!(
            hex_of(&ck_back),
            "8f3c7d5c411c203dd55aa134d6a11b04a8a36ee50a0cb990915be4a082ca4655"
        );
        assert_eq!(
            hex_of(&k_back),
            "2ece957080019fedc1e7d21bf46dce09ac2619495194edd54c35ef0280d31e4a"
        );
        let record = a_send.seal(&[0x42]).unwrap();
        assert_eq!(
            hex_of(&record),
            "ac9785f15ea6b2a4eac23e7c168e34ca3aa62f35a5d84cdbc01eb822264aed4d43016f"
        );
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Cacophony `Noise_NN_25519_ChaChaPoly_BLAKE2s`, the classical pattern NNhfs
    /// shares. Source: snow `tests/vectors/cacophony.txt` at
    /// `8ac60f51cfe3e010c84f0a454cc575ad9204fa12`
    /// (https://github.com/mcginty/snow/blob/8ac60f51cfe3e010c84f0a454cc575ad9204fa12/tests/vectors/cacophony.txt).
    #[test]
    fn cacophony_nn_blake2s_matches_sym() {
        let prologue = unhex("4a6f686e2047616c74");
        let init_e: [u8; 32] =
            unhex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
                .try_into()
                .unwrap();
        let resp_e: [u8; 32] =
            unhex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")
                .try_into()
                .unwrap();
        let p0 = unhex("4c756477696720766f6e204d69736573");
        let p1 = unhex("4d757272617920526f746862617264");
        let p2 = unhex("462e20412e20486179656b");
        let p3 = unhex("4361726c204d656e676572");
        let name = b"Noise_NN_25519_ChaChaPoly_BLAKE2s";

        let init_sec = StaticSecret::from(init_e);
        let resp_sec = StaticSecret::from(resp_e);
        let init_pub = PublicKey::from(&init_sec).to_bytes();
        let resp_pub = PublicKey::from(&resp_sec).to_bytes();

        let mut ini = Sym::new(name, &prologue);
        ini.mix_hash(&init_pub);
        let mut msg1 = init_pub.to_vec();
        msg1.extend(ini.encrypt_and_hash(&p0).unwrap());
        assert_eq!(
            hex_of(&msg1),
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"
        );

        let mut resp = Sym::new(name, &prologue);
        resp.mix_hash(&init_pub);
        assert_eq!(resp.decrypt_and_hash(&msg1[32..]).unwrap(), p0);
        resp.mix_hash(&resp_pub);
        let shared = resp_sec.diffie_hellman(&PublicKey::from(init_pub));
        resp.mix_key(shared.as_bytes());
        let mut msg2 = resp_pub.to_vec();
        msg2.extend(resp.encrypt_and_hash(&p1).unwrap());
        assert_eq!(
            hex_of(&msg2),
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ff34a6759d06e7733c83aeb5556c15bc762b664b3ba0556b1e7eaea4168bb6"
        );

        ini.mix_hash(&resp_pub);
        let shared = init_sec.diffie_hellman(&PublicKey::from(resp_pub));
        ini.mix_key(shared.as_bytes());
        assert_eq!(ini.decrypt_and_hash(&msg2[32..]).unwrap(), p1);
        assert_eq!(
            hex_of(&ini.h),
            "a621e3943a29c1d984b43727697fbec096107d0b569031ac7e0f1131de19f4f4"
        );

        let ini_ck = *ini.ck;
        let resp_ck = *resp.ck;
        let (ini_send, _) = Established::<true> {
            sym: ini,
            ck_after_ee: Zeroizing::new(ini_ck),
        }
        .split();
        let (resp_send, _) = Established::<false> {
            sym: resp,
            ck_after_ee: Zeroizing::new(resp_ck),
        }
        .split();
        let t0 = crate::aead::seal(&ini_send.ck_and_k().1, 0, &[], &p2).unwrap();
        let t1 = crate::aead::seal(&resp_send.ck_and_k().1, 0, &[], &p3).unwrap();
        assert_eq!(
            hex_of(&t0),
            "79285da88da3535f52b07b70006c85706de7ddb1fd3dddac995b7e"
        );
        assert_eq!(
            hex_of(&t1),
            "ffdad3a7f0db4c39077f223659c5c1d107666405566ecdf4ab53bf"
        );
    }
}
