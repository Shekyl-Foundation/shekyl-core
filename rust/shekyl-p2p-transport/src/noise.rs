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

use shekyl_noise::symmetric::{SplitRole, SymmetricError, SymmetricState as Sym};
use shekyl_noise::TAG_LEN;

use crate::channel::{self, RecvHalf, SendHalf};
use crate::prefix::NetworkId;
#[cfg(test)]
use shekyl_noise::HASH_LEN;

pub const PROTOCOL_NAME: &[u8] = b"Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
pub const MESSAGE1_LEN: usize = 32 + ML_KEM_768_EK_LEN;
pub const MESSAGE2_LEN: usize = 32 + ML_KEM_768_CT_LEN + TAG_LEN + TAG_LEN;

// Every responder Diffie-Hellman goes through `responder_dh`, which counts
// the call. A malformed encapsulation key must not move the count.
#[cfg(test)]
thread_local! {
    static RESPONDER_DH: Cell<u64> = const { Cell::new(0) };
}

fn responder_dh(eph: &StaticSecret, remote_e: &[u8; 32]) -> x25519_dalek::SharedSecret {
    #[cfg(test)]
    RESPONDER_DH.with(|count| count.set(count.get() + 1));
    eph.diffie_hellman(&PublicKey::from(*remote_e))
}

#[derive(Debug)]
pub enum HandshakeError {
    Decrypt,
    Kem,
    Length,
    State,
}

impl From<SymmetricError> for HandshakeError {
    fn from(error: SymmetricError) -> Self {
        match error {
            SymmetricError::Decrypt => Self::Decrypt,
            SymmetricError::State => Self::State,
        }
    }
}

/// Initiator after message 1. The next call reads message 2.
pub struct Initiator {
    sym: Sym,
    eph: StaticSecret,
    dk: ml_kem_768::DecapsKey,
}

/// Responder before message 1.
pub struct Responder {
    sym: Sym,
}

/// Responder after message 1. The next call writes message 2.
///
/// `remote_ek` is the encapsulation key `read_message1` already accepted.
/// An invalid key cannot be represented here.
pub struct ResponderReady {
    sym: Sym,
    remote_e: [u8; 32],
    remote_ek: ml_kem_768::EncapsKey,
}

/// Both messages are done. `INITIATOR` selects which `Split` half is send.
pub struct Established<const INITIATOR: bool> {
    sym: Sym,
}

impl Initiator {
    pub fn new(network_id: &NetworkId) -> Result<(Self, Vec<u8>), HandshakeError> {
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

    pub fn read_message2(mut self, message2: &[u8]) -> Result<Established<true>, HandshakeError> {
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
        Ok(Established { sym: self.sym })
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
    pub fn new(network_id: &NetworkId) -> Self {
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

    pub fn read_message1(mut self, message1: &[u8]) -> Result<ResponderReady, HandshakeError> {
        if message1.len() != MESSAGE1_LEN {
            return Err(HandshakeError::Length);
        }
        let mut remote_ek_bytes = [0u8; ML_KEM_768_EK_LEN];
        remote_ek_bytes.copy_from_slice(&message1[32..]);
        // D10.2: the encapsulation-key range check is the third rejection,
        // after the prefix and the length. It runs before the transcript and
        // before the X25519 Diffie-Hellman in `finish`. The parsed key is
        // what `ResponderReady` stores, so `finish` does not parse it again.
        // The transcript hashes the wire bytes, not the array `try_from_bytes` takes.
        let remote_ek = ml_kem_768::EncapsKey::try_from_bytes(remote_ek_bytes)
            .map_err(|_| HandshakeError::Kem)?;
        let mut remote_e = [0u8; 32];
        remote_e.copy_from_slice(&message1[..32]);
        self.sym.mix_hash(&message1[..32]);
        self.sym.mix_hash(&message1[32..]);
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
}

impl ResponderReady {
    pub fn write_message2(self) -> Result<(Established<false>, Vec<u8>), HandshakeError> {
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
        let shared = responder_dh(&eph, &self.remote_e);
        if !shared.was_contributory() {
            return Err(HandshakeError::Decrypt);
        }
        self.sym.mix_key(shared.as_bytes());
        let (ss, ct) = self
            .remote_ek
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
        Ok((Established { sym: self.sym }, msg))
    }
}

impl<const INITIATOR: bool> Established<INITIATOR> {
    /// The record halves for this role. Dropping them drops the session.
    #[must_use = "the record halves are the session"]
    pub fn split(self) -> (SendHalf, RecvHalf) {
        let role = if INITIATOR {
            SplitRole::Initiator
        } else {
            SplitRole::Responder
        };
        let (send, recv) = self.sym.into_directions(role);
        channel::session(send, recv)
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
    use shekyl_noise::REKEY_NONCES;

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
    fn protocol_name_does_not_fit_in_the_hash() {
        assert!(PROTOCOL_NAME.len() > HASH_LEN);
    }

    #[test]
    fn message_lengths_and_roundtrip() {
        let (ini, m1) = Initiator::new(&nid()).unwrap();
        assert_eq!(m1.len(), MESSAGE1_LEN);
        let before = RESPONDER_DH.with(|count| count.get());
        let (resp, m2) = Responder::new(&nid())
            .read_message1(&m1)
            .unwrap()
            .write_message2()
            .unwrap();
        assert_eq!(
            RESPONDER_DH.with(|count| count.get()),
            before + 1,
            "a successful message 2 runs the responder Diffie-Hellman once"
        );
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
    fn pinned_messages_mix_steps_and_rekey() {
        let (ini, resp, m1, m2) = pinned_pair();
        assert_eq!(m1.len(), MESSAGE1_LEN);
        assert_eq!(m2.len(), MESSAGE2_LEN);
        assert_eq!(hex_of(&m1), include_str!("kat_m1.hex").trim());
        assert_eq!(hex_of(&m2), include_str!("kat_m2.hex").trim());

        let (mut a_send, mut a_recv) = ini.split();
        let (mut b_send, mut b_recv) = resp.split();
        for i in 0..REKEY_NONCES / 2 {
            let ct = a_send.seal(&[i as u8]).unwrap();
            assert_eq!(b_recv.open_one(&ct).unwrap().0, vec![i as u8]);
        }
        for i in 0..REKEY_NONCES / 2 {
            let ct = b_send.seal(&[i as u8]).unwrap();
            assert_eq!(a_recv.open_one(&ct).unwrap().0, vec![i as u8]);
        }
        let record = a_send.seal(&[0x42]).unwrap();
        assert_eq!(
            hex_of(&record),
            "ac9785f15ea6b2a4eac23e7c168e34ca3aa62f35a5d84cdbc01eb822264aed4d43016f"
        );
    }
}
