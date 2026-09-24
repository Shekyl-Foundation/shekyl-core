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
use rand_core::{CryptoRng, OsRng, RngCore};
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
        self.write_message2_with(StaticSecret::random_from_rng(OsRng), &mut OsRng)
    }

    /// Same as [`Self::read_message1_write_message2`] with caller-supplied
    /// ephemeral and encapsulation randomness, for handshake vectors.
    pub fn read_message1_write_message2_pinned(
        &mut self,
        message1: &[u8],
        x25519: [u8; 32],
        encaps_seed: [u8; 32],
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
        self.write_message2_with(
            StaticSecret::from(x25519),
            &mut FillRng {
                seed: encaps_seed,
                n: 0,
            },
        )
    }

    fn write_message2_with(
        &mut self,
        eph: StaticSecret,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Vec<u8>, HandshakeError> {
        let remote_e = self.remote_e.ok_or(HandshakeError::State)?;
        let remote_ek = self.remote_ek.ok_or(HandshakeError::State)?;
        let epub = PublicKey::from(&eph).to_bytes();
        let mut msg = Vec::with_capacity(MESSAGE2_LEN);
        msg.extend_from_slice(&epub);
        self.sym.mix_hash(&epub);
        let shared = eph.diffie_hellman(&PublicKey::from(remote_e));
        self.sym.mix_key(shared.as_bytes());
        let ek =
            ml_kem_768::EncapsKey::try_from_bytes(remote_ek).map_err(|_| HandshakeError::Kem)?;
        let (ss, ct) = ek
            .try_encaps_with_rng(rng)
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
        // Split's HKDF produces the two transport keys and does not replace
        // `ck`. Rekey keeps descending from this chaining key.
        let ck = self.sym.ck;
        let (k_send, k_recv) = hkdf(&ck, &[]);
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
        let channel = crate::channel::Channel::from_keys(ck, keys);
        self.sym.ck.zeroize();
        self.sym.h.zeroize();
        if let Some(k) = self.sym.k.as_mut() {
            k.zeroize();
        }
        self.eph = None;
        self.dk = None;
        Ok(channel)
    }

    pub fn wrote_message1(&self) -> bool {
        self.wrote_message1
    }
}

struct FillRng {
    seed: [u8; 32],
    n: usize,
}

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

impl CryptoRng for FillRng {}

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
        let m2 = resp
            .read_message1_write_message2_pinned(&m1, [0x09; 32], [0x33; 32])
            .unwrap();
        assert_eq!(m2.len(), MESSAGE2_LEN);
        assert_ne!(resp.chaining_key(), ck_after_m1);
        assert_eq!(hex_of(&m1), "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6dcd87387b87812d54002d898ab16b9a84ec93f9e181f57aa22353a80ee48e5ff19e8ad1b29af206c4f434f198c7bbac8c999331c76a4db9c2196f984f387a98c694af66ea6937166caf386fce98b3b2964ae115cb8e7a28992c813c2541f7a13a5ea299b2ea947b736107359bd8801d15b3aae1c5a07761673fd200de9935ed9c9af56cb391013d5e534f8ad6460ac83b16437a778c607dd1749b895990599ceb3c4c74f2cd069852d7fc45dfb799bbbc6a424998f9ca2f89208c63e3103059294b6981fd830604b5604b3c15e5d423f753a2184aa6cbb057e8e59760b27fdc2b9ae6406c9c75971ec8a187347e5b9a6945c3cf4e000a0794aab9d85f4a21796d65351696bc5dc482a980bf8c573a77a8bf11b37ef6216f0ba5c32ad303bc5a0eb498b25e48354e28377316923e817015f34c4d75a2a7e79f2c21b2418a03ddb55b26e2a24419330f9780e8aaa8b180250e35b91e267eeba43d6bfc1c0cf30f7cabb9d50003b1555b12670c4ac99fc03bafc1f494a19758b4922d1944a869d33159fa637d777d3dbaa366f584419586e1e8c24ce045112bbd3c847dcedb96edc373cd126a6ec64ab160acc2a929d6e31654487673e5a5e3853b22e02c490347f434a2e60a94ab160aeb02c5f07cca9f01b3c37103cc80a3d0c8a91f2965d9988fda0cb9ca3967158a7349503d20b25d92c26f9ee6aede469d9034206c35025b08ad243a548aa9a49ffabfed6912d6a231795b8b085c0d5ba146f68a089f7c8c68f58874f9c1e82a621f74209b2b309fb0641fa4160c67085cf32096bc621a703d7961af5da8053bb381b4775626521dd916ad46ac95eabc85fbc3cf4e47ccd0ea905d64084644be19774605a50b4160827e6bb55e44aa04a90d2ce7280804b922e8997a8778ae14618cbc4f48dc5d4165b60ae473728343f92524153ac2c87982d9369880bcb4d4ab2f95924836f148e4c598e751b90ff88825891b8f13634c57073330baa7a6786426389888174fb9030b5711f6f8753de40e5af67bd405bd0b981f3ca27766744f03f21a1faa1678d28f2915c6ecc1a192ec60b8f1c0ebd0add7a05cac127ddff86344752d6a498e0a13ab86a00ac5a505e6dc4999d7567b2b2c30b108deb7c20f8863280a7979887a75564dc28c523188049699bdca938b490591a104b9993576deb3c3bb5977bb8c3aff07395446330639ab2611936b592dcac8ce889c06af4ab2976c45bb355131b0a74f8505c9d7c0c0e84c80905be651494aeccbf2004ba5e48d286c97a377a5eb097861a126b2fb9e4dd9cdcf7a13ec2a4d17915fb3c5b357f9954e19202374803a65cc7e398d66e59934ec5ed59a7098e743911b0d90a2741e2c17b941a189a632d418a4a9c027a842c30d360be4bcb3a9ac9c8ecc80ec0825bf042afea31096aa4e1f77b768d4978182787463168179382204315252bb79a46735b8c69b786333c3527485c416d03325d8805babbb9b0ac0e5ea73cb45b9888b45bfd673b8f35f5f22479e347c2a172bde19bffd32b30513441baa8cf82a57a617a4d2ca198dd2109ec23130fa3f8578abafcb554e14b085213c32cb2adb53b516e742af506642a72387432c3aa00a2ec32876655f4d150b8f3dcb7637887ff510ca3095722de0b8293f2d15288f4a4bb2bff74487");
        assert_eq!(
            hex_of(&ck_after_m1),
            "c349a55a6b5c0428654e131abf703a8f9a223cb0512dabbca0187cd23c901bba"
        );
        assert_eq!(hex_of(&m2), "57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d4216e7a6bfbcd533a04d2750a7578e8d2ec1359c4c0ef9723875a31722298357f8477f4c08e5864b7fc9f43a1975fe419caebec3bf4cb340f78456f4cae21c026627abbf2b1f1c849dd1feb774a89e10345b37ce685f5d2c5be80bcc952134d7d34dee406901cee57e4cf1134976e8dd0960a34049ed4b51174361e2e5b0121a9455c395940f54319393887cb17692cc5e25dcd4fe28e8e2f7c6b1dd7735b5c40e1d0d9c6081d2a098cf9e7d8b84acbcc053b87b72b6f1b7f6c26898fe6eba29f3d32e19ec376b49d9bbacb8acbacd9b0ce88e67d3828395b9e1fc7b83a334b7868f67f7b714e1902514f883a4735a73a9b1418006c0c55e46aeb496f869d7f26ecc3bcc902b4a0e08fd6f067457b9e3bce7edbc435d1ec88423198b52c67bc05941a227d97e45246e401077c4a4c62c14070058e72a1c642e3f92ecd28450b0480f300b15ade62fd5cf1bc7ff8c239419c87695b5fa32d7c246a5a663682aedfe09cf993ca81e2f0153abaab60aa5c78c927c7e1dcd553b14b854b2dbe4bab47db2f5600b6114ab5dbad8785958886d2c8709500a13541fe68ffe34b33968e7b241771b2a1bb8ef4c96172d097fb30aa2336395c99ecb3c03fae8e3fd87cca8e2378018d9b8af5711d05f3761f2848dbe095ee2351ab82024919da387931af4f7debc87a53441d73ade392dfba97db16ff6d2cbb459f4514db3cc4b30ca25884c9c6d7075c9786e9dce32d2dfd9f1b8ecd8c08751b9ab5a6f00214639b645829a5baaa65d8f34257e36285467ffd5cc5b4c8adb061b43a39c57b60d80b7fdb95ee71a9a07c5a711eac5f4aecb0a88f575831557036ae65cc3723007619bd8896d9720812922f8014070f7e3dbba3a8404f9bd8b59b7e5cf7ecabd8ffdb793278a15b0648b4aba4a784c703b95fd5be855f1338ea7efaa7ee26a6417e7fe2f27475a9a11ebad01cfa2a3bc13b310bc255d13bcb857963d06698165c230168bccc593592ab67c1b6c9eda9daa214120b009fe691b40fe06223e40ca87bc1e3cdb3fb73c7c04c20732d549262c8e71ae5d6dae74a9d4726c7b29a9f0799d5ec51a087a6249400d4f0cebc9b35b079e8c611b2ce816e72a7b7abd9e0deb5f9db8192718ea857a7439216d05f15dd67d601fd2a9145fe48bb4235c8e9cec863428b47754f14ec881506ae576c7fefe9d7315670d76b26a7183eef84e483fb01c57d77239170895d593a2bb699c60a45ec7bf8272077cb940aced5319bd911a5da5b6c07ba0745361b4f33654e4915652ca9ccf64259dd31d10353ac9cb0b6947fb6e99391e092bc7e6a213a15f3a3e164ef1c94d9a4ab99bcafcfd33a4c9e0b4398c92a60116293d696bbdab3a37a6e39f196aaf948de377020c75e5604a2c2a122264497ed91382fe74c61fc4ba14e7707ed7cbdf7d77fc2097bfd21c8860773bf25758e2b3fb630d14ec89e3ac9345bf3ffe8e8a64bd10cfc0323fc5446ac557d10ee26caec35706ef8aa7d60a6071accaaa531ca82c383c7c0dee02f221e7cbcb3f0a1e48fec0ba7fb3ca647e939246dadb3c8ba44e9ffd47b35dbae7a42ed0f03c8");
        assert_eq!(
            hex_of(&resp.chaining_key()),
            "aa12aef4d4c33f500f4798ec3787281d0e236e5dbe3d2711902f635ab7019763"
        );
    }
}
