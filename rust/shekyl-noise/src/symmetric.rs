// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Noise's symmetric state, shared by every handshake in the workspace.

use blake2::digest::Digest;
use blake2::Blake2s256;
use zeroize::Zeroizing;

use crate::aead::{self, HASH_LEN};
use crate::channel::{self, RecvHalf, SendHalf};

/// What the symmetric state can fail at. A handshake maps these into its own
/// error type; which of the two it was says nothing a peer may be told.
#[derive(Debug)]
pub enum SymmetricError {
    /// An AEAD operation failed: a bad tag on open.
    Decrypt,
    /// No key where one was needed, or the nonce ran out.
    State,
}

/// Which side of Noise `Split` this peer is.
///
/// The initiator sends with the first transport key and receives with the
/// second. The responder does the opposite. [`SymmetricState::into_halves`]
/// is the only place that assignment is made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitRole {
    Initiator,
    Responder,
}

/// Noise's `SymmetricState`: the chaining key, the handshake hash, and the
/// handshake cipher's key and nonce.
///
/// The protocol name is a parameter. Each handshake that uses this state
/// brings its own name and its own tokens; what is shared is the arithmetic
/// every Noise handshake does between tokens.
pub struct SymmetricState {
    ck: Zeroizing<[u8; HASH_LEN]>,
    h: [u8; HASH_LEN],
    k: Option<Zeroizing<[u8; HASH_LEN]>>,
    n: u64,
}

impl SymmetricState {
    /// `InitializeSymmetric(name)` then `MixHash(prologue)`.
    pub fn new(name: &[u8], prologue: &[u8]) -> Self {
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

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    pub fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = aead::hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        if self.k.is_none() {
            self.mix_hash(plaintext);
            return Ok(plaintext.to_vec());
        }
        let ct = self.encrypt(plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        if self.k.is_none() {
            self.mix_hash(ciphertext);
            return Ok(ciphertext.to_vec());
        }
        let pt = self.decrypt(ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        let key = self.k.as_ref().ok_or(SymmetricError::State)?;
        let ct = aead::seal(key, self.n, &self.h, plaintext).ok_or(SymmetricError::Decrypt)?;
        self.n = self.n.checked_add(1).ok_or(SymmetricError::State)?;
        Ok(ct)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        let key = self.k.as_ref().ok_or(SymmetricError::State)?;
        let pt = aead::open(key, self.n, &self.h, ciphertext).ok_or(SymmetricError::Decrypt)?;
        self.n = self.n.checked_add(1).ok_or(SymmetricError::State)?;
        Ok(pt)
    }

    /// The handshake hash `h`. It is not a secret: both sides and anyone
    /// who saw the handshake can compute what went into it.
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.h
    }

    /// Noise's `Split`, then the two record halves for `role`.
    ///
    /// Each direction keeps its own chaining key. Rekey advances the two
    /// directions independently.
    #[must_use = "the record halves are the session"]
    pub fn into_halves(self, role: SplitRole) -> (SendHalf, RecvHalf) {
        let (first, second) = aead::hkdf(&self.ck, &[]);
        let (send_key, recv_key) = match role {
            SplitRole::Initiator => (first, second),
            SplitRole::Responder => (second, first),
        };
        channel::halves(self.ck, send_key, recv_key)
    }

    /// The chaining key, for a test that pins the key schedule.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn chaining_key(&self) -> [u8; HASH_LEN] {
        *self.ck
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn hex_of(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        }
        out
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_name_that_fits_is_padded_into_the_chaining_key() {
        let name = b"short-name";
        assert!(name.len() <= HASH_LEN);
        let sym = SymmetricState::new(name, b"");
        let mut padded = [0u8; HASH_LEN];
        padded[..name.len()].copy_from_slice(name);
        assert_eq!(sym.chaining_key(), padded);
    }

    #[test]
    fn a_long_name_is_hashed_and_the_prologue_leaves_the_chaining_key() {
        let name = b"Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
        assert!(name.len() > HASH_LEN);
        let mut sym = SymmetricState::new(name, b"prologue");
        let chaining_key = sym.chaining_key();
        assert_eq!(chaining_key, aead::hash(name));
        sym.mix_hash(b"more");
        assert_eq!(sym.chaining_key(), chaining_key);
        assert_ne!(sym.handshake_hash(), chaining_key);
    }

    #[test]
    fn the_initiator_sends_the_first_transport_key() {
        let name = b"Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let prologue = b"prologue";
        let initiator = SymmetricState::new(name, prologue);
        let responder = SymmetricState::new(name, prologue);
        let chaining_key = initiator.chaining_key();
        let (first, second) = aead::hkdf(&chaining_key, &[]);
        let (initiator_send, initiator_recv) = initiator.into_halves(SplitRole::Initiator);
        let (responder_send, responder_recv) = responder.into_halves(SplitRole::Responder);
        assert_eq!(initiator_send.ck_and_k().1, *first);
        assert_eq!(initiator_recv.ck_and_k().1, *second);
        assert_eq!(responder_send.ck_and_k().1, *second);
        assert_eq!(responder_recv.ck_and_k().1, *first);
        assert_eq!(initiator_send.ck_and_k().0, chaining_key);
        assert_eq!(responder_recv.ck_and_k().0, chaining_key);
    }

    /// Cacophony `Noise_NN_25519_ChaChaPoly_BLAKE2s`, the classical pattern the
    /// P2P handshake's symmetric state shares. Source: snow
    /// `tests/vectors/cacophony.txt` at
    /// `8ac60f51cfe3e010c84f0a454cc575ad9204fa12`
    /// (https://github.com/mcginty/snow/blob/8ac60f51cfe3e010c84f0a454cc575ad9204fa12/tests/vectors/cacophony.txt).
    #[test]
    fn cacophony_nn_blake2s_matches_sym() {
        let prologue = unhex("4a6f686e2047616c74");
        let init_e: [u8; HASH_LEN] =
            unhex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
                .try_into()
                .unwrap();
        let resp_e: [u8; HASH_LEN] =
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

        let mut ini = SymmetricState::new(name, &prologue);
        ini.mix_hash(&init_pub);
        let mut msg1 = init_pub.to_vec();
        msg1.extend(ini.encrypt_and_hash(&p0).unwrap());
        assert_eq!(
            hex_of(&msg1),
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"
        );

        let mut resp = SymmetricState::new(name, &prologue);
        resp.mix_hash(&init_pub);
        assert_eq!(resp.decrypt_and_hash(&msg1[HASH_LEN..]).unwrap(), p0);
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
        assert_eq!(ini.decrypt_and_hash(&msg2[HASH_LEN..]).unwrap(), p1);
        assert_eq!(
            hex_of(&ini.handshake_hash()),
            "a621e3943a29c1d984b43727697fbec096107d0b569031ac7e0f1131de19f4f4"
        );

        let (ini_send, _) = ini.into_halves(SplitRole::Initiator);
        let (resp_send, _) = resp.into_halves(SplitRole::Responder);
        let t0 = aead::seal(&ini_send.ck_and_k().1, 0, &[], &p2).unwrap();
        let t1 = aead::seal(&resp_send.ck_and_k().1, 0, &[], &p3).unwrap();
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
