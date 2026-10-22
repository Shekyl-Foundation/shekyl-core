// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Noise's symmetric state, shared by every handshake in the workspace.

use blake2::digest::Digest;
use blake2::Blake2s256;
use zeroize::Zeroizing;

use crate::aead::{self, HASH_LEN};
use crate::direction::{Direction, RecvDirection, SendDirection};

/// What the symmetric state can fail at. A handshake maps these into its own
/// error type; which of the two it was says nothing a peer may be told.
#[derive(Debug)]
pub enum SymmetricError {
    /// A bad tag on open.
    Decrypt,
    /// No key where one was needed, the nonce ran out, or the cipher refused
    /// to seal.
    State,
}

/// Which side of Noise `Split` this peer is.
///
/// The initiator sends with the first transport key and receives with the
/// second. The responder does the opposite. [`SymmetricState::into_directions`]
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
        let [ck, k] = aead::hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    /// Noise's `MixKeyAndHash`: one input moves the chaining key, the
    /// handshake hash and the cipher key together. The hybrid patterns use
    /// it for a static KEM's shared secret.
    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let [ck, temp_h, temp_k] = aead::hkdf(&self.ck, ikm);
        self.ck = ck;
        self.mix_hash(&temp_h[..]);
        self.k = Some(temp_k);
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
        let ct = aead::seal(key, self.n, &self.h, plaintext).ok_or(SymmetricError::State)?;
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

    /// Noise's `Split` for `role`: the send direction, then the receive direction.
    ///
    /// Each direction keeps its own chaining key. Rekey advances the two
    /// directions independently. No key leaves this function.
    #[must_use = "the directions are the session"]
    pub fn into_directions(self, role: SplitRole) -> (SendDirection, RecvDirection) {
        let [first, second] = aead::hkdf(&self.ck, &[]);
        let (send_key, recv_key) = match role {
            SplitRole::Initiator => (first, second),
            SplitRole::Responder => (second, first),
        };
        let recv_ck = self.ck.clone();
        // Both directions carry the session's handshake hash, so a holder can
        // tell its own session's direction from another's.
        let h = self.h;
        (
            SendDirection(Direction::new(self.ck, send_key, h)),
            RecvDirection(Direction::new(recv_ck, recv_key, h)),
        )
    }

    #[cfg(test)]
    fn chaining_key(&self) -> [u8; HASH_LEN] {
        *self.ck
    }

    /// A state whose chaining key is `ck`, for a test that pins `Split`
    /// without running a handshake.
    #[cfg(test)]
    fn with_chaining_key(ck: [u8; HASH_LEN]) -> Self {
        Self {
            ck: Zeroizing::new(ck),
            h: [0u8; HASH_LEN],
            k: None,
            n: 0,
        }
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
        assert_eq!(
            hex_of(&chaining_key),
            "c349a55a6b5c0428654e131abf703a8f9a223cb0512dabbca0187cd23c901bba"
        );
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
        let [first, second] = aead::hkdf(&chaining_key, &[]);
        let (initiator_send, initiator_recv) = initiator.into_directions(SplitRole::Initiator);
        let (responder_send, responder_recv) = responder.into_directions(SplitRole::Responder);
        assert_eq!(initiator_send.0.ck_and_k().1, *first);
        assert_eq!(initiator_recv.0.ck_and_k().1, *second);
        assert_eq!(responder_send.0.ck_and_k().1, *second);
        assert_eq!(responder_recv.0.ck_and_k().1, *first);
        assert_eq!(initiator_send.0.ck_and_k().0, chaining_key);
        assert_eq!(responder_recv.0.ck_and_k().0, chaining_key);
    }

    /// Both directions carry the handshake hash of the state they were split
    /// from, a rekey does not change it, and a second session's directions
    /// carry their own. The RPC handshake's pending session relies on the
    /// stamp to know it got its own receiving direction back.
    #[test]
    fn both_directions_carry_the_sessions_handshake_hash() {
        let name = b"Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let mut one = SymmetricState::new(name, b"prologue");
        let mut two = SymmetricState::new(name, b"prologue");
        one.mix_hash(b"session one");
        two.mix_hash(b"session two");
        let (h1, h2) = (one.handshake_hash(), two.handshake_hash());
        assert_ne!(h1, h2);

        let (mut send, recv) = one.into_directions(SplitRole::Initiator);
        assert_eq!(send.handshake_hash(), h1);
        assert_eq!(recv.handshake_hash(), h1);
        send.0.force_nonce(crate::REKEY_NONCES - 1);
        send.seal(b"the last nonce of the first key", b"").unwrap();
        let (_, epoch) = send.seal(b"under the next key", b"").unwrap();
        assert_ne!(epoch, crate::KeyEpoch::INITIAL, "the direction rekeyed");
        assert_eq!(send.handshake_hash(), h1, "a rekey keeps the stamp");

        let (other_send, other_recv) = two.into_directions(SplitRole::Responder);
        assert_eq!(other_send.handshake_hash(), h2);
        assert_eq!(other_recv.handshake_hash(), h2);
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

        let (mut ini_send, _) = ini.into_directions(SplitRole::Initiator);
        let (mut resp_send, _) = resp.into_directions(SplitRole::Responder);
        let (t0, _) = ini_send.seal(&p2, &[]).unwrap();
        let (t1, _) = resp_send.seal(&p3, &[]).unwrap();
        assert_eq!(
            hex_of(&t0),
            "79285da88da3535f52b07b70006c85706de7ddb1fd3dddac995b7e"
        );
        assert_eq!(
            hex_of(&t1),
            "ffdad3a7f0db4c39077f223659c5c1d107666405566ecdf4ab53bf"
        );
    }

    /// The chaining key the pinned NNhfs transcript ends on, and the transport
    /// keys `Split` and one rekey produce from it. `kat_m1.hex` and
    /// `kat_m2.hex` pin that transcript in the P2P handshake.
    #[test]
    fn split_of_the_pinned_chaining_key_rekeys_to_the_pinned_keys() {
        const CHAINING_KEY: &str =
            "aa12aef4d4c33f500f4798ec3787281d0e236e5dbe3d2711902f635ab7019763";
        const INITIATOR_SEND_KEY: &str =
            "149dfa9c12e1b59a8dd22c9768a9ea3d4821ffb20aff0ddfde5680c886891370";
        const AFTER_REKEY_CK: &str =
            "65f18eb7ce1929333b118ed5a9d35a6f00857f80e49409598848f2438a4f52c4";
        const AFTER_REKEY_K: &str =
            "50c5ecd6feb1f40d4be1dce0309789c6c2e8a60f2188812090f7c2c56f0b2223";
        const OTHER_AFTER_REKEY_CK: &str =
            "8f3c7d5c411c203dd55aa134d6a11b04a8a36ee50a0cb990915be4a082ca4655";
        const OTHER_AFTER_REKEY_K: &str =
            "2ece957080019fedc1e7d21bf46dce09ac2619495194edd54c35ef0280d31e4a";

        let ck = unhex32(CHAINING_KEY);
        let (mut send, recv) =
            SymmetricState::with_chaining_key(ck).into_directions(SplitRole::Initiator);
        let (mut other, other_recv) =
            SymmetricState::with_chaining_key(ck).into_directions(SplitRole::Responder);
        assert_eq!(send.0.ck_and_k().0, ck);
        assert_eq!(send.0.ck_and_k().1, unhex32(INITIATOR_SEND_KEY));
        assert_eq!(recv.0.ck_and_k().1, other.0.ck_and_k().1);
        assert_eq!(other_recv.0.ck_and_k().1, send.0.ck_and_k().1);

        for _ in 0..crate::REKEY_NONCES {
            send.seal(&[0], &[]).unwrap();
            other.seal(&[0], &[]).unwrap();
        }
        let (ck_after, k_after) = send.0.ck_and_k();
        assert_eq!(ck_after, unhex32(AFTER_REKEY_CK));
        assert_eq!(k_after, unhex32(AFTER_REKEY_K));
        let (ck_back, k_back) = other.0.ck_and_k();
        assert_eq!(ck_back, unhex32(OTHER_AFTER_REKEY_CK));
        assert_eq!(k_back, unhex32(OTHER_AFTER_REKEY_K));
    }

    fn unhex32(s: &str) -> [u8; HASH_LEN] {
        unhex(s).try_into().unwrap()
    }
}
