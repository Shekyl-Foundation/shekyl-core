// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Noise's symmetric state, shared by every handshake in the workspace.

use blake2::digest::Digest;
use blake2::Blake2s256;
use zeroize::Zeroizing;

use crate::aead::{self, HASH_LEN};

/// What the symmetric state can fail at. A handshake maps these into its own
/// error type; which of the two it was says nothing a peer may be told.
#[derive(Debug)]
pub enum SymmetricError {
    /// An AEAD operation failed: a bad tag on open.
    Decrypt,
    /// No key where one was needed, or the nonce ran out.
    State,
}

/// What `Split` yields.
///
/// `first` and `second` are the two transport keys in the order
/// `HKDF(ck, zerolen)` returns them: the initiator sends with `first` and
/// receives with `second`, the responder the other way round. The chaining
/// key comes too, because the record layer rekeys from it.
pub struct SplitKeys {
    pub chaining_key: Zeroizing<[u8; HASH_LEN]>,
    pub first: Zeroizing<[u8; HASH_LEN]>,
    pub second: Zeroizing<[u8; HASH_LEN]>,
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

    /// Noise's `Split`.
    pub fn split(self) -> SplitKeys {
        let (first, second) = aead::hkdf(&self.ck, &[]);
        SplitKeys {
            chaining_key: self.ck,
            first,
            second,
        }
    }

    /// The chaining key, for a test that pins the key schedule.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn chaining_key(&self) -> [u8; HASH_LEN] {
        *self.ck
    }
}
