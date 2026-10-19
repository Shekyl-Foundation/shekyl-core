// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One direction of a Noise transport.
//!
//! A direction owns its chaining key, its record key and its nonce. The
//! caller supplies plaintext and associated data and does not supply the
//! nonce. Rekey is `HKDF(ck, k)` after [`REKEY_NONCES`] uses, the nonce
//! resets, and [`KeyEpoch`] advances. Nothing is written to mark it.
//!
//! The header-protection key is not a field. A framer that needs one derives
//! it when the epoch [`Direction::seal`] reports changes, and keeps it itself.

use zeroize::Zeroizing;

use crate::aead::{self, HASH_LEN};

/// Nonce uses of one record key before rekey. One name for both framers.
pub const REKEY_NONCES: u64 = 1_000;

/// Which record key a direction is using.
///
/// [`Direction::seal`] and [`Direction::open`] return the epoch of the key
/// that produced that ciphertext. The value advances only when rekey runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyEpoch(u64);

impl KeyEpoch {
    /// The epoch a direction starts on, before any rekey.
    pub const INITIAL: Self = Self(0);

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// What a direction can fail at. A framer maps these into its own error.
#[derive(Debug)]
pub enum DirectionError {
    /// The ciphertext's tag did not match.
    Decrypt,
    /// The cipher rejected the operation, or the nonce or the epoch cannot advance.
    State,
}

/// One Noise transport direction after `Split`.
///
/// Construction is [`crate::SymmetricState::into_directions`]. The two
/// directions of a session do not share a chaining key: rekey advances each
/// on its own.
pub struct Direction {
    ck: Zeroizing<[u8; HASH_LEN]>,
    k: Zeroizing<[u8; HASH_LEN]>,
    n: u64,
    epoch: KeyEpoch,
    /// Ciphertexts this direction has opened, over its whole life.
    opened: u64,
    /// The handshake hash of the session this direction was split from.
    /// Not a secret, and not changed by a rekey.
    handshake_hash: [u8; HASH_LEN],
}

impl Direction {
    pub(crate) fn new(
        ck: Zeroizing<[u8; HASH_LEN]>,
        k: Zeroizing<[u8; HASH_LEN]>,
        handshake_hash: [u8; HASH_LEN],
    ) -> Self {
        Self {
            ck,
            k,
            n: 0,
            epoch: KeyEpoch::INITIAL,
            opened: 0,
            handshake_hash,
        }
    }

    /// The handshake hash of the session this direction belongs to, stamped
    /// by [`SymmetricState::into_directions`](crate::SymmetricState::into_directions).
    ///
    /// A caller that lends a direction out and takes it back reads this to
    /// know it got its own session's direction back, and not another's: two
    /// sessions' directions are otherwise interchangeable values, and
    /// [`Self::opened`] counts only what a direction has opened, not for
    /// which session.
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.handshake_hash
    }

    /// How many ciphertexts this direction has opened. A failed tag is not
    /// counted, and a rekey does not reset the count.
    ///
    /// A direction that has opened at least one ciphertext has heard from a
    /// peer that holds the session's keys. A caller that must not act until
    /// then reads this, and not the word of whatever code it lent the
    /// direction to.
    #[must_use]
    pub fn opened(&self) -> u64 {
        self.opened
    }

    /// Seal `plaintext` under this direction's next nonce.
    ///
    /// The epoch is the record key that produced the ciphertext.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, KeyEpoch), DirectionError> {
        let epoch = self.epoch;
        let ct = aead::seal(&self.k, self.n, ad, plaintext).ok_or(DirectionError::State)?;
        self.advance()?;
        Ok((ct, epoch))
    }

    /// Open `ciphertext` under this direction's next nonce.
    ///
    /// The epoch is the record key that opened it. A failed tag does not
    /// spend the nonce.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, KeyEpoch), DirectionError> {
        let epoch = self.epoch;
        let pt = aead::open(&self.k, self.n, ad, ciphertext).ok_or(DirectionError::Decrypt)?;
        self.advance()?;
        self.opened = self.opened.saturating_add(1);
        Ok((pt, epoch))
    }

    fn advance(&mut self) -> Result<(), DirectionError> {
        let n = self.n.checked_add(1).ok_or(DirectionError::State)?;
        if n == REKEY_NONCES {
            let epoch = self.epoch.next().ok_or(DirectionError::State)?;
            let [ck, k] = aead::hkdf(&self.ck, &self.k[..]);
            self.ck = ck;
            self.k = k;
            self.n = 0;
            self.epoch = epoch;
        } else {
            self.n = n;
        }
        Ok(())
    }

    /// Set the nonce, so a test can stand on the rekey boundary.
    #[cfg(test)]
    pub(crate) fn force_nonce(&mut self, n: u64) {
        self.n = n;
    }

    /// The chaining key and the record key.
    #[cfg(test)]
    pub(crate) fn ck_and_k(&self) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
        (*self.ck, *self.k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed() -> Direction {
        Direction::new(
            Zeroizing::new([0x11; HASH_LEN]),
            Zeroizing::new([0x22; HASH_LEN]),
            [0x33; HASH_LEN],
        )
    }

    /// The count the RPC handshake's pending session gates on: an opened
    /// ciphertext moves it, a failed tag does not, and a rekey leaves it.
    #[test]
    fn only_an_opened_ciphertext_is_counted() {
        let mut send = keyed();
        let mut recv = keyed();
        assert_eq!(recv.opened(), 0);

        assert!(recv.open(&[0xa5; 48], b"ad").is_err());
        let (mut tampered, _) = keyed().seal(b"body", b"ad").unwrap();
        tampered[0] ^= 1;
        assert!(recv.open(&tampered, b"ad").is_err());
        assert_eq!(recv.opened(), 0, "a failed tag is not an open");

        let (ct, _) = send.seal(b"body", b"ad").unwrap();
        assert!(recv.open(&ct, b"other ad").is_err());
        assert_eq!(
            recv.opened(),
            0,
            "nor is the right bytes under the wrong ad"
        );
        recv.open(&ct, b"ad").unwrap();
        assert_eq!(recv.opened(), 1);
        assert_eq!(send.opened(), 0, "sealing is not opening");

        send.force_nonce(REKEY_NONCES - 1);
        recv.force_nonce(REKEY_NONCES - 1);
        let (ct, _) = send.seal(b"boundary", b"ad").unwrap();
        recv.open(&ct, b"ad").unwrap();
        let (ct, _) = send.seal(b"after", b"ad").unwrap();
        recv.open(&ct, b"ad").unwrap();
        assert_eq!(recv.opened(), 3, "a rekey does not reset the count");
    }

    #[test]
    fn the_epoch_is_the_key_that_produced_the_ciphertext() {
        let mut send = keyed();
        let mut recv = keyed();
        let (ct, epoch) = send.seal(b"a", b"ad").unwrap();
        assert_eq!(epoch, KeyEpoch::INITIAL);
        let (pt, opened) = recv.open(&ct, b"ad").unwrap();
        assert_eq!(pt, b"a");
        assert_eq!(opened, KeyEpoch::INITIAL);

        let before = send.ck_and_k();
        send.force_nonce(REKEY_NONCES - 1);
        recv.force_nonce(REKEY_NONCES - 1);
        let (ct, epoch) = send.seal(b"b", b"ad").unwrap();
        assert_eq!(epoch, KeyEpoch::INITIAL);
        let (pt, opened) = recv.open(&ct, b"ad").unwrap();
        assert_eq!(pt, b"b");
        assert_eq!(opened, KeyEpoch::INITIAL);
        let next = KeyEpoch::INITIAL.next().unwrap();

        let (ct, epoch) = send.seal(b"c", b"ad").unwrap();
        assert_eq!(epoch, next);
        let (pt, opened) = recv.open(&ct, b"ad").unwrap();
        assert_eq!(pt, b"c");
        assert_eq!(opened, next);
        assert_ne!(send.ck_and_k(), before);
    }

    #[test]
    fn a_bad_tag_does_not_spend_the_nonce() {
        let mut send = keyed();
        let mut recv = keyed();
        let (mut ct, _) = send.seal(b"a", b"ad").unwrap();
        ct[0] ^= 0xff;
        assert!(matches!(
            recv.open(&ct, b"ad"),
            Err(DirectionError::Decrypt)
        ));
        let (ct, epoch) = send.seal(b"b", b"ad").unwrap();
        assert_eq!(epoch, KeyEpoch::INITIAL);
        // The failed open left the receiver on the first nonce, so this
        // ciphertext, which used the second, does not open.
        assert!(recv.open(&ct, b"ad").is_err());
    }
}
