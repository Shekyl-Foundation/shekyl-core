// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two directions of a Noise transport.
//!
//! A session's `Split` yields a [`SendDirection`], which only seals, and a
//! [`RecvDirection`], which only opens. They are different types, so the
//! two cannot be passed in each other's place: sealing under the peer's key
//! at the peer's nonces would not type-check (close-out F3, 2026-10-22).
//!
//! Each owns its chaining key, its record key and its nonce. The caller
//! supplies plaintext and associated data and does not supply the nonce.
//! Rekey is `HKDF(ck, k)` after [`REKEY_NONCES`] uses, the nonce resets,
//! and [`KeyEpoch`] advances. Nothing is written to mark it.
//!
//! **A direction that fails is dead** (close-out F5). A failed tag, a
//! state that cannot advance, and a framer's refusal of what it opened all
//! poison the direction itself, so it refuses every later operation, even
//! when taken out of the framer that refused and wrapped again.
//!
//! The header-protection key is not a field. A framer derives one with
//! `hkdf_from_record_key`, passing its own label, when the epoch changes,
//! and keeps the output itself.

use zeroize::Zeroizing;

use crate::aead::{self, HASH_LEN};

/// Nonce uses of one record key before rekey. One name for both framers.
pub const REKEY_NONCES: u64 = 1_000;

/// Which record key a direction is using.
///
/// [`SendDirection::seal`] and [`RecvDirection::open`] return the epoch of
/// the key that produced that ciphertext. The value advances only when
/// rekey runs.
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
#[derive(Debug, Eq, PartialEq)]
pub enum DirectionError {
    /// The ciphertext's tag did not match. The direction is now dead.
    Decrypt,
    /// The cipher rejected the operation, or the nonce or the epoch cannot
    /// advance. The direction is now dead.
    State,
    /// An earlier failure killed this direction.
    Poisoned,
}

/// The state both directions share. Not public: the two typed halves are.
pub(crate) struct Direction {
    ck: Zeroizing<[u8; HASH_LEN]>,
    k: Zeroizing<[u8; HASH_LEN]>,
    n: u64,
    epoch: KeyEpoch,
    /// Ciphertexts this direction has opened, over its whole life.
    opened: u64,
    /// The handshake hash of the session this direction was split from.
    /// Not a secret, and not changed by a rekey.
    handshake_hash: [u8; HASH_LEN],
    /// A failure killed this direction.
    dead: bool,
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
            dead: false,
        }
    }

    pub(crate) fn seal(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, KeyEpoch), DirectionError> {
        self.alive()?;
        let epoch = self.epoch;
        let Some(ct) = aead::seal(&self.k, self.n, ad, plaintext) else {
            return Err(self.kill(DirectionError::State));
        };
        self.advance()?;
        Ok((ct, epoch))
    }

    pub(crate) fn open(
        &mut self,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, KeyEpoch), DirectionError> {
        self.alive()?;
        let epoch = self.epoch;
        // A failed tag does not spend the nonce. It kills the direction, so
        // nothing is opened under that nonce again either.
        let Some(pt) = aead::open(&self.k, self.n, ad, ciphertext) else {
            return Err(self.kill(DirectionError::Decrypt));
        };
        self.advance()?;
        self.opened = self.opened.saturating_add(1);
        Ok((pt, epoch))
    }

    fn alive(&self) -> Result<(), DirectionError> {
        if self.dead {
            Err(DirectionError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn kill(&mut self, error: DirectionError) -> DirectionError {
        self.dead = true;
        error
    }

    /// A framer refused what this direction opened. From now on it opens
    /// and seals nothing.
    pub(crate) fn poison(&mut self) {
        self.dead = true;
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.dead
    }

    /// After the AEAD step: a nonce or an epoch that cannot advance leaves
    /// the direction dead, since the ciphertext already used this nonce.
    fn advance(&mut self) -> Result<(), DirectionError> {
        let Some(n) = self.n.checked_add(1) else {
            return Err(self.kill(DirectionError::State));
        };
        if n == REKEY_NONCES {
            let Some(epoch) = self.epoch.next() else {
                return Err(self.kill(DirectionError::State));
            };
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

    /// The nonce and the epoch the next seal or open will use. Reading them
    /// spends neither.
    pub(crate) fn next(&self) -> (u64, KeyEpoch) {
        (self.n, self.epoch)
    }

    /// The first output of `HKDF(record key, ikm)`.
    ///
    /// The record key stays in this direction, and it is the HMAC key here
    /// as it is in rekey, as §4.4 rules. A framer passes its own label and
    /// keeps the output, deriving again when [`Self::next`]'s epoch has
    /// moved. The second output is wiped with the temporary that holds it.
    pub(crate) fn hkdf_from_record_key(&self, ikm: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
        let [key, _] = aead::hkdf(&self.k, ikm);
        key
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

/// The direction this side seals with.
///
/// Construction is [`crate::SymmetricState::into_directions`]. It seals and
/// nothing else. It cannot open, and it cannot stand where a receiving
/// direction is asked for:
///
/// ```compile_fail,E0599
/// # use shekyl_noise::SendDirection;
/// fn open_with_the_send_half(send: &mut SendDirection) {
///     let _ = send.open(&[0u8; 16], b"");
/// }
/// ```
///
/// ```compile_fail,E0308
/// # use shekyl_noise::{ClassTable, ClassedOpener, SplitRole, SymmetricState};
/// fn swap_the_halves(state: SymmetricState) {
///     let (send, _recv) = state.into_directions(SplitRole::Initiator);
///     let _ = ClassedOpener::new(send, ClassTable::new(&[512]).unwrap());
/// }
/// ```
pub struct SendDirection(pub(crate) Direction);

/// The direction this side opens with.
///
/// Construction is [`crate::SymmetricState::into_directions`]. It opens and
/// counts what it opened, and nothing else. It cannot seal, and it cannot
/// stand where a sending direction is asked for:
///
/// ```compile_fail,E0599
/// # use shekyl_noise::RecvDirection;
/// fn seal_with_the_receive_half(recv: &mut RecvDirection) {
///     let _ = recv.seal(b"", b"");
/// }
/// ```
///
/// ```compile_fail,E0308
/// # use shekyl_noise::{ClassTable, ClassedSealer, SplitRole, SymmetricState};
/// fn swap_the_halves(state: SymmetricState) {
///     let (_send, recv) = state.into_directions(SplitRole::Initiator);
///     let _ = ClassedSealer::new(recv, ClassTable::new(&[512]).unwrap());
/// }
/// ```
pub struct RecvDirection(pub(crate) Direction);

impl SendDirection {
    /// Seal `plaintext` under this direction's next nonce.
    ///
    /// The epoch is the record key that produced the ciphertext.
    ///
    /// # Errors
    ///
    /// [`DirectionError::State`] when the cipher fails or the nonce cannot
    /// advance, which kills the direction; [`DirectionError::Poisoned`]
    /// after that.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, KeyEpoch), DirectionError> {
        self.0.seal(plaintext, ad)
    }

    /// The handshake hash of the session this direction belongs to, stamped
    /// by [`SymmetricState::into_directions`](crate::SymmetricState::into_directions).
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.0.handshake_hash
    }
}

impl RecvDirection {
    /// Open `ciphertext` under this direction's next nonce.
    ///
    /// The epoch is the record key that opened it.
    ///
    /// # Errors
    ///
    /// [`DirectionError::Decrypt`] for a failed tag, which spends no nonce
    /// and kills the direction; [`DirectionError::State`] when the nonce
    /// cannot advance; [`DirectionError::Poisoned`] after either.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, KeyEpoch), DirectionError> {
        self.0.open(ciphertext, ad)
    }

    /// The handshake hash of the session this direction belongs to, stamped
    /// by [`SymmetricState::into_directions`](crate::SymmetricState::into_directions).
    ///
    /// A caller that lends a direction out and takes it back reads this to
    /// know it got its own session's direction back, and not another's: two
    /// sessions' directions are otherwise interchangeable values, and
    /// [`Self::opened`] counts only what a direction has opened, not for
    /// which session.
    ///
    /// **Precondition, stated:** the stamp tells sessions apart, and cannot
    /// be forged onto another session's direction, only because the
    /// handshake hash depends on a secret. In `hybridXK` it does: `skem`'s
    /// shared secret is mixed into it by `MixKeyAndHash`. A pattern whose
    /// hash took nothing secret would make this stamp a public value.
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.0.handshake_hash
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
        self.0.opened
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

    fn pair() -> (SendDirection, RecvDirection) {
        (SendDirection(keyed()), RecvDirection(keyed()))
    }

    /// The count the RPC handshake's pending session gates on: an opened
    /// ciphertext moves it, a failed tag does not, and a rekey leaves it.
    #[test]
    fn only_an_opened_ciphertext_is_counted() {
        for bad in 0..3 {
            let (mut send, mut recv) = pair();
            let (ct, _) = send.seal(b"body", b"ad").unwrap();
            let failed = match bad {
                0 => recv.open(&[0xa5; 48], b"ad"),
                1 => {
                    let mut tampered = ct.clone();
                    tampered[0] ^= 1;
                    recv.open(&tampered, b"ad")
                }
                _ => recv.open(&ct, b"other ad"),
            };
            assert_eq!(failed.unwrap_err(), DirectionError::Decrypt);
            assert_eq!(recv.opened(), 0, "a failed tag is not an open ({bad})");
        }

        let (mut send, mut recv) = pair();
        let (ct, _) = send.seal(b"body", b"ad").unwrap();
        recv.open(&ct, b"ad").unwrap();
        assert_eq!(recv.opened(), 1);
        send.0.force_nonce(REKEY_NONCES - 1);
        recv.0.force_nonce(REKEY_NONCES - 1);
        let (ct, _) = send.seal(b"boundary", b"ad").unwrap();
        recv.open(&ct, b"ad").unwrap();
        let (ct, _) = send.seal(b"after", b"ad").unwrap();
        recv.open(&ct, b"ad").unwrap();
        assert_eq!(recv.opened(), 3, "a rekey does not reset the count");
    }

    #[test]
    fn the_epoch_is_the_key_that_produced_the_ciphertext() {
        let (mut send, mut recv) = pair();
        let (ct, epoch) = send.seal(b"a", b"ad").unwrap();
        assert_eq!(epoch, KeyEpoch::INITIAL);
        let (pt, opened) = recv.open(&ct, b"ad").unwrap();
        assert_eq!(pt, b"a");
        assert_eq!(opened, KeyEpoch::INITIAL);

        let before = send.0.ck_and_k();
        send.0.force_nonce(REKEY_NONCES - 1);
        recv.0.force_nonce(REKEY_NONCES - 1);
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
        assert_ne!(send.0.ck_and_k(), before);
    }

    /// A failed tag spends no nonce and kills the direction: the ciphertext
    /// that was due next does not open either, and says why.
    #[test]
    fn a_bad_tag_kills_the_direction_without_spending_the_nonce() {
        let (mut send, mut recv) = pair();
        let (mut ct, _) = send.seal(b"a", b"ad").unwrap();
        let n_before = recv.0.next().0;
        ct[0] ^= 0xff;
        assert_eq!(recv.open(&ct, b"ad").unwrap_err(), DirectionError::Decrypt);
        assert_eq!(recv.0.next().0, n_before, "the nonce is not spent");
        ct[0] ^= 0xff;
        assert_eq!(
            recv.open(&ct, b"ad").unwrap_err(),
            DirectionError::Poisoned,
            "the right ciphertext does not open on a dead direction"
        );
    }

    /// A nonce that cannot advance after the AEAD step leaves the direction
    /// dead, on either side.
    #[test]
    fn a_state_failure_after_the_aead_step_kills_the_direction() {
        let (mut send, mut recv) = pair();
        send.0.force_nonce(u64::MAX);
        assert_eq!(send.seal(b"a", b"ad").unwrap_err(), DirectionError::State);
        assert_eq!(
            send.seal(b"a", b"ad").unwrap_err(),
            DirectionError::Poisoned
        );

        let ct = aead::seal(&Zeroizing::new([0x22; HASH_LEN]), u64::MAX, b"ad", b"a").unwrap();
        recv.0.force_nonce(u64::MAX);
        assert_eq!(recv.open(&ct, b"ad").unwrap_err(), DirectionError::State);
        assert_eq!(recv.open(&ct, b"ad").unwrap_err(), DirectionError::Poisoned);
    }

    /// Known answer for one rekey, computed independently in Python
    /// (`hmac` over `hashlib.blake2s`; shekyl-dev
    /// `scripts/rpc-channel/noise_vectors.py`): from chaining key 0x11..11
    /// and record key 0x22..22, the keys after REKEY_NONCES uses.
    #[test]
    fn one_rekey_matches_an_independent_implementation() {
        let (mut send, _) = pair();
        send.0.force_nonce(REKEY_NONCES - 1);
        send.seal(b"", b"").unwrap();
        let (ck, k) = send.0.ck_and_k();
        assert_eq!(hex(&ck), REKEY_CK);
        assert_eq!(hex(&k), REKEY_K);
    }

    const REKEY_CK: &str = "689595aed4202060b80a81db830fdc731a7db549f99f474b38c01aeaf5a00d83";
    const REKEY_K: &str = "33af33967dc440981ee10c21a2d67f1a37739b8738487a70e024c1b4a1549eeb";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
