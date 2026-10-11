// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s`: the RPC channel's
//! handshake (`docs/design/RPC_CHANNEL.md` §4.1).
//!
//! ```text
//! <- s                    the daemon's static bundle, known in advance
//! ...
//! -> skem, e, es          message 1   2,320 bytes
//! <- ekem, e, ee          message 2   2,320 bytes
//! -> s, se                message 3   1,264 bytes + payload
//! <- skem                 message 4   1,120 bytes + payload
//! ```
//!
//! `e` and `s` each carry an X25519 key and then an ML-KEM-768 key. Both
//! sides are authenticated by key agreement against both primitives: the
//! daemon when message 2 opens, the client classically when message 3 opens
//! and against both when its first transport record does.
//!
//! The type at each step is the only thing that step can do, and transport
//! keys exist only after message 4.
//!
//! # What a stranger can make the daemon do (§4.3)
//!
//! Message 1 is read before anything has authenticated. Reading it runs the
//! daemon's **long-term** keys on input the sender chose, so:
//!
//! - **One failure.** Every way message 1 can be wrong surfaces as
//!   [`HandshakeError::Message1`] and nothing else. In particular a
//!   ciphertext ML-KEM rejects and a ciphertext it accepts under a bad tag
//!   are the same error. Decapsulation does not fail on a rejected
//!   ciphertext; it returns a key nobody else has, and the tag then fails.
//!   That is the only way a rejection shows.
//! - **No reply.** The daemon writes nothing until message 1 has
//!   authenticated. [`Daemon::read_message1`] returns no bytes to send on
//!   failure, and the state it would have continued from is consumed.
//! - **A low-order `e` is refused before it is mixed**, at `es` here and at
//!   `ee` and `se` after. Its Diffie-Hellman result is all zero whatever the
//!   secret is, so mixing it would add nothing and accepting it would let a
//!   sender choose the result.
//! - **The client's ephemeral encapsulation key is checked** as FIPS 203
//!   requires before the daemon encapsulates to it.
//!
//! This crate writes no log line. What the listener logs about a failed
//! handshake is the listener's to keep uniform.
//!
//! # Randomness
//!
//! Every entry point draws from the operating system. The `_with_rng` forms
//! exist only under the `test-support` feature, for the cross-check that
//! drives this handshake from the seeded streams its pinned vectors were made
//! with; no build that ships has them.

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::{CryptoRngCore, OsRng};
use shekyl_noise::channel::halves;
use shekyl_noise::{RecvHalf, SendHalf, SymmetricState};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    prologue, static_fingerprint, NetworkId, StaticFingerprint, MLKEM768_EK_LEN, X25519_PUBLIC_LEN,
};

/// The Noise protocol name. It is hashed into the transcript, so it is part
/// of the wire format.
pub const PROTOCOL_NAME: &[u8] = b"Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s";

/// Length of an ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Length of a ChaCha20-Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Length of the handshake hash.
pub const HANDSHAKE_HASH_LEN: usize = 32;

/// Message 1: the `skem` ciphertext, both ephemeral keys, the empty
/// payload's tag.
pub const MESSAGE1_LEN: usize = MLKEM768_CT_LEN + X25519_PUBLIC_LEN + MLKEM768_EK_LEN + TAG_LEN;
/// Message 2: the `ekem` ciphertext, both ephemeral keys, the empty
/// payload's tag.
pub const MESSAGE2_LEN: usize = MLKEM768_CT_LEN + X25519_PUBLIC_LEN + MLKEM768_EK_LEN + TAG_LEN;
/// Message 3 without its payload: both statics, each sealed with its own
/// tag, and the payload's tag.
pub const MESSAGE3_OVERHEAD: usize =
    X25519_PUBLIC_LEN + TAG_LEN + MLKEM768_EK_LEN + TAG_LEN + TAG_LEN;
/// Message 4 without its payload: the sealed `skem` ciphertext and the
/// payload's tag.
pub const MESSAGE4_OVERHEAD: usize = MLKEM768_CT_LEN + TAG_LEN + TAG_LEN;

/// Why a handshake stopped.
///
/// One variant per message, and nothing finer. Which check inside a message
/// failed is not recorded anywhere: for message 1 that is a requirement
/// (§4.3), and for the others a finer answer would only be a finer oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// The daemon did not accept message 1. The sender gets no reply.
    Message1,
    /// The client did not accept message 2: whoever answered is not the
    /// daemon whose key the client holds, or is on another network.
    Message2,
    /// The daemon did not accept message 3.
    Message3,
    /// The client did not accept message 4.
    Message4,
    /// This side could not do its own part: the operating system gave no
    /// randomness, or a key it generated itself would not load. Nothing the
    /// peer sent causes this.
    Local,
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Message1 => "handshake message 1 was not accepted",
            Self::Message2 => "handshake message 2 was not accepted",
            Self::Message3 => "handshake message 3 was not accepted",
            Self::Message4 => "handshake message 4 was not accepted",
            Self::Local => "the handshake could not proceed on this side",
        })
    }
}

impl std::error::Error for HandshakeError {}

/// A static public bundle: an X25519 key and an ML-KEM-768 encapsulation
/// key, the latter already checked as FIPS 203 requires.
///
/// The daemon's is what every enrolled client holds. The client's is what
/// the daemon learns in message 3 and looks up.
#[derive(Clone)]
pub struct StaticPublic {
    x25519: [u8; X25519_PUBLIC_LEN],
    mlkem_ek_bytes: [u8; MLKEM768_EK_LEN],
    mlkem_ek: ml_kem_768::EncapsKey,
}

/// The two halves did not form a usable bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidStaticPublic;

impl core::fmt::Display for InvalidStaticPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a valid static public bundle")
    }
}

impl std::error::Error for InvalidStaticPublic {}

impl StaticPublic {
    /// Build a bundle from its two halves, checking the encapsulation key.
    ///
    /// # Errors
    ///
    /// When the encapsulation key fails FIPS 203's input check.
    pub fn from_parts(
        x25519: [u8; X25519_PUBLIC_LEN],
        mlkem_ek: [u8; MLKEM768_EK_LEN],
    ) -> Result<Self, InvalidStaticPublic> {
        let parsed =
            ml_kem_768::EncapsKey::try_from_bytes(mlkem_ek).map_err(|_| InvalidStaticPublic)?;
        Ok(Self {
            x25519,
            mlkem_ek_bytes: mlkem_ek,
            mlkem_ek: parsed,
        })
    }

    /// The X25519 half.
    pub fn x25519(&self) -> &[u8; X25519_PUBLIC_LEN] {
        &self.x25519
    }

    /// The ML-KEM-768 half, as it travels.
    pub fn mlkem_ek(&self) -> &[u8; MLKEM768_EK_LEN] {
        &self.mlkem_ek_bytes
    }

    /// The fingerprint an operator compares and an allowlist stores (§5).
    pub fn fingerprint(&self) -> StaticFingerprint {
        static_fingerprint(&self.x25519, &self.mlkem_ek_bytes)
    }
}

/// A long-term identity: both secret halves and the public bundle.
///
/// The secrets wipe themselves when this is dropped (`x25519-dalek`'s and
/// `fips203`'s types do it), and nothing here hands them out.
pub struct StaticKeypair {
    x25519: StaticSecret,
    mlkem_dk: ml_kem_768::DecapsKey,
    public: StaticPublic,
}

impl StaticKeypair {
    /// A new identity from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] when the generator fails.
    pub fn generate() -> Result<Self, HandshakeError> {
        Self::generate_from(&mut OsRng)
    }

    /// As [`Self::generate`], from the caller's generator. Test support.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] when the generator fails.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn generate_with_rng(rng: &mut impl CryptoRngCore) -> Result<Self, HandshakeError> {
        Self::generate_from(rng)
    }

    // X25519 first, then ML-KEM: the order a static bundle is sent in.
    fn generate_from(rng: &mut impl CryptoRngCore) -> Result<Self, HandshakeError> {
        let x25519 = StaticSecret::random_from_rng(&mut *rng);
        let (ek, mlkem_dk) =
            ml_kem_768::KG::try_keygen_with_rng(rng).map_err(|_| HandshakeError::Local)?;
        let public = StaticPublic::from_parts(PublicKey::from(&x25519).to_bytes(), ek.into_bytes())
            .map_err(|_| HandshakeError::Local)?;
        Ok(Self {
            x25519,
            mlkem_dk,
            public,
        })
    }

    /// The public bundle.
    pub fn public(&self) -> &StaticPublic {
        &self.public
    }
}

/// One side's ephemeral pair for one handshake.
struct Ephemeral {
    x25519: StaticSecret,
    mlkem_dk: ml_kem_768::DecapsKey,
    x25519_public: [u8; X25519_PUBLIC_LEN],
    mlkem_ek: [u8; MLKEM768_EK_LEN],
}

impl Ephemeral {
    // The X25519 scalar, then ML-KEM's `d` and `z`.
    fn generate(rng: &mut impl CryptoRngCore) -> Result<Self, HandshakeError> {
        let x25519 = StaticSecret::random_from_rng(&mut *rng);
        let (ek, mlkem_dk) =
            ml_kem_768::KG::try_keygen_with_rng(rng).map_err(|_| HandshakeError::Local)?;
        Ok(Self {
            x25519_public: PublicKey::from(&x25519).to_bytes(),
            mlkem_ek: ek.into_bytes(),
            x25519,
            mlkem_dk,
        })
    }
}

// Every use of a long-term secret while reading message 1 goes through
// `long_term_key_used`, which counts it under test. A message refused on
// public grounds must not move the count.
#[cfg(test)]
thread_local! {
    static LONG_TERM_USES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn long_term_key_used() {
    #[cfg(test)]
    LONG_TERM_USES.with(|count| count.set(count.get() + 1));
}

/// X25519, refusing a result the peer's key alone determined. `None` means
/// the peer sent a low-order point: the result is all zero whatever our
/// secret is, and it is never mixed.
fn dh(
    secret: &StaticSecret,
    public: &[u8; X25519_PUBLIC_LEN],
) -> Option<x25519_dalek::SharedSecret> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    shared.was_contributory().then_some(shared)
}

/// The state both sides start from: the protocol name, the prologue, and the
/// pre-message `<- s`.
fn initial_state(network_id: &NetworkId, daemon: &StaticPublic) -> SymmetricState {
    let mut sym = SymmetricState::new(PROTOCOL_NAME, &prologue(network_id));
    sym.mix_hash(daemon.x25519());
    sym.mix_hash(daemon.mlkem_ek());
    sym
}

fn array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

// ---------------------------------------------------------------- client

/// The client's entry point.
pub struct Client;

/// The client after message 1. The next call reads message 2.
pub struct ClientAwaitingMessage2<'a> {
    sym: SymmetricState,
    own: &'a StaticKeypair,
    ephemeral: Ephemeral,
}

/// The client after message 2: the daemon is authenticated. The next call
/// writes message 3.
pub struct ClientReadyForMessage3<'a> {
    sym: SymmetricState,
    own: &'a StaticKeypair,
    daemon_ephemeral: [u8; X25519_PUBLIC_LEN],
}

/// The client after message 3. The next call reads message 4.
pub struct ClientAwaitingMessage4<'a> {
    sym: SymmetricState,
    own: &'a StaticKeypair,
}

impl Client {
    /// Begin a handshake with the daemon whose bundle the client holds.
    /// Returns message 1.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] when randomness fails, or when the daemon's
    /// X25519 key is a low-order point: a bundle like that was never a
    /// daemon's, and the client says so before it sends anything.
    pub fn start<'a>(
        network_id: &NetworkId,
        own: &'a StaticKeypair,
        daemon: &StaticPublic,
    ) -> Result<(ClientAwaitingMessage2<'a>, Vec<u8>), HandshakeError> {
        Self::start_from(network_id, own, daemon, &mut OsRng)
    }

    /// As [`Self::start`], from the caller's generator. Test support.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn start_with_rng<'a>(
        network_id: &NetworkId,
        own: &'a StaticKeypair,
        daemon: &StaticPublic,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientAwaitingMessage2<'a>, Vec<u8>), HandshakeError> {
        Self::start_from(network_id, own, daemon, rng)
    }

    fn start_from<'a>(
        network_id: &NetworkId,
        own: &'a StaticKeypair,
        daemon: &StaticPublic,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientAwaitingMessage2<'a>, Vec<u8>), HandshakeError> {
        let mut sym = initial_state(network_id, daemon);
        let mut message = Vec::with_capacity(MESSAGE1_LEN);

        // skem: encapsulate to the daemon's static key. No cipher key yet,
        // so the ciphertext travels in the clear and is hashed.
        let (shared, ciphertext) = daemon
            .mlkem_ek
            .try_encaps_with_rng(rng)
            .map_err(|_| HandshakeError::Local)?;
        let sent = sym
            .encrypt_and_hash(&ciphertext.into_bytes())
            .map_err(|_| HandshakeError::Local)?;
        message.extend_from_slice(&sent);
        let shared = Zeroizing::new(shared.into_bytes());
        sym.mix_key_and_hash(&shared[..]);

        // e: both ephemeral public keys, hashed.
        let ephemeral = Ephemeral::generate(rng)?;
        sym.mix_hash(&ephemeral.x25519_public);
        message.extend_from_slice(&ephemeral.x25519_public);
        sym.mix_hash(&ephemeral.mlkem_ek);
        message.extend_from_slice(&ephemeral.mlkem_ek);

        // es
        let shared = dh(&ephemeral.x25519, daemon.x25519()).ok_or(HandshakeError::Local)?;
        sym.mix_key(shared.as_bytes());

        // The empty payload: its tag is what authenticates message 1.
        let tag = sym
            .encrypt_and_hash(&[])
            .map_err(|_| HandshakeError::Local)?;
        message.extend_from_slice(&tag);

        if message.len() != MESSAGE1_LEN {
            return Err(HandshakeError::Local);
        }
        Ok((
            ClientAwaitingMessage2 {
                sym,
                own,
                ephemeral,
            },
            message,
        ))
    }
}

impl<'a> ClientAwaitingMessage2<'a> {
    /// Read message 2. Success means the daemon holds the static keys the
    /// client was given.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Message2`] for every way message 2 can be wrong.
    pub fn read_message2(
        mut self,
        message2: &[u8],
    ) -> Result<ClientReadyForMessage3<'a>, HandshakeError> {
        const E: usize = MLKEM768_CT_LEN;
        const EKEM: usize = E + X25519_PUBLIC_LEN;
        const TAG: usize = EKEM + MLKEM768_EK_LEN;
        let fail = HandshakeError::Message2;
        if message2.len() != MESSAGE2_LEN {
            return Err(fail);
        }

        // ekem: the ciphertext is in the clear and hashed, then the secret
        // from our ephemeral decapsulation key is mixed.
        let ciphertext: [u8; MLKEM768_CT_LEN] = array(&message2[..E]).ok_or(fail)?;
        self.sym.mix_hash(&ciphertext);
        let ciphertext = ml_kem_768::CipherText::try_from_bytes(ciphertext).map_err(|_| fail)?;
        let shared = self
            .ephemeral
            .mlkem_dk
            .try_decaps(&ciphertext)
            .map_err(|_| fail)?;
        let shared = Zeroizing::new(shared.into_bytes());
        self.sym.mix_key(&shared[..]);

        // e: the daemon's ephemeral keys. Nothing in this pattern
        // encapsulates to its ML-KEM one; it is hashed because it was sent.
        let daemon_ephemeral: [u8; X25519_PUBLIC_LEN] = array(&message2[E..EKEM]).ok_or(fail)?;
        self.sym.mix_hash(&daemon_ephemeral);
        self.sym.mix_hash(&message2[EKEM..TAG]);

        // ee
        let shared = dh(&self.ephemeral.x25519, &daemon_ephemeral).ok_or(fail)?;
        self.sym.mix_key(shared.as_bytes());

        let payload = self
            .sym
            .decrypt_and_hash(&message2[TAG..])
            .map_err(|_| fail)?;
        if !payload.is_empty() {
            return Err(fail);
        }
        Ok(ClientReadyForMessage3 {
            sym: self.sym,
            own: self.own,
            daemon_ephemeral,
        })
    }
}

impl<'a> ClientReadyForMessage3<'a> {
    /// Write message 3, which carries the client's static bundle and
    /// `payload`, both sealed.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] only: nothing from the peer is read here.
    pub fn write_message3(
        mut self,
        payload: &[u8],
    ) -> Result<(ClientAwaitingMessage4<'a>, Vec<u8>), HandshakeError> {
        let fail = HandshakeError::Local;
        let mut message = Vec::with_capacity(MESSAGE3_OVERHEAD + payload.len());

        // s: each half sealed on its own.
        let sealed = self
            .sym
            .encrypt_and_hash(self.own.public.x25519())
            .map_err(|_| fail)?;
        message.extend_from_slice(&sealed);
        let sealed = self
            .sym
            .encrypt_and_hash(self.own.public.mlkem_ek())
            .map_err(|_| fail)?;
        message.extend_from_slice(&sealed);

        // se: our long-term X25519 key against the daemon's ephemeral, which
        // `ee` has already refused if it was low-order.
        let shared = dh(&self.own.x25519, &self.daemon_ephemeral).ok_or(fail)?;
        self.sym.mix_key(shared.as_bytes());

        let sealed = self.sym.encrypt_and_hash(payload).map_err(|_| fail)?;
        message.extend_from_slice(&sealed);

        if message.len() != MESSAGE3_OVERHEAD + payload.len() {
            return Err(fail);
        }
        Ok((
            ClientAwaitingMessage4 {
                sym: self.sym,
                own: self.own,
            },
            message,
        ))
    }
}

impl ClientAwaitingMessage4<'_> {
    /// Read message 4 and its payload. Success means the daemon admitted
    /// this client.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Message4`] for every way message 4 can be wrong.
    pub fn read_message4(
        mut self,
        message4: &[u8],
    ) -> Result<(Established, Vec<u8>), HandshakeError> {
        const SKEM: usize = MLKEM768_CT_LEN + TAG_LEN;
        let fail = HandshakeError::Message4;
        if message4.len() < MESSAGE4_OVERHEAD {
            return Err(fail);
        }

        // skem: the sealed ciphertext, opened, then decapsulated with our
        // long-term key. A ciphertext ML-KEM rejects yields a key the daemon
        // does not have, and the payload's tag fails.
        let ciphertext = self
            .sym
            .decrypt_and_hash(&message4[..SKEM])
            .map_err(|_| fail)?;
        let ciphertext: [u8; MLKEM768_CT_LEN] = array(&ciphertext).ok_or(fail)?;
        let ciphertext = ml_kem_768::CipherText::try_from_bytes(ciphertext).map_err(|_| fail)?;
        let shared = self
            .own
            .mlkem_dk
            .try_decaps(&ciphertext)
            .map_err(|_| fail)?;
        let shared = Zeroizing::new(shared.into_bytes());
        self.sym.mix_key_and_hash(&shared[..]);

        let payload = self
            .sym
            .decrypt_and_hash(&message4[SKEM..])
            .map_err(|_| fail)?;
        Ok((
            Established {
                sym: self.sym,
                initiator: true,
            },
            payload,
        ))
    }
}

// ---------------------------------------------------------------- daemon

/// The daemon before message 1.
pub struct Daemon<'a> {
    sym: SymmetricState,
    own: &'a StaticKeypair,
}

/// The daemon after message 1: the sender holds the daemon's bundle. The
/// next call writes message 2.
pub struct DaemonReadyForMessage2 {
    sym: SymmetricState,
    client_ephemeral: [u8; X25519_PUBLIC_LEN],
    client_ephemeral_ek: ml_kem_768::EncapsKey,
}

/// The daemon after message 2. The next call reads message 3.
pub struct DaemonAwaitingMessage3 {
    sym: SymmetricState,
    ephemeral: StaticSecret,
}

/// What message 3 told the daemon: who the client says it is, and what it
/// asked for.
///
/// The X25519 half is proven by `se` when this is returned. The ML-KEM half
/// is proven only when the client's first transport record opens. The daemon
/// decides admission on [`ClientHello::client`] and acts on nothing else
/// until that record.
pub struct ClientHello {
    /// The client's static bundle.
    pub client: StaticPublic,
    /// Message 3's payload.
    pub payload: Vec<u8>,
}

/// The daemon after message 3. The next call writes message 4, if the
/// daemon admits the client; dropping this instead refuses it.
pub struct DaemonReadyForMessage4 {
    sym: SymmetricState,
    client_ek: ml_kem_768::EncapsKey,
}

impl<'a> Daemon<'a> {
    /// A daemon ready to read one message 1.
    pub fn new(network_id: &NetworkId, own: &'a StaticKeypair) -> Self {
        Self {
            sym: initial_state(network_id, &own.public),
            own,
        }
    }

    /// Read message 1.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Message1`], for every cause. See the module
    /// documentation: nothing distinguishes one cause from another, and the
    /// caller has nothing to send.
    pub fn read_message1(
        mut self,
        message1: &[u8],
    ) -> Result<DaemonReadyForMessage2, HandshakeError> {
        const E: usize = MLKEM768_CT_LEN;
        const EKEM: usize = E + X25519_PUBLIC_LEN;
        const TAG: usize = EKEM + MLKEM768_EK_LEN;
        let fail = HandshakeError::Message1;
        if message1.len() != MESSAGE1_LEN {
            return Err(fail);
        }
        let ciphertext: [u8; MLKEM768_CT_LEN] = array(&message1[..E]).ok_or(fail)?;
        let client_ephemeral: [u8; X25519_PUBLIC_LEN] = array(&message1[E..EKEM]).ok_or(fail)?;
        let client_ephemeral_ek: [u8; MLKEM768_EK_LEN] = array(&message1[EKEM..TAG]).ok_or(fail)?;

        // FIPS 203's input check on the key message 2 will encapsulate to.
        // First, because it needs no secret and a key that fails it is
        // refused before either long-term key is used. The transcript hashes
        // the wire bytes, not what this parse returns.
        let client_ephemeral_ek =
            ml_kem_768::EncapsKey::try_from_bytes(client_ephemeral_ek).map_err(|_| fail)?;

        // skem: decapsulate with the long-term key. This cannot tell a
        // rejected ciphertext from an accepted one, by design: a rejected
        // one yields a pseudorandom secret, and the tag below fails. The
        // error arms here are for a ciphertext of the wrong size or a key
        // that will not decode, neither of which a sender can cause, and
        // they return the same error as everything else.
        self.sym.mix_hash(&ciphertext);
        let ciphertext = ml_kem_768::CipherText::try_from_bytes(ciphertext).map_err(|_| fail)?;
        long_term_key_used();
        let shared = self
            .own
            .mlkem_dk
            .try_decaps(&ciphertext)
            .map_err(|_| fail)?;
        let shared = Zeroizing::new(shared.into_bytes());
        self.sym.mix_key_and_hash(&shared[..]);

        // e
        self.sym.mix_hash(&message1[E..EKEM]);
        self.sym.mix_hash(&message1[EKEM..TAG]);

        // es: the long-term X25519 key against the sender's `e`.
        long_term_key_used();
        let shared = dh(&self.own.x25519, &client_ephemeral).ok_or(fail)?;
        self.sym.mix_key(shared.as_bytes());

        let payload = self
            .sym
            .decrypt_and_hash(&message1[TAG..])
            .map_err(|_| fail)?;
        if !payload.is_empty() {
            return Err(fail);
        }
        Ok(DaemonReadyForMessage2 {
            sym: self.sym,
            client_ephemeral,
            client_ephemeral_ek,
        })
    }
}

impl DaemonReadyForMessage2 {
    /// Write message 2.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] only.
    pub fn write_message2(self) -> Result<(DaemonAwaitingMessage3, Vec<u8>), HandshakeError> {
        self.write_from(&mut OsRng)
    }

    /// As [`Self::write_message2`], from the caller's generator. Test
    /// support.
    ///
    /// # Errors
    ///
    /// As [`Self::write_message2`].
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn write_message2_with_rng(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(DaemonAwaitingMessage3, Vec<u8>), HandshakeError> {
        self.write_from(rng)
    }

    fn write_from(
        mut self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(DaemonAwaitingMessage3, Vec<u8>), HandshakeError> {
        let fail = HandshakeError::Local;
        let mut message = Vec::with_capacity(MESSAGE2_LEN);

        // ekem: encapsulate to the client's ephemeral key. The ciphertext
        // travels in the clear and is hashed.
        let (shared, ciphertext) = self
            .client_ephemeral_ek
            .try_encaps_with_rng(rng)
            .map_err(|_| fail)?;
        let ciphertext = ciphertext.into_bytes();
        self.sym.mix_hash(&ciphertext);
        message.extend_from_slice(&ciphertext);
        let shared = Zeroizing::new(shared.into_bytes());
        self.sym.mix_key(&shared[..]);

        // e: the pattern sends an ephemeral ML-KEM key from this side too.
        // Nothing encapsulates to it (§4.1); its decapsulation key is
        // dropped here, and with it wiped.
        let ephemeral = Ephemeral::generate(rng)?;
        self.sym.mix_hash(&ephemeral.x25519_public);
        message.extend_from_slice(&ephemeral.x25519_public);
        self.sym.mix_hash(&ephemeral.mlkem_ek);
        message.extend_from_slice(&ephemeral.mlkem_ek);

        // ee. `es` already refused a low-order `e`; this is the same point.
        let shared = dh(&ephemeral.x25519, &self.client_ephemeral).ok_or(fail)?;
        self.sym.mix_key(shared.as_bytes());

        let tag = self.sym.encrypt_and_hash(&[]).map_err(|_| fail)?;
        message.extend_from_slice(&tag);

        if message.len() != MESSAGE2_LEN {
            return Err(fail);
        }
        Ok((
            DaemonAwaitingMessage3 {
                sym: self.sym,
                ephemeral: ephemeral.x25519,
            },
            message,
        ))
    }
}

impl DaemonAwaitingMessage3 {
    /// Read message 3: the client's static bundle and its payload.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Message3`] for every way message 3 can be wrong.
    pub fn read_message3(
        mut self,
        message3: &[u8],
    ) -> Result<(DaemonReadyForMessage4, ClientHello), HandshakeError> {
        const S_KEM: usize = X25519_PUBLIC_LEN + TAG_LEN;
        const PAYLOAD: usize = S_KEM + MLKEM768_EK_LEN + TAG_LEN;
        let fail = HandshakeError::Message3;
        if message3.len() < MESSAGE3_OVERHEAD {
            return Err(fail);
        }

        // s: each half opened on its own.
        let x25519 = self
            .sym
            .decrypt_and_hash(&message3[..S_KEM])
            .map_err(|_| fail)?;
        let x25519: [u8; X25519_PUBLIC_LEN] = array(&x25519).ok_or(fail)?;
        let mlkem_ek = self
            .sym
            .decrypt_and_hash(&message3[S_KEM..PAYLOAD])
            .map_err(|_| fail)?;
        let mlkem_ek: [u8; MLKEM768_EK_LEN] = array(&mlkem_ek).ok_or(fail)?;

        // se: a low-order static is refused before it is mixed.
        let shared = dh(&self.ephemeral, &x25519).ok_or(fail)?;
        self.sym.mix_key(shared.as_bytes());

        let payload = self
            .sym
            .decrypt_and_hash(&message3[PAYLOAD..])
            .map_err(|_| fail)?;

        // FIPS 203's input check on the key message 4 will encapsulate to.
        let client = StaticPublic::from_parts(x25519, mlkem_ek).map_err(|_| fail)?;
        Ok((
            DaemonReadyForMessage4 {
                sym: self.sym,
                client_ek: client.mlkem_ek.clone(),
            },
            ClientHello { client, payload },
        ))
    }
}

impl DaemonReadyForMessage4 {
    /// Write message 4, carrying `payload`. Call this only for a client the
    /// daemon admits.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] only.
    pub fn write_message4(self, payload: &[u8]) -> Result<(Established, Vec<u8>), HandshakeError> {
        self.write_from(payload, &mut OsRng)
    }

    /// As [`Self::write_message4`], from the caller's generator. Test
    /// support.
    ///
    /// # Errors
    ///
    /// As [`Self::write_message4`].
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn write_message4_with_rng(
        self,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Established, Vec<u8>), HandshakeError> {
        self.write_from(payload, rng)
    }

    fn write_from(
        mut self,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Established, Vec<u8>), HandshakeError> {
        let fail = HandshakeError::Local;
        let mut message = Vec::with_capacity(MESSAGE4_OVERHEAD + payload.len());

        // skem: encapsulate to the client's static key; the ciphertext is
        // sealed.
        let (shared, ciphertext) = self.client_ek.try_encaps_with_rng(rng).map_err(|_| fail)?;
        let sealed = self
            .sym
            .encrypt_and_hash(&ciphertext.into_bytes())
            .map_err(|_| fail)?;
        message.extend_from_slice(&sealed);
        let shared = Zeroizing::new(shared.into_bytes());
        self.sym.mix_key_and_hash(&shared[..]);

        let sealed = self.sym.encrypt_and_hash(payload).map_err(|_| fail)?;
        message.extend_from_slice(&sealed);

        if message.len() != MESSAGE4_OVERHEAD + payload.len() {
            return Err(fail);
        }
        Ok((
            Established {
                sym: self.sym,
                initiator: false,
            },
            message,
        ))
    }
}

// ------------------------------------------------------------- established

/// All four messages are done.
///
/// For the daemon this is not yet a hybrid-authenticated client: that comes
/// when the client's first transport record opens (§4.1). Nothing is served
/// before it does.
pub struct Established {
    sym: SymmetricState,
    initiator: bool,
}

impl Established {
    /// The handshake hash: a value both sides hold that is unique to this
    /// session. Not a secret.
    pub fn handshake_hash(&self) -> [u8; HANDSHAKE_HASH_LEN] {
        self.sym.handshake_hash()
    }

    /// Noise's `Split`: the two record halves. The client sends with the
    /// first transport key and the daemon with the second.
    pub fn split(self) -> (SendHalf, RecvHalf) {
        let keys = self.sym.split();
        if self.initiator {
            halves(keys.chaining_key, keys.first, keys.second)
        } else {
            halves(keys.chaining_key, keys.second, keys.first)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    const NETWORK: NetworkId = [0x42; 16];

    fn uses() -> u64 {
        LONG_TERM_USES.with(std::cell::Cell::get)
    }

    /// A daemon identity, and a message 1 it accepts.
    fn accepted_message1() -> (StaticKeypair, Vec<u8>) {
        let daemon = StaticKeypair::generate().unwrap();
        let client = StaticKeypair::generate().unwrap();
        let (_, message1) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
        (daemon, message1)
    }

    fn unhex(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap();
        }
        out
    }

    /// The encodings of the points of small order: every `u` for which
    /// X25519 returns zero whatever the scalar.
    fn low_order_points() -> Vec<[u8; 32]> {
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ]
        .into_iter()
        .map(unhex)
        .collect()
    }

    /// §4.3: a low-order point never yields a secret to mix, at any of the
    /// three Diffie-Hellman tokens, since all three go through `dh`.
    #[test]
    fn a_low_order_point_yields_nothing_to_mix() {
        let secret = StaticSecret::random_from_rng(OsRng);
        for point in low_order_points() {
            assert!(dh(&secret, &point).is_none(), "{point:02x?}");
        }
        let honest = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        assert!(dh(&secret, &honest).is_some());
    }

    /// §4.3: message 1 with a low-order `e` is refused, as message 1.
    ///
    /// This cannot tell the refusal from the tag failing: the sender made
    /// its tag with a different `e`, so the tag would fail anyway. That a
    /// low-order point is never mixed is what the test above shows, on the
    /// one function every Diffie-Hellman token goes through.
    #[test]
    fn message_1_with_a_low_order_ephemeral_is_refused() {
        for point in low_order_points() {
            let (daemon, mut message1) = accepted_message1();
            message1[MLKEM768_CT_LEN..MLKEM768_CT_LEN + X25519_PUBLIC_LEN].copy_from_slice(&point);
            assert_eq!(
                Daemon::new(&NETWORK, &daemon)
                    .read_message1(&message1)
                    .err(),
                Some(HandshakeError::Message1)
            );
        }
    }

    /// §4.3: the client's ephemeral encapsulation key is input-checked, and
    /// a key that fails the check is refused before either long-term key is
    /// used. The control shows the count moves when message 1 is good.
    #[test]
    fn a_malformed_encapsulation_key_is_refused_before_any_long_term_key_is_used() {
        let (daemon, good) = accepted_message1();

        let before = uses();
        assert!(Daemon::new(&NETWORK, &daemon).read_message1(&good).is_ok());
        assert_eq!(uses(), before + 2, "decapsulation and `es`, once each");

        let mut bad = good;
        let ek = MLKEM768_CT_LEN + X25519_PUBLIC_LEN;
        bad[ek..ek + MLKEM768_EK_LEN].fill(0xff);
        let before = uses();
        assert_eq!(
            Daemon::new(&NETWORK, &daemon).read_message1(&bad).err(),
            Some(HandshakeError::Message1)
        );
        assert_eq!(uses(), before, "no long-term key touched a malformed key");
    }

    /// A message of the wrong length is refused on its length alone.
    #[test]
    fn a_message_1_of_the_wrong_length_uses_no_long_term_key() {
        let (daemon, good) = accepted_message1();
        let long = [good.as_slice(), &[0]].concat();
        for wrong in [&good[..0], &good[..MESSAGE1_LEN - 1], long.as_slice()] {
            let before = uses();
            assert_eq!(
                Daemon::new(&NETWORK, &daemon).read_message1(wrong).err(),
                Some(HandshakeError::Message1)
            );
            assert_eq!(uses(), before);
        }
    }

    /// Rule 35: the secrets this module holds wipe themselves when dropped.
    /// The chaining key and the cipher key are `Zeroizing` in
    /// `shekyl-noise`'s symmetric state.
    ///
    /// `fips203`'s types carry the `ZeroizeOnDrop` marker. `x25519-dalek`'s
    /// do not: they derive `Zeroize` with `#[zeroize(drop)]`, which wipes on
    /// drop without the marker, and only when that crate's `zeroize` feature
    /// is on. `Zeroize` is implemented for them exactly when it is, so this
    /// stops compiling if a manifest ever turns that feature off.
    #[test]
    fn the_secret_types_wipe_on_drop() {
        fn marked<T: ZeroizeOnDrop>() {}
        fn wiping_feature_is_on<T: zeroize::Zeroize>() {}
        marked::<ml_kem_768::DecapsKey>();
        marked::<fips203::SharedSecretKey>();
        wiping_feature_is_on::<StaticSecret>();
        wiping_feature_is_on::<x25519_dalek::SharedSecret>();
    }
}
