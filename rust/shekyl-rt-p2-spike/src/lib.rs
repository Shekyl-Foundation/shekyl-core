// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DISPOSABLE probe: **RT-P2** — pinned mutual TLS in the shape
//! `shekyl-wallet-rpc` uses (rustls under tokio-rustls under axum), with the
//! wrong-pin **bite check** (`RPC_TRANSPORT_POSTURE.md` §7.1).
//!
//! RT-4 is ruled: each endpoint generates its own keypair, the client pins the
//! server's SPKI fingerprint, the server holds an allowlist of client SPKI
//! fingerprints, no CA. This crate exists to demonstrate, before RT-W4 builds
//! on the ruling, that every refusal the ruling relies on can be **observed**
//! — a pinning harness that never observes a rejection is a check that cannot
//! fail:
//!
//! 1. Correct pins connect, both directions.
//! 2. A wrong **server** pin is rejected **at the handshake, before the client
//!    writes a byte** — for a channel that will carry a passphrase, "the
//!    handshake failed" and "the passphrase never left the process" are
//!    different claims, and only the second is the security property. Asserted
//!    on both sides: the client's error is the handshake variant, and the
//!    server counts zero handler hits and one refusal *by the peer*.
//! 3. A client whose key is **not in the allowlist** is refused by the server,
//!    and so is a client that presents **no certificate at all**: client
//!    authentication being mandatory is observed, not read off a flag.
//! 4. The rejection is **distinguishable in the error type** (rule 82): a pin
//!    mismatch is a typed value a caller can match on, not a generic
//!    connection failure a user would retry into a real interception.
//! 5. A client presenting an **enrolled certificate without its private key**
//!    is refused: the allowlist says yes, proof of possession says no. This is
//!    the misuse a custom verifier invites (below), so it is observed rather
//!    than trusted.
//! 6. One peer that connects and never speaks does not stop the next one:
//!    handshakes run per connection, under a deadline, off the accept loop.
//!
//! # Why this goes through `dangerous()`, and why that is correct here
//!
//! Installing a custom server-certificate verifier in rustls goes through
//! `ClientConfig::builder().dangerous().with_custom_certificate_verifier`. The
//! name exists because the overwhelmingly common misuse of that surface is the
//! **null verifier** — accept anything, which turns TLS into an unauthenticated
//! channel. A *pin* verifier is the opposite end of that axis: it accepts
//! exactly **one** public key, rather than any key a CA in the WebPKI store
//! will sign. For a two-party, operator-to-operator relationship with no
//! delegation, that is strictly stronger than WebPKI, not weaker. The danger
//! the API name warns about is the thing this verifier refuses.
//!
//! **The actual hazard of a custom verifier is subtler than the name:** the
//! verifier must still check the handshake *signature* — that the peer holds
//! the private key for the certificate it presented. A pin verifier that
//! matched the public key and skipped `verify_tls13_signature` would accept
//! anyone who merely *replayed* the pinned certificate. Both verifiers here
//! delegate signature verification to the crypto provider's algorithms
//! (`rustls::crypto::verify_tls13_signature`), so pinning decides *which* key
//! is trusted and the provider decides whether the peer *has* it — and probe
//! 5 replays an enrolled certificate under a different key to watch that
//! refusal happen. The edit that turns probe 5 red is the null signature
//! check.
//!
//! # What is pinned, exactly
//!
//! The SHA-256 of the certificate's `SubjectPublicKeyInfo` (DER), not of the
//! whole certificate: a self-signed certificate can be re-issued (new validity
//! window, new serial) without changing the key, and an operator pairs with a
//! *key*, not with a particular signature over it. Certificate validity dates
//! are not checked — the pin is the enrolment, and a paired device does not
//! stop being paired at midnight on some date the operator never chose
//! (enrolment lifecycle is RT-7's, not the verifier's). The SPKI is read
//! through rustls's own parser ([`ParsedCertificate`]), the same parser that
//! later checks the handshake signature over the certificate, so the pin and
//! the proof of possession agree on which bytes are "the key" by construction.
//!
//! # Protocol posture: asserted where an assertion can fail
//!
//! TLS 1.3 only (`with_protocol_versions(&[&TLS13])`), read back from the
//! connection by probe 1. Resumption is off on the client and session tickets
//! are off on the server, so early data (0-RTT, RT-5) has nothing to ride and
//! the allowlist runs on **every** handshake: a resumed TLS 1.3 handshake
//! restores the client certificate from the ticket and never calls the
//! verifier, so with tickets the allowlist would run at first contact only.
//! Forward secrecy is **not** asserted by a probe. rustls offers only
//! `psk_dhe_ke` and has no static key exchange, so every completed handshake
//! has an (EC)DHE group and no edit to this crate could make such an assertion
//! go red — it would be a check that cannot fail (rule 50). It holds by
//! construction of the dependency, and that is recorded here instead of being
//! dressed as an observation.
//!
//! # RT-P1, recorded alongside (pre-registered as non-load-bearing)
//!
//! Does the pinned rustls (0.23.37) expose an **external** (out-of-band) PSK
//! API? **No.** Read from the source rather than the docs: the only public
//! item mentioning PSK is the wire enum `PskKeyExchangeMode`; `ClientConfig`
//! exposes `resumption` (session tickets) and no external-PSK configuration.
//! Per the probe's pre-registration the result cannot change RT-4 either way;
//! this is "what support actually was".

#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::future::IntoFuture as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::sign::CertifiedKey;
use rustls::{
    AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName,
    Error as TlsError, OtherError, ServerConfig, SignatureScheme,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

/// SHA-256 over the certificate's `SubjectPublicKeyInfo` (DER).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpkiFingerprint([u8; 32]);

impl SpkiFingerprint {
    /// The fingerprint of the key a certificate carries, via rustls's own
    /// parser. A certificate it cannot parse is rustls's
    /// `InvalidCertificate(BadEncoding)`, not a [`PinError`]: no policy
    /// verdict was reached, so none is claimed.
    pub fn of_cert(cert: &CertificateDer<'_>) -> Result<Self, TlsError> {
        let spki = ParsedCertificate::try_from(cert)?.subject_public_key_info();
        Ok(Self(Sha256::digest(spki.as_ref()).into()))
    }
}

impl fmt::Debug for SpkiFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpkiFingerprint({self})")
    }
}

impl fmt::Display for SpkiFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Why a peer was refused by a pin or allowlist check — a policy verdict and
/// nothing else. Typed, so a caller can tell "this is not the host you paired
/// with" from "the network is down" (rule 82): the first must never be
/// retried into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The server presented a key other than the one this client was paired
    /// with — a different wallet host, or an interception.
    ServerPinMismatch {
        /// The fingerprint this client pinned at enrolment.
        expected: SpkiFingerprint,
        /// The fingerprint the server presented.
        found: SpkiFingerprint,
    },
    /// The client presented a key that is not in the server's allowlist.
    ClientNotEnrolled {
        /// The fingerprint the client presented.
        found: SpkiFingerprint,
    },
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerPinMismatch { expected, found } => write!(
                f,
                "the wallet host's key is not the one this device was paired with \
                 (paired {expected}, presented {found}). This is a different host or an \
                 interception — do not retry; re-pair only if you know why it changed."
            ),
            Self::ClientNotEnrolled { found } => write!(
                f,
                "a device with key {found} is not enrolled on this wallet host; enrol it \
                 first."
            ),
        }
    }
}

impl std::error::Error for PinError {}

impl From<PinError> for TlsError {
    fn from(e: PinError) -> Self {
        Self::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
    }
}

/// Recover the typed refusal from a rustls error, if that is what it carries.
#[must_use]
pub fn pin_error_of(err: &TlsError) -> Option<&PinError> {
    match err {
        TlsError::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
            inner.downcast_ref::<PinError>()
        }
        _ => None,
    }
}

/// The client's verifier: exactly one server key is acceptable.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected: SpkiFingerprint,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    /// Pin `expected`; signature checks delegate to `provider_algs`.
    #[must_use]
    pub fn new(expected: SpkiFingerprint, provider_algs: WebPkiSupportedAlgorithms) -> Self {
        Self {
            expected,
            algs: provider_algs,
        }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // The pin IS the identity; the name the client typed, the chain, OCSP
        // and the validity window are WebPKI concepts with no role in a pairing.
        let found = SpkiFingerprint::of_cert(end_entity)?;
        if found != self.expected {
            return Err(PinError::ServerPinMismatch {
                expected: self.expected,
                found,
            }
            .into());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Proof of possession: the peer signed the transcript with the key the
        // pin accepted. Skipping this is the real misuse of a custom verifier.
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The server's verifier: client authentication is mandatory and the client's
/// key must be enrolled.
#[derive(Debug)]
pub struct AllowlistClientVerifier {
    allowed: BTreeSet<SpkiFingerprint>,
    algs: WebPkiSupportedAlgorithms,
}

impl AllowlistClientVerifier {
    /// Accept exactly the keys in `allowed`.
    #[must_use]
    pub fn new(
        allowed: BTreeSet<SpkiFingerprint>,
        provider_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            allowed,
            algs: provider_algs,
        }
    }
}

impl ClientCertVerifier for AllowlistClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA, so no issuer hints: the client has one identity to offer.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let found = SpkiFingerprint::of_cert(end_entity)?;
        if !self.allowed.contains(&found) {
            return Err(PinError::ClientNotEnrolled { found }.into());
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A freshly generated endpoint identity: self-signed certificate, its private
/// key, and the fingerprint the *other* side pins.
///
/// # Secret hygiene (rule 35): what wipes, and the two residuals
///
/// What this type wipes: the PKCS#8 DER it holds (`Zeroizing<PrivateKeyDer>`;
/// `rustls-pki-types` implements `Zeroize` for it), and rcgen's serialized
/// copy during generation (`KeyPair` is held in a `Zeroizing`; rcgen's
/// `zeroize` feature wipes the DER it keeps). The exported DER is **moved**,
/// not copied, into [`PrivateKeyDer`].
///
/// What it cannot wipe, recorded for RT-W4 rather than hidden:
///
/// 1. **The ring scalar.** rcgen's `KeyPair` holds a `ring::EcdsaKeyPair`
///    whose private scalar lives in ring's own allocation; rcgen's `Zeroize`
///    touches only the DER, and ring has no zeroize-on-drop. The same holds
///    for the signing key rustls parses from the DER for the config's
///    lifetime. Closing this means a key source that is not ring, or ring
///    growing a wiping drop; RT-W4 decides which.
/// 2. **rustls's DER copy.** pki-types provides `Zeroize` but no `Drop`, so
///    the copy rustls takes through `with_single_cert` /
///    `with_client_auth_cert` (`clone_key()` here) is dropped unwiped on
///    rustls's side once it has parsed the key. RT-W4 re-checks this against
///    the pki-types version it pins.
pub struct Identity {
    /// The self-signed certificate.
    pub cert: CertificateDer<'static>,
    /// Its private key (PKCS#8), wiped on drop.
    pub key: Zeroizing<PrivateKeyDer<'static>>,
    /// What the peer enrols.
    pub fingerprint: SpkiFingerprint,
}

impl Identity {
    /// Generate a new identity. The name is cosmetic — nothing verifies it.
    pub fn generate(name: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
        // The DER rcgen keeps is wiped when this scope ends (feature
        // `zeroize`); the ring scalar inside is residual 1 above.
        let signing_key = Zeroizing::new(signing_key);
        let cert = cert.der().clone();
        // `serialize_der` allocates the export; it moves straight into the
        // key type, so there is no second copy to lose track of.
        let key = Zeroizing::new(PrivateKeyDer::try_from(signing_key.serialize_der())?);
        let fingerprint = SpkiFingerprint::of_cert(&cert)?;
        Ok(Self {
            cert,
            key,
            fingerprint,
        })
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The server side of RT-4: TLS 1.3 only, this identity, client auth
/// mandatory against `allowlist`, no session tickets.
pub fn server_config(
    identity: &Identity,
    allowlist: BTreeSet<SpkiFingerprint>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = provider();
    let algs = provider.signature_verification_algorithms;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AllowlistClientVerifier::new(allowlist, algs)))
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    // No tickets: a resumed TLS 1.3 handshake restores the client certificate
    // from the ticket and never calls the verifier, so with tickets the
    // allowlist would run at first contact only. Off, it runs on every
    // handshake by construction — not because the allowlist and the session
    // cache happen to share one immutable config.
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

/// The client builder every client config shares: TLS 1.3 only, pins
/// `server_pin`. What the client *presents* is the caller's choice.
fn pinned_client_builder(
    server_pin: SpkiFingerprint,
) -> Result<
    (
        rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
        Arc<CryptoProvider>,
    ),
    TlsError,
> {
    let provider = provider();
    let algs = provider.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(server_pin, algs)));
    Ok((builder, provider))
}

/// Resumption disabled so there is nothing for 0-RTT to ride (RT-5).
fn finish_client(mut config: ClientConfig) -> Arc<ClientConfig> {
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

/// The client side of RT-4: pins `server_pin`, presents this identity.
pub fn client_config(
    identity: &Identity,
    server_pin: SpkiFingerprint,
) -> Result<Arc<ClientConfig>, TlsError> {
    let (builder, _) = pinned_client_builder(server_pin)?;
    let config =
        builder.with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    Ok(finish_client(config))
}

/// A client that pins `server_pin` but presents **no** certificate — what a
/// non-enrolled device, or a plain HTTPS client, looks like to the server.
pub fn client_config_without_identity(
    server_pin: SpkiFingerprint,
) -> Result<Arc<ClientConfig>, TlsError> {
    let (builder, _) = pinned_client_builder(server_pin)?;
    Ok(finish_client(builder.with_no_client_auth()))
}

/// A client-certificate resolver that presents one certificate and signs with
/// whatever key it was given — the replay attacker's tool, built only so a
/// probe can watch proof of possession refuse it. rustls's
/// `with_client_auth_cert` refuses a key that does not match the certificate
/// at config time, which is why the mismatch has to come in through a
/// resolver, the one door rustls leaves open for the caller to be wrong.
#[derive(Debug)]
struct PresentsExactly(Arc<CertifiedKey>);

impl ResolvesClientCert for PresentsExactly {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A client that presents `presented` (someone else's, enrolled certificate)
/// but can only sign with `signer`'s key. The allowlist will accept the
/// certificate; the CertificateVerify over the transcript cannot verify
/// under its key. Probe 5's attacker.
pub fn client_config_replaying(
    presented: &CertificateDer<'static>,
    signer: &Identity,
    server_pin: SpkiFingerprint,
) -> Result<Arc<ClientConfig>, TlsError> {
    let (builder, provider) = pinned_client_builder(server_pin)?;
    let key = provider
        .key_provider
        .load_private_key(signer.key.clone_key())?;
    let certified = CertifiedKey::new(vec![presented.clone()], key);
    let config = builder.with_client_cert_resolver(Arc::new(PresentsExactly(Arc::new(certified))));
    Ok(finish_client(config))
}

/// How long a connected peer has to finish the TLS handshake before it is
/// dropped and counted. Probe-scale; RT-W4 chooses the production value.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Everything the listener counts. Each counter is one axis a probe asserts
/// on, and every probe requires the others to be zero, so a refusal filed
/// under the wrong axis is a red test, not a rounding error.
#[derive(Clone, Default)]
struct Counters {
    refused_by_us: Arc<AtomicUsize>,
    refused_by_peer: Arc<AtomicUsize>,
    possession_failures: Arc<AtomicUsize>,
    handshake_timeouts: Arc<AtomicUsize>,
    accept_errors: Arc<AtomicUsize>,
}

impl Counters {
    /// File a failed handshake under the one counter it belongs to.
    fn record_handshake_failure(&self, err: &std::io::Error) {
        let counter = match rustls_error_in(err) {
            // Ours: the verifier's typed verdict, or the client sent no
            // certificate where one is mandatory (rustls's own refusal,
            // `certificate_required` on the wire).
            Some(e) if pin_error_of(&e).is_some() => &self.refused_by_us,
            Some(TlsError::NoCertificatesPresented) => &self.refused_by_us,
            // Theirs: a wrong server pin makes the client's verifier return
            // `CertificateError::Other`, which rustls sends as exactly
            // `certificate_unknown`. Only that alert counts: any other
            // certificate-class alert is a peer that disliked our certificate
            // for a reason that is not a pin verdict, and a peer can send any
            // alert it likes.
            Some(TlsError::AlertReceived(AlertDescription::CertificateUnknown)) => {
                &self.refused_by_peer
            }
            // The certificate passed the allowlist; the CertificateVerify
            // over the transcript did not: a replayed certificate without its
            // key. Its own axis, because it is the hazard the module doc
            // names, and filing it under "policy" would hide it.
            Some(TlsError::InvalidCertificate(CertificateError::BadSignature)) => {
                &self.possession_failures
            }
            _ => &self.accept_errors,
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

/// axum's split: these are one peer's problem and cost the next peer
/// nothing; everything else (EMFILE, ENOBUFS) is the listener's and backs off.
fn is_connection_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(
        e.kind(),
        K::ConnectionRefused | K::ConnectionAborted | K::ConnectionReset
    )
}

type Accepted = (tokio_rustls::server::TlsStream<TcpStream>, SocketAddr);

/// Accept TCP connections and hand each to its own handshake task, so a
/// peer that connects and stalls holds only its own task, never the loop.
/// Completed handshakes go to the listener through `ready`; failed ones are
/// counted where they belong.
async fn accept_loop(
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    ready: mpsc::Sender<Accepted>,
    counters: Counters,
) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Counted, so a listener that can accept nothing is
                // observable rather than a quiet epoch.
                counters.accept_errors.fetch_add(1, Ordering::SeqCst);
                if !is_connection_error(&e) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let ready = ready.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                // A closed receiver means the listener is gone; the
                // connection drops with it.
                Ok(Ok(tls)) => drop(ready.send((tls, peer)).await),
                Ok(Err(e)) => counters.record_handshake_failure(&e),
                Err(_elapsed) => {
                    counters.handshake_timeouts.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }
}

/// TLS over TCP as an axum listener. axum only ever sees connections whose
/// client passed the allowlist, and the handshake that decides that runs in a
/// per-connection task under [`HANDSHAKE_TIMEOUT`], not in `accept`: axum
/// awaits `accept` serially and spawns only afterwards, so a handshake
/// awaited inline would let one silent peer park every later client.
pub struct TlsListener {
    local_addr: SocketAddr,
    ready: mpsc::Receiver<Accepted>,
    accept_loop: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    async fn bind(
        addr: SocketAddr,
        acceptor: TlsAcceptor,
        counters: Counters,
    ) -> std::io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        let local_addr = tcp.local_addr()?;
        let (tx, ready) = mpsc::channel(32);
        let accept_loop = tokio::spawn(accept_loop(tcp, acceptor, tx, counters));
        Ok(Self {
            local_addr,
            ready,
            accept_loop,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            // Every sender lives in the accept loop or a task it spawned, and
            // the loop is aborted only when this listener drops — so this arm
            // is unreachable in practice. axum's contract is infallible; park
            // rather than fabricate a connection.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

/// A running probe server. Every counter is one probe's axis.
pub struct Served {
    /// Where it listens.
    pub addr: SocketAddr,
    /// Requests that reached the handler — must stay 0 for every refusal.
    pub hits: Arc<AtomicUsize>,
    /// Handshakes our allowlist refused, or that presented no certificate.
    pub refused_by_us: Arc<AtomicUsize>,
    /// Handshakes the peer refused with `certificate_unknown` — its pin of us
    /// did not match.
    pub refused_by_peer: Arc<AtomicUsize>,
    /// Enrolled certificate, wrong key: the CertificateVerify failed.
    pub possession_failures: Arc<AtomicUsize>,
    /// Peers that connected and did not finish the handshake in time.
    pub handshake_timeouts: Arc<AtomicUsize>,
    /// TCP accept failures and handshake failures that fit no axis above.
    pub accept_errors: Arc<AtomicUsize>,
    /// The serve task.
    pub task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// Serve one `GET /` route over pinned mutual TLS.
pub async fn serve(
    identity: &Identity,
    allowlist: BTreeSet<SpkiFingerprint>,
) -> Result<Served, Box<dyn std::error::Error + Send + Sync>> {
    let counters = Counters::default();
    let listener = TlsListener::bind(
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
        TlsAcceptor::from(server_config(identity, allowlist)?),
        counters.clone(),
    )
    .await?;
    let addr = listener.local_addr;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                "ok"
            }
        }),
    );
    let task = tokio::spawn(axum::serve(listener, app).into_future());
    Ok(Served {
        addr,
        hits,
        refused_by_us: counters.refused_by_us,
        refused_by_peer: counters.refused_by_peer,
        possession_failures: counters.possession_failures,
        handshake_timeouts: counters.handshake_timeouts,
        accept_errors: counters.accept_errors,
        task,
    })
}

/// Where a dial failed. The split is the point: a handshake failure means
/// **no application byte was written**; anything after is a different claim.
/// The variant is decided by **which call failed**, never by what the error
/// happens to carry: every error from `connect()` is a handshake-stage
/// failure whether or not a `rustls::Error` can be recovered from it.
#[derive(Debug)]
pub enum DialError {
    /// TCP connect failed — no TLS was attempted.
    Connect(std::io::Error),
    /// `TlsConnector::connect` failed: the handshake did not complete and
    /// nothing was written. Use [`rustls_error_in`] to recover the typed
    /// rustls error it usually wraps, and [`pin_error_of`] on that for a pin
    /// mismatch.
    Handshake(std::io::Error),
    /// `connect()` returned `Ok` and the failure came afterwards. In TLS 1.3
    /// the server's refusal of *our* certificate always arrives here: the
    /// client's Finished precedes the server's verdict, and `connect()`
    /// returns once the client is no longer handshaking.
    AfterHandshake(std::io::Error),
}

/// What a successful dial observed.
#[derive(Debug)]
pub struct Dialed {
    /// The HTTP response body.
    pub body: String,
    /// The negotiated protocol version.
    pub version: Option<rustls::ProtocolVersion>,
}

/// `GET /` over pinned mutual TLS, HTTP/1.1 `Connection: close`.
pub async fn dial(addr: SocketAddr, config: Arc<ClientConfig>) -> Result<Dialed, DialError> {
    let tcp = TcpStream::connect(addr).await.map_err(DialError::Connect)?;
    let name = ServerName::try_from("rt-p2.probe".to_owned()).expect("static name parses");
    let mut tls = TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(DialError::Handshake)?;
    let version = tls.get_ref().1.protocol_version();
    let request = b"GET / HTTP/1.1\r\nHost: rt-p2.probe\r\nConnection: close\r\n\r\n";
    tls.write_all(request)
        .await
        .map_err(DialError::AfterHandshake)?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw)
        .await
        .map_err(DialError::AfterHandshake)?;
    let text = String::from_utf8_lossy(&raw);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok(Dialed { body, version })
}

/// The rustls error tokio-rustls wraps in an `io::Error`, if any.
#[must_use]
pub fn rustls_error_in(err: &std::io::Error) -> Option<TlsError> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
        .cloned()
}
