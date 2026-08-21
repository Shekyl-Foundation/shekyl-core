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
//! fingerprints, no CA. This crate exists to demonstrate four things before
//! RT-W4 builds on the ruling, and the order matters — the rejections are the
//! half that matters, because a pinning harness that never observes a
//! rejection is a check that cannot fail:
//!
//! 1. Correct pins connect, both directions.
//! 2. A wrong **server** pin is rejected **at the handshake, before the client
//!    writes a byte** — for a channel that will carry a passphrase, "the
//!    handshake failed" and "the passphrase never left the process" are
//!    different claims, and only the second is the security property. Asserted
//!    on both sides: the client's error is the handshake variant, and the
//!    server counts zero handler hits and one rejected handshake.
//! 3. A client whose key is **not in the allowlist** is refused, same standard
//!    server-side.
//! 4. The rejection is **distinguishable in the error type** (rule 82): a pin
//!    mismatch is a typed value a caller can match on, not a generic
//!    connection failure a user would retry into a real interception.
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
//! **The actual hazard of a custom verifier is subtler than the name** and is
//! handled explicitly: the verifier must still check the handshake
//! *signature* — that the peer holds the private key for the certificate it
//! presented. A pin verifier that matched the public key and skipped
//! `verify_tls13_signature` would accept anyone who merely *replayed* the
//! pinned certificate. Both verifiers here delegate signature verification to
//! the crypto provider's algorithms (`rustls::crypto::verify_tls13_signature`),
//! so pinning decides *which* key is trusted and the provider decides whether
//! the peer *has* it.
//!
//! # What is pinned, exactly
//!
//! The SHA-256 of the certificate's `SubjectPublicKeyInfo` (DER), not of the
//! whole certificate: a self-signed certificate can be re-issued (new validity
//! window, new serial) without changing the key, and an operator pairs with a
//! *key*, not with a particular signature over it. Certificate validity dates
//! are not checked — the pin is the enrolment, and a paired device does not
//! stop being paired at midnight on some date the operator never chose
//! (enrolment lifecycle is RT-7's, not the verifier's).
//!
//! # Protocol posture asserted, not assumed
//!
//! TLS 1.3 only (`with_protocol_versions(&[&TLS13])`); resumption disabled on
//! the client, so early data (0-RTT, RT-5) has no ticket to ride; the
//! negotiated key-exchange group is read back and must be present (an (EC)DHE
//! share was agreed — forward secrecy is a property of the handshake that
//! happened, not of a setting).
//!
//! # RT-P1, recorded alongside (pre-registered as non-load-bearing)
//!
//! Does the pinned rustls (0.23.37) expose an **external** (out-of-band) PSK
//! API? **No.** Read from the source rather than the docs: the only public
//! item mentioning PSK is the wire enum `PskKeyExchangeMode`; `ClientConfig`
//! exposes `resumption` (session tickets) and no external-PSK configuration.
//! Per the probe's pre-registration the result cannot change RT-4 either way;
//! this is "what support actually was".

use std::collections::BTreeSet;
use std::fmt;
use std::future::IntoFuture as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError,
    OtherError, ServerConfig, SignatureScheme,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::FromDer as _;

/// SHA-256 over the certificate's `SubjectPublicKeyInfo` (DER).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpkiFingerprint([u8; 32]);

impl SpkiFingerprint {
    /// The fingerprint of the key a certificate carries.
    pub fn of_cert(cert: &CertificateDer<'_>) -> Result<Self, PinError> {
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
            .map_err(|e| PinError::Unparseable(e.to_string()))?;
        let spki = parsed.public_key().raw;
        Ok(Self(Sha256::digest(spki).into()))
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

/// Why a peer was refused by a pin or allowlist check. Typed, so a caller can
/// tell "this is not the host you paired with" from "the network is down"
/// (rule 82): the first must never be retried into.
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
    /// The certificate could not be parsed far enough to find its key.
    Unparseable(String),
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
            Self::Unparseable(detail) => {
                write!(f, "peer certificate could not be parsed: {detail}")
            }
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
pub struct Identity {
    /// The self-signed certificate.
    pub cert: CertificateDer<'static>,
    /// Its private key (PKCS#8).
    pub key: PrivateKeyDer<'static>,
    /// What the peer enrols.
    pub fingerprint: SpkiFingerprint,
}

impl Identity {
    /// Generate a new identity. The name is cosmetic — nothing verifies it.
    pub fn generate(name: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let ck = rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
        let cert = ck.cert.der().clone();
        let key = PrivateKeyDer::try_from(ck.signing_key.serialize_der())?;
        let fingerprint = SpkiFingerprint::of_cert(&cert)?;
        Ok(Self {
            cert,
            key,
            fingerprint,
        })
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The server side of RT-4: TLS 1.3 only, this identity, client auth
/// mandatory against `allowlist`.
pub fn server_config(
    identity: &Identity,
    allowlist: BTreeSet<SpkiFingerprint>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = provider();
    let algs = provider.signature_verification_algorithms;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AllowlistClientVerifier::new(allowlist, algs)))
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    Ok(Arc::new(config))
}

/// The client side of RT-4: TLS 1.3 only, pins `server_pin`, presents this
/// identity, resumption disabled so there is nothing for 0-RTT to ride.
pub fn client_config(
    identity: &Identity,
    server_pin: SpkiFingerprint,
) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = provider();
    let algs = provider.signature_verification_algorithms;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(server_pin, algs)))
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// TLS over TCP as an axum listener: the handshake happens in `accept`, so
/// axum only ever sees connections whose client passed the allowlist. Failed
/// handshakes are counted — that counter is the server-side half of the bite
/// check.
pub struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    rejected: Arc<AtomicUsize>,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((tcp, peer)) = self.tcp.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            };
            match self.acceptor.accept(tcp).await {
                Ok(tls) => return (tls, peer),
                Err(_) => {
                    self.rejected.fetch_add(1, Ordering::SeqCst);
                    // Each iteration awaits a fresh TCP connection, so this is
                    // work proportional to inbound traffic, not a spin. The
                    // yield keeps a burst of bad handshakes from starving
                    // other tasks on the runtime; a sleep here would instead
                    // penalise the next legitimate client behind an attacker.
                    // Per-peer rate limiting belongs to RT-W4's real listener,
                    // not to this probe.
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// A running probe server.
pub struct Served {
    /// Where it listens.
    pub addr: SocketAddr,
    /// Requests that reached the handler — must stay 0 for every rejection.
    pub hits: Arc<AtomicUsize>,
    /// Handshakes the acceptor refused.
    pub rejected: Arc<AtomicUsize>,
    /// The serve task.
    pub task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// Serve one `GET /` route over pinned mutual TLS.
pub async fn serve(
    identity: &Identity,
    allowlist: BTreeSet<SpkiFingerprint>,
) -> Result<Served, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = tcp.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));
    let listener = TlsListener {
        tcp,
        acceptor: TlsAcceptor::from(server_config(identity, allowlist)?),
        rejected: Arc::clone(&rejected),
    };
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
        rejected,
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
    /// `connect()` returned `Ok` and the failure came afterwards (the
    /// server's refusal of *our* certificate arrives here in TLS 1.3, because
    /// the client's Finished precedes the server's verdict).
    AfterHandshake(std::io::Error),
}

/// What a successful dial observed.
#[derive(Debug)]
pub struct Dialed {
    /// The HTTP response body.
    pub body: String,
    /// The negotiated protocol version.
    pub version: Option<rustls::ProtocolVersion>,
    /// The negotiated key-exchange group — `Some` means an (EC)DHE share was
    /// agreed, i.e. forward secrecy is a property of this connection.
    pub kx_group: Option<rustls::NamedGroup>,
}

/// `GET /` over pinned mutual TLS, HTTP/1.1 `Connection: close`.
pub async fn dial(addr: SocketAddr, config: Arc<ClientConfig>) -> Result<Dialed, DialError> {
    let tcp = TcpStream::connect(addr).await.map_err(DialError::Connect)?;
    let name = ServerName::try_from("rt-p2.probe".to_owned()).expect("static name parses");
    let mut tls = TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(DialError::Handshake)?;
    let (version, kx_group) = {
        let (_, conn) = tls.get_ref();
        (
            conn.protocol_version(),
            conn.negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
        )
    };
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
    Ok(Dialed {
        body,
        version,
        kx_group,
    })
}

/// The rustls error tokio-rustls wraps in an `io::Error`, if any.
#[must_use]
pub fn rustls_error_in(err: &std::io::Error) -> Option<TlsError> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
        .cloned()
}
