// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SOCKS5 CONNECT (RFC 1928) with optional username/password (RFC 1929).
//!
//! The crate keeps no pool and no static state. Each [`connect`] writes one
//! greeting and one request on the stream it is given. Which Tor circuit
//! that produces is Tor's, selected by the credentials in the greeting.
//!
//! [`Isolation`] is required. [`Isolation::Principal`] offers only
//! "no authentication". [`Isolation::Persona`] offers only
//! username/password, and a proxy that selects anything else fails the
//! handshake before CONNECT. Offering both would let the proxy drop the
//! stream onto the principal's circuits with no error.
//! [`accept_userpass`] is that greeting's other half: it accepts only the
//! one method [`Isolation::Persona`] offers.
//!
//! This crate does not derive a persona username. The caller supplies the
//! bytes. [`SocksUsername`] redacts them in `Debug` and wipes its copies
//! on drop.

#![deny(unsafe_code)]

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

const VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const USERPASS_VERSION: u8 = 0x01;
/// RFC 1929: any non-zero status is failure. Empty usernames use this one.
const USERPASS_FAILURE: u8 = 0x01;
/// RFC 1928: no offered method is acceptable.
const NO_ACCEPTABLE: u8 = 0xFF;
const CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const SUCCEEDED: u8 = 0x00;

/// Which circuits this connection may join.
///
/// There is no default. A forgotten argument does not compile, so it
/// cannot land in the principal's namespace by omission.
pub enum Isolation<'a> {
    /// No SOCKS authentication. The principal's traffic, and the daemon's
    /// overlay.
    Principal,
    /// Username/password only. The caller supplies the bytes.
    ///
    /// One handshake for every authenticated dial. A per-read circuit is
    /// which bytes the caller presents, not a second variant: Tor isolates
    /// on the pair, and two callers that present the same pair share a
    /// circuit.
    Persona(&'a SocksUsername),
}

/// RFC 1929 username and password bytes.
///
/// An empty username is refused. That value is the principal's no-auth
/// circuit, and a persona must not be able to name it. The password may
/// be empty; RFC 1929 allows that. Fixed width and the derivation live
/// with the caller.
pub struct SocksUsername {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl SocksUsername {
    /// Copy `username` and `password`. Longer than 255 bytes, or an empty
    /// username, is [`SocksError::Malformed`].
    pub fn new(username: &[u8], password: &[u8]) -> Result<Self, SocksError> {
        if username.is_empty() || username.len() > 255 || password.len() > 255 {
            return Err(SocksError::Malformed);
        }
        Ok(Self {
            username: Zeroizing::new(username.to_vec()),
            password: Zeroizing::new(password.to_vec()),
        })
    }
}

impl core::fmt::Debug for SocksUsername {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SocksUsername(<redacted>)")
    }
}

impl core::fmt::Debug for Isolation<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Principal => f.write_str("Principal"),
            Self::Persona(user) => f.debug_tuple("Persona").field(user).finish(),
        }
    }
}

/// Where CONNECT should open.
pub enum Destination<'a> {
    /// An IP address.
    Ip(SocketAddr),
    /// A hostname. SOCKS carries the name. The caller does not resolve it.
    /// Longer than 255 bytes is [`SocksError::Malformed`].
    Name { host: &'a str, port: u16 },
}

/// The proxy did not produce a tunnel.
#[derive(Debug)]
pub enum SocksError {
    /// The stream failed.
    Io(std::io::Error),
    /// CONNECT's reply byte. `0x00` is not this variant.
    Refused { reply: u8 },
    /// The greeting or the reply was not a SOCKS5 message we can use.
    Malformed,
    /// The proxy selected a method this isolation does not offer.
    /// CONNECT was not sent.
    AuthRejected { selected: u8 },
    /// The username/password exchange did not succeed. CONNECT was not sent.
    AuthFailed { status: u8 },
}

impl core::fmt::Display for SocksError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Refused { reply } => write!(f, "proxy refused CONNECT, reply {reply:#04x}"),
            Self::Malformed => f.write_str("malformed SOCKS5 message"),
            Self::AuthRejected { selected } => {
                write!(f, "proxy selected authentication method {selected:#04x}")
            }
            Self::AuthFailed { status } => {
                write!(f, "username/password exchange failed, status {status:#04x}")
            }
        }
    }
}

/// Open a CONNECT tunnel on `stream`.
///
/// `isolation` chooses the single authentication method offered. On
/// success the stream sits at the first tunneled byte. On
/// [`SocksError::Refused`] the reply has been consumed.
pub async fn connect<S>(
    stream: &mut S,
    isolation: Isolation<'_>,
    dest: Destination<'_>,
) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream, &isolation).await?;
    let request = request(&dest)?;
    stream.write_all(&request).await.map_err(SocksError::Io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(SocksError::Io)?;
    if head[0] != VERSION || head[2] != 0 {
        return Err(SocksError::Malformed);
    }
    consume_bind(stream, head[3]).await?;
    if head[1] != SUCCEEDED {
        return Err(SocksError::Refused { reply: head[1] });
    }
    Ok(())
}

async fn negotiate<S>(stream: &mut S, isolation: &Isolation<'_>) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = match isolation {
        Isolation::Principal => NO_AUTH,
        Isolation::Persona(_) => USER_PASS,
    };
    stream
        .write_all(&[VERSION, 1, method])
        .await
        .map_err(SocksError::Io)?;
    let mut chosen = [0u8; 2];
    stream
        .read_exact(&mut chosen)
        .await
        .map_err(SocksError::Io)?;
    if chosen[0] != VERSION {
        return Err(SocksError::Malformed);
    }
    if chosen[1] != method {
        return Err(SocksError::AuthRejected {
            selected: chosen[1],
        });
    }
    if let Isolation::Persona(user) = isolation {
        userpass(stream, user).await?;
    }
    Ok(())
}

async fn userpass<S>(stream: &mut S, user: &SocksUsername) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ulen = u8::try_from(user.username.len()).map_err(|_| SocksError::Malformed)?;
    let plen = u8::try_from(user.password.len()).map_err(|_| SocksError::Malformed)?;
    let mut msg = Zeroizing::new(Vec::with_capacity(
        3 + user.username.len() + user.password.len(),
    ));
    msg.push(USERPASS_VERSION);
    msg.push(ulen);
    msg.extend_from_slice(&user.username);
    msg.push(plen);
    msg.extend_from_slice(&user.password);
    stream.write_all(&msg).await.map_err(SocksError::Io)?;
    drop(msg);
    let mut status = [0u8; 2];
    stream
        .read_exact(&mut status)
        .await
        .map_err(SocksError::Io)?;
    if status[0] != USERPASS_VERSION || status[1] != SUCCEEDED {
        return Err(SocksError::AuthFailed { status: status[1] });
    }
    Ok(())
}

/// The RFC 1929 username and password a client presented to
/// [`accept_userpass`].
///
/// Both halves are wiped on drop. [`Debug`] redacts them, as
/// [`SocksUsername`] does.
pub struct PresentedCredentials {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl PresentedCredentials {
    /// The username the client sent.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// The password the client sent.
    #[must_use]
    pub fn password(&self) -> &[u8] {
        &self.password
    }
}

impl core::fmt::Debug for PresentedCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PresentedCredentials(<redacted>)")
    }
}

/// Accept the greeting [`Isolation::Persona`] sends, and return the pair.
///
/// The client must offer exactly username/password. A greeting that is not
/// SOCKS5, or that offers any other method list, is answered with "no
/// acceptable method" and [`SocksError::Malformed`], so a stand-in cannot
/// select "no authentication" and put the dial on a shared circuit. An empty
/// username is refused the same way [`SocksUsername::new`] refuses to build
/// one, with the RFC 1929 failure status. On success the stream sits at the
/// CONNECT request. The returned bytes are wiped on drop, including when the
/// username is refused after they have been read.
///
/// # Errors
///
/// [`SocksError::Io`] when the stream fails. [`SocksError::Malformed`] when
/// the greeting is not that one method, the RFC 1929 message is not version
/// 1, or the username is empty.
pub async fn accept_userpass<S>(stream: &mut S) -> Result<PresentedCredentials, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(SocksError::Io)?;
    if greeting[0] != VERSION {
        return refuse_greeting(stream).await;
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(SocksError::Io)?;
    if methods != [USER_PASS] {
        return refuse_greeting(stream).await;
    }
    stream
        .write_all(&[VERSION, USER_PASS])
        .await
        .map_err(SocksError::Io)?;

    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(SocksError::Io)?;
    if head[0] != USERPASS_VERSION {
        return Err(SocksError::Malformed);
    }
    let mut username = Zeroizing::new(vec![0u8; usize::from(head[1])]);
    stream
        .read_exact(&mut username)
        .await
        .map_err(SocksError::Io)?;
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await.map_err(SocksError::Io)?;
    let mut password = Zeroizing::new(vec![0u8; usize::from(plen[0])]);
    stream
        .read_exact(&mut password)
        .await
        .map_err(SocksError::Io)?;
    if username.is_empty() {
        stream
            .write_all(&[USERPASS_VERSION, USERPASS_FAILURE])
            .await
            .map_err(SocksError::Io)?;
        return Err(SocksError::Malformed);
    }
    stream
        .write_all(&[USERPASS_VERSION, SUCCEEDED])
        .await
        .map_err(SocksError::Io)?;
    Ok(PresentedCredentials { username, password })
}

/// RFC 1928 "no acceptable method", then [`SocksError::Malformed`].
async fn refuse_greeting<S>(stream: &mut S) -> Result<PresentedCredentials, SocksError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, NO_ACCEPTABLE])
        .await
        .map_err(SocksError::Io)?;
    Err(SocksError::Malformed)
}

fn request(dest: &Destination<'_>) -> Result<Vec<u8>, SocksError> {
    let mut out = vec![VERSION, CONNECT, 0];
    match dest {
        Destination::Ip(SocketAddr::V4(addr)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        Destination::Ip(SocketAddr::V6(addr)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        Destination::Name { host, port } => {
            let bytes = host.as_bytes();
            let len = u8::try_from(bytes.len()).map_err(|_| SocksError::Malformed)?;
            out.push(ATYP_NAME);
            out.push(len);
            out.extend_from_slice(bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(out)
}

async fn consume_bind<S>(stream: &mut S, atyp: u8) -> Result<(), SocksError>
where
    S: AsyncRead + Unpin,
{
    let n = match atyp {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_NAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(SocksError::Io)?;
            usize::from(len[0]) + 2
        }
        _ => return Err(SocksError::Malformed),
    };
    let mut rest = vec![0u8; n];
    stream.read_exact(&mut rest).await.map_err(SocksError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{accept_userpass, connect, Destination, Isolation, SocksError, SocksUsername};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn v4() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 18080))
    }

    #[tokio::test]
    async fn a_successful_connect_leaves_the_stream_at_the_tunnel() {
        let (mut client, mut server) = duplex(256);
        let peer = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 1, 0x00]);
            server.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0x05);
            assert_eq!(request[1], 0x01);
            assert_eq!(request[3], 0x01);
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            server.write_all(b"tunneled").await.unwrap();
        });
        connect(&mut client, Isolation::Principal, Destination::Ip(v4()))
            .await
            .unwrap();
        let mut got = [0u8; 8];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tunneled");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn a_connect_reply_is_the_reply_byte() {
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = connect(&mut client, Isolation::Principal, Destination::Ip(v4()))
            .await
            .unwrap_err();
        match err {
            SocksError::Refused { reply } => assert_eq!(reply, 0x05),
            other => panic!("expected the reply byte, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn every_nonzero_reply_byte_is_the_byte_the_proxy_sent() {
        for reply in 1u8..=255 {
            let (mut client, mut server) = duplex(64);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[0x05, 0x00]).await.unwrap();
                let mut request = [0u8; 10];
                server.read_exact(&mut request).await.unwrap();
                server
                    .write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            });
            match connect(&mut client, Isolation::Principal, Destination::Ip(v4())).await {
                Err(SocksError::Refused { reply: got }) => assert_eq!(got, reply, "reply {reply}"),
                other => panic!("reply {reply} was not kept: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_hostname_is_carried_without_resolving_it() {
        let (mut client, mut server) = duplex(128);
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[3], 0x03);
            let len = usize::from(head[4]);
            let mut name = vec![0u8; len + 2];
            server.read_exact(&mut name).await.unwrap();
            assert_eq!(&name[..len], b"example.onion");
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        connect(
            &mut client,
            Isolation::Principal,
            Destination::Name {
                host: "example.onion",
                port: 18080,
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn an_empty_username_is_not_a_persona() {
        assert!(matches!(
            SocksUsername::new(b"", b"shekyl-p"),
            Err(SocksError::Malformed)
        ));
    }

    #[test]
    fn debug_redacts_the_username() {
        let user = SocksUsername::new(b"persona-user-secret", b"shekyl-p").unwrap();
        let rendered = format!("{user:?}");
        assert!(!rendered.contains("persona-user-secret"));
        assert!(!rendered.contains("shekyl-p"));
    }

    #[tokio::test]
    async fn a_persona_offers_only_username_password_and_sends_the_bytes() {
        let user = SocksUsername::new(b"persona-user", b"shekyl-p").unwrap();
        let (mut client, mut server) = duplex(256);
        let peer = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 1, 0x02]);
            server.write_all(&[0x05, 0x02]).await.unwrap();
            let mut head = [0u8; 2];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x01);
            let mut name = vec![0u8; usize::from(head[1])];
            server.read_exact(&mut name).await.unwrap();
            assert_eq!(name, b"persona-user");
            let mut plen = [0u8; 1];
            server.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; usize::from(plen[0])];
            server.read_exact(&mut pass).await.unwrap();
            assert_eq!(pass, b"shekyl-p");
            server.write_all(&[0x01, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        connect(
            &mut client,
            Isolation::Persona(&user),
            Destination::Ip(v4()),
        )
        .await
        .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn accept_userpass_returns_the_pair_a_persona_presents() {
        let user = SocksUsername::new(b"shekyl-fetch", b"one-read").unwrap();
        let (mut client, mut server) = duplex(64);
        let peer = tokio::spawn(async move {
            let presented = accept_userpass(&mut server).await.unwrap();
            let rendered = format!("{presented:?}");
            assert!(!rendered.contains("shekyl-fetch"));
            assert!(!rendered.contains("one-read"));
            let pair = (presented.username().to_vec(), presented.password().to_vec());
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            pair
        });
        connect(
            &mut client,
            Isolation::Persona(&user),
            Destination::Ip(v4()),
        )
        .await
        .unwrap();
        let (name, pass) = peer.await.unwrap();
        assert_eq!(name, b"shekyl-fetch");
        assert_eq!(pass, b"one-read");
    }

    #[tokio::test]
    async fn accept_userpass_refuses_no_auth_and_a_mixed_greeting() {
        let (mut client, mut server) = duplex(64);
        let peer = tokio::spawn(async move { accept_userpass(&mut server).await.unwrap_err() });
        let err = connect(&mut client, Isolation::Principal, Destination::Ip(v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, SocksError::AuthRejected { selected: 0xFF }));
        assert!(matches!(peer.await.unwrap(), SocksError::Malformed));

        let (mut client, mut server) = duplex(64);
        let peer = tokio::spawn(async move { accept_userpass(&mut server).await.unwrap_err() });
        client.write_all(&[0x05, 2, 0x00, 0x02]).await.unwrap();
        let mut chosen = [0u8; 2];
        client.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [0x05, 0xFF]);
        assert!(matches!(peer.await.unwrap(), SocksError::Malformed));
    }

    #[tokio::test]
    async fn accept_userpass_refuses_a_foreign_version() {
        let (mut client, mut server) = duplex(64);
        let peer = tokio::spawn(async move { accept_userpass(&mut server).await.unwrap_err() });
        client.write_all(&[0x04, 1, 0x02]).await.unwrap();
        let mut chosen = [0u8; 2];
        client.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [0x05, 0xFF]);
        assert!(matches!(peer.await.unwrap(), SocksError::Malformed));
    }

    #[tokio::test]
    async fn accept_userpass_refuses_an_empty_username() {
        let (mut client, mut server) = duplex(64);
        let peer = tokio::spawn(async move { accept_userpass(&mut server).await.unwrap_err() });
        client.write_all(&[0x05, 1, 0x02]).await.unwrap();
        let mut chosen = [0u8; 2];
        client.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [0x05, 0x02]);
        client.write_all(&[0x01, 0, 0]).await.unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0x01, 0x01]);
        assert!(matches!(peer.await.unwrap(), SocksError::Malformed));
    }

    #[tokio::test]
    async fn a_proxy_that_picks_no_auth_for_a_persona_does_not_connect() {
        let user = SocksUsername::new(b"persona-user", b"shekyl-p").unwrap();
        let (mut client, mut server) = duplex(64);
        let peer = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 1, 0x02]);
            server.write_all(&[0x05, 0x00]).await.unwrap();
            let mut extra = [0u8; 1];
            server.read(&mut extra).await.unwrap()
        });
        let err = connect(
            &mut client,
            Isolation::Persona(&user),
            Destination::Ip(v4()),
        )
        .await
        .unwrap_err();
        match err {
            SocksError::AuthRejected { selected } => assert_eq!(selected, 0x00),
            other => panic!("expected the refused method, got {other:?}"),
        }
        drop(client);
        assert_eq!(peer.await.unwrap(), 0);
    }
}
