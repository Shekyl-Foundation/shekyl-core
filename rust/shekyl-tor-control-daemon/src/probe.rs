// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor-facing half of the probe of this node's own onion
//! (`TOR_SUPERVISOR.md` §4.5).
//!
//! The supervisor dials its own onion through the managed Tor's SOCKS port
//! and writes a handshake carrying a probe nonce. Arrival at this node's
//! inbound handshake is the evidence, and only that: what this dial sees
//! (a SOCKS reply, a close) is said in the log and moves nothing
//! (`TSR-Q14`). The bound is the supervisor's deadline, which drops this
//! dial; there is no timer here.
//!
//! The dial presents its own isolation pair ([`IsolationPair`]), a fixed
//! per-boot username minted beside the onion seed. Tor isolates streams by
//! SOCKS credentials (`IsolateSOCKSAuth`, its default), so the probe's
//! circuits are its own, apart from the peer dials, which offer no
//! authentication. One Tor process has one guard set: the guard can still
//! correlate the probe's client rendezvous with the service's, and only a
//! second Tor would remove that, which is worse (Rick, 2026-10-23).

use std::sync::Arc;

use shekyl_socks::{connect, Destination, Proxy, SocksError, SocksUsername};
use shekyl_tor_control_client::control::ServiceId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::DaemonTorPublishError;

/// Hex digits in the minted username: 16 random bytes.
const USERNAME_BYTES: usize = 16;

/// One in-process purpose's SOCKS isolation pair for the managed Tor: a
/// random username minted once per boot and presented on every use. The
/// password is fixed; Tor isolates on the pair, and the username alone
/// carries the randomness.
///
/// The bytes are wiped on drop and redacted in `Debug` ([`SocksUsername`]).
/// It is held by its purpose for the boot, as the onion seed is held by the
/// supervisor, and never written anywhere.
#[derive(Clone, Debug)]
pub struct IsolationPair(Arc<SocksUsername>);

impl IsolationPair {
    /// Mint a pair from the OS CSPRNG. No fallback: a guessable username
    /// would let another local client join the purpose's circuits.
    ///
    /// # Errors
    /// [`DaemonTorPublishError::SeedRng`] when the CSPRNG refuses.
    pub fn mint() -> Result<Self, DaemonTorPublishError> {
        let mut random = Zeroizing::new([0u8; USERNAME_BYTES]);
        if getrandom::getrandom(random.as_mut()).is_err() {
            return Err(DaemonTorPublishError::SeedRng);
        }
        let mut username = Zeroizing::new(Vec::with_capacity(USERNAME_BYTES * 2));
        for byte in random.iter() {
            username.push(hex_digit(byte >> 4));
            username.push(hex_digit(byte & 0x0f));
        }
        let pair =
            SocksUsername::new(&username, b"shekyl").map_err(|_| DaemonTorPublishError::SeedRng)?;
        Ok(Self(Arc::new(pair)))
    }

    /// The shared pair, for a proxy read at each use.
    #[must_use]
    pub fn shared(&self) -> &Arc<SocksUsername> {
        &self.0
    }
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + nibble - 10,
    }
}

/// How the probe's own dial ended. Said in the log; never a verdict
/// (`TSR-Q14`): only the nonce's arrival, or the supervisor's bound, moves
/// the inbound facet.
#[derive(Debug)]
pub enum ProbeDial {
    /// The tunnel opened, the request was written, and the far end closed:
    /// this node's inbound handshake drops its own probe.
    Delivered,
    /// The managed Tor answered the CONNECT with this reply.
    Refused {
        /// The SOCKS reply byte.
        reply: u8,
    },
    /// The SOCKS port could not be reached, or the exchange failed before a
    /// reply (`shekyl_socks` names which).
    Proxy(SocksError),
    /// The tunnel opened and the stream failed while the request was
    /// written or the close awaited.
    Stream(std::io::Error),
}

/// Dial `onion`'s `virtual_port` through `proxy` and write `request`, then
/// wait for the far end to close.
///
/// The caller drops this future at its bound. `request` is opaque here:
/// the handshake frame carrying the probe nonce.
pub async fn probe_own_onion(
    proxy: &Proxy,
    onion: &ServiceId,
    virtual_port: u16,
    request: &[u8],
) -> ProbeDial {
    let mut stream = match TcpStream::connect(proxy.at()).await {
        Ok(stream) => stream,
        Err(error) => return ProbeDial::Proxy(SocksError::Io(error)),
    };
    let host = format!("{}.onion", onion.as_str());
    let destination = Destination::Name {
        host: &host,
        port: virtual_port,
    };
    match connect(&mut stream, proxy.isolation(), destination).await {
        Ok(()) => {}
        Err(SocksError::Refused { reply }) => return ProbeDial::Refused { reply },
        Err(error) => return ProbeDial::Proxy(error),
    }
    if let Err(error) = stream.write_all(request).await {
        return ProbeDial::Stream(error);
    }
    let mut sink = [0u8; 512];
    loop {
        match stream.read(&mut sink).await {
            Ok(0) => return ProbeDial::Delivered,
            Ok(_) => {}
            Err(error) => return ProbeDial::Stream(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_socks::accept_userpass;
    use tokio::net::TcpListener;

    /// A stand-in for the managed Tor's SOCKS port: it accepts only the
    /// username/password method, reads one CONNECT by name, answers
    /// `reply`, and on success reads `expect` bytes and closes, as this
    /// node's inbound handshake does with its own probe. Returns the
    /// presented username and the CONNECT's host.
    async fn stand_in(
        listener: TcpListener,
        reply: u8,
        expect: usize,
    ) -> (Vec<u8>, String, Vec<u8>) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let presented = accept_userpass(&mut stream).await.expect("a pair");
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).await.expect("CONNECT");
        assert_eq!(&head[..4], &[0x05, 0x01, 0x00, 0x03], "CONNECT by name");
        let mut host = vec![0u8; usize::from(head[4])];
        stream.read_exact(&mut host).await.expect("host");
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.expect("port");
        stream
            .write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");
        let mut request = vec![0u8; expect];
        if reply == 0 {
            stream.read_exact(&mut request).await.expect("request");
        }
        drop(stream);
        (
            presented.username().to_vec(),
            String::from_utf8(host).expect("ascii"),
            request,
        )
    }

    fn onion() -> ServiceId {
        ServiceId::parse("url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid")
            .expect("a v3 id")
    }

    /// The probe presents its own pair, names its own onion, writes the
    /// request and ends `Delivered` when the far end drops it. Two mints
    /// present two different 32-digit usernames: a per-boot value, never
    /// one every node shares, and never the no-authentication greeting the
    /// peer dials use. Presenting no pair, or a constant username, fails
    /// this.
    #[tokio::test]
    async fn the_probe_presents_its_own_pair_and_delivers_its_request() {
        let mut usernames = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let at = listener.local_addr().expect("addr");
            let request = b"the handshake frame".to_vec();
            let served = tokio::spawn(stand_in(listener, 0x00, request.len()));
            let pair = IsolationPair::mint().expect("mint");
            let proxy = Proxy::authenticated_shared(at, Arc::clone(pair.shared()));
            let dialed = probe_own_onion(&proxy, &onion(), 11021, &request).await;
            assert!(matches!(dialed, ProbeDial::Delivered), "{dialed:?}");
            let (username, host, received) = served.await.expect("stand-in");
            assert_eq!(host, format!("{}.onion", onion().as_str()));
            assert_eq!(received, request);
            assert_eq!(username.len(), 32);
            assert!(username.iter().all(u8::is_ascii_hexdigit));
            usernames.push(username);
        }
        assert_ne!(usernames[0], usernames[1], "a fresh username per mint");
        let pair = IsolationPair::mint().expect("mint");
        assert_eq!(
            format!("{pair:?}"),
            "IsolationPair(SocksUsername(<redacted>))"
        );
    }

    /// A refusal is reported as the reply, and nothing is written: the dial
    /// says what it saw and decides nothing.
    #[tokio::test]
    async fn a_refused_probe_reports_the_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let at = listener.local_addr().expect("addr");
        let served = tokio::spawn(stand_in(listener, 0xF2, 0));
        let pair = IsolationPair::mint().expect("mint");
        let proxy = Proxy::authenticated_shared(at, Arc::clone(pair.shared()));
        let dialed = probe_own_onion(&proxy, &onion(), 11021, b"unsent").await;
        assert!(
            matches!(dialed, ProbeDial::Refused { reply: 0xF2 }),
            "{dialed:?}"
        );
        served.await.expect("stand-in");
    }

    #[test]
    fn hex_digits_cover_every_nibble() {
        let digits: Vec<u8> = (0..16).map(hex_digit).collect();
        assert_eq!(digits, b"0123456789abcdef");
    }
}
