// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SOCKS5 CONNECT with no authentication (RFC 1928).
//!
//! Clearnet's `--proxy` and the Tor connector both speak this. The crate
//! does not know which connector is calling, and it does not map a reply
//! onto a close cause. The caller does that.

#![deny(unsafe_code)]

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const SUCCEEDED: u8 = 0x00;

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
}

/// Open a CONNECT tunnel on `stream`.
///
/// On success the stream sits at the first tunneled byte. On
/// [`SocksError::Refused`] the reply has been consumed.
pub async fn connect<S>(stream: &mut S, dest: Destination<'_>) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, 1, NO_AUTH])
        .await
        .map_err(SocksError::Io)?;
    let mut chosen = [0u8; 2];
    stream
        .read_exact(&mut chosen)
        .await
        .map_err(SocksError::Io)?;
    if chosen[0] != VERSION || chosen[1] != NO_AUTH {
        return Err(SocksError::Malformed);
    }
    let request = request(&dest)?;
    stream.write_all(&request).await.map_err(SocksError::Io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(SocksError::Io)?;
    if head[0] != VERSION {
        return Err(SocksError::Malformed);
    }
    consume_bind(stream, head[3]).await?;
    if head[1] != SUCCEEDED {
        return Err(SocksError::Refused { reply: head[1] });
    }
    Ok(())
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
    use super::{connect, Destination, SocksError};
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
        connect(&mut client, Destination::Ip(v4())).await.unwrap();
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
        let err = connect(&mut client, Destination::Ip(v4()))
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
            match connect(&mut client, Destination::Ip(v4())).await {
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
            Destination::Name {
                host: "example.onion",
                port: 18080,
            },
        )
        .await
        .unwrap();
    }
}
