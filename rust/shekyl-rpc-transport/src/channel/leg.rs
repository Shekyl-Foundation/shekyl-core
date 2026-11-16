// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a daemon's channel is, and the stream a dial produces.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ChannelFault;

/// Where the daemon's channel is.
#[derive(Clone, Debug)]
pub enum Leg {
    /// An address or an onion, `host:port`, dialed directly or through a
    /// SOCKS5 proxy, which resolves the name (an onion needs one).
    Network {
        /// `host:port`: an IP address or an onion.
        endpoint: String,
        /// The SOCKS5 proxy, if any.
        socks: Option<SocketAddr>,
    },
    /// A Unix socket: a service's console leg (RT-O37).
    #[cfg(unix)]
    Socket(std::path::PathBuf),
    /// A Windows pipe: a service's console leg (RT-O37).
    #[cfg(windows)]
    Pipe(String),
}

impl std::fmt::Display for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network { endpoint, .. } => f.write_str(endpoint),
            #[cfg(unix)]
            Self::Socket(path) => write!(f, "{}", path.display()),
            #[cfg(windows)]
            Self::Pipe(name) => f.write_str(name),
        }
    }
}

/// A dialed leg.
pub enum LegStream {
    /// TCP, direct or through SOCKS.
    Tcp(tokio::net::TcpStream),
    /// A Unix socket.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// A Windows pipe.
    #[cfg(windows)]
    Pipe(tokio::net::windows::named_pipe::NamedPipeClient),
}

macro_rules! each_leg {
    ($self:ident, $io:ident => $body:expr) => {
        match $self.get_mut() {
            LegStream::Tcp($io) => $body,
            #[cfg(unix)]
            LegStream::Unix($io) => $body,
            #[cfg(windows)]
            LegStream::Pipe($io) => $body,
        }
    };
}

impl AsyncRead for LegStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_read(cx, buf))
    }
}

impl AsyncWrite for LegStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_write(cx, buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_shutdown(cx))
    }
}

impl Leg {
    /// Connect to the leg.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Unreachable`].
    pub async fn dial(&self) -> Result<LegStream, ChannelFault> {
        let unreachable = |cause: String| ChannelFault::Unreachable {
            at: self.to_string(),
            cause,
        };
        match self {
            Self::Network {
                endpoint,
                socks: None,
            } => {
                let addr: SocketAddr = endpoint
                    .parse()
                    .map_err(|_| unreachable("an onion is reached through a SOCKS proxy".into()))?;
                tokio::net::TcpStream::connect(addr)
                    .await
                    .map(LegStream::Tcp)
                    .map_err(|e| unreachable(e.to_string()))
            }
            Self::Network {
                endpoint,
                socks: Some(proxy),
            } => {
                let (host, port) = endpoint
                    .rsplit_once(':')
                    .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
                    .ok_or_else(|| unreachable("not host:port".into()))?;
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let mut tcp = tokio::net::TcpStream::connect(proxy)
                    .await
                    .map_err(|e| unreachable(format!("the SOCKS proxy {proxy}: {e}")))?;
                shekyl_socks::connect(
                    &mut tcp,
                    shekyl_socks::Isolation::Principal,
                    shekyl_socks::Destination::Name { host, port },
                )
                .await
                .map_err(|e| unreachable(format!("the SOCKS proxy {proxy}: {e}")))?;
                Ok(LegStream::Tcp(tcp))
            }
            #[cfg(unix)]
            Self::Socket(path) => tokio::net::UnixStream::connect(path)
                .await
                .map(LegStream::Unix)
                .map_err(|e| unreachable(e.to_string())),
            #[cfg(windows)]
            Self::Pipe(name) => tokio::net::windows::named_pipe::ClientOptions::new()
                .open(name)
                .map(LegStream::Pipe)
                .map_err(|e| unreachable(e.to_string())),
        }
    }
}
