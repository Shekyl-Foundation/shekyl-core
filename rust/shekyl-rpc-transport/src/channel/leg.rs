// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a daemon's channel is, and the stream a dial produces.
//!
//! A leg is the route, not a string to be parsed again. An IP may be
//! direct or through a SOCKS5 proxy. An onion has no direct route, so its
//! proxy is part of the leg. A service's console leg is a Unix socket or a
//! Windows pipe.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ChannelFault;

/// Where the daemon's channel is.
#[derive(Clone, Debug)]
pub enum Leg {
    /// An IP address and a port. `proxy` is set when that address is
    /// reached through a SOCKS5 proxy.
    Ip {
        /// The node's address.
        addr: SocketAddr,
        /// The SOCKS5 proxy, when there is one.
        proxy: Option<SocketAddr>,
    },
    /// A v3 onion and a port, reached through `proxy`. An onion without a
    /// proxy is not a leg.
    Onion {
        /// The onion host, without a port.
        host: String,
        /// The onion's port.
        port: u16,
        /// The SOCKS5 proxy, which resolves the name.
        proxy: SocketAddr,
    },
    /// A Unix socket: a service's console leg (RT-O37).
    #[cfg(unix)]
    Socket(std::path::PathBuf),
    /// A Windows pipe: a service's console leg (RT-O37).
    #[cfg(windows)]
    Pipe(String),
}

impl Leg {
    /// An IP address, directly or through `proxy`.
    #[must_use]
    pub fn ip(addr: SocketAddr, proxy: Option<SocketAddr>) -> Self {
        Self::Ip { addr, proxy }
    }

    /// The proxy used to reach this endpoint, if configured.
    #[must_use]
    pub fn proxy(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip { proxy, .. } => *proxy,
            Self::Onion { proxy, .. } => Some(*proxy),
            #[cfg(unix)]
            Self::Socket(_) => None,
            #[cfg(windows)]
            Self::Pipe(_) => None,
        }
    }

    /// The network exposure warnings for a configured channel endpoint.
    #[must_use]
    pub fn disclosures(&self, label: &str) -> crate::network_posture::DaemonDisclosures {
        crate::network_posture::daemon_disclosures(
            label,
            &self.to_string(),
            self.proxy().map(|p| format!("socks5h://{p}")).as_deref(),
            crate::network_posture::ProxyResolution::AlwaysRemote,
        )
    }

    /// An onion through `proxy`.
    #[must_use]
    pub fn onion(host: String, port: u16, proxy: SocketAddr) -> Self {
        Self::Onion { host, port, proxy }
    }
}

impl std::fmt::Display for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip { addr, .. } => write!(f, "{addr}"),
            Self::Onion { host, port, .. } => write!(f, "{host}:{port}"),
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
            Self::Ip { addr, proxy: None } => tokio::net::TcpStream::connect(addr)
                .await
                .map(LegStream::Tcp)
                .map_err(|e| unreachable(e.to_string())),
            Self::Ip {
                addr,
                proxy: Some(proxy),
            } => {
                self.through_proxy(proxy, shekyl_socks::Destination::Ip(*addr))
                    .await
            }
            Self::Onion { host, port, proxy } => {
                self.through_proxy(proxy, shekyl_socks::Destination::Name { host, port: *port })
                    .await
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

    async fn through_proxy(
        &self,
        proxy: &SocketAddr,
        destination: shekyl_socks::Destination<'_>,
    ) -> Result<LegStream, ChannelFault> {
        let mut tcp =
            tokio::net::TcpStream::connect(proxy)
                .await
                .map_err(|e| ChannelFault::Unreachable {
                    at: self.to_string(),
                    cause: format!("the SOCKS proxy {proxy}: {e}"),
                })?;
        shekyl_socks::connect(&mut tcp, shekyl_socks::Isolation::Principal, destination)
            .await
            .map_err(|e| ChannelFault::Unreachable {
                at: self.to_string(),
                cause: format!("the SOCKS proxy {proxy}: {e}"),
            })?;
        Ok(LegStream::Tcp(tcp))
    }
}
