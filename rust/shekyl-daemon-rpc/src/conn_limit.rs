// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Purpose-built connection limiting and accounting for the Axum daemon RPC.
//!
//! Inbound daemon RPC caps concurrent TCP connections in three dimensions —
//! `--rpc-max-connections` (total), `--rpc-max-connections-per-public-ip`, and
//! `--rpc-max-connections-per-private-ip`. This is a native Rust implementation
//! layered on `axum::serve`'s [`Listener`] trait, not a port of the inherited
//! epee acceptor: a [`LimitedListener`] wraps the TCP listener and admits or
//! rejects each connection against a shared [`ConnTracker`], handing accepted
//! sockets back as a [`CountedStream`] whose drop (connection close) releases
//! the slot. The same tracker's live total is what `get_info` reports as
//! `rpc_connections_count`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// Per-listener connection caps. `0` means "unlimited" for that dimension,
/// matching the daemon CLI convention for `--rpc-max-connections*`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnLimits {
    pub max_total: u64,
    pub max_per_public_ip: u64,
    pub max_per_private_ip: u64,
}

/// Shared connection accounting for one listener.
///
/// Constructed via [`ConnTracker::new`], which returns an `Arc` because the
/// tracker is shared between the [`LimitedListener`] (admission) and the
/// `get_info` handler (which reads [`ConnTracker::active_total`]).
#[derive(Debug)]
pub struct ConnTracker {
    limits: ConnLimits,
    /// Live connection total. Mutated only while `per_ip`'s lock is held so it
    /// stays coherent with the map; read lock-free for the `get_info` metric.
    total: AtomicU64,
    /// Per-IP live counts, in the same `u64` width as the caps so comparisons
    /// need no cast (a per-IP count is bounded by ports/FDs far below `u32`, but
    /// matching the limit type keeps the check clean).
    per_ip: Mutex<HashMap<IpAddr, u64>>,
}

impl ConnTracker {
    pub fn new(limits: ConnLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            total: AtomicU64::new(0),
            per_ip: Mutex::new(HashMap::new()),
        })
    }

    /// Current number of live connections — the value reported as
    /// `rpc_connections_count`.
    pub fn active_total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Try to admit a connection from `ip`. On success returns a [`ConnGuard`]
    /// that releases the slot on drop; returns `None` if the total cap or the
    /// applicable per-IP cap (public vs private, selected by [`ip_is_local`])
    /// is already reached.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        // Canonicalize IPv4-mapped IPv6 (::ffff:a.b.c.d) up front so a
        // dual-stack ([::]) listener classifies and counts a v4 client the same
        // whether it arrives mapped or native — and so the guard releases under
        // the same key it acquired.
        let ip = canonical_ip(ip);
        let per_ip_cap = if ip_is_local(ip) {
            self.limits.max_per_private_ip
        } else {
            self.limits.max_per_public_ip
        };

        // The map lock serializes acquire/release, so `total` (mutated only
        // here and in `release`) stays consistent with the per-IP counts.
        let mut map = self
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if self.limits.max_total != 0 && self.total.load(Ordering::Relaxed) >= self.limits.max_total
        {
            return None;
        }
        let slot = map.entry(ip).or_insert(0);
        if per_ip_cap != 0 && *slot >= per_ip_cap {
            return None;
        }
        *slot += 1;
        self.total.fetch_add(1, Ordering::Relaxed);
        Some(ConnGuard {
            tracker: Arc::clone(self),
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut map = self
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(slot) = map.get_mut(&ip) else {
            // Unreachable given the guard lifecycle (a ConnGuard exists iff
            // try_acquire inserted this canonical IP). Fail safe if that
            // invariant is ever broken: never decrement `total` for a slot we
            // did not find, so a desync cannot wrap the count into a huge value
            // that would wrongly reject all connections. Surface it loudly.
            tracing::error!("connection release for untracked IP {ip}: accounting desync");
            return;
        };
        // `slot` is >= 1 here (kept only while non-zero), so this cannot wrap.
        *slot -= 1;
        if *slot == 0 {
            map.remove(&ip);
        }
        self.total.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Releases one connection slot from its [`ConnTracker`] on drop.
#[derive(Debug)]
pub struct ConnGuard {
    tracker: Arc<ConnTracker>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.release(self.ip);
    }
}

/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4
/// form. A dual-stack (`[::]`) listener surfaces IPv4 clients as mapped
/// addresses; canonicalizing means they classify under the IPv4 rules and share
/// a per-IP slot with any native-IPv4 arrival. All other addresses are returned
/// unchanged.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(a),
        },
        v4 => v4,
    }
}

/// Classify an address as local/private (loopback / RFC1918 / link-local /
/// unique-local) vs. public, which selects the per-IP cap that applies. IPv4
/// (including IPv4-mapped IPv6, via [`canonical_ip`]) uses the std helpers;
/// other IPv6 ranges are checked by prefix to stay independent of
/// still-evolving `std::net` classification helpers.
fn ip_is_local(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            if a.is_loopback() {
                return true;
            }
            let o = a.octets();
            // fc00::/7 (unique-local) or fe80::/10 (link-local).
            (o[0] & 0xfe) == 0xfc || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
        }
    }
}

/// An [`axum::serve::Listener`] that admits connections through a
/// [`ConnTracker`]. A connection over a configured cap is dropped (closed
/// immediately) and accepting continues; an admitted connection is wrapped in a
/// [`CountedStream`] so its slot is released when it closes.
pub struct LimitedListener {
    inner: TcpListener,
    tracker: Arc<ConnTracker>,
}

impl LimitedListener {
    pub fn new(inner: TcpListener, tracker: Arc<ConnTracker>) -> Self {
        Self { inner, tracker }
    }
}

impl Listener for LimitedListener {
    type Io = CountedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // Delegate to tokio's TcpListener via axum's own Listener impl,
            // which logs and backs off on transient accept errors and only
            // yields on a real connection.
            let (stream, addr) = <TcpListener as Listener>::accept(&mut self.inner).await;
            match self.tracker.try_acquire(addr.ip()) {
                Some(guard) => {
                    return (
                        CountedStream {
                            inner: stream,
                            _guard: guard,
                        },
                        addr,
                    )
                }
                None => {
                    tracing::debug!(
                        peer = %addr,
                        "daemon RPC connection rejected: connection limit reached"
                    );
                    // `stream` drops here → the socket is closed. Keep accepting.
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        <TcpListener as Listener>::local_addr(&self.inner)
    }
}

/// A `TcpStream` paired with a [`ConnGuard`]; dropping it (connection close)
/// releases the tracked slot. Read/write are delegated verbatim to the inner
/// stream.
pub struct CountedStream {
    inner: TcpStream,
    _guard: ConnGuard,
}

impl AsyncRead for CountedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn total_cap_is_enforced_and_released() {
        let t = ConnTracker::new(ConnLimits {
            max_total: 2,
            ..Default::default()
        });
        let g1 = t.try_acquire(ip("1.1.1.1")).unwrap();
        let g2 = t.try_acquire(ip("2.2.2.2")).unwrap();
        assert_eq!(t.active_total(), 2);
        assert!(t.try_acquire(ip("3.3.3.3")).is_none(), "total cap reached");

        drop(g1);
        assert_eq!(t.active_total(), 1);
        let _g3 = t.try_acquire(ip("3.3.3.3")).expect("slot freed by drop");
        assert_eq!(t.active_total(), 2);
        drop(g2);
    }

    #[test]
    fn per_public_ip_cap_is_enforced_per_ip() {
        let t = ConnTracker::new(ConnLimits {
            max_per_public_ip: 1,
            ..Default::default()
        });
        let _a = t.try_acquire(ip("8.8.8.8")).unwrap();
        assert!(
            t.try_acquire(ip("8.8.8.8")).is_none(),
            "same public IP over its cap"
        );
        assert!(
            t.try_acquire(ip("9.9.9.9")).is_some(),
            "a different public IP is unaffected"
        );
    }

    #[test]
    fn private_ips_use_the_private_cap_not_the_public_one() {
        let t = ConnTracker::new(ConnLimits {
            max_per_public_ip: 1,
            max_per_private_ip: 3,
            ..Default::default()
        });
        // Loopback is local, so the private cap (3) applies, not the public (1).
        let _a = t.try_acquire(ip("127.0.0.1")).unwrap();
        let _b = t.try_acquire(ip("127.0.0.1")).unwrap();
        let _c = t.try_acquire(ip("127.0.0.1")).unwrap();
        assert!(
            t.try_acquire(ip("127.0.0.1")).is_none(),
            "private cap reached"
        );
    }

    #[test]
    fn zero_limits_mean_unlimited() {
        let t = ConnTracker::new(ConnLimits::default());
        let guards: Vec<_> = (0u16..64)
            .map(|i| {
                // Deliberate u16->byte split: both halves of `i` are kept.
                #[allow(clippy::cast_possible_truncation)]
                let addr = IpAddr::from([10, 0, (i >> 8) as u8, i as u8]);
                t.try_acquire(addr).expect("unlimited")
            })
            .collect();
        assert_eq!(t.active_total(), 64);
        drop(guards);
        assert_eq!(t.active_total(), 0, "all slots released on drop");
    }

    #[test]
    fn ip_classification_matches_public_private_split() {
        for local in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            // IPv4-mapped IPv6 (as a dual-stack [::] listener surfaces v4
            // clients) must classify by the embedded IPv4.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(ip_is_local(ip(local)), "{local} should classify as local");
        }
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                !ip_is_local(ip(public)),
                "{public} should classify as public"
            );
        }
    }

    #[test]
    fn ipv4_mapped_and_native_share_one_per_ip_slot() {
        let t = ConnTracker::new(ConnLimits {
            max_per_public_ip: 1,
            ..Default::default()
        });
        let _mapped = t.try_acquire(ip("::ffff:8.8.8.8")).unwrap();
        // The same underlying IPv4, arriving natively, must hit the same slot.
        assert!(
            t.try_acquire(ip("8.8.8.8")).is_none(),
            "mapped and native forms of one IP must not double the cap"
        );
    }
}
