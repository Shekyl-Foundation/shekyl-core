// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connectors as the session layer dials them (brief §2, "Connectors"):
//! an [`Endpoint`] becomes a clearnet or a Tor dial on the transport
//! runtime, and the wait for its admission is the layer's
//! [`ConnectFuture`]. The connectors never parse Levin; they hand the
//! layer an admitted [`Channel`].
//!
//! What a dial reads at each call — the clearnet channel choice and tally,
//! the configured proxies, the link's route — lives here, so a route that
//! fell after the dialer planned the attempt still costs that one draw
//! (`TSR-F1`) and no more.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use shekyl_clearnet::{ChannelChoice, HandshakeTally};
use shekyl_p2p_session::{Channel, ConnectFuture, Dial, Endpoint, SessionLayer};
use shekyl_socks::Proxy;
use shekyl_timing_engine::{Handle, MonotonicClock, Tick};
use shekyl_transport_layer::{
    spans, CloseCause, ConnectorId, DialEnd, DialFailure, Direction, Links, NetworkAddress, Route,
    Sockets, StreamEnd,
};
use tokio::sync::{mpsc, oneshot};

/// The backoff between a failed `accept` and the next, on both connectors.
pub(crate) const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(1);

/// What the clearnet connector needs once its listeners are bound: the
/// channel choice, the handshake tally the listeners and dials share, and
/// the operator's proxy when outbound clearnet goes through one.
pub(crate) struct ClearnetReady {
    pub kind: ChannelChoice,
    pub tally: Arc<HandshakeTally>,
    pub proxy: Option<Proxy>,
}

/// The spans every dial and accept run under, from
/// [`shekyl_transport_layer::spans`].
#[derive(Clone, Copy)]
pub(crate) struct Spans {
    pub clearnet_dial_within: Tick,
    pub clearnet_handshake_within: Tick,
    pub clearnet_gap_within: Tick,
    pub tor_dial_within: Tick,
    pub tor_gap_within: Tick,
    pub send_queue_bytes: usize,
}

impl Spans {
    pub(crate) fn measured() -> Self {
        Self {
            clearnet_dial_within: Tick::new(spans::CLEARNET_DIAL_WITHIN_NANOS),
            clearnet_handshake_within: Tick::new(spans::CLEARNET_HANDSHAKE_WITHIN_NANOS),
            clearnet_gap_within: Tick::new(spans::CLEARNET_GAP_WITHIN_NANOS),
            tor_dial_within: Tick::new(spans::TOR_DIAL_WITHIN_NANOS),
            tor_gap_within: Tick::new(spans::TOR_GAP_WITHIN_NANOS),
            send_queue_bytes: usize::try_from(spans::SEND_QUEUE_BYTES).unwrap_or(usize::MAX),
        }
    }
}

/// The connectors, as one [`Dial`] for the session layer.
pub(crate) struct Connectors {
    pub runtime: tokio::runtime::Handle,
    pub engine: Handle<MonotonicClock>,
    pub sockets: Sockets,
    pub links: Arc<Links>,
    pub network_id: [u8; 16],
    pub spans: Spans,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    /// Set once the clearnet connector is up; a clearnet dial before that
    /// is this node's own refusal.
    pub clearnet: Mutex<Option<ClearnetReady>>,
    /// The Tor proxy as configured (operator) or published (managed). A
    /// Tor dial presents it when the link's route is at the same address.
    pub tor_proxy: Mutex<Option<Proxy>>,
}

impl Connectors {
    pub(crate) fn on_cause() -> Arc<dyn Fn(CloseCause) + Send + Sync> {
        Arc::new(|cause| {
            tracing::debug!(kind = ?cause.kind(), "connector socket");
        })
    }

    pub(crate) fn set_tor_proxy(&self, proxy: Proxy) {
        *self.tor_proxy.lock().expect("tor proxy") = Some(proxy);
    }

    fn start(&self, endpoint: &Endpoint) -> Result<ConnectFuture, DialEnd> {
        match endpoint {
            Endpoint::Clearnet {
                ip,
                port,
                direction,
            } => {
                if *direction != Direction::Outbound {
                    return Err(DialEnd::local_close());
                }
                self.dial_clearnet(*ip, *port)
            }
            Endpoint::Tor { key, port } => self.dial_tor(key, *port),
            Endpoint::TorInbound => Err(DialEnd::local_close()),
        }
    }

    fn dial_clearnet(&self, ip: IpAddr, port: u16) -> Result<ConnectFuture, DialEnd> {
        let ready = self
            .clearnet
            .lock()
            .expect("clearnet")
            .as_ref()
            .map(|ready| ClearnetReady {
                kind: ready.kind,
                tally: Arc::clone(&ready.tally),
                proxy: ready.proxy.clone(),
            })
            .ok_or_else(DialEnd::local_close)?;
        let proxy = match self.links.get(ConnectorId::Clearnet).route {
            Some(Route::Direct) => None,
            Some(Route::Socks(at)) => Some(presented(at, ready.proxy.as_ref())),
            None => return Err(DialEnd::local_close()),
        };
        let address = match ip {
            IpAddr::V4(ip) => NetworkAddress::Ipv4 { ip, port },
            IpAddr::V6(ip) => NetworkAddress::Ipv6 { ip, port },
        };
        let (admitted_tx, admitted_rx) = mpsc::unbounded_channel();
        let (on_end, fail_rx) = failure_slot();
        let dial = shekyl_clearnet::Dial {
            address,
            proxy,
            sockets: self.sockets.clone(),
            kind: ready.kind,
            network_id: self.network_id,
            dial_within: self.spans.clearnet_dial_within,
            // `--proxy` is a SOCKS path the clearnet legs did not measure.
            // The Tor dial is the worst measured SOCKS path; a longer
            // deadline costs only the dialer.
            proxied_dial_within: self.spans.tor_dial_within,
            handshake_within: self.spans.clearnet_handshake_within,
            gap_within: Some(self.spans.clearnet_gap_within),
            tally: ready.tally,
            on_end,
            send_queue_bytes: self.spans.send_queue_bytes,
            admitted: shekyl_clearnet::publish_on(admitted_tx),
        };
        let spawned = self
            .runtime
            .spawn(shekyl_clearnet::dial_one(dial, self.engine.clone()));
        Ok(until_admitted(
            spawned,
            admitted_rx,
            fail_rx,
            move |admitted: shekyl_clearnet::Admitted| Channel {
                open: admitted.open,
                session: admitted.session,
                endpoint: Endpoint::Clearnet {
                    ip,
                    port,
                    direction: Direction::Outbound,
                },
                gap: admitted.gap,
            },
        ))
    }

    fn dial_tor(&self, key: &[u8; 32], port: u16) -> Result<ConnectFuture, DialEnd> {
        let Some(Route::Socks(at)) = self.links.get(ConnectorId::Tor).route else {
            return Err(DialEnd::local_close());
        };
        let proxy = presented(at, self.tor_proxy.lock().expect("tor proxy").as_ref());
        let address = NetworkAddress::Tor {
            host: shekyl_onion_v3::v3_onion_hostname(key),
            port,
        };
        let (admitted_tx, admitted_rx) = mpsc::unbounded_channel();
        let (on_end, fail_rx) = failure_slot();
        let dial = shekyl_tor::Dial {
            address,
            proxy,
            sockets: self.sockets.clone(),
            dial_within: self.spans.tor_dial_within,
            gap_within: self.spans.tor_gap_within,
            on_end,
            send_queue_bytes: self.spans.send_queue_bytes,
            admitted: shekyl_tor::publish_on(admitted_tx),
        };
        let spawned = self
            .runtime
            .spawn(shekyl_tor::dial_one(dial, self.engine.clone()));
        let key = *key;
        Ok(until_admitted(
            spawned,
            admitted_rx,
            fail_rx,
            move |admitted: shekyl_tor::Admitted| Channel {
                open: admitted.open,
                session: admitted.bytes,
                endpoint: Endpoint::Tor { key, port },
                gap: Some(admitted.gap),
            },
        ))
    }
}

/// Adopt a clearnet accept into the session layer.
///
/// The publish reports success. A channel that arrives after the layer has
/// shut down is dropped inside `adopt`, and the connector's task ends with
/// the runtime.
#[must_use]
pub(crate) fn adopt_clearnet(layer: SessionLayer<MonotonicClock>) -> shekyl_clearnet::Publish {
    Arc::new(move |admitted| {
        layer.adopt(Channel {
            open: admitted.open,
            session: admitted.session,
            endpoint: Endpoint::Clearnet {
                ip: admitted.ip,
                port: admitted.port,
                direction: Direction::Inbound,
            },
            gap: admitted.gap,
        });
        true
    })
}

/// Adopt a Tor accept. A dialed host that is not a v3 onion is dropped
/// here, before any byte, and the publish still reports success so the
/// connector does not also close the socket as its own failure.
#[must_use]
pub(crate) fn adopt_tor(layer: SessionLayer<MonotonicClock>) -> shekyl_tor::Publish {
    Arc::new(move |admitted| {
        let endpoint = match admitted.onion {
            Some((host, port)) => match shekyl_onion_v3::v3_pubkey(&host) {
                Some(key) => Endpoint::Tor { key, port },
                None => {
                    tracing::error!("tor session refused: dialed host is not a v3 onion");
                    return true;
                }
            },
            None => Endpoint::TorInbound,
        };
        layer.adopt(Channel {
            open: admitted.open,
            session: admitted.bytes,
            endpoint,
            gap: Some(admitted.gap),
        });
        true
    })
}

impl Dial for Connectors {
    /// The connect as a future that owns the spawned dial until the
    /// connector admits the channel: dropped before then, it aborts that
    /// dial, whose reservation and timer owner release on drop. After
    /// admission the same task drives the stream, so it is no longer
    /// aborted; closing the channel ends it the ordinary way.
    fn connect_async(&self, endpoint: &Endpoint) -> ConnectFuture {
        match self.start(endpoint) {
            Ok(started) => started,
            Err(end) => Box::pin(std::future::ready(Err(end))),
        }
    }

    fn stamp_stream_end(&self, connector: ConnectorId, end: StreamEnd) -> DialFailure {
        stamp(connector, end)
    }
}

/// A stream end shared code observed, stamped from the row's connector's
/// own table: the composition gives it no meaning of its own.
fn stamp(connector: ConnectorId, end: StreamEnd) -> DialFailure {
    match connector {
        ConnectorId::Clearnet => shekyl_clearnet::stamp_stream_end(end),
        ConnectorId::Tor => shekyl_tor::stamp_stream_end(end),
    }
}

/// The proxy a dial presents at `at`: the configured one when it is at
/// that address (its pair goes with it), else an unauthenticated SOCKS
/// connect there.
pub(crate) fn presented(at: SocketAddr, configured: Option<&Proxy>) -> Proxy {
    match configured {
        Some(proxy) if proxy.at() == at => proxy.clone(),
        _ => Proxy::unauthenticated(at),
    }
}

/// Aborts the spawned dial when dropped, unless detached because the
/// connect resolved.
struct AbortUntilAdmitted(Option<tokio::task::JoinHandle<()>>);

impl AbortUntilAdmitted {
    fn detach(&mut self) {
        self.0 = None;
    }
}

impl Drop for AbortUntilAdmitted {
    fn drop(&mut self) {
        if let Some(spawned) = self.0.take() {
            spawned.abort();
        }
    }
}

/// The wait for `spawned`'s admission, as a [`ConnectFuture`]. The abort
/// guard is captured before the future yields, so a drop aborts `spawned`
/// even when the future was never polled.
fn until_admitted<T: Send + 'static>(
    spawned: tokio::task::JoinHandle<()>,
    admitted_rx: mpsc::UnboundedReceiver<T>,
    fail_rx: oneshot::Receiver<DialEnd>,
    into_channel: impl FnOnce(T) -> Channel + Send + 'static,
) -> ConnectFuture {
    let mut guard = AbortUntilAdmitted(Some(spawned));
    Box::pin(async move {
        let admitted = recv_admitted(admitted_rx, fail_rx).await?;
        guard.detach();
        Ok(into_channel(admitted))
    })
}

/// The connector's first end, for the connect future: its failure before
/// the channel. Later calls (the stream's end after admission) find the
/// slot taken.
fn failure_slot() -> (
    Arc<dyn Fn(DialEnd) + Send + Sync>,
    oneshot::Receiver<DialEnd>,
) {
    let (tx, rx) = oneshot::channel();
    let slot = Arc::new(Mutex::new(Some(tx)));
    let on_end = Arc::new(move |end: DialEnd| {
        if let Some(tx) = slot.lock().expect("dial failure").take() {
            match tx.send(end) {
                Ok(()) | Err(_) => {}
            }
        }
    });
    (on_end, rx)
}

async fn recv_admitted<T>(
    mut rx: mpsc::UnboundedReceiver<T>,
    fail: oneshot::Receiver<DialEnd>,
) -> Result<T, DialEnd> {
    tokio::pin!(fail);
    tokio::select! {
        biased;
        admitted = rx.recv() => match admitted {
            Some(value) => Ok(value),
            // The dial task sends the cause and then drops the admission
            // channel. Both are ready together, and this arm is first, so
            // a closed channel is not itself the cause. Awaiting `fail`
            // here is bounded by that task: it owns the sender, dropped
            // when the task returns, which is when the channel closes.
            None => match fail.await {
                Ok(end) => Err(end),
                Err(_) => Err(DialEnd::local_close()),
            },
        },
        result = &mut fail => match result {
            Ok(end) => Err(end),
            Err(_) => Err(DialEnd::local_close()),
        },
    }
}

#[cfg(test)]
mod tests {
    use shekyl_transport_layer::{ConnectorId, StreamEnd};

    use super::stamp;

    /// Every end on every connector is that connector's own stamp. Red on
    /// dispatching to the other connector's table.
    #[test]
    fn each_stream_end_is_stamped_from_its_connectors_table() {
        for end in [
            StreamEnd::PeerClosed,
            StreamEnd::IoError,
            StreamEnd::SendQueueFull,
        ] {
            assert_eq!(
                stamp(ConnectorId::Clearnet, end),
                shekyl_clearnet::stamp_stream_end(end),
                "clearnet {end:?}"
            );
            assert_eq!(
                stamp(ConnectorId::Tor, end),
                shekyl_tor::stamp_stream_end(end),
                "tor {end:?}"
            );
        }
    }
}
