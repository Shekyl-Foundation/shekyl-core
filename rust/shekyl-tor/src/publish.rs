// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Publish the loopback forward target as an onion.
//!
//! The control call is [`DaemonTorControl::publish`] with proof-of-work
//! on. A [`DaemonTorPublishError::PowRefused`] is returned as that fault.
//! This function does not call publish again. A bind failure is not this
//! function: [`crate::listen`] returns before a listener exists, and the
//! caller does not insert the zone.
//!
//! The address this returns is what the session layer stores as
//! `m_our_address`. The C++ options stay where they are parsed.

use std::future::Future;
use std::net::SocketAddr;

use shekyl_net_address::NetworkAddress;
use shekyl_tor_control_client::control::onion::ServiceId;
use shekyl_tor_control_daemon::{DaemonTorControl, DaemonTorPublishError, OnionPow};

/// What inbound is after the forward listener is bound.
#[derive(Debug)]
pub enum InboundPosture {
    /// The onion is published. Hand this address up as `m_our_address`.
    Published { address: NetworkAddress },
    /// Tor is up and outbound still works. The onion was not published.
    OutboundOnly { fault: PublishFault },
}

/// Why publish did not produce an onion. `PowRefused` is not retried
/// without proof-of-work.
#[derive(Debug)]
pub enum PublishFault {
    PowRefused { status: u16 },
    Failed,
}

/// Publish `forward` once, with [`OnionPow::Enabled`].
///
/// `publish` is called once. A non-loopback forward is refused before
/// that call. `virtual_port` is the port peers dial. It is the caller's.
pub async fn publish_forward<F, Fut>(
    forward: SocketAddr,
    virtual_port: u16,
    publish: F,
) -> InboundPosture
where
    F: FnOnce(OnionPow) -> Fut,
    Fut: Future<Output = Result<ServiceId, DaemonTorPublishError>>,
{
    if !forward.ip().is_loopback() {
        return InboundPosture::OutboundOnly {
            fault: PublishFault::Failed,
        };
    }
    match publish(OnionPow::Enabled).await {
        Ok(id) => InboundPosture::Published {
            address: NetworkAddress::Tor {
                host: id.hostname(),
                port: virtual_port,
            },
        },
        Err(DaemonTorPublishError::PowRefused { status }) => InboundPosture::OutboundOnly {
            fault: PublishFault::PowRefused { status },
        },
        Err(_) => InboundPosture::OutboundOnly {
            fault: PublishFault::Failed,
        },
    }
}

/// The production call. One `ADD_ONION`, proof-of-work on.
pub async fn publish_with_control(
    control: &DaemonTorControl,
    forward: SocketAddr,
    virtual_port: u16,
    max_streams: u16,
) -> InboundPosture {
    publish_forward(forward, virtual_port, |pow| {
        control.publish(virtual_port, forward, max_streams, pow)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::{publish_forward, InboundPosture, PublishFault};
    use shekyl_net_address::NetworkAddress;
    use shekyl_tor_control_client::control::onion::ServiceId;
    use shekyl_tor_control_daemon::{DaemonTorPublishError, OnionPow};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 18080))
    }

    fn id() -> ServiceId {
        ServiceId::parse("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx")
            .expect("service id")
    }

    #[tokio::test]
    async fn a_pow_refusal_is_not_published_again() {
        let calls = AtomicUsize::new(0);
        let posture = publish_forward(loopback(), 18080, |pow| {
            assert_eq!(pow, OnionPow::Enabled);
            calls.fetch_add(1, Ordering::Relaxed);
            async { Err(DaemonTorPublishError::PowRefused { status: 512 }) }
        })
        .await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        match posture {
            InboundPosture::OutboundOnly {
                fault: PublishFault::PowRefused { status },
            } => assert_eq!(status, 512),
            other => panic!("expected the refusal, got a different posture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_published_onion_is_the_address_handed_up() {
        let posture = publish_forward(loopback(), 18081, |_pow| async { Ok(id()) }).await;
        match posture {
            InboundPosture::Published { address } => match address {
                NetworkAddress::Tor { host, port } => {
                    assert!(host.ends_with(".onion"));
                    assert_eq!(port, 18081);
                }
                _ => panic!("expected a tor address"),
            },
            InboundPosture::OutboundOnly { .. } => panic!("expected a published onion"),
        }
    }

    #[tokio::test]
    async fn a_routable_forward_is_not_published() {
        let calls = AtomicUsize::new(0);
        let routable = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 18080));
        let posture = publish_forward(routable, 18080, |_pow| {
            calls.fetch_add(1, Ordering::Relaxed);
            async { Ok(id()) }
        })
        .await;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        match posture {
            InboundPosture::OutboundOnly {
                fault: PublishFault::Failed,
            } => {}
            other => panic!("expected a refusal before publish, got {other:?}"),
        }
    }
}
