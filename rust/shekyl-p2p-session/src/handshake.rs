// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Levin handshake's checks and forms (brief §7.4).
//!
//! The same checks run on both directions, in the same order: the bucket
//! decodes as `COMMAND_HANDSHAKE`; `node_data.network_id` is ours (a
//! mismatch is dropped, never banned); the sync payload is read as a
//! claim and not judged. Every failure is a [`DialEnd`] the row keeps.
//!
//! The handshake carries no address on any connector (ruled 2026-10-09):
//! `basic_node_data` is the network id alone, and this node does not
//! record a claimed endpoint for a peer. What a peer discloses, it
//! discloses in the response's list.

use shekyl_levin::{
    invoke, response, BasicNodeData, Command, CoreSyncData, HandshakeRequest, HandshakeResponse,
    PeerlistEntry, PortableMap, TimedSyncRequest, TimedSyncResponse,
};
use shekyl_transport_layer::{
    CloseCause, CloseKind, ConnectorId, DialEnd, DialFailure, Reached, Retry,
};

use crate::nonce::HandshakeNonce;

/// The peer's handshake named another network. Final for the dialer: the
/// destination is not a Shekyl node of this network. Not evidence of
/// misbehaviour: the peer is dropped, never banned.
pub(crate) const fn network_mismatch(connector: ConnectorId) -> DialEnd {
    DialEnd::new(
        DialFailure::refused_by_peer(connector, Reached::StreamOpened),
        CloseCause::new(CloseKind::NetworkMismatch),
    )
}

/// The peer did not follow the session's form on an established session
/// or an inbound handshake: a bucket the state does not accept, a payload
/// that did not decode, a response with no request (PWD-B1). This node's
/// own close of a stream that opened; no dial is judged by it.
pub(crate) const fn form_failure() -> DialEnd {
    DialEnd::new(
        DialFailure::local(Retry::Again, Reached::StreamOpened),
        CloseCause::new(CloseKind::SessionRefused),
    )
}

/// The peer this node dialed did not answer its handshake with a
/// well-formed 1001 response: a bucket that broke framing, that is not the
/// response, or whose payload did not decode. The Levin layer's refusal
/// (`DIALER_OUTAGE_EVIDENCE.md` §2.2): the far end answered about this
/// destination, final, and proof of misbehaviour where the connector
/// authenticates the destination (the gray lifecycle, test 6c).
pub(crate) const fn handshake_refused(connector: ConnectorId) -> DialEnd {
    DialEnd::new(
        DialFailure::refused_by_peer(connector, Reached::StreamOpened),
        CloseCause::new(CloseKind::LevinHandshakeRejected),
    )
}

/// A request this node sent got no response within the invoke deadline.
pub(crate) const fn invoke_timeout() -> DialEnd {
    DialEnd::new(
        DialFailure::uncertain(Retry::AgainInsideWindow, Reached::StreamOpened),
        CloseCause::new(CloseKind::InvokeTimeout),
    )
}

/// What a decoded handshake, either direction, hands on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Checked {
    pub node_data: BasicNodeData,
    pub sync: CoreSyncData,
}

/// Check `node_data` against this node's network.
pub(crate) fn check_network(
    node_data: &BasicNodeData,
    network_id: [u8; 16],
    connector: ConnectorId,
) -> Result<(), DialEnd> {
    if node_data.network_id == network_id {
        Ok(())
    } else {
        Err(network_mismatch(connector))
    }
}

/// Decode and check an inbound 1001 request.
pub(crate) fn check_request(
    payload: &[u8],
    network_id: [u8; 16],
    connector: ConnectorId,
) -> Result<(Checked, HandshakeNonce), DialEnd> {
    let request = HandshakeRequest::load(payload).map_err(|_| form_failure())?;
    check_network(&request.node_data, network_id, connector)?;
    Ok((
        Checked {
            node_data: request.node_data,
            sync: request.payload_data,
        },
        request.nonce,
    ))
}

/// Decode and check a 1001 response to this node's request.
pub(crate) fn check_response(
    payload: &[u8],
    network_id: [u8; 16],
    connector: ConnectorId,
) -> Result<(Checked, Vec<PeerlistEntry>), DialEnd> {
    let response = HandshakeResponse::load(payload).map_err(|_| handshake_refused(connector))?;
    check_network(&response.node_data, network_id, connector)?;
    Ok((
        Checked {
            node_data: response.node_data,
            sync: response.payload_data,
        },
        response.local_peerlist_new,
    ))
}

/// This node's 1001 request: its network, its tip, the minted nonce.
pub(crate) fn request_bucket(
    network_id: [u8; 16],
    tip: CoreSyncData,
    nonce: HandshakeNonce,
) -> Option<Vec<u8>> {
    let payload = HandshakeRequest {
        node_data: BasicNodeData { network_id },
        payload_data: tip,
        nonce,
    }
    .store()
    .ok()?;
    Some(invoke(Command::Handshake.wire_id(), &payload))
}

/// This node's 1001 response: its network, its tip, the disclosure.
pub(crate) fn response_bucket(
    network_id: [u8; 16],
    tip: CoreSyncData,
    disclosure: Vec<PeerlistEntry>,
) -> Option<Vec<u8>> {
    let payload = HandshakeResponse {
        node_data: BasicNodeData { network_id },
        payload_data: tip,
        local_peerlist_new: disclosure,
    }
    .store()
    .ok()?;
    Some(response(Command::Handshake.wire_id(), &payload))
}

/// This node's 1002 request: its tip.
pub(crate) fn timed_sync_request_bucket(tip: CoreSyncData) -> Option<Vec<u8>> {
    let payload = TimedSyncRequest { payload_data: tip }.store().ok()?;
    Some(invoke(Command::TimedSync.wire_id(), &payload))
}

/// This node's 1002 response: its tip and the disclosure.
pub(crate) fn timed_sync_response_bucket(
    tip: CoreSyncData,
    disclosure: Vec<PeerlistEntry>,
) -> Option<Vec<u8>> {
    let payload = TimedSyncResponse {
        payload_data: tip,
        local_peerlist_new: disclosure,
    }
    .store()
    .ok()?;
    Some(response(Command::TimedSync.wire_id(), &payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_transport_layer::Evidence;

    const OURS: [u8; 16] = [7; 16];

    fn tip() -> CoreSyncData {
        CoreSyncData {
            current_height: 3,
            cumulative_difficulty: 30,
            cumulative_difficulty_top64: 0,
            top_id: [3; 32],
        }
    }

    #[test]
    fn a_request_of_another_network_is_dropped_never_banned() {
        let bucket = request_bucket([8; 16], tip(), [1; 32]).expect("encodes");
        let payload = &bucket[shekyl_levin::HEADER_SIZE..];
        for connector in [ConnectorId::Clearnet, ConnectorId::Tor] {
            let end = check_request(payload, OURS, connector).expect_err("mismatch");
            assert_eq!(end.cause().kind(), CloseKind::NetworkMismatch);
            assert_eq!(end.failure().retry(), Retry::Final);
            assert!(
                matches!(end.failure().evidence(), Evidence::Destination(_)),
                "the destination answered: it is another network's node"
            );
        }
    }

    #[test]
    fn a_request_of_our_network_hands_on_its_claim_and_nonce() {
        let bucket = request_bucket(OURS, tip(), [9; 32]).expect("encodes");
        let payload = &bucket[shekyl_levin::HEADER_SIZE..];
        let (checked, nonce) = check_request(payload, OURS, ConnectorId::Clearnet).expect("ours");
        assert_eq!(checked.sync, tip());
        assert_eq!(checked.node_data.network_id, OURS);
        assert_eq!(nonce, [9; 32]);
    }

    /// An inbound request that does not decode is a form failure, local.
    /// A response that does not decode is the dialed peer's refusal: the
    /// Levin layer's, and proof of misbehaviour only where the connector
    /// authenticates the destination.
    #[test]
    fn bytes_that_do_not_decode_are_a_form_failure_or_the_peers_refusal() {
        let end = check_request(b"not a section", OURS, ConnectorId::Clearnet).expect_err("form");
        assert_eq!(end.cause().kind(), CloseKind::SessionRefused);
        assert_eq!(end.failure().evidence(), Evidence::Local);
        for (connector, proves) in [(ConnectorId::Tor, true), (ConnectorId::Clearnet, false)] {
            let end = check_response(b"not a section", OURS, connector).expect_err("refused");
            assert_eq!(end.cause().kind(), CloseKind::LevinHandshakeRejected);
            assert!(matches!(end.failure().evidence(), Evidence::Destination(_)));
            assert_eq!(end.failure().proves_misbehaviour(), proves, "{connector:?}");
            assert_eq!(end.failure().retry(), Retry::Final);
        }
    }

    #[test]
    fn a_response_hands_on_its_list() {
        let bucket = response_bucket(OURS, tip(), vec![]).expect("encodes");
        let payload = &bucket[shekyl_levin::HEADER_SIZE..];
        let (checked, list) = check_response(payload, OURS, ConnectorId::Tor).expect("ours");
        assert_eq!(checked.sync, tip());
        assert!(list.is_empty());
    }
}
