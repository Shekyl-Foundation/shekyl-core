// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer as the session layer's peers owner.
//!
//! The layer asks for the list a handshake or timed sync discloses, hands
//! over the lists peers send, and reports a session established or closed.
//! An inbound Tor session is held once its handshake finishes, and dropped
//! from that count when it closes. A handshake still open is not held.

use shekyl_levin::PeerlistEntry;
use shekyl_p2p_session::{Endpoint, Established, PeerOwner, SessionFacts};
use shekyl_peerlist::{ConnectorId, NetworkAddress};
use shekyl_timing_engine::Clock;
use shekyl_transport_layer::DialEnd;

use super::{session_of, Dialer};

impl<C: Clock + Clone + Send + Sync + 'static> PeerOwner for Dialer<C> {
    /// The list this node discloses on `connector`, less the addresses it
    /// holds a kept session to (the lists' own rule).
    fn disclosure(&self, connector: ConnectorId) -> Vec<PeerlistEntry> {
        let now = self.now();
        let mut rng = self.rng.lock().expect("dialer rng");
        let mut shared = self.shared();
        let mut kept = shared.kept_addresses(connector);
        shared
            .lists
            .disclose(connector, now, &mut kept, &mut **rng)
            .into_iter()
            .map(|adr| PeerlistEntry { adr })
            .collect()
    }

    /// A list a peer sent on an established session. The lists admit or
    /// refuse it; a refusal closes the session.
    fn list_received(&self, session: &Established, list: Vec<PeerlistEntry>) {
        let addresses: Vec<NetworkAddress> = list.into_iter().map(|entry| entry.adr).collect();
        self.admit_on_established(session, &addresses);
    }

    /// An inbound Tor session finished its handshake: it is held.
    fn on_established(&self, session: &Established) {
        if *session.endpoint() == Endpoint::TorInbound {
            self.note_inbound_tor();
        }
    }

    /// A session closed. The board no longer holds its row; the inbound
    /// rows are re-read before the close is applied. The lists forget the
    /// session's intake ledger: socket ids never repeat, so a ledger left
    /// behind is a row for the life of the process.
    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        self.shared()
            .lists
            .forget_session(facts.connector(), session_of(facts.id));
        if facts.endpoint == Endpoint::TorInbound {
            self.note_inbound_tor();
        }
        let mut rng = self.rng.lock().expect("dialer rng");
        self.session_closed(facts.id, end, &mut **rng);
    }
}
