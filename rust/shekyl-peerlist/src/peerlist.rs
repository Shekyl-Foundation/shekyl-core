// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The lists, one partition per connector, and the door.

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{connector_for, ConnectorId};

use crate::outcome::{DialOutcome, ListName, Refusal, Source};
use crate::partition::Partition;
use crate::WHITE_REFILL_LINE;

/// Every address the lists hold and which list it is on. For the RPC
/// `peers` grant: no clock, no order, no outstanding-draw state.
pub type Snapshot = Vec<(NetworkAddress, ListName)>;

/// The peer lists of one node: a gray and a white list per connector, the
/// door between them, and the Foundation fleet the door makes an exception
/// for.
#[derive(Debug)]
pub struct Peerlist {
    /// One partition per connector, indexed by [`ConnectorId::index`].
    partitions: Vec<Partition>,
    /// The hardcoded Foundation seed fleet (brief §3). Data this crate
    /// reads: `HarvestDone` of one of these writes white. Supplied by the
    /// daemon, which owns the compiled list.
    fleet: Vec<NetworkAddress>,
}

impl Peerlist {
    /// Empty lists. `fleet` is the Foundation seed fleet; a harvest of any
    /// other address writes nothing.
    #[must_use]
    pub fn new(fleet: Vec<NetworkAddress>) -> Self {
        Self {
            partitions: (0..ConnectorId::COUNT)
                .map(|_| Partition::default())
                .collect(),
            fleet,
        }
    }

    fn partition(&self, connector: ConnectorId) -> &Partition {
        &self.partitions[connector.index()]
    }

    fn partition_mut(&mut self, connector: ConnectorId) -> &mut Partition {
        &mut self.partitions[connector.index()]
    }

    /// The connector an address belongs to, from its type (ruled
    /// 2026-09-25). `None` is an address type no local connector serves.
    #[must_use]
    pub fn connector_of(address: &NetworkAddress) -> Option<ConnectorId> {
        connector_for(address)
    }

    /// Admit one address to gray (brief §6). The connector comes from the
    /// address type; an address learned over a session is admitted only
    /// when that connector is the session's. A white entry at the address
    /// is untouched. Returns whether the address was new to gray.
    pub fn admit_gray<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        source: Source,
        rng: &mut R,
    ) -> Result<bool, Refusal> {
        let connector = Self::connector_of(address).ok_or(Refusal::NoConnector)?;
        if let Source::Session {
            connector: session, ..
        } = source
        {
            if session != connector {
                return Err(Refusal::ForeignConnector);
            }
        }
        Ok(self.partition_mut(connector).insert_gray(address, rng))
    }

    /// Admit a list a peer sent over `session` on `connector` (brief §2).
    /// One entry whose type no connector serves, or whose connector is not
    /// the session's, rejects the whole list before anything is admitted
    /// (`net_node.inl:2460` to `:2466`). Returns how many were new.
    pub fn admit_received_list<R: RelayRng + ?Sized>(
        &mut self,
        addresses: &[NetworkAddress],
        session: crate::SessionId,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Result<usize, Refusal> {
        for address in addresses {
            match Self::connector_of(address) {
                None => return Err(Refusal::NoConnector),
                Some(c) if c != connector => return Err(Refusal::ForeignConnector),
                Some(_) => {}
            }
        }
        let mut admitted = 0;
        for address in addresses {
            if self.admit_gray(
                address,
                Source::Session {
                    id: session,
                    connector,
                },
                rng,
            )? {
                admitted += 1;
            }
        }
        Ok(admitted)
    }

    /// One uniform gray address of `connector`, remembered as an
    /// outstanding draw until [`Self::apply`] resolves it.
    pub fn draw_gray<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        self.partition_mut(connector).draw_gray(rng)
    }

    /// One uniform white address of `connector`, after expiry has been
    /// evaluated at `now`. A re-contact draw: not a promotion.
    pub fn draw_white<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        let partition = self.partition_mut(connector);
        partition.expire(now);
        partition.draw_white(rng)
    }

    /// The only writer of white and the only drop of an outstanding gray
    /// draw (brief §5). The match is total.
    pub fn apply<R: RelayRng + ?Sized>(&mut self, outcome: &DialOutcome, now: Tick, rng: &mut R) {
        let Some(connector) = Self::connector_of(outcome.address()) else {
            return;
        };
        let fleet = self.fleet.contains(outcome.address());
        let partition = self.partition_mut(connector);
        match outcome {
            DialOutcome::SessionAccepted(address) | DialOutcome::Confirmed(address) => {
                if partition.is_outstanding(address) {
                    partition.promote(address, now, rng);
                } else {
                    // Already white on a session this node opened: the clock
                    // moves. An undrawn ordinary address: nothing.
                    partition.touch(address, now);
                }
            }
            DialOutcome::HarvestDone(address) => {
                if fleet {
                    partition.promote(address, now, rng);
                }
            }
            DialOutcome::DialFailed(address) | DialOutcome::PeerlistRefused(address) => {
                partition.drop_draw(address);
            }
            DialOutcome::PayloadRefused(address) => {
                partition.settle_draw(address);
            }
        }
    }

    /// White entries of `connector` at `now`, after expiry.
    pub fn white_count(&mut self, connector: ConnectorId, now: Tick) -> usize {
        let partition = self.partition_mut(connector);
        partition.expire(now);
        partition.white_len()
    }

    /// Gray entries of `connector`.
    #[must_use]
    pub fn gray_count(&self, connector: ConnectorId) -> usize {
        self.partition(connector).gray_len()
    }

    /// Whether `address` is white, on its own connector's list.
    #[must_use]
    pub fn is_white(&self, address: &NetworkAddress) -> bool {
        Self::connector_of(address).is_some_and(|c| self.partition(c).is_white(address))
    }

    /// Whether `address` is gray, on its own connector's list.
    #[must_use]
    pub fn is_gray(&self, address: &NetworkAddress) -> bool {
        Self::connector_of(address).is_some_and(|c| self.partition(c).is_gray(address))
    }

    /// Whether `connector`'s white list is below [`WHITE_REFILL_LINE`] at
    /// `now`: the refill trigger (brief §2). Reported at once when it is;
    /// otherwise [`Self::next_expiry`] is when to ask again.
    pub fn below_refill_line(&mut self, connector: ConnectorId, now: Tick) -> bool {
        self.white_count(connector, now) < WHITE_REFILL_LINE
    }

    /// The earliest white expiry of `connector`: the one deadline the
    /// refill trigger holds (brief §2). `None` when white is empty.
    #[must_use]
    pub fn next_expiry(&self, connector: ConnectorId) -> Option<Tick> {
        self.partition(connector).next_expiry()
    }

    /// Every address, unordered, for the file (brief §7): gray and white
    /// together, no clock, no list.
    #[must_use]
    pub fn persistable(&self) -> Vec<NetworkAddress> {
        self.partitions
            .iter()
            .flat_map(Partition::persistable)
            .cloned()
            .collect()
    }

    /// Reload the file: every address to gray, unordered, its connector
    /// derived again; an address whose type no connector serves is dropped
    /// (brief §7). Returns how many were admitted.
    pub fn restore<R: RelayRng + ?Sized>(
        &mut self,
        addresses: Vec<NetworkAddress>,
        rng: &mut R,
    ) -> usize {
        addresses
            .into_iter()
            .filter(|address| self.admit_gray(address, Source::Reload, rng) == Ok(true))
            .count()
    }

    /// Every address and which list it is on, across connectors. No
    /// clock, no order, no draw state.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let mut out = Vec::new();
        for partition in &self.partitions {
            out.extend(partition.gray_iter().map(|a| (a.clone(), ListName::Gray)));
            out.extend(partition.white_iter().map(|a| (a.clone(), ListName::White)));
        }
        out
    }
}
