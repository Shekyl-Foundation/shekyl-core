// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The lists, one partition per connector, and the door.

use std::net::IpAddr;

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{connector_for, BanList, ConnectorId};

use crate::outcome::{DialOutcome, ListName, Refusal, SessionId, Source};
use crate::partition::Partition;
use crate::{white_diversity_floor, DISCLOSE_COUNT, WHITE_REFILL_LINE};

/// The ban list as the peer list reads it (D4): a question, never a write.
/// The transport layer's [`BanList`] answers it; [`NoBans`] answers "no"
/// for a connector whose addresses cannot be banned, and for tests.
pub trait BanQuery {
    /// Whether `host` is under an active ban at `now`.
    fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool;
}

impl BanQuery for BanList {
    fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool {
        BanList::is_banned(self, host, now)
    }
}

/// No host is banned.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBans;

impl BanQuery for NoBans {
    fn is_banned(&mut self, _host: IpAddr, _now: Tick) -> bool {
        false
    }
}

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
    /// when that connector is the session's. An address under an active
    /// ban is refused (D4). A session that has offered
    /// [`crate::SESSION_INTAKE_CAP`] other distinct addresses within the
    /// intake span is refused (D-S1); the caller applies that to the
    /// session. A white entry at the address is untouched. Returns whether
    /// the address was new to gray.
    pub fn admit_gray<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        source: Source,
        now: Tick,
        bans: &mut dyn BanQuery,
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
        if address.ip().is_some_and(|ip| bans.is_banned(ip, now)) {
            return Err(Refusal::Banned);
        }
        let partition = self.partition_mut(connector);
        if let Source::Session { id, .. } = source {
            if !partition.record_intake(id, address, now) {
                return Err(Refusal::PeerlistRefused);
            }
        }
        Ok(partition.insert_gray(address, rng))
    }

    /// Admit a list a peer sent over `session` on `connector` (brief §2).
    /// More than [`DISCLOSE_COUNT`] addresses is `PeerlistRefused` (D3's
    /// receiver limit): the message is not trimmed and kept. One entry
    /// whose type no connector serves, or whose connector is not the
    /// session's, rejects the whole list before anything is admitted
    /// (`net_node.inl:2460` to `:2466`). A banned entry is skipped, not a
    /// rejection of the list (D4). Returns how many were new.
    pub fn admit_received_list<R: RelayRng + ?Sized>(
        &mut self,
        addresses: &[NetworkAddress],
        session: SessionId,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        rng: &mut R,
    ) -> Result<usize, Refusal> {
        if addresses.len() > DISCLOSE_COUNT {
            return Err(Refusal::PeerlistRefused);
        }
        for address in addresses {
            match Self::connector_of(address) {
                None => return Err(Refusal::NoConnector),
                Some(c) if c != connector => return Err(Refusal::ForeignConnector),
                Some(_) => {}
            }
        }
        // D-S1 for the whole list (F2): a banned entry never enters gray, so
        // it is not counted; everything else is, before any entry is
        // admitted. A list that would cross the cap admits nothing.
        let counted: Vec<&NetworkAddress> = addresses
            .iter()
            .filter(|a| !a.ip().is_some_and(|ip| bans.is_banned(ip, now)))
            .collect();
        if self
            .partition_mut(connector)
            .would_exceed_intake(session, &counted, now)
        {
            return Err(Refusal::PeerlistRefused);
        }
        let mut admitted = 0;
        for address in addresses {
            match self.admit_gray(
                address,
                Source::Session {
                    id: session,
                    connector,
                },
                now,
                bans,
                rng,
            ) {
                Ok(true) => admitted += 1,
                Ok(false) | Err(Refusal::Banned) => {}
                Err(refusal) => return Err(refusal),
            }
        }
        Ok(admitted)
    }

    /// The session ended; its intake ledger goes with it.
    pub fn forget_session(&mut self, connector: ConnectorId, session: SessionId) {
        self.partition_mut(connector).forget_session(session);
    }

    /// Distinct addresses `session` has offered on `connector` within the
    /// intake span (D-S1).
    pub fn intake_count(&mut self, connector: ConnectorId, session: SessionId, now: Tick) -> usize {
        self.partition_mut(connector).intake_count(session, now)
    }

    /// The dialer's pre-dial check (D4): a gray entry under an active ban
    /// is skipped while the ban lasts. `true` is "may dial".
    pub fn pre_dial_check(address: &NetworkAddress, now: Tick, bans: &mut dyn BanQuery) -> bool {
        !address.ip().is_some_and(|ip| bans.is_banned(ip, now))
    }

    /// This node's own dialable address on `connector`, or none: one
    /// uniform member of the disclosure population when set (the
    /// handshake-address ruling). Never a white entry.
    pub fn set_own_address(&mut self, connector: ConnectorId, address: Option<NetworkAddress>) {
        self.partition_mut(connector).set_own_address(address);
    }

    /// The connector's disclosure sample (D3): the window's sample, once
    /// drawn, served unchanged until the window ends; at the draw, empty
    /// while the eligible white list is below [`white_diversity_floor`],
    /// else `min(DISCLOSE_COUNT, population)` drawn uniformly from white
    /// plus this node's own address. Demotion (D4) and expiry run first,
    /// and neither rebuilds a sample already drawn.
    pub fn disclose<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        let partition = self.partition_mut(connector);
        partition.demote_banned(&mut |ip, at| bans.is_banned(ip, at), now, rng);
        partition.expire(now, rng);
        partition.disclose(white_diversity_floor(), now, rng)
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

    /// One uniform white address of `connector`, after demotion (D4) and
    /// expiry at `now`. A re-contact draw: not a promotion.
    pub fn draw_white<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        let partition = self.partition_mut(connector);
        partition.demote_banned(&mut |ip, at| bans.is_banned(ip, at), now, rng);
        partition.expire(now, rng);
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

    /// White entries of `connector` at `now`, after demotion (D4) and
    /// expiry: the eligible count the floor and the refill line read. The
    /// draw is for the gray eviction a demotion may cause (F3).
    pub fn white_count<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        rng: &mut R,
    ) -> usize {
        let partition = self.partition_mut(connector);
        partition.demote_banned(&mut |ip, at| bans.is_banned(ip, at), now, rng);
        partition.expire(now, rng);
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
    pub fn below_refill_line<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        rng: &mut R,
    ) -> bool {
        self.white_count(connector, now, bans, rng) < WHITE_REFILL_LINE
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
            .filter(|address| {
                self.admit_gray(address, Source::Reload, Tick::new(0), &mut NoBans, rng) == Ok(true)
            })
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
