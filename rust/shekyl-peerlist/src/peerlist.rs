// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The lists, one partition per connector, and the door.

use std::net::IpAddr;

use shekyl_draw_rng::RelayRng;
use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::ConnectionId;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{connector_for, BanList, ConnectorId};

use crate::address_file::{self, AddressFileError};
use crate::outcome::{DialOutcome, ListName, Refusal, SessionRow, Source, WhiteClock};
use crate::partition::{DiscloseEarly, DiscloseEarlyEnd, Partition};
use crate::validity::RefusedSet;
use crate::{white_diversity_floor, Ladder, DISCLOSE_COUNT, WHITE_REFILL_LINE};

/// The ban list as the peer list reads it (D4): a question, never a write.
/// The transport layer's [`BanList`] answers it; [`NoBans`] answers "no"
/// for a connector whose addresses cannot be banned, and for tests.
pub trait BanQuery {
    /// Whether `host` is under an active ban at `now`.
    fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool;
}

/// The kept sessions white expiry skips (the gray lifecycle, Rick
/// 2026-10-24). The dialer answers with the set whose close moves the
/// clock ([`Peerlist::session_ended`]). A caller with no sessions passes
/// [`NoSessions`]. This is not a ban: a ban demotes, a kept session is
/// contact.
pub trait KeptSessions {
    /// Whether this node holds a kept session to `address`.
    fn is_kept(&mut self, address: &NetworkAddress) -> bool;
}

impl KeptSessions for std::collections::BTreeSet<NetworkAddress> {
    fn is_kept(&mut self, address: &NetworkAddress) -> bool {
        self.contains(address)
    }
}

impl BanQuery for BanList {
    fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool {
        BanList::is_banned(self, host, now)
    }
}

/// One connector's seats after a single demotion and expiry.
///
/// `white` and `gray` are seats. `white_candidates` and `gray_candidates`
/// are hosts the draw could return: a host with many ports is one
/// candidate. Outstanding gray is in `gray` and in neither candidate count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeatCensus {
    /// White seats.
    pub white: usize,
    /// Hosts a white draw could return.
    pub white_candidates: usize,
    /// Gray seats, outstanding draws included.
    pub gray: usize,
    /// Hosts a gray draw could return.
    pub gray_candidates: usize,
}

/// A partition that has already been demoted and expired.
///
/// Counts and draws on this view do not demote again. The borrow ends
/// when the view drops, and the lists can be admitted to again.
pub struct Settled<'a> {
    partition: &'a mut Partition,
}

impl Settled<'_> {
    /// The four counts, with `eligible` as the dialer's candidate filter.
    pub fn census(&self, eligible: &mut dyn FnMut(&NetworkAddress) -> bool) -> SeatCensus {
        SeatCensus {
            white: self.partition.white_len(),
            white_candidates: self.partition.candidate_hosts(true, eligible),
            gray: self.partition.gray_len(),
            gray_candidates: self.partition.candidate_hosts(false, eligible),
        }
    }

    /// One gray candidate, remembered as an outstanding draw.
    pub fn draw_gray<R: RelayRng + ?Sized>(
        &mut self,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        self.partition.draw_gray_candidate(eligible, rng)
    }

    /// One white candidate. A re-contact: not a promotion, and not a
    /// second demotion.
    pub fn draw_white<R: RelayRng + ?Sized>(
        &self,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        self.partition.draw_white_candidate(eligible, rng)
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

/// No kept session. Expiry reads the clock alone.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSessions;

impl KeptSessions for NoSessions {
    fn is_kept(&mut self, _address: &NetworkAddress) -> bool {
        false
    }
}

/// Every address the lists hold and which list it is on. For the RPC
/// `peers` grant: no clock, no order, no outstanding-draw state.
pub type Snapshot = Vec<(NetworkAddress, ListName)>;

/// The peer lists of one node: a gray and a white list per connector and
/// the one door between them. Seeds are ordinary peers (brief §3, Rick
/// 2026-10-11): this crate holds no seed list and makes no exception for
/// one. The daemon admits the compiled seed addresses to gray at each
/// start as `Source::Operator`, and they reach white as any address does.
#[derive(Debug)]
pub struct Peerlist {
    /// One partition per connector, indexed by [`ConnectorId::index`].
    partitions: Vec<Partition>,
    /// The addresses the network may not hand this node (brief §2).
    refused: RefusedSet,
}

impl Peerlist {
    /// Empty lists, one partition per connector. `refused` is the set of
    /// addresses a peer may not hand this node and this node does not
    /// disclose or store: [`RefusedSet::NON_GLOBAL`], or
    /// [`RefusedSet::EMPTY`] under `--allow-local-ip`. It is fixed for the
    /// life of the lists.
    #[must_use]
    pub fn new(refused: RefusedSet) -> Self {
        Self {
            partitions: (0..ConnectorId::COUNT)
                .map(|_| Partition::default())
                .collect(),
            refused,
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
    /// ban is refused (D4), before any intake charge. A session that has
    /// offered [`crate::SESSION_INTAKE_CAP`] other distinct addresses
    /// within the intake span is refused (D-S1); the caller applies that
    /// to the session. An address that already sits — gray, including a
    /// cooling seat, outstanding, or white — is left where it is and is
    /// not a new intake charge.
    /// An address in the refused set is [`Refusal::NotGlobal`] unless the
    /// operator named it (brief §2): the check is here and not at the
    /// draws, which would strike operator-named addresses.
    /// Returns whether it newly entered gray.
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
        if !matches!(source, Source::Operator) && self.refused.refuses(address).is_some() {
            return Err(Refusal::NotGlobal);
        }
        if address.ip().is_some_and(|ip| bans.is_banned(ip, now)) {
            return Err(Refusal::Banned);
        }
        let partition = self.partition_mut(connector);
        if let Source::Session { id, .. } = source {
            if partition.is_seated(address) {
                partition.refresh_intake(id, address, now);
                return Ok(false);
            }
            if !partition.record_intake(id, address, now) {
                return Err(Refusal::PeerlistRefused);
            }
        }
        Ok(partition.insert_gray(address, rng))
    }

    /// Admit a list a peer sent over `session` (brief §2).
    /// More than [`DISCLOSE_COUNT`] addresses is `PeerlistRefused` (D3's
    /// receiver limit): the message is not trimmed and kept. One entry
    /// whose type no connector serves, or whose connector is not the
    /// session's, rejects the whole list before anything is admitted
    /// (`net_node.inl:2460` to `:2466`). So does one entry in the refused
    /// set, as `PeerlistRefused` (R4): an honest node never sends one,
    /// because [`Self::disclose`] filters them, so the entry is evidence
    /// about the sender. A banned entry is skipped, not a
    /// rejection of the list (D4). Returns how many were new.
    ///
    /// Every exchange is an exchange (Rick, 2026-10-13, PR-3 brief §2.5):
    /// a list is admitted on an inbound session as on an outbound one,
    /// under these same limits. *Records-was* PWD-I2's direction rule, an
    /// inbound list admitting nothing: it made discovery circular, since a
    /// node's own address travels only in its own sample and that sample
    /// was accepted only by peers that had already dialled it. What that
    /// rule was against — 250 entries per message, FIFO eviction, no
    /// per-session cap (Shi et al. §III-A) — is gone; what remains, an
    /// attacker holding many inbound sessions, is bounded by D-S1 and the
    /// inbound ceiling. Reopen: if §99 PM-2a shows gray or outbound
    /// occupation beyond the attacker's share of honest addresses.
    pub fn admit_received_list<R: RelayRng + ?Sized>(
        &mut self,
        addresses: &[NetworkAddress],
        session: SessionRow,
        now: Tick,
        bans: &mut dyn BanQuery,
        rng: &mut R,
    ) -> Result<usize, Refusal> {
        let SessionRow {
            id: session,
            connector,
        } = session;
        // Every exchange is an exchange (§2.5, Rick 2026-10-13): the list is
        // admitted whichever way the session was opened, under the limits
        // that bind every session. *Records-was:* PWD-I2's direction rule
        // returned Ok(0) for an inbound session here.
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
        if addresses
            .iter()
            .any(|address| self.refused.refuses(address).is_some())
        {
            return Err(Refusal::PeerlistRefused);
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
    pub fn forget_session(&mut self, connector: ConnectorId, session: ConnectionId) {
        self.partition_mut(connector).forget_session(session);
    }

    /// Distinct addresses `session` has offered on `connector` within the
    /// intake span (D-S1).
    pub fn intake_count(
        &mut self,
        connector: ConnectorId,
        session: ConnectionId,
        now: Tick,
    ) -> usize {
        self.partition_mut(connector).intake_count(session, now)
    }

    /// The dialer's pre-dial check (D4): a gray entry under an active ban
    /// is skipped while the ban lasts. `true` is "may dial".
    pub fn pre_dial_check(address: &NetworkAddress, now: Tick, bans: &mut dyn BanQuery) -> bool {
        !address.ip().is_some_and(|ip| bans.is_banned(ip, now))
    }

    /// This node's own dialable address on `connector`, or none.
    ///
    /// `None` clears it. An address whose connector is not `connector` is
    /// [`Refusal::ForeignConnector`] and is not stored; an address no
    /// connector serves is [`Refusal::NoConnector`]. When set, the address
    /// is one uniform member of the disclosure population (the
    /// handshake-address ruling) and is never a white entry. An address
    /// that is also listed stays listed: disclosure already dedups it.
    pub fn set_own_address(
        &mut self,
        connector: ConnectorId,
        address: Option<NetworkAddress>,
    ) -> Result<(), Refusal> {
        if let Some(address) = &address {
            let Some(home) = Self::connector_of(address) else {
                return Err(Refusal::NoConnector);
            };
            if home != connector {
                return Err(Refusal::ForeignConnector);
            }
        }
        self.partition_mut(connector).set_own_address(address);
        Ok(())
    }

    /// The connector's disclosure sample (D3): the window's sample, once
    /// drawn, served unchanged until the window ends; at the draw, empty
    /// while the eligible white list is below [`white_diversity_floor`],
    /// else `min(DISCLOSE_COUNT, population)` drawn uniformly from white
    /// plus this node's own address. An address in the refused set is
    /// never in the sample (brief §2): the filter is on the sample, not on
    /// white, so an operator-named private address that was confirmed
    /// stays white and is not told to a peer. Demotion (D4) and expiry
    /// run first, and neither rebuilds a sample already drawn.
    pub fn disclose<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        kept: &mut dyn KeptSessions,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        let refused = self.refused;
        let partition = self.partition_mut(connector);
        partition.demote_banned(&mut |ip, at| bans.is_banned(ip, at), now, rng);
        partition.thaw(now);
        partition.expire(now, &mut |address| kept.is_kept(address), rng);
        Self::end_disclose_early_if_due(connector, partition, now);
        partition.disclose(white_diversity_floor(), &refused, now, rng)
    }

    /// `--p2p-disclose-early` reached the lists at `now` (Rick, 2026-10-13,
    /// PR-3 brief revision 3 §2.6): every connector discloses below the
    /// floor, with a fresh draw per request, until
    /// [`crate::P2P_DISCLOSE_EARLY_SPAN_NANOS`] from `now` or until that
    /// connector's white count first reaches the floor; once ended on a
    /// connector it stays ended for the run. The local operator triggers
    /// it; the network's discovery while it boots is what benefits; no
    /// remote party can set, extend or end it. While it runs a node is
    /// recognisable, since it answers where an unflagged node returns
    /// nothing.
    pub fn set_disclose_early(&mut self, now: Tick) {
        for partition in &mut self.partitions {
            partition.set_disclose_early(now);
        }
    }

    /// The flag's state on `connector`: `None` when it was never set.
    #[must_use]
    pub fn disclose_early(&self, connector: ConnectorId) -> Option<DiscloseEarly> {
        self.partition(connector).disclose_early()
    }

    /// End the connector's flag if the span ran out or white reached the
    /// floor, and say so (rule 82).
    fn end_disclose_early_if_due(connector: ConnectorId, partition: &mut Partition, now: Tick) {
        match partition.end_disclose_early_if_due(white_diversity_floor(), now) {
            Some(DiscloseEarlyEnd::Floor) => tracing::info!(
                "{connector:?}: --p2p-disclose-early ends, white reached the floor of {}; the usual disclosure rules apply from here",
                white_diversity_floor()
            ),
            Some(DiscloseEarlyEnd::Span) => tracing::info!(
                "{connector:?}: --p2p-disclose-early ends, its span ran out; the usual disclosure rules apply from here"
            ),
            None => {}
        }
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
        kept: &mut dyn KeptSessions,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        let partition = self.partition_mut(connector);
        partition.demote_banned(&mut |ip, at| bans.is_banned(ip, at), now, rng);
        partition.thaw(now);
        partition.expire(now, &mut |address| kept.is_kept(address), rng);
        partition.draw_white(rng)
    }

    /// Demote banned white and expire stale white, once, and hand back
    /// the partition. Every white read on the wake goes through here, so
    /// a caller that settles and then draws does not demote again.
    fn prepare<'a, R: RelayRng + ?Sized>(
        &'a mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        kept: &mut dyn KeptSessions,
        rng: &mut R,
    ) -> &'a mut Partition {
        let partition = self.partition_mut(connector);
        partition.demote_banned(&mut |ip, at| bans.is_banned(ip, at), now, rng);
        partition.thaw(now);
        partition.expire(now, &mut |address| kept.is_kept(address), rng);
        partition
    }

    /// One demotion and one expiry, then the counts and the draws.
    ///
    /// The dialer's wake asks this once. [`Self::white_count`],
    /// [`Self::white_candidates`] and [`Self::draw_white_where`] each
    /// prepare on their own for a caller that does only that one thing.
    pub fn settle<'a, R: RelayRng + ?Sized>(
        &'a mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        kept: &mut dyn KeptSessions,
        rng: &mut R,
    ) -> Settled<'a> {
        Settled {
            partition: self.prepare(connector, now, bans, kept, rng),
        }
    }

    /// One gray dial candidate of `connector`, remembered as an
    /// outstanding draw until [`Self::apply`] resolves it.
    ///
    /// The draw is uniform over the hosts that have a drawable gray
    /// address `eligible` admits, then uniform over that host's eligible
    /// ports: a host that advertises many ports is drawn no more often.
    /// `eligible` is the dialer's candidate filter. `None` when nothing
    /// is eligible. A cooling seat whose cooldown has ended at `now` is
    /// drawable again first (the gray lifecycle).
    pub fn draw_gray_where<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        // A cooldown that has ended frees its seat here too, not only at
        // the next settle: a direct dial past the cooldown draws it.
        let partition = self.partition_mut(connector);
        partition.thaw(now);
        partition.draw_gray_candidate(eligible, rng)
    }

    /// One white dial candidate of `connector`, after demotion (D4) and
    /// expiry at `now`, drawn as [`Self::draw_gray_where`] draws. A
    /// re-contact draw: not a promotion.
    pub fn draw_white_where<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        kept: &mut dyn KeptSessions,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        self.prepare(connector, now, bans, kept, rng)
            .draw_white_candidate(eligible, rng)
    }

    /// How many hosts [`Self::draw_gray_where`] could return.
    #[must_use]
    pub fn gray_candidates(
        &self,
        connector: ConnectorId,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
    ) -> usize {
        self.partition(connector).candidate_hosts(false, eligible)
    }

    /// How many hosts [`Self::draw_white_where`] could return, after
    /// demotion (D4) and expiry at `now`.
    pub fn white_candidates<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        kept: &mut dyn KeptSessions,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> usize {
        self.prepare(connector, now, bans, kept, rng)
            .candidate_hosts(true, eligible)
    }

    /// [`Self::apply_on`] with [`Ladder::Climb`]: a failed test steps the
    /// cooldown ladder.
    pub fn apply<R: RelayRng + ?Sized>(&mut self, outcome: &DialOutcome, now: Tick, rng: &mut R) {
        self.apply_on(outcome, now, Ladder::Climb, rng);
    }

    /// The only writer of white and the only drop of an outstanding gray
    /// draw (brief §5). The match is total: the seat, and, for a
    /// confirmation, whether the session stayed. `ladder` is the cooldown a
    /// failed test takes; the dialer chooses it.
    pub fn apply_on<R: RelayRng + ?Sized>(
        &mut self,
        outcome: &DialOutcome,
        now: Tick,
        ladder: Ladder,
        rng: &mut R,
    ) {
        let Some(connector) = Self::connector_of(outcome.address()) else {
            return;
        };
        let partition = self.partition_mut(connector);
        match outcome {
            // Outstanding draw: white, clock stamped `now`. Already white:
            // the clock moves only because the session stayed (brief §5).
            // A white write is where `--p2p-disclose-early` ends at the floor
            // (§2.6): whenever white crosses, not only at a disclosure.
            DialOutcome::SessionAccepted(address) => {
                partition.confirm(address, now, rng, WhiteClock::Move);
                Self::end_disclose_early_if_due(connector, partition, now);
            }
            DialOutcome::Confirmed(address) => {
                partition.confirm(address, now, rng, WhiteClock::Hold);
                Self::end_disclose_early_if_due(connector, partition, now);
            }
            // The gray lifecycle (Rick, 2026-10-24): an address leaves gray
            // only on authenticated proof of misbehaviour, never for a
            // connection problem. The lists read the cause's marks and
            // nothing else. A test that proves misbehaviour drops the
            // outstanding draw; any other failed test returns it to gray
            // with a cooldown. *Records-was (2026-10-16, #1092): dropped
            // whatever the cause.*
            DialOutcome::DialFailed(address, cause)
            | DialOutcome::PeerlistRefused(address, cause) => {
                if cause.proves_misbehaviour() {
                    partition.drop_outstanding(address);
                } else {
                    partition.cool(address, now, ladder, rng);
                }
            }
            // The strand refused the payload. White is unchanged. An
            // outstanding draw returns to drawable gray.
            DialOutcome::PayloadRefused(address) => {
                partition.settle_outstanding(address);
            }
        }
    }

    /// The dialer drew `address` and did not start the test. An outstanding
    /// seat returns to drawable gray on the same ladder rung. White and
    /// cooling are left as they are. This is not an outcome: the ladder
    /// does not move.
    pub fn release_draw(&mut self, address: &NetworkAddress) {
        let Some(connector) = Self::connector_of(address) else {
            return;
        };
        self.partition_mut(connector).settle_outstanding(address);
    }

    /// A kept session to `address` ended at `now` (the gray lifecycle,
    /// item 1): its white clock moves to the close time, so the 24 hours
    /// of expiry count from the end of the connection. An address that is
    /// not white is left as it is. Returns whether a clock moved.
    pub fn session_ended(&mut self, address: &NetworkAddress, now: Tick) -> bool {
        match Self::connector_of(address) {
            Some(connector) => self.partition_mut(connector).session_ended(address, now),
            None => false,
        }
    }

    /// Whether `address` is gray and cooling after a failed test: seated,
    /// written to the file as any gray address, not drawable until its
    /// cooldown ends.
    #[must_use]
    pub fn is_cooling(&self, address: &NetworkAddress) -> bool {
        Self::connector_of(address).is_some_and(|c| self.partition(c).is_cooling(address))
    }

    /// How many failed tests in a row `address` has had: the rung of its
    /// cooldown ladder. Zero after a confirmation, or for an address that
    /// never failed.
    #[must_use]
    pub fn failed_tests(&self, address: &NetworkAddress) -> u32 {
        Self::connector_of(address).map_or(0, |c| self.partition(c).failed_tests(address))
    }

    /// White entries of `connector` at `now`, after demotion (D4) and
    /// expiry: the eligible count the floor and the refill line read. The
    /// draw is for the gray eviction a demotion may cause (F3).
    pub fn white_count<R: RelayRng + ?Sized>(
        &mut self,
        connector: ConnectorId,
        now: Tick,
        bans: &mut dyn BanQuery,
        kept: &mut dyn KeptSessions,
        rng: &mut R,
    ) -> usize {
        self.prepare(connector, now, bans, kept, rng).white_len()
    }

    /// Gray entries of `connector`, outstanding draws included. Drawing
    /// an address does not free its gray seat.
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
        kept: &mut dyn KeptSessions,
        rng: &mut R,
    ) -> bool {
        self.white_count(connector, now, bans, kept, rng) < WHITE_REFILL_LINE
    }

    /// The earliest white expiry of `connector`: the one deadline the
    /// refill trigger holds (brief §2). `None` when white is empty.
    #[must_use]
    pub fn next_expiry(&self, connector: ConnectorId) -> Option<Tick> {
        self.partition(connector).next_expiry()
    }

    /// Every address, unordered, for the file (brief §7): gray and white
    /// together, no clock, no list. An address in the refused set is not
    /// written, and neither is one whose host is under an active ban at
    /// `now` (Rick, 2026-10-24: the file carries addresses, never
    /// judgements; a banned address is left out, and the ban is not
    /// saved). The ban list is the caller's, asked through `bans` as the
    /// draws ask it. No address is left out for who supplied it.
    #[must_use]
    pub fn persistable(&self, bans: &mut dyn BanQuery, now: Tick) -> Vec<NetworkAddress> {
        self.partitions
            .iter()
            .flat_map(Partition::persistable)
            .filter(|address| self.refused.refuses(address).is_none())
            .filter(|address| !address.ip().is_some_and(|ip| bans.is_banned(ip, now)))
            .cloned()
            .collect()
    }

    /// Reload the file: every address to gray, unordered, its connector
    /// derived again; an address whose type no connector serves is dropped
    /// (brief §7), and so is one in the refused set, as a backstop for a
    /// file written under `--allow-local-ip`. Returns how many were
    /// admitted.
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

    /// The address file's bytes (brief §7): [`Self::persistable`] at `now`
    /// under `bans`, in the current [`crate::address_file`] format.
    #[must_use]
    pub fn to_file_bytes(&self, bans: &mut dyn BanQuery, now: Tick) -> Vec<u8> {
        address_file::encode(&self.persistable(bans, now))
    }

    /// Reload from the address file's bytes. A file this build cannot
    /// read is dropped whole: the error is returned and the lists are
    /// left as they were. Returns how many addresses were admitted to
    /// gray.
    pub fn restore_file<R: RelayRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<usize, AddressFileError> {
        let addresses = address_file::decode(bytes)?;
        Ok(self.restore(addresses, rng))
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
