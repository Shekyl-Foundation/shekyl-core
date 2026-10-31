// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The accept-rate bound (`P2P_TRANSPORT_LAYER.md` D10.3): at accept,
//! before any cryptographic work, per connector and per host.
//!
//! A clearnet flooder pays a TCP handshake and some bytes for each
//! connection, and each one costs this node a responder handshake (685 µs
//! on the floor device, C5). The inbound ceiling bounds how many
//! connections exist at once, not how fast they churn, and the blocking
//! pool bounds how many handshakes compute at once, not how many queue. The
//! bound here is the rate: each accepted connection spends one token from
//! its connector's bucket and one from its host's, and a connection either
//! bucket cannot pay for is refused before the handshake starts.
//!
//! A host is what the connector observes of the peer. An IPv4 address is a
//! host; an IPv6 host is its /64, the unit one subscriber is assigned, so a
//! peer cannot mint hosts by walking its own prefix (Rick, 2026-10-30). An
//! IPv4 address carried in IPv6 (`::ffff:a.b.c.d`, what a dual-stack
//! listener reports) is that IPv4 host, never the /64 every such address
//! shares.
//!
//! The rates are protocol data, held per connector in [`accept_bound`]
//! beside its declaration, the same on every node (rule 71). None is an
//! operator setting.

use std::collections::HashMap;
use std::net::IpAddr;

use shekyl_timing_engine::Tick;

use crate::declaration::{declaration, Assessment, BannableInbound, ConnectorId};

/// One bucket's shape, as the generic cell rate algorithm reads it: one
/// token every `token_every_nanos`, and at most `burst` tokens spent at
/// once by a bucket that has been idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptRate {
    /// The refill interval of one token, in nanoseconds. Not zero.
    pub token_every_nanos: u64,
    /// The bucket's depth, in tokens. Not zero.
    pub burst: u32,
}

impl AcceptRate {
    /// How far ahead of `now` a bucket may have spent before it refuses:
    /// `burst - 1` intervals.
    const fn tolerance_nanos(self) -> u64 {
        self.token_every_nanos
            .saturating_mul(self.burst.saturating_sub(1) as u64)
    }

    /// Whether `rate` describes a bucket that can ever pay: a zero interval
    /// or a zero burst is not a rate.
    #[must_use]
    pub const fn is_rate(self) -> bool {
        self.token_every_nanos > 0 && self.burst > 0
    }
}

/// How a connector's inbound connections are bounded before any
/// cryptographic work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptBound {
    /// Each accept spends a token from the connector's bucket and one from
    /// its host's bucket. Clearnet: an inbound peer has an observable
    /// address (`BannableInbound::Yes`).
    ConnectorAndHost {
        /// Every host of this connector together.
        connector: AcceptRate,
        /// One host: an IPv4 address, or an IPv6 /64.
        host: AcceptRate,
    },
    /// No daemon-side limiter. Every inbound peer is the zone, so a limiter
    /// an attacker can trip denies service to every honest peer; the
    /// onion service's proof-of-work charges the attacker instead (D10.4).
    OnionPow,
}

/// Clearnet's connector bucket: one token every 100 ms, a burst of 20.
///
/// **Assumption** (Rick, 2026-10-31; `DAEMON_RELAY_PRIVACY.md` §97). At the
/// full rate the responder spends about 0.7 % of a floor-device core
/// (10 handshakes a second at 684.5 µs each, C5), which proposes a CPU
/// budget of about 1 % of a core. Honest arrivals sit about two hundred
/// times below it. With the clearnet handshake span the linger cap is 34
/// descriptors. Re-derived by the step 7 record's item 6, the flood
/// measured against this limiter.
pub const CLEARNET_CONNECTOR_RATE: AcceptRate = AcceptRate {
    token_every_nanos: 100_000_000,
    burst: 20,
};

/// Clearnet's host bucket (an IPv4 address, or an IPv6 /64): one token
/// every 6 s, a burst of 3.
///
/// **Assumption** (Rick, 2026-10-31; §97). A dial and a white redial from
/// one peer, and a few nodes behind one NAT, fit the burst. Re-derived with
/// the connector's rate.
pub const CLEARNET_HOST_RATE: AcceptRate = AcceptRate {
    token_every_nanos: 6_000_000_000,
    burst: 3,
};

/// The connector's accept-rate bound: protocol data, one row per connector.
///
/// A connector whose inbound peers have an observable address
/// (`BannableInbound::Yes`) carries both buckets, and one whose inbound
/// peers are the zone carries the onion's proof-of-work; the build refuses
/// any other pairing (below).
#[must_use]
pub const fn accept_bound(connector: ConnectorId) -> Assessment<AcceptBound> {
    match connector {
        ConnectorId::Clearnet => Assessment::Assessed(AcceptBound::ConnectorAndHost {
            connector: CLEARNET_CONNECTOR_RATE,
            host: CLEARNET_HOST_RATE,
        }),
        ConnectorId::Tor => Assessment::Assessed(AcceptBound::OnionPow),
    }
}

// Every connector's bound, checked against its declaration at build time:
// a connector whose inbound peers have an address is never left without a
// limiter, nor given rates that cannot pay, and one whose inbound peers are
// the zone is never given a daemon-side limiter an attacker could trip for
// every honest peer (D10.3, D10.4).
const _: () = {
    let mut index = 0;
    while index < ConnectorId::ALL.len() {
        let connector = ConnectorId::ALL[index];
        let observed = declaration(connector.column()).bannable_inbound();
        match (observed, accept_bound(connector)) {
            (
                Assessment::Assessed(BannableInbound::Yes),
                Assessment::Assessed(AcceptBound::ConnectorAndHost { connector, host }),
            ) => assert!(
                connector.is_rate() && host.is_rate(),
                "an observable-address connector's buckets can pay"
            ),
            (Assessment::Assessed(BannableInbound::Yes), _) => {
                panic!("a connector whose inbound peers have an address has an assessed bound")
            }
            (
                Assessment::Assessed(BannableInbound::NoAddress),
                Assessment::Assessed(AcceptBound::OnionPow),
            ) => {}
            (Assessment::Assessed(BannableInbound::NoAddress), _) => {
                panic!("a connector whose inbound peers are the zone has no daemon-side limiter")
            }
            (Assessment::NotAssessed, _) => {
                panic!(
                    "every connector's declaration says whether its inbound peers have an address"
                )
            }
        }
        index += 1;
    }
};

/// How many refused connections may linger half-closed at once for `span`
/// under a connector's row (D10.2): its connector bucket's burst plus the
/// tokens it refills across `span`, the connections it admits in that
/// time. Zero for a row with no daemon-side limiter or not assessed.
///
/// Lingering sockets hold descriptors outside the inbound occupancy, so the
/// daemon reserves this many beside the inbound ceiling; the accept loop's
/// gate caps its lingering at the same figure ([`AcceptGate::linger_cap`]).
#[must_use]
pub fn linger_cap(bound: Assessment<AcceptBound>, span: Tick) -> u64 {
    match bound {
        Assessment::Assessed(AcceptBound::ConnectorAndHost { connector, .. })
            if connector.is_rate() =>
        {
            cap_for(connector, span)
        }
        Assessment::Assessed(_) | Assessment::NotAssessed => 0,
    }
}

const fn cap_for(connector: AcceptRate, span: Tick) -> u64 {
    let refilled = span.get() / connector.token_every_nanos;
    (connector.burst as u64).saturating_add(refilled)
}

/// What one bucket's host key is: an IPv4 address, or an IPv6 /64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostKey {
    /// An IPv4 address, including one carried in IPv6.
    V4([u8; 4]),
    /// The first 64 bits of an IPv6 address.
    V6Prefix64([u8; 8]),
}

impl HostKey {
    /// The host `ip` belongs to.
    #[must_use]
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4.octets()),
                None => {
                    let octets = v6.octets();
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&octets[..8]);
                    Self::V6Prefix64(prefix)
                }
            },
        }
    }
}

/// One bucket: its theoretical arrival time, the instant by which every
/// token it has spent has refilled. A bucket at or before `now` is full.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Bucket {
    tat_nanos: u64,
}

impl Bucket {
    /// The arrival time after one more spend at `now`, or `None` when the
    /// bucket cannot pay. Nothing is spent: [`Self::spend`] commits.
    ///
    /// An arrival time past the clock's end refuses: a saturated one would
    /// never move again, and the bucket would pay for everything after it.
    fn after_spend(self, rate: AcceptRate, now: u64) -> Option<u64> {
        let start = self.tat_nanos.max(now);
        if start - now > rate.tolerance_nanos() {
            return None;
        }
        start.checked_add(rate.token_every_nanos)
    }

    const fn spend(&mut self, tat_nanos: u64) {
        self.tat_nanos = tat_nanos;
    }

    const fn is_full(self, now: u64) -> bool {
        self.tat_nanos <= now
    }
}

/// The smallest host table that is swept for full buckets.
const SWEEP_FLOOR: usize = 64;

/// A connector's buckets: one for the connector, one per host that has
/// spent recently.
///
/// The host table cannot grow past what the connector's own rate lets in.
/// A host entry is made only when the connector's bucket pays, and an entry
/// whose bucket has refilled is the same as no entry, so it is dropped at
/// the next sweep. Live entries are therefore at most the connector's
/// burst plus the accepts its rate allows while one host bucket refills
/// from empty ([`Self::live_host_bound`]): a flooder walking addresses or
/// /64s fills the table no faster than the connector bucket admits it.
#[derive(Debug)]
pub struct AcceptGate {
    connector_rate: AcceptRate,
    host_rate: AcceptRate,
    connector: Bucket,
    hosts: HashMap<HostKey, Bucket>,
    /// The table size that triggers the next sweep: twice what survived the
    /// last one, so a sweep is amortised over the inserts that reach it.
    sweep_at: usize,
    refused: AcceptRefusals,
}

/// Connections the gate refused since the counts were last taken, by the
/// bucket that could not pay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptRefusals {
    /// The host's own bucket was empty.
    pub host: u64,
    /// The host could pay, and the connector's bucket was empty.
    pub connector: u64,
}

impl AcceptRefusals {
    /// Both counts together.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.host.saturating_add(self.connector)
    }
}

impl AcceptGate {
    /// A gate whose buckets are all full. `None` when either rate is not a
    /// rate ([`AcceptRate::is_rate`]).
    #[must_use]
    pub fn new(connector: AcceptRate, host: AcceptRate) -> Option<Self> {
        if !connector.is_rate() || !host.is_rate() {
            return None;
        }
        Some(Self {
            connector_rate: connector,
            host_rate: host,
            connector: Bucket::default(),
            hosts: HashMap::new(),
            sweep_at: SWEEP_FLOOR,
            refused: AcceptRefusals::default(),
        })
    }

    /// The gate a connector's row describes, or `None` when the row has no
    /// daemon-side limiter or is not assessed.
    #[must_use]
    pub fn for_bound(bound: Assessment<AcceptBound>) -> Option<Self> {
        match bound {
            Assessment::Assessed(AcceptBound::ConnectorAndHost { connector, host }) => {
                Self::new(connector, host)
            }
            Assessment::Assessed(AcceptBound::OnionPow) | Assessment::NotAssessed => None,
        }
    }

    /// Spend one token from the connector's bucket and one from `ip`'s
    /// host bucket at `now`. Either both are spent and the connection may
    /// proceed, or neither is and it is refused: a host whose own bucket is
    /// empty does not drain the connector's, and a refusal by the
    /// connector's bucket leaves no host entry behind.
    pub fn admit(&mut self, ip: IpAddr, now: Tick) -> bool {
        let now = now.get();
        let key = HostKey::of(ip);
        let host = self.hosts.get(&key).copied().unwrap_or_default();
        let Some(host_tat) = host.after_spend(self.host_rate, now) else {
            self.refused.host = self.refused.host.saturating_add(1);
            return false;
        };
        let Some(connector_tat) = self.connector.after_spend(self.connector_rate, now) else {
            self.refused.connector = self.refused.connector.saturating_add(1);
            return false;
        };
        self.connector.spend(connector_tat);
        self.hosts.entry(key).or_default().spend(host_tat);
        if self.hosts.len() >= self.sweep_at {
            self.hosts.retain(|_, bucket| !bucket.is_full(now));
            self.sweep_at = SWEEP_FLOOR.max(self.hosts.len().saturating_mul(2));
        }
        true
    }

    /// The refusals since the last call, and start counting again.
    pub fn take_refusals(&mut self) -> AcceptRefusals {
        std::mem::take(&mut self.refused)
    }

    /// Host entries in the table now, swept or not.
    #[must_use]
    pub fn host_entries(&self) -> usize {
        self.hosts.len()
    }

    /// How many refused connections may linger half-closed at once for
    /// `span` (D10.2): the connector bucket's burst plus the tokens it
    /// refills across `span`, the number of connections this connector
    /// admits in that time. A refusal beyond it closes at once.
    #[must_use]
    pub fn linger_cap(&self, span: Tick) -> usize {
        usize::try_from(cap_for(self.connector_rate, span)).unwrap_or(usize::MAX)
    }

    /// The most host entries whose buckets can be not full at one instant:
    /// the connector's burst, plus one per connector interval across the
    /// time a host bucket takes to refill from empty.
    #[must_use]
    pub const fn live_host_bound(&self) -> u64 {
        let refill = self
            .host_rate
            .token_every_nanos
            .saturating_mul(self.host_rate.burst as u64);
        (self.connector_rate.burst as u64)
            .saturating_add(refill / self.connector_rate.token_every_nanos)
            .saturating_add(1)
    }
}

#[cfg(test)]
#[path = "accept_rate_tests.rs"]
mod tests;
