// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The failed-address memory (dialer brief, "Failed-address memory").
//!
//! A dial that failed in a way that names the destination, on a connector
//! that authenticates it, suppresses that address for a window. Forgetting
//! shrinks the dial set, and a shrunken set favours whoever is feeding us
//! addresses, so the memory is written only where
//! [`CloseCause::implicates_address`] says and nowhere else. On clearnet
//! that is never (R2). On Tor it is a rejected handshake and the five
//! destination-naming proxy replies.
//!
//! The dialer is the only writer. It reads the same [`DialOutcome`] the
//! peer lists read, so the list write and this write cannot disagree.
//!
//! The key is the address that was dialed: host and port. A refused port
//! says nothing about another port on that host. The memory is not kept
//! across restarts.

use std::collections::BTreeMap;

use shekyl_peerlist::{CloseCause, DialOutcome, NetworkAddress, Peerlist, Tick};

/// Nanoseconds in a second.
const SECOND_NANOS: u64 = 1_000_000_000;

/// The window after the first failure: four minutes, the 90th percentile
/// of measured onion-descriptor recovery (`P2P_ANON_FAILED_ADDR_FORGET_SECONDS`
/// in the C++ this replaces). A failed onion dial is often a descriptor
/// that has not propagated, against a peer that is up.
pub const FIRST_WINDOW_NANOS: u64 = 240 * SECOND_NANOS;

/// The longest window: one hour (`P2P_FAILED_ADDR_FORGET_SECONDS`). Each
/// consecutive failure doubles the window up to this.
pub const WINDOW_CAP_NANOS: u64 = 60 * 60 * SECOND_NANOS;

/// The consecutive-failure count saturates here. The window is capped
/// long before, and a counter that wrapped would hand the short window
/// back to an address that has failed thousands of times.
const CONSECUTIVE_CAP: u32 = 32;

/// How long an address is suppressed after `consecutive` failures in a
/// row: [`FIRST_WINDOW_NANOS`], doubled for each failure after the first,
/// capped at [`WINDOW_CAP_NANOS`]. The same schedule on every operating
/// system.
#[must_use]
pub fn window_nanos(consecutive: u32) -> u64 {
    let mut window = FIRST_WINDOW_NANOS;
    let mut seen = 1;
    while seen < consecutive && window < WINDOW_CAP_NANOS {
        window = window.saturating_mul(2);
        seen += 1;
    }
    window.min(WINDOW_CAP_NANOS)
}

#[derive(Debug, Clone, Copy)]
struct Failure {
    when: Tick,
    consecutive: u32,
}

/// The addresses a recent dial failure suppresses.
#[derive(Debug, Default)]
pub struct FailedAddresses {
    failures: BTreeMap<NetworkAddress, Failure>,
}

impl FailedAddresses {
    /// An empty memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read one dial's report.
    ///
    /// `DialFailed` writes when its cause implicates the address on that
    /// address's connector. `PeerlistRefused` is the same close as a
    /// rejected handshake and is judged as one. `PayloadRefused` writes
    /// nothing and clears nothing: the peer answered. `Confirmed` and
    /// `SessionAccepted` clear the address, because a completed handshake
    /// proves it reachable.
    pub fn observe(&mut self, outcome: &DialOutcome, now: Tick) {
        match outcome {
            DialOutcome::DialFailed(address, cause)
            | DialOutcome::PeerlistRefused(address, cause) => self.failed(address, *cause, now),
            DialOutcome::PayloadRefused(_) => {}
            DialOutcome::Confirmed(address) | DialOutcome::SessionAccepted(address) => {
                self.failures.remove(address);
            }
        }
    }

    fn failed(&mut self, address: &NetworkAddress, cause: CloseCause, now: Tick) {
        let Some(connector) = Peerlist::connector_of(address) else {
            return;
        };
        if !cause.implicates_address(connector) {
            return;
        }
        let failure = self.failures.entry(address.clone()).or_insert(Failure {
            when: now,
            consecutive: 0,
        });
        failure.when = now;
        failure.consecutive = failure.consecutive.saturating_add(1).min(CONSECUTIVE_CAP);
    }

    /// Whether `address` failed recently enough that it is not a dial
    /// candidate at `now`. The window's last nanosecond still suppresses.
    #[must_use]
    pub fn is_recently_failed(&self, address: &NetworkAddress, now: Tick) -> bool {
        self.failures.get(address).is_some_and(|failure| {
            now.get().saturating_sub(failure.when.get()) <= window_nanos(failure.consecutive)
        })
    }

    /// How many addresses the memory holds, expired entries included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.failures.len()
    }

    /// Whether the memory holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}
