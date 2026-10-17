// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one preparation the Rust `main()` installs before the remnant runs.
//!
//! Two facts are read inside Rust while the remnant is still C++. The relay
//! zone's identity (which connectors are on, and whether the development
//! cover carrier runs) is what `shekyl_relay_zone_new` builds from. The
//! descriptor count reserved beyond the p2p's own inbound is what the seam
//! bind resolves the inbound ceiling from. Both are known before `run`, and
//! neither is a snapshot field: the snapshot only shrinks
//! (`DAEMON_CONFIG_CUTOVER.md` §2.9).
//!
//! The C++ harness writes the relay half alone, between notifiers, with no
//! daemon. That write overwrites. A second install that disagrees is refused.

use std::sync::{Mutex, PoisonError};

/// Which connectors the relay is, and whether the development cover runs.
///
/// `connectors` is one bit per connector index, the same mask
/// `connectors_from_mask` reads. The mask stays here so this module does not
/// take a dialer type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayIdentity {
    /// One bit per connector index.
    pub connectors: u32,
    /// The development cover carrier (`dev-relay-cover`).
    pub cover: bool,
}

/// The relay identity and the reserved descriptor count, installed together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemnantPrep {
    /// The relay the remnant opens.
    pub relay: RelayIdentity,
    /// Descriptors promised beyond the p2p's own inbound.
    pub reserved_descriptors: u64,
}

/// A second install named different facts. The first installation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrepDisagreement;

impl std::fmt::Display for PrepDisagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the remnant's preparation was already installed with different facts")
    }
}

impl std::error::Error for PrepDisagreement {}

struct Slot {
    relay: Option<RelayIdentity>,
    reserved: Option<u64>,
}

static PREP: Mutex<Slot> = Mutex::new(Slot {
    relay: None,
    reserved: None,
});

fn slot() -> std::sync::MutexGuard<'static, Slot> {
    PREP.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Installs both halves. The same facts again are the same installation.
/// A harness that already stated a different relay, or a reservation that
/// differs, is refused and the slot is left as it was.
///
/// # Errors
/// [`PrepDisagreement`] when a half already installed disagrees.
pub fn install(prep: RemnantPrep) -> Result<(), PrepDisagreement> {
    let mut slot = slot();
    if slot.relay.is_some_and(|installed| installed != prep.relay)
        || slot
            .reserved
            .is_some_and(|installed| installed != prep.reserved_descriptors)
    {
        return Err(PrepDisagreement);
    }
    slot.relay = Some(prep.relay);
    slot.reserved = Some(prep.reserved_descriptors);
    Ok(())
}

/// The harness writer: the relay half, overwritten, the reservation left
/// as it stands. `shekyl_relay_posture_record` is this and nothing else.
pub fn state_relay(identity: RelayIdentity) {
    slot().relay = Some(identity);
}

/// The relay identity, when one has been installed or stated.
#[must_use]
pub fn relay() -> Option<RelayIdentity> {
    slot().relay
}

/// The reserved descriptor count. Unset reads as 0, which is what a harness
/// that binds with no daemon reserves.
#[must_use]
pub fn reserved_descriptors() -> u64 {
    slot().reserved.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(connectors: u32, cover: bool) -> RelayIdentity {
        RelayIdentity { connectors, cover }
    }

    /// Puts the slot back. The preparation is process-wide, and a test must
    /// not leave its facts for the next one.
    struct Restore {
        relay: Option<RelayIdentity>,
        reserved: Option<u64>,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            let mut slot = slot();
            slot.relay = self.relay;
            slot.reserved = self.reserved;
        }
    }

    #[test]
    fn a_second_install_of_the_same_facts_stands_and_a_different_one_is_refused() {
        let saved = slot();
        let _restore = Restore {
            relay: saved.relay,
            reserved: saved.reserved,
        };
        drop(saved);
        // State a relay the way the harness does, then install the same
        // identity: the reservation is filled in.
        let relay = identity(0b01, false);
        state_relay(relay);
        let prep = RemnantPrep {
            relay,
            reserved_descriptors: 40,
        };
        install(prep).expect("the same relay");
        assert_eq!(reserved_descriptors(), 40);
        install(prep).expect("the same facts again");
        let other = RemnantPrep {
            relay: identity(0b10, true),
            reserved_descriptors: 40,
        };
        assert_eq!(install(other), Err(PrepDisagreement));
        assert_eq!(super::relay(), Some(relay), "the first installation stands");
        assert_eq!(reserved_descriptors(), 40);
    }
}
