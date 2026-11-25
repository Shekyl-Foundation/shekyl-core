// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A multisig group as a send's destination (R-37).

use shekyl_address::MultisigAddressPayload;
use shekyl_engine_state::GroupFingerprint;
use shekyl_tx_weight::GroupSize;

/// A multisig group a send pays: its parsed address and the address's
/// fingerprint, the name the payer shows and records (R-37). Two group
/// destinations are the same group when their fingerprints are. `Debug`
/// names the fingerprint only: the address is four kilobytes and more,
/// and a payee's address does not reach logs (`WALLET_SEND_RECORD.md`
/// C1).
#[derive(Clone)]
pub struct GroupDestination {
    address: MultisigAddressPayload,
    fingerprint: GroupFingerprint,
}

impl GroupDestination {
    /// The group `address` names.
    #[must_use]
    pub fn new(address: MultisigAddressPayload) -> Self {
        let fingerprint = GroupFingerprint::of(&address);
        Self {
            address,
            fingerprint,
        }
    }

    /// The group's address.
    #[must_use]
    pub fn address(&self) -> &MultisigAddressPayload {
        &self.address
    }

    /// The group address's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> GroupFingerprint {
        self.fingerprint
    }

    /// The group's size, as the weight model prices its output's `0x0D`
    /// entry.
    #[must_use]
    pub fn size(&self) -> GroupSize {
        GroupSize::new(self.address.n_total(), self.address.m_required())
            .expect("a group address bounds its size as the weight model does")
    }
}

impl std::fmt::Debug for GroupDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupDestination")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl PartialEq for GroupDestination {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl Eq for GroupDestination {}

impl PartialOrd for GroupDestination {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GroupDestination {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.fingerprint.cmp(&other.fingerprint)
    }
}
