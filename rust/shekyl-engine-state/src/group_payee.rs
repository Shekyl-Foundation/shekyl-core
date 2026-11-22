// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A multisig group as the wallet that pays it keeps it (R-37).
//!
//! A group's address is a file of four kilobytes and more (rule 65), so the
//! paying wallet stores each group's address once, the first time it pays
//! that group, and its send journal names the group by the address's
//! fingerprint. A group payee is then as complete as a solo one: the wallet
//! shows who was paid, and holds what an outbound proof for the payment
//! needs.
//!
//! [`GroupFingerprint`] is made only from a parsed group address. A
//! fingerprint read from a wallet file is held to the same rule by the
//! ledger's load check (`group-payees-stored`): every group the journal
//! names has its address stored, and every stored address parses and
//! hashes to the fingerprint it is kept under.

use serde::{Deserialize, Serialize};
use shekyl_address::{
    address_fingerprint, MultisigAddressError, MultisigAddressPayload, FINGERPRINT_LEN,
};

/// A group address's fingerprint (`shekyl_address::address_fingerprint`),
/// the name the payer's send journal gives the group.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    postcard_schema::Schema,
)]
pub struct GroupFingerprint([u8; FINGERPRINT_LEN]);

impl GroupFingerprint {
    /// The fingerprint of `address`.
    #[must_use]
    pub fn of(address: &MultisigAddressPayload) -> Self {
        Self(address_fingerprint(address))
    }

    /// The fingerprint's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }
}

/// A group's address as the paying wallet stores it: the address's
/// canonical bytes, made only from a parsed address. Its `Debug` names the
/// length only: a payee's address does not reach logs or error strings
/// (`WALLET_SEND_RECORD.md` C1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub struct StoredGroupAddress(Vec<u8>);

impl std::fmt::Debug for StoredGroupAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoredGroupAddress({} bytes)", self.0.len())
    }
}

impl StoredGroupAddress {
    /// Store `address`.
    #[must_use]
    pub fn new(address: &MultisigAddressPayload) -> Self {
        Self(address.to_canonical_bytes())
    }

    /// The stored address, parsed.
    ///
    /// # Errors
    ///
    /// The address's own refusal, for bytes that are not a group address.
    /// A stored address made by [`Self::new`] always parses; one read from
    /// a wallet file is checked when the ledger loads.
    pub fn address(&self) -> Result<MultisigAddressPayload, MultisigAddressError> {
        MultisigAddressPayload::from_canonical_bytes(&self.0)
    }

    /// Any bytes, as a file could hold them: the load check's tests.
    #[cfg(test)]
    pub(crate) fn from_file_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use shekyl_address::Network;

    pub(crate) fn group(seed: u8) -> MultisigAddressPayload {
        let kem = |i: u8| vec![seed ^ i; 1216];
        MultisigAddressPayload::new(
            Network::Testnet,
            3,
            2,
            [seed; 32],
            [seed.wrapping_add(1); 32],
            kem(0xF0),
            (0..3).map(kem).collect(),
        )
        .expect("a valid 2-of-3 address")
    }

    #[test]
    fn a_stored_address_parses_back_to_its_fingerprint() {
        let address = group(0x21);
        let stored = StoredGroupAddress::new(&address);
        let back = stored.address().expect("parses");
        assert_eq!(back, address);
        assert_eq!(GroupFingerprint::of(&back), GroupFingerprint::of(&address));
    }

    #[test]
    fn two_groups_have_two_fingerprints() {
        assert_ne!(
            GroupFingerprint::of(&group(0x21)),
            GroupFingerprint::of(&group(0x22))
        );
    }
}
