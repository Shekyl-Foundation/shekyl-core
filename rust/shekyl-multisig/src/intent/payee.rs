// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Who an intent pays (`SHEKYL_MULTISIG_WIRE_FORMAT.md` §2.3).
//!
//! A recipient's place in the intent is an index. The transaction key
//! permutes that index into an output position (R-24). Nothing here stores
//! or reads an output position.

use shekyl_address::multisig_address::{MultisigAddressError, MultisigAddressPayload};
use shekyl_address::{AddressError, Network, PaymentAddress};
use shekyl_crypto_pq::label::LABEL_PLAINTEXT_LEN;
use shekyl_units::AtomicUnits;

/// Who a recipient is, as the intent names it
/// (`SHEKYL_MULTISIG_WIRE_FORMAT.md` §2.3). [`crate::ValidatedIntent`]
/// resolves each against the group's network ([`Self::resolve`]).
///
/// The derived order is the wire's sort order: the kind first (the
/// variants are declared in their kind bytes' order), then the address
/// bytes, then a single-signer payee's label block.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntentPayee {
    /// A single-signer address, as its bech32m string, and the block its
    /// output's label encrypts: a payment request's echo, or the sentinel.
    Single {
        /// The address string.
        address: String,
        /// The output's label plaintext.
        label_plaintext: [u8; LABEL_PLAINTEXT_LEN],
    },
    /// A multisig group, as its address payload's canonical bytes. A
    /// spend's change is a payment to the paying group itself.
    Group {
        /// The payload's canonical bytes.
        address: Vec<u8>,
    },
}

impl IntentPayee {
    /// The kind byte of a single-signer payee.
    pub const KIND_SINGLE: u8 = 0x01;
    /// The kind byte of a group payee.
    pub const KIND_GROUP: u8 = 0x02;

    /// This payee's kind byte.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Single { .. } => Self::KIND_SINGLE,
            Self::Group { .. } => Self::KIND_GROUP,
        }
    }

    /// The address bytes the wire carries for this payee.
    #[must_use]
    pub fn address(&self) -> &[u8] {
        match self {
            Self::Single { address, .. } => address.as_bytes(),
            Self::Group { address } => address,
        }
    }

    /// This payee on `network`: the address decoded, or the group's
    /// payload parsed.
    ///
    /// A single-signer address must be the string its address encodes to
    /// (R-22), so one payee has one encoding and one intent hash. The
    /// address decoder refuses every other string too; this check is the
    /// intent's own and does not lean on it.
    ///
    /// # Errors
    ///
    /// The [`PayeeError`] that holds.
    pub fn resolve(&self, network: Network) -> Result<ResolvedPayee, PayeeError> {
        match self {
            Self::Single {
                address,
                label_plaintext,
            } => {
                let decoded =
                    PaymentAddress::decode(address, network).map_err(PayeeError::Address)?;
                written_as_encoded(&decoded, address)?;
                Ok(ResolvedPayee::Single {
                    address: decoded,
                    label_plaintext: *label_plaintext,
                })
            }
            Self::Group { address } => {
                let payload = MultisigAddressPayload::from_canonical_bytes(address)
                    .map_err(PayeeError::GroupAddress)?;
                if payload.network() != network {
                    return Err(PayeeError::GroupNetwork);
                }
                Ok(ResolvedPayee::Group(payload))
            }
        }
    }
}

/// R-22: `written` is the one string `decoded` encodes to.
fn written_as_encoded(decoded: &PaymentAddress, written: &str) -> Result<(), PayeeError> {
    if decoded.as_address().encode().map_err(PayeeError::Address)? == written {
        Ok(())
    } else {
        Err(PayeeError::NotCanonical)
    }
}

// The derived order compares variants in declaration order, which the
// wire's sort order (§2.3) requires to be the kind bytes' order.
const _: () = assert!(
    IntentPayee::KIND_SINGLE < IntentPayee::KIND_GROUP,
    "IntentPayee's variants are declared in their kind bytes' order"
);

/// Why a payee cannot be paid on the group's network.
#[derive(Debug, thiserror::Error)]
pub enum PayeeError {
    /// The address does not decode as a payable address on the network.
    #[error("the address does not decode: {0}")]
    Address(AddressError),
    /// The group's address payload does not parse.
    #[error("the group address does not parse: {0}")]
    GroupAddress(MultisigAddressError),
    /// The group is on another network.
    #[error("the group is on another network")]
    GroupNetwork,
    /// The address decodes, but is not the string it encodes to.
    #[error("the address is not written in its one canonical form")]
    NotCanonical,
}

/// A payee resolved on the group's network: what its output is built to.
#[derive(Clone, Debug)]
pub enum ResolvedPayee {
    /// A single-signer address, and its output's label plaintext.
    Single {
        /// The decoded address.
        address: PaymentAddress,
        /// The output's label plaintext.
        label_plaintext: [u8; LABEL_PLAINTEXT_LEN],
    },
    /// A multisig group.
    Group(MultisigAddressPayload),
}

/// A recipient of a validated intent: its payee resolved, and its amount.
/// Its place in the intent's recipient list is the index the transaction
/// key permutes (R-24). It is not the output's position.
#[derive(Clone, Debug)]
pub struct ResolvedRecipient {
    /// Who it pays.
    pub payee: ResolvedPayee,
    /// How much.
    pub amount: AtomicUnits,
}

/// A recipient in a [`super::SpendIntent`]. Its place among the intent's sorted
/// recipients is the index the transaction key permutes (R-24). The output
/// is written at the position that permutation assigns.
///
/// The derived order is the wire's sort order: the payee, then the amount.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IntentRecipient {
    pub payee: IntentPayee,
    pub amount: AtomicUnits,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{group_payload, single_address};
    use shekyl_crypto_pq::label::SENTINEL_PLAINTEXT;

    /// A group payee named by `bytes`, which structural checks do not parse.
    fn group_payee(bytes: &[u8]) -> IntentPayee {
        IntentPayee::Group {
            address: bytes.to_vec(),
        }
    }

    /// The derived order is the wire's: a single-signer payee before a
    /// group, as their kind bytes are (a const assertion pins the bytes'
    /// order); then the address bytes; then the label.
    #[test]
    fn payees_sort_by_kind_then_address_then_label() {
        let single = |address: &str, label: u8| IntentPayee::Single {
            address: address.into(),
            label_plaintext: [label; LABEL_PLAINTEXT_LEN],
        };
        assert!(single("zz", 9) < group_payee(&[0]));
        assert!(single("a", 9) < single("b", 0));
        assert!(single("a", 0) < single("a", 1));
        assert!(group_payee(&[1]) < group_payee(&[1, 0]));
    }

    /// R-22: another spelling of an address is not the same payee. The
    /// check compares strings itself, whatever the address decoder admits.
    #[test]
    fn a_payee_is_the_string_its_address_encodes_to() {
        let written = single_address(Network::Testnet);
        let decoded = PaymentAddress::decode(&written, Network::Testnet).unwrap();
        assert!(written_as_encoded(&decoded, &written).is_ok());
        assert!(matches!(
            written_as_encoded(&decoded, &written.to_uppercase()),
            Err(PayeeError::NotCanonical)
        ));
    }

    /// Each payee resolves on its own network, and is refused by name on
    /// another, or when its bytes do not parse.
    #[test]
    fn payees_resolve_on_the_groups_network_only() {
        let single = IntentPayee::Single {
            address: single_address(Network::Testnet),
            label_plaintext: SENTINEL_PLAINTEXT,
        };
        assert!(matches!(
            single.resolve(Network::Testnet),
            Ok(ResolvedPayee::Single { label_plaintext, .. })
                if label_plaintext == SENTINEL_PLAINTEXT
        ));
        assert!(matches!(
            single.resolve(Network::Mainnet),
            Err(PayeeError::Address(_))
        ));
        let group = group_payee(&group_payload(Network::Testnet, 0x50).to_canonical_bytes());
        assert!(matches!(
            group.resolve(Network::Testnet),
            Ok(ResolvedPayee::Group(_))
        ));
        assert!(matches!(
            group.resolve(Network::Mainnet),
            Err(PayeeError::GroupNetwork)
        ));
        assert!(matches!(
            group_payee(&[1, 2, 3]).resolve(Network::Testnet),
            Err(PayeeError::GroupAddress(_))
        ));
    }
}
