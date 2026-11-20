// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Enrollment over the channel (`INPUT_GRAMMAR.md` IG-Q87;
//! `RPC_CHANNEL.md` §5): a client's fingerprint and its ceiling, and this
//! daemon's public bundle.
//!
//! A request names a ceiling as grant and preset keywords ([`CeilingWord`]);
//! the daemon stores and lists it as its expanded grants ([`GrantName`]),
//! never as a preset's name, so a later change to a preset widens no
//! enrollment made under it.

use shekyl_rpc_grants::{Grant, GrantSet, Preset};

use super::daemon::GrantName;
use crate::hash::HashHex;
use crate::kinds::Bytes;

crate::wire_keywords! {
    /// A grant or a preset, as a ceiling names them (`RPC_CHANNEL.md` §6.1).
    pub enum CeilingWord {
        Health = "health",
        Status = "status",
        Chain = "chain",
        Pool = "pool",
        Peers = "peers",
        Submit = "submit",
        MiningWork = "mining-work",
        MiningControl = "mining-control",
        Bans = "bans",
        Node = "node",
        Config = "config",
        Enroll = "enroll",
        View = "view",
        Wallet = "wallet",
        Miner = "miner",
        Admin = "admin",
    }
}

impl CeilingWord {
    /// The ceiling word an operator's name names. The one resolver: a
    /// command line and a configuration file both ask here, and a name that
    /// is not a grant or a preset is [`None`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|word| word.as_str() == name)
    }

    /// The grants this word stands for. A preset's name is that preset; any
    /// other word is the grant of the same name ([`Grant::name`]).
    #[must_use]
    pub fn grants(self) -> GrantSet {
        if let Some(preset) = Preset::from_name(self.as_str()) {
            return preset.grants();
        }
        let grant = Grant::from_name(self.as_str()).expect("a ceiling word is a grant or a preset");
        GrantSet::of(&[grant])
    }

    /// The grants a list of words stands for, expanded.
    #[must_use]
    pub fn expand(words: &[Self]) -> GrantSet {
        words
            .iter()
            .fold(GrantSet::EMPTY, |set, word| set.union(word.grants()))
    }
}

/// A grant set as a reply lists it: its grants, in the table's order.
#[must_use]
pub fn grant_names(set: GrantSet) -> Vec<GrantName> {
    set.iter().map(GrantName::from).collect()
}

crate::wire_object! {
    /// `rpc_client_add`'s and `rpc_client_set`'s argument: a client and the
    /// ceiling it is enrolled under.
    ["rpc client"]
    pub struct ClientCeiling {
        /// The client's static-key fingerprint (RT-O14).
        pub fingerprint: HashHex,
        /// Grants and presets; stored expanded.
        pub ceiling: Vec<CeilingWord>,
    }
}

crate::wire_object! {
    /// `rpc_client_remove`'s argument.
    ["rpc client"]
    pub struct ClientFingerprint {
        /// The client's static-key fingerprint.
        pub fingerprint: HashHex,
    }
}

crate::wire_object! {
    /// One enrollment, as `rpc_client_list` shows it.
    ["rpc client"]
    pub struct Client {
        /// The client's static-key fingerprint.
        pub fingerprint: HashHex,
        /// Its ceiling's grants, expanded.
        pub ceiling: Vec<GrantName>,
    }
}

crate::wire_object! {
    /// `rpc_bundle_show`'s reply: this daemon's static public keys, the
    /// X25519 key then the ML-KEM-768 encapsulation key, the order the
    /// handshake sends them in. Give it only to a device that will be
    /// enrolled (§5).
    ["rpc"]
    pub struct Bundle {
        /// The public bundle.
        pub bundle: Bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preset expands to its grants and a grant to itself; a list is
    /// their union. Red edit: map `Wallet` to `View`, and the wallet
    /// assertion fails.
    #[test]
    fn a_ceiling_expands_to_its_grants() {
        assert_eq!(CeilingWord::expand(&[CeilingWord::Admin]), GrantSet::ALL);
        assert_eq!(
            CeilingWord::expand(&[CeilingWord::Wallet]),
            Preset::Wallet.grants()
        );
        assert_eq!(
            CeilingWord::expand(&[CeilingWord::View, CeilingWord::MiningWork]),
            Preset::Miner.grants()
        );
        assert_eq!(CeilingWord::expand(&[]), GrantSet::EMPTY);
        // Every grant and every preset is a ceiling word, and every ceiling
        // word is one of those. Red edit: drop a grant from `CeilingWord`,
        // and its name fails here.
        for grant in Grant::ALL {
            assert!(
                Preset::from_name(grant.name()).is_none(),
                "{} is a grant and a preset",
                grant.name()
            );
            let word = CeilingWord::from_name(grant.name())
                .unwrap_or_else(|| panic!("{} has no ceiling word", grant.name()));
            assert_eq!(word.grants(), GrantSet::of(&[grant]));
        }
        for preset in Preset::ALL {
            let word = CeilingWord::from_name(preset.name())
                .unwrap_or_else(|| panic!("{} has no ceiling word", preset.name()));
            assert_eq!(word.grants(), preset.grants());
        }
        assert_eq!(CeilingWord::from_name("view"), Some(CeilingWord::View));
        assert_eq!(CeilingWord::from_name("not-a-grant"), None);
        for word in CeilingWord::ALL {
            assert!(
                Grant::from_name(word.as_str()).is_some()
                    || Preset::from_name(word.as_str()).is_some(),
                "{}",
                word.as_str()
            );
        }
        // Listed in the grant table's order, never as the preset's name.
        assert_eq!(
            grant_names(Preset::View.grants()),
            [GrantName::Chain, GrantName::Pool, GrantName::Health]
        );
    }
}
