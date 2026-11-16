// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The contract's REJECTED method names and why each is refused (rule 23,
//! IG-10).
//!
//! `docs/api/wallet_rpc.yaml`'s `x-shekyl-method-registry` holds each
//! name's status, and its header holds the full rationale and the reopening
//! clause. This table is what a caller hears: a REJECTED name is answered
//! `-32601`, as any name the server does not serve, with the reason in the
//! message. The test below holds the table to the registry's REJECTED set.

/// Each REJECTED method name with the reason its refusal states.
pub const REJECTED_METHODS: &[(&str, &str)] = &[
    (
        "match_transfer_to_request",
        "attribution is automatic: get_transfers carries it \
         (wallet_rpc.yaml, REJECTED 2026-09-07)",
    ),
    (
        "claim",
        "emission claims run inside the wallet's staking; there is no manual claim \
         (wallet_rpc.yaml, REJECTED 2026-08-26)",
    ),
    (
        "claim_rewards",
        "emission claims run inside the wallet's staking; there is no manual claim \
         (wallet_rpc.yaml, REJECTED 2026-09-07)",
    ),
    (
        "get_stakes",
        "a per-stake listing would link stakes to their personas; get_staked_balance, \
         get_staked_outputs and staking_info are the aggregate reads \
         (wallet_rpc.yaml, REJECTED 2026-08-26)",
    ),
    (
        "get_tx_key",
        "the transaction key is a bearer credential; use get_tx_proof \
         (wallet_rpc.yaml, REJECTED 2026-07-23)",
    ),
    (
        "check_tx_key",
        "the transaction key is a bearer credential; use check_tx_proof \
         (wallet_rpc.yaml, REJECTED 2026-07-23)",
    ),
    (
        "get_spend_proof",
        "a spend proof only links key images to an identity, which FCMP++ hides; \
         use get_tx_proof (wallet_rpc.yaml, REJECTED 2026-07-24)",
    ),
    (
        "check_spend_proof",
        "a spend proof only links key images to an identity, which FCMP++ hides; \
         use check_tx_proof (wallet_rpc.yaml, REJECTED 2026-07-24)",
    ),
    (
        "export_unsigned",
        "cold signing is not offered: an FCMP++ spend needs the live curve tree; \
         cold storage is your seed (V3_WALLET_DECISION_LOG.md, 2026-09-07)",
    ),
    (
        "submit_signed",
        "cold signing is not offered: an FCMP++ spend needs the live curve tree; \
         cold storage is your seed (V3_WALLET_DECISION_LOG.md, 2026-09-07)",
    ),
    ("freeze", USER_FREEZE),
    ("thaw", USER_FREEZE),
    ("frozen", USER_FREEZE),
];

/// Why the user freeze is refused (Rick, 2026-11-15).
const USER_FREEZE: &str = "the wallet has no user-set hold on outputs: FCMP++ hides which \
     outputs a spend uses, and the wallet's own reservations keep built and staking-held \
     outputs out of selection (V3_WALLET_DECISION_LOG.md, 2026-11-15)";

/// The reason `method` is refused, if it is a REJECTED name.
#[must_use]
pub fn rejected_method(method: &str) -> Option<&'static str> {
    REJECTED_METHODS
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, reason)| *reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The table names exactly the registry's REJECTED methods. Bites when
    /// a name is rejected in the contract without a reason here, or a
    /// reason outlives its row.
    #[test]
    fn the_table_is_the_registrys_rejected_set() {
        let contract = include_str!("../../../docs/api/wallet_rpc.yaml");
        let start = contract
            .find("\nx-shekyl-method-registry:\n")
            .expect("the contract declares its method registry");
        let mut registry = BTreeSet::new();
        for line in contract[start + 1..].lines().skip(1) {
            if !line.starts_with("  ") {
                break;
            }
            if let Some(name) = line.trim().strip_suffix(": { status: REJECTED }") {
                registry.insert(name);
            }
        }
        assert!(
            registry.contains("freeze") && registry.len() > 10,
            "the parse found the registry: {registry:?}"
        );
        let table: BTreeSet<&str> = REJECTED_METHODS.iter().map(|(name, _)| *name).collect();
        assert_eq!(table, registry);
        assert_eq!(table.len(), REJECTED_METHODS.len(), "one row per name");
    }

    /// The user-freeze names state their reason and the decision.
    #[test]
    fn the_user_freeze_names_say_why() {
        for name in ["freeze", "thaw", "frozen"] {
            let reason = rejected_method(name).expect("rejected");
            assert!(reason.contains("no user-set hold"), "{reason}");
            assert!(reason.contains("2026-11-15"), "{reason}");
        }
        assert_eq!(rejected_method("get_balance"), None);
    }
}
