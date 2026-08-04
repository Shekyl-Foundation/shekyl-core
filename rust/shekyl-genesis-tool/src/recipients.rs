// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Genesis recipients file: schema, loading, and the allocation invariants.
//!
//! The on-disk schema is unchanged from the C++-tool era
//! (`{"network": …, "recipients": [{"label", "address", "amount_atomic"}]}`),
//! but validation is stricter: unknown keys are rejected (the old tool's
//! `amount_coins` escape hatch is gone), addresses must be in canonical
//! (post-#327, ek_bind-tagged) form for the expected network, and the
//! 5 × 20,000 SKL allocation is hard-enforced with no override flag — it is
//! consensus policy (`docs/GENESIS_TRANSPARENCY.md` §5), not a tooling knob.

use std::path::Path;

use shekyl_address::{Network, ShekylAddress, PQC_PAYLOAD_LEN};

use crate::{invalid, GenesisToolError};

/// Number of genesis recipients on every network.
pub const GENESIS_RECIPIENT_COUNT: usize = 5;

/// Per-recipient allocation: 20,000 SKL at 1 SKL = 10⁹ atomic.
pub const GENESIS_RECIPIENT_AMOUNT_ATOMIC: u64 = 20_000_000_000_000;

/// Total genesis emission: 100,000 SKL (block-0 reward; the recipient sum
/// must equal it exactly or the daemon rejects the genesis block).
pub const GENESIS_TOTAL_ATOMIC: u64 =
    GENESIS_RECIPIENT_AMOUNT_ATOMIC * GENESIS_RECIPIENT_COUNT as u64;

/// The recipients file, as committed at `config/genesis_recipients.<net>.json`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientsFile {
    /// Network name: `"mainnet"` | `"testnet"` | `"stagenet"`.
    pub network: String,
    /// The genesis recipients, in output-index order.
    pub recipients: Vec<RecipientEntry>,
}

/// One recipient entry in the file.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientEntry {
    /// Human-readable label (published; not consensus data).
    #[serde(default)]
    pub label: String,
    /// Full three-segment post-#327 address, canonical form.
    pub address: String,
    /// Allocation in atomic units (1 SKL = 10⁹ atomic).
    pub amount_atomic: u64,
}

/// A validated recipient: decoded address plus the canonical re-encoding
/// (the byte string the deterministic tx-key derivation commits to).
pub struct Recipient {
    /// Decoded address (spend/view keys + ML-KEM encap key).
    pub address: ShekylAddress,
    /// Canonical address string (round-tripped through encode).
    pub canonical: String,
    /// Allocation in atomic units.
    pub amount: u64,
    /// Label from the file.
    pub label: String,
}

/// Canonical lowercase network name used in filenames, the recipients file,
/// and the tx-key derivation preimage.
///
/// Thin alias of [`Network::as_str`] so call sites in this crate stay
/// readable without re-importing the address type's method name.
#[must_use]
pub fn network_str(net: Network) -> &'static str {
    net.as_str()
}

/// Parse and validate a recipients file body for `expected` network.
///
/// Enforces: network match, exactly [`GENESIS_RECIPIENT_COUNT`] recipients,
/// each [`GENESIS_RECIPIENT_AMOUNT_ATOMIC`], total [`GENESIS_TOTAL_ATOMIC`],
/// every address decodable **for that network**, PQC-payable, and already in
/// canonical form (so the committed file is exactly what the tx-key
/// derivation hashes).
pub fn parse_and_validate(
    json: &str,
    expected: Network,
) -> Result<Vec<Recipient>, GenesisToolError> {
    let file: RecipientsFile = serde_json::from_str(json)?;

    let want_net = network_str(expected);
    if file.network != want_net {
        return Err(invalid(format!(
            "recipients file is for network `{}`, expected `{want_net}`",
            file.network
        )));
    }

    if file.recipients.len() != GENESIS_RECIPIENT_COUNT {
        return Err(invalid(format!(
            "genesis requires exactly {GENESIS_RECIPIENT_COUNT} recipients, file has {}",
            file.recipients.len()
        )));
    }

    let mut out = Vec::with_capacity(file.recipients.len());
    let mut total: u64 = 0;
    for (i, entry) in file.recipients.into_iter().enumerate() {
        if entry.amount_atomic != GENESIS_RECIPIENT_AMOUNT_ATOMIC {
            return Err(invalid(format!(
                "recipient {i} amount_atomic {} != required {GENESIS_RECIPIENT_AMOUNT_ATOMIC} \
                 (5 × 20,000 SKL is consensus policy, not a tooling knob)",
                entry.amount_atomic
            )));
        }
        total = total
            .checked_add(entry.amount_atomic)
            .ok_or_else(|| invalid("recipient amount sum overflows u64"))?;

        let address = ShekylAddress::decode_for_network(&entry.address, expected)
            .map_err(|e| invalid(format!("recipient {i} address: {e:?}")))?;
        if address.ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(invalid(format!(
                "recipient {i} address has no full ML-KEM segment ({} bytes, need \
                 {PQC_PAYLOAD_LEN}) — a display-form address cannot be paid",
                address.ml_kem_encap_key.len()
            )));
        }
        let canonical = address
            .encode()
            .map_err(|e| invalid(format!("recipient {i} address re-encode: {e:?}")))?;
        if canonical != entry.address {
            return Err(invalid(format!(
                "recipient {i} address is not in canonical form; commit the canonical \
                 encoding instead:\n{canonical}"
            )));
        }

        out.push(Recipient {
            address,
            canonical,
            amount: entry.amount_atomic,
            label: entry.label,
        });
    }

    if total != GENESIS_TOTAL_ATOMIC {
        return Err(invalid(format!(
            "recipient sum {total} != genesis total {GENESIS_TOTAL_ATOMIC}"
        )));
    }

    Ok(out)
}

/// [`parse_and_validate`] over a file path.
pub fn load_and_validate(
    path: &Path,
    expected: Network,
) -> Result<Vec<Recipient>, GenesisToolError> {
    let body = std::fs::read_to_string(path).map_err(|e| {
        invalid(format!(
            "cannot read recipients file {}: {e}",
            path.display()
        ))
    })?;
    parse_and_validate(&body, expected)
}
