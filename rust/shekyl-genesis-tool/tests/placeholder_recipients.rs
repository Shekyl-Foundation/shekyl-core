// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic **placeholder** recipients for the committed
//! `config/genesis_recipients.*.json` files, Phase A only.
//!
//! ⚠ These keys are derived from public labels via `SHA256(label)` — anyone
//! can recompute the secrets. That is the point: they are schema
//! placeholders so the recipients files, the config-pin gate plumbing, and
//! the regtest KAT capture path all work before the real fresh-entropy
//! ceremony (`geblock gen-wallets`) replaces them at the Phase B regen.
//! Never reuse this derivation for a real allocation.
//!
//! Run to (re)print the three file bodies:
//! `cargo test -p shekyl-genesis-tool --test placeholder_recipients -- --ignored --nocapture`

use sha2::{Digest, Sha256};
use shekyl_address::{Network, ShekylAddress};
use shekyl_crypto_pq::account::{
    generate_account_from_bip39, generate_account_from_raw_seed, DerivationNetwork,
};
use shekyl_genesis_tool::recipients::{
    network_str, RecipientEntry, RecipientsFile, GENESIS_RECIPIENT_AMOUNT_ATOMIC,
    GENESIS_RECIPIENT_COUNT,
};

fn domain_entropy(label: &str) -> [u8; 32] {
    let digest = Sha256::digest(label.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn placeholder_address(net: Network, label: &str) -> String {
    let entropy = domain_entropy(label);
    let blob = match net {
        // Mainnet/stagenet are BIP-39-only (permitted_seed_format).
        Network::Mainnet | Network::Stagenet => {
            let mnemonic = shekyl_crypto_pq::bip39::mnemonic_from_entropy(&entropy)
                .expect("mnemonic_from_entropy");
            let derivation = match net {
                Network::Mainnet => DerivationNetwork::Mainnet,
                _ => DerivationNetwork::Stagenet,
            };
            generate_account_from_bip39(&mnemonic, "", derivation)
                .expect("bip39 account")
                .1
        }
        // Testnet is raw-32-only.
        Network::Testnet => {
            generate_account_from_raw_seed(&entropy, DerivationNetwork::Testnet)
                .expect("raw account")
                .1
        }
    };
    ShekylAddress::new(
        net,
        *blob.spend_pk.as_canonical_bytes(),
        *blob.view_pk.as_canonical_bytes(),
        blob.ml_kem_ek.to_vec(),
    )
    .encode()
    .expect("encode")
}

/// The derivation label for placeholder wallet `i` (1-based) on `net`.
///
/// Testnet keeps the pre-#327 developer labels, so the underlying keys are
/// unchanged from the previous placeholder era — only the address encoding
/// (ek_bind tag) is new. Mainnet/stagenet labels are new: the old single
/// combined-treasury placeholder is retired by the 5 × 20,000 SKL shape.
fn placeholder_label(net: Network, i: usize) -> String {
    match net {
        Network::Testnet => format!("shekyl-v3-genesis-testnet-developer-{i}-v1"),
        _ => format!(
            "shekyl-v3-genesis-{}-founder-{i}-placeholder-v1",
            network_str(net)
        ),
    }
}

fn placeholder_file(net: Network) -> String {
    let recipients = (1..=GENESIS_RECIPIENT_COUNT)
        .map(|i| {
            let label = placeholder_label(net, i);
            RecipientEntry {
                label: format!(
                    "PLACEHOLDER — replaced at the Phase B regen (derivation label: {label})"
                ),
                address: placeholder_address(net, &label),
                amount_atomic: GENESIS_RECIPIENT_AMOUNT_ATOMIC,
            }
        })
        .collect();
    let file = RecipientsFile {
        network: network_str(net).to_owned(),
        recipients,
    };
    let mut body = serde_json::to_string_pretty(&file).expect("serialize");
    body.push('\n');
    body
}

/// Printer for the committed placeholder files; `--ignored` because it is a
/// generator, not a check.
#[test]
#[ignore = "generator: prints the config/genesis_recipients.*.json placeholder bodies"]
fn print_placeholder_recipient_files() {
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        println!("=== genesis_recipients.{}.json ===", network_str(net));
        println!("{}", placeholder_file(net));
    }
}

/// The committed Phase A files must be exactly this generator's output —
/// guards against hand-edits drifting from the recorded derivation.
#[test]
fn committed_placeholders_match_generator() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let path = root
            .join("config")
            .join(format!("genesis_recipients.{}.json", network_str(net)));
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(
            committed,
            placeholder_file(net),
            "{} drifted from the placeholder generator; regenerate via the \
             print_placeholder_recipient_files test (or, at Phase B, delete this \
             equality test along with the placeholder era)",
            path.display()
        );
    }
}
