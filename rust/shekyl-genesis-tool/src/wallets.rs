// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fresh-entropy genesis wallet ceremony (`geblock gen-wallets`).
//!
//! Seed formats are network-enforced by
//! `shekyl_crypto_pq::account::DerivationNetwork::permitted_seed_format`:
//! mainnet/stagenet wallets are BIP-39-only (24 words, empty passphrase),
//! testnet wallets are raw-32-only. This mirrors the (private)
//! `shekyl-wallet-rpc` `generate_seed_material` shape — fresh `OsRng`
//! entropy, zeroized after use in both arms.
//!
//! Seeds are shown exactly once, in the custody files written here — there
//! is no re-export path anywhere in the stack. Custody files are 0600,
//! never overwritten, and refused inside any git worktree so secret
//! material cannot end up committed by accident.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use shekyl_address::{Network, ShekylAddress};
use shekyl_crypto_pq::account::{
    generate_account_from_bip39, generate_account_from_raw_seed, DerivationNetwork, RAW_SEED_BYTES,
};
use shekyl_crypto_pq::bip39::{mnemonic_from_entropy, SHEKYL_BIP39_ENTROPY_BYTES};
use zeroize::{Zeroize, Zeroizing};

use crate::recipients::{
    network_str, RecipientEntry, RecipientsFile, GENESIS_RECIPIENT_AMOUNT_ATOMIC,
};
use crate::{invalid, GenesisToolError};

/// Seed backup material, captured at generation (the only time it exists).
pub enum SeedBackup {
    /// BIP-39 mnemonic, 24 words, empty passphrase (mainnet/stagenet).
    Mnemonic(Zeroizing<String>),
    /// Raw 32-byte seed, lowercase hex (testnet derivation).
    RawHex(Zeroizing<String>),
}

/// One freshly generated genesis wallet.
pub struct GeneratedWallet {
    /// 1-based wallet index within this ceremony run.
    pub index: u32,
    /// Full canonical address string.
    pub address: String,
    /// The seed backup (goes only into the custody file).
    pub backup: SeedBackup,
}

fn derivation_for(net: Network) -> DerivationNetwork {
    match net {
        Network::Mainnet => DerivationNetwork::Mainnet,
        Network::Testnet => DerivationNetwork::Testnet,
        Network::Stagenet => DerivationNetwork::Stagenet,
    }
}

/// Generate `count` fresh wallets for `net` and return their addresses plus
/// seed backups. Every address is round-tripped through
/// [`ShekylAddress::decode_for_network`] before being returned.
pub fn generate_wallets(
    net: Network,
    count: u32,
) -> Result<Vec<GeneratedWallet>, GenesisToolError> {
    if count == 0 {
        return Err(invalid("gen-wallets: count must be at least 1"));
    }
    let derivation = derivation_for(net);
    let mut out = Vec::with_capacity(count as usize);
    for index in 1..=count {
        let (blob, backup) = match net {
            Network::Mainnet | Network::Stagenet => {
                let mut entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
                OsRng.fill_bytes(&mut entropy);
                let mnemonic = Zeroizing::new(
                    mnemonic_from_entropy(&entropy)
                        .map_err(|e| invalid(format!("mnemonic_from_entropy: {e:?}")))?,
                );
                entropy.zeroize();
                let (_master, blob) = generate_account_from_bip39(&mnemonic, "", derivation)
                    .map_err(|e| invalid(format!("bip39 account: {e:?}")))?;
                (blob, SeedBackup::Mnemonic(mnemonic))
            }
            Network::Testnet => {
                let mut raw = [0u8; RAW_SEED_BYTES];
                OsRng.fill_bytes(&mut raw);
                let seed_hex = Zeroizing::new(hex::encode(raw));
                let (_master, blob) = generate_account_from_raw_seed(&raw, derivation)
                    .map_err(|e| invalid(format!("raw-seed account: {e:?}")))?;
                raw.zeroize();
                (blob, SeedBackup::RawHex(seed_hex))
            }
        };

        let address = ShekylAddress::new(
            net,
            *blob.spend_pk.as_canonical_bytes(),
            *blob.view_pk.as_canonical_bytes(),
            blob.ml_kem_ek.to_vec(),
        )
        .encode()
        .map_err(|e| invalid(format!("wallet {index} address encode: {e:?}")))?;

        // Round-trip before anything is written: a wrong-network or truncated
        // address must fail here, not at chain launch.
        ShekylAddress::decode_for_network(&address, net)
            .map_err(|e| invalid(format!("wallet {index} address round-trip: {e:?}")))?;

        out.push(GeneratedWallet {
            index,
            address,
            backup,
        });
        // `blob` (AllKeysBlob) is ZeroizeOnDrop; secrets are wiped here.
    }
    Ok(out)
}

/// Refuse any output directory that sits inside a git checkout or worktree —
/// custody files hold seed material and must never be committable.
fn refuse_git_worktree(dir: &Path) -> Result<(), GenesisToolError> {
    let canonical = dir
        .canonicalize()
        .map_err(|e| invalid(format!("cannot canonicalize {}: {e}", dir.display())))?;
    for ancestor in canonical.ancestors() {
        // `.git` is a directory in a primary checkout and a file in a linked
        // worktree; either form marks the tree as committable territory.
        if ancestor.join(".git").exists() {
            return Err(invalid(format!(
                "refusing to write custody files inside a git tree ({} has a .git); \
                 choose an out-dir on user-secured storage outside any repository",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

/// Write per-wallet custody files (0600, never overwritten) plus a
/// ready-to-commit recipients-JSON skeleton (addresses only — no secrets).
/// Returns the skeleton path.
pub fn write_custody_files(
    dir: &Path,
    net: Network,
    wallets: &[GeneratedWallet],
) -> Result<PathBuf, GenesisToolError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| invalid(format!("cannot create {}: {e}", dir.display())))?;
    }
    refuse_git_worktree(dir)?;

    let net_name = network_str(net);
    let role = match net {
        Network::Mainnet | Network::Stagenet => "Founder allocation",
        Network::Testnet => "Developer",
    };

    for w in wallets {
        let path = dir.join(format!("genesis-wallet-{net_name}-{:02}.txt", w.index));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                invalid(format!(
                    "cannot create custody file {} (refusing to overwrite): {e}",
                    path.display()
                ))
            })?;

        let (seed_kind, seed_value): (&str, &str) = match &w.backup {
            SeedBackup::Mnemonic(m) => ("BIP-39 mnemonic (24 words, empty passphrase)", m),
            SeedBackup::RawHex(h) => ("raw 32-byte seed, hex (testnet derivation)", h),
        };
        let body = Zeroizing::new(format!(
            "Shekyl genesis wallet — {net_name} {role} #{index}\n\
             \n\
             This file is the ONLY copy of this wallet's seed. It was shown once at\n\
             generation and cannot be re-exported by any tool in the stack. Store it\n\
             offline (paper / HSM). Anyone holding the seed controls the funds.\n\
             \n\
             address: {address}\n\
             \n\
             seed ({seed_kind}):\n{seed_value}\n",
            index = w.index,
            address = w.address,
        ));
        file.write_all(body.as_bytes())
            .map_err(|e| invalid(format!("write {}: {e}", path.display())))?;
    }

    let skeleton = RecipientsFile {
        network: net_name.to_owned(),
        recipients: wallets
            .iter()
            .map(|w| RecipientEntry {
                label: format!("{role} {}", w.index),
                address: w.address.clone(),
                amount_atomic: GENESIS_RECIPIENT_AMOUNT_ATOMIC,
            })
            .collect(),
    };
    let skeleton_path = dir.join(format!("genesis_recipients.{net_name}.json"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&skeleton_path)
        .map_err(|e| {
            invalid(format!(
                "cannot create recipients skeleton {} (refusing to overwrite): {e}",
                skeleton_path.display()
            ))
        })?;
    let mut body = serde_json::to_string_pretty(&skeleton)?;
    body.push('\n');
    file.write_all(body.as_bytes())
        .map_err(|e| invalid(format!("write {}: {e}", skeleton_path.display())))?;

    Ok(skeleton_path)
}
