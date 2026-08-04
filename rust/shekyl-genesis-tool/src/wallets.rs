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
//!
//! The ceremony always emits exactly [`GENESIS_RECIPIENT_COUNT`] wallets —
//! the consensus allocation shape, not a tooling knob. Writes stage under a
//! temporary subdirectory and only promote to the final names after every
//! file is complete, so a mid-run failure never leaves a partial seed set at
//! the operator's `out_dir` paths.

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
    RecipientEntry, RecipientsFile, GENESIS_RECIPIENT_AMOUNT_ATOMIC, GENESIS_RECIPIENT_COUNT,
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

/// Generate exactly [`GENESIS_RECIPIENT_COUNT`] fresh wallets for `net` and
/// return their addresses plus seed backups. Every address is round-tripped
/// through [`ShekylAddress::decode_for_network`] before being returned.
pub fn generate_wallets(net: Network) -> Result<Vec<GeneratedWallet>, GenesisToolError> {
    let count = u32::try_from(GENESIS_RECIPIENT_COUNT).expect("GENESIS_RECIPIENT_COUNT fits u32");
    let derivation = derivation_for(net);
    let mut out = Vec::with_capacity(GENESIS_RECIPIENT_COUNT);
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

/// Absolute path for `dir` without requiring the leaf to exist.
fn absolute_path(dir: &Path) -> Result<PathBuf, GenesisToolError> {
    if dir.is_absolute() {
        Ok(dir.to_path_buf())
    } else {
        let cwd = std::env::current_dir()
            .map_err(|e| invalid(format!("cannot resolve current directory: {e}")))?;
        Ok(cwd.join(dir))
    }
}

/// Refuse any output directory that sits inside a git checkout or worktree —
/// custody files hold seed material and must never be committable.
///
/// Does **not** require `dir` to exist: the nearest existing ancestor is
/// canonicalized and walked, so a missing path inside a repo is refused
/// before anything is created on disk.
fn refuse_git_worktree(dir: &Path) -> Result<(), GenesisToolError> {
    let abs = absolute_path(dir)?;

    // Walk up until we hit an existing path (or the root).
    let mut probe = abs.as_path();
    while !probe.exists() {
        probe = probe.parent().ok_or_else(|| {
            invalid(format!(
                "cannot resolve parent of non-existent path {}",
                abs.display()
            ))
        })?;
    }
    let canonical = probe
        .canonicalize()
        .map_err(|e| invalid(format!("cannot canonicalize {}: {e}", probe.display())))?;

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

/// Final custody filename for wallet `index` on `net`.
fn custody_filename(net: Network, index: u32) -> String {
    format!("genesis-wallet-{}-{:02}.txt", net.as_str(), index)
}

/// Final recipients-skeleton filename for `net`.
fn skeleton_filename(net: Network) -> String {
    format!("genesis_recipients.{}.json", net.as_str())
}

/// Remove a staging directory; ignore errors (best-effort wipe of partial secrets).
fn wipe_staging(staging: &Path) {
    if let Err(e) = std::fs::remove_dir_all(staging) {
        // Staging holds the only in-progress copies of seeds; a wipe failure
        // after a successful promote is noisy but non-fatal. After a failed
        // stage the operator's final paths are untouched.
        eprintln!(
            "geblock: warning: could not remove staging dir {}: {e}",
            staging.display()
        );
    }
}

/// Write per-wallet custody files (0600, never overwritten) plus a
/// ready-to-commit recipients-JSON skeleton (addresses only — no secrets).
/// Returns the skeleton path.
///
/// Ordering:
/// 1. refuse any git worktree (before creating anything);
/// 2. preflight that no final path already exists;
/// 3. stage every file under a temporary subdirectory;
/// 4. promote staged files to their final names only after the full set is
///    written — a mid-run failure leaves the operator's final paths untouched
///    and wipes the staging directory (including any partial seeds).
pub fn write_custody_files(
    dir: &Path,
    net: Network,
    wallets: &[GeneratedWallet],
) -> Result<PathBuf, GenesisToolError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if wallets.len() != GENESIS_RECIPIENT_COUNT {
        return Err(invalid(format!(
            "gen-wallets: expected exactly {GENESIS_RECIPIENT_COUNT} wallets, got {}",
            wallets.len()
        )));
    }

    // (1) Refuse before any mkdir — a missing path inside a repo must not
    // leave an empty directory behind.
    refuse_git_worktree(dir)?;

    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| invalid(format!("cannot create {}: {e}", dir.display())))?;
    }

    // Re-check after create (covers the race where dir was created between
    // refuse and mkdir on a path that somehow escaped, and catches an
    // out_dir that is itself a freshly-initialized git repo).
    refuse_git_worktree(dir)?;

    let net_name = net.as_str();
    let role = match net {
        Network::Mainnet | Network::Stagenet => "Founder allocation",
        Network::Testnet => "Developer",
    };

    // (2) Preflight final destinations — refuse before drawing any staged secrets.
    let final_paths: Vec<PathBuf> = wallets
        .iter()
        .map(|w| dir.join(custody_filename(net, w.index)))
        .collect();
    let skeleton_path = dir.join(skeleton_filename(net));
    for path in final_paths.iter().chain(std::iter::once(&skeleton_path)) {
        if path.exists() {
            return Err(invalid(format!(
                "refusing to overwrite existing path {}",
                path.display()
            )));
        }
    }

    // (3) Stage under a unique subdirectory of out_dir.
    let staging = dir.join(format!(
        ".geblock-staging-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&staging) {
        return Err(invalid(format!(
            "cannot create staging dir {}: {e}",
            staging.display()
        )));
    }

    let stage_result = (|| -> Result<(), GenesisToolError> {
        for w in wallets {
            let path = staging.join(custody_filename(net, w.index));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| {
                    invalid(format!(
                        "cannot create staging custody file {}: {e}",
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
        let staged_skel = staging.join(skeleton_filename(net));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_skel)
            .map_err(|e| {
                invalid(format!(
                    "cannot create staging skeleton {}: {e}",
                    staged_skel.display()
                ))
            })?;
        let mut body = serde_json::to_string_pretty(&skeleton)?;
        body.push('\n');
        file.write_all(body.as_bytes())
            .map_err(|e| invalid(format!("write {}: {e}", staged_skel.display())))?;

        // (4) Promote: rename each staged file into its final name. Same-fs
        // rename is atomic per file; we preflighted that finals do not exist.
        for w in wallets {
            let from = staging.join(custody_filename(net, w.index));
            let to = dir.join(custody_filename(net, w.index));
            std::fs::rename(&from, &to).map_err(|e| {
                invalid(format!(
                    "promote custody file {} → {}: {e}",
                    from.display(),
                    to.display()
                ))
            })?;
        }
        std::fs::rename(&staged_skel, &skeleton_path).map_err(|e| {
            invalid(format!(
                "promote skeleton {} → {}: {e}",
                staged_skel.display(),
                skeleton_path.display()
            ))
        })?;
        Ok(())
    })();

    match stage_result {
        Ok(()) => {
            wipe_staging(&staging);
            Ok(skeleton_path)
        }
        Err(e) => {
            wipe_staging(&staging);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuse_git_detects_repo_without_creating_leaf() {
        // This crate lives inside the shekyl-core git tree. A non-existent
        // path under CARGO_MANIFEST_DIR must be refused *and* must not be
        // created.
        let ghost = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("geblock-refuse-git-ghost-should-not-exist");
        assert!(!ghost.exists(), "precondition: ghost path absent");
        let err = refuse_git_worktree(&ghost).expect_err("must refuse inside git tree");
        assert!(
            err.to_string().contains("git tree"),
            "unexpected error: {err}"
        );
        assert!(
            !ghost.exists(),
            "refuse_git_worktree must not create the leaf path"
        );
    }

    #[test]
    fn write_custody_rejects_wrong_wallet_count() {
        // Empty slice — no entropy, pure contract check.
        let dir = std::env::temp_dir().join(format!(
            "geblock-count-check-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        // temp_dir is typically outside the repo; if it is not, refuse will
        // fire first — either error is fine for this contract test.
        let err = write_custody_files(&dir, Network::Testnet, &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected exactly") || msg.contains("git tree"),
            "unexpected error: {msg}"
        );
        // Count check runs before mkdir: the path must not have been created.
        assert!(!dir.exists(), "count mismatch must not create out_dir");
    }
}
