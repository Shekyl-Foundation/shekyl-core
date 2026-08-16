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
//! the consensus allocation shape, not a tooling knob. The full set is
//! written to a sibling staging directory and published with a single
//! `rename(staging → out_dir)` so a failure never leaves a partial seed set
//! at the operator's final path (and never wipes un-promoted seeds after
//! some finals already exist).

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

        let address = blob
            .to_address(net)
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

/// Create a directory with mode `0700` on Unix (owner-only). On non-Unix the
/// platform default is used — production ceremony storage is Unix offline
/// media; the cfg keeps the workspace building on Windows CI.
fn create_dir_private(path: &Path, recursive: bool) -> Result<(), GenesisToolError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| invalid(format!("cannot create {}: {e}", path.display())))
}

/// Open a new file for writing with mode `0600` on Unix (owner read/write).
fn open_file_private(path: &Path) -> Result<std::fs::File, GenesisToolError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .map_err(|e| invalid(format!("cannot create {}: {e}", path.display())))
}

/// Remove a staging (or incomplete publish) directory; best-effort.
///
/// Failures are silent: the house "no debug macros in production library
/// Rust" gate forbids `eprintln!` here, and after a successful
/// `rename(staging → out_dir)` the staging path is already empty of
/// secrets. After a failed write the caller's primary `Err` is what the
/// operator acts on; a leftover `.*.geblock-staging-*` dir is still
/// discoverable by name if the wipe itself fails.
fn wipe_staging(staging: &Path) {
    drop(std::fs::remove_dir_all(staging));
}

/// Write the complete ceremony set into `staging` (must already exist, empty).
fn write_ceremony_tree(
    staging: &Path,
    net: Network,
    wallets: &[GeneratedWallet],
) -> Result<(), GenesisToolError> {
    let net_name = net.as_str();
    let role = match net {
        Network::Mainnet | Network::Stagenet => "Founder allocation",
        Network::Testnet => "Developer",
    };

    for w in wallets {
        let path = staging.join(custody_filename(net, w.index));
        let mut file = open_file_private(&path)?;

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
    let skel_path = staging.join(skeleton_filename(net));
    let mut file = open_file_private(&skel_path)?;
    let mut body = serde_json::to_string_pretty(&skeleton)?;
    body.push('\n');
    file.write_all(body.as_bytes())
        .map_err(|e| invalid(format!("write {}: {e}", skel_path.display())))?;
    Ok(())
}

/// True when `rename` failed because the paths are on different mount points.
fn is_cross_device(err: &std::io::Error) -> bool {
    // Linux/macOS: EXDEV. Windows: ERROR_NOT_SAME_DEVICE (17) sometimes
    // surfaces as Other; we also match the raw os error where available.
    err.raw_os_error() == Some(18) /* EXDEV on Linux/macOS */
        || err.kind() == std::io::ErrorKind::CrossesDevices
}

/// Copy every entry of a fully-written staging tree into an empty `dest`.
/// Used only when same-FS `rename(staging → dest)` is unavailable (EXDEV).
/// On any failure the caller must remove `dest` and leave `staging` intact.
fn copy_tree_into(staging: &Path, dest: &Path) -> Result<(), GenesisToolError> {
    let entries = std::fs::read_dir(staging)
        .map_err(|e| invalid(format!("read staging {}: {e}", staging.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| invalid(format!("read staging entry: {e}")))?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        std::fs::copy(&from, &to)
            .map_err(|e| invalid(format!("copy {} → {}: {e}", from.display(), to.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // `copy` does not preserve our 0600; re-apply owner-only.
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| invalid(format!("chmod {}: {e}", to.display())))?;
        }
    }
    Ok(())
}

/// Write per-wallet custody files (0600, never overwritten) plus a
/// ready-to-commit recipients-JSON skeleton (addresses only — no secrets).
/// Returns the skeleton path under the published `out_dir`.
///
/// Publish is atomic on the common path:
/// 1. refuse any git worktree (before creating anything);
/// 2. require `out_dir` does not already exist;
/// 3. write the full set into a sibling staging directory;
/// 4. `rename(staging → out_dir)` — one filesystem operation; either the
///    complete ceremony appears at `out_dir` or nothing does.
///
/// Cross-device fallback (rare for offline ceremony media): create `out_dir`,
/// copy the full tree, wipe staging only after every copy succeeds. A mid-copy
/// failure removes the incomplete `out_dir` and **leaves staging intact** so
/// seeds are never destroyed after a partial publish.
pub fn write_custody_files(
    dir: &Path,
    net: Network,
    wallets: &[GeneratedWallet],
) -> Result<PathBuf, GenesisToolError> {
    if wallets.len() != GENESIS_RECIPIENT_COUNT {
        return Err(invalid(format!(
            "gen-wallets: expected exactly {GENESIS_RECIPIENT_COUNT} wallets, got {}",
            wallets.len()
        )));
    }

    // (1) Refuse before any mkdir.
    refuse_git_worktree(dir)?;

    // (2) Atomic publish requires a vacant final path — no merge into a
    // pre-existing directory (that path re-introduces partial-promote races).
    if dir.exists() {
        return Err(invalid(format!(
            "out-dir {} already exists; pass a new path so the ceremony can \
             publish the full wallet set in one rename (refusing to merge into \
             an existing directory)",
            dir.display()
        )));
    }

    let abs_out = absolute_path(dir)?;
    let parent = abs_out.parent().ok_or_else(|| {
        invalid(format!(
            "out-dir {} has no parent directory",
            abs_out.display()
        ))
    })?;
    if !parent.exists() {
        create_dir_private(parent, true)?;
        // Parent was just created; re-check it is not inside a git tree.
        refuse_git_worktree(parent)?;
    }

    // Sibling staging: same parent as out_dir so rename is typically same-FS.
    let staging = parent.join(format!(
        ".{}.geblock-staging-{}-{}",
        abs_out
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "out".into()),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    refuse_git_worktree(&staging)?;
    create_dir_private(&staging, false)?;

    // (3) Write the complete set into staging. Any failure → wipe staging
    // (nothing has been published to out_dir).
    if let Err(e) = write_ceremony_tree(&staging, net, wallets) {
        wipe_staging(&staging);
        return Err(e);
    }

    // (4) Atomic publish.
    match std::fs::rename(&staging, &abs_out) {
        Ok(()) => Ok(abs_out.join(skeleton_filename(net))),
        Err(e) if is_cross_device(&e) => {
            // Different mount points: copy full tree, never wipe staging
            // until every file is at abs_out.
            if let Err(create_err) = create_dir_private(&abs_out, false) {
                // Staging still holds the only seeds.
                return Err(invalid(format!(
                    "cross-device publish: cannot create {}: {create_err} \
                     (seeds remain in staging {})",
                    abs_out.display(),
                    staging.display()
                )));
            }
            if let Err(copy_err) = copy_tree_into(&staging, &abs_out) {
                // Incomplete out_dir must not remain; staging still has seeds.
                wipe_staging(&abs_out);
                return Err(invalid(format!(
                    "cross-device publish failed: {copy_err}; \
                     incomplete out-dir removed; seeds remain in staging {}",
                    staging.display()
                )));
            }
            wipe_staging(&staging);
            Ok(abs_out.join(skeleton_filename(net)))
        }
        Err(e) => {
            // rename failed before any publish: wipe staging, out_dir absent.
            wipe_staging(&staging);
            Err(invalid(format!(
                "cannot publish ceremony to {}: {e}",
                abs_out.display()
            )))
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
        let dir = std::env::temp_dir().join(format!(
            "geblock-count-check-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let err = write_custody_files(&dir, Network::Testnet, &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected exactly") || msg.contains("git tree"),
            "unexpected error: {msg}"
        );
        assert!(!dir.exists(), "count mismatch must not create out_dir");
    }

    #[test]
    fn write_custody_rejects_existing_out_dir() {
        let dir = std::env::temp_dir().join(format!(
            "geblock-exists-check-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if refuse_git_worktree(&dir).is_err() {
            return; // cannot exercise exists-check inside a git tree
        }
        std::fs::create_dir_all(&dir).expect("create pre-existing out_dir");
        let wallets = generate_wallets(Network::Testnet).expect("generate");
        let err = write_custody_files(&dir, Network::Testnet, &wallets).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn write_custody_atomic_publish_complete_or_absent() {
        if refuse_git_worktree(&std::env::temp_dir()).is_err() {
            return; // cannot write custody under a git-ish temp root
        }
        let dir = std::env::temp_dir().join(format!(
            "geblock-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(!dir.exists());
        let wallets = generate_wallets(Network::Testnet).expect("generate");
        let skel = write_custody_files(&dir, Network::Testnet, &wallets).expect("write");
        assert!(dir.is_dir(), "out_dir must exist after success");
        assert!(skel.is_file(), "skeleton published");
        let mut custody = 0usize;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            // No leftover staging names under out_dir.
            assert!(!name.contains("geblock-staging"), "{name}");
            if name.starts_with("genesis-wallet-") {
                custody += 1;
            }
        }
        assert_eq!(custody, GENESIS_RECIPIENT_COUNT);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
