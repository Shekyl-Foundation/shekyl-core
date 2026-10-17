// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network marker (`DAEMON_CONFIG_CUTOVER.md` §2.6; IG-Q17, DC-Q15):
//! `shekyld.network` at the data directory's root, TOML holding the network
//! and the network id, written to a temporary file, synced, renamed into
//! place with the directory synced after, and read only while the lock is
//! held.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, Source};

use crate::lock::Lock;
use crate::network::Network;

/// The marker file's name: not mistaken for operator configuration.
pub const MARKER_FILE: &str = "shekyld.network";

/// The handshake id of the chain the data belongs to: 16 bytes derived from
/// its genesis, by the transport's one derivation.
pub type NetworkId = [u8; 16];

/// What the marker said, or that it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerOutcome {
    /// The directory held no store and no marker; the marker is written.
    Written,
    /// The marker names this network and this id.
    Matched,
}

/// Whether the directory holds a daemon store: the closed set the pre-flight
/// read at the implementation pin (`DAEMON_CONFIG_CUTOVER_AUDIT.md` §3).
#[must_use]
pub fn holds_store(data_dir: &Path) -> bool {
    data_dir.join("lmdb").join("data.mdb").is_file() || data_dir.join("p2pstate.bin").is_file()
}

/// Checks the marker under the lock, writing it when the directory is
/// fresh. The `Lock` parameter is the proof the lock is held.
///
/// # Errors
/// `config.marker.network` for another network's data, `config.marker.network-id`
/// for this network's name with another id, `config.marker.missing` for a
/// store with no marker, `config.marker.unreadable` for a marker that cannot
/// be read or parsed, and `config.data-dir.unusable` when the marker cannot
/// be written.
pub fn check_or_write(
    lock: &Lock,
    network: Network,
    network_id: NetworkId,
) -> Result<MarkerOutcome, Diagnostic> {
    let data_dir = lock.data_dir();
    let path = data_dir.join(MARKER_FILE);
    let shown_dir = data_dir.display().to_string();
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let (marked, marked_id) = parse(&text).ok_or_else(|| {
                Diagnostic::new(Code::MarkerUnreadable, Source::Machine)
                    .option("data-dir")
                    .param("path", path.display().to_string())
                    .param("error", "it does not hold a network and a network id")
            })?;
            if marked != network {
                return Err(Diagnostic::new(Code::MarkerNetwork, Source::Machine)
                    .option("data-dir")
                    .param("path", shown_dir)
                    .param("marked", marked.name())
                    .param("network", network.name()));
            }
            if marked_id != network_id {
                return Err(Diagnostic::new(Code::MarkerNetworkId, Source::Machine)
                    .option("data-dir")
                    .param("path", shown_dir)
                    .param("network", network.name()));
            }
            Ok(MarkerOutcome::Matched)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if holds_store(data_dir) {
                return Err(Diagnostic::new(Code::MarkerMissing, Source::Machine)
                    .option("data-dir")
                    .param("path", shown_dir));
            }
            write(data_dir, &path, network, network_id).map_err(|e| {
                Diagnostic::new(Code::DataDirUnusable, Source::Machine)
                    .option("data-dir")
                    .param("path", shown_dir.clone())
                    .param(
                        "error",
                        format!("the network marker could not be written: {e}"),
                    )
            })?;
            Ok(MarkerOutcome::Written)
        }
        Err(e) => Err(Diagnostic::new(Code::MarkerUnreadable, Source::Machine)
            .option("data-dir")
            .param("path", path.display().to_string())
            .param("error", e.to_string())),
    }
}

/// The marker's text.
#[must_use]
pub fn render(network: Network, network_id: NetworkId) -> String {
    let hex: String = network_id.iter().map(|b| format!("{b:02x}")).collect();
    format!("network = \"{}\"\nnetwork-id = \"{hex}\"\n", network.name())
}

/// The network and id a marker's text holds.
#[must_use]
pub fn parse(text: &str) -> Option<(Network, NetworkId)> {
    let table: toml::Table = text.parse().ok()?;
    let network = Network::from_word(table.get("network")?.as_str()?)?;
    let hex = table.get("network-id")?.as_str()?;
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some((network, id))
}

/// Temporary file, sync, rename, directory sync.
fn write(
    data_dir: &Path,
    path: &Path,
    network: Network,
    network_id: NetworkId,
) -> std::io::Result<()> {
    let staged: PathBuf = data_dir.join(format!("{MARKER_FILE}.tmp"));
    {
        let mut f = File::create(&staged)?;
        f.write_all(render(network, network_id).as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&staged, path)?;
    sync_dir(data_dir)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Windows has no directory handle to sync; the rename is durable on its
/// own once the file was.
#[cfg(windows)]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: NetworkId = [1; 16];
    const ID_B: NetworkId = [2; 16];

    fn locked() -> (tempfile::TempDir, Lock) {
        let d = tempfile::tempdir().unwrap();
        let lock = Lock::take(&d.path().join("data")).unwrap();
        (d, lock)
    }

    #[test]
    fn a_fresh_directory_is_marked_and_then_matches() {
        let (_d, lock) = locked();
        assert_eq!(
            check_or_write(&lock, Network::Testnet, ID_A).unwrap(),
            MarkerOutcome::Written
        );
        let text = std::fs::read_to_string(lock.data_dir().join(MARKER_FILE)).unwrap();
        assert_eq!(text, render(Network::Testnet, ID_A));
        assert_eq!(parse(&text), Some((Network::Testnet, ID_A)));
        assert_eq!(
            check_or_write(&lock, Network::Testnet, ID_A).unwrap(),
            MarkerOutcome::Matched
        );
        assert!(!lock.data_dir().join(format!("{MARKER_FILE}.tmp")).exists());
    }

    #[test]
    fn another_network_refuses_naming_both_and_the_fix() {
        let (_d, lock) = locked();
        check_or_write(&lock, Network::Testnet, ID_A).unwrap();
        let e = check_or_write(&lock, Network::Mainnet, ID_B).unwrap_err();
        assert_eq!(e.code, Code::MarkerNetwork);
        let text = e.render();
        assert!(
            text.contains("belongs to testnet") && text.contains("starting on mainnet"),
            "{text}"
        );
        assert!(text.contains("--data-dir"), "{text}");
    }

    #[test]
    fn the_same_network_with_another_id_is_a_regenesis_refusal() {
        let (_d, lock) = locked();
        check_or_write(&lock, Network::Mainnet, ID_A).unwrap();
        let e = check_or_write(&lock, Network::Mainnet, ID_B).unwrap_err();
        assert_eq!(e.code, Code::MarkerNetworkId);
        assert!(e.render().contains("regenesis"), "{e}");
    }

    #[test]
    fn a_store_with_no_marker_is_never_marked_after_the_fact() {
        let (_d, lock) = locked();
        std::fs::create_dir_all(lock.data_dir().join("lmdb")).unwrap();
        std::fs::write(lock.data_dir().join("lmdb").join("data.mdb"), "").unwrap();
        let e = check_or_write(&lock, Network::Mainnet, ID_A).unwrap_err();
        assert_eq!(e.code, Code::MarkerMissing);
        assert!(!lock.data_dir().join(MARKER_FILE).exists());
        let (_d2, lock2) = locked();
        std::fs::write(lock2.data_dir().join("p2pstate.bin"), "").unwrap();
        assert_eq!(
            check_or_write(&lock2, Network::Mainnet, ID_A)
                .unwrap_err()
                .code,
            Code::MarkerMissing
        );
    }

    #[test]
    fn a_marker_that_does_not_parse_is_unreadable_not_overwritten() {
        let (_d, lock) = locked();
        std::fs::write(lock.data_dir().join(MARKER_FILE), "network = 3\n").unwrap();
        let e = check_or_write(&lock, Network::Mainnet, ID_A).unwrap_err();
        assert_eq!(e.code, Code::MarkerUnreadable);
        assert_eq!(parse("network = \"mainnet\"\nnetwork-id = \"zz\"\n"), None);
    }
}
