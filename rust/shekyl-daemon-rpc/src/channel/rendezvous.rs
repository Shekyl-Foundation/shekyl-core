// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's machine-wide rendezvous record (`RPC_CHANNEL.md` §7.1;
//! `INPUT_GRAMMAR.md` IG-Q105), readable by every account, so a client of
//! any account on the machine finds "this computer"'s service: on Linux,
//! FreeBSD and macOS the file `<the service's rendezvous
//! directory>/shekyl-<name>`; on Windows a value under
//! `HKLM\SOFTWARE\Shekyl\Rendezvous` (Rick, 2026-11-18), whose key the
//! installer creates and the daemon checks before it publishes, never
//! creating it. A local account can hold a world-readable file open
//! without delete sharing and block a publish; nothing holds a value.
//!
//! **Always published** (Rick, 2026-11-17, amending 2026-11-14's "only when
//! the service listens on the channel"): a wallet on this machine reads it to
//! tell a service from no node at all. It names the loopback channel address
//! and the daemon's public bundle only when `rpc-listen` is on, and the view
//! listener only when `rpc-view-listen` is on.
//!
//! The record is published after the listener is bound, atomically (a file
//! staged beside it and renamed over it; a registry value written whole),
//! and removed on a clean stop, only while it is still the one this daemon
//! wrote. Its name and form
//! are `shekyl-rpc-rendezvous`'s ([`ServiceRecord`]), which the client that
//! dials a service reads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use shekyl_rpc_rendezvous::{ServiceChannel, ServiceRecord, ServiceRecordAt};

use shekyl_os_account::private_file::{Access, Replace, StagedWrite};

use super::files::FileRefused;

/// The published record. Dropping it removes it, if it is still this
/// daemon's record.
#[derive(Debug)]
pub struct ServiceRendezvous {
    at: ServiceRecordAt,
    record: Vec<u8>,
}

/// Why the record could not be published.
#[derive(Debug)]
pub enum PublishFault {
    /// The file could not be written ([`FileRefused::HeldOpen`] when
    /// another program held the staged record open past the wait).
    File(FileRefused),
    /// The registry key is missing, or its owner, readers or writers are
    /// not the installer's (Windows): the key's name and what is wrong.
    Key {
        /// `HKEY_LOCAL_MACHINE\...`.
        key: String,
        /// The condition that failed.
        found: String,
    },
    /// The registry value could not be written (Windows).
    Value(std::io::Error),
}

impl From<FileRefused> for PublishFault {
    fn from(error: FileRefused) -> Self {
        Self::File(error)
    }
}

impl ServiceRendezvous {
    /// Publish the record at `path`. `channel` is the bound channel
    /// listeners and the daemon's bundle, when the channel is on: the record
    /// names the address a local client dials ([`local_address`]). `view` is
    /// the bound view listeners: the record names the first. A previous
    /// run's record, which a crash left, is replaced; so is its staged file
    /// (a [`Replace`]).
    ///
    /// # Errors
    ///
    /// [`PublishFault`]: the file's write or rename failed, or on Windows
    /// the key is missing or exposed, or the value could not be written.
    pub fn publish(
        at: &ServiceRecordAt,
        channel: Option<(&[SocketAddr], &[u8])>,
        view: &[SocketAddr],
    ) -> Result<Self, PublishFault> {
        let record = ServiceRecord {
            channel: channel.and_then(|(bound, bundle)| {
                local_address(bound).map(|address| ServiceChannel {
                    address,
                    bundle: bundle.to_vec(),
                })
            }),
            view: view.first().copied(),
        }
        .bytes();
        match at {
            ServiceRecordAt::File(path) => {
                StagedWrite::<Replace>::create(path, &record, Access::WorldReadable)
                    .map_err(FileRefused::from)?
                    .commit()
                    .map_err(FileRefused::from)?;
            }
            #[cfg(windows)]
            ServiceRecordAt::Registry { key, value } => {
                let key = shekyl_win_sec::registry::RendezvousKey::new(key);
                key.check().map_err(|fault| PublishFault::Key {
                    key: key.name(),
                    found: fault.to_string(),
                })?;
                key.write(value, &record).map_err(PublishFault::Value)?;
            }
        }
        Ok(Self {
            at: at.clone(),
            record,
        })
    }

    /// Where the record is.
    #[must_use]
    pub fn at(&self) -> &ServiceRecordAt {
        &self.at
    }
}

impl Drop for ServiceRendezvous {
    fn drop(&mut self) {
        if !self
            .at
            .read()
            .is_ok_and(|held| held.as_ref() == Some(&self.record))
        {
            return;
        }
        match &self.at {
            ServiceRecordAt::File(path) => drop(std::fs::remove_file(path)),
            #[cfg(windows)]
            ServiceRecordAt::Registry { key, value } => {
                drop(shekyl_win_sec::registry::RendezvousKey::new(key).remove(value));
            }
        }
    }
}

/// The address a client on this machine dials: the first listener that
/// loopback reaches, a wildcard named by its family's loopback address; or,
/// when none does, the first listener.
#[must_use]
pub fn local_address(bound: &[SocketAddr]) -> Option<SocketAddr> {
    let reached = bound.iter().find_map(|addr| match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port()))
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            Some(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port()))
        }
        ip if ip.is_loopback() => Some(*addr),
        _ => None,
    });
    reached.or_else(|| bound.first().copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wildcard is named by its family's loopback address; a loopback
    /// listener by itself; with neither, the first listener.
    #[test]
    fn the_record_names_what_loopback_reaches() {
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            local_address(&[at("192.0.2.1:9"), at("0.0.0.0:28100")]),
            Some(at("127.0.0.1:28100"))
        );
        assert_eq!(local_address(&[at("[::]:28100")]), Some(at("[::1]:28100")));
        assert_eq!(
            local_address(&[at("127.0.0.1:5"), at("0.0.0.0:6")]),
            Some(at("127.0.0.1:5"))
        );
        assert_eq!(local_address(&[at("192.0.2.1:9")]), Some(at("192.0.2.1:9")));
        assert_eq!(local_address(&[]), None);
    }

    /// The record is published whole and readable by every account, and a
    /// clean stop removes it only while it is still this daemon's. Red
    /// edit: drop the content check in `Drop`, and the replaced record is
    /// removed.
    #[cfg(unix)]
    #[test]
    fn the_record_is_published_whole_and_removed_only_while_it_is_ours() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shekyl-0123456789abcdef01234567");
        let at = ServiceRecordAt::File(path.clone());
        let bound = ["0.0.0.0:28100".parse().unwrap()];
        let view = ["127.0.0.1:11030".parse().unwrap()];
        let published = ServiceRendezvous::publish(&at, Some((&bound, &[0xab; 4])), &view).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "shekyl-service-rendezvous 2\nchannel 127.0.0.1:28100\nbundle abababab\nview 127.0.0.1:11030\n"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        drop(published);
        assert!(!path.exists(), "a clean stop removes the record");

        let published = ServiceRendezvous::publish(&at, Some((&bound, &[1])), &[]).unwrap();
        std::fs::write(&path, b"someone else's").unwrap();
        drop(published);
        assert!(path.exists(), "a record this daemon no longer owns is left");
    }

    /// A service with neither listener still publishes its record, so a
    /// wallet tells it from no node, and a crash's leftover is replaced.
    /// Red edit: publish nothing when the channel is off, and the file is
    /// the leftover.
    #[test]
    fn a_service_with_no_listener_still_publishes_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shekyl-record");
        std::fs::write(&path, b"shekyl-service-rendezvous 2\nview 127.0.0.1:1\n").unwrap();
        let published =
            ServiceRendezvous::publish(&ServiceRecordAt::File(path.clone()), None, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "shekyl-service-rendezvous 2\n"
        );
        drop(published);
        assert!(!path.exists());
    }

    /// On Windows the record is a value under the installer's key: a key
    /// as the installer makes it takes the record, and a clean stop removes
    /// it while it is still this daemon's; a key another account may write
    /// and a missing key are refused, naming the key and the condition, in
    /// `config.service.rendezvous-key`'s words. Red edit: publish without
    /// the key's check, and the exposed key takes the record.
    #[cfg(windows)]
    #[test]
    fn the_record_is_a_value_under_a_checked_key() {
        use shekyl_win_sec::registry::{RendezvousKey, ScratchKey};
        let instance = shekyl_rpc_rendezvous::Instance::Default;
        let network_id = [3u8; shekyl_rpc_rendezvous::NETWORK_ID_LEN];
        let view = ["127.0.0.1:11030".parse().unwrap()];

        let good = ScratchKey::new("daemon-good", &ScratchKey::installer_sddl(""));
        let at = ServiceRecordAt::registry(good.subkey(), &network_id, &instance);
        let published = ServiceRendezvous::publish(&at, None, &view).unwrap();
        assert_eq!(
            at.read().unwrap().as_deref(),
            Some(&b"shekyl-service-rendezvous 2\nview 127.0.0.1:11030\n"[..])
        );
        drop(published);
        assert_eq!(at.read().unwrap(), None, "a clean stop removes the value");

        let exposed = ScratchKey::new(
            "daemon-exposed",
            &ScratchKey::installer_sddl("(A;CI;KW;;;BU)"),
        );
        let at = ServiceRecordAt::registry(exposed.subkey(), &network_id, &instance);
        let Err(PublishFault::Key { key, found }) = ServiceRendezvous::publish(&at, None, &view)
        else {
            panic!("an exposed key took the record");
        };
        assert_eq!(key, exposed.key().name());
        assert!(found.contains("S-1-5-32-545"), "{found}");
        assert_eq!(at.read().unwrap(), None, "nothing was written");

        let missing = r"SOFTWARE\Shekyl\Test-daemon-missing-never-created";
        let at = ServiceRecordAt::registry(missing, &network_id, &instance);
        let Err(PublishFault::Key { key, found }) = ServiceRendezvous::publish(&at, None, &view)
        else {
            panic!("a missing key took the record");
        };
        assert_eq!(key, RendezvousKey::new(missing).name());
        let refusal = crate::run::rendezvous_key_refusal(&key, &found).render();
        assert!(refusal.contains(&key), "{refusal}");
        assert!(refusal.contains("does not exist"), "{refusal}");
        assert!(
            refusal.contains("the installer creates it with the service account"),
            "{refusal}"
        );
        assert!(
            refusal.contains("config.service.rendezvous-key"),
            "{refusal}"
        );
    }
}
