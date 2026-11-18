// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's machine-wide rendezvous record (`RPC_CHANNEL.md` §7.1;
//! `INPUT_GRAMMAR.md` IG-Q105): `<the service's rendezvous
//! directory>/shekyl-<name>`, readable by users, so a client of any account
//! on the machine finds "this computer"'s service.
//!
//! **Always published** (Rick, 2026-11-17, amending 2026-11-14's "only when
//! the service listens on the channel"): a wallet on this machine reads it to
//! tell a service from no node at all. It names the loopback channel address
//! and the daemon's public bundle only when `rpc-listen` is on, and the view
//! listener only when `rpc-view-listen` is on.
//!
//! The record is published after the listener is bound, atomically (written
//! to a fresh file beside it and renamed over it), and removed on a clean
//! stop, only while it is still the one this daemon wrote. Its name and form
//! are `shekyl-rpc-rendezvous`'s ([`ServiceRecord`]), which the client that
//! dials a service reads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use shekyl_rpc_rendezvous::{ServiceChannel, ServiceRecord};

use shekyl_os_account::private_file::{self, Access, Replace, StagedWrite};

use super::files::FileRefused;

/// The published record. Dropping it removes the file, if the file is
/// still this daemon's record.
#[derive(Debug)]
pub struct ServiceRendezvous {
    path: PathBuf,
    record: Vec<u8>,
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
    /// The write or the rename failed; [`FileRefused::HeldOpen`] when
    /// another program held the staged record open past the wait.
    pub fn publish(
        path: &Path,
        channel: Option<(&[SocketAddr], &[u8])>,
        view: &[SocketAddr],
    ) -> Result<Self, FileRefused> {
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
        StagedWrite::<Replace>::create(path, &record, Access::WorldReadable)
            .map_err(|error| FileRefused::Io(private_file::staged_path(path), error))?
            .commit()?;
        Ok(Self {
            path: path.to_path_buf(),
            record,
        })
    }

    /// Where the record is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ServiceRendezvous {
    fn drop(&mut self) {
        if std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.record) {
            drop(std::fs::remove_file(&self.path));
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
        let bound = ["0.0.0.0:28100".parse().unwrap()];
        let view = ["127.0.0.1:11030".parse().unwrap()];
        let published =
            ServiceRendezvous::publish(&path, Some((&bound, &[0xab; 4])), &view).unwrap();
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

        let published = ServiceRendezvous::publish(&path, Some((&bound, &[1])), &[]).unwrap();
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
        let published = ServiceRendezvous::publish(&path, None, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "shekyl-service-rendezvous 2\n"
        );
        drop(published);
        assert!(!path.exists());
    }
}
