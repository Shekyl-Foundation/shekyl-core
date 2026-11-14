// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's machine-wide rendezvous record (`RPC_CHANNEL.md` §7.1;
//! `INPUT_GRAMMAR.md` IG-Q105): `<the service's rendezvous
//! directory>/shekyl-<name>`, readable by users, naming the loopback channel
//! address and the daemon's public bundle, so a client of any account on
//! the machine finds "this computer"'s service.
//!
//! **Published only when the service listens on the channel** (Rick,
//! 2026-11-14): `rpc-listen` is off by default and no channel port is
//! ruled, so a service started without it publishes nothing and says so at
//! start. RT-W12 must give a service a loopback channel listener by
//! default, on a channel port ruled then, before it retires the plaintext
//! admin listener: until then local tools reach a service on that listener.
//!
//! The record is published after the listener is bound, atomically (written
//! to a fresh file beside it and renamed over it), and removed on a clean
//! stop, only while it is still the one this daemon wrote.
//!
//! Its form: `shekyl-service-rendezvous 1`, then `channel <address:port>`,
//! then `bundle <hex>`, one per line.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use super::stage::{self, Access};

/// The record's first line: its format and version.
pub const RECORD_FORMAT: &str = "shekyl-service-rendezvous 1";

/// Where a service's record goes: `shekyl-<name>` in its rendezvous
/// directory, `<name>` the RT-O10 derivation over the network id and the
/// instance, as the owner's leg names its own.
#[must_use]
pub fn record_path(
    dir: &Path,
    network_id: &shekyl_rpc_channel::NetworkId,
    instance: &shekyl_rpc_channel::Instance,
) -> PathBuf {
    dir.join(format!(
        "shekyl-{}",
        shekyl_rpc_channel::rendezvous_name(network_id, instance)
    ))
}

/// The published record. Dropping it removes the file, if the file is
/// still this daemon's record.
#[derive(Debug)]
pub struct ServiceRendezvous {
    path: PathBuf,
    record: Vec<u8>,
}

impl ServiceRendezvous {
    /// Publish the record at `path`, naming the channel address a local
    /// client dials, chosen from the bound listeners ([`local_address`]),
    /// and `bundle`.
    ///
    /// # Errors
    ///
    /// No listener to name, or the write or the rename failed.
    pub fn publish(path: &Path, bound: &[SocketAddr], bundle: &[u8]) -> std::io::Result<Self> {
        let channel = local_address(bound).ok_or_else(|| {
            std::io::Error::other("a service rendezvous needs a channel listener")
        })?;
        let record = format!(
            "{RECORD_FORMAT}\nchannel {channel}\nbundle {}\n",
            hex::encode(bundle)
        )
        .into_bytes();
        let journal = stage::StagedWrite::create(path, &record, Access::WorldReadable)?;
        journal.commit()?;
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
        let published = ServiceRendezvous::publish(&path, &bound, &[0xab; 4]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "shekyl-service-rendezvous 1\nchannel 127.0.0.1:28100\nbundle abababab\n"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        drop(published);
        assert!(!path.exists(), "a clean stop removes the record");

        let published = ServiceRendezvous::publish(&path, &bound, &[1]).unwrap();
        std::fs::write(&path, b"someone else's").unwrap();
        drop(published);
        assert!(path.exists(), "a record this daemon no longer owns is left");
    }
}
