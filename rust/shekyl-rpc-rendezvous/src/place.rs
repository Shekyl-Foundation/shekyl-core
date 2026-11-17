// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a run-as-me daemon's rendezvous is, and what a Windows rendezvous
//! record says (`docs/design/RPC_CHANNEL.md` RT-15, §7.1). The daemon that
//! publishes it and the client that resolves "this computer" read this one
//! module, so the two cannot disagree on a path or a record.
//!
//! - **The directory.** Unix: the account's session directory, as it is
//!   (the daemon asserts its owner and mode before binding). Windows:
//!   `Shekyl\rendezvous` under the account's local application data folder.
//!   Reading the account's root is the caller's (the platform interface,
//!   never the environment, IG-Q14); composing the directory from it is
//!   here.
//! - **The file.** `shekyl-<name>.sock` (the socket itself) on Unix,
//!   `shekyl-<name>` (the record) on Windows, `<name>` being
//!   [`crate::rendezvous_name`]'s.
//! - **The record** (Windows): three lines, `shekyl-rendezvous 1`, `pipe
//!   \\.\pipe\shekyl-owner-<32 hex>` and `session <logon SID>`.
//! - **A service's record** (every platform; IG-Q105): three lines,
//!   `shekyl-service-rendezvous 1`, `channel <address:port>` and
//!   `bundle <hex>`, in the service's machine-wide rendezvous directory
//!   under [`service_file_name`]. The service publishes it only while it
//!   listens on the channel (Rick, 2026-11-14).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::RendezvousName;

/// A Windows record's first line: its format and version.
pub const RECORD_FORMAT: &str = "shekyl-rendezvous 1";

/// The owner's pipe's namespace prefix; the rest of the name is drawn at
/// random on each start.
pub const PIPE_PREFIX: &str = r"\\.\pipe\shekyl-owner-";

/// A service's console pipe's namespace prefix (`RPC_CHANNEL.md` RT-O37);
/// the rest of the name is drawn at random on each start and written in the
/// data directory, where only the service account and an administrator
/// read it.
pub const CONSOLE_PIPE_PREFIX: &str = r"\\.\pipe\shekyl-console-";

/// A service's record's first line: its format and version.
pub const SERVICE_RECORD_FORMAT: &str = "shekyl-service-rendezvous 1";

/// The rendezvous directory's name inside a Windows data home: the
/// account's (`Shekyl\rendezvous`, [`account_dir`]) and the service's
/// (`%ProgramData%\shekyl\rendezvous`; Rick, 2026-11-14).
pub const RENDEZVOUS_DIR: &str = "rendezvous";

/// The rendezvous file's name in its directory: the socket on Unix, the
/// record on Windows.
#[must_use]
pub fn file_name(name: &RendezvousName) -> String {
    if cfg!(windows) {
        format!("shekyl-{name}")
    } else {
        format!("shekyl-{name}.sock")
    }
}

/// A service's record's name in the service's rendezvous directory:
/// `shekyl-<name>` on every platform, a file and never a socket.
#[must_use]
pub fn service_file_name(name: &RendezvousName) -> String {
    format!("shekyl-{name}")
}

/// The daemon's static key, in the network's data directory (RT-O34).
pub const CHANNEL_KEY_FILE: &str = "rpc-channel.key";

/// The daemon's public bundle, in the network's data directory: the X25519
/// key then the ML-KEM-768 encapsulation key, what `rpc_bundle_show` replies.
pub const CHANNEL_BUNDLE_FILE: &str = "rpc-channel.bundle";

/// A service's console key, in the network's data directory (§5).
pub const CONSOLE_KEY_FILE: &str = "rpc-console.key";

/// A service's console leg on Unix: a socket in the network's data
/// directory (RT-O37).
pub const CONSOLE_SOCKET_FILE: &str = "rpc-console.sock";

/// The file naming a service's console pipe on Windows, in the network's
/// data directory (RT-O37).
pub const CONSOLE_PIPE_FILE: &str = "rpc-console.pipe";

/// Where a service's console leg is named for its data directory `dir`:
/// the socket on Unix, the pipe's file on Windows. The service binds there
/// and the CLI dials there, through this one function.
#[must_use]
pub fn console_leg_place(dir: &Path) -> PathBuf {
    dir.join(if cfg!(windows) {
        CONSOLE_PIPE_FILE
    } else {
        CONSOLE_SOCKET_FILE
    })
}

/// Where a service's record is: [`service_file_name`] in the service's
/// rendezvous directory `dir`, under the RT-O10 name of `network_id` and
/// `instance`. The daemon publishes there and a client on the same
/// machine reads there, through this one function.
#[must_use]
pub fn service_record_path(
    dir: &Path,
    network_id: &[u8; crate::NETWORK_ID_LEN],
    instance: &crate::Instance,
) -> PathBuf {
    dir.join(service_file_name(&crate::rendezvous_name(
        network_id, instance,
    )))
}

/// Windows: the account's data home, `Shekyl` under the local application
/// data folder `root`. The default rendezvous directory sits in it.
#[must_use]
pub fn data_home(root: &Path) -> PathBuf {
    root.join("Shekyl")
}

/// The default rendezvous directory for an account whose root is `root`:
/// on Unix the session directory itself, on Windows `Shekyl\rendezvous`
/// under the local application data folder.
#[must_use]
pub fn account_dir(root: &Path) -> PathBuf {
    if cfg!(windows) {
        data_home(root).join(RENDEZVOUS_DIR)
    } else {
        root.to_path_buf()
    }
}

/// A Windows rendezvous record: the pipe the daemon serves its owner on, and
/// the logon session that pipe admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// `\\.\pipe\shekyl-owner-<32 hex>`.
    pub pipe: String,
    /// The logon session's SID, as a string.
    pub session: String,
}

impl Record {
    /// The record's bytes, as the daemon publishes them.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "{RECORD_FORMAT}\npipe {}\nsession {}\n",
            self.pipe, self.session
        )
        .into_bytes()
    }

    /// Read a record. `None` for anything that is not one: another format or
    /// version, a missing line, or a pipe outside the owner's namespace.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.lines();
        if lines.next()? != RECORD_FORMAT {
            return None;
        }
        let pipe = lines.next()?.strip_prefix("pipe ")?.to_owned();
        let session = lines.next()?.strip_prefix("session ")?.to_owned();
        pipe.starts_with(PIPE_PREFIX)
            .then_some(Self { pipe, session })
    }
}

/// A service's record: the channel address a client on this machine dials
/// and the daemon's public bundle, which the client pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRecord {
    /// The loopback address the service's channel listener answers on.
    pub channel: SocketAddr,
    /// The daemon's public bundle: its X25519 key, then its ML-KEM-768
    /// encapsulation key.
    pub bundle: Vec<u8>,
}

impl ServiceRecord {
    /// The record's bytes, as the service publishes them.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut text = format!("{SERVICE_RECORD_FORMAT}\nchannel {}\nbundle ", self.channel);
        for byte in &self.bundle {
            text.push(hex_digit(byte >> 4));
            text.push(hex_digit(byte & 0x0f));
        }
        text.push('\n');
        text.into_bytes()
    }

    /// Read a record. `None` for anything that is not one: another format or
    /// version, a missing or malformed line, an empty bundle, or anything
    /// after the bundle.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.lines();
        if lines.next()? != SERVICE_RECORD_FORMAT {
            return None;
        }
        let channel = lines.next()?.strip_prefix("channel ")?.parse().ok()?;
        let hex = lines.next()?.strip_prefix("bundle ")?.as_bytes();
        if lines.next().is_some() || hex.is_empty() || hex.len() % 2 != 0 {
            return None;
        }
        let bundle = hex
            .chunks_exact(2)
            .map(|pair| Some(hex_value(pair[0])? << 4 | hex_value(pair[1])?))
            .collect::<Option<Vec<u8>>>()?;
        Some(Self { channel, bundle })
    }
}

/// The lowercase hex digit for `nibble` (below 16).
fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble & 0x0f)])
}

/// The value of a lowercase hex digit; an uppercase one is not a record's.
fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            pipe: format!("{PIPE_PREFIX}{}", "ab".repeat(16)),
            session: "S-1-5-5-0-123456".to_owned(),
        }
    }

    #[test]
    fn a_record_reads_back_as_written() {
        let r = record();
        assert_eq!(Record::parse(&r.bytes()), Some(r));
    }

    /// Red edit: drop the prefix check, and the pipe outside the owner's
    /// namespace is read as a record.
    #[test]
    fn anything_but_a_record_is_none() {
        let good = String::from_utf8(record().bytes()).unwrap();
        for bad in [
            good.replace("shekyl-rendezvous 1", "shekyl-rendezvous 2"),
            good.replace(r"\\.\pipe\shekyl-owner-", r"\\.\pipe\elsewhere-"),
            good.replace("session ", "sesion "),
            good.lines().take(2).collect::<Vec<_>>().join("\n"),
            String::new(),
        ] {
            assert_eq!(Record::parse(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(Record::parse(&[0xff, 0xfe]), None);
    }

    /// A service's record has a fixed form: the bytes below are the ones a
    /// client of RT-W12 reads.
    #[test]
    fn a_service_record_reads_back_as_written() {
        let r = ServiceRecord {
            channel: "127.0.0.1:28100".parse().unwrap(),
            bundle: vec![0xab, 0x01, 0xf0],
        };
        assert_eq!(
            r.bytes(),
            b"shekyl-service-rendezvous 1\nchannel 127.0.0.1:28100\nbundle ab01f0\n"
        );
        assert_eq!(ServiceRecord::parse(&r.bytes()), Some(r));
        let v6 = ServiceRecord {
            channel: "[::1]:9".parse().unwrap(),
            bundle: vec![0],
        };
        assert_eq!(ServiceRecord::parse(&v6.bytes()), Some(v6));
    }

    /// Red edit: let `parse` accept a trailing line, and the record with
    /// one more line is read.
    #[test]
    fn anything_but_a_service_record_is_none() {
        let good = "shekyl-service-rendezvous 1\nchannel 127.0.0.1:28100\nbundle ab01\n";
        for bad in [
            good.replace("rendezvous 1", "rendezvous 2"),
            good.replace("channel ", "chanel "),
            good.replace("127.0.0.1:28100", "localhost:28100"),
            good.replace("bundle ab01", "bundle ab0"),
            good.replace("bundle ab01", "bundle AB01"),
            good.replace("bundle ab01", "bundle zz01"),
            good.replace("bundle ab01", "bundle "),
            format!("{good}extra\n"),
            good.lines().take(2).collect::<Vec<_>>().join("\n"),
            String::new(),
        ] {
            assert_eq!(ServiceRecord::parse(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn the_file_and_the_directory_are_the_platforms() {
        let name = crate::rendezvous_name(&[7; crate::NETWORK_ID_LEN], &crate::Instance::Default);
        let file = file_name(&name);
        assert!(file.starts_with("shekyl-"), "{file}");
        assert_eq!(file.ends_with(".sock"), !cfg!(windows), "{file}");
        assert_eq!(service_file_name(&name), format!("shekyl-{name}"));
        let root = Path::new("root");
        if cfg!(windows) {
            assert_eq!(account_dir(root), root.join("Shekyl").join("rendezvous"));
        } else {
            assert_eq!(account_dir(root), root);
        }
    }
}
