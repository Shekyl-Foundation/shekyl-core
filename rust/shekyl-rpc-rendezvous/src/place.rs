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

use std::path::{Path, PathBuf};

use crate::RendezvousName;

/// A Windows record's first line: its format and version.
pub const RECORD_FORMAT: &str = "shekyl-rendezvous 1";

/// The owner's pipe's namespace prefix; the rest of the name is drawn at
/// random on each start.
pub const PIPE_PREFIX: &str = r"\\.\pipe\shekyl-owner-";

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
        data_home(root).join("rendezvous")
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

    #[test]
    fn the_file_and_the_directory_are_the_platforms() {
        let name = crate::rendezvous_name(&[7; crate::NETWORK_ID_LEN], &crate::Instance::Default);
        let file = file_name(&name);
        assert!(file.starts_with("shekyl-"), "{file}");
        assert_eq!(file.ends_with(".sock"), !cfg!(windows), "{file}");
        let root = Path::new("root");
        if cfg!(windows) {
            assert_eq!(account_dir(root), root.join("Shekyl").join("rendezvous"));
        } else {
            assert_eq!(account_dir(root), root);
        }
    }
}
