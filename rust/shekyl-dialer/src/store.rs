// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The address file on disk (slice 1 brief §7): every list address,
//! written as [`shekyl_peerlist::address_file`] encodes it, and read back
//! at the next start, where each address enters gray.
//!
//! The owner loop writes the file at [`STORE_INTERVAL_NANOS`] while it
//! runs, and the dialer writes it once more when it stops. A write
//! replaces the file in one rename, so a crash mid-write leaves the
//! previous file. A file this build cannot read is dropped whole: the
//! lists start empty and the next write replaces it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shekyl_peerlist::address_file::{self, AddressFileError};
use shekyl_peerlist::NetworkAddress;

/// How often the owner loop writes the file while it runs: thirty
/// minutes, the interval the C++ `store_config` idle call kept.
pub const STORE_INTERVAL_NANOS: u64 = 30 * 60 * 1_000_000_000;

/// Why the file's addresses were not loaded. The lists are left as they
/// were in either case, and the next store replaces the file.
#[derive(Debug)]
pub enum LoadError {
    /// The file is there and could not be read.
    Io(io::Error),
    /// The file was read and is not an address file this build reads.
    Dropped(AddressFileError),
}

/// One address file at one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressStore {
    path: PathBuf,
}

impl AddressStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The addresses the file holds. No file is a first start: empty.
    pub fn load(&self) -> Result<Vec<NetworkAddress>, LoadError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(LoadError::Io(err)),
        };
        address_file::decode(&bytes).map_err(LoadError::Dropped)
    }

    /// Write `addresses` as the file, replacing what was there in one
    /// rename. The directory is created when it is not there.
    pub fn write(&self, addresses: &[NetworkAddress]) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
            }
        }
        let staged = self.path.with_extension("tmp");
        fs::write(&staged, address_file::encode(addresses))?;
        fs::rename(&staged, &self.path)
    }
}
