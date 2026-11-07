// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Store paths for this crate's tests.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A store path inside a directory the test owns.
///
/// The directory is created under the system temp directory with a random
/// name, by a `mkdir` that refuses an existing path, so a test never opens a
/// store another test or an earlier run left behind. When this drops, the
/// directory goes with everything in it: the store, and the files a store
/// keeps beside itself (`.creation-lock`, `.discard`, `.unfinished-*`). A
/// panicking test drops it too.
///
/// Bind it to a name for as long as the store is used. A call chained on
/// the temporary (`tmp("x").with_extension("y")`) drops the directory at the
/// end of that statement and leaves a path to nothing; the compiler does
/// not catch it.
pub(crate) struct TestPath {
    path: PathBuf,
    _dir: TempDir,
}

/// A fresh `<name>.redb` path in a directory of its own.
///
/// # Panics
///
/// The directory cannot be created.
pub(crate) fn tmp(name: &str) -> TestPath {
    let dir = tempfile::Builder::new()
        .prefix("shekyl-chain-store-")
        .tempdir()
        .expect("create a test directory");
    TestPath {
        path: dir.path().join(format!("{name}.redb")),
        _dir: dir,
    }
}

impl Deref for TestPath {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TestPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
