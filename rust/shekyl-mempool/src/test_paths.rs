// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pool-file paths for this crate's tests.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A pool-file path inside a directory the test owns.
///
/// The directory is created under the system temp directory with a random
/// name, by a `mkdir` that refuses an existing path, so a test never opens a
/// file another test or an earlier run left behind. When this drops, the
/// directory goes with everything in it: the pool file and the
/// `.creation-lock` the store keeps beside it. A panicking test drops it
/// too.
///
/// The directory outlives the open pool: declare this before the pool, or
/// return it ahead of the pool in a tuple, so the pool drops first.
///
/// [`AsRef<Path>`] is the pool file: every opener in this crate takes
/// `impl AsRef<Path>`. Bind this value, then borrow it: chaining on the
/// temporary ends the directory at the end of that statement.
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
        .prefix("shekyl-mempool-")
        .tempdir()
        .expect("create a test directory");
    TestPath {
        path: dir.path().join(format!("{name}.redb")),
        _dir: dir,
    }
}

impl AsRef<Path> for TestPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
