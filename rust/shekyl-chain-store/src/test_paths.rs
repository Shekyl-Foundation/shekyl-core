// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Store paths for this crate's tests.

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
/// The directory outlives the open store.
///
/// - A local is declared before the store. Locals drop in reverse
///   declaration order, so the store drops first.
/// - A field is declared after the store. Fields drop in declaration
///   order, so the store drops first.
///
/// An owner that holds both stays whole. A struct pattern drops its
/// bindings in reverse pattern order, so naming the directory last in the
/// pattern removes it before the store.
///
/// The file is [`Self::path`]. [`AsRef<Path>`] serves a function that takes
/// `impl AsRef<Path>`. A function that takes `&Path` is handed
/// [`Self::path`]. Bind this value, then borrow it: chaining on the
/// temporary ends the directory at the end of that statement.
pub(crate) struct TestPath {
    path: PathBuf,
    _dir: TempDir,
}

impl TestPath {
    /// The store file inside the directory this owns.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
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

impl AsRef<Path> for TestPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
