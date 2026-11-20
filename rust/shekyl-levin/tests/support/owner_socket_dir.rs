// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A short directory for a live test's owner socket. A support module the
//! live tests include by `#[path]`; under `tests/support/` it is not a test
//! target of its own.

use std::path::PathBuf;

/// A private directory for one daemon's owner socket, mode 0700.
///
/// It is not under the data directory. macOS keeps a test's temporary
/// directory at a path long enough that nesting the socket there exceeds
/// `sun_path` (104 bytes, the terminator included; `RPC_CHANNEL.md` §7.1).
/// `/tmp` stays short. The caller removes the directory when the daemon
/// exits.
#[must_use]
pub fn owner_socket_dir(port: u16) -> PathBuf {
    let dir = short_root().join(format!("skl-{}-{port}", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    private_dir_builder()
        .create(&dir)
        .unwrap_or_else(|error| panic!("create {}: {error}", dir.display()));
    dir
}

/// A builder for a directory only this account can enter: mode 0700 on
/// Unix. On Windows the per-user temporary directory is already private.
fn private_dir_builder() -> std::fs::DirBuilder {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new()
    }
}

fn short_root() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir()
    }
}
