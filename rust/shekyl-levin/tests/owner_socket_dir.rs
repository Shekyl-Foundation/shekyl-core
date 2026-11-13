// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A short directory for a live test's owner socket.

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
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&dir)
        .unwrap_or_else(|error| panic!("create {}: {error}", dir.display()));
    dir
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
