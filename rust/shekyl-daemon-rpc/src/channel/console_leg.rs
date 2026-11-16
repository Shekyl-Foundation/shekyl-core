// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's console leg (`RPC_CHANNEL.md` RT-O37, ruled 2026-11-15).
//!
//! The console key reaches a service on a leg only the service account and
//! an administrator can open, as the owner reaches a run-as-me daemon on one
//! only it can open. The channel's handshake runs over it unchanged: the leg
//! decides who reaches the console's reserved slots, and the key still
//! decides the authority. A connection there that claims any other key is
//! closed at message 3 ([`super::listener::Leg::Console`]).
//!
//! - **Unix:** a socket at [`CONSOLE_SOCKET_FILE`] in the network's data
//!   directory, inside the service's data home, which is `0700` and owned by
//!   the service account; the socket itself is `0600`. A socket left by a
//!   previous start is replaced: the data directory's exclusive lock is
//!   held, so nothing else is serving it.
//! - **Windows:** a pipe under a fresh random name, with the data home's
//!   ACL (`shekyl_win_sec::OwnerOnlyPipeListener::bind_console`), named in
//!   [`CONSOLE_PIPE_FILE`] in the data directory. A fixed name could be
//!   taken by another account before the service starts.
//!
//! The CLI finds the leg at the same fixed name in the data directory.

use std::path::{Path, PathBuf};

/// The console's socket, in the network's data directory (Unix).
pub const CONSOLE_SOCKET_FILE: &str = "rpc-console.sock";

/// The file naming the console's pipe, in the network's data directory
/// (Windows).
pub const CONSOLE_PIPE_FILE: &str = "rpc-console.pipe";

/// The console leg's listener.
#[cfg(unix)]
pub type ConsoleListener = tokio::net::UnixListener;

/// The console leg's listener.
#[cfg(windows)]
pub type ConsoleListener = crate::owner::OwnerListener;

/// Where the console's leg is named for the data directory `dir`.
#[must_use]
pub fn place(dir: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        dir.join(CONSOLE_SOCKET_FILE)
    }
    #[cfg(windows)]
    {
        dir.join(CONSOLE_PIPE_FILE)
    }
}

/// Bind the console's leg for the data directory `dir`. Called inside the
/// server's runtime, under the data directory's lock.
///
/// # Errors
///
/// Something other than a socket is at the socket's path, or the bind, the
/// mode or (Windows) the pipe's record failed.
#[cfg(unix)]
pub fn bind(dir: &Path) -> std::io::Result<ConsoleListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let path = place(dir);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(&path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} is not a socket; it is not replaced", path.display()),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Bind the console's leg for the data directory `dir`. Called inside the
/// server's runtime, under the data directory's lock.
///
/// # Errors
///
/// The pipe could not be created, or its record not written.
#[cfg(windows)]
pub fn bind(dir: &Path) -> std::io::Result<ConsoleListener> {
    use rand_core::{OsRng, RngCore};
    let mut draw = [0u8; 16];
    OsRng.fill_bytes(&mut draw);
    let name = format!(
        "{}{}",
        shekyl_rpc_rendezvous::CONSOLE_PIPE_PREFIX,
        draw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let listener = shekyl_win_sec::OwnerOnlyPipeListener::bind_console(name.clone())
        .map_err(|e| std::io::Error::other(format!("the console's pipe: {e}")))?;
    shekyl_os_account::private_file::replace_private(&place(dir), name.as_bytes())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(crate::owner::OwnerListener::from(listener))
}

/// Remove the console's leg on a clean stop: the socket (Unix) or the
/// pipe's record (Windows). A leg already gone is not an error.
pub fn retire(dir: &Path) {
    match std::fs::remove_file(place(dir)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            target: "global",
            "the console's leg {} could not be removed: {e}",
            place(dir).display()
        ),
    }
}
