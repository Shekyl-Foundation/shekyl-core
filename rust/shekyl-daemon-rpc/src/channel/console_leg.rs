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
//!   directory, which must be the service account's alone, bound through
//!   the listeners' shared bind
//!   (`shekyl_rpc_transport::listen::bind_owner_only_socket`): `0600` from
//!   before it listens. A socket left by a previous start is replaced: the
//!   data directory's exclusive lock is held, so nothing else serves it,
//!   and its connection is refused.
//! - **Windows:** a pipe under a fresh random name, with the data home's
//!   ACL (`shekyl_win_sec::OwnerOnlyPipeListener::bind_console`), named in
//!   [`CONSOLE_PIPE_FILE`] in the data directory. A fixed name could be
//!   taken by another account before the service starts.
//!
//! The CLI finds the leg at the same fixed name in the data directory.

use std::path::{Path, PathBuf};

pub use shekyl_rpc_rendezvous::{CONSOLE_PIPE_FILE, CONSOLE_SOCKET_FILE};

/// The console leg's listener.
#[cfg(unix)]
pub type ConsoleListener = tokio::net::UnixListener;

/// The console leg's listener.
#[cfg(windows)]
pub type ConsoleListener = crate::owner::OwnerListener;

/// Where the console's leg is named for the data directory `dir`
/// (`shekyl_rpc_rendezvous::console_leg_place`, which the CLI dials).
#[must_use]
pub fn place(dir: &Path) -> PathBuf {
    shekyl_rpc_rendezvous::console_leg_place(dir)
}

/// Bind the console's leg for the data directory `dir`. Called inside the
/// server's runtime, under the data directory's lock.
///
/// # Errors
///
/// The data directory is not the service account's alone, something that
/// is not a stale socket of this account is at the socket's path, or the
/// bind failed.
#[cfg(unix)]
pub fn bind(dir: &Path) -> Result<ConsoleListener, crate::run::StartFault> {
    bind_socket(dir).map_err(crate::run::StartFault::Refused)
}

#[cfg(unix)]
fn bind_socket(dir: &Path) -> Result<ConsoleListener, String> {
    use shekyl_rpc_transport::listen::{bind_owner_only_socket, OwnerSocketRefusal, SocketRefusal};
    let path = place(dir);
    match bind_owner_only_socket(&path) {
        Ok(bound) => bound
            .into_tokio()
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(OwnerSocketRefusal::NoDirectory) => {
            Err(format!("{} names no directory", path.display()))
        }
        Err(OwnerSocketRefusal::Directory(why)) => Err(format!(
            "{}; the console's leg is not bound there",
            why.clause(Some(&dir.display().to_string()))
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::Answers)) => Err(format!(
            "something answers on {} while this daemon holds the data directory's lock; it is \
             not replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::NotASocket)) => Err(format!(
            "{} is not a socket; it is not replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::NotThisAccounts(uid))) => Err(format!(
            "{} is a socket another account owns (uid {uid}); it is not replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::Unknown(why))) => Err(format!(
            "{}: whether anything still holds this socket is not known ({why}); it is not \
             replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::NotRemoved(why))) => {
            Err(format!("{}: {why}", path.display()))
        }
        Err(OwnerSocketRefusal::Socket(error)) => Err(format!("{}: {error}", path.display())),
    }
}

/// Bind the console's leg for the data directory `dir`. Called inside the
/// server's runtime, under the data directory's lock.
///
/// # Errors
///
/// The pipe could not be created, or its record not written
/// ([`crate::run::StartFault::HeldOpen`] when another program held the
/// staged record open past the wait).
#[cfg(windows)]
pub fn bind(dir: &Path) -> Result<ConsoleListener, crate::run::StartFault> {
    use rand_core::{OsRng, RngCore};
    let mut draw = [0u8; 16];
    OsRng.fill_bytes(&mut draw);
    let name = format!(
        "{}{}",
        shekyl_rpc_rendezvous::CONSOLE_PIPE_PREFIX,
        draw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let listener = shekyl_win_sec::OwnerOnlyPipeListener::bind_console(name.clone())
        .map_err(|e| format!("the console's pipe: {e}"))?;
    let path = place(dir);
    let replaced = shekyl_os_account::private_file::replace_console(&path, name.as_bytes())
        .map_err(super::files::FileRefused::from)?;
    super::files::note_replaced(&path, &replaced);
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// **The console's leg is never bound in a data directory others can
    /// enter**, and the refusal names the directory; in an owner-only one
    /// it is bound 0600 (Rick, 2026-11-22: the directory check is mandatory
    /// for every socket listener). Red edit: bind without the shared bind's
    /// directory check.
    #[tokio::test]
    async fn the_console_leg_is_bound_only_in_an_owner_only_data_directory() {
        let dir = tempfile::tempdir().expect("a data directory");
        let path = place(dir.path());
        for mode in [0o750, 0o755, 0o770] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            let refused = bind_socket(dir.path()).expect_err("refused");
            assert!(
                refused.contains(&dir.path().display().to_string())
                    && refused.contains("other accounts can enter")
                    && refused.contains("the console's leg is not bound there"),
                "mode {mode:o}: {refused}"
            );
            assert!(!path.exists(), "nothing was bound under mode {mode:o}");
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 700");
        let _leg = bind_socket(dir.path()).expect("bound in an owner-only data directory");
        let mode = std::fs::metadata(&path)
            .expect("the leg")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the console's leg is the service account's"
        );
    }
}
