// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's socket: dialled before it is published, bound, watched, and
//! removed on a clean exit (`docs/design/RPC_CHANNEL.md` RT-15, RT-16,
//! §7.1).
//!
//! A run-as-me daemon serves its own account on a Unix socket in a
//! directory only that account can reach. Every connection on it is the
//! host's administrator ([`crate::authority::Authority::owner`]): the
//! directory's containment is the authentication, so there is no key on
//! this leg.
//!
//! - **Start-up dial.** Before publishing, an existing socket at the path is
//!   dialled: it answers, so another daemon of this account, network and
//!   instance is running, and this one refuses to start and says so;
//!   nothing listens, so it is stale and replaced; it is not this account's
//!   socket, so it is reported and left alone. A bare "address in use"
//!   cannot tell a live daemon from a leftover file.
//! - **The watch.** The daemon's life is its rendezvous's. If the socket or
//!   its directory goes (the session ended under a daemon left in a
//!   terminal multiplexer, or something removed it), the daemon logs why
//!   and stops cleanly, so a run-as-me daemon stops when its session ends.
//! - **Clean exit** removes the socket before the listener drains, and only
//!   the socket this daemon bound: a path someone has since replaced is not
//!   removed.
//!
//! What the path is, and the checks on its directory, are the walk's
//! ([`shekyl_daemon_config::owner_socket`]); this module only does what the
//! walk checked.

#[cfg(unix)]
pub use unix::{serve_ready, watch, OwnerListener, OwnerSocket, Place, Rendezvous};

#[cfg(not(unix))]
pub use windows::{OwnerListener, OwnerSocket};

/// Windows serves its owner on a pipe, which this build does not serve
/// yet. The walk plans no owner's socket there
/// (`shekyl_daemon_config::owner_socket::plan`), so no value of these
/// types exists, and the server's and the run's owner paths are Unix's.
#[cfg(not(unix))]
mod windows {
    use shekyl_daemon_config::OwnerSocketPlan;
    use shekyl_options::{Code, Diagnostic, Source};

    /// No owner's socket is held on Windows.
    pub enum OwnerSocket {}
    /// No owner listener is served on Windows.
    pub enum OwnerListener {}

    impl OwnerSocket {
        /// Never called: the walk plans no owner's socket on Windows.
        ///
        /// # Errors
        ///
        /// Always, naming the platform.
        pub fn bind(plan: &OwnerSocketPlan, _network: &str) -> Result<Self, Diagnostic> {
            Err(Diagnostic::new(Code::SocketDirUnusable, Source::Machine)
                .param("path", plan.dir.display().to_string())
                .param("found", "Windows serves its owner on a pipe, not a socket"))
        }
    }
}

/// How often the watch looks at the rendezvous. A socket removed under a
/// running daemon is noticed within this long.
pub const WATCH_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    use shekyl_daemon_config::owner_socket::assert_dir;
    use shekyl_daemon_config::OwnerSocketPlan;
    use shekyl_options::{Code, Diagnostic, Source};

    /// The bound listener, as [`OwnerSocket::into_parts`] hands it to the
    /// server.
    pub type OwnerListener = UnixListener;

    /// The listener in the server's runtime.
    ///
    /// # Errors
    ///
    /// The runtime would not take the socket.
    pub fn serve_ready(listener: OwnerListener) -> io::Result<tokio::net::UnixListener> {
        let listener = tokio::net::UnixListener::from_std(listener)?;
        if let Ok(addr) = listener.local_addr() {
            if let Some(path) = addr.as_pathname() {
                tracing::info!(
                    target: "global",
                    "shekyl-daemon-rpc listening on {} (owner's socket)",
                    path.display()
                );
            }
        }
        Ok(listener)
    }

    /// The bound owner's socket, not yet served.
    #[derive(Debug)]
    pub struct OwnerSocket {
        listener: UnixListener,
        rendezvous: Rendezvous,
    }

    /// The published socket's path and identity. Dropping it removes the
    /// socket if it is still the one this daemon bound.
    #[derive(Debug)]
    pub struct Rendezvous(Place);

    /// Where the socket is and which file it is: what the watch compares.
    #[derive(Clone, Debug)]
    pub struct Place {
        path: PathBuf,
        dir: PathBuf,
        ident: (u64, u64),
    }

    impl OwnerSocket {
        /// Dial any socket already at the plan's path, then bind and publish
        /// this daemon's. `network` is the network's name, for the refusal.
        ///
        /// # Errors
        ///
        /// - `config.socket.running`: another daemon of this account answers
        ///   there;
        /// - `config.socket.impostor`: the path holds something that is not
        ///   this account's socket;
        /// - `config.socket-dir.unusable`: the directory no longer passes
        ///   the walk's checks, or cannot hold a socket.
        pub fn bind(plan: &OwnerSocketPlan, network: &str) -> Result<Self, Diagnostic> {
            let unusable = |found: String| {
                Diagnostic::new(Code::SocketDirUnusable, Source::Machine)
                    .param("path", plan.dir.display().to_string())
                    .param("found", found)
            };
            assert_dir(&plan.dir).map_err(unusable)?;
            dial_existing(plan, network)?;
            let listener = UnixListener::bind(&plan.path).map_err(|e| match e.kind() {
                // A daemon that won the race between the dial and the bind.
                io::ErrorKind::AddrInUse => running(plan, network),
                _ => unusable(format!("it cannot hold a socket: {e}")),
            })?;
            // From here a failure must not leave the bound path behind.
            let rendezvous = Rendezvous::of(plan).map_err(unusable)?;
            // The directory is the containment; the socket's own mode keeps
            // it the owner's if the directory is ever widened.
            std::fs::set_permissions(&plan.path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| unusable(format!("the socket's mode cannot be set: {e}")))?;
            listener
                .set_nonblocking(true)
                .map_err(|e| unusable(format!("the socket cannot be made non-blocking: {e}")))?;
            Ok(Self {
                listener,
                rendezvous,
            })
        }

        /// The listener to serve, and the rendezvous to watch and remove.
        #[must_use]
        pub fn into_parts(self) -> (UnixListener, Rendezvous) {
            (self.listener, self.rendezvous)
        }

        /// Where the socket is.
        #[must_use]
        pub fn path(&self) -> &Path {
            self.rendezvous.path()
        }
    }

    impl Rendezvous {
        /// The socket just bound at the plan's path. If its identity cannot
        /// be read, the path is removed here: the bind made it, and nothing
        /// else has had a chance to.
        fn of(plan: &OwnerSocketPlan) -> Result<Self, String> {
            let meta = std::fs::symlink_metadata(&plan.path).map_err(|e| {
                if let Err(removal) = std::fs::remove_file(&plan.path) {
                    tracing::warn!(
                        "the owner's socket {} could not be removed: {removal}",
                        plan.path.display()
                    );
                }
                format!("the bound socket cannot be read back: {e}")
            })?;
            Ok(Self(Place {
                path: plan.path.clone(),
                dir: plan.dir.clone(),
                ident: (meta.dev(), meta.ino()),
            }))
        }

        /// Where the socket is.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.0.path
        }

        /// What the watch compares, without the removal on drop.
        #[must_use]
        pub fn place(&self) -> Place {
            self.0.clone()
        }

        /// See [`Place::check`].
        ///
        /// # Errors
        ///
        /// As [`Place::check`].
        pub fn check(&self) -> Result<(), String> {
            self.0.check()
        }
    }

    impl Place {
        /// Where the socket is.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// `Ok` while the socket this daemon bound is still at its path;
        /// otherwise what happened, in the operator's words.
        ///
        /// # Errors
        ///
        /// The socket or its directory was removed, or the path now holds
        /// something else.
        pub fn check(&self) -> Result<(), String> {
            match std::fs::symlink_metadata(&self.path) {
                Ok(meta) if (meta.dev(), meta.ino()) == self.ident => Ok(()),
                Ok(_) => Err("was replaced by something else".to_owned()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    if self.dir.is_dir() {
                        Err("was removed".to_owned())
                    } else {
                        Err("was removed with its directory".to_owned())
                    }
                }
                Err(e) => Err(format!("can no longer be read: {e}")),
            }
        }
    }

    impl Drop for Rendezvous {
        /// Remove the socket only if it is still the one this daemon bound.
        fn drop(&mut self) {
            if self.check().is_ok() {
                if let Err(e) = std::fs::remove_file(&self.0.path) {
                    tracing::warn!(
                        "the owner's socket {} could not be removed: {e}",
                        self.0.path.display()
                    );
                }
            }
        }
    }

    /// Watch the rendezvous every [`super::WATCH_EVERY`] until `stop`. When it
    /// goes, say why and call `gone`, which stops the daemon (`RPC_CHANNEL.md`
    /// §7.1: a run-as-me daemon's life is its rendezvous's).
    pub async fn watch(
        place: Place,
        gone: std::sync::Arc<dyn Fn() + Send + Sync>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut every = tokio::time::interval(super::WATCH_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _signal = stop.wait_for(|&stop| stop) => return,
                _tick = every.tick() => {}
            }
            if let Err(why) = place.check() {
                tracing::error!(
                    target: "global",
                    "the owner's socket {} {why}; the daemon stops, as a daemon run as its \
                     user does when that user's session ends",
                    place.path.display()
                );
                gone();
                return;
            }
        }
    }

    fn running(plan: &OwnerSocketPlan, network: &str) -> Diagnostic {
        Diagnostic::new(Code::SocketRunning, Source::Machine)
            .param("network", network)
            .param("instance", plan.instance_label())
            .param("path", plan.path.display().to_string())
    }

    /// The start-up dial (`RPC_CHANNEL.md` §7.1): an answer is a running
    /// daemon, a refusal is a stale socket to replace, and anything that is
    /// not this account's socket is reported and left alone.
    fn dial_existing(plan: &OwnerSocketPlan, network: &str) -> Result<(), Diagnostic> {
        let impostor = |found: String| {
            Diagnostic::new(Code::SocketImpostor, Source::Machine)
                .param("path", plan.path.display().to_string())
                .param("found", found)
        };
        let meta = match std::fs::symlink_metadata(&plan.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(impostor(format!("it cannot be read: {e}"))),
        };
        if !meta.file_type().is_socket() {
            return Err(impostor("a file that is not a socket".to_owned()));
        }
        if meta.uid() != plan.owner {
            return Err(impostor(format!("a socket owned by uid {}", meta.uid())));
        }
        match UnixStream::connect(&plan.path) {
            Ok(_answered) => Err(running(plan, network)),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                tracing::info!(
                    target: "global",
                    "replacing a stale owner's socket at {} (nothing answered)",
                    plan.path.display()
                );
                std::fs::remove_file(&plan.path)
                    .map_err(|e| impostor(format!("a stale socket that cannot be removed: {e}")))
            }
            Err(e) => Err(impostor(format!("a socket that cannot be dialled: {e}"))),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use shekyl_rpc_channel::Instance;

        fn plan_in(dir: &Path) -> OwnerSocketPlan {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            OwnerSocketPlan {
                path: dir.join("shekyl-0123456789abcdef01234567.sock"),
                dir: dir.to_path_buf(),
                owner: euid(),
                instance: Instance::Default,
            }
        }

        /// This test's account: the owner of a directory it just made.
        fn euid() -> u32 {
            let probe = tempfile::tempdir().unwrap();
            std::fs::metadata(probe.path()).unwrap().uid()
        }

        /// A second daemon of the same account, network and instance is
        /// refused while the first answers. Two arms hold this: the dial's
        /// answer, and the bind's address-in-use for a daemon that bound
        /// between the dial and the bind. Red edit (run): treat an answer as
        /// stale, and the bind's arm alone still refuses as running; map
        /// that arm to unusable as well, and this test fails.
        #[test]
        fn a_second_daemon_is_refused_while_the_first_answers() {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let first = OwnerSocket::bind(&plan, "regtest").unwrap();
            let refused = OwnerSocket::bind(&plan, "regtest").unwrap_err();
            assert_eq!(refused.code, Code::SocketRunning);
            assert!(refused.render().contains("regtest"));
            drop(first);
        }

        /// A socket nobody answers on is stale and is replaced.
        #[test]
        fn a_stale_socket_is_replaced() {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let stale = UnixListener::bind(&plan.path).unwrap();
            drop(stale);
            assert!(plan.path.exists(), "a dropped listener leaves its path");
            let bound = OwnerSocket::bind(&plan, "regtest").unwrap();
            assert_eq!(bound.path(), plan.path);
        }

        /// What is not a socket is reported and left alone.
        #[test]
        fn a_file_at_the_path_is_an_impostor_and_is_not_removed() {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            std::fs::write(&plan.path, b"not a socket").unwrap();
            let refused = OwnerSocket::bind(&plan, "regtest").unwrap_err();
            assert_eq!(refused.code, Code::SocketImpostor);
            assert_eq!(std::fs::read(&plan.path).unwrap(), b"not a socket");
        }

        /// A clean exit removes the socket this daemon bound, and the socket
        /// is the owner's alone.
        #[test]
        fn a_clean_exit_removes_the_socket_it_bound() {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let bound = OwnerSocket::bind(&plan, "regtest").unwrap();
            let mode = std::fs::metadata(&plan.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let (listener, rendezvous) = bound.into_parts();
            drop(rendezvous);
            assert!(!plan.path.exists());
            drop(listener);
        }

        /// A path someone replaced after the bind is not this daemon's to
        /// remove; the watch reports it as replaced.
        #[test]
        fn a_replaced_socket_is_reported_and_not_removed() {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let (_listener, rendezvous) = OwnerSocket::bind(&plan, "regtest").unwrap().into_parts();
            assert_eq!(rendezvous.check(), Ok(()));
            std::fs::remove_file(&plan.path).unwrap();
            assert_eq!(rendezvous.check(), Err("was removed".to_owned()));
            std::fs::write(&plan.path, b"someone else's").unwrap();
            assert_eq!(
                rendezvous.check(),
                Err("was replaced by something else".to_owned())
            );
            drop(rendezvous);
            assert_eq!(std::fs::read(&plan.path).unwrap(), b"someone else's");
        }

        /// The watch stops the daemon when the socket goes, and not before.
        /// Red edit: return from `watch` without checking and `gone` is
        /// never called.
        #[tokio::test]
        async fn the_watch_stops_the_daemon_when_the_socket_goes() {
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::Arc;

            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let (_listener, rendezvous) = OwnerSocket::bind(&plan, "regtest").unwrap().into_parts();
            let stopped = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stopped);
            let gone: Arc<dyn Fn() + Send + Sync> =
                Arc::new(move || flag.store(true, Ordering::SeqCst));
            let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let watching = tokio::spawn(watch(rendezvous.place(), gone, stop_rx));
            tokio::time::sleep(crate::owner::WATCH_EVERY * 2).await;
            assert!(!stopped.load(Ordering::SeqCst), "nothing went");
            std::fs::remove_file(&plan.path).unwrap();
            tokio::time::timeout(crate::owner::WATCH_EVERY * 3, watching)
                .await
                .expect("the watch notices within its period")
                .unwrap();
            assert!(stopped.load(Ordering::SeqCst));
        }

        /// A watch told to stop returns without calling `gone`, so the
        /// daemon's own removal at a clean exit is not read as a loss.
        #[tokio::test]
        async fn a_stopped_watch_does_not_report() {
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::Arc;

            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let (_listener, rendezvous) = OwnerSocket::bind(&plan, "regtest").unwrap().into_parts();
            let called = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&called);
            let gone: Arc<dyn Fn() + Send + Sync> =
                Arc::new(move || flag.store(true, Ordering::SeqCst));
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let watching = tokio::spawn(watch(rendezvous.place(), gone, stop_rx));
            stop_tx.send_replace(true);
            watching.await.unwrap();
            drop(rendezvous);
            tokio::time::sleep(crate::owner::WATCH_EVERY * 2).await;
            assert!(!called.load(Ordering::SeqCst));
        }

        /// The watch tells a removed directory from a removed socket.
        #[test]
        fn a_removed_directory_is_named() {
            let base = tempfile::tempdir().unwrap();
            let dir = base.path().join("session");
            std::fs::create_dir(&dir).unwrap();
            let plan = plan_in(&dir);
            let (_listener, rendezvous) = OwnerSocket::bind(&plan, "regtest").unwrap().into_parts();
            std::fs::remove_dir_all(&dir).unwrap();
            assert_eq!(
                rendezvous.check(),
                Err("was removed with its directory".to_owned())
            );
        }
    }
}
