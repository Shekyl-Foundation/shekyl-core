// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Spawning one incarnation and keeping its data directory across a respawn.
//!
//! A failed spawn returns the directory. [`DaemonTorControl::stop_for_respawn`]
//! stops the child and returns it too. Dropping the directory wipes it, which
//! is the daemon's stop, not a respawn (`TSR-Q1`).

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use kameo::actor::Spawn;
use tokio::sync::{oneshot, watch};

use shekyl_tor_control_client::binary::VerifiedTorBinary;
use shekyl_tor_control_client::control::{
    BootstrapReadiness, Command, DiskWrites, EventSink, ManagedTor, SocksPort, TorControlClient,
    TorControlClientConfig, TorLaunch,
};
use shekyl_tor_control_client::directory_cache;

use super::{DaemonTorConfig, DaemonTorControl, DaemonTorStartError};
use crate::data_dir::{EphemeralDataDir, CACHE_DIR_NAME};

/// A data directory kept across a respawn. Dropping it wipes the directory.
pub struct KeptDataDir {
    dir: EphemeralDataDir,
}

impl KeptDataDir {
    /// The directory tor uses as `DataDirectory`.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// A spawn that did not come up, with the directory still on disk.
pub struct LaunchFailure {
    /// Why it did not come up.
    pub error: DaemonTorStartError,
    /// The directory. Drop it to wipe, or spawn into it again.
    pub directory: KeptDataDir,
}

/// Why [`DaemonTorControl::spawn_keeping`] failed.
pub enum SpawnError {
    /// The directory was not created.
    DataDir(io::Error),
    /// Tor did not answer. The directory is still on disk.
    Launch(LaunchFailure),
}

impl DaemonTorControl {
    /// Spawn tor and return when `GETINFO version` answers. Bootstrap is
    /// not a gate.
    pub async fn spawn_keeping(config: DaemonTorConfig) -> Result<Self, SpawnError> {
        let data_dir =
            EphemeralDataDir::create_under(&config.data_dir_parent).map_err(SpawnError::DataDir)?;
        let kept = KeptDataDir { dir: data_dir };
        Self::spawn_in(kept, config, true)
            .await
            .map_err(SpawnError::Launch)
    }

    /// [`Self::spawn_keeping`], wiping the directory when the spawn fails.
    pub async fn launch(config: DaemonTorConfig) -> Result<Self, DaemonTorStartError> {
        match Self::spawn_keeping(config).await {
            Ok(up) => Ok(up),
            Err(SpawnError::DataDir(error)) => Err(DaemonTorStartError::DataDir(error)),
            Err(SpawnError::Launch(failure)) => Err(failure.error),
        }
    }

    /// Spawn into a directory a previous incarnation kept. The cache is not
    /// copied again.
    pub async fn spawn_into(
        directory: KeptDataDir,
        tor_binary: VerifiedTorBinary,
        events: EventSink,
        reply_deadline: Duration,
    ) -> Result<Self, LaunchFailure> {
        let parent = directory
            .path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        Self::spawn_in(
            directory,
            DaemonTorConfig {
                tor_binary,
                data_dir_parent: parent,
                events,
                reply_deadline,
            },
            false,
        )
        .await
    }

    async fn spawn_in(
        directory: KeptDataDir,
        config: DaemonTorConfig,
        install_cache: bool,
    ) -> Result<Self, LaunchFailure> {
        let DaemonTorConfig {
            tor_binary,
            events,
            reply_deadline,
            ..
        } = config;
        let copied = if install_cache {
            let cache_dir = directory
                .path()
                .parent()
                .map(|parent| parent.join(CACHE_DIR_NAME))
                .unwrap_or_default();
            let data_path = directory.path().to_path_buf();
            match tokio::task::spawn_blocking(move || {
                directory_cache::install_into(&cache_dir, &data_path)
            })
            .await
            {
                Ok(Ok(copied)) => copied,
                Ok(Err(error)) => {
                    return Err(LaunchFailure {
                        error: DaemonTorStartError::DataDir(error),
                        directory,
                    })
                }
                Err(join) => {
                    return Err(LaunchFailure {
                        error: DaemonTorStartError::DataDir(io::Error::other(join)),
                        directory,
                    })
                }
            }
        } else {
            Vec::new()
        };
        let (exit_tx, exit_rx) = oneshot::channel();
        let (exit_watch_tx, exit_watch) = watch::channel(None);
        tokio::spawn(async move {
            if let Ok(exit) = exit_rx.await {
                let _sent = exit_watch_tx.send(Some(exit));
            }
        });
        let (readiness, ready) = BootstrapReadiness::new();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary,
                data_dir: directory.path().to_path_buf(),
                socks_port: SocksPort::Auto,
                disable_network: false,
                disk_writes: DiskWrites::Prompt,
                exit_observer: Some(exit_tx),
            }),
            events,
            readiness,
        });
        let handle = Self {
            actor,
            exit_watch,
            socks_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            reply_deadline,
            stopping: Arc::new(AtomicBool::new(false)),
            copied,
            bootstrapped: false,
            ready,
            data_dir: Some(directory.dir),
        };
        if let Err(error) = handle
            .ask_bounded(Command::GetInfo(vec!["version".to_owned()]), reply_deadline)
            .await
        {
            let directory = handle.abandon().await;
            return Err(LaunchFailure { error, directory });
        }
        Ok(handle)
    }

    /// Stop the child and keep the directory for the next spawn.
    pub async fn stop_for_respawn(mut self) -> KeptDataDir {
        let exit = self.stop_actor().await;
        self.save_if_clean(&exit).await;
        KeptDataDir {
            dir: self.data_dir.take().expect("data directory"),
        }
    }

    async fn abandon(mut self) -> KeptDataDir {
        let _exit = self.stop_actor().await;
        KeptDataDir {
            dir: self.data_dir.take().expect("data directory"),
        }
    }
}
