// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a boot keeps outside its per-boot directory: the public directory
//! cache, and, for a persistent onion, Tor's guard `state`.
//!
//! One install copies both into a fresh directory. One write-back, after a
//! clean stop of a Tor that bootstrapped, puts both back. A respawn stop and
//! the daemon's stop are that same write-back (`TSR-Q8`, `TSR-Q2`).

use std::io;
use std::path::Path;

use shekyl_tor_control_client::directory_cache::{self, DirectoryCache, GuardState};

use super::CacheSave;
use crate::data_dir::CACHE_DIR_NAME;

/// What a clean stop wrote back. `guards` is `None` for a per-boot onion,
/// which keeps none.
#[derive(Debug)]
pub struct KeptSave {
    /// The public directory cache (`TSR-Q8`).
    pub cache: CacheSave,
    /// A persistent onion's guards (`TSR-Q2`). `None` when this boot has none.
    pub guards: Option<CacheSave>,
}

/// Copy the directory cache, then a persistent onion's guards, into a fresh
/// `data_dir`. A kept directory already holds both, so a respawn does not
/// call this.
///
/// The names the cache copied are returned. Guards absent, or not yet kept,
/// copy nothing and are not an error.
///
/// # Errors
///
/// A write into `data_dir` failed.
pub(super) fn install_into(
    cache_dir: &Path,
    data_dir: &Path,
    guards: Option<&GuardState>,
) -> io::Result<Vec<&'static str>> {
    let copied = directory_cache::install_into(cache_dir, data_dir)?;
    if let Some(guards) = guards {
        guards.copy_into(data_dir)?;
    }
    Ok(copied)
}

/// Write the cache and the guards back from `data_dir`. Each destination is
/// judged on its own: a cache with no parent is not due, and the guards still
/// try their own directory. A failure of one leaves the other's previous files.
pub(super) fn save_from(data_dir: &Path, guards: Option<&GuardState>) -> KeptSave {
    let cache = match data_dir.parent() {
        Some(parent) => {
            let cache = DirectoryCache::at(parent.join(CACHE_DIR_NAME));
            outcome(save_cache(&cache, data_dir))
        }
        None => CacheSave::NotDue,
    };
    let guards = guards.map(|guards| outcome(guards.save_from(data_dir)));
    KeptSave { cache, guards }
}

fn save_cache(cache: &DirectoryCache, data_dir: &Path) -> io::Result<()> {
    cache.ensure()?;
    cache.save_from(data_dir)
}

fn outcome(saved: io::Result<()>) -> CacheSave {
    match saved {
        Ok(()) => CacheSave::Saved,
        Err(error) => CacheSave::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    /// A directory removed when the test ends, including on a panic.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "shekyl-kept-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("the clock is after the unix epoch")
                    .as_nanos()
            ));
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_clean_stop_writes_the_cache_and_the_guards_from_one_directory() {
        let scratch = Scratch::new();
        let root = scratch.path();
        let data = root.join("ephemeral-tor-boot");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("cached-certs"), b"certs").unwrap();
        std::fs::write(data.join("state"), b"guards").unwrap();
        let guards = GuardState::for_onion(root, "one");

        let saved = save_from(&data, Some(&guards));
        assert!(matches!(saved.cache, CacheSave::Saved), "{:?}", saved.cache);
        assert!(matches!(saved.guards, Some(CacheSave::Saved)));
        assert_eq!(
            std::fs::read(root.join(CACHE_DIR_NAME).join("cached-certs")).unwrap(),
            b"certs"
        );
        assert_eq!(
            std::fs::read(guards.path().join("state")).unwrap(),
            b"guards"
        );

        let per_boot = save_from(&data, None);
        assert!(matches!(per_boot.cache, CacheSave::Saved));
        assert!(per_boot.guards.is_none());

        let fresh = root.join("ephemeral-tor-next");
        std::fs::create_dir_all(&fresh).unwrap();
        let copied = install_into(&root.join(CACHE_DIR_NAME), &fresh, Some(&guards)).unwrap();
        assert_eq!(copied, ["cached-certs"]);
        assert_eq!(std::fs::read(fresh.join("state")).unwrap(), b"guards");

        // A path with no parent has nowhere to put the cache. The guards,
        // when this boot has none, stay absent.
        let orphan = save_from(Path::new(""), None);
        assert!(matches!(orphan.cache, CacheSave::NotDue));
        assert!(orphan.guards.is_none());
    }
}
