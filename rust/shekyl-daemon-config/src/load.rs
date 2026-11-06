// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The command line through the sections: the file, its secret check, the
//! resolution and the build (`DAEMON_CONFIG_CUTOVER.md` §2.2 steps 2–4).
//!
//! One parse. The daemon's start and the snapshot a C++ test binary or the
//! blockchain importer asks for both come through [`load`] (rule 26 B2), so
//! what a test constructs is what the daemon would have constructed from the
//! same arguments. It takes no lock, writes no marker and starts no logging;
//! those are the daemon's steps after it.

use std::path::PathBuf;

use shekyl_options::{read_file, Cli, Diagnostic, Kind, Value};

use crate::resolve::{choosers, resolve, Resolved};
use crate::sections::{build, DaemonConfig};
use crate::{file, paths, Platform, TABLE};

/// The file, the resolved values and the sections. `config_path` is the
/// path the announcements name, including when the default file was absent.
/// `file_read` is set only when a file was read.
pub struct Loaded {
    /// The configuration file named or defaulted.
    pub config_path: PathBuf,
    /// The file actually read, when one was.
    pub file_read: Option<PathBuf>,
    /// Every value and its source.
    pub resolved: Resolved,
    /// The typed configuration, by section.
    pub config: DaemonConfig,
}

/// Read `cli`'s configuration file (the named one, or the run mode's
/// default for the chosen network), check that a file holding a secret is
/// readable only by the permitted principals, resolve, and build.
///
/// # Errors
///
/// The refusals, typed (IG-11); the caller renders them.
pub fn load(cli: Cli, platform: &Platform) -> Result<Loaded, Vec<Diagnostic>> {
    let (network, mode) = choosers(&cli);
    let (config_path, named) = match cli.given.iter().find(|g| g.row.name == "config-file") {
        Some(g) => match &g.value {
            Value::Path(p) => (p.clone(), true),
            other => unreachable!("the config-file row's kind is a path, not {other:?}"),
        },
        None => (
            paths::config_file_default(platform, mode, network).map_err(|d| vec![d])?,
            false,
        ),
    };
    let opened = file::open(&config_path, named).map_err(|d| vec![d])?;
    let mut given = Vec::new();
    if let Some(config_file) = &opened {
        given = read_file(&TABLE, &config_path, &config_file.text)?;
        for g in given.iter().filter(|g| matches!(g.row.kind, Kind::Secret)) {
            config_file
                .secret_readable_only_by_permitted(g.row.name)
                .map_err(|d| vec![d])?;
        }
    }
    let mut resolved = resolve(&TABLE, network, cli, given)?;
    let file_read = opened.as_ref().map(|f| f.path.clone());
    let config = build(&mut resolved, network, mode, platform, file_read.as_deref())?;
    Ok(Loaded {
        config_path,
        file_read,
        resolved,
        config,
    })
}
