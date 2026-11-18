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

use crate::file::ConfigFile;
use crate::resolve::{choosers, resolve, Resolved};
use crate::sections::{build, DaemonConfig};
use crate::{file, paths, Platform, TABLE};

/// The configuration file the command line chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFileChoice {
    /// A file the command line named. It must exist.
    Named(PathBuf),
    /// The run mode's default for the network. Absent, it means the
    /// defaults.
    Default(PathBuf),
    /// `config-file none`: no file is read, whatever exists at the default
    /// path. The command line and the defaults alone, as a program that
    /// starts its own daemon asks for: a node that means the same on every
    /// machine, whatever another install keeps in the shared file.
    None,
}

/// The file, the resolved values and the sections. `config_file` is the
/// choice the announcements name, including when the default file was
/// absent. `file_read` is set only when a file was read.
pub struct Loaded {
    /// The configuration file named, defaulted, or none.
    pub config_file: ConfigFileChoice,
    /// The file actually read, when one was.
    pub file_read: Option<PathBuf>,
    /// Every value and its source.
    pub resolved: Resolved,
    /// The typed configuration, by section.
    pub config: DaemonConfig,
}

/// What [`load`] makes of a command line once its file step is done: the
/// resolved values and the sections. [`Loaded`] is this and the path the
/// file step named.
pub struct AfterFile {
    /// The file the values were read from, when one was opened.
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
/// Two steps: the file ([`config_file`]) and everything after it
/// ([`after_file`]).
///
/// # Errors
///
/// The refusals, typed (IG-11); the caller renders them.
pub fn load(cli: Cli, platform: &Platform) -> Result<Loaded, Vec<Diagnostic>> {
    load_with(cli, platform, DefaultFile::Read)
}

/// [`load`], with the default file left unread: a file `cli` names is read
/// as [`load`] reads it, and when it names none the result is what a host
/// with no default file gives. On Unix the default path is the machine's
/// (`/etc/shekyl`), whatever `platform` says, so a test that starts the
/// daemon through its entry point loads with this and reads nothing from
/// the host it runs on.
///
/// # Errors
///
/// As [`load`].
pub fn load_default_file_unread(cli: Cli, platform: &Platform) -> Result<Loaded, Vec<Diagnostic>> {
    load_with(cli, platform, DefaultFile::Unread)
}

/// Whether the file step opens the default file when `cli` names none.
#[derive(Clone, Copy)]
enum DefaultFile {
    Read,
    Unread,
}

fn load_with(
    cli: Cli,
    platform: &Platform,
    default_file: DefaultFile,
) -> Result<Loaded, Vec<Diagnostic>> {
    let (choice, opened) = config_file(&cli, platform, default_file).map_err(|d| vec![d])?;
    let AfterFile {
        file_read,
        resolved,
        config,
    } = after_file(cli, platform, opened)?;
    Ok(Loaded {
        config_file: choice,
        file_read,
        resolved,
        config,
    })
}

/// [`load`]'s file step: the path `cli` names, the run mode's default for
/// the chosen network, or none, and that file opened and permission-checked.
/// The file is `None` when the default file is absent or left unread, and
/// when `cli` asks for no file; a named file that is absent is refused.
fn config_file(
    cli: &Cli,
    platform: &Platform,
    default_file: DefaultFile,
) -> Result<(ConfigFileChoice, Option<ConfigFile>), Diagnostic> {
    let (network, mode) = choosers(cli);
    let choice = match cli.given.iter().find(|g| g.row.name == "config-file") {
        Some(g) => match &g.value {
            Value::Path(p) => ConfigFileChoice::Named(p.clone()),
            // The row's one word (`Kind::PATH_OR_NONE`).
            Value::Word(_) => ConfigFileChoice::None,
            other => unreachable!("the config-file row's kind is a path or none, not {other:?}"),
        },
        None => ConfigFileChoice::Default(paths::config_file_default(platform, mode, network)?),
    };
    let opened = match (&choice, default_file) {
        (ConfigFileChoice::None, _) | (ConfigFileChoice::Default(_), DefaultFile::Unread) => None,
        (ConfigFileChoice::Named(path), _) => file::open(path, true)?,
        (ConfigFileChoice::Default(path), DefaultFile::Read) => file::open(path, false)?,
    };
    Ok((choice, opened))
}

/// Everything [`load`] does after its file step: read `opened`'s rows,
/// check that a file holding a secret is readable only by the permitted
/// principals, resolve, and build.
///
/// `opened` is `None` when no file was read, which is production's own
/// value on a host whose default file is absent. A test that is not about
/// reading a file calls this with `None`: it then takes every step `load`
/// takes, and reads nothing from the host it runs on. `choosers` and
/// [`crate::sections::build`](crate::sections) stay in this crate, so a
/// daemon configuration is not built by a second composition. Precedence
/// ([`crate::resolve::resolve`]) is public for a binary that resolves its
/// own table.
///
/// # Errors
///
/// The refusals, typed (IG-11); the caller renders them.
pub fn after_file(
    cli: Cli,
    platform: &Platform,
    opened: Option<ConfigFile>,
) -> Result<AfterFile, Vec<Diagnostic>> {
    let (network, mode) = choosers(&cli);
    let mut given = Vec::new();
    if let Some(config_file) = &opened {
        given = read_file(&TABLE, &config_file.path, &config_file.text)?;
        for g in given.iter().filter(|g| matches!(g.row.kind, Kind::Secret)) {
            config_file
                .secret_readable_only_by_permitted(g.row.name)
                .map_err(|d| vec![d])?;
        }
    }
    let mut resolved = resolve(&TABLE, network, cli, given)?;
    let file_read = opened.map(|f| f.path);
    let config = build(&mut resolved, network, mode, platform, file_read.as_deref())?;
    Ok(AfterFile {
        file_read,
        resolved,
        config,
    })
}
