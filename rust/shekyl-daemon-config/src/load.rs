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

use std::path::{Path, PathBuf};

use shekyl_options::{read_file, Cli, Diagnostic, Kind, Table, Value};

use crate::file::ConfigFile;
use crate::resolve::{choosers, chosen_network, resolve, Resolved};
use crate::sections::{build, DaemonConfig};
use crate::{file, paths, Network, Platform, RunMode, TABLE};

/// What the file step did with the configuration file. The startup line is
/// this match. A file that was opened, a missing default, and `none` are
/// three values, so a caller cannot pair a read path with the wrong choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFileFate {
    /// A file was opened. The command line named it, or it was the run
    /// mode's default and it was present. The startup line is
    /// `config-file={path} (cli)`.
    Read(PathBuf),
    /// The run mode's default path, and no file there. The startup line is
    /// `config-file=none-at:{path} (default)`.
    DefaultAbsent(PathBuf),
    /// `config-file none`. No file was opened, whatever is at the default
    /// path. The startup line is `config-file=none (cli)`.
    None,
}

/// The file the command line chose, before the opener runs.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ChosenFile {
    /// A file the command line named. It must exist.
    Named(PathBuf),
    /// The run mode's default for the network.
    Default(PathBuf),
    /// `config-file none`.
    None,
}

impl ChosenFile {
    /// The fate of this choice once the opener has run. `opened` is whether
    /// the opener returned a file. A named file that is absent never reaches
    /// here: the opener refuses it.
    fn fate(self, opened: bool) -> ConfigFileFate {
        match (self, opened) {
            (Self::None, _) => ConfigFileFate::None,
            (Self::Named(path) | Self::Default(path), true) => ConfigFileFate::Read(path),
            (Self::Default(path), false) => ConfigFileFate::DefaultAbsent(path),
            (Self::Named(path), false) => unreachable!(
                "a named configuration file that is absent is refused by the opener ({})",
                path.display()
            ),
        }
    }
}

/// The file step's fate, the resolved values and the sections.
pub struct Loaded {
    /// What the file step did. The announcements print this.
    pub config_file: ConfigFileFate,
    /// Every value and its source.
    pub resolved: Resolved,
    /// The typed configuration, by section.
    pub config: DaemonConfig,
}

/// What [`load`] makes of a command line once its file step is done: the
/// resolved values and the sections. [`Loaded`] is this and the file
/// step's fate.
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
    let config_file = choice.fate(opened.is_some());
    let AfterFile {
        resolved, config, ..
    } = after_file(cli, platform, opened)?;
    Ok(Loaded {
        config_file,
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
) -> Result<(ChosenFile, Option<ConfigFile>), Diagnostic> {
    let choice = choose_file(cli, platform)?;
    let opened = open_chosen(&choice, default_file, file::open)?;
    Ok((choice, opened))
}

/// Which configuration file `cli` chose: the one it names, none, or the run
/// mode's default for the chosen network. Reads nothing.
fn choose_file(cli: &Cli, platform: &Platform) -> Result<ChosenFile, Diagnostic> {
    let (network, mode) = choosers(cli);
    Ok(
        match cli.given.iter().find(|g| g.row.name == "config-file") {
            Some(g) => match &g.value {
                Value::Path(path) => ChosenFile::Named(path.clone()),
                Value::Word("none") => ChosenFile::None,
                Value::Word(other) => {
                    unreachable!("config-file admits one word, `none`, not {other}")
                }
                other => {
                    unreachable!("the config-file row's kind is a path or none, not {other:?}")
                }
            },
            None => ChosenFile::Default(paths::config_file_default(platform, mode, network)?),
        },
    )
}

/// Open the file `choice` names with `open` (production's is
/// [`file::open`], which takes the path and whether it was named). `None`
/// is no file and no call: the opener is never reached for it, whatever is
/// at the default path.
fn open_chosen(
    choice: &ChosenFile,
    default_file: DefaultFile,
    open: impl FnOnce(&Path, bool) -> Result<Option<ConfigFile>, Diagnostic>,
) -> Result<Option<ConfigFile>, Diagnostic> {
    match (choice, default_file) {
        (ChosenFile::None, _) | (ChosenFile::Default(_), DefaultFile::Unread) => Ok(None),
        (ChosenFile::Named(path), _) => open(path, true),
        (ChosenFile::Default(path), DefaultFile::Read) => open(path, false),
    }
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

/// Another binary's table, read as the daemon reads its own.
pub struct TableLoaded {
    /// The network the command line chose.
    pub network: Network,
    /// What the file step did. An announcement prints this.
    pub config_file: ConfigFileFate,
    /// Every value and its source.
    pub resolved: Resolved,
}

/// The one load for a binary with its own table and a per-account file
/// (`shekyl-rpc-tunnel`, `shekyl-cli`, `shekyl-wallet-rpc`): the file
/// `config-file` names, or `<account root>/<binary>-<network>.toml`; its
/// checks; a file holding a secret readable only by the permitted principals;
/// then the one precedence. The account's root is read only for that
/// default, so an account with no home runs when it names the file.
///
/// # Errors
///
/// The refusals, typed (IG-11); the caller renders them.
pub fn load_table(
    table: &Table,
    binary: &str,
    cli: Cli,
    platform: &Platform,
) -> Result<TableLoaded, Vec<Diagnostic>> {
    let network = chosen_network(&cli);
    let choice = match cli.given.iter().find(|g| g.row.name == "config-file") {
        Some(g) => match &g.value {
            Value::Path(path) => ChosenFile::Named(path.clone()),
            other => unreachable!("config-file is a path, not {other:?}"),
        },
        None => ChosenFile::Default(
            paths::root(platform, RunMode::User, "config-file")
                .map_err(|d| vec![d])?
                .join(format!("{binary}-{}.toml", network.name())),
        ),
    };
    let opened = open_chosen(&choice, DefaultFile::Read, file::open).map_err(|d| vec![d])?;
    let mut given = Vec::new();
    if let Some(config_file) = &opened {
        given = read_file(table, &config_file.path, &config_file.text)?;
        for g in given.iter().filter(|g| matches!(g.row.kind, Kind::Secret)) {
            config_file
                .secret_readable_only_by_permitted(g.row.name)
                .map_err(|d| vec![d])?;
        }
    }
    let config_file = choice.fate(opened.is_some());
    let resolved = resolve(table, network, cli, given)?;
    Ok(TableLoaded {
        network,
        config_file,
        resolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one load for a binary with its own table: its default file sits
    /// in the account's root under the binary's name and network, an absent
    /// default is the defaults, an account with no home must name the file,
    /// and a named file that is absent is refused. Red edit: drop the
    /// network from the default name, and the first assertion fails.
    #[test]
    fn load_table_finds_the_binarys_file_under_the_account_root() {
        use shekyl_options::{read_cli, Code};
        let cli = |list: &[&str]| {
            read_cli(&TABLE, list.iter().map(std::ffi::OsString::from)).expect("the arguments")
        };
        let home = Path::new("/nonexistent-shekyl-test-home");
        let platform = Platform {
            home: Some(home.to_path_buf()),
            ..Platform::default()
        };
        let loaded = load_table(
            &TABLE,
            "shekyl-x",
            cli(&["--network", "testnet"]),
            &platform,
        )
        .expect("an absent default file is the defaults");
        assert_eq!(loaded.network, Network::Testnet);
        let root = paths::root(&platform, RunMode::User, "config-file").expect("the root");
        assert_eq!(
            loaded.config_file,
            ConfigFileFate::DefaultAbsent(root.join("shekyl-x-testnet.toml"))
        );

        let no_home = Platform::default();
        let refused = load_table(&TABLE, "shekyl-x", cli(&[]), &no_home)
            .err()
            .expect("no root for the default path");
        assert_eq!(refused[0].code, Code::PathNoHome);

        let absent = if cfg!(windows) {
            r"C:\nonexistent-shekyl-test-home\named.toml"
        } else {
            "/nonexistent-shekyl-test-home/named.toml"
        };
        let named = cli(&["--config-file", absent]);
        assert!(
            load_table(&TABLE, "shekyl-x", named, &no_home).is_err(),
            "a named file that is absent is refused"
        );
    }

    /// **`config-file none` reaches no opener, whatever is at the default
    /// path.** The file step's opener is the seam: under `None` it is never
    /// called, read mode or not, while a default and a named choice each
    /// call it once with their own path. The host's `/etc` is never
    /// touched. Red edit: in `open_chosen`, open the run mode's default for
    /// `None` (the opener is called, and the test fails at its panic).
    #[test]
    fn config_file_none_reaches_no_opener() {
        let never = |path: &Path, _named: bool| -> Result<Option<ConfigFile>, Diagnostic> {
            panic!("`none` opened {}", path.display())
        };
        for mode in [DefaultFile::Read, DefaultFile::Unread] {
            assert!(open_chosen(&ChosenFile::None, mode, never)
                .expect("no file")
                .is_none());
        }

        let mut seen = Vec::new();
        let record = |path: &Path, named: bool| -> Result<Option<ConfigFile>, Diagnostic> {
            seen.push((path.to_path_buf(), named));
            Ok(None)
        };
        open_chosen(
            &ChosenFile::Default("/etc/shekyl/shekyld-regtest.toml".into()),
            DefaultFile::Read,
            record,
        )
        .unwrap();
        assert_eq!(
            seen,
            [(PathBuf::from("/etc/shekyl/shekyld-regtest.toml"), false)]
        );

        let mut seen = Vec::new();
        let record = |path: &Path, named: bool| -> Result<Option<ConfigFile>, Diagnostic> {
            seen.push((path.to_path_buf(), named));
            Ok(None)
        };
        open_chosen(
            &ChosenFile::Named("/srv/shekyld.toml".into()),
            DefaultFile::Unread,
            record,
        )
        .unwrap();
        assert_eq!(seen, [(PathBuf::from("/srv/shekyld.toml"), true)]);
    }
}
