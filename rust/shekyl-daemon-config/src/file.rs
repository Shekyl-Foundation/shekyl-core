// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The configuration file's checks (`DAEMON_CONFIG_CUTOVER.md` §2.4), in the
//! order that reads no value from an unsafe file:
//!
//! 1. open the file and judge the opened handle, so a symbolic link is
//!    judged by its target;
//! 2. refuse if the file, or any directory from it to the root, can be
//!    written outside the permitted principals;
//! 3. read and parse the whole file (the caller's);
//! 4. if the parsed file holds a secret, refuse if the file can be read
//!    outside the permitted principals (the caller asks
//!    [`ConfigFile::secret_readable_only_by_permitted`]);
//! 5. apply.
//!
//! The permitted principals are root and the daemon's account on Unix. On
//! Windows the check is an allowlist: SYSTEM, Administrators and the
//! daemon's own account, and any other access-control entry that grants
//! the right refuses, whatever it names.
//!
//! The rule is a pure function over what the file system reports (the Unix
//! rule takes its probe as an argument), so it is tested on described trees
//! and never on the machine the tests run on, whose directories are
//! whatever that machine's umask made them.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, Source};

/// An opened, permission-checked configuration file.
#[derive(Debug)]
pub struct ConfigFile {
    /// The path as given or derived.
    pub path: PathBuf,
    /// The whole text.
    pub text: String,
    file: File,
}

impl ConfigFile {
    /// Refuses if the file can be read outside the permitted principals;
    /// called once the parsed file is known to hold a secret, naming it.
    ///
    /// # Errors
    /// `config.file.secret-readable`, naming the principal found.
    pub fn secret_readable_only_by_permitted(&self, secret: &str) -> Result<(), Diagnostic> {
        if let Some(principal) = reader_outside_permitted(&self.file, &self.path) {
            return Err(Diagnostic::new(Code::FileSecretReadable, Source::Machine)
                .option(secret)
                .param("path", self.path.display().to_string())
                .param("principal", principal)
                .param("permitted", PERMITTED));
        }
        Ok(())
    }
}

/// Who may write the file and its directories, as a refusal names them.
#[cfg(unix)]
const PERMITTED: &str = "root and the daemon's account, with no group or other write bit";
#[cfg(windows)]
const PERMITTED: &str = "SYSTEM, Administrators and the daemon's account";

/// Opens and checks the file at `path`.
///
/// A missing file at the default path is `Ok(None)`: the defaults apply,
/// and the effective-configuration line says so. A missing file at a path
/// the operator named is refused (`config.file.missing`).
///
/// # Errors
/// `config.file.missing`, `config.file.unreadable` or
/// `config.file.permissions`, each naming the path.
pub fn open(path: &Path, named: bool) -> Result<Option<ConfigFile>, Diagnostic> {
    let shown = path.display().to_string();
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !named => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Diagnostic::new(Code::FileMissing, Source::Cli)
                .option("config-file")
                .param("path", shown));
        }
        Err(e) => {
            return Err(Diagnostic::new(Code::FileUnreadable, Source::Machine)
                .option("config-file")
                .param("path", shown)
                .param("error", e.to_string()));
        }
    };
    if let Some((where_, principal)) = writer_outside_permitted(&file, path) {
        return Err(Diagnostic::new(Code::FilePermissions, Source::Machine)
            .option("config-file")
            .param("path", where_)
            .param("principal", principal)
            .param("permitted", PERMITTED));
    }
    let mut text = String::new();
    if let Err(e) = file.read_to_string(&mut text) {
        return Err(Diagnostic::new(Code::FileUnreadable, Source::Machine)
            .option("config-file")
            .param("path", shown)
            .param("error", e.to_string()));
    }
    Ok(Some(ConfigFile {
        path: path.to_path_buf(),
        text,
        file,
    }))
}

/// Every directory from the file's parent to the root, nearest first.
fn ancestors(path: &Path) -> Vec<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    absolute
        .ancestors()
        .skip(1)
        .map(Path::to_path_buf)
        .collect()
}

#[cfg(unix)]
pub(crate) mod unix {
    //! The Unix rule: the owner is root or the daemon's account, and no
    //! group or other write bit is set, on the file and on every directory
    //! above it.

    use std::path::Path;

    /// What the rule reads of a file or directory.
    #[derive(Clone, Copy, Debug)]
    pub struct Entry {
        /// The owner.
        pub uid: u32,
        /// The group.
        pub gid: u32,
        /// The permission bits.
        pub mode: u32,
    }

    impl Entry {
        /// A principal outside the permitted set who can write.
        fn writer(self, me: u32) -> Option<String> {
            if self.uid != 0 && self.uid != me {
                return Some(format!("its owner, uid {}", self.uid));
            }
            if self.mode & 0o002 != 0 {
                return Some("every account (world-writable)".to_owned());
            }
            if self.mode & 0o020 != 0 {
                return Some(format!("its group, gid {}", self.gid));
            }
            None
        }

        /// A principal outside the permitted set who can read.
        pub fn reader(self) -> Option<String> {
            if self.mode & 0o004 != 0 {
                return Some("every account (world-readable)".to_owned());
            }
            if self.mode & 0o040 != 0 {
                return Some(format!("its group, gid {}", self.gid));
            }
            None
        }
    }

    /// The first place a principal outside the permitted set can write,
    /// with who: the file (`file`, as its open handle reports it) or one of
    /// `dirs` (each as `probe` reports it, nearest first). A directory the
    /// probe cannot read is refused as unknown.
    pub fn writer_outside_permitted(
        me: u32,
        file: Entry,
        file_shown: &Path,
        dirs: &[std::path::PathBuf],
        probe: &dyn Fn(&Path) -> Option<Entry>,
    ) -> Option<(String, String)> {
        if let Some(who) = file.writer(me) {
            return Some((file_shown.display().to_string(), who));
        }
        for dir in dirs {
            let Some(entry) = probe(dir) else {
                return Some((dir.display().to_string(), "unknown (unreadable)".to_owned()));
            };
            if let Some(who) = entry.writer(me) {
                return Some((dir.display().to_string(), who));
            }
        }
        None
    }

    /// What the file system reports, in the rule's terms.
    pub fn entry_of(meta: &std::fs::Metadata) -> Entry {
        use std::os::unix::fs::MetadataExt;
        Entry {
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        }
    }
}

#[cfg(unix)]
fn writer_outside_permitted(file: &File, path: &Path) -> Option<(String, String)> {
    let me = rustix::process::geteuid().as_raw();
    let meta = file.metadata().ok()?;
    unix::writer_outside_permitted(me, unix::entry_of(&meta), path, &ancestors(path), &|dir| {
        std::fs::metadata(dir).ok().as_ref().map(unix::entry_of)
    })
}

#[cfg(unix)]
fn reader_outside_permitted(file: &File, _path: &Path) -> Option<String> {
    file.metadata().ok().map(|m| unix::entry_of(&m).reader())?
}

#[cfg(windows)]
fn writer_outside_permitted(_file: &File, path: &Path) -> Option<(String, String)> {
    use shekyl_win_sec::dacl::{write_grantees, Grantee};
    let judge = |shown: &Path| -> Option<(String, String)> {
        match write_grantees(shown) {
            Ok(grantees) => grantees.into_iter().find_map(|g| match g {
                Grantee::Permitted => None,
                Grantee::Other(sid) => Some((shown.display().to_string(), sid)),
            }),
            Err(e) => Some((shown.display().to_string(), format!("unknown: {e}"))),
        }
    };
    if let Some(found) = judge(path) {
        return Some(found);
    }
    ancestors(path).into_iter().find_map(|dir| judge(&dir))
}

#[cfg(windows)]
fn reader_outside_permitted(_file: &File, path: &Path) -> Option<String> {
    use shekyl_win_sec::dacl::{read_grantees, Grantee};
    match read_grantees(path) {
        Ok(grantees) => grantees.into_iter().find_map(|g| match g {
            Grantee::Permitted => None,
            Grantee::Other(sid) => Some(sid),
        }),
        Err(e) => Some(format!("unknown: {e}")),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::{writer_outside_permitted, Entry};
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    const ME: u32 = 1000;

    const fn entry(uid: u32, gid: u32, mode: u32) -> Entry {
        Entry { uid, gid, mode }
    }

    const CLEAN: &[(&str, Entry)] = &[
        ("/", entry(0, 0, 0o40755)),
        ("/etc", entry(0, 0, 0o40755)),
        ("/etc/shekyl", entry(0, 0, 0o40755)),
    ];

    /// Judges a file at `/etc/shekyl/shekyld-mainnet.toml` over a described
    /// tree.
    fn judge(file: Entry, entries: &[(&str, Entry)]) -> Option<(String, String)> {
        let map: BTreeMap<PathBuf, Entry> = entries
            .iter()
            .map(|(p, e)| (PathBuf::from(p), *e))
            .collect();
        let dirs = vec![
            PathBuf::from("/etc/shekyl"),
            PathBuf::from("/etc"),
            PathBuf::from("/"),
        ];
        writer_outside_permitted(
            ME,
            file,
            Path::new("/etc/shekyl/shekyld-mainnet.toml"),
            &dirs,
            &|p| map.get(p).copied(),
        )
    }

    #[test]
    fn a_root_owned_tree_and_a_private_file_are_permitted() {
        assert_eq!(judge(entry(0, 0, 0o100644), CLEAN), None);
        assert_eq!(judge(entry(ME, ME, 0o100600), CLEAN), None);
        assert_eq!(
            judge(entry(ME, ME, 0o100644), CLEAN),
            None,
            "world-readable is not world-writable"
        );
    }

    #[test]
    fn a_writable_file_or_directory_is_refused_naming_the_place_and_the_principal() {
        let file = "/etc/shekyl/shekyld-mainnet.toml";
        let found = judge(entry(ME, ME, 0o100602), CLEAN).unwrap();
        assert_eq!(
            found,
            (file.to_owned(), "every account (world-writable)".to_owned())
        );
        let found = judge(entry(ME, 7, 0o100620), CLEAN).unwrap();
        assert_eq!(found, (file.to_owned(), "its group, gid 7".to_owned()));
        let found = judge(entry(4242, 4242, 0o100600), CLEAN).unwrap();
        assert_eq!(found, (file.to_owned(), "its owner, uid 4242".to_owned()));
        let group_dir = &[
            ("/", entry(0, 0, 0o40755)),
            ("/etc", entry(0, 0, 0o40755)),
            ("/etc/shekyl", entry(0, 50, 0o40775)),
        ];
        let found = judge(entry(0, 0, 0o100644), group_dir).unwrap();
        assert_eq!(
            found,
            ("/etc/shekyl".to_owned(), "its group, gid 50".to_owned())
        );
        let sticky = &[
            ("/", entry(0, 0, 0o40755)),
            ("/etc", entry(0, 0, 0o41777)),
            ("/etc/shekyl", entry(ME, ME, 0o40700)),
        ];
        let found = judge(entry(ME, ME, 0o100600), sticky).unwrap();
        assert_eq!(
            found,
            (
                "/etc".to_owned(),
                "every account (world-writable)".to_owned()
            )
        );
    }

    #[test]
    fn an_unreadable_directory_is_refused_rather_than_skipped() {
        let partial = &[("/", entry(0, 0, 0o40755))];
        let (place, who) = judge(entry(0, 0, 0o100644), partial).unwrap();
        assert_eq!(place, "/etc/shekyl");
        assert!(who.contains("unreadable"));
    }

    #[test]
    fn a_secret_is_readable_only_by_owner_and_root() {
        assert_eq!(entry(ME, ME, 0o100600).reader(), None);
        assert_eq!(
            entry(ME, 9, 0o100640).reader().as_deref(),
            Some("its group, gid 9")
        );
        assert_eq!(
            entry(ME, ME, 0o100644).reader().as_deref(),
            Some("every account (world-readable)")
        );
    }

    /// Real files: `open` judges the handle, and the file's own mode is
    /// judged before any directory, so these hold whatever the machine's
    /// directories look like.
    #[test]
    fn a_missing_default_file_is_the_defaults_and_a_missing_named_file_refuses() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("shekyld-mainnet.toml");
        assert!(open(&p, false).unwrap().is_none());
        let e = open(&p, true).unwrap_err();
        assert_eq!(e.code, Code::FileMissing);
        assert!(e.render().contains("shekyld-mainnet.toml"));
    }

    /// A file the account cannot open is refused before any directory is
    /// judged, naming the file and the operating system's error.
    #[test]
    fn a_file_that_cannot_be_opened_is_unreadable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.toml");
        std::fs::write(&p, "").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = open(&p, true).unwrap_err();
        assert_eq!(e.code, Code::FileUnreadable, "{e}");
        assert_eq!(e.get("path"), Some(p.display().to_string().as_str()));
        assert!(e.get("error").is_some_and(|m| !m.is_empty()));
    }

    #[test]
    fn a_world_writable_file_is_refused_at_the_file_itself() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.toml");
        std::fs::write(&p, "").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o602)).unwrap();
        let e = open(&p, true).unwrap_err();
        assert_eq!(e.code, Code::FilePermissions);
        assert_eq!(e.get("path"), Some(p.display().to_string().as_str()));
        assert_eq!(e.get("principal"), Some("every account (world-writable)"));
    }

    #[test]
    fn a_symbolic_link_is_judged_by_its_target() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("real.toml");
        std::fs::write(&target, "").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o602)).unwrap();
        let link = d.path().join("c.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = open(&link, true).unwrap_err();
        assert_eq!(e.code, Code::FilePermissions);
        assert_eq!(e.get("principal"), Some("every account (world-writable)"));
    }
}
