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
//! The permitted principals are root and the daemon's account on Unix, and
//! for reading a file that holds a secret also the daemon's group (Rick,
//! 2026-10-19), when the daemon's account is that group's only member
//! (Rick, 2026-10-22): a service install keeps the file `root:<daemon
//! group>` `0640` under `/etc/shekyl` `root:root` `0755`, written by root
//! only and read by root and the daemon; a per-account install keeps it
//! owner-only `0600`. One file, no separate secrets file. The mode bits are
//! that whole policy only when the access-control list names nobody else
//! and the group holds nobody else (its member list, and every account
//! whose primary group it is); a list or a membership that does, or one
//! that cannot be read, refuses.
//!
//! On Windows the check is an allowlist: SYSTEM, Administrators,
//! TrustedInstaller (the servicing account a default `C:\` grants full
//! control to) and the daemon's own account, and any other access-control
//! entry that grants the right refuses, whatever it names.
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
                .param("permitted", READ_PERMITTED));
        }
        Ok(())
    }
}

/// Who may write the file and its directories, as a refusal names them.
#[cfg(unix)]
const PERMITTED: &str = "root and the daemon's account, with no group or other write bit";
#[cfg(windows)]
const PERMITTED: &str = "SYSTEM, Administrators, TrustedInstaller and the daemon's account";

/// Who may read a file that holds a secret, as a refusal names them.
#[cfg(unix)]
const READ_PERMITTED: &str = "root, the daemon's account and the daemon's group when that \
    account is its only member (root:<daemon group> 0640 for a service, or 0600 owned by the \
    daemon's account)";
#[cfg(windows)]
const READ_PERMITTED: &str = PERMITTED;

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
    //! above it. A file that holds a secret is also refused when its
    //! access-control list names a reader the mode bits do not, or when
    //! the group that can read it holds an account besides the daemon's.

    use std::path::Path;

    pub(crate) use crate::acl::AclProbe;
    pub(crate) use crate::group::Membership;

    /// A probe that could not be read. The same words name an unreadable
    /// directory, a file whose metadata could not be read, and a list that
    /// could not be read: the check refuses, it does not guess.
    pub(crate) const UNREADABLE: &str = "unknown (unreadable)";

    /// The principal a secret-read refusal names for [`AclProbe::Named`].
    pub(crate) const ACL_NAMED: &str = "a named entry on its access-control list";

    /// Access-class bits of a mode. The file type lives in the high bits and
    /// is not part of either rule.
    const OTHER_READ: u32 = 0o004;
    const OTHER_WRITE: u32 = 0o002;
    const GROUP_READ: u32 = 0o040;
    const GROUP_WRITE: u32 = 0o020;

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
            if self.mode & OTHER_WRITE != 0 {
                return Some("every account (world-writable)".to_owned());
            }
            if self.mode & GROUP_WRITE != 0 {
                return Some(format!("its group, gid {}", self.gid));
            }
            None
        }

        /// A principal outside the permitted set who can read, from the mode
        /// bits alone: every account, or a group other than the daemon's own
        /// (`my_group`, the daemon's effective group).
        ///
        /// The owner is root or the daemon's account, which the write check
        /// has already required. A secret file is judged by [`secret_reader`],
        /// which also takes the access-control list and the group's
        /// membership: these bits are the whole read policy only when that
        /// list is [`AclProbe::ModeOnly`] and the group is the daemon alone.
        pub fn reader(self, my_group: u32) -> Option<String> {
            if self.mode & OTHER_READ != 0 {
                return Some("every account (world-readable)".to_owned());
            }
            if self.mode & GROUP_READ != 0 && self.gid != my_group {
                return Some(format!("its group, gid {}", self.gid));
            }
            None
        }

        /// Whether the daemon's own group can read: the one case the
        /// group's membership decides.
        fn readable_by_my_group(self, my_group: u32) -> bool {
            self.mode & GROUP_READ != 0 && self.gid == my_group
        }
    }

    /// Who outside the permitted set can read a secret file: the mode bits,
    /// unless the access-control list names someone else or could not be
    /// read; and when the daemon's own group can read, `members` is asked
    /// who else is in it (Rick, 2026-10-22). The membership is read only
    /// then, so a private file never consults it.
    pub(crate) fn secret_reader(
        entry: Entry,
        my_group: u32,
        acl: AclProbe,
        members: &dyn Fn() -> Result<Membership, String>,
    ) -> Option<String> {
        match acl {
            AclProbe::Named => return Some(ACL_NAMED.to_owned()),
            AclProbe::Unreadable => return Some(UNREADABLE.to_owned()),
            AclProbe::ModeOnly => {}
        }
        if let Some(who) = entry.reader(my_group) {
            return Some(who);
        }
        if !entry.readable_by_my_group(my_group) {
            return None;
        }
        match members() {
            Ok(Membership::Sole) => None,
            Ok(Membership::Listed(name)) => Some(format!(
                "its group, gid {}, which lists the account {name}",
                entry.gid
            )),
            Ok(Membership::Primary(name)) => Some(format!(
                "its group, gid {}, which is the primary group of the account {name}",
                entry.gid
            )),
            Err(why) => Some(format!(
                "its group, gid {}, whose membership could not be read ({why})",
                entry.gid
            )),
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
                return Some((dir.display().to_string(), UNREADABLE.to_owned()));
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
    let Ok(meta) = file.metadata() else {
        return Some((path.display().to_string(), unix::UNREADABLE.to_owned()));
    };
    unix::writer_outside_permitted(me, unix::entry_of(&meta), path, &ancestors(path), &|dir| {
        std::fs::metadata(dir).ok().as_ref().map(unix::entry_of)
    })
}

#[cfg(unix)]
fn reader_outside_permitted(file: &File, _path: &Path) -> Option<String> {
    let me = rustix::process::geteuid().as_raw();
    let my_group = rustix::process::getegid().as_raw();
    let Ok(meta) = file.metadata() else {
        return Some(unix::UNREADABLE.to_owned());
    };
    unix::secret_reader(
        unix::entry_of(&meta),
        my_group,
        crate::acl::probe(file),
        &|| crate::group::members_besides_me(my_group, me),
    )
}

#[cfg(windows)]
fn writer_outside_permitted(_file: &File, path: &Path) -> Option<(String, String)> {
    use shekyl_win_sec::dacl::{directory_write_grantees, write_grantees, DaclError, Grantee};
    let judge =
        |shown: &Path, grantees: Result<Vec<Grantee>, DaclError>| -> Option<(String, String)> {
            match grantees {
                Ok(grantees) => grantees.into_iter().find_map(|g| match g {
                    Grantee::Permitted => None,
                    Grantee::Other(sid) => Some((shown.display().to_string(), sid)),
                }),
                Err(e) => Some((shown.display().to_string(), format!("unknown: {e}"))),
            }
        };
    // The file by every write right; a directory above it by the rights
    // that replace or remove an entry (a default `C:\` lets Users add a
    // subdirectory, which changes no file below it).
    if let Some(found) = judge(path, write_grantees(path)) {
        return Some(found);
    }
    ancestors(path)
        .into_iter()
        .find_map(|dir| judge(&dir, directory_write_grantees(&dir)))
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
    use super::unix::{
        secret_reader, writer_outside_permitted, AclProbe, Entry, Membership, ACL_NAMED, UNREADABLE,
    };
    use super::*;
    use crate::group::AccountName;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    const ME: u32 = 1000;

    fn account_name(bytes: &[u8]) -> AccountName {
        AccountName::new(bytes).expect("a test name is non-empty")
    }

    /// `S_IFREG` and `S_IFDIR`. The rules never read the file type; the
    /// described trees carry it so a mode still looks like a mode.
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    /// `S_ISVTX`, the restricted-deletion bit on a directory.
    const S_ISVTX: u32 = 0o1000;

    const fn reg(perm: u32) -> u32 {
        S_IFREG | perm
    }

    const fn dir(perm: u32) -> u32 {
        S_IFDIR | perm
    }

    const fn entry(uid: u32, gid: u32, mode: u32) -> Entry {
        Entry { uid, gid, mode }
    }

    const CLEAN: &[(&str, Entry)] = &[
        ("/", entry(0, 0, dir(0o755))),
        ("/etc", entry(0, 0, dir(0o755))),
        ("/etc/shekyl", entry(0, 0, dir(0o755))),
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
        assert_eq!(judge(entry(0, 0, reg(0o644)), CLEAN), None);
        assert_eq!(judge(entry(ME, ME, reg(0o600)), CLEAN), None);
        assert_eq!(
            judge(entry(ME, ME, reg(0o644)), CLEAN),
            None,
            "world-readable is not world-writable"
        );
    }

    #[test]
    fn a_writable_file_or_directory_is_refused_naming_the_place_and_the_principal() {
        let file = "/etc/shekyl/shekyld-mainnet.toml";
        let found = judge(entry(ME, ME, reg(0o602)), CLEAN).unwrap();
        assert_eq!(
            found,
            (file.to_owned(), "every account (world-writable)".to_owned())
        );
        let found = judge(entry(ME, 7, reg(0o620)), CLEAN).unwrap();
        assert_eq!(found, (file.to_owned(), "its group, gid 7".to_owned()));
        let found = judge(entry(4242, 4242, reg(0o600)), CLEAN).unwrap();
        assert_eq!(found, (file.to_owned(), "its owner, uid 4242".to_owned()));
        let group_dir = &[
            ("/", entry(0, 0, dir(0o755))),
            ("/etc", entry(0, 0, dir(0o755))),
            ("/etc/shekyl", entry(0, 50, dir(0o775))),
        ];
        let found = judge(entry(0, 0, reg(0o644)), group_dir).unwrap();
        assert_eq!(
            found,
            ("/etc/shekyl".to_owned(), "its group, gid 50".to_owned())
        );
        let sticky = &[
            ("/", entry(0, 0, dir(0o755))),
            ("/etc", entry(0, 0, dir(S_ISVTX | 0o1777))),
            ("/etc/shekyl", entry(ME, ME, dir(0o700))),
        ];
        let found = judge(entry(ME, ME, reg(0o600)), sticky).unwrap();
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
        let partial = &[("/", entry(0, 0, dir(0o755)))];
        let (place, who) = judge(entry(0, 0, reg(0o644)), partial).unwrap();
        assert_eq!(place, "/etc/shekyl");
        assert!(who.contains("unreadable"));
    }

    #[test]
    fn a_secret_is_readable_by_root_the_daemon_and_its_group_only() {
        // The daemon's group in these cases.
        const MINE: u32 = 50;
        // Per-account: owner-only.
        assert_eq!(entry(ME, ME, reg(0o600)).reader(MINE), None);
        // Service: root:<daemon group> 0640.
        assert_eq!(entry(0, MINE, reg(0o640)).reader(MINE), None);
        // Another group can read: refused.
        assert_eq!(
            entry(0, 9, reg(0o640)).reader(MINE).as_deref(),
            Some("its group, gid 9")
        );
        // Every account can read: refused, whatever the group.
        assert_eq!(
            entry(0, MINE, reg(0o644)).reader(MINE).as_deref(),
            Some("every account (world-readable)")
        );
    }

    /// The mode bits are the whole secret-read policy only when the list adds
    /// no principal. A named entry refuses a file the mode would allow, and a
    /// list that cannot be read refuses too.
    #[test]
    fn a_named_access_list_entry_is_outside_the_mode_bits() {
        const MINE: u32 = 50;
        let private = entry(ME, ME, reg(0o600));
        let service = entry(0, MINE, reg(0o640));
        let sole = || Ok(Membership::Sole);
        assert_eq!(
            secret_reader(private, MINE, AclProbe::ModeOnly, &sole),
            None
        );
        assert_eq!(
            secret_reader(service, MINE, AclProbe::ModeOnly, &sole),
            None
        );
        assert_eq!(
            secret_reader(service, MINE, AclProbe::Named, &sole).as_deref(),
            Some(ACL_NAMED)
        );
        assert_eq!(
            secret_reader(private, MINE, AclProbe::Unreadable, &sole).as_deref(),
            Some(UNREADABLE)
        );
    }

    /// The daemon's group may read a secret only while the daemon's account
    /// is its only member (Rick, 2026-10-22): a listed second member, a
    /// second account whose primary group it is, and a membership that
    /// cannot be read each refuse, naming what was found. A file the group
    /// cannot read never asks.
    #[test]
    fn a_group_readable_secret_needs_the_daemon_as_the_groups_only_member() {
        const MINE: u32 = 50;
        let service = entry(0, MINE, reg(0o640));
        let judge = |members: Result<Membership, String>| {
            secret_reader(service, MINE, AclProbe::ModeOnly, &|| members.clone())
        };
        assert_eq!(judge(Ok(Membership::Sole)), None);
        assert_eq!(
            judge(Ok(Membership::Listed(account_name(b"alice")))).as_deref(),
            Some("its group, gid 50, which lists the account alice")
        );
        assert_eq!(
            judge(Ok(Membership::Primary(account_name(b"backup")))).as_deref(),
            Some("its group, gid 50, which is the primary group of the account backup")
        );
        assert_eq!(
            judge(Err(
                "the system's account list could not be read: boom".to_owned()
            ))
            .as_deref(),
            Some(
                "its group, gid 50, whose membership could not be read \
                 (the system's account list could not be read: boom)"
            )
        );
        // A file the group cannot read never consults the membership, and
        // another group's read is refused as that group before any read.
        let never = || -> Result<Membership, String> {
            panic!("a membership was read for a file the group cannot read")
        };
        assert_eq!(
            secret_reader(entry(ME, ME, reg(0o600)), MINE, AclProbe::ModeOnly, &never),
            None
        );
        assert_eq!(
            secret_reader(entry(0, 9, reg(0o640)), MINE, AclProbe::ModeOnly, &never).as_deref(),
            Some("its group, gid 9")
        );
    }

    /// The service shape writes as root only: root:<daemon group> 0640 under
    /// a root:root 0755 directory passes the write check, and the same file
    /// group-writable does not.
    #[test]
    fn the_service_shape_is_written_by_root_only() {
        let dirs = &[
            ("/", entry(0, 0, dir(0o755))),
            ("/etc", entry(0, 0, dir(0o755))),
            ("/etc/shekyl", entry(0, 0, dir(0o755))),
        ];
        assert_eq!(judge(entry(0, 50, reg(0o640)), dirs), None);
        let found = judge(entry(0, 50, reg(0o660)), dirs).unwrap();
        assert_eq!(found.1, "its group, gid 50");
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
    /// judged, naming the file and the operating system's error. Root
    /// opens every file, so under root (CI's container) the arm cannot be
    /// reached and the test says so rather than judging the directory
    /// walk by accident.
    #[test]
    fn a_file_that_cannot_be_opened_is_unreadable() {
        if rustix::process::geteuid().is_root() {
            use std::io::Write as _;
            drop(writeln!(
                std::io::stderr(),
                "not run: root opens a mode-000 file; the unreadable arm needs an unprivileged account"
            ));
            return;
        }
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
