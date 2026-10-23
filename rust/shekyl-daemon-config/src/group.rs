// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's group, as the secret-read rule reads it (Rick, 2026-10-22):
//! a configuration file that holds a secret and is readable through the
//! daemon's group is refused unless the group's only member is the daemon's
//! account. The members are the group's member list plus every account
//! whose primary group it is. A membership that cannot be read completely
//! refuses, naming why.
//!
//! The judgement is a pure function over the names the system reports
//! ([`judge`]), tested on described lists. [`members_besides_me`] is the one
//! reader, over `getgrgid_r`, `getpwuid_r` and the `getpwent` walk, which
//! rustix does not wrap; it is the one place after `acl` where the crate's
//! `unsafe_code` deny is lifted. What the walk sees is what the name
//! service enumerates: a directory service configured not to enumerate its
//! accounts reports none and no error, and the walk cannot see past that;
//! the operator docs say the daemon's group must stay a local group.
//!
//! `getpwent` walks one process-wide cursor, so two walks at once would
//! interleave. The walk holds [`WALK`] from `setpwent` to `endpwent`: it is
//! callable from any number of threads and they take turns. Nothing else in
//! the tree moves that cursor (`getpwuid_r` and `getpwuid`, the other
//! password reads, look one entry up and leave it alone), and at start the
//! check runs from `load`, before the daemon's logging, runtime or any
//! thread of its own exists (`shekyl-daemon`'s `run`); the lock is what
//! makes that order a convenience rather than a condition.

/// What the group holds besides the daemon's account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GroupMembers {
    /// The daemon's account is the only member.
    Sole,
    /// Another account is a member, by the group's member list.
    Listed(String),
    /// Another account has the group as its primary group.
    Primary(String),
    /// The membership could not be read completely; the reason.
    Unreadable(String),
}

/// One account of the password database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    /// The login name.
    pub name: String,
    /// The user id.
    pub uid: u32,
    /// The primary group.
    pub gid: u32,
}

/// Who is in group `gid` besides `me`: `listed` is the group's member list
/// and `accounts` every account the password database enumerates. A listed
/// name that is not the daemon's is another member; so is an account whose
/// primary group is `gid` and whose uid is not the daemon's.
pub(crate) fn judge(
    me: &Account,
    gid: u32,
    listed: &[String],
    accounts: &[Account],
) -> GroupMembers {
    if let Some(other) = listed.iter().find(|name| **name != me.name) {
        return GroupMembers::Listed(other.clone());
    }
    if let Some(other) = accounts.iter().find(|a| a.gid == gid && a.uid != me.uid) {
        return GroupMembers::Primary(other.name.clone());
    }
    GroupMembers::Sole
}

/// The one cursor `getpwent` walks, held for the whole walk.
static WALK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The live answer for group `gid` and the daemon's account `uid`.
pub(crate) fn members_besides_me(gid: u32, uid: u32) -> GroupMembers {
    let me = match sys::account(uid) {
        Ok(me) => me,
        Err(why) => return GroupMembers::Unreadable(why),
    };
    let listed = match sys::listed(gid) {
        Ok(listed) => listed,
        Err(why) => return GroupMembers::Unreadable(why),
    };
    let accounts = match sys::accounts() {
        Ok(accounts) => accounts,
        Err(why) => return GroupMembers::Unreadable(why),
    };
    judge(&me, gid, &listed, &accounts)
}

/// The three reads, each returning the reason it could not answer.
#[allow(unsafe_code)]
mod sys {
    use std::ffi::CStr;

    use super::Account;

    /// Where a reentrant lookup's strings are written; doubled on `ERANGE`
    /// up to [`BUFFER_MAX`].
    const BUFFER_START: usize = 16 * 1024;
    const BUFFER_MAX: usize = 1024 * 1024;

    /// The name at a C string the system handed back.
    ///
    /// # Safety
    /// `ptr` is non-null and points at a NUL-terminated string that is live
    /// for the call.
    unsafe fn name_at(ptr: *const libc::c_char) -> String {
        // SAFETY: the caller's contract.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    /// The account `uid` names, by `getpwuid_r`.
    pub(super) fn account(uid: u32) -> Result<Account, String> {
        let mut buffer = vec![0u8; BUFFER_START];
        loop {
            // SAFETY: `passwd` is plain data; a zeroed value is a valid
            // out-struct for `getpwuid_r` to fill.
            let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: `entry`, `buffer` and `found` are live locals of the
            // sizes passed; the strings are written into `buffer`, which
            // outlives every read of `entry` below.
            let rc = unsafe {
                libc::getpwuid_r(
                    uid,
                    &raw mut entry,
                    buffer.as_mut_ptr().cast::<libc::c_char>(),
                    buffer.len(),
                    &raw mut found,
                )
            };
            if rc == libc::ERANGE && buffer.len() < BUFFER_MAX {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            if rc != 0 {
                let err = std::io::Error::from_raw_os_error(rc);
                return Err(format!(
                    "the daemon's account, uid {uid}, could not be read: {err}"
                ));
            }
            if found.is_null() || entry.pw_name.is_null() {
                return Err(format!(
                    "the daemon's account, uid {uid}, is not known to the system"
                ));
            }
            // SAFETY: `pw_name` points at a NUL-terminated string inside
            // `buffer`, which is live.
            let name = unsafe { name_at(entry.pw_name) };
            return Ok(Account {
                name,
                uid: entry.pw_uid,
                gid: entry.pw_gid,
            });
        }
    }

    /// The member list of group `gid`, by `getgrgid_r`.
    pub(super) fn listed(gid: u32) -> Result<Vec<String>, String> {
        let mut buffer = vec![0u8; BUFFER_START];
        loop {
            // SAFETY: `group` is plain data; a zeroed value is a valid
            // out-struct for `getgrgid_r` to fill.
            let mut entry: libc::group = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::group = std::ptr::null_mut();
            // SAFETY: as for `getpwuid_r` above; the member list and its
            // strings are written into `buffer`.
            let rc = unsafe {
                libc::getgrgid_r(
                    gid,
                    &raw mut entry,
                    buffer.as_mut_ptr().cast::<libc::c_char>(),
                    buffer.len(),
                    &raw mut found,
                )
            };
            if rc == libc::ERANGE && buffer.len() < BUFFER_MAX {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            if rc != 0 {
                let err = std::io::Error::from_raw_os_error(rc);
                return Err(format!(
                    "the daemon's group, gid {gid}, could not be read: {err}"
                ));
            }
            if found.is_null() {
                return Err(format!(
                    "the daemon's group, gid {gid}, is not known to the system"
                ));
            }
            let mut names = Vec::new();
            let mut member = entry.gr_mem;
            if !member.is_null() {
                // SAFETY: `gr_mem` is a NULL-terminated array of pointers
                // to NUL-terminated strings, all inside `buffer`.
                unsafe {
                    while !(*member).is_null() {
                        names.push(name_at(*member));
                        member = member.add(1);
                    }
                }
            }
            return Ok(names);
        }
    }

    /// Every account the password database enumerates, by the `getpwent`
    /// walk, under [`super::WALK`]. The walk ends on a NULL with errno
    /// clear; a NULL with errno set is a read that did not complete.
    pub(super) fn accounts() -> Result<Vec<Account>, String> {
        // A poisoned lock is a walk that panicked mid-way; the cursor is
        // reset by `setpwent` below either way, so the guard is taken.
        let _walk = super::WALK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::new();
        // SAFETY: `setpwent` and `endpwent` take nothing and touch only the
        // library's cursor, which `_walk` makes ours for the whole walk.
        unsafe { libc::setpwent() };
        let result = loop {
            clear_errno();
            // SAFETY: as above; the returned entry is the library's own
            // storage, read before the next call and never kept.
            let entry = unsafe { libc::getpwent() };
            if entry.is_null() {
                let err = std::io::Error::last_os_error();
                break if err.raw_os_error().unwrap_or(0) == 0 {
                    Ok(())
                } else {
                    Err(format!(
                        "the system's account list could not be read: {err}"
                    ))
                };
            }
            // SAFETY: `entry` is non-null and its `pw_name` is a
            // NUL-terminated string, both live until the next call.
            let (name, uid, gid) = unsafe {
                if (*entry).pw_name.is_null() {
                    break Err("the system's account list holds an account with no name".to_owned());
                }
                (name_at((*entry).pw_name), (*entry).pw_uid, (*entry).pw_gid)
            };
            out.push(Account { name, uid, gid });
        };
        // SAFETY: as for `setpwent`.
        unsafe { libc::endpwent() };
        result.map(|()| out)
    }

    /// Clears the thread's errno, so a NULL from `getpwent` can be told
    /// apart from an error: `getpwent` is specified to leave errno alone at
    /// the end of the list, so a stale value would read as a failed walk.
    /// The accessor is each libc's own, named here as the libc crate
    /// declares it (read at its source, 0.2.191); a target this does not
    /// name does not build, rather than skipping the clear and judging a
    /// stale errno.
    fn clear_errno() {
        // SAFETY: each accessor returns the address of this thread's errno,
        // which is ours to write.
        unsafe {
            #[cfg(any(target_os = "linux", target_os = "dragonfly"))]
            {
                *libc::__errno_location() = 0;
            }
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                *libc::__error() = 0;
            }
            #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
            {
                *libc::__errno() = 0;
            }
            #[cfg(any(target_os = "illumos", target_os = "solaris"))]
            {
                *libc::___errno() = 0;
            }
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "dragonfly",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "illumos",
            target_os = "solaris"
        )))]
        compile_error!(
            "group::clear_errno: name this target's errno accessor as the libc crate declares it"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{judge, members_besides_me, Account, GroupMembers};

    fn account(name: &str, uid: u32, gid: u32) -> Account {
        Account {
            name: name.to_owned(),
            uid,
            gid,
        }
    }

    const DAEMON: u32 = 50;

    fn me() -> Account {
        account("shekyl", 901, DAEMON)
    }

    #[test]
    fn the_daemon_alone_is_the_sole_member() {
        let accounts = [account("root", 0, 0), me(), account("alice", 1000, 1000)];
        assert_eq!(judge(&me(), DAEMON, &[], &accounts), GroupMembers::Sole);
        // The daemon's own name on the list is still the daemon.
        assert_eq!(
            judge(&me(), DAEMON, &["shekyl".to_owned()], &accounts),
            GroupMembers::Sole
        );
    }

    #[test]
    fn a_second_listed_member_is_named() {
        let accounts = [me()];
        assert_eq!(
            judge(
                &me(),
                DAEMON,
                &["shekyl".to_owned(), "alice".to_owned()],
                &accounts
            ),
            GroupMembers::Listed("alice".to_owned())
        );
    }

    #[test]
    fn a_second_account_with_the_group_as_its_primary_group_is_named() {
        let accounts = [me(), account("backup", 902, DAEMON)];
        assert_eq!(
            judge(&me(), DAEMON, &[], &accounts),
            GroupMembers::Primary("backup".to_owned())
        );
        // The list is read first: a listed stranger is named over a
        // primary-group one.
        assert_eq!(
            judge(&me(), DAEMON, &["bob".to_owned()], &accounts),
            GroupMembers::Listed("bob".to_owned())
        );
    }

    /// The live reader answers for the account the tests run as. Which
    /// answer depends on the machine, so this pins only that every read
    /// completes and is reported in the rule's terms.
    #[test]
    fn the_live_reader_answers_for_the_running_account() {
        let gid = rustix::process::getegid().as_raw();
        let uid = rustix::process::geteuid().as_raw();
        match members_besides_me(gid, uid) {
            GroupMembers::Sole | GroupMembers::Listed(_) | GroupMembers::Primary(_) => {}
            GroupMembers::Unreadable(why) => assert!(!why.is_empty(), "a reason is named"),
        }
    }

    /// Two threads may ask at once: the walks take turns on [`super::WALK`]
    /// and both complete with the same answer. The lock is what lets the
    /// check run from anywhere, not only before the daemon's first thread.
    #[test]
    fn concurrent_walks_take_turns_and_agree() {
        let gid = rustix::process::getegid().as_raw();
        let uid = rustix::process::geteuid().as_raw();
        let answers: Vec<GroupMembers> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(move || members_besides_me(gid, uid)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("a walk completes"))
                .collect()
        });
        assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
    }

    /// A group the system does not know is an unreadable membership, named.
    #[test]
    fn an_unknown_group_is_unreadable_and_named() {
        let uid = rustix::process::geteuid().as_raw();
        match members_besides_me(u32::MAX - 7, uid) {
            GroupMembers::Unreadable(why) => assert!(why.contains("gid"), "{why}"),
            other => panic!("an unknown group must be unreadable, not {other:?}"),
        }
    }
}
