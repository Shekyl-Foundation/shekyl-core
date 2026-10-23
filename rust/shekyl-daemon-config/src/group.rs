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
//! `unsafe_code` deny is lifted. A name is the bytes the system returned.
//! What the walk sees is what the name service enumerates: a directory
//! service configured not to enumerate its accounts reports none and no
//! error, and the walk cannot see past that; the operator docs say the
//! daemon's group must stay a local group.
//!
//! `getpwent` walks one process-wide cursor, so two walks at once would
//! interleave. The walk holds [`WALK`] from `setpwent` to `endpwent`: it is
//! callable from any number of threads and they take turns. Nothing else in
//! the tree moves that cursor (`getpwuid_r` and `getpwuid`, the other
//! password reads, look one entry up and leave it alone), and at start the
//! check runs from `load`, before the daemon's logging, runtime or any
//! thread of its own exists (`shekyl-daemon`'s `run`); the lock is what
//! makes that order a convenience rather than a condition. The cursor is
//! closed when the walk's guard drops, including when the walk panics.

/// A login name as the name service spelled it, without the trailing NUL.
///
/// The bytes are the identity. Two names that render as the same lossy
/// UTF-8 text are still different accounts. [`Display`](std::fmt::Display)
/// is for a refusal sentence only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountName(Vec<u8>);

impl AccountName {
    /// `bytes` as a name. Empty is not a name.
    pub(crate) fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            Some(Self(bytes.to_vec()))
        }
    }
}

impl std::fmt::Display for AccountName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

/// Who is in the group besides the daemon's account.
///
/// A read that did not finish is not a membership. That is the `Err` of
/// [`members_besides_me`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Membership {
    /// The daemon's account is the only member.
    Sole,
    /// Another account is on the group's member list.
    Listed(AccountName),
    /// Another account has the group as its primary group.
    Primary(AccountName),
}

/// One account of the password database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    /// The login name.
    name: AccountName,
    /// The user id.
    uid: u32,
    /// The primary group.
    gid: u32,
}

/// Who is in group `gid` besides `me`: `listed` is the group's member list
/// and `accounts` every account the caller has already decided to show the
/// rule. A listed name that is not the daemon's is another member; so is an
/// account whose primary group is `gid` and whose uid is not the daemon's.
/// The list is read first.
#[must_use]
pub(crate) fn judge(
    me: &Account,
    gid: u32,
    listed: &[AccountName],
    accounts: &[Account],
) -> Membership {
    if let Some(other) = listed.iter().find(|name| *name != &me.name) {
        return Membership::Listed((*other).clone());
    }
    if let Some(other) = accounts
        .iter()
        .find(|account| account.gid == gid && account.uid != me.uid)
    {
        return Membership::Primary(other.name.clone());
    }
    Membership::Sole
}

/// The one cursor `getpwent` walks, held for the whole walk.
static WALK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The live answer for group `gid` and the daemon's account `uid`.
///
/// A member list that already names someone else is the whole answer:
/// [`judge`] reads that list before any account, so the password walk is
/// not consulted. Otherwise the walk is a search for the first other
/// account whose primary group is `gid`, and it stops there. Confirming
/// [`Membership::Sole`] still reads the database through to its end,
/// because only the end proves nobody else has the group.
pub(crate) fn members_besides_me(gid: u32, uid: u32) -> Result<Membership, String> {
    let me = sys::account(uid)?;
    let listed = sys::listed(gid)?;
    // An empty account list is complete when the member list already names
    // someone else: `judge` returns that account before it reads `accounts`.
    let accounts = if listed.iter().any(|name| name != &me.name) {
        Vec::new()
    } else {
        sys::first_other_primary(gid, &me)?.into_iter().collect()
    };
    Ok(judge(&me, gid, &listed, &accounts))
}

/// The three reads, each returning the reason it could not answer.
#[allow(unsafe_code)]
mod sys {
    use std::ffi::CStr;

    use super::{Account, AccountName};

    /// First buffer for a reentrant lookup. A short entry fits; `ERANGE` grows it.
    const LOOKUP_BUFFER_START: usize = 16 * 1024;
    /// Largest buffer a lookup may use. A still-short buffer refuses.
    const LOOKUP_BUFFER_MAX: usize = 1024 * 1024;

    /// One attempt to fill a caller-owned buffer.
    enum BufferRead<T> {
        /// The call finished. The value was copied out of the buffer.
        Done(T),
        /// The buffer was too small.
        Range,
        /// The call failed with this `errno` value.
        Failed(i32),
    }

    /// Runs `read` on a buffer that doubles from [`LOOKUP_BUFFER_START`]
    /// while the call reports `ERANGE`, and stops at [`LOOKUP_BUFFER_MAX`].
    fn with_buffer<T>(mut read: impl FnMut(&mut [u8]) -> BufferRead<T>) -> Result<T, i32> {
        let mut buffer = vec![0u8; LOOKUP_BUFFER_START];
        loop {
            match read(&mut buffer) {
                BufferRead::Done(value) => return Ok(value),
                BufferRead::Range if buffer.len() < LOOKUP_BUFFER_MAX => {
                    let next = buffer.len().saturating_mul(2).min(LOOKUP_BUFFER_MAX);
                    if next <= buffer.len() {
                        return Err(libc::ERANGE);
                    }
                    buffer.resize(next, 0);
                }
                BufferRead::Range => return Err(libc::ERANGE),
                BufferRead::Failed(rc) => return Err(rc),
            }
        }
    }

    /// The name at a C string the system handed back.
    ///
    /// # Safety
    /// `ptr` is null, or it points at a NUL-terminated string that is live
    /// for the call. Null and empty are both "no name".
    unsafe fn read_name(ptr: *const libc::c_char) -> Option<AccountName> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: the caller's contract.
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        AccountName::new(bytes)
    }

    /// The operating system's text for `rc`, as a refusal embeds it.
    fn os_error(rc: i32) -> std::io::Error {
        std::io::Error::from_raw_os_error(rc)
    }

    /// The account `uid` names, by `getpwuid_r`.
    pub(super) fn account(uid: u32) -> Result<Account, String> {
        match with_buffer(|buffer| {
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
            if rc == libc::ERANGE {
                return BufferRead::Range;
            }
            if rc != 0 {
                return BufferRead::Failed(rc);
            }
            if found.is_null() {
                return BufferRead::Done(Err(format!(
                    "the daemon's account, uid {uid}, is not known to the system"
                )));
            }
            // SAFETY: `pw_name` is null or a NUL-terminated string inside
            // `buffer`, which is live.
            let Some(name) = (unsafe { read_name(entry.pw_name) }) else {
                return BufferRead::Done(Err(format!(
                    "the daemon's account, uid {uid}, has no name"
                )));
            };
            if entry.pw_uid != uid {
                return BufferRead::Done(Err(format!(
                    "the daemon's account, uid {uid}, was reported as uid {}",
                    entry.pw_uid
                )));
            }
            BufferRead::Done(Ok(Account {
                name,
                uid: entry.pw_uid,
                gid: entry.pw_gid,
            }))
        }) {
            Ok(account) => account,
            Err(rc) => Err(format!(
                "the daemon's account, uid {uid}, could not be read: {}",
                os_error(rc)
            )),
        }
    }

    /// The member list of group `gid`, by `getgrgid_r`.
    pub(super) fn listed(gid: u32) -> Result<Vec<AccountName>, String> {
        match with_buffer(|buffer| {
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
            if rc == libc::ERANGE {
                return BufferRead::Range;
            }
            if rc != 0 {
                return BufferRead::Failed(rc);
            }
            if found.is_null() {
                return BufferRead::Done(Err(format!(
                    "the daemon's group, gid {gid}, is not known to the system"
                )));
            }
            if entry.gr_gid != gid {
                return BufferRead::Done(Err(format!(
                    "the daemon's group, gid {gid}, was reported as gid {}",
                    entry.gr_gid
                )));
            }
            let mut names = Vec::new();
            let mut member = entry.gr_mem;
            if !member.is_null() {
                // SAFETY: `gr_mem` is a NULL-terminated array of pointers
                // to NUL-terminated strings, all inside `buffer`.
                unsafe {
                    while !(*member).is_null() {
                        let Some(name) = read_name(*member) else {
                            return BufferRead::Done(Err(format!(
                                "the daemon's group, gid {gid}, lists an account with no name"
                            )));
                        };
                        names.push(name);
                        member = member.add(1);
                    }
                }
            }
            BufferRead::Done(Ok(names))
        }) {
            Ok(names) => names,
            Err(rc) => Err(format!(
                "the daemon's group, gid {gid}, could not be read: {}",
                os_error(rc)
            )),
        }
    }

    /// Closes the `getpwent` cursor, including when the walk returns early
    /// or panics. Constructed immediately after `setpwent`.
    struct WalkCursor;

    impl Drop for WalkCursor {
        fn drop(&mut self) {
            // SAFETY: `endpwent` takes nothing and touches only the
            // library's cursor, which the caller holds under [`super::WALK`].
            unsafe { libc::endpwent() }
        }
    }

    /// The first account besides `me` whose primary group is `gid`, by the
    /// `getpwent` walk under [`super::WALK`]. The walk ends on a NULL with
    /// errno clear; a NULL with errno set is a read that did not complete,
    /// and so is an account with no name. `Ok(None)` is a finished list
    /// with no such account.
    pub(super) fn first_other_primary(gid: u32, me: &Account) -> Result<Option<Account>, String> {
        // A poisoned lock is a walk that panicked mid-way. The cursor is
        // rewound by `setpwent` and closed by `_cursor` either way.
        let _walk = super::WALK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: `setpwent` takes nothing and touches only the library's
        // cursor, which `_walk` makes ours until it drops.
        unsafe { libc::setpwent() };
        let _cursor = WalkCursor;
        loop {
            clear_errno();
            // SAFETY: as above; the returned entry is the library's own
            // storage, read before the next call and never kept.
            let entry = unsafe { libc::getpwent() };
            if entry.is_null() {
                let err = std::io::Error::last_os_error();
                return if err.raw_os_error().unwrap_or(0) == 0 {
                    Ok(None)
                } else {
                    Err(format!(
                        "the system's account list could not be read: {err}"
                    ))
                };
            }
            // SAFETY: `entry` is non-null. `pw_name` is null or a
            // NUL-terminated string, both live until the next call.
            let (name, uid, primary) = unsafe {
                let Some(name) = read_name((*entry).pw_name) else {
                    return Err(
                        "the system's account list holds an account with no name".to_owned()
                    );
                };
                (name, (*entry).pw_uid, (*entry).pw_gid)
            };
            if primary == gid && uid != me.uid {
                return Ok(Some(Account {
                    name,
                    uid,
                    gid: primary,
                }));
            }
        }
    }

    /// Clears the thread's errno, so a NULL from `getpwent` can be told
    /// apart from an error: `getpwent` is specified to leave errno alone at
    /// the end of the list, so a stale value would read as a failed walk.
    /// The accessor is each libc's own, named here as the libc crate
    /// declares it (read at its source, 0.2.184, the version this crate
    /// locks); a target this does not name does not build, rather than
    /// skipping the clear and judging a stale errno.
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

    #[cfg(test)]
    mod tests {
        use super::read_name;
        use crate::group::AccountName;

        #[test]
        fn a_name_is_the_bytes_up_to_the_nul_and_empty_is_refused() {
            let read = unsafe { read_name(c"shekyl".as_ptr()) }.expect("a name");
            assert_eq!(read, AccountName::new(b"shekyl").unwrap());
            assert!(unsafe { read_name(c"".as_ptr()) }.is_none());
            assert!(unsafe { read_name(std::ptr::null()) }.is_none());
            assert!(AccountName::new(b"").is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{judge, members_besides_me, Account, AccountName, Membership};

    fn name(bytes: &[u8]) -> AccountName {
        AccountName::new(bytes).expect("a test name is non-empty")
    }

    fn account(bytes: &[u8], uid: u32, gid: u32) -> Account {
        Account {
            name: name(bytes),
            uid,
            gid,
        }
    }

    /// A gid the system does not assign. The unknown-group test uses it.
    const UNKNOWN_GID: u32 = u32::MAX - 7;
    const DAEMON_GID: u32 = 50;

    fn me() -> Account {
        account(b"shekyl", 901, DAEMON_GID)
    }

    #[test]
    fn the_daemon_alone_is_the_sole_member() {
        let accounts = [account(b"root", 0, 0), me(), account(b"alice", 1000, 1000)];
        assert_eq!(judge(&me(), DAEMON_GID, &[], &accounts), Membership::Sole);
        // The daemon's own name on the list is still the daemon.
        assert_eq!(
            judge(&me(), DAEMON_GID, &[name(b"shekyl")], &accounts),
            Membership::Sole
        );
    }

    #[test]
    fn a_second_listed_member_is_named() {
        let accounts = [me()];
        assert_eq!(
            judge(
                &me(),
                DAEMON_GID,
                &[name(b"shekyl"), name(b"alice")],
                &accounts
            ),
            Membership::Listed(name(b"alice"))
        );
    }

    #[test]
    fn a_second_account_with_the_group_as_its_primary_group_is_named() {
        let accounts = [me(), account(b"backup", 902, DAEMON_GID)];
        assert_eq!(
            judge(&me(), DAEMON_GID, &[], &accounts),
            Membership::Primary(name(b"backup"))
        );
        // The list is read first: a listed stranger is named over a
        // primary-group one, whatever accounts were supplied.
        assert_eq!(
            judge(&me(), DAEMON_GID, &[name(b"bob")], &accounts),
            Membership::Listed(name(b"bob"))
        );
    }

    /// `0xFF` and `0xFE` both render as U+FFFD. They are different accounts,
    /// and the member-list check must refuse the second one.
    #[test]
    fn distinct_non_utf8_names_stay_distinct() {
        let me = account(b"shekyl\xff", 901, DAEMON_GID);
        let other = name(b"shekyl\xfe");
        assert_eq!(me.name.to_string(), other.to_string());
        assert_ne!(me.name, other);
        assert_eq!(
            judge(&me, DAEMON_GID, std::slice::from_ref(&other), &[]),
            Membership::Listed(other)
        );
    }

    /// The live reader answers for the account the tests run as. The
    /// membership depends on the machine; a read that does not finish does
    /// not.
    #[test]
    fn the_live_reader_reads_the_running_account() {
        let gid = rustix::process::getegid().as_raw();
        let uid = rustix::process::geteuid().as_raw();
        members_besides_me(gid, uid).expect("the running account's membership can be read");
    }

    /// Two threads may ask at once: the walks take turns on [`super::WALK`]
    /// and both complete with the same answer. The lock is what lets the
    /// check run from anywhere, not only before the daemon's first thread.
    #[test]
    fn concurrent_walks_take_turns_and_agree() {
        let gid = rustix::process::getegid().as_raw();
        let uid = rustix::process::geteuid().as_raw();
        let answers: Vec<Membership> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(move || members_besides_me(gid, uid)))
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .expect("a walk completes")
                        .expect("the membership can be read")
                })
                .collect()
        });
        assert!(
            answers.windows(2).all(|pair| pair[0] == pair[1]),
            "{answers:?}"
        );
    }

    /// A group the system does not know is a failed read, named.
    #[test]
    fn an_unknown_group_is_unreadable_and_named() {
        let uid = rustix::process::geteuid().as_raw();
        let why = members_besides_me(UNKNOWN_GID, uid).expect_err("an unknown group is unreadable");
        assert!(why.contains("gid"), "{why}");
    }
}
