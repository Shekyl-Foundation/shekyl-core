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
//! reader, over `getgrgid_r`, `getpwuid_r` and the account walk, which
//! rustix does not wrap; it is the one place after `acl` where the crate's
//! `unsafe_code` deny is lifted. A name is the bytes the system returned.
//! What the walk sees is what the name service enumerates: a directory
//! service configured not to enumerate its accounts reports none and no
//! error, and so does one that is stopped (glibc reports an unavailable
//! service as the end of its list), and the walk cannot see past that; the
//! operator docs say the daemon's group must stay a local group.
//!
//! **The walk's end.** Each step of the walk is judged by [`step`], a pure
//! function over what the library returned, under the target's
//! [`Convention`] (read at each libc's source, 2026-11-15):
//!
//! - glibc walks with `getpwent_r`, whose return code is the answer: `0`
//!   with an entry, `ENOENT` at the end of the list, `ERANGE` for a buffer
//!   too small, any other code an error (`nss/getnssent_r.c`,
//!   `__nss_getent_r`). An `ERANGE` is retried with a larger buffer: the
//!   files module seeks back to the line it could not fit
//!   (`nss/nss_readline.c`, `__nss_readline_seek`) and `sssd`'s client
//!   keeps its entry (`src/sss_client/nss_passwd.c`), so the next call
//!   returns the same account. `errno` is not read: a complete walk over a
//!   stopped `sssd` ends with `errno` `ENOENT` and return code `ENOENT`,
//!   which the earlier errno walk read as a failed read.
//! - FreeBSD, DragonFly and NetBSD walk with `getpwent_r`, which ends the
//!   list with `0` and a null result (`lib/libc/gen/getpwent.c` in each).
//!   Their files and compat backends move past an entry before checking
//!   that it fits, so an `ERANGE` retried would skip that account: it
//!   refuses instead, and the walk starts at the largest buffer so that
//!   only an entry past it can meet one.
//! - musl, macOS and iOS, OpenBSD, illumos and Solaris keep the `getpwent`
//!   walk, which tells the end from an error by `errno` alone: the libc
//!   crate declares no `getpwent_r` for them (musl defines none,
//!   `include/pwd.h`; illumos's has another signature). `getpwent` leaves
//!   `errno` alone at the end of the list (musl `src/passwd/getpwent_a.c`),
//!   so the walk clears it before each call.
//!
//! A target this does not name does not build.
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

/// How a target's library reports one step of the account walk (module
/// docs, "The walk's end").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Convention {
    /// glibc's `getpwent_r`: `ENOENT` ends the list; `ERANGE` is retried.
    ReturnEnoent,
    /// The BSDs' `getpwent_r`: `0` with no entry ends the list; `ERANGE`
    /// refuses, because the cursor has already passed the entry.
    ReturnZero,
    /// `getpwent` and `errno`: `0` with no entry ends the list.
    Errno,
}

/// One entry the library returned, read out of its storage. `name` is
/// `None` when the entry has no name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) name: Option<AccountName>,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// What one step of the walk means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// An account; the walk goes on.
    Account(Account),
    /// The list is complete.
    End,
    /// The buffer was too small and the same entry comes back on the next
    /// call: grow it and call again.
    Grow,
    /// The read did not complete; why.
    Refused(String),
}

/// One step of the walk, judged: `code` is the return code under the
/// `getpwent_r` conventions and `errno` under [`Convention::Errno`], and
/// `entry` is the entry the call returned, if any. Every outcome a
/// target's library does not document as the end of the list or an entry
/// refuses, so the check fails closed.
#[must_use]
pub(crate) fn step(convention: Convention, code: i32, entry: Option<Entry>) -> Step {
    match entry {
        // `errno` is meaningful only when `getpwent` returns no entry.
        Some(entry) if code == 0 || convention == Convention::Errno => match entry.name {
            Some(name) => Step::Account(Account {
                name,
                uid: entry.uid,
                gid: entry.gid,
            }),
            None => {
                Step::Refused("the system's account list holds an account with no name".to_owned())
            }
        },
        Some(_) => Step::Refused(format!(
            "the system's account list returned an entry with an error: {}",
            std::io::Error::from_raw_os_error(code)
        )),
        None => match (convention, code) {
            (Convention::ReturnEnoent, libc::ENOENT)
            | (Convention::ReturnZero | Convention::Errno, 0) => Step::End,
            (Convention::ReturnEnoent, libc::ERANGE) => Step::Grow,
            (Convention::ReturnZero, libc::ERANGE) => Step::Refused(
                "the system's account list holds an entry larger than the largest buffer, \
                 and this library moves past an entry it could not fit"
                    .to_owned(),
            ),
            (Convention::ReturnEnoent, 0) => {
                Step::Refused("the system's account list returned no entry and no end".to_owned())
            }
            (_, code) => Step::Refused(format!(
                "the system's account list could not be read: {}",
                std::io::Error::from_raw_os_error(code)
            )),
        },
    }
}

/// The login name of `uid`, when the password database has it.
#[must_use]
pub(crate) fn login_name(uid: u32) -> Option<AccountName> {
    sys::account(uid).ok().map(|account| account.name)
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

    use super::{Account, AccountName, Convention, Entry, Step};

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
    /// account walk under [`super::WALK`], each step judged by
    /// [`super::step`]. `Ok(None)` is a finished list with no such account.
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
        let mut next = Next::new();
        loop {
            match next.read() {
                Step::Account(account) => {
                    if account.gid == gid && account.uid != me.uid {
                        return Ok(Some(account));
                    }
                }
                Step::End => return Ok(None),
                Step::Grow => next.grow()?,
                Step::Refused(why) => return Err(why),
            }
        }
    }

    /// The walk's next entry by `getpwent_r` (glibc, FreeBSD, DragonFly,
    /// NetBSD), into a buffer the walk keeps.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    ))]
    struct Next {
        buffer: Vec<u8>,
    }

    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    ))]
    impl Next {
        /// glibc re-reads an entry that did not fit, so it starts small and
        /// grows; the BSDs move past it, so they start at the largest
        /// buffer and refuse past it.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        const CONVENTION: Convention = Convention::ReturnEnoent;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        const START: usize = LOOKUP_BUFFER_START;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
        const CONVENTION: Convention = Convention::ReturnZero;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
        const START: usize = LOOKUP_BUFFER_MAX;

        fn new() -> Self {
            Self {
                buffer: vec![0u8; Self::START],
            }
        }

        fn read(&mut self) -> Step {
            // SAFETY: `passwd` is plain data; a zeroed value is a valid
            // out-struct for `getpwent_r` to fill.
            let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: `entry`, `buffer` and `found` are live and of the
            // sizes passed; the strings are written into `buffer`, which
            // outlives every read of `entry` below. The cursor is the
            // walk's, under [`super::WALK`].
            let rc = unsafe {
                libc::getpwent_r(
                    &raw mut entry,
                    self.buffer.as_mut_ptr().cast::<libc::c_char>(),
                    self.buffer.len(),
                    &raw mut found,
                )
            };
            let returned = if found.is_null() {
                None
            } else {
                // SAFETY: `found` is `&entry`; `pw_name` is null or a
                // NUL-terminated string inside `buffer`, which is live.
                Some(Entry {
                    name: unsafe { read_name(entry.pw_name) },
                    uid: entry.pw_uid,
                    gid: entry.pw_gid,
                })
            };
            super::step(Self::CONVENTION, rc, returned)
        }

        /// The buffer doubled, to [`LOOKUP_BUFFER_MAX`]; past it, refused.
        fn grow(&mut self) -> Result<(), String> {
            let next = self.buffer.len().saturating_mul(2).min(LOOKUP_BUFFER_MAX);
            if next <= self.buffer.len() {
                return Err(format!(
                    "the system's account list holds an entry larger than {LOOKUP_BUFFER_MAX} bytes"
                ));
            }
            self.buffer.resize(next, 0);
            Ok(())
        }
    }

    /// The walk's next entry by `getpwent`, told from an error by `errno`
    /// (musl, macOS and iOS, OpenBSD, illumos, Solaris): the libc crate
    /// declares no `getpwent_r` for these targets, musl defines none, and
    /// illumos's has another signature. The entry is the library's own
    /// storage, read before the next call and never kept.
    #[cfg(any(
        all(target_os = "linux", target_env = "musl"),
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    struct Next;

    #[cfg(any(
        all(target_os = "linux", target_env = "musl"),
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    impl Next {
        fn new() -> Self {
            Self
        }

        #[allow(clippy::unused_self)]
        fn read(&mut self) -> Step {
            clear_errno();
            // SAFETY: the cursor is the walk's, under [`super::WALK`]; the
            // returned entry is the library's own storage, read before the
            // next call and never kept.
            let found = unsafe { libc::getpwent() };
            if found.is_null() {
                let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return super::step(Convention::Errno, code, None);
            }
            // SAFETY: `found` is non-null. `pw_name` is null or a
            // NUL-terminated string, both live until the next call.
            let returned = unsafe {
                Entry {
                    name: read_name((*found).pw_name),
                    uid: (*found).pw_uid,
                    gid: (*found).pw_gid,
                }
            };
            super::step(Convention::Errno, 0, Some(returned))
        }

        /// `getpwent` owns its buffer: [`Step::Grow`] is not an answer it
        /// gives.
        #[allow(clippy::unused_self)]
        fn grow(&mut self) -> Result<(), String> {
            Err("the system's account list asked for a larger buffer it does not take".to_owned())
        }
    }

    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        all(target_os = "linux", target_env = "musl"),
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    compile_error!(
        "group: name this target's account walk, getpwent_r and its end-of-list convention, \
         or getpwent with errno, read at its libc's source"
    );

    /// Clears the thread's errno, so a NULL from `getpwent` can be told
    /// apart from an error: `getpwent` is specified to leave errno alone at
    /// the end of the list, so a stale value would read as a failed walk.
    /// The accessor is each libc's own, named here as the libc crate
    /// declares it (read at its source, 0.2.184, the version this crate
    /// locks). Only the targets that keep the errno walk call it.
    #[cfg(any(
        all(target_os = "linux", target_env = "musl"),
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    fn clear_errno() {
        // SAFETY: each accessor returns the address of this thread's errno,
        // which is ours to write.
        unsafe {
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = 0;
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "openbsd")]
            {
                *libc::__errno() = 0;
            }
            #[cfg(any(target_os = "illumos", target_os = "solaris"))]
            {
                *libc::___errno() = 0;
            }
        }
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
    use super::{
        judge, members_besides_me, step, Account, AccountName, Convention, Entry, Membership, Step,
    };

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

    fn entry(bytes: &[u8], uid: u32, gid: u32) -> Entry {
        Entry {
            name: AccountName::new(bytes),
            uid,
            gid,
        }
    }

    const ALL: [Convention; 3] = [
        Convention::ReturnEnoent,
        Convention::ReturnZero,
        Convention::Errno,
    ];

    /// An entry is an account under every convention, and an entry with no
    /// name refuses, naming it.
    #[test]
    fn an_entry_is_an_account_and_one_with_no_name_refuses() {
        for convention in ALL {
            assert_eq!(
                step(convention, 0, Some(entry(b"alice", 1000, 1000))),
                Step::Account(account(b"alice", 1000, 1000)),
                "{convention:?}"
            );
            match step(convention, 0, Some(entry(b"", 1000, 1000))) {
                Step::Refused(why) => assert!(why.contains("no name"), "{convention:?}: {why}"),
                other => panic!("{convention:?}: {other:?}"),
            }
        }
        // `getpwent`'s errno means nothing beside an entry: a stale value
        // does not refuse it.
        assert_eq!(
            step(
                Convention::Errno,
                libc::ENOENT,
                Some(entry(b"alice", 1000, 1000))
            ),
            Step::Account(account(b"alice", 1000, 1000))
        );
        // `getpwent_r` returns an entry only with 0: an entry beside an error
        // code is not trusted.
        assert!(matches!(
            step(
                Convention::ReturnEnoent,
                libc::EIO,
                Some(entry(b"alice", 1000, 1000))
            ),
            Step::Refused(_)
        ));
    }

    /// The end of the list, as each library says it: glibc's `ENOENT`, the
    /// BSDs' `0` with no entry, and `getpwent`'s no entry with `errno` clear.
    /// The `ENOENT` a stopped `sssd` leaves is glibc's end, not an error.
    #[test]
    fn the_end_of_the_list_is_each_librarys_own() {
        assert_eq!(
            step(Convention::ReturnEnoent, libc::ENOENT, None),
            Step::End
        );
        assert_eq!(step(Convention::ReturnZero, 0, None), Step::End);
        assert_eq!(step(Convention::Errno, 0, None), Step::End);
        // The other library's end is not this one's.
        assert!(matches!(
            step(Convention::ReturnEnoent, 0, None),
            Step::Refused(_)
        ));
        assert!(matches!(
            step(Convention::ReturnZero, libc::ENOENT, None),
            Step::Refused(_)
        ));
        assert!(matches!(
            step(Convention::Errno, libc::ENOENT, None),
            Step::Refused(_)
        ));
    }

    /// A real error refuses under every convention, naming the system's
    /// text for it, so the check fails closed.
    #[test]
    fn a_real_error_refuses() {
        for convention in ALL {
            match step(convention, libc::EIO, None) {
                Step::Refused(why) => {
                    let text = std::io::Error::from_raw_os_error(libc::EIO).to_string();
                    assert!(why.contains(&text), "{convention:?}: {why}");
                }
                other => panic!("{convention:?}: {other:?}"),
            }
        }
    }

    /// A buffer too small: glibc returns the same entry again, so the walk
    /// grows its buffer and asks again; the BSDs have moved past it, so a
    /// retry would skip an account, and the walk refuses.
    #[test]
    fn a_buffer_too_small_grows_where_the_entry_comes_back_and_refuses_where_it_does_not() {
        assert_eq!(
            step(Convention::ReturnEnoent, libc::ERANGE, None),
            Step::Grow
        );
        match step(Convention::ReturnZero, libc::ERANGE, None) {
            Step::Refused(why) => assert!(why.contains("larger than"), "{why}"),
            other => panic!("{other:?}"),
        }
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
