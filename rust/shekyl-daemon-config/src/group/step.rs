// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How one call of the account walk is judged.
//!
//! The readers in `sys` turn a libc call into a [`ReentrantReading`]
//! or an [`ErrnoReading`]. The functions here are the whole meaning of that
//! call, and they are pure: the tests describe every target's answers on one
//! host. A new library is a new reading and an arm here, not a branch in the
//! search.
//!
//! - glibc (`getpwent_r`): `0` with a record is an account, `ENOENT` with no
//!   result is the end, `ERANGE` with no result asks for a larger buffer. The
//!   files module seeks back to the line it could not fit
//!   (`nss/nss_readline.c`, `__nss_readline_seek`) and `sssd`'s client keeps
//!   its entry (`src/sss_client/nss_passwd.c`), so the retry returns the same
//!   account. Any other code refuses. An unavailable service is `ENOENT` too
//!   (`nss/getnssent_r.c`, `__nss_getent_r`), which is the end of the list,
//!   not a failed read.
//! - FreeBSD, DragonFly and NetBSD (`getpwent_r`): `0` with no result is the
//!   end (`lib/libc/gen/getpwent.c` in each). `ERANGE` refuses. Their files
//!   and compat backends move past an entry before checking that it fits, so
//!   a retry would skip that account and the check would fail open.
//! - musl, macOS and iOS, OpenBSD, illumos and Solaris (`getpwent`): the libc
//!   crate declares no `getpwent_r` for them (musl defines none,
//!   `include/pwd.h`; illumos's has another signature). No result with
//!   `errno` clear is the end. `getpwent` leaves `errno` alone at the end of
//!   the list (musl `src/passwd/getpwent_a.c`), so the reader clears it
//!   before each call. A record carries no `errno`: the call returns the
//!   entry or null.
//!
//! A result pointer set beside a nonzero `getpwent_r` code is
//! [`ReentrantReading::Unread`]. The record is not decoded. The call refuses.
//!
//! A target this does not name does not build.

// One target's binary calls one judge. The other judge is the other
// target's reader, and the tests below are its caller on every host.
// Test builds still deny `dead_code`, so an unused helper fails there.
#![cfg_attr(not(test), allow(dead_code))]

use super::{Account, AccountName};

/// Which `getpwent_r` this target is.
///
/// Both variants are constructed by the tests on every host. A production
/// build constructs the one its reader names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReentrantConvention {
    /// glibc: `ENOENT` ends the list; `ERANGE` is retried.
    Glibc,
    /// FreeBSD, DragonFly, NetBSD: `0` with no result ends the list;
    /// `ERANGE` refuses, because the cursor has already passed the entry.
    Bsd,
}

/// One passwd record, copied out of the library's storage.
///
/// `name` is `None` when the entry has no name. The bytes are read only for
/// [`ReentrantReading::Record`] and [`ErrnoReading::Record`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) name: Option<AccountName>,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

/// What one `getpwent_r` presented.
///
/// A record exists only for return code `0`. A nonzero code with a result
/// pointer is [`Unread`](Self::Unread): the fields stay in the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReentrantReading {
    /// Return code `0` and a decoded record.
    Record(Entry),
    /// The result pointer was set and the return code was not `0`.
    Unread { code: i32 },
    /// The result pointer was null.
    Absent { code: i32 },
}

/// What one `getpwent` presented.
///
/// The entry and `errno` are alternatives. A stale `errno` beside a record
/// cannot be represented, and the judge cannot refuse the record for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ErrnoReading {
    /// `getpwent` returned a record.
    Record(Entry),
    /// `getpwent` returned null. `errno` is what the call left after the
    /// reader cleared it: `0` is the end of the list.
    Empty { errno: i32 },
}

/// A call the walk can act on: an account, the end of the list, or a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// An account; the walk goes on.
    Account(Account),
    /// The list is complete.
    End,
    /// The read did not complete; why.
    Refused(String),
}

impl Step {
    /// The walk's answer for a settled call.
    pub(super) fn answer(self) -> Result<Option<Account>, String> {
        match self {
            Self::Account(account) => Ok(Some(account)),
            Self::End => Ok(None),
            Self::Refused(why) => Err(why),
        }
    }
}

/// A `getpwent_r` call, including glibc's request to grow the buffer.
///
/// [`Grow`](Self::Grow) is not a step of the search. The reentrant reader
/// retries it, and only glibc's convention produces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReentrantStep {
    /// The call settled.
    Settled(Step),
    /// The buffer was too small and the same entry comes back on the next call.
    Grow,
}

/// One `getpwent_r` call, judged. Every outcome the convention does not
/// document as an entry, the end of the list, or a short buffer refuses, so
/// the check fails closed.
#[must_use]
pub(super) fn step_reentrant(
    convention: ReentrantConvention,
    reading: ReentrantReading,
) -> ReentrantStep {
    let settled = match reading {
        ReentrantReading::Record(entry) => record(entry),
        ReentrantReading::Unread { code } => Step::Refused(format!(
            "the system's account list returned an entry with an error: {}",
            os_text(code)
        )),
        ReentrantReading::Absent { code } => match (convention, code) {
            (ReentrantConvention::Glibc, libc::ENOENT) | (ReentrantConvention::Bsd, 0) => Step::End,
            (ReentrantConvention::Glibc, libc::ERANGE) => return ReentrantStep::Grow,
            // The files and compat backends advance the cursor before they
            // notice the entry does not fit, so a retry would read the next
            // account and skip this one. A skipped account is one whose
            // primary group the check never sees. These targets start at the
            // largest buffer, so only an entry over that size reaches here.
            (ReentrantConvention::Bsd, libc::ERANGE) => Step::Refused(
                "the system's account list holds an entry larger than the largest buffer, \
                 and this library moves past an entry it could not fit"
                    .to_owned(),
            ),
            (ReentrantConvention::Glibc, 0) => {
                Step::Refused("the system's account list returned no entry and no end".to_owned())
            }
            (_, code) => refuse_os(code),
        },
    };
    ReentrantStep::Settled(settled)
}

/// One `getpwent` call, judged. `ERANGE` is a failed read: this call does
/// not take a caller buffer, so there is nothing to grow.
#[must_use]
pub(super) fn step_errno(reading: ErrnoReading) -> Step {
    match reading {
        ErrnoReading::Record(entry) => record(entry),
        ErrnoReading::Empty { errno: 0 } => Step::End,
        ErrnoReading::Empty { errno } => refuse_os(errno),
    }
}

/// The record as an account, or a refusal when it has no name.
fn record(entry: Entry) -> Step {
    match entry.name {
        Some(name) => Step::Account(Account {
            name,
            uid: entry.uid,
            gid: entry.gid,
        }),
        None => Step::Refused("the system's account list holds an account with no name".to_owned()),
    }
}

fn refuse_os(code: i32) -> Step {
    Step::Refused(format!(
        "the system's account list could not be read: {}",
        os_text(code)
    ))
}

fn os_text(code: i32) -> String {
    std::io::Error::from_raw_os_error(code).to_string()
}

#[cfg(test)]
mod tests {
    use super::super::{Account, AccountName};
    use super::{
        step_errno, step_reentrant, Entry, ErrnoReading, ReentrantConvention, ReentrantReading,
        ReentrantStep, Step,
    };

    fn account(bytes: &[u8], uid: u32, gid: u32) -> Account {
        Account {
            name: AccountName::new(bytes).expect("a test name is non-empty"),
            uid,
            gid,
        }
    }

    fn record(bytes: &[u8], uid: u32, gid: u32) -> Entry {
        Entry {
            name: AccountName::new(bytes),
            uid,
            gid,
        }
    }

    fn glibc(reading: ReentrantReading) -> ReentrantStep {
        step_reentrant(ReentrantConvention::Glibc, reading)
    }

    fn bsd(reading: ReentrantReading) -> ReentrantStep {
        step_reentrant(ReentrantConvention::Bsd, reading)
    }

    fn settled(step: ReentrantStep) -> Step {
        match step {
            ReentrantStep::Settled(step) => step,
            ReentrantStep::Grow => panic!("expected a settled step"),
        }
    }

    fn refused(step: Step) -> String {
        match step {
            Step::Refused(why) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A record is an account under every convention, and a record with no
    /// name refuses. The errno reading has no code beside the record: a
    /// stale errno cannot be written down, so it cannot refuse the account.
    #[test]
    fn a_record_is_an_account_and_one_with_no_name_refuses() {
        let alice = ReentrantReading::Record(record(b"alice", 1000, 1000));
        let nameless = ReentrantReading::Record(record(b"", 1000, 1000));
        assert_eq!(
            settled(glibc(alice.clone())),
            Step::Account(account(b"alice", 1000, 1000))
        );
        assert_eq!(
            settled(bsd(alice)),
            Step::Account(account(b"alice", 1000, 1000))
        );
        assert_eq!(
            step_errno(ErrnoReading::Record(record(b"alice", 1000, 1000))),
            Step::Account(account(b"alice", 1000, 1000))
        );
        assert!(refused(settled(glibc(nameless.clone()))).contains("no name"));
        assert!(refused(settled(bsd(nameless))).contains("no name"));
        assert!(
            refused(step_errno(ErrnoReading::Record(record(b"", 1000, 1000)))).contains("no name")
        );
    }

    /// A result pointer beside a nonzero code is not a record, on either
    /// reentrant convention, and it is not a short buffer to retry.
    #[test]
    fn an_unread_result_beside_an_error_refuses() {
        let io = std::io::Error::from_raw_os_error(libc::EIO).to_string();
        for step in [
            glibc(ReentrantReading::Unread { code: libc::EIO }),
            bsd(ReentrantReading::Unread { code: libc::EIO }),
        ] {
            let why = refused(settled(step));
            assert!(why.contains("entry with an error"), "{why}");
            assert!(why.contains(&io), "{why}");
        }
        // ERANGE beside a pointer is the same refusal, not a buffer to grow
        // and not the BSD "moved past the entry" refusal.
        let range = std::io::Error::from_raw_os_error(libc::ERANGE).to_string();
        for step in [
            glibc(ReentrantReading::Unread { code: libc::ERANGE }),
            bsd(ReentrantReading::Unread { code: libc::ERANGE }),
        ] {
            let why = refused(settled(step));
            assert!(why.contains("entry with an error"), "{why}");
            assert!(why.contains(&range), "{why}");
            assert!(!why.contains("moves past"), "{why}");
        }
    }

    /// The end of the list, as each library says it. The other library's end
    /// is a refusal. The `ENOENT` a stopped `sssd` leaves is glibc's end.
    #[test]
    fn the_end_of_the_list_is_each_librarys_own() {
        assert_eq!(
            glibc(ReentrantReading::Absent { code: libc::ENOENT }),
            ReentrantStep::Settled(Step::End)
        );
        assert_eq!(
            bsd(ReentrantReading::Absent { code: 0 }),
            ReentrantStep::Settled(Step::End)
        );
        assert_eq!(step_errno(ErrnoReading::Empty { errno: 0 }), Step::End);

        assert!(
            refused(settled(glibc(ReentrantReading::Absent { code: 0 })))
                .contains("no entry and no end")
        );
        assert!(refused(settled(bsd(ReentrantReading::Absent {
            code: libc::ENOENT
        })))
        .contains("could not be read"));
        assert!(refused(step_errno(ErrnoReading::Empty {
            errno: libc::ENOENT
        }))
        .contains("could not be read"));
    }

    /// A real error refuses under every convention, naming the system's text.
    #[test]
    fn a_real_error_refuses() {
        let text = std::io::Error::from_raw_os_error(libc::EIO).to_string();
        let why = refused(settled(glibc(ReentrantReading::Absent { code: libc::EIO })));
        assert!(why.contains(&text), "{why}");
        let why = refused(settled(bsd(ReentrantReading::Absent { code: libc::EIO })));
        assert!(why.contains(&text), "{why}");
        let why = refused(step_errno(ErrnoReading::Empty { errno: libc::EIO }));
        assert!(why.contains(&text), "{why}");
    }

    /// A buffer too small: glibc returns the same entry again, so the reader
    /// grows and asks again. The BSDs have moved past it, so the walk
    /// refuses. `getpwent` has no caller buffer: `ERANGE` is a failed read,
    /// not a grow.
    #[test]
    fn a_buffer_too_small_grows_on_glibc_and_refuses_everywhere_else() {
        assert_eq!(
            glibc(ReentrantReading::Absent { code: libc::ERANGE }),
            ReentrantStep::Grow
        );
        let why = refused(settled(bsd(ReentrantReading::Absent {
            code: libc::ERANGE,
        })));
        assert!(why.contains("larger than"), "{why}");
        assert!(why.contains("moves past"), "{why}");
        let why = refused(step_errno(ErrnoReading::Empty {
            errno: libc::ERANGE,
        }));
        assert!(why.contains("could not be read"), "{why}");
        let text = std::io::Error::from_raw_os_error(libc::ERANGE).to_string();
        assert!(why.contains(&text), "{why}");
    }
}
