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
//! reader. It asks [`sys`] for `getgrgid_r`, `getpwuid_r` and the account
//! walk, which rustix does not wrap; [`sys`] is the one place after `acl`
//! where the crate's `unsafe_code` deny is lifted. A name is the bytes the
//! system returned.
//!
//! What the walk sees is what the name service enumerates: a directory
//! service configured not to enumerate its accounts reports none and no
//! error, and so does one that is stopped (glibc reports an unavailable
//! service as the end of its list). The walk cannot see past that; the
//! operator docs say the daemon's group must stay a local group.
//!
//! Each step of the walk is judged by [`step`], a pure function of the
//! reading the library returned. The process-wide cursor that walk holds
//! is [`sys`]'s.

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

/// The login name of `uid`, when the password database has it.
#[must_use]
pub(crate) fn login_name(uid: u32) -> Option<AccountName> {
    sys::account(uid).ok().map(|account| account.name)
}

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

mod step;

/// The libc reads. rustix has no API for them, so this module is where the
/// crate's `unsafe_code` deny is lifted.
#[allow(unsafe_code)]
mod sys;

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

    /// Two threads may ask at once: the walks take turns on the cursor lock
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
