// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The calling account, as the configuration check names it (IG-Q60):
//! exit 0 certifies this account in this environment, and the success line
//! says which.

/// The account the process runs as: the login name and uid on Unix, the
/// SID on Windows. Never empty; an account the database cannot name is
/// its number.
#[must_use]
pub fn current() -> String {
    describe()
}

/// Whether the process runs as uid 0. The check run as root certifies
/// root's account, which the success line warns about (IG-Q60). Windows
/// has no uid 0; elevation is not root.
#[must_use]
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn describe() -> String {
    let uid = rustix::process::geteuid().as_raw();
    match crate::group::login_name(uid) {
        Some(name) => format!("{name} (uid {uid})"),
        None => format!("uid {uid}"),
    }
}

#[cfg(windows)]
fn describe() -> String {
    match shekyl_win_sec::sid::current_user_sid() {
        Ok(sid) => sid.as_str().to_owned(),
        Err(e) => format!("an account whose SID could not be read ({e})"),
    }
}

#[cfg(not(any(unix, windows)))]
fn describe() -> String {
    "an account this platform does not name".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_is_named_and_root_is_told_apart() {
        let me = current();
        assert!(!me.is_empty());
        #[cfg(unix)]
        {
            let uid = rustix::process::geteuid().as_raw();
            assert!(me.contains(&format!("uid {uid}")), "{me}");
            assert_eq!(is_root(), uid == 0);
        }
    }
}
