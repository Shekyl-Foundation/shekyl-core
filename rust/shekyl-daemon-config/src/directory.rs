// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's judgments of a directory.
//!
//! What the path is — it exists, it is not a link, it is a directory, who
//! owns it, which permission bits are set — is read once, in
//! [`shekyl_os_account::directory`]. The mode rule stays with the caller:
//! a service home and the owner's socket directory are
//! [`shekyl_os_account::OWNER_ONLY_DIR_MODE`] exactly, a data directory and
//! a socket directory are refused when
//! [`shekyl_os_account::directory::DirectoryFacts::group_or_other_can_enter`]
//! is set, and a service rendezvous is refused when
//! [`shekyl_os_account::directory::DirectoryFacts::group_or_other_can_write`]
//! is set. This module keeps the judgment that is the daemon's alone: a
//! service does not run as root.

pub(crate) use shekyl_os_account::directory::{DirectoryFacts, DirectoryFault};
pub(crate) use shekyl_os_account::OWNER_ONLY_DIR_MODE;

/// The account a service refuses to run as.
const ROOT_ACCOUNT: u32 = 0;

/// A service runs as an ordinary account.
///
/// # Errors
///
/// The daemon's effective uid is root.
pub(crate) fn require_service_account(account: u32) -> Result<(), String> {
    if account == ROOT_ACCOUNT {
        Err("the daemon runs as root".to_owned())
    } else {
        Ok(())
    }
}
