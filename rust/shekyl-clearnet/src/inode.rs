// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One descriptor per socket. The count is `readlink` results equal to
//! that socket's `socket:[inode]`, not every descriptor in the process.

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::path::Path;

/// How many open descriptors name the same socket as `fd`.
///
/// Linux publishes the inode in the `/proc/self/fd` link target. A split
/// that shares one file descriptor stays at one. A duplicate would not.
#[cfg(target_os = "linux")]
pub fn socket_descriptors(fd: RawFd) -> io::Result<usize> {
    let mine = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if link_matches(&entry.path(), &mine) {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

#[cfg(target_os = "linux")]
fn link_matches(path: &Path, mine: &Path) -> bool {
    std::fs::read_link(path).is_ok_and(|link| link == mine)
}

/// Unix builds other than Linux have no `/proc` inode to count. The
/// check is the Linux one D11 names.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn socket_descriptors(_fd: RawFd) -> io::Result<usize> {
    Ok(1)
}
