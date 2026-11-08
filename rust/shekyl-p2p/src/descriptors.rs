// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The process descriptor probe and the inbound ceiling it yields.
//!
//! `shekyl-peer-policy` owns the arithmetic ([`InboundCeiling::resolve`]).
//! This module owns the observation: `getrlimit` on POSIX, `/proc/self/fd`
//! on Linux, and the named absence of a per-process ceiling on Windows. The
//! probe describes the process at the moment of the call. The network takes
//! it once, before its listeners bind, and reserves them with the rest
//! ([`crate::NetworkPlan::listener_descriptors`]).
//!
//! The one `unsafe` in this crate is `getrlimit`; it is scoped to this
//! module.

#![allow(unsafe_code)]

use shekyl_peer_policy::{DescriptorLimit, DescriptorSnapshot, InboundCeiling};

/// Descriptors the managed Tor's probe holds while it runs
/// (`TOR_SUPERVISOR.md` §4.5): one dial at a time.
pub const PROBE_DESCRIPTORS: u64 = 1;

/// The inbound ceiling for this process now: its descriptor limit less what
/// it holds and the `reserved` descriptors its owner has promised but not
/// opened, with no inbound held yet.
#[must_use]
pub fn inbound_ceiling(reserved: u64) -> InboundCeiling {
    InboundCeiling::resolve(observe_descriptors(), reserved, 0)
}

/// The descriptor limit and count, as this platform can read them.
#[must_use]
pub fn observe_descriptors() -> DescriptorSnapshot {
    #[cfg(windows)]
    {
        DescriptorSnapshot {
            limit: DescriptorLimit::NoPerProcessLimit,
            held: None,
        }
    }
    #[cfg(unix)]
    {
        observe_unix()
    }
    #[cfg(not(any(windows, unix)))]
    {
        DescriptorSnapshot {
            limit: DescriptorLimit::LimitUnreadable,
            held: None,
        }
    }
}

#[cfg(unix)]
fn observe_unix() -> DescriptorSnapshot {
    DescriptorSnapshot {
        limit: read_soft_nofile(),
        held: count_open_descriptors(),
    }
}

#[cfg(unix)]
fn read_soft_nofile() -> DescriptorLimit {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live `rlimit` and `RLIMIT_NOFILE` is the
    // resource this probe is defined to read. `getrlimit` writes only
    // that struct.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
    if rc != 0 {
        return DescriptorLimit::LimitUnreadable;
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return DescriptorLimit::Unlimited;
    }
    // `rlim_t` is unsigned on Linux and signed on FreeBSD. Widen first so
    // both compile, then refuse a value that is not a usable soft limit.
    let wide = i128::from(limit.rlim_cur);
    if wide < 0 {
        return DescriptorLimit::LimitUnreadable;
    }
    let Ok(soft) = u64::try_from(wide) else {
        return DescriptorLimit::LimitUnreadable;
    };
    DescriptorLimit::Soft(soft)
}

/// Open descriptors, or `None` when this platform cannot count them.
///
/// Linux reads `/proc/self/fd`, which a process may read for itself where
/// `/proc/<pid>/fd` is refused. The directory handle is one of the names
/// counted and is closed before the result is returned, so it is not
/// charged. Any unreadable entry fails the count: an undercount would
/// inflate the ceiling.
#[cfg(target_os = "linux")]
fn count_open_descriptors() -> Option<u64> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    let mut open = 0u64;
    for entry in entries {
        entry.ok()?;
        open = open.saturating_add(1);
    }
    Some(open.saturating_sub(1))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn count_open_descriptors() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_probe_returns_a_finite_ceiling() {
        let snapshot = observe_descriptors();
        let DescriptorLimit::Soft(soft) = snapshot.limit else {
            panic!("a Linux test process has a soft NOFILE limit");
        };
        let held = snapshot.held.expect("Linux counts /proc/self/fd");
        assert!(soft > 0);
        assert!(held > 0);
        assert!(held <= soft);
        // Resolved from this snapshot: a second probe would count what the
        // other tests in this binary hold at that instant.
        assert_eq!(
            InboundCeiling::resolve(snapshot, 0, 0),
            InboundCeiling::Bounded(u32::try_from(soft - held).expect("fits"))
        );
        assert!(matches!(inbound_ceiling(0), InboundCeiling::Bounded(_)));
    }

    #[test]
    fn a_reservation_lowers_the_ceiling() {
        // One snapshot: a second probe would count the descriptors the
        // other tests in this binary hold at that instant.
        let snapshot = observe_descriptors();
        let InboundCeiling::Bounded(free) = InboundCeiling::resolve(snapshot, 0, 0) else {
            return;
        };
        if free < 2 {
            return;
        }
        assert_eq!(
            InboundCeiling::resolve(snapshot, 1, 0),
            InboundCeiling::Bounded(free - 1)
        );
    }
}
