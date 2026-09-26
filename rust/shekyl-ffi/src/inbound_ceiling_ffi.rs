// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Process descriptor probe and the inbound-ceiling decision, as one call.
//!
//! [`shekyl-peer-policy`] owns the arithmetic. This module owns the
//! observation: `getrlimit` on POSIX, `/proc/self/fd` on Linux, and the
//! named absence of a per-process ceiling on Windows. The C++ caller passes
//! only the descriptors it has already promised and invokes this **after**
//! the listeners it wants counted are open — the probe describes the
//! process at the moment of the call.

use shekyl_peer_policy::{DescriptorLimit, DescriptorSnapshot, InboundCeiling, UnboundedReason};

/// C ABI discriminant. Zero is not a kind: a zeroed struct is not
/// [`SHEKYL_INBOUND_CEILING_BOUNDED`]. Keep these in lockstep with
/// `SHEKYL_INBOUND_CEILING_*` in `src/shekyl/shekyl_ffi.h`.
pub const SHEKYL_INBOUND_CEILING_BOUNDED: u32 = 1;
pub const SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT: u32 = 2;
pub const SHEKYL_INBOUND_CEILING_UNLIMITED: u32 = 3;
pub const SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE: u32 = 4;
pub const SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE: u32 = 5;
pub const SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER: u32 = 6;

/// Decision plus the observation the log line quotes.
///
/// Layout is `#[repr(C)]`: two `u32` then two `u64`, 24 bytes, no padding.
/// `soft_limit` is meaningful when the limit was a soft limit, including
/// when the count then failed. `held` is meaningful when the count was
/// taken. The `kind` says which.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShekylInboundCeiling {
    pub kind: u32,
    pub ceiling: u32,
    pub soft_limit: u64,
    pub held: u64,
}

/// Resolve the inbound safety bound from this process and `reserved`.
///
/// `reserved` is descriptors the caller has promised but not opened.
///
/// `inbound_held` is how many descriptors this process currently spends on
/// inbound connections it has already accepted. They are excluded from the
/// observed count, because this bound MEASURES inbound: leaving them in would
/// charge them twice and make the answer depend on how loaded the node was
/// when the call happened. Pass `0` when nothing is connected yet.
///
/// # Safety
///
/// `out` must be non-null and point at a writable [`ShekylInboundCeiling`]
/// for the duration of the call. A null `out` returns without writing.
#[no_mangle]
pub unsafe extern "C" fn shekyl_inbound_ceiling_resolve(
    reserved: u64,
    inbound_held: u64,
    out: *mut ShekylInboundCeiling,
) {
    if out.is_null() {
        return;
    }
    let snapshot = observe_descriptors();
    let ceiling = InboundCeiling::resolve(snapshot, reserved, inbound_held);
    // SAFETY: `out` is non-null and the caller guarantees it is writable
    // for one `ShekylInboundCeiling`.
    unsafe {
        out.write(to_abi(snapshot, ceiling));
    }
}

fn to_abi(snapshot: DescriptorSnapshot, ceiling: InboundCeiling) -> ShekylInboundCeiling {
    let soft_limit = match snapshot.limit {
        DescriptorLimit::Soft(limit) => limit,
        DescriptorLimit::Unlimited
        | DescriptorLimit::NoPerProcessLimit
        | DescriptorLimit::LimitUnreadable => 0,
    };
    let held = snapshot.held.unwrap_or(0);
    let (kind, ceiling) = match ceiling {
        InboundCeiling::Bounded(ceiling) => (SHEKYL_INBOUND_CEILING_BOUNDED, ceiling),
        InboundCeiling::Unbounded(UnboundedReason::NoPerProcessLimit) => {
            (SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT, 0)
        }
        InboundCeiling::Unbounded(UnboundedReason::Unlimited) => {
            (SHEKYL_INBOUND_CEILING_UNLIMITED, 0)
        }
        InboundCeiling::Unbounded(UnboundedReason::LimitUnreadable) => {
            (SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE, 0)
        }
        InboundCeiling::Unbounded(UnboundedReason::CountUnreadable) => {
            (SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE, 0)
        }
        InboundCeiling::Unbounded(UnboundedReason::ExceedsCounter) => {
            (SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER, 0)
        }
    };
    ShekylInboundCeiling {
        kind,
        ceiling,
        soft_limit,
        held,
    }
}

fn observe_descriptors() -> DescriptorSnapshot {
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
    use super::{
        ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_BOUNDED,
        SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE, SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER,
        SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE, SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT,
        SHEKYL_INBOUND_CEILING_UNLIMITED,
    };

    #[test]
    fn abi_layout_matches_the_header() {
        assert_eq!(std::mem::size_of::<ShekylInboundCeiling>(), 24);
        assert_eq!(std::mem::align_of::<ShekylInboundCeiling>(), 8);
        assert_eq!(std::mem::offset_of!(ShekylInboundCeiling, kind), 0);
        assert_eq!(std::mem::offset_of!(ShekylInboundCeiling, ceiling), 4);
        assert_eq!(std::mem::offset_of!(ShekylInboundCeiling, soft_limit), 8);
        assert_eq!(std::mem::offset_of!(ShekylInboundCeiling, held), 16);
        // The header's constexpr values. A zero kind is deliberately unused.
        assert_eq!(SHEKYL_INBOUND_CEILING_BOUNDED, 1);
        assert_eq!(SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT, 2);
        assert_eq!(SHEKYL_INBOUND_CEILING_UNLIMITED, 3);
        assert_eq!(SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE, 4);
        assert_eq!(SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE, 5);
        assert_eq!(SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER, 6);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_probe_returns_a_finite_ceiling() {
        let mut out = ShekylInboundCeiling {
            kind: 0,
            ceiling: 0,
            soft_limit: 0,
            held: 0,
        };
        // SAFETY: `out` is a live local.
        unsafe { super::shekyl_inbound_ceiling_resolve(0, 0, &raw mut out) };
        assert_eq!(out.kind, SHEKYL_INBOUND_CEILING_BOUNDED);
        assert!(out.soft_limit > 0);
        assert!(out.held > 0);
        assert!(out.held <= out.soft_limit);
        assert_eq!(u64::from(out.ceiling), out.soft_limit - out.held);
    }
}
