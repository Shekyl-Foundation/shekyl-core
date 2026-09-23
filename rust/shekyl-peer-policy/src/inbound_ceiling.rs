// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The inbound **safety** bound: how many inbound connections this process
//! can hold without exhausting its descriptors.
//!
//! This is not a policy ceiling. A policy ceiling would be a network-wide
//! choice about how much service to offer below the safety bound; nothing
//! here makes that choice. The inputs are a descriptor observation and the
//! count of descriptors the process has already promised elsewhere.
//!
//! # The observation is tagged
//!
//! A soft limit of zero is a real limit: the process may open nothing more,
//! and the ceiling is zero. A failed probe is a different value, and so is
//! "this platform has no per-process ceiling". Collapsing those into one
//! sentinel is what turns "cannot read" and "limit is zero" into the same
//! unbounded admission.

/// What the operating system reported about this process's descriptor limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorLimit {
    /// `RLIMIT_NOFILE`'s soft limit. Zero means the process may open nothing.
    Soft(u64),
    /// The soft limit is `RLIM_INFINITY`.
    Unlimited,
    /// The platform has no per-process descriptor ceiling to read.
    NoPerProcessLimit,
    /// `getrlimit` failed, or this platform cannot answer it.
    LimitUnreadable,
}

/// One probe: the limit, and how many descriptors were open when it was taken.
///
/// `held` is `None` when the open-descriptor count could not be taken. A
/// missing count is not zero — zero would be a process holding nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorSnapshot {
    pub limit: DescriptorLimit,
    /// Descriptors open at probe time, excluding the probe's own directory
    /// handle once that handle has been closed.
    pub held: Option<u64>,
}

/// Why no enforceable ceiling could be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnboundedReason {
    /// See [`DescriptorLimit::NoPerProcessLimit`].
    NoPerProcessLimit,
    /// See [`DescriptorLimit::Unlimited`].
    Unlimited,
    /// See [`DescriptorLimit::LimitUnreadable`].
    LimitUnreadable,
    /// The limit was read and the open-descriptor count was not.
    CountUnreadable,
    /// Headroom does not fit the 32-bit admission counter, so every value
    /// that counter can store would still admit.
    ExceedsCounter,
}

/// The admission decision for public inbound, and the process-wide backstop
/// when the operator left `--in-peers` unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundCeiling {
    /// Admit at most this many inbound connections. Zero admits none.
    Bounded(u32),
    /// No finite ceiling. The caller says which reason, and does not invent
    /// a number.
    Unbounded(UnboundedReason),
}

impl InboundCeiling {
    /// `reserved` is descriptors promised but not yet open: outbound caps,
    /// explicit inbound caps on zones other than the one being resolved, and
    /// any budget another subsystem has already claimed.
    ///
    /// Headroom is `soft - held - reserved`, saturating at zero. A result
    /// that does not fit `u32` is [`UnboundedReason::ExceedsCounter`], because
    /// storing `u32::MAX` in the admission counter would never refuse.
    #[must_use]
    /// `inbound_held` is how many of `snapshot.held` are sockets belonging to
    /// inbound connections this node has already accepted.
    ///
    /// **They are added back before the subtraction, and that is what makes
    /// this derivation independent of load.** The ceiling bounds *inbound*,
    /// and the caller compares live inbound against it — so leaving those
    /// descriptors inside `held` would charge them on both sides: once as
    /// consumed headroom, once as connections measured against the reduced
    /// result. The ceiling would then depend on how many peers happened to be
    /// connected at the moment it was derived, halving as the node filled,
    /// and a re-derive on a busy node could refuse every further peer.
    ///
    /// Deriving at startup hid this, because nothing was connected yet. It
    /// stopped being hidden when a runtime `out_peers` change began
    /// re-deriving under load.
    pub fn resolve(snapshot: DescriptorSnapshot, reserved: u64, inbound_held: u64) -> Self {
        let limit = match snapshot.limit {
            DescriptorLimit::NoPerProcessLimit => {
                return Self::Unbounded(UnboundedReason::NoPerProcessLimit);
            }
            DescriptorLimit::Unlimited => {
                return Self::Unbounded(UnboundedReason::Unlimited);
            }
            DescriptorLimit::LimitUnreadable => {
                return Self::Unbounded(UnboundedReason::LimitUnreadable);
            }
            DescriptorLimit::Soft(limit) => limit,
        };
        let Some(held) = snapshot.held else {
            return Self::Unbounded(UnboundedReason::CountUnreadable);
        };
        // Inbound sockets are not spent headroom from this bound's point of
        // view -- they are what it measures.
        let held_excluding_inbound = held.saturating_sub(inbound_held);
        let headroom = limit.saturating_sub(held_excluding_inbound.saturating_add(reserved));
        match u32::try_from(headroom) {
            Ok(ceiling) => Self::Bounded(ceiling),
            Err(_) => Self::Unbounded(UnboundedReason::ExceedsCounter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DescriptorLimit, DescriptorSnapshot, InboundCeiling, UnboundedReason};

    fn soft(limit: u64, held: u64) -> DescriptorSnapshot {
        DescriptorSnapshot {
            limit: DescriptorLimit::Soft(limit),
            held: Some(held),
        }
    }

    #[test]
    fn headroom_is_the_limit_minus_what_is_open_and_promised() {
        assert_eq!(
            InboundCeiling::resolve(soft(1024, 64), 12, 0),
            InboundCeiling::Bounded(948)
        );
    }

    #[test]
    fn a_soft_limit_of_zero_admits_nothing() {
        // Distinct from a failed probe: the OS answered, and the answer is none.
        assert_eq!(
            InboundCeiling::resolve(soft(0, 0), 0, 0),
            InboundCeiling::Bounded(0)
        );
    }

    #[test]
    fn commitments_past_the_limit_saturate_at_zero() {
        assert_eq!(
            InboundCeiling::resolve(soft(64, 64), 32, 0),
            InboundCeiling::Bounded(0)
        );
    }

    #[test]
    fn every_promised_descriptor_costs_one_slot() {
        let without = InboundCeiling::resolve(soft(1024, 64), 0, 0);
        let with = InboundCeiling::resolve(soft(1024, 64), 64, 0);
        assert_eq!(without, InboundCeiling::Bounded(960));
        assert_eq!(with, InboundCeiling::Bounded(896));
    }

    #[test]
    fn a_raised_finite_limit_is_honoured() {
        assert_eq!(
            InboundCeiling::resolve(soft(524_288, 64), 12, 0),
            InboundCeiling::Bounded(524_212)
        );
    }

    #[test]
    fn headroom_past_the_admission_counter_is_not_stored_as_u32_max() {
        let snapshot = DescriptorSnapshot {
            limit: DescriptorLimit::Soft(u64::MAX),
            held: Some(0),
        };
        assert_eq!(
            InboundCeiling::resolve(snapshot, 0, 0),
            InboundCeiling::Unbounded(UnboundedReason::ExceedsCounter)
        );
    }

    #[test]
    fn an_unlimited_rlimit_is_unbounded() {
        let snapshot = DescriptorSnapshot {
            limit: DescriptorLimit::Unlimited,
            held: Some(12),
        };
        assert_eq!(
            InboundCeiling::resolve(snapshot, 0, 0),
            InboundCeiling::Unbounded(UnboundedReason::Unlimited)
        );
    }

    #[test]
    fn a_platform_with_no_per_process_ceiling_is_unbounded() {
        let snapshot = DescriptorSnapshot {
            limit: DescriptorLimit::NoPerProcessLimit,
            held: None,
        };
        assert_eq!(
            InboundCeiling::resolve(snapshot, 0, 0),
            InboundCeiling::Unbounded(UnboundedReason::NoPerProcessLimit)
        );
    }

    #[test]
    fn a_failed_limit_read_is_unbounded() {
        let snapshot = DescriptorSnapshot {
            limit: DescriptorLimit::LimitUnreadable,
            held: Some(4),
        };
        assert_eq!(
            InboundCeiling::resolve(snapshot, 0, 0),
            InboundCeiling::Unbounded(UnboundedReason::LimitUnreadable)
        );
    }

    #[test]
    fn a_missing_descriptor_count_is_not_zero_held() {
        let snapshot = DescriptorSnapshot {
            limit: DescriptorLimit::Soft(4096),
            held: None,
        };
        assert_eq!(
            InboundCeiling::resolve(snapshot, 0, 0),
            InboundCeiling::Unbounded(UnboundedReason::CountUnreadable)
        );
    }

    #[test]
    fn live_inbound_does_not_shrink_the_ceiling_that_measures_it() {
        // The property the runtime re-derive needs: deriving under load must
        // give the same answer as deriving at rest. An inbound socket sits
        // inside `held`, so without excluding it the ceiling would fall by one
        // for every peer already connected -- charged as spent headroom AND
        // measured against the smaller result.
        let at_rest = InboundCeiling::resolve(soft(1024, 64), 12, 0);
        let under_load = InboundCeiling::resolve(soft(1024, 64 + 300), 12, 300);
        assert_eq!(
            at_rest, under_load,
            "the ceiling must not depend on how many peers were connected when it was derived"
        );
    }

    #[test]
    fn excluding_inbound_never_underflows_or_inflates() {
        // A count larger than `held` cannot mint headroom: saturating
        // subtraction floors it, so the worst case is the whole held set
        // excluded, never a negative that wraps into a huge ceiling.
        let absurd = InboundCeiling::resolve(soft(1024, 64), 12, u64::MAX);
        assert_eq!(absurd, InboundCeiling::Bounded(1024 - 12));
    }
}
