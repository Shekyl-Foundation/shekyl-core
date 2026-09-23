// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How many inbound connections a node may hold — the **safety** bound.
//!
//! # Two ceilings, and conflating them is what produced the defect this replaces
//!
//! * **The safety bound (here).** *Do not exhaust the process.* It is
//!   **read from the operating system**, not chosen: the descriptor limit
//!   minus what this daemon is already using and what it has promised to
//!   outbound. It differs per deployment, and that is **correct** — it is a
//!   statement about one machine's actual limit, not about policy.
//! * **A policy ceiling.** *How much service we choose to provide*, below the
//!   safety bound. That would be a network-wide default, and **nothing here
//!   sets one.**
//!
//! `--in-peers` shipped as the sentinel `-1` narrowed into a `uint32_t`, so
//! the effective ceiling was `UINT32_MAX` and never fired. That was not a
//! policy choice, it was an unbounded interval nobody had noticed.
//!
//! # Why memory does not appear in this calculation
//!
//! Measured on the rule-76 floor device (`skl-pi`, Pi 4 Model B) and on a
//! development host, same instrument, 2026-09-22
//! (`shekyl-levin/tests/inbound_cost_bench.rs`): **119 live inbound
//! connections cost 360 KiB of RSS on the floor device**, a marginal of
//! 0.2 KiB by the top of the sweep, against a ~539 MiB startup peak that does
//! not move with connection count at all. A quiescent inbound connection is
//! free in memory; descriptors are what it actually consumes.
//!
//! *(The development host read ~91 KiB per connection for the same sweep.
//! That figure does not reproduce on the floor — baseline and peak agree
//! across the two machines within 12% and 0.2% — so it was measuring
//! something that scales with the host rather than with connection state.
//! Provisioning against it would have set a bound from an artifact of the
//! measuring machine.)*

/// The inbound descriptor ceiling, resolved from the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InboundCeiling(u32);

impl InboundCeiling {
    /// Resolve the safety bound from what the OS and the configuration say.
    ///
    /// * `soft_limit` — `RLIMIT_NOFILE`'s soft limit, the descriptor count
    ///   this process may actually reach.
    /// * `in_use` — descriptors already held after initialisation: the store,
    ///   the listeners, the log, the RPC surface. Counted, not estimated.
    /// * `reserved_outbound` — descriptors this node has promised to outbound
    ///   connections it may open later. Configured, so it is known rather
    ///   than guessed.
    ///
    /// **No transient margin is subtracted, and that is deliberate.**
    /// `in_use` is sampled *after* initialisation, so the steady descriptor
    /// set — store, listeners, log — is already inside it. What is left over
    /// is per-operation churn, and the store maps its file once at open
    /// rather than per transaction. Inventing a margin here would be exactly
    /// the picked number this whole derivation exists to avoid; if churn ever
    /// proves to matter, it is measurable and the reserve becomes measured
    /// too.
    ///
    /// Saturates at zero rather than wrapping. **Zero is a real answer** — a
    /// node with no descriptor headroom cannot serve inbound, and reporting
    /// that honestly is better than admitting connections it cannot keep.
    #[must_use]
    pub fn resolve(soft_limit: u64, in_use: u64, reserved_outbound: u64) -> Self {
        let committed = in_use.saturating_add(reserved_outbound);
        let headroom = soft_limit.saturating_sub(committed);
        Self(u32::try_from(headroom).unwrap_or(u32::MAX))
    }

    /// The resolved ceiling.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Does this node have descriptor headroom for inbound service at all?
    #[must_use]
    pub const fn serves_inbound(self) -> bool {
        self.0 > 0
    }
}

#[cfg(test)]
mod tests {
    use super::InboundCeiling;

    #[test]
    fn headroom_is_the_limit_minus_what_is_committed() {
        assert_eq!(InboundCeiling::resolve(1024, 64, 12).get(), 948);
    }

    #[test]
    fn a_node_with_no_headroom_serves_no_inbound_rather_than_wrapping() {
        // The subtraction must not wrap into a huge ceiling: that is the
        // failure mode `--in-peers -1` had, arriving by a different route.
        let c = InboundCeiling::resolve(64, 64, 32);
        assert_eq!(c.get(), 0);
        assert!(!c.serves_inbound());
    }

    #[test]
    fn a_raised_hard_limit_is_honoured_rather_than_clamped() {
        // An operator who raises LimitNOFILE gets the headroom they asked
        // for; this bound reads the machine, it does not impose a policy.
        assert_eq!(InboundCeiling::resolve(524_288, 64, 12).get(), 524_212);
    }

    #[test]
    fn an_absurd_limit_saturates_instead_of_truncating() {
        assert_eq!(InboundCeiling::resolve(u64::MAX, 0, 0).get(), u32::MAX);
    }

    #[test]
    fn outbound_is_reserved_before_inbound_is_offered() {
        let without = InboundCeiling::resolve(1024, 64, 0).get();
        let with = InboundCeiling::resolve(1024, 64, 64).get();
        assert_eq!(without - with, 64, "every promised outbound slot costs one");
    }
}
