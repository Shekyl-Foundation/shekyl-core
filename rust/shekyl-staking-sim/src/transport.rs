//! L16 — transport / latency-regime coupling.
//!
//! The firewalled-pseudonym requirement forces the heavy archival fetch onto
//! onion-service↔Tor-client rendezvous (the slowest Tor configuration). In this
//! sim that makes `fetch_latency_per_unit` the transport operating point on the
//! `L2–L6` band (L10 seating lag), and the slow read path depresses the
//! per-holder uptime the retrieval SLA sees (L15 availability).
//!
//! Post-testnet work calibrates *where* on the band live transport sits and the
//! depression constant `k`; L16 fixes the **coupling shape** only.

use crate::model::fetch_latency;

/// Representative deep-shard fetch latency in epochs for a transport-regime marker
/// `L` (the L10 `fetch_latency_per_unit` value at `deep_shard_size = 1`).
pub fn regime_latency_epochs(deep_shard_size: f64, latency_per_unit: f64) -> f64 {
    fetch_latency(true, deep_shard_size, latency_per_unit) as f64
}

/// Effective per-holder uptime under onion rendezvous.
///
/// A holder that is network-up still delivers fewer successful serves within an
/// outage window when every read traverses rendezvous hops. Model:
/// `u_eff = u_base / (1 + k · L)` clamped to `(0, 1]`, where `L` is the
/// representative deep fetch latency in epochs. At `L = 0` (no transport lag —
/// the inert / clearnet-hypothetical baseline) `u_eff = u_base`; each epoch of
/// fetch latency depresses `u` monotonically.
pub fn effective_uptime(u_base: f64, latency_epochs: f64, k: f64) -> f64 {
    if u_base <= 0.0 {
        return 0.0;
    }
    if latency_epochs <= 0.0 || k <= 0.0 {
        return u_base.min(1.0);
    }
    (u_base / (1.0 + k * latency_epochs)).clamp(f64::EPSILON, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_latency_preserves_base_uptime() {
        assert!((effective_uptime(0.9, 0.0, 0.07) - 0.9).abs() < 1e-12);
        assert!((effective_uptime(0.9, 6.0, 0.0) - 0.9).abs() < 1e-12);
    }

    #[test]
    fn latency_depresses_uptime_monotonically() {
        let u2 = effective_uptime(0.9, 2.0, 0.07);
        let u6 = effective_uptime(0.9, 6.0, 0.07);
        assert!(u2 < 0.9);
        assert!(u6 < u2);
    }

    #[test]
    fn regime_latency_matches_fetch_latency() {
        assert_eq!(regime_latency_epochs(1.0, 2.0), 2.0);
        assert_eq!(regime_latency_epochs(1.0, 0.0), 0.0);
    }
}
