// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The metrics sink — the measurement RD-F11 made part of E2's deliverable.
//!
//! `RANDOMX_V2_RUST.md` §9 left the verifier's full-dataset mode unbuilt
//! **pending measured need**, and `RANDOMX_V2_MINING_ASYMMETRY.md` option (a)
//! revisits it on a measurement nobody had an instrument to take. The
//! replay driver is the first workload that runs RandomX verification at
//! volume over a real chain, so the number arrives with it: light-mode
//! wall-clock **per hash** (inside [`ChainSubstrate::longhash`]) and **per
//! block** (the whole stateless stage), with the cache derivations counted
//! and timed apart — a derive is the 256 MiB Argon2d fill and dominates the
//! first block of every seed epoch, and a per-hash mean that folded it in
//! would misstate both numbers.
//!
//! Recorded, not judged: whether Shekyl wants the dataset mode is decided
//! on this artifact, by whoever owns that decision, against the
//! provisioning floor (rule 76) — which is why the artifact carries the
//! host it was measured on rather than pretending to be the floor.
//!
//! Lock-free counters (`AtomicU64`, relaxed): N `form` workers hash
//! concurrently and the sink must not serialize them into the number it is
//! measuring.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

/// The artifact's schema.
pub const METRICS_SCHEMA: &str = "shekyl_e2_metrics_v1";

/// Running totals, updated from many threads without a lock.
#[derive(Debug, Default)]
pub struct Metrics {
    hashes: AtomicU64,
    hash_ns: AtomicU64,
    hash_ns_min: AtomicU64,
    hash_ns_max: AtomicU64,
    derives: AtomicU64,
    derive_ns: AtomicU64,
    blocks_formed: AtomicU64,
    form_ns: AtomicU64,
}

fn observe(count: &AtomicU64, total: &AtomicU64, d: Duration) {
    count.fetch_add(1, Ordering::Relaxed);
    total.fetch_add(ns(d), Ordering::Relaxed);
}

fn ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Metrics {
    /// Fresh counters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hash_ns_min: AtomicU64::new(u64::MAX),
            ..Self::default()
        }
    }

    /// One `compute_hash` call took `d` (the derive, if any, excluded).
    pub fn hashed(&self, d: Duration) {
        observe(&self.hashes, &self.hash_ns, d);
        let n = ns(d);
        self.hash_ns_min.fetch_min(n, Ordering::Relaxed);
        self.hash_ns_max.fetch_max(n, Ordering::Relaxed);
    }

    /// One cache derivation (a seed epoch's first use) took `d`.
    pub fn derived(&self, d: Duration) {
        observe(&self.derives, &self.derive_ns, d);
    }

    /// One block's stateless stage took `d` end to end.
    pub fn block_formed(&self, d: Duration) {
        observe(&self.blocks_formed, &self.form_ns, d);
    }

    /// Time `f` as one hash.
    pub fn timed_hash<T>(&self, f: impl FnOnce() -> T) -> T {
        let t = Instant::now();
        let out = f();
        self.hashed(t.elapsed());
        out
    }

    /// Time `f` as one derive.
    pub fn timed_derive<T>(&self, f: impl FnOnce() -> T) -> T {
        let t = Instant::now();
        let out = f();
        self.derived(t.elapsed());
        out
    }

    /// The artifact, as of now.
    #[must_use]
    pub fn snapshot(&self) -> MetricsArtifact {
        let hashes = self.hashes.load(Ordering::Relaxed);
        let hash_ns = self.hash_ns.load(Ordering::Relaxed);
        let derives = self.derives.load(Ordering::Relaxed);
        let derive_ns = self.derive_ns.load(Ordering::Relaxed);
        let blocks = self.blocks_formed.load(Ordering::Relaxed);
        let form_ns = self.form_ns.load(Ordering::Relaxed);
        let mean = |total: u64, n: u64| if n == 0 { None } else { Some(total / n) };
        MetricsArtifact {
            schema_version: METRICS_SCHEMA,
            host: Host::this(),
            mode: "light (cache-only; no dataset)",
            hashes,
            hash_ns_total: hash_ns,
            hash_ns_mean: mean(hash_ns, hashes),
            hash_ns_min: (hashes > 0).then(|| self.hash_ns_min.load(Ordering::Relaxed)),
            hash_ns_max: (hashes > 0).then(|| self.hash_ns_max.load(Ordering::Relaxed)),
            cache_derives: derives,
            derive_ns_total: derive_ns,
            derive_ns_mean: mean(derive_ns, derives),
            blocks_formed: blocks,
            form_ns_total: form_ns,
            form_ns_mean: mean(form_ns, blocks),
        }
    }
}

/// Where the numbers were taken. Not the provisioning floor unless it
/// says so; a reader compares against the floor, never assumes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Host {
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
    /// `std::env::consts::OS`.
    pub os: &'static str,
    /// `available_parallelism`, when the platform reports it.
    pub threads: Option<usize>,
}

impl Host {
    fn this() -> Self {
        Self {
            arch: std::env::consts::ARCH,
            os: std::env::consts::OS,
            threads: std::thread::available_parallelism().ok().map(usize::from),
        }
    }
}

/// The measurement RD-F11 asked for, as the dataset-mode decision reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetricsArtifact {
    /// [`METRICS_SCHEMA`].
    pub schema_version: &'static str,
    /// The measuring host.
    pub host: Host,
    /// Which verifier mode ran.
    pub mode: &'static str,
    /// `compute_hash` calls.
    pub hashes: u64,
    /// Wall-clock over all hashes, nanoseconds, derives excluded.
    pub hash_ns_total: u64,
    /// Per hash.
    pub hash_ns_mean: Option<u64>,
    /// Fastest hash.
    pub hash_ns_min: Option<u64>,
    /// Slowest hash.
    pub hash_ns_max: Option<u64>,
    /// Cache derivations (one per seed epoch first met).
    pub cache_derives: u64,
    /// Wall-clock over all derives.
    pub derive_ns_total: u64,
    /// Per derive.
    pub derive_ns_mean: Option<u64>,
    /// Blocks through the stateless stage.
    pub blocks_formed: u64,
    /// Wall-clock over all `form`s (hashing included).
    pub form_ns_total: u64,
    /// Per block.
    pub form_ns_mean: Option<u64>,
}

impl Default for MetricsArtifact {
    /// Nothing measured yet, on this host.
    fn default() -> Self {
        Metrics::new().snapshot()
    }
}

impl MetricsArtifact {
    /// The artifact as JSON.
    ///
    /// # Errors
    ///
    /// Serialization only.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_means_and_extremes_and_the_empty_artifact_has_no_means() {
        let m = Metrics::new();
        let empty = m.snapshot();
        assert_eq!(empty.hashes, 0);
        assert_eq!(empty.hash_ns_mean, None);
        assert_eq!(empty.hash_ns_min, None);
        m.hashed(Duration::from_nanos(100));
        m.hashed(Duration::from_nanos(300));
        m.derived(Duration::from_millis(2));
        m.block_formed(Duration::from_nanos(1_000));
        let s = m.snapshot();
        assert_eq!(s.hashes, 2);
        assert_eq!(s.hash_ns_total, 400);
        assert_eq!(s.hash_ns_mean, Some(200));
        assert_eq!((s.hash_ns_min, s.hash_ns_max), (Some(100), Some(300)));
        assert_eq!(s.cache_derives, 1);
        assert_eq!(s.derive_ns_mean, Some(2_000_000));
        assert_eq!((s.blocks_formed, s.form_ns_mean), (1, Some(1_000)));
        assert_eq!(s.schema_version, METRICS_SCHEMA);
        assert!(s.to_json().expect("json").contains("shekyl_e2_metrics_v1"));
    }

    #[test]
    fn timed_wrappers_return_the_value_and_count_once() {
        let m = Metrics::new();
        assert_eq!(m.timed_hash(|| 7), 7);
        assert_eq!(m.timed_derive(|| "d"), "d");
        let s = m.snapshot();
        assert_eq!((s.hashes, s.cache_derives), (1, 1));
    }
}
