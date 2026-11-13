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
//! wall-clock **per hash** (inside a hashing job's longhash) and **per
//! block** (the whole stateless stage), with the cache derivations counted
//! and timed apart — a derive is the 256 MiB Argon2d fill and dominates the
//! first block of every seed epoch, and a per-hash mean that folded it in
//! would misstate both numbers. This sink does not count derives: the
//! hasher does, and [`Metrics::snapshot`] is handed its count
//! ([`Derives`]), so a derive has one source.
//!
//! Recorded, not judged: whether Shekyl wants the dataset mode is decided
//! on this artifact, by whoever owns that decision, against the
//! provisioning floor (rule 76) — which is why the artifact carries the
//! host it was measured on rather than pretending to be the floor.
//!
//! Lock-free counters (`AtomicU64`, relaxed): N `form` workers hash
//! concurrently and the sink must not serialize them into the number it is
//! measuring.
//!
//! The artifact also carries the **concurrency it was measured at**
//! ([`Concurrency`]): light mode is memory-bound, so the per-hash wall
//! grows with the number of hashers sharing the host (the first run
//! measured 0.34 s at one hasher and 0.64 s at sixteen on a 16-thread
//! box), and a per-hash figure without its hasher count is not a
//! measurement of the verifier.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde::Serialize;

/// The artifact's schema. `v2` added [`MetricsArtifact::concurrency`];
/// `v3` added the live sync's phases (chain sync's transit and entry, the
/// connector's apply); `v4` added each response's bytes, the header
/// responses, and the door's seat wait per body span; `v5` reads the
/// derives from the hasher and replaces the wait for another thread's
/// derive with each job's wait for its lease.
///
/// Totals only, no derived rate: a per-response minimum rate would be
/// dominated by tiny tip replies. The model's deadline is `transit +
/// bytes / SYNC_RATE_FLOOR`, so the floor is throughput after the round
/// trip, which only the owner's per-response debug lines can separate.
pub const METRICS_SCHEMA: &str = "shekyl_e2_metrics_v5";

/// How many workers shared the host while the numbers were taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Concurrency {
    /// `form` workers hashing at once (`PipelineConfig::hashers`).
    pub hashers: usize,
    /// Blocks formed ahead of the writer (`PipelineConfig::window`).
    pub window: usize,
}

/// The hasher's derive count and time (`shekyl_hasher::Resident::builds`
/// and `build_ns`): the artifact's one source for both. A sink over no
/// hasher reports none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Derives {
    /// Caches derived since the hasher started.
    pub builds: u64,
    /// Nanoseconds those derives took, summed.
    pub build_ns: u64,
}

/// Running totals, updated from many threads without a lock.
#[derive(Debug)]
pub struct Metrics {
    /// Set once by the pipeline at the start of a run; `None` in a sink no
    /// pipeline has run over.
    concurrency: OnceLock<Concurrency>,
    hashes: AtomicU64,
    hash_ns: AtomicU64,
    hash_ns_min: AtomicU64,
    hash_ns_max: AtomicU64,
    leases: AtomicU64,
    lease_wait_ns: AtomicU64,
    blocks_formed: AtomicU64,
    form_ns: AtomicU64,
    applies: AtomicU64,
    applied_blocks: AtomicU64,
    apply_ns: AtomicU64,
    transit_spans: AtomicU64,
    transit_blocks: AtomicU64,
    transit_bytes: AtomicU64,
    transit_ns: AtomicU64,
    header_responses: AtomicU64,
    header_bytes: AtomicU64,
    header_ns: AtomicU64,
    seated_spans: AtomicU64,
    seat_waits: AtomicU64,
    seat_wait_ns: AtomicU64,
    seat_wait_ns_max: AtomicU64,
    entries: AtomicU64,
    entry_ns: AtomicU64,
}

fn observe(count: &AtomicU64, total: &AtomicU64, d: Duration) {
    count.fetch_add(1, Ordering::Relaxed);
    total.fetch_add(ns(d), Ordering::Relaxed);
}

fn ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Fresh counters. `hash_ns_min` starts at `u64::MAX` so the first hash
    /// sets it; a derived `Default` would start it at zero and report a
    /// minimum no hash produced.
    #[must_use]
    pub fn new() -> Self {
        Self {
            concurrency: OnceLock::new(),
            hashes: AtomicU64::new(0),
            hash_ns: AtomicU64::new(0),
            hash_ns_min: AtomicU64::new(u64::MAX),
            hash_ns_max: AtomicU64::new(0),
            leases: AtomicU64::new(0),
            lease_wait_ns: AtomicU64::new(0),
            blocks_formed: AtomicU64::new(0),
            form_ns: AtomicU64::new(0),
            applies: AtomicU64::new(0),
            applied_blocks: AtomicU64::new(0),
            apply_ns: AtomicU64::new(0),
            transit_spans: AtomicU64::new(0),
            transit_blocks: AtomicU64::new(0),
            transit_bytes: AtomicU64::new(0),
            transit_ns: AtomicU64::new(0),
            header_responses: AtomicU64::new(0),
            header_bytes: AtomicU64::new(0),
            header_ns: AtomicU64::new(0),
            seated_spans: AtomicU64::new(0),
            seat_waits: AtomicU64::new(0),
            seat_wait_ns: AtomicU64::new(0),
            seat_wait_ns_max: AtomicU64::new(0),
            entries: AtomicU64::new(0),
            entry_ns: AtomicU64::new(0),
        }
    }

    /// The concurrency a run is about to measure under. The first call
    /// stands: a sink measures one run.
    pub fn configured(&self, concurrency: Concurrency) {
        let _first_stands = self.concurrency.set(concurrency);
    }

    /// One `compute_hash` call took `d` (the derive, if any, excluded).
    pub fn hashed(&self, d: Duration) {
        observe(&self.hashes, &self.hash_ns, d);
        let n = ns(d);
        self.hash_ns_min.fetch_min(n, Ordering::Relaxed);
        self.hash_ns_max.fetch_max(n, Ordering::Relaxed);
    }

    /// One hashing job waited `d` for its lease: from its request to its
    /// first line, which is the wait for a place, for a build, and for the
    /// permit when the job holds one.
    pub fn leased(&self, d: Duration) {
        observe(&self.leases, &self.lease_wait_ns, d);
    }

    /// One block's stateless stage took `d` end to end.
    pub fn block_formed(&self, d: Duration) {
        observe(&self.blocks_formed, &self.form_ns, d);
    }

    /// The connector applied a run of `blocks` blocks (its connect and
    /// commit, and the wait for its mailbox) in `d`.
    pub fn applied(&self, blocks: usize, d: Duration) {
        observe(&self.applies, &self.apply_ns, d);
        self.applied_blocks
            .fetch_add(u64::try_from(blocks).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Chain sync's body request for `blocks` blocks was answered `d` after
    /// it was sent, with a response of `bytes` bytes: the round trip and
    /// the peer's serving.
    pub fn transited(&self, blocks: usize, bytes: usize, d: Duration) {
        observe(&self.transit_spans, &self.transit_ns, d);
        self.transit_blocks
            .fetch_add(u64::try_from(blocks).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.transit_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Chain sync's header request was answered `d` after it was sent,
    /// with a response of `bytes` bytes.
    pub fn headers_transited(&self, bytes: usize, d: Duration) {
        observe(&self.header_responses, &self.header_ns, d);
        self.header_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// The door seated one body span chain sync offered. `waited` is how
    /// long the span was held for a seat first, from the door's first
    /// refusal for room to the offer it admitted; `None` when it was
    /// seated at its first offer.
    pub fn seated(&self, waited: Option<Duration>) {
        self.seated_spans.fetch_add(1, Ordering::Relaxed);
        if let Some(d) = waited {
            observe(&self.seat_waits, &self.seat_wait_ns, d);
            self.seat_wait_ns_max.fetch_max(ns(d), Ordering::Relaxed);
        }
    }

    /// One arrival chain sync offered the entry was answered `d` after the
    /// offer: the door's wait, `form`, and the connector's apply.
    pub fn entered(&self, d: Duration) {
        observe(&self.entries, &self.entry_ns, d);
    }

    /// Time `f` as one hash.
    pub fn timed_hash<T>(&self, f: impl FnOnce() -> T) -> T {
        let t = Instant::now();
        let out = f();
        self.hashed(t.elapsed());
        out
    }

    /// The artifact, as of now, with the hasher's `derives`.
    #[must_use]
    pub fn snapshot(&self, derives: Derives) -> MetricsArtifact {
        let hashes = self.hashes.load(Ordering::Relaxed);
        let hash_ns = self.hash_ns.load(Ordering::Relaxed);
        let Derives {
            builds: derives,
            build_ns: derive_ns,
        } = derives;
        let leases = self.leases.load(Ordering::Relaxed);
        let lease_wait_ns = self.lease_wait_ns.load(Ordering::Relaxed);
        let blocks = self.blocks_formed.load(Ordering::Relaxed);
        let form_ns = self.form_ns.load(Ordering::Relaxed);
        let applies = self.applies.load(Ordering::Relaxed);
        let applied_blocks = self.applied_blocks.load(Ordering::Relaxed);
        let apply_ns = self.apply_ns.load(Ordering::Relaxed);
        let transit_spans = self.transit_spans.load(Ordering::Relaxed);
        let transit_blocks = self.transit_blocks.load(Ordering::Relaxed);
        let transit_bytes = self.transit_bytes.load(Ordering::Relaxed);
        let transit_ns = self.transit_ns.load(Ordering::Relaxed);
        let header_responses = self.header_responses.load(Ordering::Relaxed);
        let header_bytes = self.header_bytes.load(Ordering::Relaxed);
        let header_ns = self.header_ns.load(Ordering::Relaxed);
        let seated_spans = self.seated_spans.load(Ordering::Relaxed);
        let seat_waits = self.seat_waits.load(Ordering::Relaxed);
        let seat_wait_ns = self.seat_wait_ns.load(Ordering::Relaxed);
        let entries = self.entries.load(Ordering::Relaxed);
        let entry_ns = self.entry_ns.load(Ordering::Relaxed);
        let mean = |total: u64, n: u64| if n == 0 { None } else { Some(total / n) };
        MetricsArtifact {
            schema_version: METRICS_SCHEMA,
            host: Host::this(),
            concurrency: self.concurrency.get().copied(),
            mode: "light (cache-only; no dataset)",
            hashes,
            hash_ns_total: hash_ns,
            hash_ns_mean: mean(hash_ns, hashes),
            hash_ns_min: (hashes > 0).then(|| self.hash_ns_min.load(Ordering::Relaxed)),
            hash_ns_max: (hashes > 0).then(|| self.hash_ns_max.load(Ordering::Relaxed)),
            cache_derives: derives,
            derive_ns_total: derive_ns,
            derive_ns_mean: mean(derive_ns, derives),
            leases,
            lease_wait_ns_total: lease_wait_ns,
            lease_wait_ns_mean: mean(lease_wait_ns, leases),
            blocks_formed: blocks,
            form_ns_total: form_ns,
            form_ns_mean: mean(form_ns, blocks),
            applies,
            applied_blocks,
            apply_ns_total: apply_ns,
            apply_ns_per_block: mean(apply_ns, applied_blocks),
            transit_spans,
            transit_blocks,
            transit_bytes,
            transit_ns_total: transit_ns,
            transit_ns_per_block: mean(transit_ns, transit_blocks),
            header_responses,
            header_bytes,
            header_ns_total: header_ns,
            header_ns_mean: mean(header_ns, header_responses),
            seated_spans,
            seat_waits,
            seat_wait_ns_total: seat_wait_ns,
            seat_wait_ns_mean: mean(seat_wait_ns, seat_waits),
            seat_wait_ns_max: (seat_waits > 0)
                .then(|| self.seat_wait_ns_max.load(Ordering::Relaxed)),
            entries,
            entry_ns_total: entry_ns,
            entry_ns_mean: mean(entry_ns, entries),
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
    /// How many workers shared it (module docs); `None` when no pipeline
    /// configured the sink.
    pub concurrency: Option<Concurrency>,
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
    /// Hashing jobs granted a lease.
    pub leases: u64,
    /// Wall-clock those jobs waited for their lease, summed: the wait for
    /// a place, a build and, for a job that holds one, its permit.
    pub lease_wait_ns_total: u64,
    /// Per job.
    pub lease_wait_ns_mean: Option<u64>,
    /// Blocks through the stateless stage.
    pub blocks_formed: u64,
    /// Wall-clock over all `form`s: hashing included for a hashed form,
    /// none for `form_judged`, whose proof chain sync's executor paid for.
    pub form_ns_total: u64,
    /// Per block.
    pub form_ns_mean: Option<u64>,
    /// Runs the connector applied for the live service.
    pub applies: u64,
    /// Blocks in those runs.
    pub applied_blocks: u64,
    /// Wall-clock over all applies: the connector's connect and commit,
    /// and the wait for its mailbox.
    pub apply_ns_total: u64,
    /// Per applied block.
    pub apply_ns_per_block: Option<u64>,
    /// Chain sync's body requests answered.
    pub transit_spans: u64,
    /// Blocks those requests named.
    pub transit_blocks: u64,
    /// Bytes those requests' responses carried, summed: the payload each
    /// peer sent for the blocks it served.
    pub transit_bytes: u64,
    /// Wall-clock from each request's send to its answer, summed.
    pub transit_ns_total: u64,
    /// Per block named: a request's round trip shared by its blocks.
    pub transit_ns_per_block: Option<u64>,
    /// Chain sync's header requests answered.
    pub header_responses: u64,
    /// Bytes those responses carried, summed.
    pub header_bytes: u64,
    /// Wall-clock from each header request's send to its answer, summed.
    /// A session with a second header request sent before the first was
    /// answered is timed from the later send.
    pub header_ns_total: u64,
    /// Per header response.
    pub header_ns_mean: Option<u64>,
    /// Body spans the door seated: every offer it admitted, whether at
    /// its first offer or after a wait for room.
    pub seated_spans: u64,
    /// Seated spans that were first refused for room (`NoRoom` or
    /// `Throttled`) and offered again. Against `seated_spans`, the share
    /// of spans that waited; against the cap on body requests in flight,
    /// the cap at which seats, not spans, become the limit.
    pub seat_waits: u64,
    /// Wall-clock from each waiting span's first refusal to the offer the
    /// door admitted, summed.
    pub seat_wait_ns_total: u64,
    /// Per waiting span.
    pub seat_wait_ns_mean: Option<u64>,
    /// The longest wait for a seat.
    pub seat_wait_ns_max: Option<u64>,
    /// Arrivals chain sync offered the entry and heard answered.
    pub entries: u64,
    /// Wall-clock from each offer to its answer, summed: the door's wait,
    /// `form`, and the apply.
    pub entry_ns_total: u64,
    /// Per arrival.
    pub entry_ns_mean: Option<u64>,
}

impl Default for MetricsArtifact {
    /// Nothing measured yet, on this host.
    fn default() -> Self {
        Metrics::new().snapshot(Derives::default())
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

    /// The artifact as one line of JSON, for a log line.
    ///
    /// # Errors
    ///
    /// Serialization only.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_means_and_extremes_and_the_empty_artifact_has_no_means() {
        let m = Metrics::new();
        let empty = m.snapshot(Derives::default());
        assert_eq!(empty.hashes, 0);
        assert_eq!(empty.hash_ns_mean, None);
        assert_eq!(empty.hash_ns_min, None);
        m.hashed(Duration::from_nanos(100));
        m.hashed(Duration::from_nanos(300));
        m.block_formed(Duration::from_nanos(1_000));
        let s = m.snapshot(Derives {
            builds: 1,
            build_ns: 2_000_000,
        });
        assert_eq!(s.hashes, 2);
        assert_eq!(s.hash_ns_total, 400);
        assert_eq!(s.hash_ns_mean, Some(200));
        assert_eq!((s.hash_ns_min, s.hash_ns_max), (Some(100), Some(300)));
        assert_eq!(s.cache_derives, 1);
        assert_eq!(s.derive_ns_mean, Some(2_000_000));
        m.leased(Duration::from_millis(1));
        let leased = m.snapshot(Derives::default());
        assert_eq!(
            (
                leased.leases,
                leased.lease_wait_ns_total,
                leased.lease_wait_ns_mean
            ),
            (1, 1_000_000, Some(1_000_000))
        );
        assert_eq!((s.blocks_formed, s.form_ns_mean), (1, Some(1_000)));
        assert_eq!(s.schema_version, METRICS_SCHEMA);
        assert!(s.to_json().expect("json").contains(METRICS_SCHEMA));
        assert_eq!(s.concurrency, None, "no pipeline configured the sink");
        // The sync's responses: the empty artifact has no header mean and
        // no seat-wait extremes.
        assert_eq!((empty.header_responses, empty.header_ns_mean), (0, None));
        assert_eq!((empty.seat_waits, empty.seat_wait_ns_max), (0, None));
        m.transited(3, 1_500, Duration::from_nanos(900));
        m.headers_transited(400, Duration::from_nanos(200));
        m.headers_transited(600, Duration::from_nanos(400));
        m.seated(None);
        m.seated(Some(Duration::from_nanos(50)));
        m.seated(Some(Duration::from_nanos(150)));
        let s = m.snapshot(Derives::default());
        assert_eq!(
            (s.transit_spans, s.transit_blocks, s.transit_bytes),
            (1, 3, 1_500)
        );
        assert_eq!(
            (s.transit_ns_total, s.transit_ns_per_block),
            (900, Some(300))
        );
        assert_eq!(
            (s.header_responses, s.header_bytes, s.header_ns_total),
            (2, 1_000, 600)
        );
        assert_eq!(s.header_ns_mean, Some(300));
        assert_eq!((s.seated_spans, s.seat_waits), (3, 2));
        assert_eq!(
            (
                s.seat_wait_ns_total,
                s.seat_wait_ns_mean,
                s.seat_wait_ns_max
            ),
            (200, Some(100), Some(150))
        );
    }

    #[test]
    fn the_concurrency_is_stamped_once_and_the_first_stands() {
        let m = Metrics::new();
        m.configured(Concurrency {
            hashers: 4,
            window: 32,
        });
        m.configured(Concurrency {
            hashers: 1,
            window: 1,
        });
        assert_eq!(
            m.snapshot(Derives::default()).concurrency,
            Some(Concurrency {
                hashers: 4,
                window: 32
            })
        );
    }

    #[test]
    fn timed_wrappers_return_the_value_and_count_once() {
        let m = Metrics::new();
        assert_eq!(m.timed_hash(|| 7), 7);
        let s = m.snapshot(Derives::default());
        assert_eq!((s.hashes, s.cache_derives), (1, 0));
    }
}
