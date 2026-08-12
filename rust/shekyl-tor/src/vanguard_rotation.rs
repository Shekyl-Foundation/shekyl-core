// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The vanguard rotation manager — supervisor-scoped state that outlives Tor
//! incarnations, so a Tor **restart never causes a rotation** (PR-C3).
//!
//! # The load-bearing invariant
//!
//! Persisted state is authoritative. An incarnation **restores and applies**
//! the current set; it never re-selects. Only the wall clock expires a node.
//! Get this wrong and every supervisor restart re-draws the set — which is
//! exactly vanguards-lite's weakness (its guard topology resets when Tor
//! restarts), so we would have paid for full vanguards' complexity while
//! reimplementing lite's flaw. Our backoff starts at 1 s, so a flapping Tor
//! could re-draw many times an hour: the over-rotation failure at its worst.
//! [`RotationState::restore`] therefore keeps every surviving node's identity
//! **and its expiry timestamp** untouched.
//!
//! # Lifetimes (spec-pinned; prop-333 / guard-spec)
//!
//! - **L2:** uniform over [30, 60] days (mean 45). Implementations *may*
//!   expose L2 as a user pinning option.
//! - **L3:** `max(X, X)` over [1, 48] hours inclusive (mean 31.5 h), and
//!   **not** user-pinnable. The skew is deliberate: some chance of a very
//!   short rotation to deter compromise/coercion, biased toward longer
//!   periods so a Sybil attack must be sustained.
//!
//! **Recorded divergence:** the spec *text* gives L2 a uniform distribution,
//! but notes the reference implementation uses `max(X, X)` for *both* layers
//! "for simplicity." We follow the spec text (the analyzed version): L2
//! uniform, L3 `max(X, X)`.
//!
//! # Replacement policy on restore
//!
//! A persisted fingerprint may have left the consensus, and pinning a dead
//! relay breaks circuits. Restore reconciles against the consensus and
//! **replaces only the missing nodes, never the set** — every replacement is
//! a fresh draw and therefore an adversary opportunity, so it is minimized.
//! **Flag-loss is deliberately *not* a replacement trigger here:**
//! vanguards-lite replaces a vanguard that loses `Fast`/`Stable`, but the
//! proposal explicitly notes the design did not have to be that way. Treating
//! flag-loss as a rotation is a separate, argued decision — not inherited.
//!
//! # Ownership
//!
//! [`VanguardManager`] is the sole orchestration surface the supervisor calls.
//! Selection, lifetimes, control-port I/O, and persistence all live here so
//! `service` stays a thin policy loop rather than growing feature branches.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kameo::error::SendError;
use tokio::sync::oneshot;

use crate::control::consensus::{parse_ns_all, ConsensusRelay};
use crate::control::vanguards::{
    HsLayerPins, RelayFingerprint, NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS,
};
use crate::control::{Command, ControlError, TorControl};

/// L2 lifetime bounds (spec): uniform over [30, 60] days.
const L2_LIFETIME_MIN: Duration = Duration::from_secs(30 * 86_400);
const L2_LIFETIME_MAX: Duration = Duration::from_secs(60 * 86_400);
/// L3 lifetime bounds (spec): `max(X, X)` over [1, 48] hours inclusive.
const L3_LIFETIME_MIN: Duration = Duration::from_secs(3_600);
const L3_LIFETIME_MAX: Duration = Duration::from_secs(48 * 3_600);

// ── Mode + sealed witness ──────────────────────────────────────────────────

/// Whether this Tor instance runs supervisor-managed **full** vanguards.
///
/// Defaults to [`Self::Off`]: full vanguards adds two guard layers where
/// tor's built-in lite adds one, which the spec is explicit costs longer
/// paths and higher latency — a non-serving instance should not pay that.
///
/// The four configurations, and why only three are representable:
/// - `Off` + no onion — a plain client (the unchanged default);
/// - `Managed` + no onion — **legitimate**: the witness leg is an onion
///   *client* building rendezvous circuits, and client-side guard discovery
///   is a real attack, so this configuration stays available;
/// - `Managed` + onion — the serving posture;
/// - `Off` + onion — **the configuration our own ruling forbids** (a serving
///   persona with lite-only protection is silently weaker with no feedback
///   channel, against an adversary whose success is invisible to the
///   operator). It is made unrepresentable at the registration surface:
///   publishing a persona onion requires a [`VanguardsActive`] witness, and
///   no witness exists in `Off`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VanguardsMode {
    /// No supervisor pinning; tor's built-in vanguards-lite applies.
    #[default]
    Off,
    /// The supervisor selects, pins, rotates and persists full vanguards.
    Managed,
}

/// Evidence that full vanguards are **pinned and confirmed on the current
/// incarnation** — the token the onion-registration surface demands.
///
/// Mintable only by the confirmed-`SETCONF` path inside [`VanguardManager`].
/// This is the crate's established sealed-witness pattern
/// ([`VerifiedTorBinary`](crate::binary::VerifiedTorBinary)): the guarantee
/// is structural rather than a convention the serving daemon must remember.
///
/// Deliberately carries no data — it is proof, not a value.
///
/// **No test bypass exists yet, on purpose.** The obvious sibling would be a
/// loud `unchecked_for_test` mirroring
/// [`VerifiedTorBinary`](crate::binary::VerifiedTorBinary)'s, and one should
/// land the day a test drives [`crate::onion_service::publish_onion`]
/// directly. Today no test does — the supervisor path mints the witness for
/// real — so adding the escape hatch now would put an unused hole in a
/// security gate, which is the kind of debt this codebase deletes rather than
/// carries.
#[derive(Debug)]
pub struct VanguardsActive(());

impl VanguardsActive {
    fn confirmed() -> Self {
        Self(())
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// Why applying vanguards aborted.
#[derive(Debug)]
pub enum VanguardsAbort {
    /// The caller asked the service to stop mid-apply.
    Shutdown,
    /// The control actor died — an incarnation death, not a vanguards fault.
    ActorGone,
    /// The apply itself failed.
    Failed(VanguardsError),
}

/// Why a vanguards apply failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VanguardsError {
    /// The control channel failed (or the reply timed out).
    Control(ControlError),
    /// Tor refused the `SETCONF` / `GETINFO` with a non-250 status.
    Rejected {
        /// The status tor returned.
        status: u16,
    },
    /// The consensus could not fill or repair the vanguard set.
    Rotation(RotationError),
    /// The persisted state could not be written — refused loudly rather than
    /// running with state that would be lost on restart, because losing it
    /// means the next process start re-draws (a rotation a restart must never
    /// cause). In-memory state is still committed so a same-process retry
    /// does not re-select.
    Persist(String),
}

impl std::fmt::Display for VanguardsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Control(e) => write!(f, "vanguards control failure: {e}"),
            Self::Rejected { status } => write!(f, "tor refused SETCONF with status {status}"),
            Self::Rotation(e) => write!(f, "vanguard set could not be built: {e}"),
            Self::Persist(e) => write!(f, "vanguard state could not be persisted: {e}"),
        }
    }
}

impl std::error::Error for VanguardsError {}

/// Why a rotation operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationError {
    /// The consensus lacks enough eligible relays to fill or replace the set.
    TooFewEligible {
        /// Eligible, positive-bandwidth candidates available.
        available: usize,
        /// Seats that needed filling.
        needed: usize,
    },
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewEligible { available, needed } => write!(
                f,
                "only {available} eligible relays for {needed} vanguard seats"
            ),
        }
    }
}

impl std::error::Error for RotationError {}

// ── Selection (bandwidth-weighted) ─────────────────────────────────────────

/// A source of randomness for vanguard selection — a seam so the weighted
/// draw is deterministic under test yet a real CSPRNG in production.
///
/// Selection must be **unpredictable** (an adversary who could predict our
/// draw could bias toward landing in the set), so the production impl
/// ([`OsVanguardRng`]) pulls from the OS CSPRNG; tests use a seeded
/// generator. Modeled on the `challenge_coverage` sim's local-PRNG
/// precedent rather than pulling a `rand` dependency.
pub trait VanguardRng {
    /// The next 64 random bits.
    fn next_u64(&mut self) -> u64;
}

/// Production RNG: OS CSPRNG bytes via `getrandom`.
pub struct OsVanguardRng;

impl VanguardRng for OsVanguardRng {
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG");
        u64::from_le_bytes(buf)
    }
}

/// Draw disjoint layer-2 and layer-3 fingerprint sets, bandwidth-weighted —
/// without replacement. L2 is drawn first, L3 from the remainder.
/// `None` if the eligible pool cannot fill `l2 + l3` seats.
fn select_disjoint(
    relays: &[ConsensusRelay],
    l2: usize,
    l3: usize,
    rng: &mut impl VanguardRng,
) -> Option<(Vec<RelayFingerprint>, Vec<RelayFingerprint>)> {
    let mut pool = eligible_pool(relays);
    if pool.len() < l2 + l3 {
        return None;
    }
    let layer2 = draw_weighted(&mut pool, l2, rng);
    let layer3 = draw_weighted(&mut pool, l3, rng);
    Some((layer2, layer3))
}

/// Draw **one** replacement relay, bandwidth-weighted, excluding everything
/// in `exclude`. `None` if nothing eligible remains.
fn draw_replacement(
    relays: &[ConsensusRelay],
    exclude: &[RelayFingerprint],
    rng: &mut impl VanguardRng,
) -> Option<RelayFingerprint> {
    let mut pool: Vec<(RelayFingerprint, u64)> = eligible_pool(relays)
        .into_iter()
        .filter(|(fp, _)| !exclude.contains(fp))
        .collect();
    if pool.is_empty() {
        return None;
    }
    Some(draw_weighted(&mut pool, 1, rng).remove(0))
}

fn eligible_pool(relays: &[ConsensusRelay]) -> Vec<(RelayFingerprint, u64)> {
    relays
        .iter()
        .filter(|r| r.eligible && r.bandwidth > 0)
        .map(|r| (r.fingerprint, r.bandwidth))
        .collect()
}

/// Draw `count` fingerprints from `pool` weighted by bandwidth, removing
/// each as it is drawn. Caller guarantees `pool.len() >= count`.
fn draw_weighted(
    pool: &mut Vec<(RelayFingerprint, u64)>,
    count: usize,
    rng: &mut impl VanguardRng,
) -> Vec<RelayFingerprint> {
    let mut drawn = Vec::with_capacity(count);
    for _ in 0..count {
        let total: u128 = pool.iter().map(|(_, bw)| u128::from(*bw)).sum();
        // total > 0: every pool entry has bandwidth > 0 and pool is non-empty.
        let mut target = (u128::from(rng.next_u64()) % total) + 1;
        let mut idx = 0;
        for (i, (_, bw)) in pool.iter().enumerate() {
            target = target.saturating_sub(u128::from(*bw));
            if target == 0 {
                idx = i;
                break;
            }
        }
        drawn.push(pool.swap_remove(idx).0);
    }
    drawn
}

// ── Persistence ────────────────────────────────────────────────────────────

/// The persisted state file inside the Tor `DataDirectory`.
///
/// **Plaintext, deliberately.** Tor's own guard state — which holds the *L1
/// entry guards*, strictly more sensitive than our L2/L3 set — sits
/// unencrypted in the same directory; encrypting one file beside it would be
/// theatre. The honest operator-facing statement is about the directory as a
/// whole: the Tor data directory is a persona-linkable artifact, and backing
/// it up or imaging the host is a deanonymization vector.
#[must_use]
pub fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("shekyl-vanguards.state")
}

/// Load persisted rotation state. `None` when absent **or malformed** —
/// including wrong set sizes, duplicates, or L2/L3 overlap. A corrupt file
/// is treated as "no state" (the caller selects fresh) rather than as a
/// partial set that would silently under-pin.
#[must_use]
fn load_state(path: &Path) -> Option<RotationState> {
    let text = std::fs::read_to_string(path).ok()?;
    RotationState::deserialize(&text)
}

/// Persist rotation state **atomically** (write a temp file, then rename).
///
/// Atomicity is load-bearing, not hygiene: a torn write would be read back as
/// corrupt, the caller would select fresh, and the restart would have caused a
/// rotation — precisely the invariant this module exists to hold.
///
/// On Windows, `rename` cannot overwrite an existing destination, so the
/// destination is removed first. That is not a fully atomic replace on
/// Windows, but it is the portable shape available without a platform-specific
/// replace API; a crash between remove and rename leaves the `.tmp` for the
/// next start to ignore (load reads only the canonical path → select fresh).
fn save_state(path: &Path, state: &RotationState) -> std::io::Result<()> {
    let tmp = path.with_extension("state.tmp");
    std::fs::write(&tmp, state.serialize())?;
    // POSIX rename overwrites atomically. Windows rename fails if dest exists.
    #[cfg(windows)]
    {
        // Windows rename cannot overwrite; best-effort remove first.
        drop(std::fs::remove_file(path));
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup; the rename error is what the caller needs.
            drop(std::fs::remove_file(&tmp));
            Err(e)
        }
    }
}

// ── Rotation state ─────────────────────────────────────────────────────────

/// Which layer a node sits in — its lifetime distribution differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layer {
    /// Second-level guard (L2): uniform 30–60 day lifetime.
    Two,
    /// Third-level guard (L3): `max(X, X)` 1–48 hour lifetime.
    Three,
}

/// One pinned vanguard: its identity and the instant it expires.
///
/// Expiry is an absolute wall-clock time (persisted as Unix seconds) so it
/// survives process restarts — the whole point is that the clock, not a
/// restart, drives rotation. Each node's expiry is tracked **independently**
/// (the spec keeps per-node rotation times so the primary and second-level
/// guards' rotations are not disclosed together).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VanguardNode {
    fingerprint: RelayFingerprint,
    expires_at: SystemTime,
}

/// The full rotation state: the L2 and L3 node sets with their timers.
///
/// Supervisor-scoped and persisted; incarnations read it to apply pins, the
/// rotation loop mutates it as nodes expire. Once constructed (via
/// [`Self::select_fresh`] or a successful [`Self::deserialize`]), both layers
/// always hold exactly the spec counts and are pairwise disjoint.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RotationState {
    layer2: Vec<VanguardNode>,
    layer3: Vec<VanguardNode>,
}

impl RotationState {
    /// Draw a fresh state from the consensus — the first-ever selection, when
    /// no persisted state exists. Every node gets an independent lifetime
    /// from its layer's distribution.
    fn select_fresh(
        consensus: &[ConsensusRelay],
        now: SystemTime,
        rng: &mut impl VanguardRng,
    ) -> Result<Self, RotationError> {
        let needed = NUM_LAYER2_GUARDS + NUM_LAYER3_GUARDS;
        let (l2_fps, l3_fps) =
            select_disjoint(consensus, NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS, rng).ok_or(
                RotationError::TooFewEligible {
                    available: eligible_pool(consensus).len(),
                    needed,
                },
            )?;
        Ok(Self {
            layer2: l2_fps
                .into_iter()
                .map(|fp| VanguardNode {
                    fingerprint: fp,
                    expires_at: now + sample_lifetime(Layer::Two, rng),
                })
                .collect(),
            layer3: l3_fps
                .into_iter()
                .map(|fp| VanguardNode {
                    fingerprint: fp,
                    expires_at: now + sample_lifetime(Layer::Three, rng),
                })
                .collect(),
        })
    }

    /// The pins an incarnation applies via `SETCONF`. Always `Some` for a
    /// well-formed state (non-empty layers by construction).
    fn to_pins(&self) -> Option<HsLayerPins> {
        HsLayerPins::new(
            self.layer2.iter().map(|n| n.fingerprint).collect(),
            self.layer3.iter().map(|n| n.fingerprint).collect(),
        )
    }

    /// **Restore** against the current consensus: keep every node whose relay
    /// is still present (identity **and** expiry untouched), replace **only**
    /// nodes whose relay has left the consensus. Does not expire anything —
    /// that is [`Self::expire_due`]'s job. A restart alone must not rotate.
    fn restore(
        mut self,
        consensus: &[ConsensusRelay],
        rng: &mut impl VanguardRng,
    ) -> Result<Self, RotationError> {
        // "Present" = appears in the consensus at all, regardless of flags.
        let present: HashSet<RelayFingerprint> = consensus.iter().map(|r| r.fingerprint).collect();

        let mut in_use: Vec<RelayFingerprint> = self
            .layer2
            .iter()
            .chain(&self.layer3)
            .map(|n| n.fingerprint)
            .filter(|fp| present.contains(fp))
            .collect();

        swap_absent(&mut self.layer2, &present, consensus, &mut in_use, rng)?;
        swap_absent(&mut self.layer3, &present, consensus, &mut in_use, rng)?;
        Ok(self)
    }

    /// Rotate out every node whose expiry is at or before `now`, replacing
    /// each with a fresh draw and a new lifetime. Returns how many nodes
    /// rotated (for no-op short-circuiting).
    fn expire_due(
        &mut self,
        consensus: &[ConsensusRelay],
        now: SystemTime,
        rng: &mut impl VanguardRng,
    ) -> Result<usize, RotationError> {
        let mut in_use: Vec<RelayFingerprint> = self
            .layer2
            .iter()
            .chain(&self.layer3)
            .map(|n| n.fingerprint)
            .collect();
        let mut rotated = 0;
        rotated += rotate_expired(
            &mut self.layer2,
            Layer::Two,
            consensus,
            now,
            &mut in_use,
            rng,
        )?;
        rotated += rotate_expired(
            &mut self.layer3,
            Layer::Three,
            consensus,
            now,
            &mut in_use,
            rng,
        )?;
        Ok(rotated)
    }

    /// The earliest expiry across all nodes. `None` only for an empty state
    /// (which cannot arise from `select_fresh` / valid deserialize).
    fn next_expiry(&self) -> Option<SystemTime> {
        self.layer2
            .iter()
            .chain(&self.layer3)
            .map(|n| n.expires_at)
            .min()
    }

    /// Serialize to the persisted text form: one `L2|L3 $fp <unix-secs>` line
    /// per node.
    fn serialize(&self) -> String {
        let mut out = String::new();
        for (tag, nodes) in [("L2", &self.layer2), ("L3", &self.layer3)] {
            for node in nodes {
                let secs = node
                    .expires_at
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                out.push_str(tag);
                out.push(' ');
                out.push_str(&node.fingerprint.to_specifier());
                out.push(' ');
                out.push_str(&secs.to_string());
                out.push('\n');
            }
        }
        out
    }

    /// Parse the persisted text form. `None` on any malformed line **or** on
    /// a structurally invalid state (wrong counts, duplicates, L2/L3 overlap).
    /// A corrupt state file is treated as "no state" — never as a partial set
    /// that would silently under-pin.
    fn deserialize(text: &str) -> Option<Self> {
        let mut layer2 = Vec::new();
        let mut layer3 = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split(' ');
            let tag = parts.next()?;
            let fingerprint = RelayFingerprint::parse(parts.next()?)?;
            let secs: u64 = parts.next()?.parse().ok()?;
            if parts.next().is_some() {
                return None; // trailing garbage
            }
            let node = VanguardNode {
                fingerprint,
                expires_at: UNIX_EPOCH + Duration::from_secs(secs),
            };
            match tag {
                "L2" => layer2.push(node),
                "L3" => layer3.push(node),
                _ => return None,
            }
        }
        // Exact sizes — the load-bearing under-pin gate.
        if layer2.len() != NUM_LAYER2_GUARDS || layer3.len() != NUM_LAYER3_GUARDS {
            return None;
        }
        // Pairwise uniqueness across both layers (no within-layer dups, no
        // L2/L3 overlap). Spec requires a disjoint topology.
        let mut seen = HashSet::with_capacity(NUM_LAYER2_GUARDS + NUM_LAYER3_GUARDS);
        for n in layer2.iter().chain(&layer3) {
            if !seen.insert(n.fingerprint) {
                return None;
            }
        }
        Some(Self { layer2, layer3 })
    }
}

/// Swap every node whose relay is absent from the consensus for a fresh
/// bandwidth-weighted draw. The slot **keeps its existing expiry timer** —
/// swapping a dead relay is a repair, not a rotation.
fn swap_absent(
    set: &mut [VanguardNode],
    present: &HashSet<RelayFingerprint>,
    consensus: &[ConsensusRelay],
    in_use: &mut Vec<RelayFingerprint>,
    rng: &mut impl VanguardRng,
) -> Result<(), RotationError> {
    for node in set.iter_mut() {
        if !present.contains(&node.fingerprint) {
            let fresh =
                draw_replacement(consensus, in_use, rng).ok_or(RotationError::TooFewEligible {
                    available: eligible_pool(consensus).len(),
                    needed: 1,
                })?;
            in_use.push(fresh);
            node.fingerprint = fresh;
        }
    }
    Ok(())
}

/// Rotate every node whose expiry is at or before `now`. Returns the count
/// rotated. `in_use` is kept current so two expiries in one pass cannot draw
/// the same replacement.
fn rotate_expired(
    set: &mut [VanguardNode],
    layer: Layer,
    consensus: &[ConsensusRelay],
    now: SystemTime,
    in_use: &mut [RelayFingerprint],
    rng: &mut impl VanguardRng,
) -> Result<usize, RotationError> {
    let mut rotated = 0;
    for node in set.iter_mut() {
        if node.expires_at <= now {
            let old = node.fingerprint;
            let fresh =
                draw_replacement(consensus, in_use, rng).ok_or(RotationError::TooFewEligible {
                    available: eligible_pool(consensus).len(),
                    needed: 1,
                })?;
            if let Some(slot) = in_use.iter_mut().find(|f| **f == old) {
                *slot = fresh;
            }
            node.fingerprint = fresh;
            node.expires_at = now + sample_lifetime(layer, rng);
            rotated += 1;
        }
    }
    Ok(rotated)
}

fn sample_lifetime(layer: Layer, rng: &mut impl VanguardRng) -> Duration {
    match layer {
        Layer::Two => uniform_between(L2_LIFETIME_MIN, L2_LIFETIME_MAX, rng),
        Layer::Three => {
            let a = uniform_between(L3_LIFETIME_MIN, L3_LIFETIME_MAX, rng);
            let b = uniform_between(L3_LIFETIME_MIN, L3_LIFETIME_MAX, rng);
            a.max(b)
        }
    }
}

fn uniform_between(min: Duration, max: Duration, rng: &mut impl VanguardRng) -> Duration {
    let span = max.as_secs() - min.as_secs();
    let offset = if span == 0 {
        0
    } else {
        rng.next_u64() % (span + 1)
    };
    min + Duration::from_secs(offset)
}

// ── Manager (supervisor-facing orchestration) ──────────────────────────────

/// Supervisor-scoped owner of vanguard mode, in-memory rotation state, and
/// the on-disk path. Constructed once per [`crate::service::TorService`] and
/// passed into every incarnation — never re-created on restart.
pub struct VanguardManager {
    mode: VanguardsMode,
    state: Option<RotationState>,
    path: PathBuf,
}

impl VanguardManager {
    /// Load from disk when `Managed` (absent/corrupt → empty, first establish
    /// selects fresh). `Off` never touches the file.
    #[must_use]
    pub fn load(mode: VanguardsMode, data_dir: &Path) -> Self {
        let path = state_path(data_dir);
        let state = match mode {
            VanguardsMode::Off => None,
            VanguardsMode::Managed => load_state(&path),
        };
        Self { mode, state, path }
    }

    /// Whether this instance manages full vanguards.
    #[must_use]
    pub fn is_managed(&self) -> bool {
        matches!(self.mode, VanguardsMode::Managed)
    }

    /// Sleep duration until the earliest per-node expiry. `None` when Off or
    /// when no state has been established yet (the hold-loop arm stays inert).
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        if !self.is_managed() {
            return None;
        }
        let at = self.state.as_ref()?.next_expiry()?;
        Some(
            at.duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO),
        )
    }

    /// Bring this incarnation's vanguards up: fetch consensus, restore (or
    /// select fresh), expire anything the clock aged out, `SETCONF`, persist.
    ///
    /// Returns `None` when mode is [`VanguardsMode::Off`]. On Managed, mints
    /// the sealed [`VanguardsActive`] witness after a confirmed `SETCONF`.
    ///
    /// # Errors
    ///
    /// [`VanguardsAbort`] on shutdown, actor death, timeout, refusal, or an
    /// unfillable set.
    pub async fn establish(
        &mut self,
        actor: &kameo::actor::ActorRef<TorControl>,
        reply_deadline: Duration,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<Option<VanguardsActive>, VanguardsAbort> {
        if !self.is_managed() {
            return Ok(None);
        }
        let witness = self.pin_set(actor, reply_deadline, shutdown).await?;
        Ok(Some(witness))
    }

    /// Mid-life reconcile: repair relays that left the consensus **and**
    /// expire due nodes, then re-`SETCONF` and persist. Called from the hold
    /// loop's rotation arm — never from a restart path (restart uses
    /// [`Self::establish`], which runs the same repair+expire pipeline).
    ///
    /// A no-op when Off or when no state is held yet.
    ///
    /// # Errors
    ///
    /// [`VanguardsAbort`] on control / rotation / persist failure. Failing
    /// here fails the incarnation: the pinned set and our state would
    /// otherwise disagree, and `Ready` is defined as the full posture being up.
    pub async fn reconcile(
        &mut self,
        actor: &kameo::actor::ActorRef<TorControl>,
        reply_deadline: Duration,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<(), VanguardsAbort> {
        if !self.is_managed() || self.state.is_none() {
            return Ok(());
        }
        let _witness = self.pin_set(actor, reply_deadline, shutdown).await?;
        Ok(())
    }

    /// Shared pin pipeline used by both establish and mid-life reconcile:
    /// consensus → restore-or-fresh → expire → SETCONF → commit memory →
    /// persist.
    ///
    /// In-memory state is committed **before** disk write so a transient
    /// persist failure on first selection cannot force the next incarnation
    /// down the `select_fresh` path (the restart-driven rotation this design
    /// forbids). Persist still fails the incarnation loudly — the operator
    /// must learn about a directory that cannot hold state.
    async fn pin_set(
        &mut self,
        actor: &kameo::actor::ActorRef<TorControl>,
        reply_deadline: Duration,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<VanguardsActive, VanguardsAbort> {
        let consensus = fetch_consensus(actor, reply_deadline, shutdown).await?;

        let mut rng = OsVanguardRng;
        let now = SystemTime::now();

        // Clone, never take — an error must not leave the manager holding
        // `None` when it previously had state (that would turn a transient
        // failure into a forced re-draw on the next establish).
        let built = match self.state.clone() {
            Some(previous) => previous.restore(&consensus, &mut rng),
            None => RotationState::select_fresh(&consensus, now, &mut rng),
        };
        let mut state = built.map_err(|e| VanguardsAbort::Failed(VanguardsError::Rotation(e)))?;

        // A long downtime may have spanned whole lifetimes; the clock still
        // decides. Mid-life reconcile also runs restore above so a relay that
        // left the consensus is repaired without waiting for its expiry.
        state
            .expire_due(&consensus, now, &mut rng)
            .map_err(|e| VanguardsAbort::Failed(VanguardsError::Rotation(e)))?;

        let witness = apply_pins(actor, &state, reply_deadline, shutdown).await?;

        // Commit memory first so a same-process retry after persist failure
        // reuses this set rather than selecting fresh.
        self.state = Some(state.clone());

        if let Err(e) = save_state(&self.path, &state) {
            return Err(VanguardsAbort::Failed(VanguardsError::Persist(
                e.to_string(),
            )));
        }
        Ok(witness)
    }
}

/// Fetch the consensus over the control port (`GETINFO ns/all`).
async fn fetch_consensus(
    actor: &kameo::actor::ActorRef<TorControl>,
    reply_deadline: Duration,
    shutdown: &mut oneshot::Receiver<()>,
) -> Result<Vec<ConsensusRelay>, VanguardsAbort> {
    let reply = tokio::select! {
        _ = &mut *shutdown => return Err(VanguardsAbort::Shutdown),
        () = tokio::time::sleep(reply_deadline) => {
            return Err(VanguardsAbort::Failed(VanguardsError::Control(ControlError::Timeout)));
        }
        r = actor.ask(Command::GetInfo(vec!["ns/all".to_owned()])) => r,
    };
    match reply {
        Ok(reply) if reply.status() == 250 => Ok(parse_ns_all(&reply)),
        Ok(reply) => Err(VanguardsAbort::Failed(VanguardsError::Rejected {
            status: reply.status(),
        })),
        Err(SendError::HandlerError(e)) => Err(VanguardsAbort::Failed(VanguardsError::Control(e))),
        Err(_) => Err(VanguardsAbort::ActorGone),
    }
}

/// Apply `state`'s pins with one `SETCONF`; mint the witness only on `250`.
async fn apply_pins(
    actor: &kameo::actor::ActorRef<TorControl>,
    state: &RotationState,
    reply_deadline: Duration,
    shutdown: &mut oneshot::Receiver<()>,
) -> Result<VanguardsActive, VanguardsAbort> {
    let pins = state
        .to_pins()
        .ok_or(VanguardsAbort::Failed(VanguardsError::Rotation(
            RotationError::TooFewEligible {
                available: 0,
                needed: NUM_LAYER2_GUARDS + NUM_LAYER3_GUARDS,
            },
        )))?;
    let reply = tokio::select! {
        _ = &mut *shutdown => return Err(VanguardsAbort::Shutdown),
        () = tokio::time::sleep(reply_deadline) => {
            return Err(VanguardsAbort::Failed(VanguardsError::Control(ControlError::Timeout)));
        }
        r = actor.ask(Command::SetConf(pins)) => r,
    };
    match reply {
        Ok(reply) if reply.status() == 250 => Ok(VanguardsActive::confirmed()),
        Ok(reply) => Err(VanguardsAbort::Failed(VanguardsError::Rejected {
            status: reply.status(),
        })),
        Err(SendError::HandlerError(e)) => Err(VanguardsAbort::Failed(VanguardsError::Control(e))),
        Err(_) => Err(VanguardsAbort::ActorGone),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeded SplitMix64 (no `rand` dep).
    struct SeededRng(u64);
    impl VanguardRng for SeededRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    fn pool(n: u8) -> Vec<ConsensusRelay> {
        (1..=n)
            .map(|b| ConsensusRelay {
                fingerprint: RelayFingerprint::from_bytes([b; 20]),
                bandwidth: 1000,
                eligible: true,
            })
            .collect()
    }

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    fn full_state_text(state: &RotationState) -> String {
        state.serialize()
    }

    #[test]
    fn fresh_selection_fills_both_layers_disjoint() {
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(1)).unwrap();
        assert_eq!(state.layer2.len(), NUM_LAYER2_GUARDS);
        assert_eq!(state.layer3.len(), NUM_LAYER3_GUARDS);
        let mut seen = HashSet::new();
        for n in state.layer2.iter().chain(&state.layer3) {
            assert!(n.expires_at > t0());
            assert!(seen.insert(n.fingerprint), "duplicate in fresh set");
        }
    }

    #[test]
    fn selection_is_bandwidth_weighted() {
        // One relay with overwhelming weight is picked essentially always.
        let mut relays = vec![ConsensusRelay {
            fingerprint: RelayFingerprint::from_bytes([1; 20]),
            bandwidth: 1_000_000,
            eligible: true,
        }];
        for b in 2..=12u8 {
            relays.push(ConsensusRelay {
                fingerprint: RelayFingerprint::from_bytes([b; 20]),
                bandwidth: 1,
                eligible: true,
            });
        }
        let heavy = RelayFingerprint::from_bytes([1; 20]);
        let mut hits = 0;
        for seed in 0..200u64 {
            let state =
                RotationState::select_fresh(&relays, t0(), &mut SeededRng(seed)).expect("enough");
            if state
                .layer2
                .iter()
                .chain(&state.layer3)
                .any(|n| n.fingerprint == heavy)
            {
                hits += 1;
            }
        }
        assert!(hits >= 199, "bandwidth weighting not applied: {hits}/200");
    }

    #[test]
    fn selection_ignores_ineligible_and_zero_bandwidth() {
        let mut relays = vec![
            ConsensusRelay {
                fingerprint: RelayFingerprint::from_bytes([1; 20]),
                bandwidth: 500,
                eligible: true,
            },
            ConsensusRelay {
                fingerprint: RelayFingerprint::from_bytes([2; 20]),
                bandwidth: 500,
                eligible: true,
            },
        ];
        // Pad to fill 4+6 with only eligible seats — but only 2 eligible,
        // so selection must refuse.
        relays.push(ConsensusRelay {
            fingerprint: RelayFingerprint::from_bytes([3; 20]),
            bandwidth: 999_999,
            eligible: false,
        });
        relays.push(ConsensusRelay {
            fingerprint: RelayFingerprint::from_bytes([4; 20]),
            bandwidth: 0,
            eligible: true,
        });
        let err = RotationState::select_fresh(&relays, t0(), &mut SeededRng(7)).unwrap_err();
        assert!(matches!(
            err,
            RotationError::TooFewEligible {
                available: 2,
                needed: 10
            }
        ));
    }

    #[test]
    fn restore_with_all_relays_present_is_a_no_op_the_invariant() {
        let consensus = pool(30);
        let original = RotationState::select_fresh(&consensus, t0(), &mut SeededRng(9)).unwrap();
        let restored = original
            .clone()
            .restore(&consensus, &mut SeededRng(123))
            .unwrap();
        assert_eq!(
            restored, original,
            "restore must preserve identities AND expiry timers"
        );
    }

    #[test]
    fn restore_replaces_only_missing_relays_and_keeps_survivor_timers() {
        let consensus = pool(30);
        let original = RotationState::select_fresh(&consensus, t0(), &mut SeededRng(5)).unwrap();

        let dropped = original.layer2[0].fingerprint;
        let shrunk: Vec<ConsensusRelay> = consensus
            .iter()
            .filter(|r| r.fingerprint != dropped)
            .copied()
            .collect();

        let restored = original
            .clone()
            .restore(&shrunk, &mut SeededRng(77))
            .unwrap();

        assert_ne!(restored.layer2[0].fingerprint, dropped);
        assert_eq!(
            restored.layer2[0].expires_at, original.layer2[0].expires_at,
            "a swapped-dead-relay slot keeps its timer (not a rotation)"
        );
        for i in 1..NUM_LAYER2_GUARDS {
            assert_eq!(restored.layer2[i], original.layer2[i]);
        }
        assert_eq!(restored.layer3, original.layer3);

        let all: Vec<_> = restored
            .layer2
            .iter()
            .chain(&restored.layer3)
            .map(|n| n.fingerprint)
            .collect();
        let mut dedup = all.clone();
        dedup.sort_by_key(RelayFingerprint::to_specifier);
        dedup.dedup();
        assert_eq!(all.len(), dedup.len(), "no duplicate after replacement");
    }

    #[test]
    fn only_the_clock_expires_nodes() {
        let consensus = pool(30);
        let mut state = RotationState::select_fresh(&consensus, t0(), &mut SeededRng(2)).unwrap();
        let before = state.clone();

        let rotated = state
            .expire_due(&consensus, t0(), &mut SeededRng(3))
            .unwrap();
        assert_eq!(rotated, 0);
        assert_eq!(state, before, "no expiry => no change");

        let earliest = state.next_expiry().unwrap();
        let due_count = state
            .layer2
            .iter()
            .chain(&state.layer3)
            .filter(|n| n.expires_at <= earliest)
            .count();
        let rotated = state
            .expire_due(&consensus, earliest, &mut SeededRng(4))
            .unwrap();
        assert_eq!(rotated, due_count);
        for n in state.layer2.iter().chain(&state.layer3) {
            assert!(n.expires_at > earliest || n.expires_at > t0());
        }
    }

    #[test]
    fn l3_lifetimes_fall_in_the_spec_band_and_skew_long() {
        let mut rng = SeededRng(11);
        let mut total = 0u64;
        let n = 500;
        for _ in 0..n {
            let d = sample_lifetime(Layer::Three, &mut rng);
            assert!(d >= L3_LIFETIME_MIN && d <= L3_LIFETIME_MAX);
            total += d.as_secs();
        }
        let mean_hours = (total / n) / 3600;
        assert!(
            mean_hours >= 25,
            "max(X,X) must skew long; mean was {mean_hours}h"
        );
    }

    #[test]
    fn persistence_round_trips() {
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(8)).unwrap();
        let text = full_state_text(&state);
        let back = RotationState::deserialize(&text).expect("valid");
        assert_eq!(back, state);
    }

    #[test]
    fn corrupt_or_partial_state_is_rejected_whole() {
        // Malformed lines.
        assert!(RotationState::deserialize("L2 $notahex 123").is_none());
        assert!(RotationState::deserialize("L2 $AA 123").is_none());
        assert!(
            RotationState::deserialize("LX $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1").is_none()
        );
        assert!(
            RotationState::deserialize("L2 $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1 extra")
                .is_none()
        );

        // Empty / whitespace — not "empty state", no state.
        assert!(RotationState::deserialize("").is_none());
        assert!(RotationState::deserialize("\n\n").is_none());

        // Structurally short: one valid L2 + one valid L3 under-pins.
        let short = "\
L2 $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1\n\
L3 $BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB 2\n";
        assert!(
            RotationState::deserialize(short).is_none(),
            "under-sized set must not load"
        );

        // A full-size set with an L2/L3 overlap is rejected.
        let mut lines = Vec::new();
        let mut l2_fps = Vec::new();
        for i in 0..NUM_LAYER2_GUARDS {
            let mut fp = [0u8; 20];
            fp[0] = u8::try_from(i + 1).expect("set size fits u8");
            l2_fps.push(fp);
            lines.push(format!(
                "L2 {} 100",
                RelayFingerprint::from_bytes(fp).to_specifier()
            ));
        }
        // L3[0] deliberately reuses L2[0]'s fingerprint.
        lines.push(format!(
            "L3 {} 100",
            RelayFingerprint::from_bytes(l2_fps[0]).to_specifier()
        ));
        for i in 1..NUM_LAYER3_GUARDS {
            let mut fp = [0u8; 20];
            fp[0] = u8::try_from(50 + i).expect("set size fits u8");
            lines.push(format!(
                "L3 {} 100",
                RelayFingerprint::from_bytes(fp).to_specifier()
            ));
        }
        assert!(
            RotationState::deserialize(&lines.join("\n")).is_none(),
            "overlapping L2/L3 must not load"
        );
    }

    #[test]
    fn manager_off_never_establishes_a_witness() {
        // Pure unit shape: Off load has no state and reports no deadline.
        let dir = tempfile::tempdir().unwrap();
        let mgr = VanguardManager::load(VanguardsMode::Off, dir.path());
        assert!(!mgr.is_managed());
        assert!(mgr.next_deadline().is_none());
    }

    #[test]
    fn manager_managed_loads_valid_state_and_rejects_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());

        // Corrupt → treated as no state (no deadline until establish selects).
        std::fs::write(&path, "L2 $AA 1\n").unwrap();
        let mgr = VanguardManager::load(VanguardsMode::Managed, dir.path());
        assert!(mgr.is_managed());
        assert!(mgr.next_deadline().is_none());

        // Valid full set → loaded; a deadline exists.
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(3)).unwrap();
        save_state(&path, &state).unwrap();
        let mgr = VanguardManager::load(VanguardsMode::Managed, dir.path());
        assert!(mgr.is_managed());
        assert!(mgr.next_deadline().is_some());
    }

    #[test]
    fn selection_is_deterministic_under_a_fixed_seed() {
        let a = RotationState::select_fresh(&pool(20), t0(), &mut SeededRng(42)).unwrap();
        let b = RotationState::select_fresh(&pool(20), t0(), &mut SeededRng(42)).unwrap();
        assert_eq!(a, b);
    }
}
