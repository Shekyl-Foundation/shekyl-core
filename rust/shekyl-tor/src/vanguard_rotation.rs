// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The vanguard rotation manager — supervisor-scoped state that outlives Tor
//! incarnations, so a Tor **restart never causes a rotation** (VG-3).
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
//! `RotationState::restore` therefore keeps every surviving node's identity
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
//! # Two kinds of fault
//!
//! [`VanguardsError`] ends an incarnation; [`VanguardsWarning`] does not. The
//! line between them is whether the **live** posture is still right: a control
//! failure or an unfillable set leaves the pinned set and our state at odds, so
//! the incarnation cannot be trusted to keep serving — but a state file that
//! cannot be read or written leaves tor bootstrapped, SOCKS listening and the
//! correct set pinned, degrading only *restart survival*. Reporting the second
//! kind by tearing tor down would trade a conditional future privacy loss for a
//! certain present liveness loss, recurring every incarnation for as long as the
//! disk stays broken. So it alarms and keeps serving, and the alarm clears itself
//! on the next successful persist.
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
/// This is the *derived* knob, not the configured one: callers choose a
/// [`ServingPosture`](crate::service::ServingPosture), which implies the mode.
/// That is what keeps the one forbidden pairing — a serving persona on
/// lite-only guard protection, silently weaker with no feedback channel, against
/// an adversary whose success is invisible to the operator — from existing to be
/// checked for. The runtime gate is the second, independent lock: publishing a
/// persona onion needs a [`VanguardsActive`] witness, and no witness is minted
/// in `Off`.
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
}

impl std::fmt::Display for VanguardsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Control(e) => write!(f, "vanguards control failure: {e}"),
            Self::Rejected { status } => write!(f, "tor refused SETCONF with status {status}"),
            Self::Rotation(e) => write!(f, "vanguard set could not be built: {e}"),
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
    /// Too few of the router entries the `ns/all` reply announced could be
    /// decoded for it to be read as a picture of the network.
    ///
    /// This is refused rather than acted on because the downstream reading of
    /// "absent from the consensus" is "this vanguard left the network, replace
    /// it" — so a wholesale parse failure would present as the entire network
    /// churning at once and re-draw the persona's whole guard topology.
    ConsensusUnusable {
        /// Entries whose identity decoded.
        decoded: usize,
        /// Entries the reply announced.
        announced: usize,
    },
    /// The OS CSPRNG refused. Selection has to be unpredictable, so there is no
    /// degraded draw to fall back to.
    RngUnavailable,
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewEligible { available, needed } => write!(
                f,
                "only {available} eligible relays for {needed} vanguard seats"
            ),
            Self::ConsensusUnusable { decoded, announced } => write!(
                f,
                "only {decoded} of {announced} announced consensus entries could be read"
            ),
            Self::RngUnavailable => write!(f, "the OS CSPRNG refused to produce bytes"),
        }
    }
}

impl std::error::Error for RotationError {}

impl From<RngUnavailable> for RotationError {
    fn from(RngUnavailable: RngUnavailable) -> Self {
        Self::RngUnavailable
    }
}

/// A vanguards fault the **transport survives**.
///
/// Separate from [`VanguardsError`] deliberately, and the distinction is the
/// lesson of the persistence path: a fault that leaves tor bootstrapped, SOCKS
/// listening, and the correct guard set pinned must not be reported by killing
/// tor. Both variants degrade a *future* guarantee — the set surviving a
/// restart — while the live posture is exactly right, so the honest response is
/// a loud alarm that clears itself when the next persist succeeds, not an
/// outage that recurs every incarnation for as long as the disk stays broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VanguardsWarning {
    /// Persisted state was present but unusable — unreadable, or content that
    /// failed the structural gate — so the set was drawn fresh. That re-draw
    /// **is** the restart-driven rotation this module exists to prevent, and it
    /// repeats on every start until the operator clears the file.
    StateUnusable(String),
    /// The set is pinned and live but its state file could not be written, so
    /// the next process start would re-draw. In-memory state still carries the
    /// set, so nothing rotates while this process lives.
    StateUnpersisted(String),
}

impl std::fmt::Display for VanguardsWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateUnusable(why) => write!(
                f,
                "persisted vanguard state was unusable, so the set was re-drawn: {why}"
            ),
            Self::StateUnpersisted(why) => write!(
                f,
                "vanguard state could not be persisted (the live set is correct; a restart \
                 would re-draw): {why}"
            ),
        }
    }
}

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
    ///
    /// # Errors
    ///
    /// [`RngUnavailable`] when the source refuses.
    fn next_u64(&mut self) -> Result<u64, RngUnavailable>;
}

/// The randomness source refused.
///
/// Fallible rather than panicking, which is the point: every draw runs inside
/// the supervisor task, so an `expect` here would abort that task and drop the
/// posture channel — a dead Tor service with a *closed* channel instead of a
/// `Degraded` posture, the one outcome the supervisor's "never silent"
/// commitment forbids. A blocked `getrandom` (a hardened seccomp profile, a
/// container policy) is rare but it is an environment fact, not a bug, so it
/// fails the incarnation the way any other vanguards fault does. The crate
/// already handles the same call this way in the SAFECOOKIE handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngUnavailable;

impl std::fmt::Display for RngUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the OS CSPRNG refused to produce bytes")
    }
}

impl std::error::Error for RngUnavailable {}

/// Production RNG: OS CSPRNG bytes via `getrandom`.
pub struct OsVanguardRng;

impl VanguardRng for OsVanguardRng {
    fn next_u64(&mut self) -> Result<u64, RngUnavailable> {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).map_err(|_| RngUnavailable)?;
        Ok(u64::from_le_bytes(buf))
    }
}

/// Draw disjoint layer-2 and layer-3 fingerprint sets, bandwidth-weighted —
/// without replacement. L2 is drawn first, L3 from the remainder.
fn select_disjoint(
    relays: &[ConsensusRelay],
    l2: usize,
    l3: usize,
    rng: &mut impl VanguardRng,
) -> Result<(Vec<RelayFingerprint>, Vec<RelayFingerprint>), RotationError> {
    let mut pool = eligible_pool(relays);
    if pool.len() < l2 + l3 {
        return Err(RotationError::TooFewEligible {
            available: pool.len(),
            needed: l2 + l3,
        });
    }
    let layer2 = draw_weighted(&mut pool, l2, rng)?;
    let layer3 = draw_weighted(&mut pool, l3, rng)?;
    Ok((layer2, layer3))
}

/// Draw **one** replacement relay, bandwidth-weighted, excluding everything
/// in `exclude`.
fn draw_replacement(
    relays: &[ConsensusRelay],
    exclude: &[RelayFingerprint],
    rng: &mut impl VanguardRng,
) -> Result<RelayFingerprint, RotationError> {
    let mut pool: Vec<(RelayFingerprint, u64)> = eligible_pool(relays)
        .into_iter()
        .filter(|(fp, _)| !exclude.contains(fp))
        .collect();
    if pool.is_empty() {
        return Err(RotationError::TooFewEligible {
            available: 0,
            needed: 1,
        });
    }
    Ok(draw_weighted(&mut pool, 1, rng)?.remove(0))
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
) -> Result<Vec<RelayFingerprint>, RngUnavailable> {
    let mut drawn = Vec::with_capacity(count);
    for _ in 0..count {
        let total: u128 = pool.iter().map(|(_, bw)| u128::from(*bw)).sum();
        // total > 0: every pool entry has bandwidth > 0 and pool is non-empty.
        let mut target = (u128::from(rng.next_u64()?) % total) + 1;
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
    Ok(drawn)
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

/// The in-progress copy [`save_state`] writes before committing it over
/// [`state_path`]. Also the crash-recovery copy [`read_state`] falls back to:
/// it exists **only** when a save did not complete.
fn temp_path(path: &Path) -> PathBuf {
    path.with_extension("state.tmp")
}

/// What reading the persisted state found.
///
/// Three outcomes, not two, because "no file" and "a file we could not use" are
/// different facts with different costs. Collapsing them — as an `Option` does —
/// makes an unreadable state file indistinguishable from a first run, so the
/// persona's whole guard topology gets re-drawn with nothing said about it.
enum StateOnDisk {
    /// Nothing persisted: a genuine first run, where selecting fresh is both
    /// correct and unremarkable.
    Absent,
    /// A usable state — from the canonical file, or recovered from the temp copy
    /// an interrupted save left behind.
    Held(RotationState),
    /// Something is there that could not be turned into a state: an I/O error,
    /// or content that failed the structural gate. The caller still selects
    /// fresh (a persona with no transport is the worse failure), but that
    /// re-draw is the restart-driven rotation this module exists to prevent, so
    /// it is reported rather than silently absorbed — see
    /// [`VanguardsWarning::StateUnusable`].
    Unusable(String),
}

/// Read persisted rotation state, distinguishing absent from unusable.
///
/// Malformed content — wrong set sizes, duplicates, L2/L3 overlap — is never
/// accepted as a partial set that would silently under-pin. When the canonical
/// file is missing or unusable, the temp copy is tried: it exists only after an
/// interrupted save, where it may be the *only* durable record of the set, and
/// [`RotationState::deserialize`]'s structural gate is what makes reading a
/// possibly-partial file safe.
fn read_state(path: &Path) -> StateOnDisk {
    let recovered = |fallback: StateOnDisk| match std::fs::read_to_string(temp_path(path)) {
        Ok(text) => RotationState::deserialize(&text).map_or(fallback, StateOnDisk::Held),
        Err(_) => fallback,
    };
    match std::fs::read_to_string(path) {
        Ok(text) => match RotationState::deserialize(&text) {
            Some(state) => StateOnDisk::Held(state),
            None => recovered(StateOnDisk::Unusable(format!(
                "{} is present but is not a well-formed vanguard state",
                path.display()
            ))),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => recovered(StateOnDisk::Absent),
        // Present but unreadable (permissions, a directory in its place, a
        // failing disk). The bytes may be perfectly good, so treating this as a
        // first run would re-draw a set that is sitting right there.
        Err(e) => recovered(StateOnDisk::Unusable(format!(
            "{} could not be read: {e}",
            path.display()
        ))),
    }
}

/// Persist rotation state **atomically and durably**: write a temp file, force
/// it to stable storage, rename it over the canonical path, then force the
/// directory entry.
///
/// Both halves are load-bearing for the same reason, and neither alone is
/// enough. Atomicity keeps a half-written file from ever being read as the
/// state; durability keeps the rename from committing a directory entry that
/// points at data the page cache still holds, which a power loss would expose as
/// a zero-length file. Either way the read-back is corrupt, the caller selects
/// fresh, and the restart has caused a rotation — precisely the invariant this
/// module exists to hold.
///
/// The temp file is **never deleted on failure**. After a failed rename it can
/// be the only durable copy of the set — Windows cannot rename onto an existing
/// file, so the destination has to go first — and [`read_state`] falls back to
/// it. A successful rename consumes it, so a temp file lingering is itself the
/// signal that the last save did not complete.
///
/// **The boundary of that recovery, stated rather than implied:** the temp has
/// one fixed name, so a later save truncates it. Both copies are therefore lost
/// only by a *double* fault — a Windows rename that failed after the destination
/// was removed, followed by a save whose write also fails — and only a process
/// restart inside that window re-draws, since in-memory state carries the set
/// meanwhile. Per-save unique temp names would close it at the cost of durable
/// garbage accumulating in the Tor `DataDirectory` (or a GC pass to sweep it),
/// which is the worse trade for a two-fault, one-platform path.
fn save_state(path: &Path, state: &RotationState) -> std::io::Result<()> {
    use std::io::Write as _;

    let tmp = temp_path(path);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(state.serialize().as_bytes())?;
        // The rename below is only as good as the bytes it commits.
        file.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // POSIX `rename` overwrites atomically and never reports this; Windows
        // refuses an existing destination, so remove and retry — and only ever
        // here, after the temp is already on stable storage, so the window where
        // the canonical path is missing is covered by `read_state`'s fallback
        // rather than left open. Any other error is the caller's to see.
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }
        std::fs::remove_file(path)?;
        std::fs::rename(&tmp, path)?;
    }
    sync_parent_dir(path);
    Ok(())
}

/// Force the directory entry the rename just created.
///
/// Best-effort: not every platform lets a directory be opened for sync (Windows
/// does not), and a failure costs durability of the *rename*, not correctness —
/// a reader still sees either the old state or the new one, never a mix.
fn sync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(handle) = std::fs::File::open(dir) {
            drop(handle.sync_all());
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
        let (l2_fps, l3_fps) =
            select_disjoint(consensus, NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS, rng)?;
        Ok(Self {
            layer2: fresh_nodes(l2_fps, Layer::Two, now, rng)?,
            layer3: fresh_nodes(l3_fps, Layer::Three, now, rng)?,
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
                // Checked, not `+`: `SystemTime` addition panics past the
                // platform's representable range, and this input is a file that
                // any torn write or disk fault can put an arbitrary u64 into.
                // The contract here is `None` on malformed input — a panic would
                // instead abort the supervisor task and close the posture
                // channel, i.e. kill the whole Tor service with no diagnostic.
                expires_at: UNIX_EPOCH.checked_add(Duration::from_secs(secs))?,
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

/// Give each drawn fingerprint an independent lifetime from its layer's
/// distribution.
fn fresh_nodes(
    fingerprints: Vec<RelayFingerprint>,
    layer: Layer,
    now: SystemTime,
    rng: &mut impl VanguardRng,
) -> Result<Vec<VanguardNode>, RotationError> {
    fingerprints
        .into_iter()
        .map(|fingerprint| {
            Ok(VanguardNode {
                fingerprint,
                expires_at: now + sample_lifetime(layer, rng)?,
            })
        })
        .collect()
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
            let fresh = draw_replacement(consensus, in_use, rng)?;
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
            let fresh = draw_replacement(consensus, in_use, rng)?;
            if let Some(slot) = in_use.iter_mut().find(|f| **f == old) {
                *slot = fresh;
            }
            node.fingerprint = fresh;
            node.expires_at = now + sample_lifetime(layer, rng)?;
            rotated += 1;
        }
    }
    Ok(rotated)
}

fn sample_lifetime(layer: Layer, rng: &mut impl VanguardRng) -> Result<Duration, RngUnavailable> {
    match layer {
        Layer::Two => uniform_between(L2_LIFETIME_MIN, L2_LIFETIME_MAX, rng),
        Layer::Three => {
            let a = uniform_between(L3_LIFETIME_MIN, L3_LIFETIME_MAX, rng)?;
            let b = uniform_between(L3_LIFETIME_MIN, L3_LIFETIME_MAX, rng)?;
            Ok(a.max(b))
        }
    }
}

fn uniform_between(
    min: Duration,
    max: Duration,
    rng: &mut impl VanguardRng,
) -> Result<Duration, RngUnavailable> {
    let span = max.as_secs() - min.as_secs();
    let offset = if span == 0 {
        0
    } else {
        rng.next_u64()? % (span + 1)
    };
    Ok(min + Duration::from_secs(offset))
}

// ── Manager (supervisor-facing orchestration) ──────────────────────────────

/// Supervisor-scoped owner of vanguard mode, in-memory rotation state, and
/// the on-disk path. Constructed once per [`crate::service::TorService`] and
/// passed into every incarnation — never re-created on restart.
pub struct VanguardManager {
    mode: VanguardsMode,
    state: Option<RotationState>,
    path: PathBuf,
    /// The current non-fatal fault, if any — see [`VanguardsWarning`]. Held as
    /// live state rather than a one-shot event so that it *clears itself*: the
    /// first successful persist retires it, which is what makes the operator
    /// alarm end on its own when the disk comes back.
    warning: Option<VanguardsWarning>,
}

impl VanguardManager {
    /// Load from disk when `Managed`. `Off` never touches the file.
    ///
    /// State that is absent (a first run) leaves no warning; state that is
    /// present but unusable leaves a [`VanguardsWarning::StateUnusable`], because
    /// the fresh selection it forces is exactly the restart-driven rotation this
    /// module exists to prevent and the operator is the only one who can stop it
    /// recurring.
    #[must_use]
    pub fn load(mode: VanguardsMode, data_dir: &Path) -> Self {
        let path = state_path(data_dir);
        let (state, warning) = match mode {
            VanguardsMode::Off => (None, None),
            VanguardsMode::Managed => match read_state(&path) {
                StateOnDisk::Absent => (None, None),
                StateOnDisk::Held(state) => (Some(state), None),
                StateOnDisk::Unusable(why) => (None, Some(VanguardsWarning::StateUnusable(why))),
            },
        };
        Self {
            mode,
            state,
            path,
            warning,
        }
    }

    /// The live non-fatal fault, if any. The supervisor publishes this alongside
    /// `Ready` — the transport is up, and this is what is nevertheless wrong.
    #[must_use]
    pub fn warning(&self) -> Option<VanguardsWarning> {
        self.warning.clone()
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
    /// [`VanguardsAbort`] when the control round trip or the draw itself fails —
    /// then the pinned set and our state genuinely disagree, so the incarnation
    /// cannot be trusted to keep serving. A persist failure is **not** in that
    /// class: it leaves the live set correct, so it is reported as a
    /// [`VanguardsWarning`] instead of tearing a working tor down.
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
    /// consensus → restore-or-fresh → expire → repair → SETCONF → commit memory
    /// → persist.
    ///
    /// **Expire before repair, deliberately.** A node that is both past its
    /// expiry *and* gone from the consensus needs exactly **one** replacement:
    /// rotating it draws a relay that is in the consensus by construction, so
    /// the repair pass then finds nothing to do. The other order replaces the
    /// same slot twice — two adversary-facing draws where the clock only bought
    /// one, in a module whose whole discipline is minimizing draws.
    ///
    /// In-memory state is committed **before** the disk write so a transient
    /// persist failure on first selection cannot force the next incarnation
    /// down the `select_fresh` path (the restart-driven rotation this design
    /// forbids). A persist failure then becomes a
    /// [`VanguardsWarning::StateUnpersisted`], not an abort: the `SETCONF` has
    /// already been confirmed, so the live set is exactly right and the only
    /// thing lost is restart survival. Failing the incarnation for it would
    /// SIGTERM a healthy tor — dropping SOCKS, unpublishing the persona's onion,
    /// and re-bootstrapping — every incarnation for as long as the directory
    /// stays unwritable, trading a conditional future privacy loss for a certain
    /// present liveness loss. The slash model this supervisor serves prices that
    /// the other way round.
    async fn pin_set(
        &mut self,
        actor: &kameo::actor::ActorRef<TorControl>,
        reply_deadline: Duration,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<VanguardsActive, VanguardsAbort> {
        let consensus = fetch_consensus(actor, reply_deadline, shutdown).await?;

        let mut rng = OsVanguardRng;
        let now = SystemTime::now();
        let rotation_failed =
            |e: RotationError| VanguardsAbort::Failed(VanguardsError::Rotation(e));

        // Clone, never take — an error must not leave the manager holding
        // `None` when it previously had state (that would turn a transient
        // failure into a forced re-draw on the next establish).
        let mut state = match self.state.clone() {
            Some(previous) => previous,
            None => {
                RotationState::select_fresh(&consensus, now, &mut rng).map_err(rotation_failed)?
            }
        };

        // A long downtime may have spanned whole lifetimes; the clock still
        // decides.
        state
            .expire_due(&consensus, now, &mut rng)
            .map_err(rotation_failed)?;

        // Then repair: a relay that left the consensus is swapped without
        // waiting for its expiry, timers untouched.
        let state = state
            .restore(&consensus, &mut rng)
            .map_err(rotation_failed)?;

        let witness = apply_pins(actor, &state, reply_deadline, shutdown).await?;

        // Commit memory first so a same-process retry after persist failure
        // reuses this set rather than selecting fresh.
        self.state = Some(state.clone());

        self.warning = match save_state(&self.path, &state) {
            // A durable write retires whatever was wrong before — including an
            // unusable file at load, which this rename has just replaced.
            Ok(()) => None,
            Err(e) => Some(VanguardsWarning::StateUnpersisted(e.to_string())),
        };
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
        Ok(reply) if reply.status() == 250 => {
            let view = parse_ns_all(&reply);
            // Refuse a view we cannot read rather than acting on it: everything
            // downstream reads "absent from the consensus" as "this vanguard
            // left the network", so a wholesale parse shortfall would present as
            // the whole network churning and re-draw the persona's entire guard
            // topology. Better to fail this incarnation loudly.
            if !view.is_trustworthy() {
                return Err(VanguardsAbort::Failed(VanguardsError::Rotation(
                    RotationError::ConsensusUnusable {
                        decoded: view.relays.len(),
                        announced: view.announced,
                    },
                )));
            }
            Ok(view.relays)
        }
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
    let pins = state.to_pins().ok_or_else(|| {
        VanguardsAbort::Failed(VanguardsError::Rotation(RotationError::TooFewEligible {
            available: state.layer2.len() + state.layer3.len(),
            needed: NUM_LAYER2_GUARDS + NUM_LAYER3_GUARDS,
        }))
    })?;
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
        fn next_u64(&mut self) -> Result<u64, RngUnavailable> {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            Ok(z ^ (z >> 31))
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
            let d = sample_lifetime(Layer::Three, &mut rng).expect("seeded rng");
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
        let text = state.serialize();
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
    fn an_out_of_range_expiry_is_rejected_rather_than_panicking() {
        // `SystemTime + Duration` panics past the platform's range, and this
        // input is a file any torn write can put an arbitrary u64 into. A panic
        // here runs inside the supervisor task, so it would close the posture
        // channel — a dead Tor service with NO failure signal, for a file the
        // contract says to treat as simply absent.
        let fp = "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(RotationState::deserialize(&format!("L2 {fp} {}\n", u64::MAX)).is_none());
        assert!(
            RotationState::deserialize(&format!("L2 {fp} {}\n", i64::MAX as u64 + 1)).is_none()
        );
    }

    #[test]
    fn a_refusing_rng_fails_the_draw_instead_of_panicking() {
        // Same reasoning one layer down: every draw runs inside the supervisor
        // task, so a blocked `getrandom` must surface as a rotation error the
        // supervisor can alarm on and retry, not as an aborted task.
        struct Refuses;
        impl VanguardRng for Refuses {
            fn next_u64(&mut self) -> Result<u64, RngUnavailable> {
                Err(RngUnavailable)
            }
        }
        assert_eq!(
            RotationState::select_fresh(&pool(30), t0(), &mut Refuses),
            Err(RotationError::RngUnavailable)
        );
    }

    #[test]
    fn an_expired_and_absent_node_is_replaced_exactly_once() {
        // Expire-before-repair is what buys this. A node past its expiry that has
        // ALSO left the consensus needs one replacement: rotating it draws a
        // relay that is in the consensus by construction, so the repair pass then
        // finds nothing to do. The other order draws twice for the same slot —
        // two adversary opportunities where the clock only bought one.
        let consensus = pool(30);
        let mut rng = SeededRng(77);
        let mut state = RotationState::select_fresh(&consensus, t0(), &mut rng).unwrap();

        // Age every node out, and make the whole persisted set absent from a
        // consensus of entirely different relays.
        for node in state.layer2.iter_mut().chain(state.layer3.iter_mut()) {
            node.expires_at = t0();
        }
        let replacement_pool: Vec<ConsensusRelay> = (100..=160u8)
            .map(|b| ConsensusRelay {
                fingerprint: RelayFingerprint::from_bytes([b; 20]),
                bandwidth: 1000,
                eligible: true,
            })
            .collect();

        let after_expiry = {
            let mut s = state.clone();
            s.expire_due(&replacement_pool, t0() + Duration::from_secs(1), &mut rng)
                .unwrap();
            s
        };
        // The pipeline's order: expire, then repair.
        let repaired = after_expiry
            .clone()
            .restore(&replacement_pool, &mut rng)
            .unwrap();
        assert_eq!(
            repaired, after_expiry,
            "the repair pass must find nothing left to do after expiry re-drew the slots",
        );
    }

    #[test]
    fn a_durable_save_leaves_no_temp_behind() {
        // The temp file is the crash-recovery copy, so its *presence* is the
        // signal that a save did not complete. A successful save must consume it.
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(5)).unwrap();
        save_state(&path, &state).unwrap();
        assert!(path.exists());
        assert!(!temp_path(&path).exists());
        // And an overwrite of an existing file works on every platform.
        save_state(&path, &state).unwrap();
        assert!(!temp_path(&path).exists());
    }

    #[test]
    fn an_interrupted_save_is_recovered_from_the_temp_copy() {
        // The window this closes: a rename that failed after the destination was
        // removed (Windows cannot rename onto an existing file), leaving the temp
        // as the ONLY durable copy. Reading only the canonical path would re-draw
        // the persona's whole topology; the structural gate is what makes reading
        // a possibly-partial temp safe.
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(6)).unwrap();
        std::fs::write(temp_path(&path), state.serialize()).unwrap();

        match read_state(&path) {
            StateOnDisk::Held(recovered) => assert_eq!(recovered, state),
            _ => panic!("a complete temp copy must be recovered, not re-drawn"),
        }

        // A partial temp is still refused — recovery must not lower the bar.
        std::fs::write(temp_path(&path), "L2 $AA 1\n").unwrap();
        assert!(matches!(read_state(&path), StateOnDisk::Absent));
    }

    #[test]
    fn an_unreadable_state_file_is_not_mistaken_for_a_first_run() {
        // Collapsing "no file" and "a file we could not read" into one answer is
        // what lets a permissions change silently re-draw the persona's guard
        // topology on every start, with nothing said about it.
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());
        assert!(matches!(read_state(&path), StateOnDisk::Absent));

        // A directory where the state file belongs: present, unreadable.
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(read_state(&path), StateOnDisk::Unusable(_)));

        let mgr = VanguardManager::load(VanguardsMode::Managed, dir.path());
        assert!(
            matches!(mgr.warning(), Some(VanguardsWarning::StateUnusable(_))),
            "the forced re-draw must reach the operator, not just happen",
        );
    }

    #[test]
    fn manager_managed_loads_valid_state_and_rejects_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());

        // Corrupt → no state (no deadline until establish selects), and the
        // re-draw that forces is reported rather than absorbed.
        std::fs::write(&path, "L2 $AA 1\n").unwrap();
        let mgr = VanguardManager::load(VanguardsMode::Managed, dir.path());
        assert!(mgr.is_managed());
        assert!(mgr.next_deadline().is_none());
        assert!(matches!(
            mgr.warning(),
            Some(VanguardsWarning::StateUnusable(_))
        ));

        // Valid full set → loaded; a deadline exists.
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(3)).unwrap();
        save_state(&path, &state).unwrap();
        let mgr = VanguardManager::load(VanguardsMode::Managed, dir.path());
        assert!(mgr.is_managed());
        assert!(mgr.next_deadline().is_some());
        assert_eq!(mgr.warning(), None, "a clean load carries no warning");
    }

    #[test]
    fn selection_is_deterministic_under_a_fixed_seed() {
        let a = RotationState::select_fresh(&pool(20), t0(), &mut SeededRng(42)).unwrap();
        let b = RotationState::select_fresh(&pool(20), t0(), &mut SeededRng(42)).unwrap();
        assert_eq!(a, b);
    }
}
