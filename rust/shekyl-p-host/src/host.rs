// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`PersonaServingHost`]: the loopback serving loop and the onion that
//! publishes it, composed into one object with one lifetime.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use shekyl_p_serve::{PServeEndpoint, StoreShardProvider};
use shekyl_tor::control::ServiceId;
use shekyl_tor::onion_identity::OnionIdentity;
use shekyl_tor::service::{
    OnionServiceSpec, ServingPosture, TorPosture, TorService, TorServiceConfig,
};
use tokio::sync::watch;

use crate::serve_set::{PinError, PinnedServeSet, ServeSetPinner, Staleness, StalenessBound};

/// The serving identity and the shape of its published port.
///
/// Takes an [`OnionIdentity`] — the **expanded** credential — never a seed.
/// That is `ARCHIVAL_CHALLENGE_MECHANISM.md` §7.2 check (iii) made
/// structural: the custody boundary is *which secret crosses into the
/// serving side*, and a config that cannot hold a seed cannot hold the
/// master seed one convenient edit away from it. The derivation happens
/// wallet-side, once; what reaches this crate is already expanded.
#[derive(Debug)]
pub struct PersonaServing {
    /// The wallet-derived serving identity (expanded key + `.onion`).
    pub identity: OnionIdentity,
    /// Virtual port the onion publishes (the port a witness dials).
    pub virtual_port: u16,
    /// Per-rendezvous-circuit stream cap. **Carried placeholder
    /// (SPIKE-PIN-1), not a derivation** — parameterized so the W₂ rig
    /// chooses it (see [`OnionServiceSpec`]).
    pub max_streams: u16,
}

/// Why a serving host could not start.
#[derive(Debug)]
pub enum HostError {
    /// The loopback listener could not be bound.
    Bind {
        /// The bind error, verbatim.
        detail: String,
    },
    /// The serve-set could not be pinned, so nothing is served. See
    /// [`PinError`] — the two arms differ in remedy (retry vs rebuild).
    Pin(PinError),
    /// The bound endpoint's address was refused as an `ADD_ONION` target.
    ///
    /// Unreachable in practice — [`PServeEndpoint::bind`] binds
    /// `127.0.0.1:0` and nothing else — and kept as a typed refusal rather
    /// than an `expect` precisely because it guards a **privacy** invariant
    /// (hard invariant 4: the serve target is loopback). If the two ever
    /// disagree, the persona must fail to start, not start with its shard
    /// server on a routable interface.
    NonLoopbackTarget,
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind { detail } => write!(f, "serving endpoint bind failed: {detail}"),
            Self::Pin(e) => write!(f, "serving host did not start: {e}"),
            Self::NonLoopbackTarget => {
                f.write_str("serving endpoint address was refused as a non-loopback onion target")
            }
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pin(e) => Some(e),
            Self::Bind { .. } | Self::NonLoopbackTarget => None,
        }
    }
}

/// A bonded persona's serving host: the loopback shard server, the onion
/// that makes it reachable, and the pins that keep its shards alive.
///
/// # What the composition adds over its two halves
///
/// Neither half is safe alone, and the unsafe combinations are the ones
/// this type removes:
///
/// - **The endpoint is bound exactly once, and the host owns it for its
///   whole life.** `TorService` republishes the onion on *every*
///   incarnation's `Ready` from the [`OnionServiceSpec`] in its config — the
///   same loopback target every time. A rebind (`:0` picks a fresh ephemeral
///   port) under an unchanged spec would leave the onion mapped to a dead
///   port: the persona would look healthy, publish at its advertised
///   address, and answer nothing. There is no rebind method here, and the
///   endpoint outlives every tor incarnation because it is not owned by
///   one. Same failure class as a vanguards rotation on restart — silent,
///   and paid for an epoch later at the slash.
/// - **Serving cannot start before the serve-set is pinned.** [`Self::start`]
///   takes a [`ServeSetPinner`] and acquires the witness itself. The
///   §9.6 item 4 hazard is not a startup step that could be reordered or
///   forgotten; there is no argument through which to hand in an
///   unpinned host.
/// - **And it serves the store those pins are in.** The witness carries its
///   own [`ServingReader`](shekyl_curve_tree::ServingReader); `start` takes
///   no store argument at all. Pins applied to one store while another is
///   served would leave the served store unpinned — the same silent-slash
///   hazard, re-entering through the API's shape rather than through
///   bookkeeping. A call site holding two opaque store handles is a call
///   site that can pair them wrongly, so there is only ever one.
/// - **A serving persona always runs full vanguards.** The posture this host
///   writes is [`ServingPosture::Serving`], the one variant that carries both
///   the onion and `VanguardsMode::Managed`. The "onion without vanguards"
///   combination has no representation to reach.
///
/// # Custody (§7.2(iii))
///
/// This host holds: an expanded [`OnionIdentity`], a **read-only**
/// [`ServingReader`](shekyl_curve_tree::ServingReader) on the store (via
/// the live witness), and the one [`ServeSetPinner`] taken at start. It
/// holds no seed, no bond spend authority, and no store write handle of
/// its own — pinning writes go through the pinner to the curve-tree
/// actor. The one assumption worth stating rather than leaving implicit:
/// the design frames the custody boundary as *which secret crosses the
/// process boundary*, and this host is in-process with the wallet — so
/// what enforces the boundary here is the type of what it can hold, not
/// an address space. Splitting the serving host into its own process is
/// a stronger form of the same rule and is not foreclosed by anything
/// here.
pub struct PersonaServingHost<P: ServeSetPinner> {
    /// Bound once in [`Self::start`]; never rebound. See the type doc.
    endpoint: PServeEndpoint,
    tor: TorService,
    service_id: ServiceId,
    /// The one pinner this host will ever use. Held rather than taken per
    /// call so the store the pins land in cannot change between the initial
    /// acquire and any later refresh — see [`Self::refresh`].
    pinner: P,
    /// Held, not just consumed: dropping the witness on the floor would
    /// make the pins look like a startup formality rather than a live
    /// property of this host. Behind a `Mutex` because it is exactly that —
    /// live — and [`Self::refresh`] replaces it as holdings change.
    pinned: Mutex<PinnedServeSet>,
    /// Failed [`Self::refresh`] attempts since the last successful one.
    ///
    /// **Host state on purpose, because every store-derived signal shares a
    /// failure mode with the thing it is watching.** The lag arms of
    /// [`Staleness`] read the curve-tree store; a fail-stopped curve-tree
    /// actor that cannot be resumed stops block ingest *and* fails every
    /// pin, so the stamp and the tip freeze together and the lag stays
    /// constant — an affirmative healthy reading on a wallet that is
    /// comprehensively broken. A count of attempts is the one local fact
    /// that fault cannot suppress, because the attempts keep happening.
    ///
    /// Relaxed ordering throughout: this is a counter read for a human, with
    /// no other state ordered against it.
    refresh_failures: AtomicU32,
    /// Serializes a whole [`Self::refresh`] attempt — read the witness, pin,
    /// install, update the tally — rather than each of its writes.
    ///
    /// The witness `Mutex` makes every individual assignment atomic and does
    /// nothing about the sequence they belong to. Two overlapping refreshes
    /// are a read-modify-write race on serving state: the slower attempt
    /// installs its older witness *after* the faster one has installed a
    /// newer, and a late failure can `fetch_add` a tally that a newer success
    /// has already cleared (or a late success `store(0)` over a newer
    /// failure). The result is a tripwire reporting the wrong thing in both
    /// directions — `RefreshFailing` on a host that is refreshing, and silence
    /// on one that is not, which is the direction that ends in a slash.
    ///
    /// A `tokio::sync::Mutex` rather than the `std` one because it is held
    /// across the pin's actor round trip. That is exactly the shape
    /// [`Self::lock_pinned`]'s lock must never take, and the two are
    /// deliberately different locks for that reason: this one spans the await,
    /// that one spans an assignment.
    ///
    /// Callers wait rather than being turned away, which keeps the contract
    /// worth having: when `refresh` returns `Ok`, the pins are current as of a
    /// moment at or after the call. A "someone else is already refreshing, so
    /// this was a no-op" success would be indistinguishable from a real one at
    /// the call site, and the caller most likely to hit it is the retry after
    /// a failure.
    refresh_gate: tokio::sync::Mutex<()>,
}

impl<P: ServeSetPinner> PersonaServingHost<P> {
    /// Bind the loopback serving endpoint, point an onion at it, and start
    /// the supervisor.
    ///
    /// **Order matters and is fixed here.** The endpoint binds first,
    /// because its ephemeral port is the onion's target and cannot be known
    /// before the bind; the spec is then built against that address and the
    /// supervisor started. Nothing downstream may re-derive the target.
    ///
    /// `tor.posture` is **overwritten** with the serving posture this host
    /// builds. A serving host serves by definition, and the posture is the
    /// one field of the supervisor config it is the sole correct author of;
    /// refusing a mis-set value instead would be a runtime check on a
    /// question the caller was never being asked. Every other field of
    /// `tor` — binary source, data dir, event sink, policy, offline-test
    /// flag — is the caller's.
    ///
    /// Returns as soon as the supervisor is spawned: the onion publishes on
    /// the first incarnation's `Ready`, which callers observe through
    /// [`Self::posture`]. The `.onion` address is available immediately
    /// (it is derived, not assigned), so a persona can be advertised
    /// without waiting for tor.
    ///
    /// # Errors
    ///
    /// [`HostError::Pin`] if the serve-set could not be pinned,
    /// [`HostError::Bind`] if the loopback listener cannot be created, and
    /// [`HostError::NonLoopbackTarget`] if the bound address is refused as
    /// an onion target.
    pub async fn start(
        mut tor: TorServiceConfig,
        serving: PersonaServing,
        pinner: P,
    ) -> Result<Self, HostError> {
        // The pins are taken here, from the pinner this host keeps. Nothing
        // is handed in already-pinned, so there is no way to start a host
        // whose pins came from somewhere its refreshes cannot reach.
        let pinned = PinnedServeSet::acquire(&pinner)
            .await
            .map_err(HostError::Pin)?;
        // The reader comes from the witness, not from an argument: the store
        // served must be the store pinned, and the only way to make that
        // unconditional is to leave the caller no way to name a second one.
        let provider = StoreShardProvider::new(pinned.reader().clone());
        let endpoint = PServeEndpoint::bind(Arc::new(provider))
            .await
            .map_err(|e| HostError::Bind {
                detail: e.to_string(),
            })?;

        let spec = OnionServiceSpec::new(
            serving.identity,
            serving.virtual_port,
            endpoint.addr(),
            serving.max_streams,
        )
        .ok_or(HostError::NonLoopbackTarget)?;
        let service_id = spec.service_id().clone();

        tor.posture = ServingPosture::Serving(spec);
        let tor = TorService::spawn(tor);

        Ok(Self {
            endpoint,
            tor,
            service_id,
            pinner,
            pinned: Mutex::new(pinned),
            refresh_failures: AtomicU32::new(0),
            refresh_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// The `.onion` address this persona serves at — derived, so it is
    /// known before tor is.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// The supervisor's posture channel (`Ready` means SOCKS discovered
    /// *and* the onion published).
    #[must_use]
    pub fn posture(&self) -> watch::Receiver<TorPosture> {
        self.tor.posture()
    }

    /// A snapshot of the serve-set these pins cover.
    #[must_use]
    pub fn pinned_serve_set(&self) -> PinnedServeSet {
        self.lock_pinned().clone()
    }

    /// Take the serve-set lock, **tolerating poisoning**.
    ///
    /// A poisoned mutex means some task panicked while holding this lock, and
    /// the standard reflex — propagate — is wrong here for two reasons. The
    /// critical sections are a `clone` and a single assignment, so there is no
    /// torn state a panic could have left behind: the witness inside is either
    /// the old value or the new one, and both are whole. And the cost of
    /// propagating is paid on a serving host, where every subsequent read
    /// becoming a panic converts one unrelated fault into a persona that stops
    /// answering — which is a slash. `expect` here would trade a recoverable
    /// condition for the exact outcome this crate exists to prevent.
    fn lock_pinned(&self) -> std::sync::MutexGuard<'_, PinnedServeSet> {
        self.pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Re-derive the pins from a freshly read bond record.
    ///
    /// **Call this unconditionally on every refresh tick — do not gate it on
    /// "did holdings change".** Pinning is idempotent and additive, so
    /// re-pinning an unchanged set costs one bounded write and re-pinning a
    /// grown one closes the slashing direction outright. A conditional
    /// refresh reintroduces the question "did we notice the change", which is
    /// the question §9.6 item 4 exists because nobody can answer reliably.
    ///
    /// **Acquire before release.** The new witness is minted — meaning its
    /// pins are already applied — before the old one is dropped, so there is
    /// no instant in which neither covers the set. The pin call runs outside
    /// the lock (it awaits an actor round trip), and only the swap is
    /// serialized; a failure leaves the previous witness in place, which is
    /// the safe direction: stale pins retain bytes, missing pins lose them.
    ///
    /// **Takes no pinner, and that is what keeps the pins in the store being
    /// served.** `refreshed` builds the new witness with *this host's* reader,
    /// because the endpoint never rebinds and so the served store cannot
    /// change. If the refresh could be handed a different pinner, its pins
    /// could land in a different store while the witness claimed they were
    /// here — a witness asserting safety for a store nobody is serving, which
    /// is worse than no witness. One host, one pinner, taken at `start`.
    ///
    /// The set is not supplied either: the pinner reports the shards it
    /// derived from the connected record. A serving host does not name its
    /// own obligations on any tick, first or later.
    ///
    /// **Every attempt is counted, and that is what makes the tripwire
    /// whole.** A failure here is recorded on the host, so
    /// [`Self::staleness`] can report it even when the same fault has frozen
    /// the store-derived clocks — see [`Staleness::RefreshFailing`]. The
    /// caller still gets the error; it does not have to keep the tally to
    /// get an honest reading back.
    ///
    /// # Errors
    ///
    /// [`PinError`] as [`PinnedServeSet::refreshed`]; the host keeps serving
    /// on its previous pins either way.
    pub async fn refresh(&self) -> Result<(), PinError> {
        // Clone the current witness rather than holding the lock across the
        // await: the pin is an actor round trip, and holding a lock across it
        // is the shape the curve-tree actor's own lock-ordering rule exists
        // to forbid.
        //
        // Taken before the witness is read, not just around the install: the
        // whole attempt is one read-modify-write on serving state, and gating
        // only the write would still let a slow attempt overwrite a newer
        // witness with one derived from a staler read. See `refresh_gate`.
        let _gate = self.refresh_gate.lock().await;
        let current = self.pinned_serve_set();
        match current.refreshed(&self.pinner).await {
            Ok(next) => {
                *self.lock_pinned() = next;
                self.refresh_failures.store(0, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.refresh_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Whether the serve-set is still tracking the bond record.
    ///
    /// The detector for a refresh that is no longer keeping up, in either of
    /// the two shapes that has. Poll this beside the tor posture.
    ///
    /// - **Stopped.** The P-scan task halts into its own log on a
    ///   chain-exhaustiveness anomaly, is cancelled, panics, or was never
    ///   started. Nothing on the serving side observes that, so the evidence
    ///   is the store's ingest climbing past the tip stamped at the last
    ///   successful refresh.
    /// - **Failing.** Refresh keeps being attempted and keeps returning
    ///   [`PinError`]. This arm is checked **first**, and it is checked
    ///   before any store read, because the fault that produces it may be
    ///   the same fault that has frozen the store's clocks — a curve-tree
    ///   actor that fail-stopped and could not be resumed stops ingest and
    ///   fails every pin at once. Asking the store first would let that case
    ///   answer `Current`.
    ///
    /// A store read failure while refresh is failing therefore does not mask
    /// the reading: there is nothing to read.
    ///
    /// # Errors
    ///
    /// Store failure reading the sync tip.
    pub fn staleness(
        &self,
        bound: StalenessBound,
    ) -> Result<Staleness, shekyl_curve_tree::StoreError> {
        let consecutive = self.refresh_failures.load(Ordering::Relaxed);
        if consecutive > 0 {
            return Ok(Staleness::RefreshFailing { consecutive });
        }
        self.lock_pinned().staleness(bound)
    }

    /// The bound loopback address the onion targets.
    ///
    /// Stable for the host's whole life — that is the invariant, not an
    /// implementation note (see the type doc). Exposed so a test, or the W₂
    /// rig, can dial the serving loop directly without the onion leg.
    #[must_use]
    pub fn serve_addr(&self) -> std::net::SocketAddr {
        self.endpoint.addr()
    }

    /// Shards served, refused over capacity, lookup failures, and accept
    /// failures — the endpoint's four aggregate counters, in that order.
    ///
    /// Aggregate and monotone by design: there is no per-request structure
    /// to read here, because there is no per-request record anywhere in the
    /// serving path.
    #[must_use]
    pub fn counters(&self) -> (u64, u64, u64, u64) {
        (
            self.endpoint.served_count(),
            self.endpoint.refused_count(),
            self.endpoint.lookup_failure_count(),
            self.endpoint.accept_error_count(),
        )
    }

    /// Stop serving: tear the onion down first, then the listener.
    ///
    /// **That order is the point.** `TorService::shutdown` awaits the
    /// current incarnation's child being reaped, and the actor's `on_stop`
    /// has already `DEL_ONION`'d what it published — so by the time this
    /// returns, no descriptor points at the loopback port. Dropping the
    /// listener first would leave a live onion mapping at a closed port for
    /// the length of the teardown, which is a worse failure than being
    /// offline: a witness reaching it gets a connection refused mid-window
    /// rather than an unreachable service it can retry.
    pub async fn shutdown(self) {
        self.tor.shutdown().await;
        drop(self.endpoint);
    }
}

impl<P: ServeSetPinner> std::fmt::Debug for PersonaServingHost<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The serving address is the persona's identity on the wire; it is
        // chain-public, but there is nothing here worth printing by default.
        f.debug_struct("PersonaServingHost").finish_non_exhaustive()
    }
}
