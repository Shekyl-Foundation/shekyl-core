// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D6 — the live apparatus: one tor, two personas, timed fetches over real
//! rendezvous circuits.
//!
//! Separated from the measurement binary so the same wiring is exercised by an
//! `#[ignore]`d live test (with a small payload, as apparatus validation) and by
//! the real measurement (with the 3.33 MB shard). A harness only the binary can
//! reach is a harness nothing checks.
//!
//! # Cold vs warm, and why "cold" is a fresh persona id rather than a NEWNYM
//!
//! §6.2 asks for circuit setup to be inside the timed path unless a warm circuit
//! is defensible, and for both to be reported. The two arms are produced by the
//! isolation mechanism that already exists rather than by asking tor to rotate:
//!
//! - **Cold** — a *different* [`PCanonicalId`] per fetch. Tor's
//!   `IsolateSOCKSAuth` gives each distinct SOCKS username its own circuit, so
//!   every fetch builds a new client circuit and a new rendezvous. This is also
//!   the *faithful* model: each drawn miner is a different client, so a cold
//!   fetch is what a real challenge looks like.
//! - **Warm** — one [`PCanonicalId`] reused, so tor reuses the circuit and only
//!   the rendezvous/stream cost is paid.
//!
//! A `SIGNAL NEWNYM` would have been the other way to force cold circuits, and it
//! is deliberately not used: `NEWNYM` is process-global, so it would also rotate
//! the *other* persona's client circuits mid-arm and contaminate the concurrent
//! arm running beside it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kameo::actor::Spawn as _;
use shekyl_p_transport::{PTorClient, PTransportError, RequestErrorKind, TorSocksEndpoint};
use shekyl_tor::control::onion::{AddOnion, OnionFlags, OnionPort, ServiceId};
use shekyl_tor::control::{BootstrapReadiness, BootstrapState, Command, EventSink, TorControl};
use shekyl_tor::control::{ManagedTor, SocksPort, TorControlConfig, TorLaunch};
use shekyl_types::{PCanonicalId, PSlot};

use crate::measure::{FailureKind, Observation};
use crate::onion_key::derive_onion_identity;
use crate::serve::{ServeEndpoint, ROUTE_PREFIX};

/// Ceiling on a single fetch before the harness calls it a timeout.
///
/// Above `shekyl-p-transport`'s own 120 s global timeout, so the transport's
/// bound fires first and the harness ceiling is only a backstop — that way a
/// timeout is classified by the layer that actually knows why.
pub const FETCH_CEILING: Duration = Duration::from_secs(180);

/// How long to wait for a freshly-published descriptor to become reachable.
///
/// Descriptor upload to the HSDirs plus a client's fetch of it takes tens of
/// seconds on a cold service; this bounds the wait rather than assuming it.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(300);

/// A persona serving a shard over its own onion.
pub struct Persona {
    /// The persona's slot.
    pub slot: PSlot,
    /// Its canonical id — the SOCKS isolation key for *its own* outbound
    /// traffic. Not used by the client leg (a miner is a different client).
    pub id: PCanonicalId,
    /// Its published onion.
    pub service_id: ServiceId,
    /// The loopback endpoint tor forwards to.
    pub endpoint: ServeEndpoint,
}

impl Persona {
    /// The persona's published `.onion` service id.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// The URL a client fetches shard `index` from.
    #[must_use]
    pub fn shard_url(&self, index: u64) -> String {
        format!("http://{}{ROUTE_PREFIX}{index}", self.service_id.hostname())
    }
}

/// A running measurement apparatus: a managed tor plus its published personas.
pub struct Apparatus {
    control: kameo::actor::ActorRef<TorControl>,
    socks: TorSocksEndpoint,
    /// The published personas, in slot order.
    pub personas: Vec<Persona>,
}

/// Why the apparatus could not be brought up. Every arm is an *apparatus*
/// failure, deliberately distinct from a fetch failure: a measurement that
/// silently ran against a broken apparatus is worse than no measurement.
#[derive(Debug)]
pub enum ApparatusError {
    /// Tor did not bootstrap within the deadline.
    Bootstrap,
    /// The control connection failed.
    Control(String),
    /// `ADD_ONION` was refused.
    AddOnion(u16),
    /// tor's reply carried no parseable service id.
    NoServiceId,
    /// The serve endpoint could not bind loopback.
    Bind(std::io::Error),
    /// No persona became reachable within [`PUBLISH_TIMEOUT`].
    NotReachable,
}

impl std::fmt::Display for ApparatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap => write!(f, "tor did not bootstrap"),
            Self::Control(e) => write!(f, "control connection failed: {e}"),
            Self::AddOnion(s) => write!(f, "ADD_ONION refused with status {s}"),
            Self::NoServiceId => write!(f, "ADD_ONION reply carried no service id"),
            Self::Bind(e) => write!(f, "serve endpoint bind failed: {e}"),
            Self::NotReachable => write!(f, "no persona became reachable before the deadline"),
        }
    }
}

impl std::error::Error for ApparatusError {}

impl Apparatus {
    /// Bring up `persona_count` personas, each serving `payload`, behind one
    /// managed tor.
    ///
    /// # ⚠️ `persona_count > 1` builds a layout the firewall FORBIDS
    ///
    /// Multi-persona *holding* is real (Model D — `PSlot` is the index into the
    /// staker's derive-forward persona set), but the permission is **conditional
    /// on non-co-activation**: `ARCHIVAL_BOND_CONSTRUCTION.md:667` permits
    /// retired-but-bonded personas precisely because they are "**not
    /// co-activation — no simultaneous wire activity**". `stake_engine.rs`'s
    /// `active: Option<PSlot>` says the same thing in code — **many held, one on
    /// the wire.**
    ///
    /// Publishing two onions on one daemon puts two personas on the wire at once.
    /// Any latency or linkage number taken that way is an **artifact of a
    /// deployment that will not exist**, and
    /// `ARCHIVAL_FIREWALL_GATE6.md` §10.9 — a ratified Round-2 exit pin — already
    /// requires non-overlapping guard sets for exactly this reason. The PD-F-2
    /// `D*` is therefore derived from **`persona_count = 1`** runs only.
    ///
    /// **Do not "fix" this by splitting tor instances.** `P` and the principal
    /// sharing one guard set is the deliberate §7 residual, accepted at
    /// `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md:616` under "correct as-is — do not
    /// 'fix'": separate instances are *worse*, because a non-default config is
    /// itself a fingerprint to a guard observer — a weaker adversary than the
    /// correlator the shared guard exposes. **One tor process is the correct
    /// shape.**
    ///
    /// **`persona_count > 1` is retained deliberately — to *price* the forbidden
    /// layout, not by accident.** A measurement of a configuration the design
    /// rules out is what lets the project quantify the cost of doing it anyway,
    /// and that cost lands on **both** axes at once: complete entry-guard overlap
    /// (privacy) *and* **≥ ×1.54** on `D*` (throughput). Co-serving is therefore
    /// never the efficient choice, which is a stronger deterrent than the rule
    /// alone. The ×1.54 is a **floor** — C-tor-specific, `N = 2`, one vantage,
    /// one run — so cite it as "at least this bad, measured once", never as a
    /// coefficient. Callers using this path must label results non-conformant.
    ///
    /// **The serving rule:** one persona serves per wallet. An operator wanting
    /// several *serving* personas uses separate wallets — and should use separate
    /// machines, each with its own default-configured tor. Beyond linkability,
    /// each co-served
    /// persona is added **attack surface** (an inbound onion, intro points, a
    /// descriptor, a share of one process's failure domain) for a reward that
    /// comes from its *bond*, not from sharing a host.
    ///
    /// `tor_binary` goes through the **real SP-T0c hash-pin gate**
    /// (`binary::discover_and_verify_at`), not the test bypass: the pinned Tor
    /// Expert Bundle is what production launches, so a measurement taken against
    /// an unverified binary would be a measurement of something else. A binary
    /// that fails the pin fails the measurement.
    pub async fn bring_up(
        tor_binary: std::path::PathBuf,
        data_dir: std::path::PathBuf,
        master_seed: &[u8; 64],
        persona_count: u32,
        payload: Arc<Vec<u8>>,
    ) -> Result<Self, ApparatusError> {
        let socks_port = free_port();
        let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (readiness, mut ready_rx) = BootstrapReadiness::new();
        let verified = shekyl_tor::binary::discover_and_verify_at(&tor_binary)
            .map_err(|e| ApparatusError::Control(e.to_string()))?;
        let control = TorControl::spawn(TorControlConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: verified,
                data_dir,
                socks_port: SocksPort::Fixed(socks_port),
                disable_network: false,
                exit_observer: None,
            }),
            events: EventSink::new(events_tx),
            readiness,
        });

        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if matches!(*ready_rx.borrow_and_update(), BootstrapState::Ready) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(ApparatusError::Bootstrap);
            }
            tokio::time::timeout(Duration::from_secs(10), ready_rx.changed())
                .await
                .ok();
        }

        let mut personas = Vec::new();
        for slot in 0..persona_count {
            let slot = PSlot::from_raw(slot);
            let identity = derive_onion_identity(master_seed, slot);
            let service_id = identity.service_id().clone();
            let endpoint = ServeEndpoint::bind(Arc::clone(&payload))
                .await
                .map_err(ApparatusError::Bind)?;
            let port = OnionPort::loopback(80, endpoint.addr())
                .expect("ServeEndpoint always binds loopback");
            // MaxStreams is pinned conservatively here; see SPIKE-PIN-1 in the
            // measurement report. A shard read is one stream per connection and
            // the harness never opens more, so 8 leaves headroom without letting
            // one client hold many streams on a rendezvous circuit.
            let request = AddOnion::new(identity.into_onion_key(), port, 8)
                .with_flags(OnionFlags { discard_pk: true });
            let reply = control
                .ask(Command::AddOnion(request))
                .await
                .map_err(|e| ApparatusError::Control(e.to_string()))?;
            if reply.status() != 250 {
                return Err(ApparatusError::AddOnion(reply.status()));
            }
            let published = shekyl_tor::control::onion::parse_service_id(reply.lines())
                .ok_or(ApparatusError::NoServiceId)?;
            // The address tor published must be the address the derivation
            // predicted — otherwise the client leg would dial a service that
            // exists but is not this persona's, and every fetch would fail for a
            // reason the taxonomy would misattribute to the network.
            if published != service_id {
                return Err(ApparatusError::NoServiceId);
            }
            personas.push(Persona {
                slot,
                id: PCanonicalId::from_bytes(persona_probe_id(slot)),
                service_id,
                endpoint,
            });
        }

        Ok(Self {
            control,
            socks: TorSocksEndpoint::loopback(socks_port),
            personas,
        })
    }

    /// Block until at least one persona answers, so the measurement does not
    /// record descriptor-publication delay as fetch latency.
    ///
    /// This is an **apparatus** step, and its cost is deliberately excluded from
    /// every arm: publication happens once when the persona comes online, not
    /// once per challenge, so folding it into the fetch distribution would
    /// inflate the tail with a cost a real drawn miner never pays.
    pub async fn await_reachable(&self, expected_len: usize) -> Result<Duration, ApparatusError> {
        let started = Instant::now();
        let persona = self.personas.first().ok_or(ApparatusError::NotReachable)?;
        let url = persona.shard_url(0);
        while started.elapsed() < PUBLISH_TIMEOUT {
            let probe = PCanonicalId::from_bytes(persona_probe_id(PSlot::from_raw(u32::MAX)));
            if let Ok(bytes) = self.fetch_once(&probe, &url).await {
                if bytes == expected_len {
                    return Ok(started.elapsed());
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Err(ApparatusError::NotReachable)
    }

    /// One fetch as `client_id`, returning the byte count on success.
    async fn fetch_once(&self, client_id: &PCanonicalId, url: &str) -> Result<usize, FailureKind> {
        let Ok(client) = PTorClient::for_persona(client_id, &self.socks) else {
            return Err(FailureKind::Transport);
        };
        let url = url.to_owned();
        // `blocking_get` is synchronous by design (the transport crate keeps the
        // async bridge at its consumer), so it rides `spawn_blocking` here rather
        // than stalling a runtime worker for the length of a Tor fetch.
        let joined = tokio::time::timeout(
            FETCH_CEILING,
            tokio::task::spawn_blocking(move || client.blocking_get(&url)),
        )
        .await;
        match joined {
            Err(_) => Err(FailureKind::Timeout),
            Ok(Err(_join)) => Err(FailureKind::Transport),
            Ok(Ok(Ok(body))) => Ok(body.len()),
            Ok(Ok(Err(e))) => Err(classify(&e)),
        }
    }

    /// Time one fetch of `expected_len` bytes from `persona` as `client_id`.
    ///
    /// The clock starts before the client is constructed and stops after the last
    /// byte, so circuit build is inside the timed path (§6.2) for a cold client
    /// and outside it for a warm one — which is exactly the difference the two
    /// arms report.
    pub async fn timed_fetch(
        &self,
        client_id: &PCanonicalId,
        persona_index: usize,
        expected_len: usize,
    ) -> Observation {
        let Some(persona) = self.personas.get(persona_index) else {
            return Observation::failure(Duration::ZERO, FailureKind::Transport);
        };
        let url = persona.shard_url(0);
        let start = Instant::now();
        let outcome = self.fetch_once(client_id, &url).await;
        let elapsed = start.elapsed();
        match outcome {
            // A short body is an apparatus failure, not a fast success — the
            // distinction the `Truncated` class exists to keep visible.
            Ok(len) if len == expected_len => Observation::success(elapsed),
            Ok(_) => Observation::failure(elapsed, FailureKind::Truncated),
            Err(kind) => Observation::failure(elapsed, kind),
        }
    }

    /// Total requests the endpoints actually served — the apparatus cross-check.
    #[must_use]
    pub fn served_total(&self) -> u64 {
        self.personas
            .iter()
            .map(|p| p.endpoint.request_count())
            .sum()
    }

    /// Withdraw the onions and stop tor.
    pub async fn shutdown(self) {
        // `on_stop` issues DEL_ONION for every published service before killing
        // the child, so the explicit stop here is the whole teardown.
        self.control.stop_gracefully().await.ok();
        self.control.wait_for_shutdown().await;
    }
}

/// Map a transport error to the measurement's failure taxonomy.
///
/// The mapping is coarse because the transport crate deliberately returns
/// username-free categories only (its invariant (a)) — a finer taxonomy would
/// require the crate to surface exactly the detail it is designed not to.
fn classify(e: &PTransportError) -> FailureKind {
    match e {
        // A transport-level failure below HTTP against an `.onion` target is a
        // circuit/rendezvous failure in all but name: the SOCKS dial is what
        // builds the rendezvous, so "could not connect" here means the
        // rendezvous did not come up.
        PTransportError::Request(RequestErrorKind::Transport) => FailureKind::Circuit,
        // A body that could not be read to completion.
        PTransportError::Request(RequestErrorKind::Read) => FailureKind::Truncated,
        // Proxy misconfiguration and an HTTP non-2xx share an arm because they
        // share a meaning for this measurement: **the apparatus is wrong, not the
        // network.** A 404 means the client asked for a route the endpoint does
        // not serve; a proxy error means the SOCKS endpoint was misconfigured.
        // Neither is evidence about Tor latency, and both must be visible as
        // non-network failures rather than inflating the circuit-failure count.
        PTransportError::Proxy { .. } | PTransportError::Request(RequestErrorKind::Http(_)) => {
            FailureKind::Transport
        }
    }
}

/// A deterministic stand-in client id for probing.
///
/// Distinct per slot so probes do not share a circuit; derived rather than random
/// so a run is reproducible.
fn persona_probe_id(slot: PSlot) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&slot.to_raw().to_le_bytes());
    id[4] = 0xA5;
    id
}

/// A fresh client id for the cold arm — a *different* miner each fetch.
#[must_use]
pub fn cold_client_id(sequence: u64) -> PCanonicalId {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&sequence.to_le_bytes());
    id[8] = 0xC0;
    PCanonicalId::from_bytes(id)
}

/// The single reused client id for the warm arm.
#[must_use]
pub fn warm_client_id() -> PCanonicalId {
    let mut id = [0u8; 32];
    id[0] = 0x0F;
    id[1] = 0xF0;
    PCanonicalId::from_bytes(id)
}

/// Reserve a free loopback port for tor's SOCKS listener.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// The bound SOCKS endpoint, for a caller that needs to dial directly.
impl Apparatus {
    /// The managed tor's SOCKS endpoint.
    #[must_use]
    pub fn socks(&self) -> SocketAddr {
        self.socks.addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_ids_differ_per_fetch_and_warm_id_is_stable() {
        // The whole cold/warm distinction rests on this: distinct SOCKS usernames
        // get distinct circuits, identical ones share. If cold ids collided, the
        // "cold" arm would silently be a second warm arm.
        assert_ne!(cold_client_id(0), cold_client_id(1));
        assert_ne!(cold_client_id(1), cold_client_id(2));
        assert_eq!(warm_client_id(), warm_client_id());
        assert_ne!(cold_client_id(0), warm_client_id());
    }

    #[test]
    fn probe_ids_are_slot_distinct() {
        assert_ne!(
            persona_probe_id(PSlot::from_raw(0)),
            persona_probe_id(PSlot::from_raw(1))
        );
    }

    #[test]
    fn shard_url_targets_the_spike_route_on_the_onion() {
        let id = ServiceId::parse(&"a".repeat(56)).expect("valid id");
        let persona = Persona {
            slot: PSlot::from_raw(0),
            id: PCanonicalId::from_bytes([0u8; 32]),
            service_id: id.clone(),
            // A throwaway endpoint just to build the struct; not served from.
            endpoint: {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                rt.block_on(ServeEndpoint::bind(Arc::new(vec![0u8; 1])))
                    .expect("bind")
            },
        };
        assert_eq!(
            persona.shard_url(7),
            format!("http://{}.onion/x-spike/v0/shard/7", "a".repeat(56))
        );
    }

    #[test]
    fn transport_errors_map_to_distinguishable_classes() {
        // A read failure must not be reported as a circuit failure: the verdict
        // turns on separating "Tor was slow/unreachable" from "the apparatus
        // returned a short body".
        assert_eq!(
            classify(&PTransportError::Request(RequestErrorKind::Transport)),
            FailureKind::Circuit
        );
        assert_eq!(
            classify(&PTransportError::Request(RequestErrorKind::Read)),
            FailureKind::Truncated
        );
    }
}
