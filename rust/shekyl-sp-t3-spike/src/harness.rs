// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D6 — the live apparatus, **re-based daemon→wallet** (`ARCHIVAL_SHARD_FETCH.md`
//! §9.1 step (c)): one *client* tor standing in for the daemon, one *serving*
//! tor per persona standing in for each wallet host, and the production fetch
//! client timing fetches over real rendezvous circuits.
//!
//! Separated from the measurement binary so the same wiring is exercised by an
//! `#[ignore]`d live test (with a small payload, as apparatus validation), by a
//! loopback test with no tor at all (the client leg against the production
//! endpoint through a SOCKS shim), and by the real measurement (with the 3.33 MB
//! shard). A harness only the binary can reach is a harness nothing checks.
//!
//! # The topology, and why it changed
//!
//! The first rig ran **persona→persona**: one tor hosted the onions *and* dialled
//! them, with `shekyl-p-transport`'s per-client SOCKS isolation producing the
//! cold/warm arms. `EU-D1` then ruled the protocol **daemon→wallet** — the
//! daemon is the client, and it dials through its own tor zone with **no**
//! per-fetch isolation (`SF-D2`, `SF-D3`: circuits are reused). Since `SF` (a)
//! the serve side also requires the `SF-D5` request header and countersigns
//! the body, which `blocking_get` cannot carry; every fetch through the old leg
//! was the identical 404. So the leg is now [`shekyl_p_fetch::PFetchClient`],
//! the shipped daemon client, and the process split matches the protocol:
//!
//! - **Client tor** — the daemon's. Every fetch dials through its SOCKS port.
//!   Its circuit state is what the cold and warm arms manipulate.
//! - **One serving tor per persona** — the wallet hosts'. One persona on the
//!   wire per tor is the *conformant* shape (many held, one serving —
//!   `ARCHIVAL_BOND_CONSTRUCTION.md:667`), so a multi-persona apparatus models
//!   several independent operators rather than the co-serving layout the
//!   firewall forbids (§10.9) and the old rig priced at ×1.54. Guard sets are
//!   per process; only the box's bandwidth is shared, and that is named as a
//!   confound in the report rather than hidden in the arm.
//!
//! # Cold vs warm on a no-isolation client
//!
//! §6.2 asks for circuit setup to be inside the timed path unless a warm circuit
//! is defensible, and for both to be reported. With the production client there
//! is no per-fetch SOCKS username to vary, so the arms come from what a real
//! daemon's tor does over time rather than from an isolation key:
//!
//! - **Cold** — [`Apparatus::rotate_client_circuits`] sends `SIGNAL NEWNYM` to
//!   the **client** tor before the fetch. Tor marks every client circuit dirty
//!   and purges its client-side onion-service state (descriptor cache,
//!   intro-point state), so the next fetch pays the **descriptor fetch, the
//!   intro circuit, and the rendezvous circuit** from nothing. That is the
//!   first-contact cost a drawn miner pays for a `P` it has never dialled — the
//!   challenge shape — and it is *colder* than the old isolation arm, which
//!   shared one tor's descriptor cache across its "distinct" clients. The
//!   signal is process-global, which is exactly why the client tor is its own
//!   process here: it rotates nothing on the serving side. Tor rate-limits
//!   `NEWNYM` to one per ten seconds and silently defers a faster one, so the
//!   harness spaces its signals itself; that wait is *outside* the timed path.
//! - **Warm** — no signal between fetches to the same persona, so the client
//!   tor reuses its rendezvous circuit and only the stream cost is paid. This
//!   is the organic fill scheduler's steady state against one `P`.
//! - **Concurrent** — `n` cold fetches to `n` personas at once through the one
//!   client tor: the client-side circuit-churn question `SF-D7` names as the
//!   upper bound on `N`. One [`PFetchClient`] **per persona** here, so the
//!   sweep is never shaped by the SPIKE-PIN semaphore it exists to replace —
//!   a production daemon has exactly one client, and the crate says so; the
//!   rig multiplies them on purpose to measure what `N` *could* be rather than
//!   what it *is*.
//!
//! # The chain the apparatus does not have
//!
//! `P` gates `anchor_height` against its own height (`SF-D5`) and the client
//! anchors at `tip − 720`. The spike has no chain, so both sides read one
//! shared number, [`APPARATUS_OWN_HEIGHT`], and the anchor hash is a fixed
//! constant: `P` signs the decoded header bytes without interpreting them, and
//! the hash is only ever *looked up* at block admission, which is consensus's
//! job and not this rig's. The countersignature is verified for real, under
//! the persona's ephemeral test key, which the client leg reads at bring-up the
//! way a daemon reads the bond record.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kameo::actor::Spawn as _;
use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_p_fetch::{
    ContentRefused, ContentVerify, FetchError, FetchTarget, PFetchClient, RequestHeader,
    ServingEndpoint, Stall, Timeouts,
};
use shekyl_tor_control_client::control::onion::{
    AddOnion, OnionFlags, OnionPort, OnionPow, ServiceId,
};
use shekyl_tor_control_client::control::{
    BootstrapReadiness, BootstrapState, Command, EventSink, ManagedTor, Signal, SocksPort,
    TorControlClient, TorControlClientConfig, TorLaunch,
};
use shekyl_types::PSlot;

use shekyl_p_serve::{PServeEndpoint, ShardBody, TestKeySigner};

use crate::fixture::FixtureShardProvider;
use crate::measure::{FailureKind, Observation};
use crate::onion_key::derive_onion_identity;

/// The apparatus's fixed chain view: the height every persona reports for
/// the `SF-D5` pre-sign gate, and the height the client leg anchors its
/// request header against (`tip − 720`). The spike has no chain; one shared
/// number is what makes the gate pass for the right reason.
pub const APPARATUS_OWN_HEIGHT: u64 = 100_000;

/// The anchor height every request carries: `APPARATUS_OWN_HEIGHT − 720`, the
/// value a synced daemon would compute against its own tip.
pub const APPARATUS_ANCHOR_HEIGHT: u64 = APPARATUS_OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS;

/// The anchor hash every request carries. Fixed, not looked up: the rig has
/// no chain to read `block_hash(anchor_height)` from, `P` never interprets
/// it, and the client verifies the countersignature over the header *it
/// sent*. Only block admission compares it against a chain, and that is not
/// this apparatus.
pub const APPARATUS_ANCHOR_HASH: [u8; 32] = [0x5a; 32];

/// Ceiling on a single fetch before the harness calls it a timeout.
///
/// Above the sum of the production client's own per-step bounds
/// ([`Timeouts::DEFAULT`]: dial + head + body), so the client's bound fires
/// first and the harness ceiling is only a backstop — that way a timeout is
/// classified by the layer that actually knows why.
pub const FETCH_CEILING: Duration = Duration::from_secs(720);

/// How long to wait for a freshly-published descriptor to become reachable.
///
/// Descriptor upload to the HSDirs plus a client's fetch of it takes tens of
/// seconds on a cold service; this bounds the wait rather than assuming it.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(300);

/// Tor's `MAX_SIGNEWNYM_RATE`: a `NEWNYM` within this many seconds of the
/// last is acknowledged and *deferred*, not applied. The cold arm must not
/// time a fetch believing the rotation happened when tor is still holding
/// it, so [`Apparatus::rotate_client_circuits`] waits this out first.
pub const NEWNYM_MIN_SPACING: Duration = Duration::from_secs(10);

/// How long a managed tor may take to bootstrap before bring-up gives up.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);

/// The apparatus's **pinned** derivation seed — the harness takes no seed from
/// its caller, by design.
///
/// SPIKE-F-4 relocated the onion-key derivation onto the *production* GF-9 path
/// ([`derive_onion_identity`] → `shekyl_crypto_pq::archival_p::derive_p_hs_id_seed`).
/// A consequence the old spike-local label used to mask: feeding a real wallet's
/// `master_seed_64` here would now serve at the persona's **actual production
/// `.onion`** — the co-activation Model D forbids (`BOND_CONSTRUCTION.md:667`,
/// one persona on the wire per wallet). The apparatus is *retained* (rule 15) for
/// the owed Tor hop-latency measurement, so it will be run again; pinning the
/// seed makes "never point this at a wallet" an enforced invariant rather than
/// operator discipline. Distinct personas come from the `p_slot` sweep, not from
/// distinct seeds, so parameterizing the seed bought nothing the sweep does not.
///
/// Kept **private**: it is the harness's internal fixed context, not public API —
/// a `publish = false` spike must not invite external coupling to a test seed. The
/// derivation network/format are pinned alongside it at the one call site
/// (`Mainnet`/`Bip39`; the `.onion` value is irrelevant to a latency measurement,
/// so any fixed context works, and this one matches the KAT's slot-0 vector).
const APPARATUS_PINNED_SEED: [u8; 64] = [0x11u8; 64];

/// One managed tor process: its control actor and the SOCKS port it listens on.
struct ManagedInstance {
    control: kameo::actor::ActorRef<TorControlClient>,
    socks: SocketAddr,
}

impl ManagedInstance {
    /// Launch `tor_binary` with `data_dir` and wait for it to bootstrap.
    ///
    /// `tor_binary` goes through the **real SP-T0c hash-pin gate**
    /// (`binary::discover_and_verify_at`), not the test bypass: the pinned Tor
    /// Expert Bundle is what production launches, so a measurement taken against
    /// an unverified binary would be a measurement of something else. A binary
    /// that fails the pin fails the measurement.
    async fn launch(tor_binary: &Path, data_dir: PathBuf) -> Result<Self, ApparatusError> {
        let socks_port = free_port();
        let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (readiness, mut ready_rx) = BootstrapReadiness::new();
        let verified = shekyl_tor_control_client::binary::discover_and_verify_at(tor_binary)
            .map_err(|e| ApparatusError::Control(e.to_string()))?;
        let control = TorControlClient::spawn(TorControlClientConfig {
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

        let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
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

        Ok(Self {
            control,
            socks: SocketAddr::from(([127, 0, 0, 1], socks_port)),
        })
    }

    /// Stop the process. `on_stop` issues `DEL_ONION` for every published
    /// service before killing the child, so this is the whole teardown.
    async fn shutdown(self) {
        self.control.stop_gracefully().await.ok();
        self.control.wait_for_shutdown().await;
    }
}

/// A persona serving a shard over its own onion, behind its own tor.
pub struct Persona {
    /// The persona's slot.
    pub slot: PSlot,
    /// Its published onion.
    pub service_id: ServiceId,
    /// The loopback endpoint tor forwards to — the **production** serving
    /// loop (`shekyl_p_serve`), driven here with a fixture provider. The
    /// spike measures what ships, not a lookalike.
    pub endpoint: PServeEndpoint,
    /// What a daemon reads from the bond record before dialling: the
    /// endpoint column and the identity key (`SF-D13`). Read once here at
    /// bring-up, from the same material the onion was published from.
    serving: ServingEndpoint,
    verifying_key: HybridPublicKey,
    /// The wallet host's tor — one per persona, the conformant shape.
    tor: ManagedInstance,
}

impl Persona {
    /// The persona's published `.onion` service id.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// The key this persona countersigns under — what a reader on another
    /// host needs beside the onion to verify the body (`SF-D8`). In
    /// production this is the bond record's identity key; here it is the
    /// ephemeral test key minted at bring-up.
    #[must_use]
    pub fn verifying_key(&self) -> &HybridPublicKey {
        &self.verifying_key
    }

    /// The typed fetch target for shard `shard_id`, as a scheduler would
    /// build it from local chain state.
    #[must_use]
    pub fn target(&self, shard_id: u64) -> FetchTarget {
        FetchTarget {
            endpoint: self.serving,
            verifying_key: self.verifying_key.clone(),
            shard_id,
        }
    }
}

/// The client leg: the production [`PFetchClient`], one per persona.
///
/// Public so the loopback test can drive it against a `PServeEndpoint`
/// through a SOCKS shim with no tor in the picture — the wiring the live
/// test and the measurement then run over real circuits.
pub struct ClientLeg {
    lanes: Vec<PFetchClient>,
}

impl ClientLeg {
    /// `lanes` clients dialling through `proxy` with the production bounds.
    #[must_use]
    pub fn new(proxy: SocketAddr, lanes: usize) -> Self {
        Self {
            lanes: (0..lanes.max(1))
                .map(|_| PFetchClient::with_timeouts(proxy, Timeouts::DEFAULT))
                .collect(),
        }
    }

    /// One fetch on lane `lane` (modulo the lane count), returning the
    /// verified body length on success.
    ///
    /// The header is minted fresh per call ([`RequestHeader::fresh`]) with the
    /// apparatus anchor, exactly as a daemon mints one per need; the content
    /// hole accepts every body, because what the rig checks is the
    /// transport and the countersignature, not `R_k`.
    pub async fn fetch_once(
        &self,
        lane: usize,
        target: &FetchTarget,
    ) -> Result<usize, FailureKind> {
        let client = &self.lanes[lane % self.lanes.len()];
        let header = RequestHeader::fresh(APPARATUS_ANCHOR_HEIGHT, APPARATUS_ANCHOR_HASH)
            .map_err(|_| FailureKind::Refused)?;
        let fetched = tokio::time::timeout(
            FETCH_CEILING,
            client.fetch(target, &header, Arc::new(AcceptAnyContent)),
        )
        .await;
        match fetched {
            Err(_) => Err(FailureKind::Timeout),
            Ok(Ok(shard)) => Ok(shard.body().len()),
            Ok(Err(e)) => Err(classify(&e)),
        }
    }
}

/// The content-verify hole, plugged open: the rig measures transport and
/// the countersignature, and compares body *length* itself so a short body
/// stays `Truncated` rather than becoming a content refusal.
struct AcceptAnyContent;

impl ContentVerify for AcceptAnyContent {
    fn verify(&self, _shard_id: u64, _body: &[u8]) -> Result<(), ContentRefused> {
        Ok(())
    }
}

/// A running measurement apparatus: the client tor and leg, plus the
/// published personas behind their own tors.
pub struct Apparatus {
    client_tor: ManagedInstance,
    client: ClientLeg,
    /// Wall-clock of the last `NEWNYM` sent to the client tor, for the
    /// rate-limit spacing.
    last_newnym: Mutex<Option<Instant>>,
    /// The published personas, in slot order.
    pub personas: Vec<Persona>,
    /// The body length every fetch is checked against — **derived, never
    /// passed in.**
    ///
    /// Computed once at bring-up from the payload, through the production
    /// serving contract ([`shekyl_p_serve::ShardBody::header`]), so it is
    /// the length the endpoint will actually write: `RF-D4`'s frame header
    /// plus the leaf bytes. (The client strips the countersignature envelope
    /// before handing the body over, so the envelope is not in this figure.)
    /// Before this field existed every caller passed the raw fixture length,
    /// and when the frame landed that number went stale at four call sites at
    /// once. A number a caller supplies is a number that drifts when the wire
    /// moves; a number the apparatus derives from the same code that writes
    /// the wire cannot.
    expected_len: usize,
}

/// Why the apparatus could not be brought up. Every arm is an *apparatus*
/// failure, deliberately distinct from a fetch failure: a measurement that
/// silently ran against a broken apparatus is worse than no measurement.
#[derive(Debug)]
pub enum ApparatusError {
    /// A tor did not bootstrap within the deadline.
    Bootstrap,
    /// A control connection failed.
    Control(String),
    /// `ADD_ONION` was refused.
    AddOnion(u16),
    /// tor's reply carried no parseable service id, or published an id other
    /// than the one the derivation predicted.
    NoServiceId,
    /// The serve endpoint could not bind loopback.
    Bind(std::io::Error),
    /// No persona became reachable within [`PUBLISH_TIMEOUT`].
    NotReachable,
    /// The payload cannot be served at all: not a whole number of leaves, or
    /// more than one segment. Refused at bring-up, because an apparatus that
    /// serves a 404 for every shard measures nothing.
    Unframeable {
        /// The offending payload length.
        bytes: usize,
    },
}

impl std::fmt::Display for ApparatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap => write!(f, "tor did not bootstrap"),
            Self::Control(e) => write!(f, "control connection failed: {e}"),
            Self::AddOnion(s) => write!(f, "ADD_ONION refused with status {s}"),
            Self::NoServiceId => write!(
                f,
                "ADD_ONION reply carried no service id, or not the derived one"
            ),
            Self::Bind(e) => write!(f, "serve endpoint bind failed: {e}"),
            Self::NotReachable => write!(f, "no persona became reachable before the deadline"),
            Self::Unframeable { bytes } => write!(
                f,
                "payload of {bytes} bytes is not servable (not a whole number of leaves, or \
                 more than one segment)"
            ),
        }
    }
}

impl std::error::Error for ApparatusError {}

impl Apparatus {
    /// Bring up `persona_count` personas, each serving `payload` behind its
    /// own tor, plus the client tor the fetches dial through.
    ///
    /// `persona_count` is the width of the concurrent arm: `n` personas are
    /// `n` independent wallet hosts a daemon can have fetches in flight to at
    /// once. Each is its own tor process (the conformant one-persona shape);
    /// bring-up launches them in parallel, so the cost is one bootstrap's
    /// wall-clock, not `n`. Everything on one box shares the box's uplink —
    /// a confound the concurrent arm's report names, and one that biases it
    /// pessimistic.
    ///
    /// `data_dir` is the root; each tor gets a sub-directory under it.
    pub async fn bring_up(
        tor_binary: PathBuf,
        data_dir: PathBuf,
        persona_count: u32,
        payload: Arc<[u8]>,
    ) -> Result<Self, ApparatusError> {
        Self::bring_up_with_pow(
            tor_binary,
            data_dir,
            persona_count,
            payload,
            OnionPow::Disabled,
        )
        .await
    }

    /// [`Self::bring_up`] with the onions' PoW defenses selected.
    ///
    /// Split out for SPIKE-F-11's two arms: the same apparatus is measured with
    /// PoW off and on, and the difference between those runs is the honest-client
    /// cost of the defense (SPIKE-F-15's coupling). `bring_up` keeps its old
    /// signature and defaults to [`OnionPow::Disabled`], which is what every
    /// existing caller and the recorded `D*` were measured under.
    pub async fn bring_up_with_pow(
        tor_binary: PathBuf,
        data_dir: PathBuf,
        persona_count: u32,
        payload: Arc<[u8]>,
        pow: OnionPow,
    ) -> Result<Self, ApparatusError> {
        // The expected body length, derived through the production contract
        // BEFORE any tor is launched: the same `ShardBody::flat` the fixture
        // provider will call per request, so what the probes compare against
        // is what the endpoint will write — frame header included.
        let expected_len = ShardBody::flat(Arc::clone(&payload))
            .ok_or(ApparatusError::Unframeable {
                bytes: payload.len(),
            })?
            .header()
            .framed_len();
        let expected_len = usize::try_from(expected_len).expect("framed length fits usize");

        // Launch every tor at once: the client's and one per persona.
        let tor_binary = Arc::<Path>::from(tor_binary);
        let mut launches = tokio::task::JoinSet::new();
        {
            let bin = Arc::clone(&tor_binary);
            let dir = data_dir.join("client-tor");
            launches.spawn(async move { (None, ManagedInstance::launch(&bin, dir).await) });
        }
        for slot in 0..persona_count {
            let bin = Arc::clone(&tor_binary);
            let dir = data_dir.join(format!("persona-{slot}-tor"));
            launches.spawn(async move { (Some(slot), ManagedInstance::launch(&bin, dir).await) });
        }
        let mut client_tor = None;
        let mut serving_tors: Vec<Option<ManagedInstance>> =
            (0..persona_count).map(|_| None).collect();
        while let Some(joined) = launches.join_next().await {
            let (which, launched) = joined.map_err(|e| ApparatusError::Control(e.to_string()))?;
            let instance = launched?;
            match which {
                None => client_tor = Some(instance),
                Some(slot) => {
                    serving_tors[usize::try_from(slot).expect("slot fits usize")] = Some(instance);
                }
            }
        }
        let client_tor = client_tor.ok_or(ApparatusError::Bootstrap)?;

        let mut personas = Vec::new();
        for (slot, tor) in serving_tors.into_iter().enumerate() {
            let tor = tor.ok_or(ApparatusError::Bootstrap)?;
            let slot = PSlot::from_raw(u32::try_from(slot).expect("slot fits u32"));
            // One pinned derivation context (see `APPARATUS_PINNED_SEED`): the
            // fixed test seed under mainnet/bip39. Explicit here, not hidden in
            // the derivation.
            let identity = derive_onion_identity(
                &APPARATUS_PINNED_SEED,
                DerivationNetwork::Mainnet,
                SeedFormat::Bip39,
                slot,
            );
            let service_id = identity.service_id().clone();
            // The "bond record" the client leg will dial from: the endpoint
            // column is the onion's public key, and the two encodings of it
            // (tor's service id, `shekyl-onion-v3`'s hostname) must agree or
            // the client would dial a service that is not this persona's.
            let serving = ServingEndpoint::from_record_bytes(identity.public_key());
            if serving.onion_address() != service_id.hostname() {
                return Err(ApparatusError::NoServiceId);
            }
            // An ephemeral attestation key per persona: the spike measures
            // the shipped serve path, and signing is on it. Its own height is
            // the apparatus's fixed chain view; the client leg anchors its
            // requests against the same number.
            let signer = Arc::new(TestKeySigner::ephemeral(APPARATUS_OWN_HEIGHT));
            let verifying_key = signer.public_key().clone();
            let endpoint = PServeEndpoint::bind(
                Arc::new(FixtureShardProvider::new(Arc::clone(&payload))),
                signer,
            )
            .await
            .map_err(ApparatusError::Bind)?;
            let port = OnionPort::loopback(80, endpoint.addr())
                .expect("PServeEndpoint always binds loopback");
            // MaxStreams is pinned conservatively here; see SPIKE-PIN-1 in the
            // measurement report. A shard read is one stream per connection and
            // the harness never opens more, so 8 leaves headroom without letting
            // one client hold many streams on a rendezvous circuit.
            let request = AddOnion::new(identity.mint_onion_key(), port, 8)
                .with_flags(OnionFlags { discard_pk: true })
                .with_pow(pow);
            let reply = tor
                .control
                .ask(Command::AddOnion(request))
                .await
                .map_err(|e| ApparatusError::Control(e.to_string()))?;
            if reply.status() != 250 {
                return Err(ApparatusError::AddOnion(reply.status()));
            }
            let published =
                shekyl_tor_control_client::control::onion::parse_service_id(reply.lines())
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
                service_id,
                endpoint,
                serving,
                verifying_key,
                tor,
            });
        }

        let client = ClientLeg::new(client_tor.socks, personas.len());
        Ok(Self {
            client_tor,
            client,
            last_newnym: Mutex::new(None),
            personas,
            expected_len,
        })
    }

    /// The body length every fetch is checked against: frame header plus
    /// shard, as the endpoint writes it and the client hands it over.
    /// Exposed so operators and logs can print the number a remote reader
    /// should expect.
    #[must_use]
    pub fn expected_body_len(&self) -> usize {
        self.expected_len
    }

    /// The client tor's SOCKS endpoint — the "daemon's tor zone" every fetch
    /// dials through.
    #[must_use]
    pub fn client_socks(&self) -> SocketAddr {
        self.client_tor.socks
    }

    /// Block until at least one persona answers, so the measurement does not
    /// record descriptor-publication delay as fetch latency.
    ///
    /// This is an **apparatus** step, and its cost is deliberately excluded from
    /// every arm: publication happens once when the persona comes online, not
    /// once per challenge, so folding it into the fetch distribution would
    /// inflate the tail with a cost a real drawn miner never pays.
    pub async fn await_reachable(&self) -> Result<Duration, ApparatusError> {
        let started = Instant::now();
        let persona = self.personas.first().ok_or(ApparatusError::NotReachable)?;
        let target = persona.target(0);
        while started.elapsed() < PUBLISH_TIMEOUT {
            if let Ok(bytes) = self.client.fetch_once(0, &target).await {
                if bytes == self.expected_len {
                    return Ok(started.elapsed());
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Err(ApparatusError::NotReachable)
    }

    /// Make the next fetch **cold**: `SIGNAL NEWNYM` to the client tor, so it
    /// drops every client circuit and its onion-service client state.
    ///
    /// Waits out tor's ten-second rate limit first — a signal inside the
    /// window is acknowledged and deferred, which would let the "cold" fetch
    /// run on the old circuits. The wait is not timed; call this, then
    /// [`Self::timed_fetch`]. Process-global by nature, so a concurrent arm
    /// rotates once before its batch, not once per fetch.
    pub async fn rotate_client_circuits(&self) -> Result<(), ApparatusError> {
        let wait = {
            let last = self.last_newnym.lock().expect("newnym clock");
            last.map(|t| NEWNYM_MIN_SPACING.saturating_sub(t.elapsed()))
        };
        if let Some(wait) = wait.filter(|w| !w.is_zero()) {
            tokio::time::sleep(wait).await;
        }
        let reply = self
            .client_tor
            .control
            .ask(Command::Signal(Signal::NewNym))
            .await
            .map_err(|e| ApparatusError::Control(e.to_string()))?;
        if reply.status() != 250 {
            return Err(ApparatusError::Control(format!(
                "SIGNAL NEWNYM answered {}",
                reply.status()
            )));
        }
        *self.last_newnym.lock().expect("newnym clock") = Some(Instant::now());
        Ok(())
    }

    /// Time one fetch of shard `0` from `persona_index` through the client tor.
    ///
    /// The clock starts before the header is minted and stops after the
    /// countersignature verifies, so on a cold client (after
    /// [`Self::rotate_client_circuits`]) descriptor fetch, intro, and
    /// rendezvous are inside the timed path (§6.2), and on a warm one only
    /// the stream is. Success means the verified body was exactly
    /// [`Self::expected_body_len`] bytes; anything shorter is `Truncated`.
    pub async fn timed_fetch(&self, persona_index: usize) -> Observation {
        let Some(persona) = self.personas.get(persona_index) else {
            return Observation::failure(Duration::ZERO, FailureKind::Refused);
        };
        let target = persona.target(0);
        let start = Instant::now();
        let outcome = self.client.fetch_once(persona_index, &target).await;
        let elapsed = start.elapsed();
        match outcome {
            // A short body is an apparatus failure, not a fast success — the
            // distinction the `Truncated` class exists to keep visible.
            Ok(len) if len == self.expected_len => Observation::success(elapsed),
            Ok(_) => Observation::failure(elapsed, FailureKind::Truncated),
            Err(kind) => Observation::failure(elapsed, kind),
        }
    }

    /// Total requests the endpoints actually served — the apparatus cross-check.
    #[must_use]
    pub fn served_total(&self) -> u64 {
        self.personas
            .iter()
            .map(|p| p.endpoint.served_count())
            .sum()
    }

    /// Total connections shed for exceeding the serve-side in-flight cap
    /// ([`MAX_INFLIGHT`](shekyl_p_serve::MAX_INFLIGHT)).
    ///
    /// The signal that `SPIKE-PIN-2` is binding: a non-zero value during a
    /// SPIKE-F-11 sweep means the **cap**, not the transport, is shaping the
    /// tail — so the reported latency would be a measurement of the placeholder
    /// rather than of the service, and the sweep point must be discarded or the
    /// cap raised before it is believed.
    #[must_use]
    pub fn refused_total(&self) -> u64 {
        self.personas
            .iter()
            .map(|p| p.endpoint.refused_count())
            .sum()
    }

    /// Withdraw the onions and stop every tor.
    pub async fn shutdown(self) {
        for persona in self.personas {
            persona.tor.shutdown().await;
        }
        self.client_tor.shutdown().await;
    }
}

/// Map the production client's error taxonomy onto the measurement's.
///
/// `SF-D6` types outcomes by what the *scheduler* should do next; §6.4 types
/// them by whether Tor or the apparatus is to blame. The two agree on the
/// no-complete-exchange side (a stall is the network) and collapse on the
/// completed side: every decided refusal — miss, malformed, bad
/// countersignature, content — means the apparatus, not the path, is wrong.
fn classify(e: &FetchError) -> FailureKind {
    match e {
        // The SOCKS dial against an `.onion` is what builds the rendezvous, so
        // "could not connect" means the rendezvous did not come up.
        FetchError::Stall(Stall::DialTimeout | Stall::Dial(_)) => FailureKind::Circuit,
        // The connection came up and then went quiet.
        FetchError::Stall(Stall::HeadTimeout | Stall::BodyTimeout | Stall::NoClose) => {
            FailureKind::Timeout
        }
        // Bytes stopped short, or the stream broke.
        FetchError::Stall(Stall::ClosedBeforeHead | Stall::Truncated { .. } | Stall::Io(_)) => {
            FailureKind::Truncated
        }
        FetchError::Miss
        | FetchError::Malformed(_)
        | FetchError::BadCountersignature
        | FetchError::ContentRefused(_) => FailureKind::Refused,
    }
}

/// Reserve a free loopback port for a tor's SOCKS listener.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local_addr")
        .port()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_p_fetch::Malformed;

    #[test]
    fn anchor_is_the_burial_depth_below_own_height() {
        // The one number both sides read: P gates the anchor against its own
        // height ± L, and the client anchors at tip − 720. If these drifted
        // apart every fetch would be the identical 404 and the taxonomy would
        // call it `Refused` — visible, but for the wrong reason.
        assert_eq!(
            APPARATUS_OWN_HEIGHT - APPARATUS_ANCHOR_HEIGHT,
            PASS_ANCHOR_DEPTH_BLOCKS
        );
    }

    #[test]
    fn fetch_ceiling_is_a_backstop_above_the_client_bounds() {
        // The client's own bounds must fire first, so a timeout is classified
        // by the layer that knows which step stalled.
        let t = Timeouts::DEFAULT;
        assert!(FETCH_CEILING > t.dial + t.head + t.body_total);
    }

    #[test]
    fn fetch_errors_map_to_distinguishable_classes() {
        // A read failure must not be reported as a circuit failure: the verdict
        // turns on separating "Tor was slow/unreachable" from "the apparatus
        // returned a short body" from "the apparatus refused the exchange".
        assert_eq!(
            classify(&FetchError::Stall(Stall::DialTimeout)),
            FailureKind::Circuit
        );
        assert_eq!(
            classify(&FetchError::Stall(Stall::HeadTimeout)),
            FailureKind::Timeout
        );
        assert_eq!(
            classify(&FetchError::Stall(Stall::Truncated {
                declared: 10,
                received: 3
            })),
            FailureKind::Truncated
        );
        assert_eq!(classify(&FetchError::Miss), FailureKind::Refused);
        assert_eq!(
            classify(&FetchError::Malformed(Malformed::Status(500))),
            FailureKind::Refused
        );
        assert_eq!(
            classify(&FetchError::BadCountersignature),
            FailureKind::Refused
        );
    }
}
