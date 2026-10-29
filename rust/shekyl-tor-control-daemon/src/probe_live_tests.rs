// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe against a real Tor (`TOR_SUPERVISOR.md` §4.5; the probe
//! brief's tests 6 to 8).
//!
//! A stand-in at the onion's forward target plays this node's inbound
//! handshake: the probe's request arriving there is the nonce arriving.
//! The C++ handshake that recognises the nonce is not in a cargo test; the
//! dialer's take and the FFI's code are pinned by their own tests, and §7
//! runs the whole path on the daemon. These tests pin what only a real Tor
//! can: the dial with its own pair reaches the onion on a circuit of its
//! own, a respawn into the kept directory republishes the same onion and
//! is reachable again, and a deleted onion is missed and restored by the
//! republish, which must delete before it adds.

use std::net::SocketAddr;
use std::time::Duration;

use shekyl_socks::Proxy;
use shekyl_tor_control_client::control::{
    Command, EventReceiver, EventSink, RoundMark, ServiceId, TorEvent, UploadRounds,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use std::path::PathBuf;

use shekyl_tor_control_client::binary::VerifiedTorBinary;
use shekyl_tor_control_client::control::{AddOnionReplyError, SocksTimeout};

#[cfg(target_os = "linux")]
use crate::ephemeral::tests::tor_under;
use crate::ephemeral::tests::wait_for_the_network;
use crate::probe::{probe_own_onion, IsolationPair, ProbeDial};
use crate::test_support::tor_binary;
use crate::{DaemonTorConfig, DaemonTorControl, DaemonTorPublishError, OnionPow, OnionSeed};

/// The onion's virtual port in these tests.
const VIRTUAL_PORT: u16 = 11021;
/// The probe's bound (`TSR-M2`), as the supervisor's core holds it.
const PROBE_WITHIN: Duration = Duration::from_secs(60);
/// The supervisor's shortest delay after a round's first upload (§10).
const PROBE_AFTER: Duration = Duration::from_secs(15);
/// How long a test waits for a round. Not a daemon bound.
const ROUND_HANG: Duration = Duration::from_secs(300);
/// How long after a round's first upload a test waits for the round to end.
const ROUND_SETTLE: Duration = Duration::from_secs(60);

/// The forward target: an accepted stream whose first bytes are the probe's
/// request is the probe arriving. It is reported, then held until the test
/// releases it, so the stream can be seen on its circuit; then it is closed,
/// as this node's handshake drops its own probe. Any other stream is held
/// open (a peer dial's stand-in) until the test ends.
struct StandIn {
    at: SocketAddr,
    arrivals: mpsc::UnboundedReceiver<Instant>,
    release: std::sync::Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl StandIn {
    async fn bind(request: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let at = listener.local_addr().expect("addr");
        let (tx, arrivals) = mpsc::unbounded_channel();
        let release = std::sync::Arc::new(Notify::new());
        let held = std::sync::Arc::clone(&release);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let request = request.clone();
                let tx = tx.clone();
                let held = std::sync::Arc::clone(&held);
                tokio::spawn(async move {
                    let mut first = vec![0u8; request.len()];
                    if stream.read_exact(&mut first).await.is_err() {
                        return;
                    }
                    if first == request {
                        let _sent = tx.send(Instant::now());
                        held.notified().await;
                        drop(stream);
                    } else {
                        let mut sink = [0u8; 64];
                        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
                    }
                });
            }
        });
        Self {
            at,
            arrivals,
            release,
            task,
        }
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A probe request carrying fresh random bytes, as a nonce does.
fn request() -> Vec<u8> {
    let mut bytes = b"probe ".to_vec();
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("entropy");
    bytes.extend_from_slice(&nonce);
    bytes
}

fn subscribed_config(
    binary: VerifiedTorBinary,
    parent: PathBuf,
    events: EventSink,
) -> DaemonTorConfig {
    DaemonTorConfig {
        tor_binary: binary,
        data_dir_parent: parent,
        events,
        reply_deadline: Duration::from_secs(30),
        socks_timeout: SocksTimeout::TorDefault,
    }
}

async fn subscribe(boot: &DaemonTorControl) {
    let reply = boot
        .ask(Command::supervisor_events())
        .await
        .expect("SETEVENTS");
    assert_eq!(reply.status(), 250);
}

/// Wait for `service`'s next round to finish uploading: its first
/// successful upload, then the round's end or [`ROUND_SETTLE`] after that
/// upload, whichever comes first. `TSR-M3` probed after its uploads had
/// settled; a probe right after the first upload can find the descriptor
/// for the current period not yet on the directories (`0xF0`), which is
/// the core's timing question, not what these tests pin.
async fn round_uploaded(received: &mut EventReceiver, service: &ServiceId) {
    let mut rounds = UploadRounds::new(service.clone());
    let hang = Instant::now() + ROUND_HANG;
    let mut settle: Option<Instant> = None;
    loop {
        let until = settle.map_or(hang, |at| at.min(hang));
        let Ok(reply) = tokio::time::timeout_at(until, received.recv()).await else {
            assert!(settle.is_some(), "an upload round in time");
            return;
        };
        let reply = reply.expect("the sink is open");
        let Some(TorEvent::HsDesc(desc)) = shekyl_tor_control_client::control::parse_event(&reply)
        else {
            continue;
        };
        for mark in rounds.observe(&desc) {
            match mark {
                RoundMark::FirstUploaded => settle = Some(Instant::now() + ROUND_SETTLE),
                RoundMark::Ended { uploaded, .. } if uploaded > 0 && settle.is_some() => return,
                _ => {}
            }
        }
    }
}

/// Probe `service` through `proxy` and wait up to the bound for the
/// stand-in to see the request. `Some(latency)` when it arrived.
async fn probe_once(
    proxy: &Proxy,
    service: &ServiceId,
    stand_in: &mut StandIn,
    request: &[u8],
) -> (Option<Duration>, Option<ProbeDial>) {
    let started = Instant::now();
    let dial = probe_own_onion(proxy, service, VIRTUAL_PORT, request);
    tokio::pin!(dial);
    let bound = started + PROBE_WITHIN;
    tokio::select! {
        arrived = tokio::time::timeout_at(bound, stand_in.arrivals.recv()) => {
            match arrived {
                Ok(Some(at)) => (Some(at.duration_since(started)), None),
                _ => (None, None),
            }
        }
        ended = &mut dial => {
            // The dial ended before an arrival: it can only have failed.
            let late = tokio::time::timeout_at(bound, stand_in.arrivals.recv()).await;
            (late.ok().flatten().map(|at| at.duration_since(started)), Some(ended))
        }
    }
}

/// The rounds a test gives the supervisor's remedy (§4.4) before it fails.
const REMEDY_ROUNDS: u32 = 3;

/// Probe `service` after its round, and on a miss do what the supervisor
/// does: publish it again and probe after that round. Returns the round the
/// probe arrived in (1 is the first) and its latency, with the stand-in
/// still holding the probe's stream.
///
/// A single probe can miss on a healthy Tor: on the x86 diagnostic of
/// 2026-10-29 (tor 0.4.9.13) a first probe after the first round's uploads
/// answered `0xF0`, and one probe after a republish missed while the same
/// Tor still held its client state from the miss before it (`TOR_SUPERVISOR.md`
/// §10, `TSR-M3`). What these tests pin is that the dial reaches the onion
/// within the remedy, not that one probe never misses.
#[allow(clippy::too_many_arguments)]
async fn reachable(
    boot: &DaemonTorControl,
    received: &mut EventReceiver,
    seed: &OnionSeed,
    service: &ServiceId,
    pair: &IsolationPair,
    stand_in: &mut StandIn,
    request: &[u8],
) -> (u32, Duration) {
    let mut misses = Vec::new();
    for round in 1..=REMEDY_ROUNDS {
        tokio::time::sleep(PROBE_AFTER).await;
        let (arrived, ended) = probe_once(&proxy_for(boot, pair), service, stand_in, request).await;
        if let Some(latency) = arrived {
            return (round, latency);
        }
        misses.push(ended);
        let again = boot
            .republish(seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
            .await
            .expect("the remedy's republish");
        assert_eq!(&again, service, "the held seed is the same onion");
        round_uploaded(received, service).await;
    }
    panic!("not reachable within {REMEDY_ROUNDS} rounds of the remedy: {misses:?}");
}

/// The client rendezvous circuits Tor holds to `service`, each with whether
/// it carries a SOCKS username (`GETINFO circuit-status`; Tor names the
/// isolation pair a circuit was built for as `SOCKS_USERNAME=`).
async fn client_rendezvous(boot: &DaemonTorControl, service: &ServiceId) -> Vec<bool> {
    let reply = boot
        .ask(Command::GetInfo(vec!["circuit-status".to_owned()]))
        .await
        .expect("GETINFO circuit-status");
    let query = format!("REND_QUERY={}", service.as_str());
    reply
        .lines()
        .iter()
        .filter(|line| line.contains("PURPOSE=HS_CLIENT_REND") && line.contains(&query))
        .map(|line| line.contains("SOCKS_USERNAME="))
        .collect()
}

fn proxy_for(boot: &DaemonTorControl, pair: &IsolationPair) -> Proxy {
    Proxy::authenticated_shared(boot.socks_addr(), std::sync::Arc::clone(pair.shared()))
}

/// **Test 6.** A cold start publishes, and a probe arrives inside its bound
/// within the remedy's rounds ([`reachable`]). The probe's rendezvous circuit carries its
/// SOCKS username: Tor built it for the probe's pair, and a peer dial,
/// which offers no authentication, cannot join it (`IsolateSOCKSAuth`).
#[tokio::test]
#[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps, publishes, network)"]
async fn a_cold_start_is_reachable_and_the_probe_is_on_its_own_circuit() {
    let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());
    let parent = tempfile::tempdir().expect("tempdir");
    let (events, mut received) = EventSink::bounded();
    let mut boot = DaemonTorControl::launch(subscribed_config(
        binary,
        parent.path().to_path_buf(),
        events,
    ))
    .await
    .expect("start");
    subscribe(&boot).await;
    wait_for_the_network(&mut boot).await;

    let probe_request = request();
    let mut stand_in = StandIn::bind(probe_request.clone()).await;
    let seed = DaemonTorControl::mint_seed().expect("seed");
    // A fresh Tor holds no service: the delete's 552 is not a failure.
    let service = boot
        .republish(&seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
        .await
        .expect("publish");
    round_uploaded(&mut received, &service).await;

    let pair = IsolationPair::mint().expect("pair");
    let (_round, latency) = reachable(
        &boot,
        &mut received,
        &seed,
        &service,
        &pair,
        &mut stand_in,
        &probe_request,
    )
    .await;
    // The stand-in still holds the probe's stream: its circuit is up.
    let circuits = client_rendezvous(&boot, &service).await;
    stand_in.release.notify_waiters();
    assert!(
        !circuits.is_empty() && circuits.iter().all(|named| *named),
        "the probe's rendezvous carries its pair, so no unauthenticated peer dial shares it: {circuits:?}"
    );
    assert!(latency < PROBE_WITHIN);
    boot.shutdown().await;
}

/// **Test 7.** A Tor killed and respawned into its kept directory
/// republishes the same onion from the held seed, and is reachable again
/// within the remedy's rounds.
#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
async fn a_respawn_republishes_the_same_onion_and_is_reachable_again() {
    let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());
    let parent = tempfile::tempdir().expect("tempdir");
    let (events, mut received) = EventSink::bounded();
    let mut boot = DaemonTorControl::spawn_keeping(subscribed_config(
        binary.clone(),
        parent.path().to_path_buf(),
        events.clone(),
    ))
    .await
    .unwrap_or_else(|_| panic!("start"));
    subscribe(&boot).await;
    wait_for_the_network(&mut boot).await;

    let probe_request = request();
    let mut stand_in = StandIn::bind(probe_request.clone()).await;
    let seed = DaemonTorControl::mint_seed().expect("seed");
    let pair = IsolationPair::mint().expect("pair");
    let first = boot
        .republish(&seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
        .await
        .expect("publish");
    round_uploaded(&mut received, &first).await;
    reachable(
        &boot,
        &mut received,
        &seed,
        &first,
        &pair,
        &mut stand_in,
        &probe_request,
    )
    .await;
    stand_in.release.notify_waiters();

    // Kill Tor, as a crash does, and respawn into the kept directory.
    let death = tokio::spawn(boot.death());
    let pid = tor_under(parent.path()).expect("the tor under this parent");
    let status = shekyl_tor_control_client::spawn_lock::status(
        std::process::Command::new("kill").args(["-9", &pid.to_string()]),
    )
    .expect("kill");
    assert!(status.success());
    tokio::time::timeout(Duration::from_secs(30), death)
        .await
        .expect("the death is heard")
        .expect("watcher");
    let kept = boot.stop_for_respawn().await;
    let mut boot = DaemonTorControl::spawn_into(
        kept,
        binary,
        events,
        Duration::from_secs(30),
        SocksTimeout::TorDefault,
    )
    .await
    .unwrap_or_else(|_| panic!("respawn"));
    subscribe(&boot).await;
    wait_for_the_network(&mut boot).await;

    let request_again = request();
    let mut stand_in = StandIn::bind(request_again.clone()).await;
    let second = boot
        .republish(&seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
        .await
        .expect("republish after the respawn");
    assert_eq!(second, first, "the held seed is the same onion");
    round_uploaded(&mut received, &second).await;
    reachable(
        &boot,
        &mut received,
        &seed,
        &second,
        &pair,
        &mut stand_in,
        &request_again,
    )
    .await;
    stand_in.release.notify_waiters();
    boot.shutdown().await;
}

/// **Test 8.** An `ADD_ONION` for a service Tor still holds is refused
/// (550): the reason the republish deletes first. An onion deleted from
/// under the supervisor is missed by the next probe; the republish (whose
/// delete now finds nothing) restores it, reachable within the remedy's
/// rounds. The brief named a second control connection for the delete;
/// the managed Tor has none (its one controller is the inherited owning
/// socket), so the delete goes over that connection, which is the same
/// effect on Tor.
#[tokio::test]
#[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps, publishes three times, network)"]
async fn a_deleted_onion_is_missed_and_the_republish_restores_it() {
    let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());
    let parent = tempfile::tempdir().expect("tempdir");
    let (events, mut received) = EventSink::bounded();
    let mut boot = DaemonTorControl::launch(subscribed_config(
        binary,
        parent.path().to_path_buf(),
        events,
    ))
    .await
    .expect("start");
    subscribe(&boot).await;
    wait_for_the_network(&mut boot).await;

    let probe_request = request();
    let mut stand_in = StandIn::bind(probe_request.clone()).await;
    let seed = DaemonTorControl::mint_seed().expect("seed");
    let pair = IsolationPair::mint().expect("pair");
    let service = boot
        .publish(&seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
        .await
        .expect("publish");
    match boot
        .publish(&seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
        .await
    {
        Err(DaemonTorPublishError::Publish(AddOnionReplyError::Rejected { status: 550 })) => {}
        other => panic!("a second ADD_ONION for a held service is a collision, got {other:?}"),
    }
    round_uploaded(&mut received, &service).await;

    let deleted = boot
        .ask(Command::DelOnion(service.clone()))
        .await
        .expect("DEL_ONION");
    assert_eq!(deleted.status(), 250);
    tokio::time::sleep(PROBE_AFTER).await;
    let (arrived, ended) = probe_once(
        &proxy_for(&boot, &pair),
        &service,
        &mut stand_in,
        &probe_request,
    )
    .await;
    assert!(
        arrived.is_none(),
        "a deleted onion is not reachable ({ended:?})"
    );

    let restored = boot
        .republish(&seed, VIRTUAL_PORT, stand_in.at, 8, OnionPow::Enabled)
        .await
        .expect("the republish restores it");
    assert_eq!(restored, service);
    round_uploaded(&mut received, &restored).await;
    reachable(
        &boot,
        &mut received,
        &seed,
        &restored,
        &pair,
        &mut stand_in,
        &probe_request,
    )
    .await;
    stand_in.release.notify_waiters();
    boot.shutdown().await;
}
