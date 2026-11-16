// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The channel end to end (RT-W10 step 4): the listener on a real socket,
//! the real handshake from the client's side, the record stream, and HTTP
//! over it into the router. No mock transport. Each test names the change
//! that makes it fail.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use shekyl_chain_rules::{AdmissionPolicy, RuleSet};
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_mempool::Pool;
use shekyl_rpc_channel::handshake::{
    Client, StaticKeypair, StaticPublic, MESSAGE2_LEN, MESSAGE4_LEN,
};
use shekyl_rpc_channel::NetworkId;
use shekyl_rpc_grants::{Grant, GrantSet, Preset};
use shekyl_rpc_stream::RecordStream;
use shekyl_rpc_types::wire::rpc::CeilingWord;
use shekyl_types::archival::SettlementEpochBlocks;
use shekyl_types::{BlockHeight, UnixSeconds};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Semaphore};

use super::store::Enroller;
use super::{Channel, ChannelSetup};
use crate::authority::Authority;
use crate::conn_limit::{ConnLimits, ConnTracker, LimitedListener};
use crate::handles::Handles;
use crate::hash_budget::HashBudget;
use crate::options::OptionsAbsent;
use crate::server::AppState;
use crate::shard_view::ShardViewAbsent;
use crate::store_facts::RulesAt;
use crate::submit::{DaemonTxVerifier, RustPoolShim, StoreChain, SubmitEngine};

const NETWORK: NetworkId = [7u8; 16];

/// The host's administrator, as the owner's leg stamps it.
const HOST: Authority = Authority::owner(false);

/// A served channel and its data directory.
struct Served {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    channel: Arc<Channel>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
    tracker: Arc<ConnTracker>,
}

impl Served {
    async fn start(service: bool) -> Self {
        let dir = tempfile::tempdir().expect("a directory");
        let data_dir = dir.path().to_path_buf();
        let channel = Channel::open(&ChannelSetup {
            data_dir: data_dir.clone(),
            network_id: NETWORK,
            service,
            service_rendezvous: None,
            instance: shekyl_rpc_rendezvous::Instance::Default,
        })
        .expect("the channel opens");
        let state = app_state(&data_dir, Arc::clone(&channel));
        let router = crate::server::channel_router(state, &[]);
        let bound = crate::bind::bind_channel_listener("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let addr = bound.local_addr();
        let (_, listener) = bound.into_parts();
        let (stop, mut stopped) = watch::channel(false);
        let tracker = ConnTracker::new(ConnLimits::default());
        let serving = tokio::spawn(super::listener::serve(
            LimitedListener::new(listener, Arc::clone(&tracker)),
            super::listener::Leg::Network,
            Arc::clone(&channel),
            router,
            async move {
                drop(stopped.wait_for(|&s| s).await);
            },
        ));
        Self {
            _dir: dir,
            data_dir,
            channel,
            addr,
            stop,
            serving,
            tracker,
        }
    }

    fn bundle(&self) -> StaticPublic {
        self.channel.key.public().clone()
    }

    fn enrol(&self, client: &StaticKeypair, ceiling: &[CeilingWord]) {
        self.channel
            .client_add(
                HOST,
                Enroller::Host,
                *client.public().fingerprint().as_bytes(),
                ceiling,
            )
            .expect("enrolled");
    }
}

/// The state the router serves: a real submit engine over an empty store
/// and pool, every node handle absent, and `channel`.
fn app_state(dir: &std::path::Path, channel: Arc<Channel>) -> Arc<AppState> {
    let epoch = SettlementEpochBlocks::new(10_000).expect("non-zero epoch");
    let store = Arc::new(ChainStore::create(dir.join("chain.redb"), epoch).expect("store"));
    let pool = {
        let snapshot = store.begin_read().expect("a snapshot");
        Pool::open(
            dir.join("pool.redb"),
            UnixSeconds::from_raw(1),
            &SnapshotView::new(&snapshot),
            &RuleSet::GENESIS,
            &shekyl_network::HARNESS_NETWORK_ID,
            &AdmissionPolicy::GENESIS,
        )
        .expect("pool")
        .0
    };
    let rules: Arc<dyn RulesAt> = Arc::new(|_: BlockHeight| RuleSet::GENESIS);
    let shim = RustPoolShim::new(
        StoreChain::new(store, rules),
        Arc::new(Mutex::new(pool)),
        AdmissionPolicy::GENESIS,
        || UnixSeconds::from_raw(1),
        shekyl_network::HARNESS_NETWORK_ID,
    );
    Arc::new(AppState {
        submit_engine: Arc::new(SubmitEngine::new(shim, DaemonTxVerifier)),
        conn_tracker: ConnTracker::new(ConnLimits::default()),
        shard_view: Arc::new(ShardViewAbsent),
        options: Arc::new(OptionsAbsent),
        handles: Handles::absent(),
        tor: Arc::new(crate::tor_facts::TorAbsent),
        hash_budget: Arc::new(HashBudget::new(Instant::now())),
        coinbase_reads: Arc::new(Semaphore::new(1)),
        channel: Some(channel),
    })
}

/// A client session over the channel: the ceiling message 4 carried, and
/// HTTP over the record stream.
struct Session {
    ceiling: GrantSet,
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    mark: shekyl_rpc_stream::SubmissionMark,
}

/// How a connection ended before a session.
#[derive(Debug, PartialEq, Eq)]
enum NoSession {
    /// The daemon closed the connection before message 2: no slot, or no
    /// listener.
    ClosedBeforeMessage2,
    /// The daemon closed the connection before message 4.
    ClosedBeforeMessage4,
}

/// The client's side of the handshake, as a record stream.
async fn open_stream(
    served: &Served,
    client: &StaticKeypair,
    request: GrantSet,
) -> Result<(RecordStream<TcpStream>, GrantSet), NoSession> {
    let tcp = TcpStream::connect(served.addr).await.expect("connect");
    open_over(tcp, &served.bundle(), client, request).await
}

/// The client's side of the handshake over `tcp`, any stream.
async fn open_over<S>(
    mut tcp: S,
    daemon: &StaticPublic,
    client: &StaticKeypair,
    request: GrantSet,
) -> Result<(RecordStream<S>, GrantSet), NoSession>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (c, message1) = Client::start(&NETWORK, client, daemon).expect("message 1");
    tcp.write_all(&message1).await.expect("write message 1");
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    if tcp.read_exact(&mut message2).await.is_err() {
        return Err(NoSession::ClosedBeforeMessage2);
    }
    let c = c
        .read_message2(&message2)
        .expect("the daemon is the bundle's");
    let (c, message3) = c.write_message3(&request.to_payload()).expect("message 3");
    tcp.write_all(&message3).await.expect("write message 3");
    let mut message4 = vec![0u8; MESSAGE4_LEN];
    if tcp.read_exact(&mut message4).await.is_err() {
        return Err(NoSession::ClosedBeforeMessage4);
    }
    let (established, ceiling) = c.read_message4(&message4).expect("message 4");
    let ceiling = GrantSet::from_payload(&ceiling).expect("a ceiling");
    let (send, recv) = established.into_directions();
    Ok((RecordStream::new(tcp, send, recv), ceiling))
}

/// The client's side, as RT-W11's client will run it.
async fn connect(
    served: &Served,
    client: &StaticKeypair,
    request: GrantSet,
) -> Result<Session, NoSession> {
    let (stream, ceiling) = open_stream(served, client, request).await?;
    session_over(stream, ceiling).await
}

/// The HTTP session over an opened record stream.
async fn session_over<S>(stream: RecordStream<S>, ceiling: GrantSet) -> Result<Session, NoSession>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mark = stream.submission_mark();
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("http");
    tokio::spawn(connection);
    Ok(Session {
        ceiling,
        sender,
        mark,
    })
}

impl Session {
    /// One JSON-RPC call; the reply's envelope, or `None` once the session
    /// is closed.
    async fn call(&mut self, method: &str, params: Value) -> Option<Value> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }))
        .unwrap();
        let request = hyper::Request::post("/json_rpc")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        self.sender.ready().await.ok()?;
        let response = self.sender.send_request(request).await.ok()?;
        let body = response.into_body().collect().await.ok()?.to_bytes();
        serde_json::from_slice(&body).ok()
    }
}

fn code(reply: &Value) -> Option<&str> {
    reply["error"]["data"]["code"].as_str()
}

/// **An unenrolled client gets no message 4** (§4.5): the daemon reads its
/// claim after message 3 and closes. Red edit: admit an unknown fingerprint
/// as a `view` client in `Channel::admitted`, and the session opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unenrolled_client_gets_no_message_4() {
    let served = Served::start(false).await;
    let stranger = StaticKeypair::generate().unwrap();
    assert_eq!(
        connect(&served, &stranger, Preset::View.grants())
            .await
            .err(),
        Some(NoSession::ClosedBeforeMessage4)
    );
}

/// **Message 4 carries the ceiling; the connection holds the clamp.** An
/// `admin` client that asks for `view` is told `admin`, and is refused
/// `rpc_bundle_show` (`enrol`) on that connection. Red edit: stamp the
/// ceiling instead of `request ∩ ceiling` in the listener, and the bundle
/// is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn message_4_carries_the_ceiling_and_the_connection_holds_the_clamp() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::Admin]);

    let mut viewing = connect(&served, &client, Preset::View.grants())
        .await
        .expect("a session");
    assert_eq!(viewing.ceiling, GrantSet::ALL);
    let refused = viewing
        .call("rpc_bundle_show", json!({}))
        .await
        .expect("a reply");
    assert_eq!(code(&refused), Some("grant.outside"), "{refused}");

    let mut admin = connect(&served, &client, GrantSet::ALL)
        .await
        .expect("a session");
    let bundle = admin
        .call("rpc_bundle_show", json!({}))
        .await
        .expect("a reply");
    assert!(bundle["result"]["bundle"].is_string(), "{bundle}");
}

/// **Removing a client closes its live session** (§5; the pre-flight's
/// named edit "revocation"). Red edit: drop `changing.close` from
/// `Channel::client_remove`, and the session keeps answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_client_closes_its_live_session() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::View]);
    let mut session = connect(&served, &client, Preset::View.grants())
        .await
        .expect("a session");
    assert!(session.call("version", json!({})).await.is_some());
    let fingerprint = *client.public().fingerprint().as_bytes();
    served
        .channel
        .client_remove(HOST, fingerprint)
        .expect("removed");
    let after = tokio::time::timeout(Duration::from_secs(5), session.call("version", json!({})))
        .await
        .expect("the call ends");
    assert!(
        after.is_none(),
        "the session answered after its removal: {after:?}"
    );
    assert_eq!(
        connect(&served, &client, Preset::View.grants()).await.err(),
        Some(NoSession::ClosedBeforeMessage4)
    );
}

/// **A key holds at most `SESSIONS_PER_CLIENT` sessions** (RT-O37). The
/// next one is told `bound.sessions` on its first request and closed; a
/// session that ends frees its place. Red edit: drop the count test in
/// `Sessions::register`, and the fifth session is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_past_its_session_cap_is_refused_by_name() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::View]);
    let mut held = Vec::new();
    for _ in 0..shekyl_rpc_channel::SESSIONS_PER_CLIENT {
        let mut session = connect(&served, &client, Preset::View.grants())
            .await
            .expect("a session");
        // The test's node has no handles, so a served call is answered
        // not ready; what matters is that the cap did not refuse it.
        let reply = session.call("version", json!({})).await.expect("served");
        assert_ne!(code(&reply), Some("bound.sessions"), "{reply}");
        held.push(session);
    }
    let mut past = connect(&served, &client, Preset::View.grants())
        .await
        .expect("the handshake completes");
    let refused = past.call("version", json!({})).await.expect("a refusal");
    assert_eq!(code(&refused), Some("bound.sessions"), "{refused}");
    assert!(
        past.call("version", json!({})).await.is_none(),
        "a refused session stays open"
    );

    drop(held.pop());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut again = connect(&served, &client, Preset::View.grants())
            .await
            .expect("a session");
        let reply = again.call("version", json!({})).await.expect("an answer");
        if code(&reply) != Some("bound.sessions") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the closed session's place never freed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// **A lowered ceiling closes the session; a raised one does not** (§5:
/// no mid-session downgrade). Red edit: never close in `client_set`, and
/// the lowered session keeps answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lowered_ceiling_closes_the_session_and_a_raised_one_does_not() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    let fingerprint = *client.public().fingerprint().as_bytes();
    served.enrol(&client, &[CeilingWord::View]);
    let mut session = connect(&served, &client, Preset::View.grants())
        .await
        .expect("a session");
    served
        .channel
        .client_set(HOST, fingerprint, &[CeilingWord::Wallet])
        .expect("raised");
    assert!(session.call("version", json!({})).await.is_some());
    served
        .channel
        .client_set(HOST, fingerprint, &[CeilingWord::Health])
        .expect("lowered");
    let after = tokio::time::timeout(Duration::from_secs(5), session.call("version", json!({})))
        .await
        .expect("the call ends");
    assert!(
        after.is_none(),
        "the session answered after its ceiling was lowered"
    );
}

/// **An unpadded submission is refused over the channel** (RT-O28; the
/// pre-flight's named edit "submission shape"). The same call armed as a
/// submission reaches `tx_submit` itself. Red edit: remove the shape check
/// in the dispatch's `TxSubmit` arm, and the unpadded body is not refused
/// for its shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unpadded_submission_is_refused_over_the_channel() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::Wallet]);
    let mut session = connect(&served, &client, Preset::Wallet.grants())
        .await
        .expect("a session");
    let body = json!({ "body": "AAAA" });
    let unpadded = session
        .call("tx_submit", body.clone())
        .await
        .expect("a reply");
    assert_eq!(code(&unpadded), Some("submit.unpadded"), "{unpadded}");
    session.mark.arm();
    let padded = session.call("tx_submit", body).await.expect("a reply");
    assert_ne!(code(&padded), Some("submit.unpadded"), "{padded}");
}

/// **Two `tx_submit` requests in one padded frame are not two submissions.**
/// The frame's payload is one claim. Each request is refused. Red edit:
/// have `tx_submit` read `ends_in_submission` again, and the second request
/// is not `submit.unpadded`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_submissions_in_one_frame_are_both_refused() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::Wallet]);
    let (mut stream, _) = open_stream(&served, &client, Preset::Wallet.grants())
        .await
        .expect("a session");
    let mark = stream.submission_mark();
    let mut bytes = tx_submit_post("aa");
    bytes.extend(tx_submit_post("bb"));
    mark.arm();
    stream.write_all(&bytes).await.expect("the frame");
    stream.flush().await.expect("the frame is sealed");
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while got
        .windows(b"submit.unpadded".len())
        .filter(|window| *window == b"submit.unpadded")
        .count()
        < 2
    {
        assert!(deadline > Instant::now(), "both refusals: {got:?}");
        let mut buf = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("a response")
            .expect("the read");
        assert!(n > 0, "the daemon closed before both refusals: {got:?}");
        got.extend_from_slice(&buf[..n]);
    }
}

/// One `tx_submit` HTTP request, as the channel's client writes it.
fn tx_submit_post(body: &str) -> Vec<u8> {
    let json =
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tx_submit","params":{{"body":"{body}"}}}}"#);
    format!(
        "POST /json_rpc HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{json}",
        json.len()
    )
    .into_bytes()
}

/// **The console key is the host's administrator and never an enrolment**
/// (§5). A service makes it on its first start; it connects with every
/// grant and the host's classes; it is not listed, and the enrolment
/// methods cannot name it. Red edit: admit the console key as
/// `Client(ALL)`, and `relay_stats` is refused as host-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_console_key_is_the_host_and_never_an_enrolment() {
    let served = Served::start(true).await;
    let console = super::files::read_key(&served.data_dir.join(super::files::CONSOLE_KEY_FILE))
        .expect("readable")
        .expect("a service has a console key");
    let fingerprint = *console.public().fingerprint().as_bytes();
    let mut session = connect(&served, &console, GrantSet::ALL)
        .await
        .expect("a session");
    assert_eq!(session.ceiling, GrantSet::ALL);
    let host = session
        .call("relay_stats", json!({}))
        .await
        .expect("a reply");
    assert_ne!(code(&host), Some("grant.host-only"), "{host}");

    assert!(served.channel.client_list(HOST).unwrap().is_empty());
    let removed = served
        .channel
        .client_remove(HOST, fingerprint)
        .expect_err("not an enrolment");
    assert_eq!(removed.diagnostic.code, super::codes::CONSOLE);
}

/// **A service's console leg serves the console key alone, from its own
/// reserve** (RT-O37). Served through `serve_bound`, as a start serves it,
/// with the shared pool already full: the console key is answered as the
/// host; an enrolled key there gets no message 4, whatever its ceiling;
/// the socket is the service account's alone. Red edits: build the console
/// leg's listener with `LimitedListener::new` in `serve_bound`, and the
/// console is closed at accept with the pool; drop the console-only
/// check in the listener's `handshake`, and the enrolled key is answered.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_console_leg_serves_the_console_key_alone_from_its_reserve() {
    use std::os::unix::fs::PermissionsExt;

    let served = Served::start(true).await;
    let tracker = ConnTracker::new(ConnLimits::checked(1, 0, 0).expect("limits"));
    let _pool_full = tracker
        .try_acquire("10.0.0.9".parse().expect("an address"))
        .expect("the one shared slot");
    let console_listener =
        super::console_leg::bind(&served.data_dir).expect("the console's leg binds");
    let place = super::console_leg::place(&served.data_dir);
    let mode = std::fs::metadata(&place)
        .expect("bound")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    // The router's own chain store: `Served` holds the one in its data
    // directory.
    let store_dir = tempfile::tempdir().expect("a directory");
    let router = crate::server::channel_router(
        app_state(store_dir.path(), Arc::clone(&served.channel)),
        &[],
    );
    let (stop, stopped) = watch::channel(false);
    let serving = tokio::spawn(crate::server::serve_bound(
        Vec::new(),
        None,
        Some(crate::server::ChannelServed {
            router,
            channel: Arc::clone(&served.channel),
            network: Vec::new(),
            console: Some(console_listener),
        }),
        Arc::clone(&tracker),
        stopped,
    ));

    let console = super::files::read_key(&served.data_dir.join(super::files::CONSOLE_KEY_FILE))
        .expect("readable")
        .expect("a service has a console key");
    let io = tokio::net::UnixStream::connect(&place).await.expect("dial");
    let (stream, ceiling) = open_over(io, &served.bundle(), &console, GrantSet::ALL)
        .await
        .expect("the console is admitted from its reserve");
    let mut session = session_over(stream, ceiling).await.expect("a session");
    let host = session
        .call("relay_stats", json!({}))
        .await
        .expect("a reply");
    assert_ne!(code(&host), Some("grant.host-only"), "{host}");

    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::Admin]);
    let io = tokio::net::UnixStream::connect(&place).await.expect("dial");
    assert_eq!(
        open_over(io, &served.bundle(), &client, Preset::View.grants())
            .await
            .err(),
        Some(NoSession::ClosedBeforeMessage4)
    );

    drop(session);
    stop.send_replace(true);
    serving.await.expect("joined").expect("served");
}

/// **Enrolment is bounded by the caller's own grant** (RT-O9.1). A key
/// holding `enrol` and `view` may enrol `view`, not `bans`; may not remove
/// or change an `admin` enrolment; and lists only what lies within its
/// grant. Red edit: drop the `within_caller` check on the new ceiling in
/// `client_add`, and the `bans` enrolment is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrolment_is_bounded_by_the_callers_grant() {
    let served = Served::start(false).await;
    let narrow = Authority::channel(
        Preset::View.grants().union(GrantSet::of(&[Grant::Enrol])),
        false,
    );
    let by = Enroller::Client([5; 32]);
    let admin_key = [1u8; 32];
    served
        .channel
        .client_add(HOST, Enroller::Host, admin_key, &[CeilingWord::Admin])
        .unwrap();

    served
        .channel
        .client_add(narrow, by, [2; 32], &[CeilingWord::View])
        .expect("within its grant");
    let beyond = served
        .channel
        .client_add(narrow, by, [3; 32], &[CeilingWord::Bans])
        .expect_err("beyond its grant");
    assert_eq!(beyond.diagnostic.code, super::codes::BEYOND_CALLER);
    assert_eq!(
        served
            .channel
            .client_remove(narrow, admin_key)
            .expect_err("an admin enrolment")
            .diagnostic
            .code,
        super::codes::BEYOND_CALLER
    );
    let listed: Vec<[u8; 32]> = served
        .channel
        .client_list(narrow)
        .unwrap()
        .into_iter()
        .map(|c| c.fingerprint.to_bytes())
        .collect();
    assert_eq!(listed, vec![[2u8; 32]]);
    assert_eq!(
        served
            .channel
            .client_add(HOST, Enroller::Host, [2; 32], &[CeilingWord::View])
            .expect_err("enrolled")
            .diagnostic
            .code,
        super::codes::ENROLLED
    );
}

/// **A silent connection is closed at the message-1 deadline** (§4.3).
/// Red edit: drop the message-1 timeout, and the connection stays open
/// until the 11-second handshake deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_connection_is_closed_at_the_message_1_deadline() {
    let served = Served::start(false).await;
    let mut tcp = TcpStream::connect(served.addr).await.expect("connect");
    let started = Instant::now();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(9), tcp.read(&mut byte))
        .await
        .expect("closed before the handshake deadline");
    assert_eq!(read.ok(), Some(0), "closed, nothing sent");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(3) && waited < Duration::from_secs(8),
        "{waited:?}"
    );
}

/// **A stop waits for every connection** (Copilot's review of #1377,
/// finding 5): the listener returns only once a live session and a
/// connection still in its handshake have both closed, and the handshake
/// ends on the stop rather than at its deadline. The handshaking client has
/// sent message 1 and read message 2, so the daemon waits for message 3
/// under the 11-second handshake deadline alone. Red edit: drop the wait in
/// `listener::serve`, and it returns with connections still counted; drop
/// the stop from the handshake's `select!`, and the stop waits out that
/// deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_waits_for_every_connection_and_ends_a_handshake() {
    let served = Served::start(false).await;
    let client = StaticKeypair::generate().unwrap();
    served.enrol(&client, &[CeilingWord::View]);
    let mut session = connect(&served, &client, Preset::View.grants())
        .await
        .expect("a session");
    assert!(session.call("version", json!({})).await.is_some());
    let mut handshaking = TcpStream::connect(served.addr).await.expect("connect");
    let other = StaticKeypair::generate().unwrap();
    let (_waiting, message1) =
        Client::start(&NETWORK, &other, &served.bundle()).expect("message 1");
    handshaking
        .write_all(&message1)
        .await
        .expect("write message 1");
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    handshaking
        .read_exact(&mut message2)
        .await
        .expect("message 2: the daemon now waits for message 3");
    let counted = Instant::now();
    while served.tracker.active_total() < 2 {
        assert!(counted.elapsed() < Duration::from_secs(5), "both counted");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    served.stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(8), served.serving)
        .await
        .expect("the stop does not wait out the handshake deadline")
        .expect("the listener's task")
        .expect("the listener");
    assert_eq!(
        served.tracker.active_total(),
        0,
        "every connection ended before the listener returned"
    );
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(500), handshaking.read(&mut byte))
        .await
        .expect("the handshaking connection is closed when the listener returns");
    assert_eq!(read.ok(), Some(0));
    let after = tokio::time::timeout(
        Duration::from_millis(500),
        session.call("version", json!({})),
    )
    .await
    .expect("the session is closed when the listener returns");
    assert!(after.is_none(), "{after:?}");
}

/// **The console key's reset replaces the console enrolment and nothing
/// else** (IG-Q88, §5), run offline as the switch runs it: the old console
/// key is no longer admitted, the new one is, an enrolled client is
/// untouched, and the next start reads the note it left. Red edit: skip
/// the store commit in `console::install`, and the old console key is still
/// admitted.
#[test]
fn the_console_key_reset_replaces_the_console_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let setup = ChannelSetup {
        data_dir: dir.path().to_path_buf(),
        network_id: NETWORK,
        service: true,
        service_rendezvous: None,
        instance: shekyl_rpc_rendezvous::Instance::Default,
    };
    let path = dir.path().join(super::files::CONSOLE_KEY_FILE);
    let client = StaticKeypair::generate().unwrap();
    let client_fp = *client.public().fingerprint().as_bytes();
    let old = {
        let channel = Channel::open(&setup).expect("opens");
        channel
            .client_add(HOST, Enroller::Host, client_fp, &[CeilingWord::View])
            .unwrap();
        super::files::read_key(&path)
            .unwrap()
            .expect("the console key")
    };

    let written = super::reset_console_key(dir.path()).expect("reset, offline");
    assert_eq!(written, path);
    let new = super::files::read_key(&path)
        .unwrap()
        .expect("the new console key");
    assert_ne!(new.public().fingerprint(), old.public().fingerprint());
    {
        let store = super::store::Store::open(dir.path()).unwrap();
        assert!(
            store.take_console_reset().unwrap().is_some(),
            "the note is left"
        );
        let fingerprint = store.console().unwrap().expect("the cell");
        store.commit_console(&fingerprint, Some(1)).unwrap();
    }

    let channel = Channel::open(&setup).expect("the next start");
    assert!(
        channel.store.take_console_reset().unwrap().is_none(),
        "the start read the note"
    );
    assert_eq!(
        channel
            .admitted(old.public().fingerprint().as_bytes())
            .unwrap(),
        None
    );
    assert_eq!(
        channel
            .admitted(new.public().fingerprint().as_bytes())
            .unwrap(),
        Some(super::Admitted::Console)
    );
    assert_eq!(
        channel.admitted(&client_fp).unwrap(),
        Some(super::Admitted::Client(Preset::View.grants()))
    );
}
