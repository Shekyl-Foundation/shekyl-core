// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A19 on the real pathway: a real `shekyld` on regtest, real blocks, and a
//! real `shekyl-wallet-rpc` process that is killed, signalled and refused a
//! write (the alpha.11 bug hunt §A19; the wallet lane brief, PR 1).
//!
//! On alpha.11 a send's record, its retained tx secret and its input lock
//! lived in memory until the wallet closed. A wallet server that stopped
//! any other way lost them: the OUTBOUND proof for a payment that settled,
//! and the lock, so the next send re-selected the input and was refused as
//! a double spend. These gates hold the fix where it can be seen: the
//! process, not the engine, dies.
//!
//! Requires `SHEKYLD_BIN` and `SHEKYL_WALLET_RPC_BIN` (both staged in
//! `build/bin` by the CMake build). Each gate funds a wallet created here
//! from a known seed (the daemon mines to its address), closes it, and
//! hands its directory to the wallet server.

#![cfg(test)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{mine_address_from_seed, regtest_expectation, regtest_params, RegtestDaemon};

/// A JSON-RPC refusal from the wallet server.
#[derive(Debug)]
struct RpcRefusal {
    code: i64,
    // Read through `Debug` in every failure message.
    #[allow(dead_code)]
    message: String,
    data: Option<Value>,
}

/// A real `shekyl-wallet-rpc` process on a loopback port, without login
/// (loopback is the posture that permits it), on regtest, pointed at the
/// test's daemon.
struct WalletServer {
    child: Option<Child>,
    port: u16,
    log: PathBuf,
}

impl WalletServer {
    fn spawn(wallet_dir: &Path, daemon_port: u16, log_dir: &Path, tag: &str) -> Self {
        let bin = std::env::var_os("SHEKYL_WALLET_RPC_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYL_WALLET_RPC_BIN not set. Build the wallet server \
                 (cmake --build build) and pass build/bin/shekyl-wallet-rpc"
            )
        });
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            l.local_addr().expect("local_addr").port()
        };
        let log = log_dir.join(format!("wallet-rpc-{tag}.log"));
        let out = std::fs::File::create(log_dir.join(format!("wallet-rpc-{tag}.out")))
            .expect("stdout file");
        let child = Command::new(bin)
            .arg("--wallet-dir")
            .arg(wallet_dir)
            .arg("--rpc-bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--disable-rpc-login")
            .arg("--network")
            .arg("regtest")
            .arg("--daemon-address")
            .arg(format!("http://127.0.0.1:{daemon_port}"))
            .arg("--log-file")
            .arg(&log)
            .stdout(out.try_clone().expect("dup"))
            .stderr(out)
            .spawn()
            .expect("spawn shekyl-wallet-rpc");
        let mut server = Self {
            child: Some(child),
            port,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if server.call("get_version", json!({})).is_ok() {
                return server;
            }
            if let Some(status) = server.child_mut().try_wait().expect("try_wait") {
                panic!(
                    "shekyl-wallet-rpc exited before it answered ({status}); log:\n{}",
                    server.log_text()
                );
            }
            assert!(
                Instant::now() < deadline,
                "shekyl-wallet-rpc did not answer within 60 s; log:\n{}",
                server.log_text()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("the server is running")
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().expect("the server is running").id()
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// One JSON-RPC call over a fresh connection.
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcRefusal> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let transport = |e: std::io::Error| RpcRefusal {
            code: 0,
            message: format!("transport: {e}"),
            data: None,
        };
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).map_err(transport)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(600)))
            .map_err(transport)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            shekyl_rpc_types::endpoint::JSON_RPC_PATH,
            self.port,
            body.len()
        );
        stream.write_all(request.as_bytes()).map_err(transport)?;
        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(transport)?;
        let (_, payload) = response
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("{method}: an HTTP response without a body: {response}"));
        let reply: Value = serde_json::from_str(payload)
            .unwrap_or_else(|e| panic!("{method}: a reply that is not JSON ({e}): {payload}"));
        if let Some(error) = reply.get("error") {
            return Err(RpcRefusal {
                code: error["code"].as_i64().unwrap_or(0),
                message: error["message"].as_str().unwrap_or("").to_owned(),
                data: error.get("data").cloned(),
            });
        }
        Ok(reply["result"].clone())
    }

    /// A call that must succeed.
    fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params).unwrap_or_else(|e| {
            panic!(
                "{method} refused: {e:?}; log tail:\n{}",
                tail(&self.log_text())
            )
        })
    }

    /// Send `signal` (a `kill` name: KILL, TERM, INT, HUP) to the process.
    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.pid().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{signal} failed: {status}");
    }

    /// Wait for the process to exit, at most `limit`.
    fn wait_exit(&mut self, limit: Duration) -> ExitStatus {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child_mut().try_wait().expect("try_wait") {
                self.child = None;
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "shekyl-wallet-rpc did not exit within {limit:?}; log tail:\n{}",
                tail(&self.log_text())
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for WalletServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

const PASSWORD: &str = "a19-send-durable";

/// The wallet's name on the wire: the server opens `<wallet-dir>/<name>.wallet`.
const NAME: &str = "a19";

/// A wallet created from `seed` and closed, in a fresh directory, beside a
/// daemon that mines to its address; returns the daemon, the directory,
/// and a directory for the server's logs.
async fn wallet_and_daemon(seed_byte: u8) -> (RegtestDaemon, tempfile::TempDir, tempfile::TempDir) {
    let seed = [seed_byte; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    let tmp = tempfile::tempdir().expect("wallet dir");
    let creds = super::super::lifecycle::Credentials::password_only(PASSWORD.as_bytes());
    let base = tmp.path().join(format!("{NAME}.wallet"));
    let rpc = shekyl_rpc_transport::HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("daemon rpc");
    let created = super::super::Engine::<super::super::SoloSigner>::create(
        regtest_params(&base, &creds, &seed),
        super::super::DaemonClient::verifying(rpc, regtest_expectation()),
    )
    .expect("create the wallet");
    created
        .close(&super::super::lifecycle::Credentials::password_only(
            PASSWORD.as_bytes(),
        ))
        .await
        .expect("close the created wallet");
    let logs = tempfile::tempdir().expect("log dir");
    (daemon, tmp, logs)
}

fn open(server: &WalletServer) {
    server.ok("open_wallet", json!({"name": NAME, "password": PASSWORD}));
}

fn refresh(server: &WalletServer) {
    server.ok("refresh", json!({}));
}

/// Mine and refresh in batches until the unlocked balance reaches `need`.
async fn fund(daemon: &RegtestDaemon, server: &WalletServer, need: u64) {
    for _ in 0..40 {
        daemon.generate_blocks(10).await;
        refresh(server);
        let balance = server.ok("get_balance", json!({}));
        let unlocked: u64 = balance["unlocked"]
            .as_str()
            .expect("unlocked is a decimal string")
            .parse()
            .expect("unlocked parses");
        if unlocked >= need {
            return;
        }
    }
    panic!("the wallet did not reach an unlocked balance of {need}");
}

/// Build a send of `amount` to `address`, mining past the reference
/// block's spendability edge when the wallet asks for it (`-29112` names
/// the wait), and return the reservation id and its content generation.
async fn build(
    daemon: &RegtestDaemon,
    server: &WalletServer,
    address: &str,
    amount: u64,
) -> (String, i64) {
    for _ in 0..20 {
        match server.call(
            "build_pending_tx",
            json!({
                "recipients": [{"address": address, "amount": amount.to_string()}],
                "priority": "STANDARD",
            }),
        ) {
            Ok(built) => {
                return (
                    built["pending_tx_id"].as_str().expect("id").to_owned(),
                    built["content_gen"].as_i64().expect("content_gen"),
                )
            }
            Err(RpcRefusal {
                code: -29112, data, ..
            }) => {
                let wait = data
                    .as_ref()
                    .and_then(|d| d["wait_blocks"].as_u64())
                    .unwrap_or(1);
                daemon.generate_blocks(wait.max(1)).await;
                refresh(server);
            }
            Err(RpcRefusal {
                code: -29111 | -29110,
                ..
            }) => {
                daemon.generate_blocks(2).await;
                refresh(server);
            }
            Err(other) => panic!(
                "build_pending_tx refused: {other:?}; log tail:\n{}",
                tail(&server.log_text())
            ),
        }
    }
    panic!("build_pending_tx never succeeded");
}

/// Build and submit a send; the daemon must freshly accept it and the
/// wallet must save the verdict. Returns the txid.
async fn send(daemon: &RegtestDaemon, server: &WalletServer, address: &str, amount: u64) -> String {
    let (id, gen) = build(daemon, server, address, amount).await;
    let submitted = server.ok(
        "submit_pending_tx",
        json!({"pending_tx_id": id, "seen_gen": gen}),
    );
    assert_eq!(submitted["verdict"], "ACCEPTED", "{submitted}");
    assert_eq!(submitted["verdict_saved"], true, "{submitted}");
    submitted["tx_hash"].as_str().expect("tx_hash").to_owned()
}

fn alarm_for(server: &WalletServer, txid: &str) -> Option<String> {
    server
        .ok("tx_alarm", json!({}))
        .as_array()
        .expect("tx_alarm is a list")
        .iter()
        .find(|row| row["id"] == txid)
        .map(|row| row["alarm"].as_str().expect("alarm keyword").to_owned())
}

fn outgoing_state(server: &WalletServer, txid: &str) -> Option<String> {
    server.ok("get_transfers", json!({}))["transfers"]
        .as_array()
        .expect("get_transfers lists rows")
        .iter()
        .find(|row| row["tx_hash"] == txid && row["direction"] == "OUTGOING")
        .map(|row| row["state"].as_str().expect("state").to_owned())
}

/// The A19 scenario, killed: fund, send, and `kill -9` the wallet server
/// right after the daemon's accept. A new server opens the wallet, and
/// everything the send recorded is there: the record (history), the
/// secret (an OUTBOUND proof that verifies), the bytes (a resend the daemon
/// answers), the lock (a new send that is not a double spend), and the
/// held send listed for the user's decision — then mined, confirmed, and
/// gone from the list.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_send_survives_a_kill_after_its_accept() {
    let (daemon, wallet_dir, logs) = wallet_and_daemon(0x61).await;
    let recipient = mine_address_from_seed(
        &[0x62; shekyl_crypto_pq::account::SEED_BYTES],
        shekyl_address::Network::Regtest,
    );
    const AMOUNT: u64 = 1_000_000_000;

    let mut first = WalletServer::spawn(wallet_dir.path(), daemon.rpc_port, logs.path(), "first");
    open(&first);
    fund(&daemon, &first, 4 * AMOUNT).await;
    let txid = send(&daemon, &first, &recipient, AMOUNT).await;
    first.signal("KILL");
    let status = first.wait_exit(Duration::from_secs(10));
    assert!(!status.success(), "SIGKILL ends the process: {status}");
    assert!(
        daemon.tx_pool_size().await >= 1,
        "the send is in the daemon's pool"
    );

    let second = WalletServer::spawn(wallet_dir.path(), daemon.rpc_port, logs.path(), "second");
    open(&second);

    assert_eq!(
        alarm_for(&second, &txid).as_deref(),
        Some("earlier-session"),
        "the send from before the kill waits for the user's decision"
    );
    assert!(
        outgoing_state(&second, &txid).is_some(),
        "the send's record survived the kill"
    );
    let proof = second.ok("get_tx_proof", json!({"txid": txid, "address": recipient}));
    assert_eq!(proof["direction"], "OUTBOUND", "{proof}");
    let checked = second.ok(
        "check_tx_proof",
        json!({"txid": txid, "address": recipient, "proof": proof["proof"]}),
    );
    assert_eq!(
        checked["valid"], true,
        "the retained secret proves the payment: {checked}"
    );

    // The lock: a new send selects other inputs. Had it re-selected the
    // held send's input, the daemon would refuse it as a double spend.
    let next = send(&daemon, &second, &recipient, AMOUNT).await;
    assert_ne!(next, txid);

    // The bytes: the user's resend is answered by the daemon.
    let resent = second.ok("tx_resend", json!({"id": txid}));
    assert_eq!(resent["tx_hash"], txid);
    assert!(
        resent["verdict"] == "ALREADY_IN_POOL" || resent["verdict"] == "ALREADY_IN_CHAIN",
        "{resent}"
    );

    daemon.generate_blocks(1).await;
    refresh(&second);
    assert_eq!(
        outgoing_state(&second, &txid).as_deref(),
        Some("CONFIRMED"),
        "mined and confirmed"
    );
    assert_eq!(
        alarm_for(&second, &txid),
        None,
        "a confirmed send needs no decision"
    );
}

/// Each stop signal closes the wallet cleanly: the process exits 0 after
/// logging the close, and the next server finds the send it made.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn each_stop_signal_closes_the_wallet() {
    let (daemon, wallet_dir, logs) = wallet_and_daemon(0x63).await;
    let recipient = mine_address_from_seed(
        &[0x64; shekyl_crypto_pq::account::SEED_BYTES],
        shekyl_address::Network::Regtest,
    );
    const AMOUNT: u64 = 1_000_000_000;

    let mut previous: Option<String> = None;
    for signal in ["TERM", "INT", "HUP"] {
        let mut server =
            WalletServer::spawn(wallet_dir.path(), daemon.rpc_port, logs.path(), signal);
        open(&server);
        if let Some(txid) = &previous {
            assert!(
                outgoing_state(&server, txid).is_some(),
                "the send made before the last signal is on disk"
            );
        } else {
            fund(&daemon, &server, 6 * AMOUNT).await;
        }
        let txid = send(&daemon, &server, &recipient, AMOUNT).await;
        server.signal(signal);
        let status = server.wait_exit(Duration::from_secs(60));
        assert!(
            status.success(),
            "SIG{signal}: the server closes the wallet and exits 0, got {status}; log tail:\n{}",
            tail(&server.log_text())
        );
        assert!(
            server.log_text().contains("the wallet is saved and closed"),
            "SIG{signal}: the close is logged; log tail:\n{}",
            tail(&server.log_text())
        );
        daemon.generate_blocks(1).await;
        previous = Some(txid);
    }

    let last = WalletServer::spawn(wallet_dir.path(), daemon.rpc_port, logs.path(), "last");
    open(&last);
    let txid = previous.expect("three sends");
    assert!(outgoing_state(&last, &txid).is_some());
}

/// A send whose record cannot be saved is not sent: with the wallet
/// directory unwritable the submit is refused `-29120` and the daemon's
/// pool stays empty; with the directory writable again, the kept
/// reservation submits and is accepted.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_send_that_cannot_be_saved_is_not_sent() {
    use std::os::unix::fs::PermissionsExt;

    let (daemon, wallet_dir, logs) = wallet_and_daemon(0x65).await;
    let recipient = mine_address_from_seed(
        &[0x66; shekyl_crypto_pq::account::SEED_BYTES],
        shekyl_address::Network::Regtest,
    );
    const AMOUNT: u64 = 1_000_000_000;

    let server = WalletServer::spawn(wallet_dir.path(), daemon.rpc_port, logs.path(), "nosave");
    open(&server);
    fund(&daemon, &server, 2 * AMOUNT).await;
    let (id, gen) = build(&daemon, &server, &recipient, AMOUNT).await;
    assert_eq!(
        daemon.tx_pool_size().await,
        0,
        "an empty pool before the submit"
    );

    let dir = wallet_dir.path();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).expect("chmod 555");
    assert!(
        std::fs::write(dir.join("probe"), b"x").is_err(),
        "the wallet directory must refuse writes for this gate to mean anything \
         (running as root?)"
    );
    let refused = server.call(
        "submit_pending_tx",
        json!({"pending_tx_id": id, "seen_gen": gen}),
    );
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");

    let refused = refused.expect_err("a send that cannot be saved is refused");
    assert_eq!(refused.code, -29120, "SEND_NOT_SAVED: {refused:?}");
    assert_eq!(daemon.tx_pool_size().await, 0, "nothing reached the daemon");

    let submitted = server.ok(
        "submit_pending_tx",
        json!({"pending_tx_id": id, "seen_gen": gen}),
    );
    assert_eq!(
        submitted["verdict"], "ACCEPTED",
        "the kept reservation submits: {submitted}"
    );
    assert_eq!(daemon.tx_pool_size().await, 1);
}
