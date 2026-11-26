// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A real `shekyl-wallet-rpc` process for the regtest gates that drive the
//! wallet through its contract: the A19 gates (`send_durable`) and the
//! balance and signer gates (`balance`). Requires `SHEKYL_WALLET_RPC_BIN`
//! (staged in `build/bin` by `cargo xtask build`) beside `SHEKYLD_BIN`.

#![cfg(test)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{regtest_expectation, regtest_params, RegtestDaemon};

/// A JSON-RPC refusal from the wallet server.
#[derive(Debug)]
pub(super) struct RpcRefusal {
    pub(super) code: i64,
    // Read through `Debug` in every failure message.
    #[allow(dead_code)]
    message: String,
    pub(super) data: Option<Value>,
}

/// A real `shekyl-wallet-rpc` process on a loopback port, without login
/// (loopback is the posture that permits it), on regtest, pointed at the
/// test's daemon.
pub(super) struct WalletServer {
    child: Option<Child>,
    port: u16,
    log: PathBuf,
}

impl WalletServer {
    pub(super) fn spawn(wallet_dir: &Path, daemon_port: u16, log_dir: &Path, tag: &str) -> Self {
        let bin = std::env::var_os("SHEKYL_WALLET_RPC_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYL_WALLET_RPC_BIN not set. Build the wallet server \
                 (cargo xtask build, in rust/) and pass build/bin/shekyl-wallet-rpc"
            )
        });
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            l.local_addr().expect("local_addr").port()
        };
        let log = log_dir.join(format!("wallet-rpc-{tag}.log"));
        let out = std::fs::File::create(log_dir.join(format!("wallet-rpc-{tag}.out")))
            .expect("stdout file");
        let mut cmd = Command::new(bin);
        cmd.arg("--wallet-dir")
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
            .stderr(out);
        let child = shekyl_spawn::spawn_lock::spawn(&mut cmd).expect("spawn shekyl-wallet-rpc");
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

    pub(super) fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("the server is running")
    }

    pub(super) fn pid(&self) -> u32 {
        self.child.as_ref().expect("the server is running").id()
    }

    pub(super) fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// One JSON-RPC call over a fresh connection.
    pub(super) fn call(&self, method: &str, params: Value) -> Result<Value, RpcRefusal> {
        let mut request = json!({"jsonrpc": "2.0", "id": 1, "method": method});
        request["params"] = params;
        let body = request.to_string();
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
    pub(super) fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params).unwrap_or_else(|e| {
            panic!(
                "{method} refused: {e:?}; log tail:\n{}",
                tail(&self.log_text())
            )
        })
    }

    /// Send `signal` (a `kill` name: KILL, TERM, INT, HUP) to the process.
    pub(super) fn signal(&self, signal: &str) {
        let mut kill = Command::new("kill");
        kill.arg(format!("-{signal}")).arg(self.pid().to_string());
        let status = shekyl_spawn::spawn_lock::status(&mut kill).expect("run kill");
        assert!(status.success(), "kill -{signal} failed: {status}");
    }

    /// Wait for the process to exit, at most `limit`.
    pub(super) fn wait_exit(&mut self, limit: Duration) -> ExitStatus {
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
            // A process that already exited refuses the kill; either way the
            // wait reaps it, and a test that is ending has nothing to do with
            // the outcome.
            drop(child.kill());
            drop(child.wait());
        }
    }
}

pub(super) fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

/// Every gate's wallets share one password; their names tell them apart.
pub(super) const PASSWORD: &str = "regtest-wallet-server";

/// A wallet created from `seed` and closed, as `<dir>/<name>.wallet`: the
/// directory a wallet server serves `name` from.
pub(super) async fn create_wallet(
    daemon: &RegtestDaemon,
    dir: &Path,
    name: &str,
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
) {
    let creds = super::super::lifecycle::Credentials::password_only(PASSWORD.as_bytes());
    let base = dir.join(format!("{name}.wallet"));
    let rpc = daemon.wallet_rpc();
    let created = super::super::Engine::<super::super::SoloSigner>::create(
        regtest_params(&base, &creds, seed),
        super::super::DaemonClient::verifying(rpc, regtest_expectation()),
    )
    .expect("create the wallet");
    created
        .close(&super::super::lifecycle::Credentials::password_only(
            PASSWORD.as_bytes(),
        ))
        .await
        .expect("close the created wallet");
}

/// A wallet named `name`, created from `[seed_byte; 32]` and closed, in a
/// fresh directory, beside a daemon that mines to its address; returns the
/// daemon, the directory, and a directory for the servers' logs.
pub(super) async fn wallet_and_daemon(
    name: &str,
    seed_byte: u8,
) -> (RegtestDaemon, tempfile::TempDir, tempfile::TempDir) {
    let seed = [seed_byte; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    let tmp = tempfile::tempdir().expect("wallet dir");
    create_wallet(&daemon, tmp.path(), name, &seed).await;
    let logs = tempfile::tempdir().expect("log dir");
    (daemon, tmp, logs)
}

pub(super) fn open(server: &WalletServer, name: &str) {
    server.ok("open_wallet", json!({"name": name, "password": PASSWORD}));
}

pub(super) fn refresh(server: &WalletServer) {
    server.ok("refresh", json!({}));
}

/// An amount field of a reply, parsed from its decimal string.
pub(super) fn amount(reply: &Value, field: &str) -> u64 {
    reply[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a decimal string: {reply}"))
        .parse()
        .unwrap_or_else(|e| panic!("{field} parses ({e}): {reply}"))
}

/// Mine and refresh in batches until the spendable balance reaches `need`.
pub(super) async fn fund(daemon: &RegtestDaemon, server: &WalletServer, need: u64) {
    for _ in 0..40 {
        daemon.generate_blocks(10).await;
        refresh(server);
        if amount(&server.ok("get_balance", json!({})), "spendable") >= need {
            return;
        }
    }
    panic!("the wallet did not reach a spendable balance of {need}");
}

/// Build a send of `amount` to `address`, mining past the reference
/// block's spendability edge when the wallet asks for it (`-29112` names
/// the wait), and return the reservation id and its content generation.
pub(super) async fn build(
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
                "priority": "standard",
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
pub(super) async fn send(
    daemon: &RegtestDaemon,
    server: &WalletServer,
    address: &str,
    amount: u64,
) -> String {
    let (id, gen) = build(daemon, server, address, amount).await;
    let submitted = server.ok(
        "submit_pending_tx",
        json!({"pending_tx_id": id, "seen_gen": gen}),
    );
    assert_eq!(submitted["verdict"], "ACCEPTED", "{submitted}");
    assert_eq!(submitted["verdict_saved"], true, "{submitted}");
    submitted["tx_hash"].as_str().expect("tx_hash").to_owned()
}
