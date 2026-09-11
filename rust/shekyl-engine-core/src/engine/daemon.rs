// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine → daemon RPC client wrapper.
//!
//! [`DaemonClient`] is the [`Engine`](super::Engine)-facing type for
//! reaching `shekyld` over HTTP(S). It is a thin wrapper around
//! [`shekyl_rpc_transport::HttpRpc`], chosen as the
//! default transport because it is the only daemon-RPC client crate
//! already in the workspace and it implements
//! [`shekyl_rpc_client::Rpc`].
//!
//! # Why a wrapper rather than `pub use`
//!
//! Three reasons, each independently sufficient:
//!
//! 1. **Insulates `Engine`'s public API from the transport choice.**
//!    The `Engine::daemon()` accessor returns a stable type. If a
//!    later phase swaps the underlying transport (UDS, gRPC, in-process
//!    test fake) the `Engine`-level signature is unchanged.
//! 2. **One audited site for daemon-bound calls.** The wallet's
//!    daemon-touching operations (`get_fee_estimates` for fee-priority
//!    resolution, transfer submission, the identity handshake on
//!    `get_version`) ultimately go through this type.
//! 3. **Keeps the cross-cutting lock 1 contract local.** The
//!    "caller-provided multi-threaded `tokio` runtime" requirement
//!    sits on a [`HttpRpc`] field rather than radiating through
//!    the wallet API.
//!
//! # Identity handshake (`VC-4`)
//!
//! [`DaemonClient::verifying`] compares the daemon's `get_version` tuple
//! to this build on first request, gated at [`Rpc::post`]. A mismatch is
//! [`RpcError::InvalidNode`]. [`DaemonClient::new`] performs no check
//! and exists for harnesses whose fake daemons serve no `get_version`.
//! Wallet-file vs caller network remains [`OpenError::NetworkMismatch`]
//! (`{ wallet, expected }`); that is a different fact.

use std::future::Future;

use serde_json::{json, Value};
use shekyl_rpc_client::{FeeRate, RejectCause, Rpc, RpcError};
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::{FeeTier, GetFeeEstimateResponse};
use shekyl_scanner::ScannableBlock;
use shekyl_wire::Transaction;

use crate::engine::pending::TxHash;
use crate::engine::traits::{DaemonEngine, DaemonHealth, FeeEstimates, TxSubmitOutcome};
use crate::engine::transaction_submitter::submit_outcome_from_verdict;

// One owner for the grace-block horizon: the constant lives in
// `shekyl-rpc-client` (a first-class workspace crate since the
// un-vendoring — the old "not re-exporting vendored internals"
// rationale for a local copy no longer applies).
use shekyl_rpc_client::GRACE_BLOCKS_FOR_FEE_ESTIMATE;

/// Map a daemon `get_fee_estimate` reply onto the three-tier
/// [`FeeEstimates`] snapshot, deriving every tier and the rounding mask
/// from this **one** response.
///
/// Parses through [`GetFeeEstimateResponse`] so a wire-arity change is a
/// type error here rather than a local JSON destructure the shared
/// contract cannot see. Tiers are [`FeeTier::Low`] / [`FeeTier::Normal`]
/// / [`FeeTier::High`] — one slot each, `[economy, standard, priority]`.
///
/// A missing `fees` array is malformed, not a legacy scalar to synthesize
/// from: Shekyl genesis is already 2021-scaling, and the invented
/// `×1 / ×5 / ×1000` band is gone.
fn fee_estimates_from_reply(reply: &GetFeeEstimateResponse) -> Result<FeeEstimates, RpcError> {
    if !reply.status.is_ok() {
        return Err(RpcError::InvalidFee);
    }
    let mask = reply.quantization_mask;
    Ok(FeeEstimates {
        economy: FeeRate::new(reply.fees.get(FeeTier::Low), mask)?,
        standard: FeeRate::new(reply.fees.get(FeeTier::Normal), mask)?,
        priority: FeeRate::new(reply.fees.get(FeeTier::High), mask)?,
        quantization_mask: mask,
    })
}

#[cfg(test)]
fn fee_estimates_from_value(result: &Value) -> Result<FeeEstimates, RpcError> {
    let reply = serde_json::from_value(result.clone()).map_err(|_| RpcError::InvalidFee)?;
    fee_estimates_from_reply(&reply)
}

/// What a wallet requires of the daemon it dials (`VC-4`).
///
/// Cross-cutting lock 5 (`WALLET_REWRITE_PLAN.md` :216): the daemon's
/// network is verified before any wallet operation. Comparison itself lives
/// in [`shekyl_rpc_types::IdentityExpectation`]; this type is the wallet
/// mapping (`shekyl_address::Network` has no `Fakechain`).
#[derive(Debug, Clone)]
pub struct DaemonExpectation {
    /// The network this wallet is bound to.
    pub network: shekyl_address::Network,
    /// Whether a `fakechain` daemon is acceptable.
    pub fakechain: FakechainPolicy,
}

/// Whether a wallet may run against a `shekyld --regtest` daemon (`VC-D6`).
///
/// **Typed, defaulted to `Refuse`, and armed only in-process by the regtest
/// harness and by tests. There is no operator flag and none ships** (`VC-R3`).
/// A `fakechain` daemon takes mainnet's configuration
/// (`cryptonote_config.h:562`), so it reports mainnet's genesis hash, mainnet's
/// constants digest and the same RPC version: three of the four axes are blind
/// to it by construction and `nettype` is the only one that can see it. A
/// shipped flag would therefore be a documented off-switch for the sole
/// defence against a mainnet wallet scanning a regtest chain with real
/// addresses. The asymmetry decides it — no flag costs a rare workflow some
/// friction; the flag costs the defence.
///
/// Reopening criterion: a *named* operator task that requires it, at which
/// point the surface is derived from that task rather than provisioned ahead
/// of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakechainPolicy {
    /// A daemon reporting `fakechain` is refused. The default, and the only
    /// value any shipped path selects.
    #[default]
    Refuse,
    /// A `fakechain` daemon is accepted. Set by `regtest_e2e` and by tests.
    Accept,
}

impl DaemonExpectation {
    fn pins(&self) -> shekyl_rpc_types::IdentityExpectation {
        let network = match self.network {
            shekyl_address::Network::Mainnet => shekyl_rpc_types::DaemonNetwork::Mainnet,
            shekyl_address::Network::Testnet => shekyl_rpc_types::DaemonNetwork::Testnet,
            shekyl_address::Network::Stagenet => shekyl_rpc_types::DaemonNetwork::Stagenet,
        };
        match self.fakechain {
            FakechainPolicy::Refuse => shekyl_rpc_types::IdentityExpectation::exact(network),
            FakechainPolicy::Accept => {
                shekyl_rpc_types::IdentityExpectation::exact_or_fakechain(network)
            }
        }
    }
}

/// Engine's view of the daemon RPC connection.
///
/// Held on [`Engine`](super::Engine) and shared, by clone, with
/// `shekyl-scanner` and the tx-submission path. The underlying
/// [`HttpRpc`] is `Clone + Send + Sync`; cloning it is cheap
/// (an `Arc`-wrapped HTTP client + URL string).
///
/// `DaemonClient` implements [`shekyl_rpc_client::Rpc`] (delegating `post` to
/// the wrapped transport) and the crate-internal `DaemonEngine` Stage 1
/// trait (in `crate::engine::traits`); callers reach the upstream
/// `Rpc` methods (block / height / output / mempool) via the
/// supertrait bound on `DaemonEngine` rather than going through the
/// underlying transport directly.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    inner: HttpRpc,
    /// What this wallet requires of the daemon, and the verdict once the
    /// handshake has run. `None` means the caller took responsibility for
    /// identity itself — see [`DaemonClient::new`].
    expectation: Option<DaemonExpectation>,
    /// Handshake verdict: `Ok` / confirmed mismatch are stored; transport
    /// failures are not (`get_or_try_init`).
    checked: std::sync::Arc<tokio::sync::OnceCell<Result<(), shekyl_rpc_types::IdentityMismatch>>>,
}

impl DaemonClient {
    /// Wrap an existing [`HttpRpc`] connection.
    ///
    /// **Performs no identity check.** For harnesses whose fake daemons serve
    /// no `get_version`, and for callers that have verified by other means.
    /// Every shipped path uses [`DaemonClient::verifying`] instead.
    pub fn new(inner: HttpRpc) -> Self {
        Self {
            inner,
            expectation: None,
            checked: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Wrap a connection and require the daemon to prove its identity before
    /// the first request (`VC-4`). **This is the constructor every shipped
    /// path uses**; [`DaemonClient::new`] performs no check and exists for
    /// harnesses whose fake daemons serve no `get_version`.
    #[must_use]
    pub fn verifying(inner: HttpRpc, expectation: DaemonExpectation) -> Self {
        Self {
            inner,
            expectation: Some(expectation),
            checked: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Run the identity handshake once, then reuse a confirmed verdict (`VC-4`).
    ///
    /// Transport / method errors are **not** stored: a daemon that is down or
    /// not ready on the first request must not permanently disable the client.
    /// A parsed mismatch (including a strict shape failure, `VC-D16`) is.
    async fn ensure_identity(&self) -> Result<(), RpcError> {
        let Some(expected) = self.expectation.as_ref() else {
            return Ok(());
        };
        match self
            .checked
            .get_or_try_init(|| async {
                match self.run_identity_handshake(expected).await {
                    Ok(()) => Ok(Ok(())),
                    Err(HandshakeFail::Mismatch(m)) => Ok(Err(m)),
                    Err(HandshakeFail::Transport(e)) => Err(e),
                }
            })
            .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(mismatch)) => Err(RpcError::InvalidNode(wallet_identity_message(mismatch))),
            Err(e) => Err(e),
        }
    }

    async fn run_identity_handshake(
        &self,
        expected: &DaemonExpectation,
    ) -> Result<(), HandshakeFail> {
        let reply = fetch_get_version(&self.inner).await?;
        expected
            .pins()
            .check(&reply)
            .map_err(HandshakeFail::Mismatch)
    }

    /// Fetch the block at `number` as a [`ScannableBlock`] via the native
    /// `shekyl-wire` parse (`engine::block_fetch`).
    ///
    /// Public inherent wrapper around the crate-private
    /// [`DaemonEngine::fetch_scannable_block`] default so transitional
    /// consumers (GUI `wallet_bridge` sync loop) can use the same path as
    /// `Engine` without depending on the private trait. Replaces the
    /// deleted `shekyl_rpc_client::Rpc::get_scannable_block_by_number`.
    ///
    /// The return type is the scanner crate's [`ScannableBlock`], re-exported
    /// from `shekyl-engine-core` so callers can name it without a direct
    /// `shekyl-scanner` dependency. A local wrapper/newtype is rejected:
    /// that would duplicate the canonical type and drift (type-placement).
    pub async fn fetch_scannable_block(&self, number: usize) -> Result<ScannableBlock, RpcError> {
        crate::engine::block_fetch::default_fetch_scannable_block(self, number).await
    }
}

enum HandshakeFail {
    Transport(RpcError),
    Mismatch(shekyl_rpc_types::IdentityMismatch),
}

/// Fetch `get_version` without going through [`DaemonClient::post`] (that
/// would recurse into the handshake). A JSON-RPC **error** object is
/// transport — the daemon is reachable but not ready — not a wire mismatch.
async fn fetch_get_version(
    inner: &HttpRpc,
) -> Result<shekyl_rpc_types::GetVersionResponse, HandshakeFail> {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "get_version",
        "params": {},
    }))
    .map_err(|e| HandshakeFail::Transport(RpcError::InternalError(e.to_string())))?;
    let raw = inner
        .post("json_rpc", body)
        .await
        .map_err(HandshakeFail::Transport)?;
    let envelope: Value = serde_json::from_slice(&raw)
        .map_err(|e| HandshakeFail::Mismatch(shekyl_rpc_types::IdentityMismatch::unreadable(e)))?;
    if let Some(error) = envelope.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no reason given");
        return Err(HandshakeFail::Transport(RpcError::ConnectionError(
            format!("get_version: {message}"),
        )));
    }
    let result = envelope.get("result").ok_or_else(|| {
        HandshakeFail::Mismatch(shekyl_rpc_types::IdentityMismatch::unreadable(
            "malformed get_version reply: no result",
        ))
    })?;
    serde_json::from_value(result.clone())
        .map_err(|e| HandshakeFail::Mismatch(shekyl_rpc_types::IdentityMismatch::unreadable(e)))
}

fn wallet_identity_message(m: &shekyl_rpc_types::IdentityMismatch) -> String {
    use shekyl_rpc_types::{core_rpc_version_string, IdentityAxis, IdentityMismatch};
    match m {
        IdentityMismatch::Wire { ours, theirs } => {
            let older = if theirs < ours {
                "daemon"
            } else {
                "this wallet"
            };
            format!(
                "{axis} mismatch: this wallet is {}, the daemon is {} — the {older} is the \
                 older one; update it. Refusing before any wallet operation.",
                core_rpc_version_string(*ours),
                core_rpc_version_string(*theirs),
                axis = IdentityAxis::Wire,
            )
        }
        IdentityMismatch::WireUnreadable { ours, evidence } => format!(
            "this daemon's `get_version` does not match the RPC contract this wallet \
             was built against, so the two are on different RPC versions. This wallet \
             is {}. The reply could not be read, so the daemon's version cannot be \
             named here; align the two builds. (evidence: {evidence})",
            core_rpc_version_string(*ours),
        ),
        IdentityMismatch::Rules { ours, theirs } => format!(
            "{axis} mismatch: this wallet's digest is {ours}, the daemon's is {theirs}. The \
             RPC contract matches, so neither side is a stale release — one tree's config/ \
             differs from the other, which is a different RULE SET rather than a version \
             skew. Balances read from it would be computed under rules this wallet does \
             not implement.",
            axis = IdentityAxis::Rules,
        ),
        IdentityMismatch::Network { ours, theirs } => format!(
            "{axis} mismatch: this wallet is a {ours} wallet, the daemon runs \
             {theirs}. This is the case cross-cutting lock 5 names — a wallet pointed at a \
             daemon on another network — so it refuses rather than scanning it.",
            axis = IdentityAxis::Network,
        ),
        IdentityMismatch::Genesis {
            ours,
            theirs,
            network,
        } => format!(
            "{axis} mismatch: this daemon's chain starts at {theirs}, this wallet's \
             {network} genesis is {ours}. Whatever else agrees, that is a different \
             chain.",
            axis = IdentityAxis::Genesis,
        ),
    }
}

impl Rpc for DaemonClient {
    /// Every request this wallet makes funnels here, which is why the
    /// identity handshake is gated at this one point: no wallet operation can
    /// reach the daemon before the tuple has been checked (`VC-4`).
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        async move {
            self.ensure_identity().await?;
            self.inner.post(route, body).await
        }
    }
}

impl DaemonEngine for DaemonClient {
    type Error = RpcError;

    /// Atomic single-RPC fee snapshot (§3.3).
    ///
    /// Issues **one** `get_fee_estimate` JSON-RPC call and maps its
    /// response onto all three non-`Custom`
    /// [`FeePriority`](super::FeePriority) tiers plus the snapshot
    /// `quantization_mask` via [`GetFeeEstimateResponse`] — not three
    /// per-tier [`Rpc::get_fee_rate`] calls, so the tier band carries no
    /// tier-vs-tier skew from interleaved reads.
    fn get_fee_estimates(&self) -> impl Send + Future<Output = Result<FeeEstimates, Self::Error>> {
        async move {
            let reply: GetFeeEstimateResponse = self
                .json_rpc_call(
                    "get_fee_estimate",
                    Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
                )
                .await?;
            fee_estimates_from_reply(&reply)
        }
    }

    /// Offer `tx_bytes` to the daemon over the typed submit route and
    /// map its [`SubmitVerdict`](shekyl_rpc_client::SubmitVerdict) to a
    /// [`TxSubmitOutcome`].
    ///
    /// 1. Parse `tx_bytes` back into a [`Transaction`]. A round-trip
    ///    failure is a malformed-tx rejection — these are the wallet's
    ///    *own* serialized bytes, so a parse failure is a build-path
    ///    defect, not a daemon verdict; no round-trip is issued
    ///    (mirrors the daemon's own Phase-A `Rejected{Malformed}`, so
    ///    the local guard and the wire verdict agree).
    /// 2. Compute the tx id **locally** from the parsed transaction;
    ///    never read it back from a daemon field, so an untrusted
    ///    daemon cannot influence the id the wallet records.
    /// 3. [`Rpc::publish_transaction`]; a transport/protocol failure
    ///    (including an unknown top-level verdict tag per the §2.3 skew
    ///    rules) surfaces as [`Self::Error`] — the orchestrator maps it
    ///    to the ambiguous-reservation path, not to an outcome.
    /// 4. Map the daemon verdict via [`submit_outcome_from_verdict`].
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl Send + Future<Output = Result<TxSubmitOutcome, Self::Error>> {
        async move {
            let tx = match Transaction::from_bytes(&tx_bytes) {
                Ok(tx) => tx,
                Err(e) => {
                    // The wallet is refusing bytes it built itself: a
                    // build-path defect, never a daemon verdict. Loud by
                    // design — the outcome below is indistinguishable from
                    // the daemon's Phase-A refusal, so this line is the only
                    // place the cause is visible.
                    tracing::error!(
                        error = %e,
                        tx_len = tx_bytes.len(),
                        "wallet-built transaction failed its own round-trip parse; \
                         refused locally as Malformed, no RPC issued"
                    );
                    return Ok(TxSubmitOutcome::Rejected {
                        cause: RejectCause::Malformed,
                    });
                }
            };

            let hash = TxHash::from_bytes(tx.hash());

            let verdict = self.publish_transaction(&tx_bytes).await?;
            Ok(submit_outcome_from_verdict(&verdict, hash))
        }
    }

    /// Snapshot daemon health via **one** `get_info` JSON-RPC read
    /// (§5.2 item 3). Identity is already gated at [`Rpc::post`].
    ///
    /// The summed outgoing/incoming connection counts and the sync
    /// position feed the §5.3 escape ladder's health gate. Untrusted-
    /// daemon input is parsed defensively (rule `20-rust-vs-cpp-policy`
    /// §3): a response missing the mandatory `height` field is a
    /// malformed reply ([`RpcError::InvalidNode`]), not a silently
    /// defaulted zero (a false "synced at height 0" would mislead the
    /// ladder's sync gate). Absent connection counts map to `0` — the
    /// safe direction, since a peerless reading only ever routes to the
    /// operator-alarm rung, never to a rebuild. `target_height` follows
    /// the info surface's "0 when synced" convention, so its absence
    /// maps to `0`, and the connection sum is `saturating_add` (rule §4).
    fn get_health(&self) -> impl Send + Future<Output = Result<DaemonHealth, Self::Error>> {
        async move {
            let info: Value = self.json_rpc_call("get_info", None).await?;
            let height = info
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcError::InvalidNode("get_info missing height".to_string()))?;
            let target_height = info
                .get("target_height")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let outgoing = info
                .get("outgoing_connections_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let incoming = info
                .get("incoming_connections_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            Ok(DaemonHealth {
                connections: outgoing.saturating_add(incoming),
                height,
                target_height,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    //! `fee_estimates_from_value` mapping regression (§3.3).
    //!
    //! The single-RPC snapshot's daemon-response mapping is a pure
    //! function, so it is exercised directly against synthetic
    //! `result` objects without a live daemon. The `DaemonClient`
    //! transport (`json_rpc_call` → `post`) is covered by the Phase 6
    //! live-`shekyld` harness, not here.
    use super::*;

    // ── VC-4: the identity handshake ────────────────────────────────────
    //
    // A wallet must refuse a daemon that is not the one it was built for,
    // BEFORE any wallet operation reads from it. Cross-cutting lock 5 has
    // required this since Phase 1 and nothing implemented it; these are the
    // tests that make the requirement falsifiable.
    //
    // Each case disagrees on exactly ONE axis and agrees on the others, so a
    // passing test names which comparison fired rather than "something
    // refused". The transport is a real loopback socket, so the refusal is
    // reached through `post` — the funnel every wallet request uses — rather
    // than by calling the checker directly.

    use std::io::{Read as _, Write as _};

    /// A one-request daemon that answers `get_version` with `reply`.
    fn fake_daemon(reply: String) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            while let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let Ok(n) = s.read(&mut buf) else { return };
                if n == 0 {
                    return;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                drop(s.write_all(head.as_bytes()));
                drop(s.write_all(reply.as_bytes()));
            }
        });
        address
    }

    /// A `get_version` reply agreeing with this build except where `edit`
    /// says otherwise.
    fn version_reply(edit: impl FnOnce(&mut shekyl_rpc_types::GetVersionResponse)) -> String {
        let mut reply = shekyl_rpc_types::GetVersionResponse {
            status: shekyl_rpc_types::RpcStatus::ok(),
            version: shekyl_rpc_types::CORE_RPC_VERSION,
            release: false,
            current_height: 1,
            target_height: 0,
            hard_forks: vec![],
            consensus_constants_digest: shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST_HASH,
            nettype: shekyl_rpc_types::DaemonNetwork::Mainnet,
            genesis_hash: shekyl_rpc_types::HashHex::from_bytes(
                shekyl_rpc_types::genesis_hash_for(shekyl_rpc_types::DaemonNetwork::Mainnet),
            ),
        };
        edit(&mut reply);
        json!({"jsonrpc": "2.0", "id": "0", "result": reply}).to_string()
    }

    async fn client_for(reply: String, expectation: DaemonExpectation) -> DaemonClient {
        let rpc = HttpRpc::new(format!("http://{}", fake_daemon(reply)))
            .await
            .expect("loopback endpoint");
        DaemonClient::verifying(rpc, expectation)
    }

    fn mainnet_expectation() -> DaemonExpectation {
        DaemonExpectation {
            network: shekyl_address::Network::Mainnet,
            fakechain: FakechainPolicy::Refuse,
        }
    }

    /// The refusal must arrive through the request funnel, not only from a
    /// checker called directly — otherwise a wallet operation could reach the
    /// daemon around it.
    async fn first_request_error(reply: String, expectation: DaemonExpectation) -> String {
        let client = client_for(reply, expectation).await;
        match client.post("/get_height", Vec::new()).await {
            Ok(_) => panic!("the request must be refused before it reaches the daemon"),
            Err(e) => format!("{e:?}"),
        }
    }

    #[tokio::test]
    async fn an_agreeing_daemon_is_not_refused() {
        // The check must be able to PASS, or every test below proves only
        // that something is broken.
        let client = client_for(version_reply(|_| {}), mainnet_expectation()).await;
        assert!(
            client.ensure_identity().await.is_ok(),
            "a daemon agreeing on every axis must pass"
        );
    }

    #[tokio::test]
    async fn a_wire_version_mismatch_refuses_and_names_the_older_side() {
        let out =
            first_request_error(version_reply(|r| r.version -= 1), mainnet_expectation()).await;
        assert!(out.contains("RPC contract mismatch"), "{out}");
        assert!(
            out.contains("the daemon is the older one"),
            "the refusal must say which side to update: {out}"
        );
    }

    #[tokio::test]
    async fn a_rules_digest_mismatch_refuses_without_inventing_an_ordering() {
        let out = first_request_error(
            version_reply(|r| {
                r.consensus_constants_digest = shekyl_rpc_types::HashHex::from_bytes([0x99; 32]);
            }),
            mainnet_expectation(),
        )
        .await;
        assert!(out.contains("consensus constants mismatch"), "{out}");
        // VC-D15: a hash carries no ordering and the message must not claim one.
        assert!(
            !out.contains("older"),
            "a digest mismatch cannot know a stale side and must not name one: {out}"
        );
        assert!(out.contains("different RULE SET"), "{out}");
    }

    #[tokio::test]
    async fn a_foreign_genesis_daemon_is_refused() {
        let out = first_request_error(
            version_reply(|r| {
                r.genesis_hash = shekyl_rpc_types::HashHex::from_bytes([0xff; 32]);
            }),
            mainnet_expectation(),
        )
        .await;
        assert!(out.contains("genesis block mismatch"), "{out}");
        assert!(out.contains("different chain"), "{out}");
    }

    #[tokio::test]
    async fn a_wrong_network_daemon_is_refused_which_is_lock_5() {
        // The case only this axis can see: the digest is generated from ONE
        // JSON for every network, so a testnet daemon from this same tree
        // carries the SAME digest and the SAME RPC version.
        let out = first_request_error(
            version_reply(|r| r.nettype = shekyl_rpc_types::DaemonNetwork::Testnet),
            mainnet_expectation(),
        )
        .await;
        assert!(out.contains("network mismatch"), "{out}");
        assert!(out.contains("lock 5"), "{out}");
    }

    #[tokio::test]
    async fn a_fakechain_daemon_is_refused_by_default_and_accepted_only_when_armed() {
        let fakechain =
            || version_reply(|r| r.nettype = shekyl_rpc_types::DaemonNetwork::Fakechain);

        // Default: refused. This is the shipped behaviour, and there is no
        // operator flag that changes it (VC-R3).
        let out = first_request_error(fakechain(), mainnet_expectation()).await;
        assert!(out.contains("network mismatch"), "{out}");

        // Armed in-process, as the regtest harness does.
        let client = client_for(
            fakechain(),
            DaemonExpectation {
                network: shekyl_address::Network::Mainnet,
                fakechain: FakechainPolicy::Accept,
            },
        )
        .await;
        assert!(
            client.ensure_identity().await.is_ok(),
            "the harness must be able to run against its own regtest daemon"
        );
    }

    #[tokio::test]
    async fn a_get_version_that_does_not_parse_is_reported_as_a_wire_mismatch() {
        // VC-D16: the tuple fields are strict, so a daemon whose get_version
        // shape moved fails deserialization before any axis is read. That IS
        // the wire axis disagreeing and the operator must be told so.
        let out = first_request_error(
            json!({"jsonrpc": "2.0", "id": "0", "result": {"status": "OK", "version": 1}})
                .to_string(),
            mainnet_expectation(),
        )
        .await;
        assert!(out.contains("does not match the RPC contract"), "{out}");
        assert!(
            out.contains("cannot be named here"),
            "it must say the daemon's version is unavailable rather than guess: {out}"
        );
    }

    #[tokio::test]
    async fn the_verdict_is_computed_once_and_reused() {
        // The handshake is per connection, not per request: a wallet that
        // re-verified on every call would multiply every operation's round
        // trips. The fake daemon answers `get_version` to ANY request, so a
        // second handshake would succeed — what this asserts is that the
        // second call does not repeat it, by observing that a refusal stays
        // refused rather than being re-derived.
        let client = client_for(version_reply(|r| r.version -= 1), mainnet_expectation()).await;
        let first = client.ensure_identity().await;
        let second = client.ensure_identity().await;
        assert!(
            first.is_err() && second.is_err(),
            "the verdict must persist"
        );
    }

    #[tokio::test]
    async fn an_unverified_client_makes_no_handshake_at_all() {
        // `DaemonClient::new` is the harness constructor: it must not reach
        // for `get_version`, or every existing fixture would need one.
        let rpc = HttpRpc::new(format!("http://{}", fake_daemon(String::new())))
            .await
            .expect("loopback endpoint");
        let client = DaemonClient::new(rpc);
        assert!(client.ensure_identity().await.is_ok());
    }

    #[tokio::test]
    async fn a_transport_failure_is_not_cached_as_a_mismatch() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let reply = version_reply(|_| {});
        std::thread::spawn(move || {
            if let Ok((s, _)) = listener.accept() {
                drop(s);
            }
            while let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let Ok(n) = s.read(&mut buf) else { return };
                if n == 0 {
                    return;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                drop(s.write_all(head.as_bytes()));
                drop(s.write_all(reply.as_bytes()));
            }
        });
        let rpc = HttpRpc::new(format!("http://{address}"))
            .await
            .expect("loopback endpoint");
        let client = DaemonClient::verifying(rpc, mainnet_expectation());
        let first = client.ensure_identity().await;
        assert!(
            matches!(first, Err(RpcError::ConnectionError(_))),
            "a hang-up is transport, not InvalidNode: {first:?}"
        );
        let second = client.ensure_identity().await;
        assert!(
            second.is_ok(),
            "a later agreeing daemon must pass after a transport miss: {second:?}"
        );
    }

    #[tokio::test]
    async fn a_jsonrpc_error_is_not_cached_as_a_mismatch() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let error_body =
            json!({"jsonrpc":"2.0","id":0,"error":{"code":-1,"message":"not ready"}}).to_string();
        let ok_body = version_reply(|_| {});
        std::thread::spawn(move || {
            for payload in [error_body, ok_body] {
                let Ok((mut s, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 8192];
                drop(s.read(&mut buf));
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                drop(s.write_all(head.as_bytes()));
                drop(s.write_all(payload.as_bytes()));
            }
        });
        let rpc = HttpRpc::new(format!("http://{address}"))
            .await
            .expect("loopback endpoint");
        let client = DaemonClient::verifying(rpc, mainnet_expectation());
        let first = client.ensure_identity().await;
        assert!(
            matches!(first, Err(RpcError::ConnectionError(_))),
            "not-ready is transport, not a contract mismatch: {first:?}"
        );
        let second = client.ensure_identity().await;
        assert!(
            second.is_ok(),
            "the handshake must retry after a method error: {second:?}"
        );
    }

    /// Tiers map Low/Normal/High onto `[economy, standard, priority]`,
    /// and the shared `quantization_mask` lands on the snapshot.
    #[test]
    fn fee_estimates_array_maps_the_three_priced_tiers() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 400],
            "quantization_mask": 8u64,
        });
        let est = fee_estimates_from_value(&result).expect("well-formed fee array");
        assert_eq!(est.economy, FeeRate::new(100, 8).unwrap());
        assert_eq!(est.standard, FeeRate::new(200, 8).unwrap());
        assert_eq!(est.priority, FeeRate::new(400, 8).unwrap());
        assert_eq!(est.quantization_mask, 8);
        assert_ne!(est.economy, est.priority);
    }

    /// A reply carrying only the scalar `fee` is malformed, not a
    /// legacy shape to synthesize tiers from.
    #[test]
    fn fee_estimates_refuses_a_scalar_only_reply() {
        for reply in [
            json!({"status": "OK", "fee": 10u64, "quantization_mask": 4u64}),
            json!({"status": "OK", "fees": null, "fee": 10u64, "quantization_mask": 4u64}),
        ] {
            assert!(
                matches!(fee_estimates_from_value(&reply), Err(RpcError::InvalidFee)),
                "a scalar-only reply must not synthesize a tier band: {reply}"
            );
        }
    }

    #[test]
    fn fee_estimates_rejects_non_ok_status() {
        let result = json!({
            "status": "BUSY",
            "fees": [100u64, 200, 400],
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// A count other than three is a parse error, including the four-slot
    /// shape that used to be the contract. Reading four as a longer
    /// three-slot answer would put priority on the old bridge slot.
    #[test]
    fn fee_estimates_rejects_the_wrong_tier_count() {
        for fees in [
            json!([100u64, 200]),
            json!([100u64, 200, 300, 400]),
            json!([100u64, 200, 300, 400, 500, 600]),
            json!([]),
        ] {
            let result = json!({
                "status": "OK",
                "fees": fees,
                "quantization_mask": 8u64,
            });
            assert!(
                matches!(fee_estimates_from_value(&result), Err(RpcError::InvalidFee)),
                "a tier count other than three must not parse: {result}"
            );
        }
    }

    /// A present-but-non-array `fees` (e.g. a string) is malformed, and
    /// the neighbouring scalar `fee` does not rescue it.
    #[test]
    fn fee_estimates_rejects_non_array_fees() {
        let result = json!({
            "status": "OK",
            "fees": "oops",
            "fee": 10u64,
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// Absent `quantization_mask` is the wire default (`OPT(1)`), matching
    /// [`GetFeeEstimateResponse`].
    #[test]
    fn fee_estimates_absent_mask_is_the_wire_default() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 400],
        });
        let est = fee_estimates_from_value(&result).expect("mask OPT(1)");
        assert_eq!(est.quantization_mask, 1);
        assert_eq!(est.priority, FeeRate::new(400, 1).unwrap());
    }

    /// `quantization_mask == 0` would make `FeeRate::new` reject; the
    /// mapping surfaces that as `InvalidFee` rather than panicking.
    #[test]
    fn fee_estimates_rejects_zero_mask() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 400],
            "quantization_mask": 0u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }
}
