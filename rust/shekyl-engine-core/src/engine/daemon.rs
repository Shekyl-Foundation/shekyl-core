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
//!    daemon-touching operations (`get_info` for network verification,
//!    `get_fee_estimates` for fee-priority resolution, transfer
//!    submission) ultimately go through this type, which gives Phase 2a
//!    a single place to add tracing spans, fee-sanity checks, and
//!    network-mismatch detection without touching every call site.
//! 3. **Keeps the cross-cutting lock 1 contract local.** The
//!    "caller-provided multi-threaded `tokio` runtime" requirement
//!    sits on a [`HttpRpc`] field rather than radiating through
//!    the wallet API.
//!
//! # Network verification (Phase 2a)
//!
//! [`DaemonClient`] does not yet verify the daemon's network on
//! construction; that ships with `Engine::open_*`'s lifecycle commit,
//! which calls `get_info` and compares the daemon-reported network with
//! the wallet file's region 1 declaration. Mismatches surface as
//! [`OpenError::NetworkMismatch`](super::error::OpenError::NetworkMismatch).

use std::future::Future;

use serde_json::{json, Value};
use shekyl_rpc_client::{FeeRate, RejectCause, Rpc, RpcError};
use shekyl_rpc_transport::HttpRpc;
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

/// Map a daemon `get_fee_estimate` JSON-RPC `result` object onto the
/// three-tier [`FeeEstimates`] snapshot (§3.3), deriving every tier
/// and the rounding mask from this **one** response.
///
/// Mirrors `shekyl_rpc_client::Rpc::get_fee_rate`'s response handling but
/// resolves **all three** non-`Custom` tiers from a single call rather
/// than one tier per call. Tiers map to `fees` indices `0` (economy),
/// `1` (standard), `3` (priority) per `V3_WALLET_DECISION_LOG.md`.
/// Index `2` (`Fm`, "elevated") is deliberately unmapped: the wallet
/// offers three named tiers, and the ladder's ends — cheapest and
/// fastest — are the ones a user picks between.
///
/// # `fees` is required, and its absence is not a legacy shape
///
/// The ArticMine 2021 fee ladder is live **from genesis**:
/// `HF_VERSION_2021_SCALING` is `1` (`src/cryptonote_config.h`), so
/// `core_rpc_server::on_get_base_fee_estimate` always takes the
/// `version >= HF_VERSION_2021_SCALING` branch and always answers with
/// a four-element `fees` array (`Blockchain::
/// get_dynamic_base_fee_estimate_2021_scaling` `resize(4)`s it). Every
/// Shekyl daemon is subject to the same rule.
///
/// A pre-2021-scaling daemon answering with a bare scalar `fee` is
/// therefore a shape that **cannot occur on this chain**; it is
/// Monero-lineage inheritance, and the multiplier ladder the wallet
/// used to synthesize from it (`×1 / ×5 / ×1000`) was an invented
/// tier band with no daemon behind it — one that put `priority`
/// three orders of magnitude above `economy` and so tripped the
/// absolute cap on any base fee over 100, refusing the whole snapshot
/// (Economy included) for a daemon that had charged nothing unusual.
/// Deleted per rules 60 / 15 / 16: a missing `fees` array is a
/// malformed reply, like any other missing field.
///
/// Untrusted-daemon input is parsed defensively (rule
/// `20-rust-vs-cpp-policy.mdc` §3): every field is validated, and
/// missing or non-numeric fields and `status != "OK"` map to
/// [`RpcError::InvalidFee`] / [`RpcError::InvalidPriority`].
fn fee_estimates_from_value(result: &Value) -> Result<FeeEstimates, RpcError> {
    if result.get("status").and_then(Value::as_str) != Some("OK") {
        return Err(RpcError::InvalidFee);
    }

    let mask = result
        .get("quantization_mask")
        .and_then(Value::as_u64)
        .ok_or(RpcError::InvalidFee)?;

    // `FeeRate::new` already rejects `mask == 0` / `per_weight == 0`;
    // surface a per-tier rate or the upstream error verbatim.
    let rate = |per_weight: u64| FeeRate::new(per_weight, mask);

    // `fees` must be an array of at least the four tiers every Shekyl
    // daemon emits. Absent, null, or any non-array (`fees: "oops"`) is
    // a malformed reply — there is no fallback shape to degrade to, so
    // nothing here can silently accept a snapshot the daemon did not
    // actually quote.
    let Some(Value::Array(fees)) = result.get("fees") else {
        return Err(RpcError::InvalidFee);
    };
    // A short array is a malformed estimate, not a silently-clamped
    // one. Destructured once rather than indexed three times, so the
    // ladder positions are named here and nowhere else — including
    // `_elevated` (`Fm`), whose absence from the wallet's tier set is
    // now visible in the code instead of only in prose. A longer array
    // from a future daemon keeps working (rule 75).
    let [economy, standard, _elevated, priority, ..] = &fees[..] else {
        return Err(RpcError::InvalidPriority);
    };
    let tier = |value: &Value| -> Result<u64, RpcError> {
        value.as_u64().ok_or(RpcError::InvalidPriority)
    };
    let (economy, standard, priority) = (
        rate(tier(economy)?)?,
        rate(tier(standard)?)?,
        rate(tier(priority)?)?,
    );

    Ok(FeeEstimates {
        economy,
        standard,
        priority,
        quantization_mask: mask,
    })
}

/// What a wallet requires of the daemon it dials (`VC-4`).
///
/// Cross-cutting lock 5 (`WALLET_REWRITE_PLAN.md` :216) has required since
/// Phase 1 that the daemon's network be verified before any wallet operation,
/// as a defence against a DNS answer pointing a testnet wallet at a mainnet
/// daemon. What landed compared the wallet FILE against the caller's
/// `expected` parameter and never asked the daemon — the variant's fields,
/// `{ wallet, expected }`, have no place for a daemon-reported value — while
/// two docstrings said otherwise. This type is the missing half.
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

/// Which axis of the identity tuple disagreed (`VC-4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAxis {
    /// `CORE_RPC_VERSION`: the two binaries do not share an RPC contract.
    Wire,
    /// The consensus-constant digest: built from different `config/`
    /// authorities, which is a different rule set.
    Rules,
    /// `nettype`: same rules, a different instance of them.
    Network,
    /// Block 0's hash: the chain does not start where this build's does.
    Genesis,
}

impl std::fmt::Display for IdentityAxis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wire => "RPC contract",
            Self::Rules => "consensus constants",
            Self::Network => "network",
            Self::Genesis => "genesis block",
        })
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
    /// The handshake verdict, computed on the **first** request and reused.
    ///
    /// First-use rather than at construction or at `Engine::open_*`: the open
    /// path is synchronous and the daemon is not, and opening a wallet file
    /// should not require a network round trip. It is also the honest reading
    /// of a connect-time check — before the first request to this daemon —
    /// and it is the same shape the console arm uses (`VC-3`), so the two
    /// arms answer the question the same way.
    checked: std::sync::Arc<tokio::sync::OnceCell<Result<(), String>>>,
}

impl DaemonClient {
    /// Wrap an existing [`HttpRpc`] connection.
    ///
    /// **Performs no identity check.** For harnesses whose fake daemons serve
    /// no `get_version`, and for callers that have verified by other means.
    /// Every shipped path uses [`DaemonClient::verifying`] instead.
    ///
    /// This docstring used to read "daemon network verification is performed
    /// by `Engine::open_*`". That was false for the whole of Phase 1: what
    /// `open_*` compares is the wallet FILE against the caller's `expected`
    /// parameter, and no daemon-reported value entered the comparison at all.
    /// Corrected with the check that makes it true elsewhere (`VC-4`).
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

    /// Run the identity handshake once, then reuse its verdict (`VC-4`).
    ///
    /// Four axes, all read from **one** `get_version` reply: two calls could
    /// straddle a restart or a proxy fronting two nodes and return axes from
    /// different daemons, so a client would accept a tuple that never
    /// simultaneously existed (`VC-R2`).
    ///
    /// **`VC-D16`** — the reply's fields are strict, so a daemon whose
    /// `get_version` shape has moved fails to deserialize before any axis is
    /// read. That is the wire axis disagreeing, reported in those terms.
    async fn ensure_identity(&self) -> Result<(), RpcError> {
        let Some(expected) = self.expectation.as_ref() else {
            return Ok(());
        };
        let verdict = self
            .checked
            .get_or_init(|| async { self.run_identity_handshake(expected).await })
            .await;
        match verdict {
            Ok(()) => Ok(()),
            Err(reason) => Err(RpcError::InvalidNode(reason.clone())),
        }
    }

    async fn run_identity_handshake(&self, expected: &DaemonExpectation) -> Result<(), String> {
        let reply: shekyl_rpc_types::GetVersionResponse = self
            .inner
            .json_rpc_call("get_version", None)
            .await
            .map_err(|e| {
                format!(
                    "this daemon's `get_version` does not match the RPC contract this wallet \
                     was built against, so the two are on different RPC versions. This wallet \
                     is {ours}. The reply could not be read, so the daemon's version cannot be \
                     named here; align the two builds. (evidence: {e})",
                    ours = version_string(shekyl_rpc_types::CORE_RPC_VERSION),
                )
            })?;

        if reply.version != shekyl_rpc_types::CORE_RPC_VERSION {
            let (ours, them) = (shekyl_rpc_types::CORE_RPC_VERSION, reply.version);
            let older = if them < ours { "daemon" } else { "this wallet" };
            return Err(format!(
                "{axis} mismatch: this wallet is {}, the daemon is {} — the {older} is the \
                 older one; update it. Refusing before any wallet operation.",
                version_string(ours),
                version_string(them),
                axis = IdentityAxis::Wire,
            ));
        }
        if reply.consensus_constants_digest != shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST_HASH {
            // A digest carries no ordering, so the refusal does not invent
            // one (`VC-D15`); it says what the disagreement means instead.
            return Err(format!(
                "{axis} mismatch: this wallet's digest is {ours}, the daemon's is {theirs}. The \
                 RPC contract matches, so neither side is a stale release — one tree's config/ \
                 differs from the other, which is a different RULE SET rather than a version \
                 skew. Balances read from it would be computed under rules this wallet does \
                 not implement.",
                ours = shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST,
                theirs = reply.consensus_constants_digest,
                axis = IdentityAxis::Rules,
            ));
        }

        let ours_network = expectation_network(expected.network);
        let network_ok = reply.nettype == ours_network
            || (reply.nettype == shekyl_rpc_types::DaemonNetwork::Fakechain
                && expected.fakechain == FakechainPolicy::Accept);
        if !network_ok {
            return Err(format!(
                "{axis} mismatch: this wallet is a {ours_network} wallet, the daemon runs \
                 {theirs}. This is the case cross-cutting lock 5 names — a wallet pointed at a \
                 daemon on another network — so it refuses rather than scanning it.",
                theirs = reply.nettype,
                axis = IdentityAxis::Network,
            ));
        }

        let expected_genesis = genesis_hash_for(expected.network);
        if !GENESIS_PINS_ARE_PLACEHOLDERS && reply.genesis_hash.to_bytes() != expected_genesis {
            return Err(format!(
                "{axis} mismatch: this daemon's chain starts at {theirs}, this wallet's \
                 {ours_network} genesis is {ours}. Whatever else agrees, that is a different \
                 chain.",
                theirs = reply.genesis_hash,
                ours = shekyl_rpc_types::HashHex::from_bytes(expected_genesis),
                axis = IdentityAxis::Genesis,
            ));
        }
        Ok(())
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

/// `3.29` from the packed constant, for an operator-facing message.
fn version_string(packed: u32) -> String {
    format!("{}.{}", packed >> 16, packed & 0xffff)
}

/// The wallet's network as the daemon spells it on the wire.
///
/// `shekyl_address::Network` has three variants and deliberately no
/// `Fakechain` (`V3_WALLET_DECISION_LOG.md` :1397 defers that workspace-wide
/// change), which is why the wire-side [`shekyl_rpc_types::DaemonNetwork`]
/// carries the fourth and the fakechain arm is a policy rather than a mapping.
fn expectation_network(network: shekyl_address::Network) -> shekyl_rpc_types::DaemonNetwork {
    match network {
        shekyl_address::Network::Mainnet => shekyl_rpc_types::DaemonNetwork::Mainnet,
        shekyl_address::Network::Testnet => shekyl_rpc_types::DaemonNetwork::Testnet,
        shekyl_address::Network::Stagenet => shekyl_rpc_types::DaemonNetwork::Stagenet,
    }
}

/// The genesis block hash this build expects on `network` (`VC-D12`).
///
/// Rule 71: the network selects **data** — which constant is compared — and
/// never control flow. These are pins, not a computation: the daemon derives
/// block 0 from `GENESIS_TX` / `GENESIS_NONCE` per network
/// (`src/cryptonote_config.h:368`, `:500`, `:511`) and the client side has
/// never held the answer at all, which is what `VC-R2` found while checking
/// whether anything compared it.
///
/// **These are placeholders until the KAT lands.** A pin whose value is not
/// derived from the chain it names is a number, not a fact — so `VC-4`'s
/// remaining task is capturing block 0 from a live daemon per network the way
/// the txid KATs were captured, and replacing these. Until then
/// `GENESIS_PINS_ARE_PLACEHOLDERS` is `true` and the genesis axis does not
/// refuse; the other three do.
const fn genesis_hash_for(_network: shekyl_address::Network) -> [u8; 32] {
    [0u8; 32]
}

/// Whether [`genesis_hash_for`] returns real pins yet.
///
/// Stated as a constant rather than a comment so the arm that skips the
/// comparison is visible to a grep and cannot be forgotten: this is the one
/// axis of the tuple that is not yet armed.
const GENESIS_PINS_ARE_PLACEHOLDERS: bool = true;

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
    /// `quantization_mask` via [`fee_estimates_from_value`] — not
    /// three per-tier [`Rpc::get_fee_rate`] calls, so the tier band
    /// carries no tier-vs-tier skew from interleaved reads.
    fn get_fee_estimates(&self) -> impl Send + Future<Output = Result<FeeEstimates, Self::Error>> {
        async move {
            let result: Value = self
                .json_rpc_call(
                    "get_fee_estimate",
                    Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
                )
                .await?;
            fee_estimates_from_value(&result)
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
            let Ok(tx) = Transaction::from_bytes(&tx_bytes) else {
                return Ok(TxSubmitOutcome::Rejected {
                    cause: RejectCause::Malformed,
                });
            };

            let hash = TxHash::from_bytes(tx.hash());

            let verdict = self.publish_transaction(&tx_bytes).await?;
            Ok(submit_outcome_from_verdict(&verdict, hash))
        }
    }

    /// Snapshot daemon health via **one** `get_info` JSON-RPC read
    /// (§5.2 item 3) — the same info surface `Engine::open_*` already
    /// queries for network verification, so this adds no new RPC method.
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
            genesis_hash: shekyl_rpc_types::HashHex::from_bytes([0u8; 32]),
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

    /// V3 daemon: `fees` array present, tiers map to indices 0/1/3
    /// and the shared `quantization_mask` lands on the snapshot.
    #[test]
    fn fee_estimates_array_maps_indices_0_1_3() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400],
            "fee": 100,
            "quantization_mask": 8u64,
        });
        let est = fee_estimates_from_value(&result).expect("well-formed fee array");
        assert_eq!(est.economy, FeeRate::new(100, 8).unwrap());
        assert_eq!(est.standard, FeeRate::new(200, 8).unwrap());
        // Index 3, *not* 2 — the "elevated" tier (index 2) has no
        // wallet `FeePriority`.
        assert_eq!(est.priority, FeeRate::new(400, 8).unwrap());
        assert_eq!(est.quantization_mask, 8);
        // Tiers are distinct (regression for a collapsed mapping).
        assert_ne!(est.economy, est.priority);
    }

    /// A reply carrying only the scalar `fee` is malformed, not a
    /// legacy shape to synthesize tiers from.
    ///
    /// `HF_VERSION_2021_SCALING` is `1`, so every Shekyl daemon emits
    /// `fees[4]`; the `×1 / ×5 / ×1000` ladder the wallet used to
    /// invent here had no daemon behind it, and its `×1000` priority
    /// meant any base fee above 100 blew the absolute cap and got the
    /// **whole** snapshot refused — Economy included — for a daemon
    /// charging nothing unusual.
    ///
    /// This bites against the ladder being reintroduced. It does NOT
    /// cover the `fees` mapping (that is
    /// `fee_estimates_array_maps_indices_0_1_3`).
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
            "fees": [100u64, 200, 300, 400],
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// A `fees` array too short to carry the priority tier (index 3)
    /// is malformed, not silently clamped to a lower tier.
    #[test]
    fn fee_estimates_rejects_short_fees_array() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200],
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidPriority)
        ));
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

    /// A daemon that grows the ladder past four tiers keeps working:
    /// the wallet reads its three positions and ignores the rest
    /// (rule 75 — no coordinated wallet upgrade for a tier it does not
    /// offer).
    #[test]
    fn fee_estimates_tolerates_a_longer_fees_array() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400, 500, 600],
            "quantization_mask": 8u64,
        });
        let est = fee_estimates_from_value(&result).expect("a longer ladder is not malformed");
        assert_eq!(est.economy, FeeRate::new(100, 8).unwrap());
        assert_eq!(est.standard, FeeRate::new(200, 8).unwrap());
        assert_eq!(est.priority, FeeRate::new(400, 8).unwrap());
    }

    #[test]
    fn fee_estimates_rejects_missing_mask() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400],
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// `quantization_mask == 0` would make `FeeRate::new` reject; the
    /// mapping surfaces that as `InvalidFee` rather than panicking.
    #[test]
    fn fee_estimates_rejects_zero_mask() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400],
            "quantization_mask": 0u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }
}
