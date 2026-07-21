// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CB-3 dispatch seam — the Engine-side `P`→principal **drain request
//! path** (`ARCHIVAL_DRAIN_SEND_FD2.md` §6; the `claim_dispatch` sibling).
//!
//! [`orchestrate_drain`] is the production preparer+assembler and deliberately
//! returns its reply **unbroadcast** (CB-3: the builder never self-schedules).
//! This module is the other half of that routing: one explicit drain intent in
//! (a slot, a payment, a fee), one assembled drain dispatched through the
//! audited posture→submitter choke point ([`BroadcastSubmitter::local`] →
//! [`submit_bound`]) out. Scheduling policy — when a drain fires, how it is
//! split, over what cadence — stays external (the GUI drain flow, §12.4); this
//! method fires once per caller intent, never on a loop of its own.
//!
//! Mirrors [`Engine::submit_emission_claim`](super::claim_dispatch)'s shape: a
//! self-arc method that clones its actor handles under one brief read lock,
//! loads the sealed P-scan state and the live reservation set through the same
//! independent stores the bond/claim paths use, and hands everything to the
//! pipeline. A drain is **self-initiated** — there is no daemon-side source to
//! fetch (unlike a claim), so the reference is anchored off the wallet's own
//! `chain_tip` ([`LedgerEngine::synced_height`]) exactly as a bond post is.
//! Secrets stay inside the stake actor (rule 36); this seam touches public
//! material only.
//!
//! ## The principal destination (T-DS-3)
//!
//! A drain's vout 0 pays the wallet's **own** principal address, and that
//! destination is **never caller-supplied** — a caller-chosen target would let
//! a drain move `P` value to an arbitrary address, defeating the point of the
//! firewall's value-out leg being a self-sweep. The seam resolves it
//! engine-side from [`Engine::primary_address`] and decodes it into the public
//! [`DrainDestination`] triple with the **same** birational map the transfer
//! path uses for any recipient ([`ed25519_pk_to_x25519_pk`] on the view key),
//! so the drain's output is bit-for-bit an ordinary transfer output (T-DS-6 ∧
//! T-DS-7 wire-shape parity, `drain_assembly` module docs).
//!
//! ## Persist-before-dispatch
//!
//! The bond/claim load-bearing invariant holds here too: no drain bytes reach
//! any submitter unless a sealed [`PendingDrain`] already holds them. The
//! record carries the swept-input reservation (it feeds the shared
//! [`reserved_gindexes`](shekyl_engine_state::PendingPostBlock::reserved_gindexes)
//! union, so neither a bond sweep, a claim fee sweep, nor a second drain can
//! double-spend the drained inputs while this drain is in flight); one live
//! drain per persona is the in-flight dedup. A crash after the seal resumes as
//! "maybe sent", which is safe because every resend is byte-identical.
//! Retirement (confirmation observe / terminal-reject prune, byte-identical
//! resubmit) is the drain dispatch driver — the record shape this seam seals
//! already serves it, the WI-3 sibling slice.
//!
//! ## Transport (T-DS-2)
//!
//! Dispatch rides the persona-transport choke point ([`BroadcastSubmitter`]),
//! the same isolation bond-post and claim dispatch already use — the drain
//! introduces no new broadcast path. The pre-bound ① `Local` posture (loopback
//! on the operator's own box) is the privacy default; the operator's explicit
//! ② posture choice plugs in via the 2c config-source slice, which swaps this
//! call, not this seam. The bytes never touch a bare `DaemonClient`.
//!
//! [`orchestrate_drain`]: super::drain_orchestrator::orchestrate_drain
//! [`submit_bound`]: BroadcastSubmitter::submit_bound
//! [`ed25519_pk_to_x25519_pk`]: shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk

use std::sync::Arc;

use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingDrain, PendingPostState};
use shekyl_engine_state::pscan_state::{PFundingOutputRecord, PScanState};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::drain_assembly::{AssembledDrain, DrainDestination};
use super::drain_orchestrator::{orchestrate_drain, DrainCtx, DrainOrchestrationError};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::start::{load_pscan_state_for_engine, pending_post_store_for_engine};
use super::signer::EngineSignerKind;
use super::stake_engine::{PSlot, StakeEngineError};
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::transaction_submitter::{BroadcastSubmitError, BroadcastSubmitter, SubmitSuccess};
use super::Engine;

/// What one dispatched drain did: the assembled drain's public facts plus the
/// network verdict. Secrets never cross the boundary — the contained
/// [`PBoundBytes`](super::bond_assembly::PBoundBytes) redacts its own `Debug`.
// Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the receipt's
// production reader is the RPC drain entry (rule-21, the same retirement
// condition `submit_emission_claim`'s receipt carries); the PR e2e is the test
// consumer.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DrainReceipt {
    /// The dispatched drain exactly as assembled (persona-bound bytes + the
    /// swept-input reservation set) — the actor's reply embedded whole.
    pub drain: AssembledDrain,
    /// The daemon's submit verdict (network-exposed / already mined).
    pub submit: SubmitSuccess,
}

/// Why the drain request refused, at any rung: before the pipeline (no stake
/// engine, actor refusals, destination resolution, state reads), inside it
/// ([`DrainOrchestrationError`]), or at the dispatch choke point. Every arm is
/// caller-actionable per rule 82, and scalar-free (no amount or gindex in any
/// rendering — the firewall's value-out leg leaks nothing through its errors).
#[derive(Debug, thiserror::Error)]
pub(crate) enum DrainRequestError {
    /// This wallet runs no stake engine — it is not a staker, and the drain
    /// path does not exist here.
    #[error("this wallet is not a staker: no stake engine is running")]
    NotStaker,
    /// A stake-actor call **outside** the assembly itself refused (persona
    /// identity projection or handle mint); assembly-time refusals arrive as
    /// [`Self::Drain`].
    #[error("stake engine: {0}")]
    Stake(#[from] StakeEngineError),
    /// The persona's public identity key failed canonical encoding — a
    /// corrupted resident key; fail closed.
    #[error("persona identity encoding: {0}")]
    Identity(shekyl_crypto_pq::CryptoError),
    /// The wallet's own principal view key did not map to a valid X25519
    /// point — a corrupted resident key; fail closed rather than assemble a
    /// drain whose output the wallet itself could never decap.
    #[error("principal destination: {detail}")]
    Destination {
        /// The invariant that broke.
        detail: &'static str,
    },
    /// A sealed-state read failed (the P-scan seal or the pending-post seal) —
    /// fail-closed, never an invented-empty set over a bad seal.
    #[error("engine state read ({context}): {detail}")]
    State {
        /// Which read refused.
        context: &'static str,
        /// The store's own rendering of the failure.
        detail: String,
    },
    /// A live pending drain already exists for this persona. One live drain
    /// per persona: the live record IS the in-flight input reservation — a
    /// second drain would race for the same swept inputs. Wait for the pending
    /// drain to confirm or fail before re-draining.
    #[error("a pending drain already exists for this persona; one live drain per persona")]
    DrainPending,
    /// The drain pipeline refused (reference anchor, exit-reserve, planning,
    /// path assembly, or the actor's assembly itself).
    #[error(transparent)]
    Drain(#[from] DrainOrchestrationError),
    /// The assembled bytes' dispatch failed at (or behind) the submit choke
    /// point; the drain was assembled but its network fate is the error's to
    /// name.
    #[error("drain broadcast: {0}")]
    Submit(#[from] BroadcastSubmitError),
}

impl DrainRequestError {
    /// A fail-closed sealed-state read refusal, context named.
    fn state(context: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::State {
            context,
            detail: detail.to_string(),
        }
    }
}

#[allow(private_bounds)] // same Engine-trait privacy posture as submit_emission_claim
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Self: Send + Sync,
{
    /// Assemble and dispatch one `P`→principal drain for the persona at
    /// `p_slot` — the CB-3 request path (module docs).
    ///
    /// `payment` is paid to the wallet's own principal (vout 0); `fee` funds
    /// the tx from the swept `P` inputs; the residual (`swept − payment − fee`)
    /// returns to `P` as change on a partial drain. The reserve gate
    /// ([`orchestrate_drain`]) refuses a live-persona drain that would spend
    /// the pool below the exit-fee reserve (DS-4); a retired persona may sweep
    /// to zero. The principal destination is resolved engine-side (T-DS-3), not
    /// caller-supplied.
    // Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the
    // production caller is the RPC drain entry — the same rule-21 retirement
    // condition `submit_emission_claim` carries; the PR regtest e2e is the test
    // consumer.
    #[allow(dead_code)]
    pub(crate) async fn submit_drain(
        self_arc: Arc<RwLock<Self>>,
        p_slot: PSlot,
        payment: AtomicUnits,
        fee: AtomicUnits,
    ) -> Result<DrainReceipt, DrainRequestError> {
        // Brief read: clone the actor handles + the ledger snapshot the pipeline
        // needs, and capture the wallet's own primary address (the drain
        // destination is engine-resolved, T-DS-3). A drain anchors off the
        // wallet's own synced tip (self-initiated, like a bond post).
        let (daemon, stake, curve_tree, pending_write_lock, chain_tip, snapshot, primary) = {
            let g = self_arc.read().await;
            let stake = g.stake_handle().ok_or(DrainRequestError::NotStaker)?;
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_write_lock.clone(),
                g.ledger.synced_height(),
                g.ledger.snapshot(),
                g.primary_address(),
            )
        };
        let block_hash_at = move |h: u64| snapshot.block_hash_at(h);
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);

        // Resolve the principal destination triple with the SAME birational map
        // the transfer path applies to any recipient's view key, so a drain
        // output is bit-for-bit a transfer output (wire-shape parity). The
        // wallet's own view key is always valid; a failure here is a corrupted
        // resident key — fail closed.
        let x25519_pk = ed25519_pk_to_x25519_pk(&primary.view_key).map_err(|_| {
            DrainRequestError::Destination {
                detail: "principal view key does not map to a valid X25519 point",
            }
        })?;
        let dest = DrainDestination {
            spend_pk: primary.spend_key,
            x25519_pk,
            ml_kem_ek: primary.ml_kem_encap_key.clone(),
        };

        // Three independent reads, joined: the persona identity (a pure actor
        // projection — never a caller-supplied id that could disagree with the
        // slot), the sealed P-scan state, and the live gindex reservations
        // (outputs committed to in-flight bond posts, claims, OR drains must not
        // be re-swept — an independent store over the engine-held write lock).
        let (identity, pscan_state, reserved) = tokio::join!(
            stake.persona_identity(p_slot),
            load_pscan_state_for_engine(self_arc.clone()),
            store.read(shekyl_engine_state::PendingPostBlock::reserved_gindexes),
        );
        let identity = identity?;
        let bond_id_bytes = identity
            .bond_id
            .to_canonical_bytes()
            .map_err(DrainRequestError::Identity)?;
        let p_canonical_id = p_canonical_id_from_hybrid_pubkey(&bond_id_bytes);

        // Sealed funding records + this persona's retirement status, borrowed
        // from the loaded seal. No P-scan seal ⇒ no funding to drain (the
        // pipeline refuses loudly downstream) and "not retired" (the safe
        // default: a live persona keeps its exit reserve).
        let pscan_state =
            pscan_state.map_err(|e| DrainRequestError::state("pscan state load", e))?;
        let funding_records: &[PFundingOutputRecord] = pscan_state
            .as_ref()
            .map(PScanState::funding_outputs)
            .unwrap_or(&[]);
        let retired = pscan_state
            .as_ref()
            .is_some_and(|s| s.retired_records().iter().any(|r| r.p_slot == p_slot));
        let reserved = reserved.map_err(|e| DrainRequestError::state("reserved gindexes", e))?;

        // Optimistic fast-fail on a live drain (one live drain per persona —
        // the in-flight input reservation). The AUTHORITATIVE serialization is
        // `push_drain` under the write lock at the seal below, which rejects
        // atomically even if two same-persona requests race past this gate;
        // this read only saves the wasted proof work.
        let already = store
            .read(|block| block.has_live_drain_for(&p_canonical_id))
            .await
            .map_err(|e| DrainRequestError::state("pending-drain read", e))?;
        if already {
            return Err(DrainRequestError::DrainPending);
        }

        let handle = stake.mint_handle(p_slot).await?;

        // Assemble through the production pipeline — the reply comes back
        // unbroadcast (CB-3); routing it is the step below, not the builder's.
        let assembled = orchestrate_drain(
            handle,
            DrainCtx {
                stake: &stake,
                tree: &curve_tree,
                funding_records,
                reserved: &reserved,
                dest,
                payment: payment.to_raw(),
                fee: fee.to_raw(),
                retired,
                chain_tip,
            },
            block_hash_at,
        )
        .await?;

        // Persist-before-dispatch (module docs): seal the drain record — bytes,
        // input reservation — and its Dispatched transition in ONE mutation,
        // before any network send. A crash after this seal resumes as "maybe
        // sent", which is safe because every resend is byte-identical. `at`
        // reads the same named daemon-claimed-tip clock the bond/claim dispatch
        // stamps (WI-3 R2-1).
        let dispatch_tip = daemon_claimed_tip(&daemon)
            .await
            .map_err(|e| DrainRequestError::state("dispatch tip", e))?;
        let persona = *assembled.bound_tx.persona();
        let sealed = PendingDrain {
            p_slot,
            persona,
            tx_bytes: assembled.bound_tx.bytes().to_vec(),
            funding_gindexes: assembled.funding_gindexes.clone(),
            state: PendingPostState::Pending,
        };
        let pushed = store
            .mutate(move |block| {
                let ok = block.push_drain(sealed)
                    && block
                        .mark_drain_dispatched(&persona, dispatch_tip)
                        .is_some();
                (ok, ok)
            })
            .await
            .map_err(|e| DrainRequestError::state("pending-drain seal", e))?;
        if !pushed {
            return Err(DrainRequestError::DrainPending);
        }

        // Dispatch through the pre-bound ① `Local` posture (the audited
        // persona-transport choke point, T-DS-2) — the privacy default:
        // loopback on the operator's own box. The operator's explicit ②
        // posture choice plugs in via the 2c config-source slice, which swaps
        // this call, not this seam. A submit failure leaves the sealed record
        // live — the bytes may have reached the network, and the drain driver's
        // byte-identical resubmit / terminal-reject retire owns its fate.
        let submitter = BroadcastSubmitter::local(persona, Arc::new(daemon));
        let submit = submitter.submit_bound(assembled.bound_tx.clone()).await?;

        Ok(DrainReceipt {
            drain: assembled,
            submit,
        })
    }
}

#[cfg(test)]
mod tests {
    /// The seam's structural pins, `wire.rs`-tripwire style. Two guards keep a
    /// needle from matching anything but a live call site:
    ///
    /// - the trailing test module is dropped (these needles cannot self-match);
    /// - **comment-only lines are stripped** before searching, so a doc-comment
    ///   mention of a forbidden token (`DaemonClient`, `.submit(`) can never
    ///   trip a `!contains` guard — only real code counts.
    ///
    /// 1. assembly enters ONLY through the production pipeline
    ///    (`orchestrate_drain`) — never a direct actor `assemble_drain` ask
    ///    that would skip the orchestrator's anchor/scope/reserve/path stages;
    /// 2. dispatch rides ONLY the audited persona-transport choke point (the
    ///    pre-bound `BroadcastSubmitter::local` construction + `submit_bound`)
    ///    — never a bare submitter and never a default `DaemonClient` (T-DS-2);
    /// 3. persist-before-dispatch: the pending-drain seal (`push_drain`)
    ///    textually precedes the network send.
    #[test]
    fn seam_routes_through_the_pipeline_and_the_submit_choke_point() {
        let production = include_str!("drain_dispatch.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("drain_dispatch.rs has a production section");
        // Code-only view: drop comment-only lines (`//`, `///`, `//!`) so the
        // module docs' references to forbidden tokens cannot satisfy the
        // negative guards below.
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        let pipeline_call = "orchestrate_drain(";
        assert!(
            code.contains(pipeline_call),
            "the seam must assemble only via the production pipeline"
        );
        let direct_ask = ".assemble_drain(";
        assert!(
            !code.contains(direct_ask),
            "the seam must not ask the actor directly (the pipeline owns anchor/reserve/paths)"
        );

        let choke_construct = "BroadcastSubmitter::local(";
        assert!(
            code.contains(choke_construct),
            "submitter construction must stay on the audited choke point"
        );
        let choke_submit = ".submit_bound(";
        assert!(
            code.contains(choke_submit),
            "dispatch must ride submit_bound's persona-pairing check"
        );
        let bare_submit = ".submit(";
        assert!(
            !code.contains(bare_submit),
            "no bare TransactionSubmitter::submit around the persona-pairing check (T-DS-2)"
        );
        // T-DS-2: the drain must not reach for a raw daemon client to broadcast.
        let raw_client = "DaemonClient";
        assert!(
            !code.contains(raw_client),
            "the drain submit must route through the persona transport, never a default DaemonClient"
        );

        // Persist-before-dispatch ordering pin.
        let seal_call = ".push_drain(";
        let seal_at = code
            .find(seal_call)
            .expect("the seam must seal a pending drain");
        let submit_at = code.find(choke_submit).expect("checked non-empty above");
        assert!(
            seal_at < submit_at,
            "the pending-drain seal must precede the network send"
        );
    }
}
