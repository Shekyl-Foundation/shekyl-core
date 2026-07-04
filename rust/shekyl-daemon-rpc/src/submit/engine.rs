// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The submit engine — Phase A→B→C→D control flow and the **verdict
//! classifier** (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.1).
//!
//! Generic over the [`SubmitStateShim`] (state seam) and [`TxVerifier`]
//! (crypto seam), so the full control flow — including every race
//! classification — is testable with deterministic mocks (§10 item 2)
//! before the FFI shims exist.

use shekyl_rpc_types::{RejectCause, SubmitVerdict};

use crate::submit::certificate::VerificationCertificate;
use crate::submit::consensus::{FCMP_REFERENCE_BLOCK_MAX_AGE, FCMP_REFERENCE_BLOCK_MIN_AGE};
use crate::submit::facts::{CommitOutcome, KeyImageConflict, SubmitFacts, SubmitStateShim, TxMeta};
use crate::submit::fee::fee_meets_floor;
use crate::submit::phase_a::{parse_submission, ParsedSubmission, SubmitTxKind};
use crate::submit::verify::TxVerifier;

/// An internal fault — **never a verdict** (§3.4 / §4.2). The transport
/// layer surfaces it as a transport-level error (the client's `Err` arm),
/// so a daemon defect is not converted into a wallet rebuild.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineFault {
    /// The snapshot shim reported an internal failure (DB exception,
    /// marshalling fault, fee-parameter derivation failure) — §3.4's
    /// loud-failure gate on the Phase-B side.
    #[error("submit snapshot internal fault (see daemon log)")]
    SnapshotFault,
    /// The commit shim reported an internal inconsistency (release-mode
    /// txid divergence, marshalling fault) — §3.4's loud-failure gate.
    #[error("submit commit internal fault (see daemon log)")]
    CommitFault,
    /// A seam returned facts that violate its contract (e.g. `Raced` with
    /// no changed premise). Loud by design: a contract violation is a
    /// daemon defect, and classifying it as a verdict would teach the
    /// wallet to act on garbage.
    #[error("submit state shim contract violation: {0}")]
    ShimContract(&'static str),
}

/// The trust tier of the transport endpoint a submission arrived on — the
/// disclosure boundary for Dandelion++ embargo state (§3.1 identity-category
/// pin).
///
/// The `all`-category presence fact ([`SubmitFacts::in_pool`]) exists for the
/// daemon's own admission engine (duplicate-safety + the F31 owner
/// status-query-by-resubmit). It must **not** be disclosed to a foreign
/// caller: a stem relay holds the tx bytes, and a fast `AlreadyInPool` vs a
/// full-verify `Accepted` on the public `POST /submit_transaction` would map
/// the Dandelion++ stem path back toward the origin daemon. `Foreign`
/// therefore sees only broadcast-visible ([`SubmitFacts::in_pool_broadcast`])
/// presence — exactly what the legacy `relay_category::legacy` identity check
/// disclosed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitCaller {
    /// Unrestricted/local endpoint — the daemon's own wallet. Sees the
    /// daemon's own embargoed (`local`/stem) insertions, so the F31
    /// resubmit-as-status query returns `AlreadyInPool` during the embargo.
    Owner,
    /// Restricted/public endpoint — a foreign caller. Embargo state is
    /// concealed; only broadcast-visible presence is disclosed.
    Foreign,
}

/// What a caller of the given tier may learn about the submitted txid's pool
/// presence (§3.1 identity-category pin; the stem-presence-oracle boundary).
enum PoolDisclosure {
    /// Not pool-resident (at the `all` category) — proceed with admission.
    Absent,
    /// Presence may be disclosed as `AlreadyInPool`: the owner, or a
    /// broadcast-visible tx that has already fluffed and carries no embargo
    /// secret.
    Reveal,
    /// Pool-resident but only in a non-broadcast (embargoed) state, and the
    /// caller is foreign: presence must stay indistinguishable from a fresh
    /// submission. Run the full battery and report `Accepted` — the tx *is*
    /// in the pool and will be relayed, so this is honest as well as
    /// non-disclosing (the legacy existing-tx arm's `OK + not_relayed`).
    Conceal,
}

/// The disclosure decision, shared by the Phase-B early return and the
/// Phase-D race classifier so the two cannot drift.
fn disclose_pool_presence(facts: &SubmitFacts, caller: SubmitCaller) -> PoolDisclosure {
    if !facts.in_pool {
        return PoolDisclosure::Absent;
    }
    match caller {
        SubmitCaller::Owner => PoolDisclosure::Reveal,
        SubmitCaller::Foreign if facts.in_pool_broadcast => PoolDisclosure::Reveal,
        SubmitCaller::Foreign => PoolDisclosure::Conceal,
    }
}

/// Where a reference height sits relative to the FCMP age window — the exact
/// consensus comparison shape (blockchain.cpp `check_tx_inputs`), single-
/// sourced so Phase C and the Phase-D race classifier cannot diverge on an
/// off-by-one or a Decision-14 constant change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefAgeWindow {
    InWindow,
    /// Younger than `FCMP_REFERENCE_BLOCK_MIN_AGE` (→ `ReferenceTooRecent`).
    TooRecent,
    /// Older than `FCMP_REFERENCE_BLOCK_MAX_AGE` (→ `StaleRoot`).
    TooOld,
}

/// `chain_height` is a block count; both bounds mirror the consensus check
/// (blockchain.cpp:3745-3765 / 3658-3671).
fn ref_age_window(chain_height: u64, ref_height: u64) -> RefAgeWindow {
    if chain_height < FCMP_REFERENCE_BLOCK_MIN_AGE
        || ref_height > chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE
    {
        return RefAgeWindow::TooRecent;
    }
    if chain_height > FCMP_REFERENCE_BLOCK_MAX_AGE
        && ref_height < chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE
    {
        return RefAgeWindow::TooOld;
    }
    RefAgeWindow::InWindow
}

/// The Rust admission engine (§3). One instance per daemon; `submit` is
/// synchronous.
///
/// The F39 verification cap is **not** held here. It is a process-global
/// async semaphore acquired at the transport dispatch layer
/// ([`crate::submit::phase_c_semaphore`]) *before* this synchronous `submit`
/// is `spawn_blocking`'d — see [`crate::submit::gate`] for why the bound had
/// to move out of the synchronous engine. A direct caller (the race-suite
/// mock, a future native mempool) is therefore unbounded by construction;
/// production bounds it at the handler.
#[derive(Debug)]
pub struct SubmitEngine<S, V> {
    shim: S,
    verifier: V,
}

impl<S: SubmitStateShim, V: TxVerifier> SubmitEngine<S, V> {
    /// Engine over a state shim and a verifier.
    pub fn new(shim: S, verifier: V) -> Self {
        Self { shim, verifier }
    }

    /// Submit one transaction (hex blob) through the §3.1 phase pipeline.
    ///
    /// `Ok(verdict)` is the atomic wire verdict; `Err(EngineFault)` is the
    /// transport-level internal-fault arm (HTTP 5xx at the RPC layer, the
    /// client's `Err`), never a verdict.
    pub fn submit(&self, tx_hex: &str, caller: SubmitCaller) -> Result<SubmitVerdict, EngineFault> {
        // ── Phase A: Rust-native admission, no FFI (§3.1) ──────────────
        let parsed = match parse_submission(tx_hex) {
            Ok(parsed) => parsed,
            Err(reject) => {
                tracing::debug!(reason = %reject.reason, "submit rejected at Phase A");
                return Ok(reject.verdict());
            }
        };

        // ── Phase B: POD fact snapshot (shim 1, one short lock) ────────
        let facts = self
            .shim
            .snapshot_facts(&parsed.txid, &parsed.key_images, &parsed.reference_block)
            .map_err(|_| EngineFault::SnapshotFault)?;

        // Early return on identity only. In-chain outranks in-pool (a
        // just-mined tx can transiently be both; "settled" is the more
        // useful truth). A snapshot key-image hit is a re-check input,
        // never a verdict — emitting DoubleSpendConflict here would
        // resurrect defect 0.4's self-duplicate race.
        if facts.in_chain {
            return Ok(SubmitVerdict::AlreadyInChain);
        }
        // Pool identity discloses only what the caller's tier permits. A
        // `Conceal` (foreign caller, embargoed presence) deliberately does
        // *not* early-return: an instant `AlreadyInPool` vs a full-verify
        // `Accepted` would make the public endpoint a stem-presence oracle.
        // We fall through to the full battery; the Phase-D commit detects the
        // duplicate (raced on `in_pool`) and `classify_race` conceals it as
        // `Accepted`, indistinguishable from a fresh accept.
        if matches!(
            disclose_pool_presence(&facts, caller),
            PoolDisclosure::Reveal
        ) {
            return Ok(SubmitVerdict::AlreadyInPool);
        }

        // ── Phase C: policy arithmetic + verification (no locks) ───────
        // The F39 concurrency cap is enforced at the transport dispatch
        // layer — the process-global async semaphore acquired before this
        // synchronous submit is `spawn_blocking`'d — not here (see
        // `crate::submit::gate`).
        let cert = match self.phase_c(&parsed, &facts)? {
            Ok(cert) => cert,
            Err(cause) => return Ok(SubmitVerdict::Rejected { cause }),
        };

        // ── Phase D: check-and-commit (shim 2, one short lock) ─────────
        let meta = TxMeta {
            weight: parsed.weight,
            fee: parsed.fee,
        };
        match self
            .shim
            .commit(&parsed.blob, &parsed.txid, &meta, &cert, &facts)
        {
            CommitOutcome::Committed => {
                // Post-commit relay nudge (shim 3, §4.3): latency only —
                // the D++ embargo + periodic loop are the guarantee.
                self.shim.relay(&parsed.txid);
                Ok(SubmitVerdict::Accepted)
            }
            CommitOutcome::PrunedOnInsert => {
                // F23 / defect 0.7: admitted then evicted by the insert
                // tail's prune() under pool pressure.
                Ok(SubmitVerdict::Rejected {
                    cause: RejectCause::FeeTooLow,
                })
            }
            CommitOutcome::Raced(fresh) => self.classify_race(&parsed, &cert, &fresh, caller),
            CommitOutcome::InternalFault => Err(EngineFault::CommitFault),
        }
    }

    /// Phase C proper: deterministic policy arithmetic, then the crypto
    /// battery behind the [`TxVerifier`] seam. `Ok(Ok(cert))` is success;
    /// `Ok(Err(cause))` is a rejection verdict; `Err(fault)` is internal.
    #[allow(clippy::type_complexity)]
    fn phase_c(
        &self,
        parsed: &ParsedSubmission,
        facts: &SubmitFacts,
    ) -> Result<Result<VerificationCertificate, RejectCause>, EngineFault> {
        // Weight rule (rows I3/N3): the limit is a compile-time constant
        // on Shekyl (marshalled through the snapshot for one source of
        // truth), so this needs no Phase-D re-check. Over-weight is
        // deterministic for the bytes → Malformed.
        if parsed.weight > facts.weight_limit {
            tracing::debug!(
                weight = parsed.weight,
                limit = facts.weight_limit,
                "submit rejected: weight over limit"
            );
            return Ok(Err(RejectCause::Malformed));
        }

        // Reference checks — spending shapes only: the C++ oracle never
        // consults referenceBlock for a serve-credit-only tx
        // (blockchain.cpp:3565-3609), and neither does the engine.
        let reference = match parsed.kind {
            SubmitTxKind::Spend | SubmitTxKind::BondPost => {
                let Some(reference) = facts.reference else {
                    // Defect 0.6's named verdict: unknown-by-hash at
                    // snapshot time is a sync-gated retry, not a flagless
                    // failure.
                    return Ok(Err(RejectCause::ReferenceNotFound));
                };
                // Age-window arithmetic over the snapshot height.
                match ref_age_window(facts.chain_height.to_raw(), reference.height.to_raw()) {
                    RefAgeWindow::TooRecent => return Ok(Err(RejectCause::ReferenceTooRecent)),
                    RefAgeWindow::TooOld => return Ok(Err(RejectCause::StaleRoot)),
                    RefAgeWindow::InWindow => {}
                }
                // Tree-depth range (row K10): cheap arithmetic the engine
                // owns; the crypto seam re-consumes the depth for the
                // proof itself.
                let tx_depth = match &parsed.tx.ct {
                    shekyl_wire::transaction::Ct::Fcmp {
                        prunable: Some(prunable),
                        ..
                    } => prunable.tree_depth,
                    _ => 0,
                };
                if tx_depth == 0 || tx_depth > u64::from(reference.tree_depth) {
                    return Ok(Err(RejectCause::StaleRoot));
                }
                Some(reference)
            }
            SubmitTxKind::ServeCreditOnly => None,
        };

        // Fee floor against the snapshot params (row P2; re-gated at D
        // against fresh params, F34). Serve-credit txs carry fee 0 by
        // consensus and the floor is never 0, so the non-spending arm
        // terminates here today — the SP-T4a contradiction, recorded in
        // FOLLOWUPS, reproduced for parity rather than resolved.
        if !fee_meets_floor(
            parsed.weight,
            parsed.fee,
            facts.fee_per_byte,
            facts.fee_quantization_mask,
        ) {
            return Ok(Err(RejectCause::FeeTooLow));
        }

        // The crypto battery (FCMP++ membership, BP+, CT balance, PQC
        // hybrid auth, archival-arm checks) behind the seam.
        if let Err(failure) = self.verifier.verify(parsed, facts) {
            return Ok(Err(failure.into()));
        }

        // Mint the witness (§3.3) — the only construction site in the
        // crate, so "grep certificate construction = grep Phase C
        // completion" holds.
        match reference {
            Some(reference) => Ok(Ok(VerificationCertificate::new(
                parsed.txid,
                parsed.reference_block,
                reference.height,
                reference.root,
            ))),
            None => {
                // Unreachable while the fee floor is nonzero (fee 0 <
                // floor rejects above). Reaching here means the shim
                // supplied fee_per_byte == 0 — a contract violation —
                // and minting a root-anchored certificate without a
                // verified root would forge the §3.3 witness meaning.
                // Loud failure per the user-absent-context inversion.
                Err(EngineFault::ShimContract(
                    "serve-credit submission cleared the fee floor (fee_per_byte == 0?); \
                     no root-anchored certificate can attest a non-spending arm (SP-T4a)",
                ))
            }
        }
    }

    /// The Phase-D race classifier: fresh facts in, **most-terminal-first**
    /// verdict out (§3.1). The C++ never chooses a verdict; this function
    /// is the single point where a raced commit becomes one.
    fn classify_race(
        &self,
        parsed: &ParsedSubmission,
        cert: &VerificationCertificate,
        fresh: &SubmitFacts,
        caller: SubmitCaller,
    ) -> Result<SubmitVerdict, EngineFault> {
        // 1. Settled identity outranks everything: a reorg plus a
        //    competing spend must still report the settled fact.
        if fresh.in_chain {
            return Ok(SubmitVerdict::AlreadyInChain);
        }
        // 2. Pool identity (the defect-0.4 self-duplicate race: a
        //    concurrent submit of the same bytes won the commit).
        //    Cannot co-occur with a foreign key-image conflict — a
        //    pool-resident tx's own images map to its own txid. Disclosure
        //    is tier-gated exactly as at Phase B: a foreign caller who won a
        //    race against an embargoed tx is told `Accepted` (concealed),
        //    never `AlreadyInPool`, so the race outcome is not an oracle.
        match disclose_pool_presence(fresh, caller) {
            PoolDisclosure::Reveal => return Ok(SubmitVerdict::AlreadyInPool),
            PoolDisclosure::Conceal => return Ok(SubmitVerdict::Accepted),
            PoolDisclosure::Absent => {}
        }
        // 3. Terminal conflict: a *different* transaction consumed one of
        //    our inputs while we verified.
        if fresh.key_image_conflicts.contains(&KeyImageConflict::Other) {
            return Ok(SubmitVerdict::Rejected {
                cause: RejectCause::DoubleSpendConflict,
            });
        }
        // 4. Reference/root drift (reorg, pop, root-table motion): the
        //    certificate's anchoring premise no longer holds → rebuild
        //    against a fresh root. Every drift shape — hash vanished,
        //    height moved, root mismatch, age window failed on the fresh
        //    height — classifies StaleRoot (retryable: rebuild).
        if matches!(parsed.kind, SubmitTxKind::Spend | SubmitTxKind::BondPost) {
            let drifted = match fresh.reference {
                None => true,
                Some(reference) => {
                    reference.height != cert.ref_height()
                        || reference.root != *cert.root()
                        || ref_age_window(fresh.chain_height.to_raw(), reference.height.to_raw())
                            != RefAgeWindow::InWindow
                }
            };
            if drifted {
                return Ok(SubmitVerdict::Rejected {
                    cause: RejectCause::StaleRoot,
                });
            }
        }
        // 5. Dynamic fee floor moved (F34): re-run the same arithmetic
        //    over the fresh params.
        if !fee_meets_floor(
            parsed.weight,
            parsed.fee,
            fresh.fee_per_byte,
            fresh.fee_quantization_mask,
        ) {
            return Ok(SubmitVerdict::Rejected {
                cause: RejectCause::FeeTooLow,
            });
        }
        // A `Raced` with no re-classifiable premise is a shim contract
        // violation — loud, never a guessed verdict.
        Err(EngineFault::ShimContract(
            "commit reported Raced but no re-checked premise classifies",
        ))
    }
}
