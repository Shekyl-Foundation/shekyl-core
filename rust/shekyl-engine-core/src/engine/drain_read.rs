// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D2 aggregate drain-balance read — the "how much is drainable?" surface
//! (`ARCHIVAL_DRAIN_SEND_FD2.md`).
//!
//! The drain path's balance surface is a single aggregate scalar
//! (`DrainBalance`, from `drain_orchestrator`) — never a per-epoch / per-reward
//! decomposition (the F-D1 trust boundary; `drain_orchestrator` §"F-D2"). This
//! module is the engine-side accessor a UI (the eventual DS-PR-3 GUI slice)
//! polls to render the drainable balance: it lifts the sealed `P` funding set,
//! anchors the same send-path reference a real drain uses, and returns the
//! aggregate spendable scalar.
//!
//! ## Anchor parity
//!
//! The read anchors through [`anchored_reference_block`] — the canonical
//! send-path derivation (`min(tip, ingested) − REF_ANCHOR_AGE`, reorg-safe,
//! resync-loud) the bond path already uses (`bond_orchestrator`'s
//! `assemble_bond_post` / `sweep_bond_funding`). So the "drainable" figure the
//! UI shows is the balance measured at the very block a spend would be proven
//! against, not a raw-tip figure that includes outputs no membership path can
//! yet cover. Today that parity holds against the bond path; when DS-PR-2's
//! `orchestrate_drain` lands it anchors through the *same* helper, so the read
//! shares the drain's anchor by construction.
//!
//! ## Composition
//!
//! The brief-read prelude (capture the public anchor operands under a short
//! lock, then drive the async steps off the arc) and the self-arc receiver
//! mirror the dev-present bond/refresh entries — `assemble_bond_post`
//! (`bond_orchestrator`) for the anchor + pscan-load prelude, and
//! `start_refresh` (`refresh`) for the `Arc<RwLock<Self>>` handle shape.
//! [`load_pscan_state_for_engine`] takes the arc (not `&self`) to run its own
//! brief lock, so the accessor cannot be a `&self` method.

use std::sync::Arc;

use tokio::sync::RwLock;

use shekyl_engine_file::WalletFile;
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;

use super::bond_assembly::BondAssemblyError;
use super::bond_orchestrator::anchored_reference_block;
use super::drain_orchestrator::drain_balance;
use super::pscan::start::load_pscan_state_for_engine;
use super::signer::EngineSignerKind;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Why the aggregate `P`-balance read could not produce a scalar.
///
/// Two-armed by design (rule 82; DS-PR-3 locked decision). The caller — and
/// through it the wallet UI — must distinguish a *transient, self-resolving*
/// "still syncing" condition from a *non-transient* state fault: the two demand
/// different user-facing renders (a "syncing" placeholder vs. an error), and
/// collapsing them into one string would re-hide exactly the distinction the
/// syncing-state decision drew. Neither arm carries a scalar amount or a
/// gindex — a balance-read failure discloses nothing about the (possibly empty)
/// spend set.
#[derive(Debug, thiserror::Error)]
pub enum DrainBalanceReadError {
    /// The send-path reference anchor is not yet available: the curve tree has
    /// not ingested far enough to derive a submittable reference height (fresh
    /// tree, ingest lagging tip, chain shorter than the anchor age). Transient
    /// — it clears on its own as ingest catches up; the UI renders a "syncing"
    /// placeholder, never a zero balance. Maps 1:1 from the single genuinely
    /// transient anchor arm (`BondAssemblyError::ReferenceResyncing`) — a plain
    /// code span, not an intra-doc link, since `BondAssemblyError` is `pub(crate)`
    /// and cannot be a public-doc link target.
    #[error("drain balance unavailable while the wallet syncs: {detail}")]
    Unanchorable {
        /// Operator-facing detail naming which anchoring precondition is not
        /// yet met. Static text — no amount, no gindex.
        detail: &'static str,
    },
    /// A non-transient read fault: the sealed P-scan state failed to load, an
    /// anchor build step failed (curve-tree ingested-tip read, reference root),
    /// or the aggregate sum overflowed (structurally unreachable under the
    /// supply cap; a corrupt state otherwise). Fail-closed — never a fabricated
    /// zero over a bad read, so the UI surfaces a fault rather than a misleading
    /// "0 drainable".
    #[error("drain balance read failed: {detail}")]
    State {
        /// Rendered cause (public error text — never key material or a raw
        /// record field).
        detail: String,
    },
}

/// Map an [`anchored_reference_block`] failure onto the read surface's
/// two-armed taxonomy.
///
/// Only the genuinely-transient [`BondAssemblyError::ReferenceResyncing`] arm
/// becomes [`DrainBalanceReadError::Unanchorable`] ("syncing"); every other arm
/// — today only [`BondAssemblyError::Build`], and defensively any arm added
/// later — is a non-transient [`DrainBalanceReadError::State`]. Pulled out as a
/// named seam so the DS-PR-3 locked "keep the two-way distinction alive"
/// decision is unit-tested directly rather than buried in the accessor body.
fn anchor_err_to_read_err(err: BondAssemblyError) -> DrainBalanceReadError {
    match err {
        BondAssemblyError::ReferenceResyncing { detail } => {
            DrainBalanceReadError::Unanchorable { detail }
        }
        other => DrainBalanceReadError::State {
            detail: other.to_string(),
        },
    }
}

#[allow(private_bounds)] // same Engine-trait privacy posture as start_refresh / assemble_bond_post
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
    /// F-D2 aggregate drain-balance read: the total spendable `P` scalar the
    /// wallet may drain, measured at the same send-path reference a real drain
    /// anchors to.
    ///
    /// Returns the aggregate scalar only — [`drain_balance`] drops every
    /// reward-sequence coordinate (the F-D1 trust boundary), so no
    /// decomposition crosses this surface. No seal (non-staker, or nothing
    /// scanned yet) is an honest `0`, never a fabricated one over a failed read;
    /// the pscan load runs first so a fresh wallet reports `0 drainable` rather
    /// than a spurious "syncing" against an empty tree.
    ///
    /// # Errors
    ///
    /// - [`DrainBalanceReadError::Unanchorable`] — the reference anchor is not
    ///   yet available (transient; render "syncing").
    /// - [`DrainBalanceReadError::State`] — a non-transient fault (pscan-load,
    ///   anchor build, or aggregation overflow); render an error, not a zero.
    pub async fn drain_balance_aggregate(
        self_arc: Arc<RwLock<Self>>,
    ) -> Result<AtomicUnits, DrainBalanceReadError> {
        // Brief read: capture the public anchor operands (curve tree, synced
        // tip, block-hash resolver), exactly the `assemble_bond_post` prelude.
        // A balance read touches public material only — no actor handles, no
        // secrets.
        let (curve_tree, chain_tip, block_hash_at) = {
            let g = self_arc.read().await;
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let block_hash_at = move |h: u64| snap.block_hash_at(h);
            (g.curve_tree.clone(), chain_tip, block_hash_at)
        };

        // Sealed funding set. No seal ⇒ non-staker / nothing scanned ⇒ honest
        // zero, short-circuited before anchoring (a fresh wallet has no tree to
        // anchor and no balance to report — a syncing placeholder here would be
        // a lie).
        let Some(pscan_state) = load_pscan_state_for_engine(self_arc).await.map_err(|e| {
            DrainBalanceReadError::State {
                detail: e.to_string(),
            }
        })?
        else {
            return Ok(AtomicUnits::from_raw(0));
        };

        // Anchor the canonical send-path reference (reorg-safe, resync-loud);
        // only the transient arm becomes "syncing".
        let reference = anchored_reference_block(&curve_tree, chain_tip, block_hash_at)
            .await
            .map_err(anchor_err_to_read_err)?;
        let reference_height = BlockHeight::from_raw(reference.height.0);

        // Aggregate spendable scalar at the reference — lineage-blind by
        // construction.
        let balance =
            drain_balance(pscan_state.funding_outputs(), reference_height).map_err(|e| {
                DrainBalanceReadError::State {
                    detail: e.to_string(),
                }
            })?;
        Ok(balance.spendable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_rpc_transport::SimpleRequestRpc;
    use tempfile::TempDir;

    use crate::engine::lifecycle::EngineCreateParams;
    use crate::engine::{Credentials, DaemonClient, SoloSigner};

    // ---- error-taxonomy mapping (Fix 2 / DS-PR-3 locked decision) ----------

    #[test]
    fn resyncing_anchor_error_maps_to_unanchorable() {
        let mapped = anchor_err_to_read_err(BondAssemblyError::ReferenceResyncing {
            detail: "curve tree has not ingested any block yet",
        });
        match mapped {
            DrainBalanceReadError::Unanchorable { detail } => {
                assert_eq!(detail, "curve tree has not ingested any block yet");
            }
            other => panic!("ReferenceResyncing must map to Unanchorable, got {other:?}"),
        }
    }

    #[test]
    fn build_anchor_error_maps_to_state() {
        // A non-transient anchor build failure (curve-tree read, reference
        // root) must NOT be rendered as "syncing".
        let mapped = anchor_err_to_read_err(BondAssemblyError::build(
            "curve-tree ingested tip",
            "backend unavailable",
        ));
        assert!(
            matches!(mapped, DrainBalanceReadError::State { .. }),
            "Build must map to State, got {mapped:?}"
        );
    }

    // ---- Ok(0) on no seal (real engine, no pscan) --------------------------

    /// Build a fresh `Engine<SoloSigner>` on a tempdir, wrapped in the
    /// `Arc<RwLock<…>>` the accessor takes. A freshly-created wallet has no
    /// pscan seal, so `load_pscan_state_for_engine` returns `None`. The daemon
    /// points at an unreachable URL but is never contacted on this path (the
    /// `None` short-circuit fires before anchoring).
    async fn fresh_engine_arc() -> (Arc<RwLock<Engine<SoloSigner>>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"drain-balance-read tests");
        let mut seed = [0u8; MASTER_SEED_BYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(13);
        }
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let rpc = SimpleRequestRpc::new("http://127.0.0.1:1".to_string())
            .await
            .expect("construct SimpleRequestRpc against unreachable URL (no connect attempt yet)");
        let daemon = DaemonClient::new(rpc);
        let wallet = Engine::<SoloSigner>::create(params, daemon)
            .expect("create FULL wallet for drain-balance-read tests");
        (Arc::new(RwLock::new(wallet)), tmp)
    }

    #[tokio::test]
    async fn aggregate_is_zero_when_no_pscan_seal() {
        let (arc, _tmp) = fresh_engine_arc().await;
        let balance = Engine::drain_balance_aggregate(arc)
            .await
            .expect("no seal must yield an honest Ok(0), not a syncing/state error");
        assert_eq!(
            balance,
            AtomicUnits::from_raw(0),
            "a non-staker wallet drains nothing"
        );
    }
}
