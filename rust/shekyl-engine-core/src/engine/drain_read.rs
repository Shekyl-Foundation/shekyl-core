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
//! polls to render the drainable balance: it lifts the sealed `P` funding set
//! **scoped to the live active persona** (the same slot scope a real drain's
//! planning applies, so the advertised figure is spendable by the `drain` it
//! sizes), anchors the same send-path reference a real drain uses, and returns
//! the aggregate spendable scalar.
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
use super::pscan::start::{load_pending_posts_for_engine, load_pscan_state_for_engine};
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
/// [`anchored_reference_block`] raises exactly two arms: the genuinely-transient
/// [`BondAssemblyError::ReferenceResyncing`] (→
/// [`DrainBalanceReadError::Unanchorable`], "syncing") and the non-transient
/// [`BondAssemblyError::Build`] (→ [`DrainBalanceReadError::State`]; its
/// `stage`/`detail` are operational text — the anchor never holds a record, so
/// never an amount or a gindex). Any *other* arm is unreachable here today, but
/// several `BondAssemblyError` variants (`InsufficientFunding`,
/// `OutputNotYetDrained`, …) render amounts/gindexes in their `Display` — so the
/// catch-all maps to [`DrainBalanceReadError::State`] with a **static** message
/// rather than the variant's `Display`, upholding the taxonomy's "no amount or
/// gindex crosses the read surface" promise ([`DrainBalanceReadError`])
/// structurally, not by relying on the leaking arms staying unreachable. Pulled
/// out as a named seam so the DS-PR-3 locked "keep the two-way distinction
/// alive" decision is unit-tested directly rather than buried in the accessor.
fn anchor_err_to_read_err(err: BondAssemblyError) -> DrainBalanceReadError {
    match err {
        BondAssemblyError::ReferenceResyncing { detail } => {
            DrainBalanceReadError::Unanchorable { detail }
        }
        BondAssemblyError::Build { stage, detail } => DrainBalanceReadError::State {
            detail: format!("reference anchor build failed at {stage}: {detail}"),
        },
        // Defence in depth: no other arm reaches here from
        // `anchored_reference_block`, and the leaking variants above must never
        // surface their `Display` on the read path — fail closed with a static
        // message so no amount or gindex can cross the surface.
        _ => DrainBalanceReadError::State {
            detail: "reference anchoring failed unexpectedly".to_string(),
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
    /// **Scoped to the live active persona** — the contract's own wording
    /// ("the aggregate drainable scalar across the active persona's pool"):
    /// [`drain_to_principal`](super::drain_facade) spends only the active
    /// persona's slot-scoped records (`drain_orchestrator`'s scoped
    /// projection), so this read measures the same set. A wallet-wide sum
    /// would advertise dormant held personas' funds that an immediate `drain`
    /// cannot move, so an amount at or under the displayed figure could still
    /// refuse as unaffordable. No stake engine, or no active persona, is an
    /// honest `0` — nothing is drainable *right now*, consistent with the
    /// `drain` the figure exists to size — short-circuited before any file or
    /// anchor work.
    ///
    /// Returns the aggregate scalar only — [`drain_balance`] drops every
    /// reward-sequence coordinate (the F-D1 trust boundary), so no
    /// decomposition crosses this surface. "Spendable" is mature ∧
    /// **unreserved**: a funding output a live bond post / claim / drain already
    /// commits (the sealed `reserved_gindexes` union) is not drainable, so it is
    /// netted out — the same "spendable = unreserved mature" definition the bond
    /// sweep uses, and the set a real drain's selection excludes. No seal
    /// (non-staker, or nothing scanned yet) is an honest `0`, never a fabricated
    /// one over a failed read; the pscan load runs before anchoring so a fresh
    /// wallet reports `0 drainable` rather than a spurious "syncing" against an
    /// empty tree.
    ///
    /// # Errors
    ///
    /// - [`DrainBalanceReadError::Unanchorable`] — the reference anchor is not
    ///   yet available (transient; render "syncing").
    /// - [`DrainBalanceReadError::State`] — a non-transient fault (pscan-load,
    ///   persona resolution, anchor build, or aggregation overflow); render an
    ///   error, not a zero.
    pub async fn drain_balance_aggregate(
        self_arc: Arc<RwLock<Self>>,
    ) -> Result<AtomicUnits, DrainBalanceReadError> {
        // Brief read: capture the public anchor operands (curve tree, synced
        // tip, block-hash resolver), exactly the `assemble_bond_post` prelude,
        // plus the stake handle for the active-persona scope. Public material
        // only — the handle projects a public identity, no secret crosses.
        let (curve_tree, chain_tip, block_hash_at, stake) = {
            let g = self_arc.read().await;
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let block_hash_at = move |h: u64| snap.block_hash_at(h);
            (
                g.curve_tree.clone(),
                chain_tip,
                block_hash_at,
                g.stake_handle(),
            )
        };

        // Active-persona scope: no stake engine / idle staker ⇒ an honest
        // zero (the `drain` this figure sizes would refuse -29507/-29508),
        // before any file I/O or anchoring.
        let Some(stake) = stake else {
            return Ok(AtomicUnits::from_raw(0));
        };
        let Some(identity) =
            stake
                .active_persona()
                .await
                .map_err(|e| DrainBalanceReadError::State {
                    detail: e.to_string(),
                })?
        else {
            return Ok(AtomicUnits::from_raw(0));
        };
        let active_slot = identity.p_slot;

        // Sealed funding set. No seal ⇒ non-staker / nothing scanned ⇒ honest
        // zero, short-circuited before anchoring (a fresh wallet has no tree to
        // anchor and no balance to report — a syncing placeholder here would be
        // a lie).
        let Some(pscan_state) = load_pscan_state_for_engine(self_arc.clone())
            .await
            .map_err(|e| DrainBalanceReadError::State {
                detail: e.to_string(),
            })?
        else {
            return Ok(AtomicUnits::from_raw(0));
        };

        // In-flight reservations: a funding output a live bond post / claim /
        // drain already commits (its gindex in the sealed persist-before-dispatch
        // `reserved_gindexes` union) is not drainable. Netting it out keeps this
        // read consistent with the bond sweep's "spendable = unreserved mature"
        // definition and with the drain selection that excludes the same set. No
        // pending seal ⇒ nothing reserved.
        let reserved = load_pending_posts_for_engine(self_arc)
            .await
            .map_err(|e| DrainBalanceReadError::State {
                detail: e.to_string(),
            })?
            .map(|block| block.reserved_gindexes())
            .unwrap_or_default();

        // Anchor the canonical send-path reference (reorg-safe, resync-loud);
        // only the transient arm becomes "syncing".
        let reference = anchored_reference_block(&curve_tree, chain_tip, block_hash_at)
            .await
            .map_err(anchor_err_to_read_err)?;
        let reference_height = BlockHeight::from_raw(reference.height.0);

        scoped_spendable(
            pscan_state.funding_outputs(),
            active_slot,
            reference_height,
            &reserved,
        )
    }
}

/// The active-persona-scoped aggregate: `records` filtered to `active_slot`'s
/// own funding outputs — the same `r.p_slot == slot` predicate
/// `drain_orchestrator`'s scoped projection applies before planning, so the
/// advertised figure and the plannable set are one definition — then summed
/// mature ∧ unreserved by [`drain_balance`]. `p_slot` is a public slot
/// ordinal, not a mint-lineage coordinate, so the filter stays outside the
/// §12.3 carve exactly as the orchestrator's copy does. A free function so
/// the scoping is unit-testable without an anchored curve tree (the accessor
/// above cannot reach this line offline — anchoring precedes it).
fn scoped_spendable(
    records: &[shekyl_engine_state::pscan_state::PFundingOutputRecord],
    active_slot: shekyl_types::PSlot,
    reference_height: BlockHeight,
    reserved: &std::collections::BTreeSet<shekyl_types::GlobalOutputIndex>,
) -> Result<AtomicUnits, DrainBalanceReadError> {
    // Borrowed filter chained into `drain_balance`'s own predicates: no
    // record is cloned (each carries an ML-KEM ciphertext buffer, and this
    // runs at poll frequency), and the mature ∧ unreserved definition stays
    // in `drain_balance` — scoping here, eligibility there, one copy of each.
    let scoped = records.iter().filter(|r| r.p_slot == active_slot);
    let balance = drain_balance(scoped, reference_height, reserved).map_err(|e| {
        DrainBalanceReadError::State {
            detail: e.to_string(),
        }
    })?;
    Ok(balance.spendable)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn unexpected_anchor_error_never_leaks_an_amount_or_gindex() {
        // These arms are unreachable from `anchored_reference_block` today, but
        // if one ever reaches the mapper its `Display` (which renders amounts /
        // gindexes) must NOT surface on the read path — the taxonomy promises no
        // amount or gindex crosses it. Structural firewall, not reachability
        // luck: assert a State arm with a static, value-free detail.
        let mapped = anchor_err_to_read_err(BondAssemblyError::InsufficientFunding {
            available: 4_242_424,
            required: 9_999_999,
        });
        let DrainBalanceReadError::State { detail } = mapped else {
            panic!("an amount-bearing arm must map to State, got {mapped:?}");
        };
        assert!(
            !detail.contains("4242424") && !detail.contains("9999999"),
            "amount leaked onto the read surface: {detail}"
        );

        let mapped =
            anchor_err_to_read_err(BondAssemblyError::OutputNotYetDrained { gindex: 8_675_309 });
        let DrainBalanceReadError::State { detail } = mapped else {
            panic!("a gindex-bearing arm must map to State, got {mapped:?}");
        };
        assert!(
            !detail.contains("8675309"),
            "gindex leaked onto the read surface: {detail}"
        );
    }

    // ---- Active-persona scoping (the pure aggregation) ---------------------

    use crate::engine::test_support::{activate_persona, funding_record, staker_engine};
    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_types::PSlot;

    /// This suite's deterministic-seed multiplier (`test_support::fixed_seed`).
    const SEED_MULT: u8 = 13;

    /// The scoped aggregate sums ONLY the active slot's records — a dormant
    /// held persona's funds must not be advertised as drainable, because the
    /// `drain` this figure sizes cannot spend them (its planning scopes to
    /// the active slot). Bites against the slot filter being dropped, which
    /// would regress the read to the wallet-wide sum this fix retired.
    #[test]
    fn scoped_spendable_sums_only_the_active_slot() {
        let records = [
            funding_record(3, 10, 5, 40_000, MintLineageOutput::EmissionReward),
            funding_record(3, 11, 5, 2_000, MintLineageOutput::EmissionReward),
            // Dormant persona's record: coverable value, wrong slot.
            funding_record(7, 12, 5, 900_000, MintLineageOutput::EmissionReward),
        ];
        let spendable = scoped_spendable(
            &records,
            PSlot::from_raw(3),
            BlockHeight::from_raw(1_000),
            &Default::default(),
        )
        .expect("aggregate");
        assert_eq!(
            spendable,
            AtomicUnits::from_raw(42_000),
            "only the active slot's records may sum"
        );

        // Negative control: with the dormant slot active, its record is the
        // whole answer — the filter selects, it does not merely subtract.
        let other = scoped_spendable(
            &records,
            PSlot::from_raw(7),
            BlockHeight::from_raw(1_000),
            &Default::default(),
        )
        .expect("aggregate");
        assert_eq!(other, AtomicUnits::from_raw(900_000));
    }

    // ---- Honest zeros before any anchor work (real engines, offline) -------

    #[tokio::test(flavor = "multi_thread")]
    async fn aggregate_is_zero_when_no_stake_engine() {
        let (_tmp, engine) = crate::engine::test_support::non_staker_engine(SEED_MULT);
        let arc = Arc::new(RwLock::new(engine));
        let balance = Engine::drain_balance_aggregate(arc)
            .await
            .expect("a non-staker must yield an honest Ok(0), not a syncing/state error");
        assert_eq!(
            balance,
            AtomicUnits::from_raw(0),
            "a non-staker wallet drains nothing"
        );
    }

    /// A staker with no active persona is an honest zero — nothing is
    /// drainable *right now* (`drain` itself refuses `NoActivePersona`) —
    /// short-circuited before the seal load and anchoring, which is what
    /// makes this test runnable offline.
    #[tokio::test(flavor = "multi_thread")]
    async fn aggregate_is_zero_when_no_active_persona() {
        let (_tmp, engine) = staker_engine(3, SEED_MULT);
        let arc = Arc::new(RwLock::new(engine));
        let balance = Engine::drain_balance_aggregate(arc)
            .await
            .expect("an idle staker must yield an honest Ok(0)");
        assert_eq!(balance, AtomicUnits::from_raw(0));
    }

    /// With an active persona AND a sealed funding set, the read proceeds
    /// past both scope gates to the anchor step — offline that is the
    /// transient `Unanchorable` ("syncing"), never a fabricated zero. Proves
    /// the persona gate does not false-refuse a real staker and that the
    /// sealed set loads before anchoring.
    #[tokio::test(flavor = "multi_thread")]
    async fn active_persona_with_sealed_funding_reaches_the_anchor() {
        use shekyl_engine_state::pscan_cursor::PScanCursor;
        use shekyl_engine_state::pscan_state::PScanState;

        let (_tmp, engine) = staker_engine(3, SEED_MULT);
        activate_persona(&engine, 3).await;

        // Seal a funding set through the engine's own persistence handle.
        let state = PScanState::new(
            PScanCursor::genesis(),
            Default::default(),
            Default::default(),
            Vec::new(),
            vec![funding_record(
                3,
                10,
                5,
                40_000,
                MintLineageOutput::EmissionReward,
            )],
            Vec::new(),
            Default::default(),
        );
        let bytes = state.to_postcard_bytes().expect("encode pscan state");
        engine
            .persistence()
            .save_pscan_state(engine.state_wrap_key().as_bytes(), &bytes)
            .expect("seal funding set");

        let arc = Arc::new(RwLock::new(engine));
        let err = Engine::drain_balance_aggregate(arc)
            .await
            .expect_err("a fresh tree cannot anchor — the read must say syncing, not 0");
        assert!(
            matches!(err, DrainBalanceReadError::Unanchorable { .. }),
            "got {err:?}"
        );
    }
}
