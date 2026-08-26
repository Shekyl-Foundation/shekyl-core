// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `StakeEngine` actor core: held personas, spawn, and inherent methods.
//!
//! Message handlers live in sibling modules and reach actor state through
//! `pub(crate)` fields (transfer-style; secrets stay inside this tree — rule 36).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, PanicError};

use rand_core::RngCore as _;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
#[cfg(feature = "conformance")]
use shekyl_standoff::draw::GapRng;
#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, TimelineEvent};
use shekyl_types::PCanonicalId;

use crate::engine::pscan::persona_scanner::guaranteed_scanner_for_persona;
use crate::engine::pscan::scan_step::{FundingOutputMatch, KeyImageWatchSet};
use crate::engine::stake_timing::{OsRngGapAdapter, DEFAULT_ENTRY_GAP};
use crate::engine::{Network, ShekylAddress};

use super::helpers::{derive_funding_key_image, draw_entry_gap_guarded};
use super::types::*;

/// The `kameo` actor owning the held archival personas (the derive-forward
/// set), **not** the master seed.
///
/// The single-threaded message loop serializes access to `held`/`active`, so a
/// activation (install-new-active, then wipe-retired-iff-ephemeral) is atomic with
/// respect to other messages.
pub(crate) struct StakeEngine {
    /// The held derive-forward set, keyed by slot and tagged bonded/ephemeral.
    /// Activation wipes only the ephemeral retired slot; bonded personas stay
    /// resident so unbonding remains reachable.
    pub(crate) held: BTreeMap<PSlot, HeldPersona>,
    /// The currently-active slot, or `None` when idle. Always a key of `held`
    /// when `Some`.
    pub(crate) active: Option<PSlot>,
    /// Activation generation. Advances on every activation that changes `active`,
    /// invalidating every [`PersonaHandle`] minted before it — the mechanism
    /// behind operation-scoped handles (typed contract #2).
    pub(crate) generation: u64,
    /// SP-R0 arm #1 (DQ-A): the key-image watch cache — key images of `P`'s
    /// held, unspent funding outputs, derived in-actor from the vault.
    /// Refreshed per scan-step from the task's authoritative held list
    /// (derive-on-add / drop-on-prune); **never persisted** — re-derived at
    /// open from the sealed records. Containment is the type's
    /// (redacting `Debug`, no `Serialize`).
    pub(crate) watch_cache: KeyImageWatchSet,
    /// Held records whose watch key-image derivation failed (public prune
    /// keys only). Derivation is deterministic, so re-trying every step would
    /// re-fail identically — and failing the step would wedge the whole scan
    /// pipeline on one bad record. Instead the record is skipped (loudly, see
    /// `absorb_watch_derivation`) until it leaves the held set; sound for the
    /// pruning attestation because the sweep's own derivation of the same
    /// bundle fails the same way, so a quarantined record can never be swept
    /// into a bond post. **Never persisted**; cleared per-record when the
    /// task's held list drops the record.
    pub(crate) watch_quarantine: BTreeSet<shekyl_types::GlobalOutputIndex>,
    /// GF-7 measurement-hook observer (injected via [`StakeEngineArgs`];
    /// see the field docs there). Feature-gated out of default builds.
    #[cfg(feature = "gf7-hooks")]
    pub(crate) observer: Box<dyn BroadcastTimelineObserver>,
}

impl StakeEngine {
    /// Validate a presented handle: it must be from the current generation and
    /// name a still-held slot. A generation mismatch means an activation occurred
    /// since the handle was minted (operation-scoped contract), so it is stale.
    pub(crate) fn validate_handle(&self, handle: &PersonaHandle) -> Result<(), StakeEngineError> {
        if handle.generation != self.generation {
            return Err(StakeEngineError::StaleHandle);
        }
        // A current-generation handle proves the slot was held at mint, and no wipe has
        // happened since (a wipe advances the generation), so this branch is unreachable by
        // construction. If it *does* fire with a matching generation, a wipe failed to
        // advance the generation — a real invariant bug, NOT an ordinary stale handle.
        // Make it loud in dev rather than silently collapse it into `StaleHandle` (which
        // would mask the distinct failure); still fail closed in release, where
        // `StaleHandle` is the safe response either way.
        if !self.held.contains_key(&handle.p_slot) {
            debug_assert!(
                false,
                "validate_handle: a current-generation handle names an unheld slot \
                 (p_slot={:?}, handle.generation={}, engine.generation={}) — a wipe did not \
                 advance the generation (invariant violation, not a stale handle). The two \
                 generations are equal here by the check above; if they differ, that is the bug.",
                handle.p_slot, handle.generation, self.generation
            );
            return Err(StakeEngineError::StaleHandle);
        }
        Ok(())
    }

    /// Steps 1–5 shared verbatim by the [`PlanBondPost`] and [`AssembleBond`]
    /// handlers: validate the handle, cross-check it against the ticket's slot,
    /// preflight the OS entropy source, draw the guarded entry gap, plan the
    /// entry seam, and emit the GF-7 hooks. Returns the validated handle slot and
    /// the placement plan.
    ///
    /// This is the **single definition** of a security-relevant sequence — the
    /// RNG source preflight, the double-jitter degeneracy guard, the
    /// timing-decorrelation plan, and the observer emission. Both bond handlers
    /// must run it identically; keeping it in one place means a future change to
    /// the draw/guard discipline (a stronger degeneracy check, a new observer
    /// event) lands once rather than silently diverging between two copies and
    /// weakening the timing firewall in the un-updated path with no compile error.
    pub(crate) fn validate_and_draw_bond_offset(
        &mut self,
        handle: &PersonaHandle,
        ticket_slot: PSlot,
    ) -> Result<(PSlot, u64), StakeEngineError> {
        // 1. Validate the handle: generation currency + slot membership.
        self.validate_handle(handle)?;

        // 2. Slot cross-check: tickets witness a specific slot; a ticket cannot
        //    authorize signing for any other slot (even a held one).
        let handle_slot = handle.p_slot;
        if handle_slot != ticket_slot {
            return Err(StakeEngineError::SlotMismatch {
                handle_slot,
                ticket_slot,
            });
        }

        // 3. Preflight the OS entropy source (Round 3 — source failure, fail-loud).
        //    `GapRng::next_u64` is infallible; a source failure therefore must be
        //    caught here via `try_fill_bytes` before calling `draw_entry_gap`.
        //    No silent fallback: source failure → `RngSourceFailed`, not a retry
        //    on a weaker source.
        {
            let mut probe = [0u8; 8];
            rand_core::OsRng
                .try_fill_bytes(&mut probe)
                .map_err(StakeEngineError::RngSourceFailed)?;
            let _ = probe; // consumed; used only to exercise the source
        }

        // 4. Entry-gap draw + per-draw degeneracy guard (S4/S5, Round 2/3).
        //    `draw_entry_gap_guarded` draws twice (spread_draw, spread_probe) and
        //    fires `RngDegeneracy` if they are equal (double-jitter-trap detection).
        //    The actual timing draw result is returned on success.
        let mut rng = OsRngGapAdapter;
        let spread = draw_entry_gap_guarded(DEFAULT_ENTRY_GAP.as_blocks(), &mut rng)
            .map_err(|DegenerateDraw| StakeEngineError::RngDegeneracy)?;
        // S6: the session-level `certify_draw` self-cert (over `OsRngGapAdapter`,
        // gated, at session start) is wired in `on_start` — see
        // `run_session_self_cert` and the `conformance` feature.

        // 5. The bond post fires `spread` blocks after the private intent `t0`.
        //    There is no second event to order and no plan to build: only the
        //    post is chain-attributable, the funding transfer is the unnamed
        //    CT-hidden FCMP++ input (`ARCHIVAL_FIREWALL_GATE6.md` pass-4 (d) +
        //    note 8), so the order coin was retired and the offset *is* the draw.
        let bond_post_offset_blocks = spread;

        // GF-7 hooks-spec §3: emit the draw-consumption and schedule events to
        // the injected observer. Sim-facing only — this block is compiled out
        // of default builds (§4 layer 3), and the production observer is the
        // no-op (§6.1). Payload discipline: opaque wallet-local slot ordinal,
        // block-relative offsets, no wall-clock, no identities.
        #[cfg(feature = "gf7-hooks")]
        {
            let persona = u64::from(handle_slot.to_raw());
            self.observer.record(TimelineEvent::EntryGapDrawConsumed {
                persona,
                window_blocks: DEFAULT_ENTRY_GAP.as_blocks(),
                spread_blocks: spread,
            });
            self.observer.record(TimelineEvent::BondPostScheduled {
                persona,
                bond_post_offset_blocks,
            });
        }

        Ok((handle_slot, bond_post_offset_blocks))
    }

    /// Project the public identity of a held slot. The caller must have
    /// validated membership (e.g. via [`Self::validate_handle`]).
    pub(crate) fn identity_of(&self, slot: PSlot) -> PersonaIdentity {
        PersonaIdentity::from_keys(
            self.held
                .get(&slot)
                .expect("identity_of called for a held slot")
                .keys(),
        )
    }

    /// Project the held persona at `slot` into its public
    /// [`ShekylAddress`](shekyl_address::ShekylAddress) — built **in-actor**,
    /// from the already-live bundle (never re-derived). The reply type is
    /// structurally public-only (an address cannot carry a secret), so
    /// **no `P` secret leaves the actor** (rule 36). The orchestrator
    /// uses this only to address a funding transfer *to* `P`
    /// (`Engine::stake_in`), where `P` is a public recipient. `network`
    /// is the principal wallet's network (the actor is
    /// network-agnostic; the address's network is the sender's).
    pub(crate) fn receive_address_of(&self, slot: PSlot, network: Network) -> ShekylAddress {
        let keys = self
            .held
            .get(&slot)
            .expect("receive_address_of called for a held slot")
            .keys();
        keys.to_address(network)
    }

    /// Wipe the retired slot iff it is ephemeral; a bonded persona is left
    /// resident (typed contract #4 — the wipe path accepts only the ephemeral
    /// type, so this match is the single place a slot can be removed).
    pub(crate) fn wipe_retired_if_ephemeral(&mut self, retired: PSlot) {
        if matches!(self.held.get(&retired), Some(HeldPersona::Ephemeral(_))) {
            // The `remove` yields the owned `EphemeralPersona`; `wipe_ephemeral`
            // accepts nothing else, so a `Bonded` variant cannot reach it.
            if let Some(HeldPersona::Ephemeral(persona)) = self.held.remove(&retired) {
                wipe_ephemeral(persona);
            }
        }
    }

    /// SP-R0 arm #1 (DQ-A) watch upkeep — the cheap, in-actor half of the
    /// refresh against the task's authoritative held-funding list (the
    /// records-driven framing pin). Drop-on-prune: cached (and quarantined)
    /// entries whose gindex is no longer held are dropped. Returns the
    /// derive-on-add candidates — the uncached records whose CPU-heavy
    /// derivation the caller offloads
    /// ([`derive_watch_key_images_offloaded`](Self::derive_watch_key_images_offloaded));
    /// the derivation never runs in the actor's async context (DQ5/DQ6).
    pub(crate) fn watch_upkeep(&mut self, held: &[FundingOutputMatch]) -> Vec<FundingOutputMatch> {
        let held_gindexes: BTreeSet<shekyl_types::GlobalOutputIndex> =
            held.iter().map(|m| m.gindex).collect();
        self.watch_cache.retain_gindexes(&held_gindexes);
        self.watch_quarantine.retain(|g| held_gindexes.contains(g));
        self.watch_derivation_candidates(held)
    }

    /// The subset of `records` whose watch key image still needs deriving:
    /// not yet watched, not quarantined, and owned by a resident-**bonded**
    /// slot. The watched-gindex set is built once, so the pass is
    /// `O(n log n)` in the held count, not the quadratic
    /// scan-per-record it replaces.
    ///
    /// A record whose owning slot is not resident-bonded is skipped, not an
    /// error: a retired persona's funding records are arm #2's retire-time
    /// atomic prune (the records leave with the persona; until then their
    /// spends are unwatchable by construction — the keys are wiped), and a
    /// bonded persona's records always have resident keys.
    pub(crate) fn watch_derivation_candidates(
        &self,
        records: &[FundingOutputMatch],
    ) -> Vec<FundingOutputMatch> {
        let watched = self.watch_cache.watched_gindexes();
        records
            .iter()
            .filter(|m| {
                !watched.contains(&m.gindex)
                    && !self.watch_quarantine.contains(&m.gindex)
                    && matches!(self.held.get(&m.p_slot), Some(HeldPersona::Bonded(_)))
            })
            .cloned()
            .collect()
    }

    /// Derive the watch key images of `records` on a blocking thread: the
    /// per-record hybrid-KEM decapsulation + scalar multiplication must not
    /// run on the async executor — the same DQ5/DQ6 offload discipline as the
    /// extractor, which a catch-up step over a large held set would otherwise
    /// violate for the whole derivation run. The vault is **moved** into the
    /// closure and moved back with the outcomes — never cloned (the secrets
    /// exist once, rule 35/36), and never into the *extractor* closure (the
    /// DQ-A pin: spend material and the scan closure stay separated). The
    /// handler holds `&mut self` across this `await`, so no other message can
    /// observe the actor without its vault.
    ///
    /// Per-record outcomes are values, not early returns: one record's
    /// deterministic derivation failure must not abort the others or the step
    /// (see [`absorb_watch_derivation`](Self::absorb_watch_derivation)).
    pub(crate) async fn derive_watch_key_images_offloaded(
        &mut self,
        records: Vec<FundingOutputMatch>,
    ) -> Vec<(shekyl_types::GlobalOutputIndex, Result<[u8; 32], String>)> {
        let held = std::mem::take(&mut self.held);
        let joined = tokio::task::spawn_blocking(move || {
            let outcomes = records
                .iter()
                .map(|m| {
                    let outcome = match held.get(&m.p_slot) {
                        Some(persona @ HeldPersona::Bonded(_)) => derive_funding_key_image(
                            persona.keys(),
                            m.ciphertext_x25519,
                            &m.ciphertext_ml_kem,
                            m.index_in_transaction,
                            m.output_key,
                        ),
                        // `watch_derivation_candidates` filtered to
                        // resident-bonded slots; a vanished slot here is a
                        // logic error — a per-record failure, never a panic
                        // (the vault must ride back out of this closure).
                        _ => Err("owning slot no longer resident-bonded".to_owned()),
                    };
                    (m.gindex, outcome)
                })
                .collect();
            (held, outcomes)
        })
        .await;
        match joined {
            Ok((held, outcomes)) => {
                self.held = held;
                outcomes
            }
            // The vault moved into the closure and the closure died: the keys
            // unwound (wiped) with it and are unrecoverable. Returning an
            // error would leave a resident actor that scans keyless — a
            // silent DQ7 weakening; fail-stop instead, the actor's documented
            // no-restart panic posture (`on_panic`).
            Err(join_err) => panic!("watch-derivation offload lost the vault: {join_err}"),
        }
    }

    /// Fold one offloaded derivation outcome into the watch (derive-on-add)
    /// or the quarantine, returning the key image on success.
    ///
    /// Quarantine, **not** a step error: the derivation is deterministic
    /// (same record, same vault ⇒ same failure), so failing the step would
    /// permanently wedge the scan pipeline on one bad record — frontier
    /// frozen, balances, bond-post matches, and unbond processing all
    /// stalled. Skipping only this record keeps the wallet syncing, and is
    /// sound for the [`SpentRecordsDurablyPruned`] attestation: assemble
    /// re-derives the same bundle (`derive_spend_parts`) and fails the same
    /// way, so a record the watch cannot derive can never be swept into a
    /// bond post — the duplicate-key-image poison the witness precludes
    /// cannot arise from a quarantined record. Loud (error level, once per
    /// record per residency): a failed derivation is still corrupted-state
    /// evidence.
    pub(crate) fn absorb_watch_derivation(
        &mut self,
        gindex: shekyl_types::GlobalOutputIndex,
        outcome: Result<[u8; 32], String>,
    ) -> Option<[u8; 32]> {
        match outcome {
            Ok(key_image) => {
                self.watch_cache.insert(key_image, gindex);
                Some(key_image)
            }
            Err(reason) => {
                if self.watch_quarantine.insert(gindex) {
                    tracing::error!(
                        gindex = gindex.to_raw(),
                        %reason,
                        "watch key-image derivation failed; record quarantined from the \
                         spent-watch until it leaves the held set (its on-chain spend \
                         will not be observed; assemble of this record fails identically, \
                         so it cannot be swept into a bond post either)"
                    );
                }
                None
            }
        }
    }

    /// Build the bonded union's transient scan inputs for a [`ScanStep`]: a
    /// [`GuaranteedScanner`] per bonded persona (SP-1, burning-bug-immune) plus
    /// their cleartext `p_canonical_id` set (the public half of the SP-3 dual
    /// extractor).
    ///
    /// These are built from the resident bundles and handed straight into the
    /// offload closure: the scanners are transient secret copies dropped at the
    /// end of the scan-step (DQ5), adding no resident secret surface beyond the
    /// keys the actor already vaults. Ephemeral (lookahead, no-bond) personas are
    /// **not** scanned — archival funding accrues only to a persona with a live
    /// bond (the bonded tag is the available signal; SP-6 reconciles it).
    ///
    /// Fails closed if a resident key is malformed: a silently-weakened scanner
    /// would mis-size the privacy parameter `C_min` (DQ7).
    ///
    /// `known_personas` is recomputed here **on purpose**, not cached: it rides
    /// the same loop that rebuilds the transient secret scanners, which *must*
    /// be rebuilt every batch (DQ5). Caching only the public id map would save
    /// one `persona_canonical_id` per bonded persona per batch (marginal, since
    /// bonded personas are few) at the cost of a stale-cache invalidation surface
    /// on a firewall-critical set — a missed invalidation would silently drop a
    /// newly-bonded persona's bond-post matches. Recompute is the safe trade.
    pub(crate) fn bonded_scan_inputs(&self) -> Result<BondedScanInputs, ScanSetupError> {
        let mut scanners = Vec::new();
        let mut known_personas = BTreeMap::new();
        for (slot, held) in &self.held {
            if let HeldPersona::Bonded(_) = held {
                let keys = held.keys();
                // Slot-tagged so the extractor can attribute each recovered
                // output to its owning persona (WI-2 D-A1 funding records).
                scanners.push((
                    slot.to_raw(),
                    guaranteed_scanner_for_persona(keys).map_err(ScanSetupError::Scanner)?,
                ));
                let id = persona_canonical_id(keys).map_err(ScanSetupError::CanonicalId)?;
                known_personas.insert(id, slot.to_raw());
            }
        }
        Ok((scanners, known_personas))
    }

    /// Retire a now-terminal bonded persona (2d-1 DQ8): wipe its key and drop it
    /// from the scan union, identified by the witness's `p_canonical_id`.
    ///
    /// The witness already proves eligibility; this only *applies* it. **Idempotent
    /// and conservative:** a persona already gone is a [`RetireOutcome::NotHeld`]
    /// no-op; the **active** persona is left in place ([`RetireOutcome::
    /// SkippedActive`]) — a terminal persona should not be active, but we never wipe
    /// the active slot mid-use; and a slot that still holds unspent funding is left
    /// in place ([`RetireOutcome::SkippedFunded`], the **funded-gate**) so the
    /// irreversible wipe never strands spendable `P` funds. Only
    /// [`HeldPersona::Bonded`] is matched (an ephemeral persona has no bond to be
    /// terminal).
    pub(crate) fn retire_bonded(
        &mut self,
        witness: &RetirementWitness,
        funded_slots: &FundedSlots,
    ) -> RetireOutcome {
        // Find the bonded persona whose canonical id matches the witness. A key
        // that fails to encode is skipped (it cannot be the match); the scan that
        // produced the witness already encoded it.
        let slot = self.held.iter().find_map(|(slot, held)| match held {
            HeldPersona::Bonded(_) => {
                let id = persona_canonical_id(held.keys()).ok()?;
                (id == witness.p_canonical_id).then_some(*slot)
            }
            HeldPersona::Ephemeral(_) => None,
        });
        let Some(slot) = slot else {
            return RetireOutcome::NotHeld;
        };
        if self.active == Some(slot) {
            return RetireOutcome::SkippedActive { slot };
        }
        // Funded-gate: never wipe a slot that still holds unspent funding. The
        // wipe is irreversible and the open path stops deriving a retired slot,
        // so wiping a funded slot would strand spendable `P` funds. Defer until
        // the funding is drained; the durable pending trigger re-fires the retire.
        if funded_slots.contains(slot) {
            return RetireOutcome::SkippedFunded { slot };
        }
        // Remove + wipe the now-terminal bonded persona. The match re-confirms the
        // `Bonded` variant, so `wipe_bonded` (typed contract #4's DQ8 exception) is
        // reached only here.
        if let Some(HeldPersona::Bonded(persona)) = self.held.remove(&slot) {
            wipe_bonded(persona);
        }
        RetireOutcome::Retired { slot }
    }
}

/// `P`'s cleartext canonical id from its keys — `cSHAKE256` over the canonical
/// `hybrid_bond_id` bytes, the same value an on-chain bond-post carries. `Err` if
/// the hybrid key does not canonically encode (a corrupted resident key).
pub(crate) fn persona_canonical_id(
    keys: &ArchivalPKeys,
) -> Result<PCanonicalId, shekyl_crypto_pq::CryptoError> {
    let hybrid = keys.hybrid_bond_id().to_canonical_bytes()?;
    Ok(p_canonical_id_from_hybrid_pubkey(&hybrid))
}

/// Failure surface of [`StakeEngine`]'s spawn ([`Actor::on_start`]).
///
/// The variant set is **designed for the failures known to be incoming, not just
/// today's** (S6 plan §2.1 / F3): 2d-1's `P`-scan init (scan-store open, cursor
/// recovery) will add **always-on** variants here, so it *adds a variant* rather
/// than reshaping the type. Today the **only** variant is the conformance RNG
/// self-cert, `#[cfg]`-compiled out by default — so in the default build this is
/// an **empty enum**, `on_start` cannot construct an `Err`, and the failure
/// branch is zero-cost.
///
/// `Debug` satisfies kameo's `ReplyError` bound (blanket `Debug + Send + 'static`);
/// `Clone` is required by `ActorRef::wait_for_startup_result`, the eager
/// observation path the spawn site uses (S6 plan §2.1).
#[derive(Debug, Clone)]
pub(crate) enum StakeEngineStartError {
    /// The session RNG self-cert (S6, conformance build only) graded the
    /// production `OsRng` adapter as **non-conformant**. A degenerate timing RNG
    /// defeats the gate-6 decorrelation firewall, so the actor refuses to start
    /// (fail-stop → wallet-open fails loudly with the grade in the report).
    #[cfg(feature = "conformance")]
    RngSelfCertFailed(shekyl_standoff::conformance::CertifyReport),
}

/// S6 — grade `rng` with the session self-cert and decide whether the actor may
/// start: pass → `Ok(())`, non-conformant → `Err(RngSelfCertFailed(report))`.
///
/// Extracted from [`Actor::on_start`] so the **decision** is unit-testable with
/// an injected degenerate RNG without spawning the actor (the *full* spawn →
/// fail-stop → `OpenError` path with a degenerate source is the Round-2/`R0-D#`
/// test). Conformance build only.
#[cfg(feature = "conformance")]
pub(super) fn run_session_self_cert<R: GapRng>(rng: &mut R) -> Result<(), StakeEngineStartError> {
    let report = shekyl_standoff::conformance::certify_draw(
        rng,
        DEFAULT_ENTRY_GAP.as_blocks(),
        crate::engine::stake_timing::CERTIFY_SAMPLE_N,
    );
    if report.passed() {
        Ok(())
    } else {
        Err(StakeEngineStartError::RngSelfCertFailed(report))
    }
}

impl Actor for StakeEngine {
    type Args = StakeEngineArgs;
    type Error = StakeEngineStartError;

    /// Build the actor from the pre-derived bundles. Tag each bundle
    /// bonded/ephemeral from the `bonded` hint; no derivation happens here (the
    /// seed never reaches the actor under Model D).
    async fn on_start(
        args: StakeEngineArgs,
        _actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        let held = args
            .bundles
            .into_iter()
            .map(|(slot, keys)| {
                let tagged = if args.bonded.contains(&slot) {
                    HeldPersona::Bonded(BondedPersona(keys))
                } else {
                    HeldPersona::Ephemeral(EphemeralPersona(keys))
                };
                (slot, tagged)
            })
            .collect::<BTreeMap<_, _>>();

        // Defensive: the orchestrator guarantees `active ∈ bundles`. Drop a
        // dangling cursor to idle rather than carry an unresolvable active slot.
        let active = args.active.filter(|slot| held.contains_key(slot));

        // S6 — session RNG self-cert. Compiled in **only** under the `conformance`
        // feature (`x86_64` enforced by the module-level `compile_error!`); the
        // default build has no grade at all. Grade the real `OsRng` adapter before the
        // actor accepts any work; a non-conformant CSPRNG fail-stops the spawn (and
        // so wallet-open), so a degenerate timing RNG never reaches the gate-6
        // decorrelation draw. This certifies the real adapter at the real
        // session-start — stronger than the reference-RNG KAT (S6 §0). A
        // **non-test `conformance`** build always grades; the **`test +
        // conformance`** build selects via `args.self_cert` (default `Skip`, so
        // unrelated tests are neither slowed nor flaked by the grade's α=1e-6
        // false-positive).
        #[cfg(all(feature = "conformance", not(test)))]
        run_session_self_cert(&mut OsRngGapAdapter)?;
        #[cfg(all(feature = "conformance", test))]
        match args.self_cert {
            TestSelfCert::Skip => {}
            TestSelfCert::RealOsRng => run_session_self_cert(&mut OsRngGapAdapter)?,
            TestSelfCert::Degenerate => {
                struct ConstZeroRng;
                impl GapRng for ConstZeroRng {
                    fn next_u64(&mut self) -> u64 {
                        0
                    }
                }
                run_session_self_cert(&mut ConstZeroRng)?;
            }
        }

        Ok(Self {
            held,
            active,
            generation: 0,
            watch_cache: KeyImageWatchSet::new(),
            watch_quarantine: BTreeSet::new(),
            #[cfg(feature = "gf7-hooks")]
            observer: args.observer,
        })
    }

    /// Fail-stop on panic. The kameo default, locked explicitly so the
    /// secret-owner's no-restart posture is pinned at the type layer rather than
    /// inherited from a framework default that could change under a dependency
    /// bump (mirrors [`KeyActor`](super::key_actor::KeyActor)).
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    /// Defense-in-depth wipe at stop. Each held bundle's per-field
    /// `ZeroizeOnDrop` also runs at task-end drop; clearing the map here makes
    /// the zeroization observable at fail-stop and is idempotent with the
    /// drop-glue wipe.
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        // Dropping every held bundle runs each secret field's `ZeroizeOnDrop`.
        self.active = None;
        self.held.clear();
        Ok(())
    }
}
