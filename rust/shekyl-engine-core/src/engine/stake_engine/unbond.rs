// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `AssembleUnbond` — the terminal full exit's producer-side preconditions.
//!
//! `verify_unbond_bond_post`'s rejection arms are two categories, and this
//! module owns the half [`build_unbond_vin`] cannot.
//!
//! The builder fixes the five fields a producer controls. The remaining arms —
//! `RecordMissing`, `IntervalLogFull`, `CooldownNotElapsed`,
//! `SlashSettlementPending` — are **record state**: facts about the chain that
//! no vin construction can satisfy. A producer that ignored them would assemble
//! a well-formed post the daemon then rejects, and on this path that is the
//! difference that matters. An exit is the last step before an irreversible
//! persona-key wipe; a wallet that says "sent" and fails at the chain has told
//! the user the wrong thing about an operation they cannot take back. So the
//! refusal happens **here**, with a named cause, before anything is built.
//!
//! **The predicates are consensus's own, called — not restated.**
//! [`release_cooldown_elapsed`] and [`slashes_settled_through`] are the exact
//! functions the verify arm runs, and `MAX_BOND_BAD_INTERVALS` is the same
//! constant. A second implementation here could drift from the verifier that
//! decides the transaction, and the drift would be invisible until a real exit
//! failed. A gate could report that divergence after the fact; calling the same
//! function makes it not happen.

use kameo::message::{Context, Message};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand_core::RngCore as _;
use shekyl_archival_bond_builder::{build_unbond_vin, verify_debit_funding};
use shekyl_archival_retention::bond_connect::MAX_BOND_BAD_INTERVALS;
use shekyl_archival_retention::bond_post::bond_post_funding_floor_met;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_archival_retention::release_cooldown::{
    release_cooldown_elapsed, slashes_settled_through,
};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme as _};
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, PqcAuth, TreeContext, WireEncodeInput,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::Input;
use zeroize::Zeroizing;

use shekyl_types::PCanonicalId;

use crate::engine::bond_assembly::{
    finalize_bond_tx, wire_bond_post_input, BondAssemblyError, FundingInputContext, PBoundBytes,
};
use crate::engine::emission_source::{ClaimSourceFor, ServeAnchor, SlashWatermark};

use super::actor::{persona_canonical_id, StakeEngine};
use super::helpers::{construct_vouts_to_base, prepare_funding_inputs, ConstructedVouts};
use super::types::*;

/// The record facts an exit's preconditions read, as the daemon reported them,
/// **bound to the persona they were read for**.
///
/// Fields are private and [`Self::from_claim_source`] is the only production
/// constructor, which takes one [`ClaimSourceFor`] — a decoded response
/// already paired with the `P` it was requested for. Two properties follow
/// structurally rather than by convention, and both matter on a path whose
/// confirmation is irreversible:
///
/// - **One read view.** Every field comes from a single response, so
///   `bonded_total_atomic` and the cooldown anchor cannot straddle a block —
///   which would otherwise let readiness be computed on one view and the vin be
///   built against another.
/// - **One persona.** The id travels with the facts, so a caller cannot pair
///   persona A's balance and anchors with persona B's handle. Field-by-field
///   assembly is what would allow that, and it is not available.
///
/// [`ServeAnchor`] and [`SlashWatermark`] rather than `Option<u64>` on purpose.
/// Both consensus predicates treat an absent anchor as *permissive*, so a bare
/// `Option` reaching this struct could carry "the daemon says nothing served"
/// (correct, permissive) or "the field never arrived" (must be fail-closed) with
/// no way to tell them apart. The decoder makes the second unconstructible — an
/// absent field is a decode error — and these types carry that guarantee the
/// rest of the way.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UnbondRecordState {
    /// The persona these facts describe — checked against the handle's own
    /// derived id before anything is built for it.
    p_id: PCanonicalId,
    /// The record's current bonded balance; the exit's `bond_debit` by contract.
    bonded_total_atomic: u64,
    /// The record's interval-log length.
    bad_interval_count: usize,
    /// The whole-record release-cooldown anchor, folded by the daemon.
    last_served: ServeAnchor,
    /// The slash scheduler's monotone watermark.
    last_settled_slash: SlashWatermark,
    /// The settled epoch the daemon derived from its own tip.
    current_settlement_epoch: u64,
}

impl UnbondRecordState {
    /// Build from one [`ClaimSourceFor`] — the only production constructor.
    ///
    /// **Takes no `p_id` argument on purpose.** An earlier revision accepted the
    /// id and the response separately, which labels rather than binds: passing
    /// persona A's response with persona B's id produced A's facts wearing B's
    /// name, and the handler's equality check then agreed with the name. The id
    /// now arrives already fastened to the response by the code that sent the
    /// request, so the mismatched pair cannot be expressed here at all.
    ///
    /// `None` when the daemon holds no bond record for that `P`: there is no
    /// exit to assess, which the caller reports rather than treating as an
    /// error. Both the record facts and `current_settlement_epoch` come from
    /// this one response, so the settled epoch a refusal quotes is the epoch
    /// the anchors were read against.
    #[allow(dead_code)] // PR-P4: retires with the `unstake` verb, which fetches the record.
    pub(crate) fn from_claim_source(fetched: &ClaimSourceFor) -> Option<Self> {
        let source = fetched.source();
        let bond = source.bond.as_ref()?;
        Some(Self {
            p_id: fetched.p_id(),
            bonded_total_atomic: bond.bonded_total_atomic,
            bad_interval_count: bond.bad_interval_count,
            last_served: bond.last_served,
            last_settled_slash: bond.last_settled_slash,
            current_settlement_epoch: source.current_settled_epoch,
        })
    }

    /// The persona these facts describe.
    pub(crate) fn p_id(&self) -> PCanonicalId {
        self.p_id
    }

    /// The exit's `bond_debit` by contract — `verify_unbond_bond_post` requires
    /// the vin's debit to equal this exactly.
    pub(crate) fn bonded_total_atomic(&self) -> u64 {
        self.bonded_total_atomic
    }

    /// Refuse, with a named cause, if this record cannot support a full exit.
    ///
    /// Mirrors the verify arm's record-state checks in the same order, using the
    /// same predicates, so a refusal here and a rejection there cannot disagree
    /// about *why*.
    pub(crate) fn ensure_exit_ready(&self) -> Result<(), UnbondNotReady> {
        // FIRST, because it is first at the verifier: `NothingToUnbond` is
        // checked before the interval log, the cooldown, or the watermark
        // (`verify_unbond_bond_post` step 3). An earlier revision left this to
        // `build_unbond_vin` on the grounds that the builder consumes the
        // operand — true, and it does still check it as its own constructor
        // invariant. But deferring it here reordered the *reasons*: a
        // zero-balance record with a full interval log was refused as
        // `IntervalLogFull` while the chain would have said `NothingToUnbond`.
        // The whole point of running consensus's own predicates in consensus's
        // own order is that a wallet refusal and a chain rejection cannot
        // disagree about why, so the operand this struct already holds is
        // tested here too. The two checks cannot diverge: same field, same
        // comparison, no derivation between them.
        if self.bonded_total_atomic == 0 {
            return Err(UnbondNotReady::NothingToUnbond);
        }

        // The connect must append a clean interval-close; a full log makes the
        // tx unconnectable, so verify rejects it too. Same bound, one constant.
        if self.bad_interval_count >= MAX_BOND_BAD_INTERVALS {
            return Err(UnbondNotReady::IntervalLogFull {
                count: self.bad_interval_count,
                max: MAX_BOND_BAD_INTERVALS,
            });
        }

        // Both predicates are called unconditionally, on the operand form
        // `as_verify_operand` produces and nothing else. A tempting shortening
        // is to note that neither can refuse a never-served record
        // (`release_cooldown_elapsed(None, _)` and `slashes_settled_through(_,
        // None)` are both `true`) and wrap the pair in a `ServedAt` match. That
        // trades a wrong message for a missing check: if either absent arm ever
        // moved, the match would *skip* the predicate instead of running it.
        // The refusals carry the anchor as read, so no branch here has to
        // restate what consensus does with `None`.
        let anchor = self.last_served.as_verify_operand();
        if !release_cooldown_elapsed(anchor, self.current_settlement_epoch) {
            return Err(UnbondNotReady::CooldownNotElapsed {
                last_served: self.last_served,
                current_settlement_epoch: self.current_settlement_epoch,
            });
        }

        if !slashes_settled_through(self.last_settled_slash.as_verify_operand(), anchor) {
            return Err(UnbondNotReady::SlashSettlementPending {
                last_served: self.last_served,
                watermark: self.last_settled_slash,
            });
        }

        Ok(())
    }
}

/// Assemble the **full, broadcast-ready** `Unbond` exit transaction inside the
/// actor — the debit-side twin of `AssembleBond` (gate-4 §3.5).
///
/// The exit carries no ticket and draws no entry-gap offset. That seam exists
/// to place a *bond post* at a random remove from the private funding intent
/// that preceded it; an exit has no such anchor — the event it follows is a
/// cooldown expiring on-chain, which is already public. Adding a draw here
/// would delay an irreversible operation the user asked for, and hide nothing.
///
/// **Not reachable, deliberately.** Nothing on this path is wired to an RPC
/// method or CLI verb, and wallet-RPC `unstake` stays RESERVED until a regtest
/// walk has exercised the retire path end to end.
pub(crate) struct AssembleUnbond {
    /// Operation-scoped capability proving the slot is currently held.
    pub handle: PersonaHandle,
    /// The record facts, from one claim-source read view.
    pub record: UnbondRecordState,
    /// The selected funding inputs with their assembled membership paths —
    /// public identity + public tree data only; spend secrets are re-derived
    /// inside the handler (rule 36).
    ///
    /// Drawn from the typed `P`-space pool (JoinMarket **cover** + claim
    /// **earnings**), per `ARCHIVAL_BOND_CONSTRUCTION.md` §3.5 rule 1: a
    /// principal output is unrepresentable in the selector's input type. The
    /// exit is the terminal post, so it is the one constructor permitted to
    /// spend the pool below `EXIT_FEE_RESERVE_ATOMIC` — that reserve exists to
    /// keep *this* transaction fundable.
    pub funding: Vec<FundingInputContext>,
    /// The curve-tree reference context the paths were assembled against.
    pub tree_ctx: TreeContext,
    /// The canonical weight-priced P-lane floor fee, resolved engine-side.
    ///
    /// No knob, by contract (§3.5 rule 3): a tunable fee on a `P`-attributed
    /// transaction is a wallet-fingerprint channel in a cleartext field.
    pub fee: u64,
}

/// Reply of [`AssembleUnbond`]: the persona-bound wire bytes minted at the
/// single P-1 site, plus the spent funding records' gindexes for the caller's
/// reservation record. Secrets never cross the boundary.
///
/// No placement offset, unlike `AssembledBondPost` — see [`AssembleUnbond`] for
/// why the exit draws none.
#[derive(Debug)]
#[allow(dead_code)] // PR-P4: retires with the `unstake` verb; today's readers are tests.
pub(crate) struct AssembledUnbondPost {
    /// The fully-signed, wire-encoded exit transaction, persona-bound.
    pub bound_tx: PBoundBytes,
    /// The spent funding records' gindexes — the reservation set.
    pub funding_gindexes: Vec<shekyl_types::GlobalOutputIndex>,
}

impl Message<AssembleUnbond> for StakeEngine {
    type Reply = Result<AssembledUnbondPost, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleUnbond,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // ── Step 1: handle validation. No ticket, no entry-gap draw. ──────
        self.validate_handle(&msg.handle)?;

        // ── Step 2: borrow the held bundle (never crosses the boundary) ───
        let keys = self
            .held
            .get(&msg.handle.p_slot)
            .expect("validate_handle confirmed the slot is held")
            .keys();

        // ── Step 3: the handle and the record facts arrive as two
        // independent values, so BEFORE either is used, prove they describe
        // the same persona. The handle proves the slot is held; it says
        // nothing about whose record was read. Without this, a caller holding
        // two claim-source responses could pair persona A's balance and
        // anchors with persona B's handle, and the wallet would answer
        // readiness from A's cooldown while building B's post. The daemon
        // would reject the result — but the readiness answer would already
        // have been wrong, and this path's confirmation is an irreversible
        // persona-key wipe.
        //
        // Derived from the resident keys rather than carried on the handle:
        // `persona_canonical_id` hashes the same canonical bytes an on-chain
        // bond-post carries, so this compares the id the chain will see.
        //
        // `a_record_read_for_another_persona_is_refused_at_the_actor` drives
        // this through the actor and goes red if the comparison is deleted. A
        // unit test on `UnbondRecordState` cannot cover it: the id it would
        // check is the one the test itself supplied, so the refusal has to be
        // observed where the two independent values actually meet.
        let handle_p_id = persona_canonical_id(keys)
            .map_err(|e| StakeEngineError::ScanSetup(ScanSetupError::CanonicalId(e)))?;
        if handle_p_id != msg.record.p_id() {
            return Err(StakeEngineError::RecordPersonaMismatch);
        }

        // ── Step 4: preconditions BEFORE construction — nothing is built for
        // a record that cannot exit, so a refusal never produces a post a
        // caller ignoring the error could broadcast. ──────────────────────
        msg.record.ensure_exit_ready()?;

        // ── Step 5: construct the vin. The constructed value is the SINGLE
        // source of the post: it feeds the debit term, the wire prefix input
        // (step 9), and the balance check — so the prefix and the post cannot
        // diverge by construction.
        let built = build_unbond_vin(keys.bond_post_keys(), msg.record.bonded_total_atomic())
            .map_err(StakeEngineError::BondBuild)?;
        let hybrid_pk_bytes = built.vin().hybrid_public_key.clone();
        let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
        let bond_debit = built.vin().bond_debit;
        let debit_term = built.debit_term();

        // ── Step 6: funding — the SHAPE floor first, then the DEBIT rule.
        //
        // A bond post carries at least one real `txin_to_key` spend input,
        // whatever the kind — so the fee comes from P working capital and never
        // from released collateral alone. The predicate is CALLED, not
        // restated: `bond_post_funding_floor_met` owns the rule
        // (`shekyl-archival-retention`), the same way `verify_debit_funding`
        // owns the balance rule below. The daemon still decides this one in C++
        // (`blockchain.cpp`, "Archival bond-post tx requires at least one
        // txin_to_key funding input"); that copy goes away with the
        // tx-verification migration, and until it does, the wallet is not
        // holding a second private copy of the rule.
        //
        // Placed after the record-state arms (steps 4-5) and before the
        // arithmetic because that is where consensus places it — after
        // `check_archival_bond_post_input`, before every amount rule — so a
        // caller who also got the fee wrong is told about the missing input
        // first, exactly as a node would.
        //
        // Nothing below could catch the empty set: released collateral alone
        // clears the sufficiency test, and `verify_debit_funding` closes
        // tautologically at zero funding because the outputs are derived from
        // the same `sources` term. Un-guarded, this state reached the prover
        // and came back as `TxBuilderError::NoInputs` under stage "proving" —
        // naming the pipeline step where a condition belongs.
        // `an_exit_with_no_funding_inputs_is_refused_by_name` goes red if this
        // call is deleted.
        if !bond_post_funding_floor_met(msg.funding.len()) {
            return Err(BondAssemblyError::FundingInputsRequired.into());
        }

        // The DEBIT rule inverts the credit path rather than sharing it.
        // Released collateral is a *source*: `sum(funding) + bond_debit ==
        // sum(outputs) + fee`. On the bond path the floor was a cost the
        // funding had to cover; here it is value arriving, so the only thing
        // funding must cover is whatever the fee exceeds.
        let mut funding_total: u64 = 0;
        for ctx in &msg.funding {
            funding_total = funding_total
                .checked_add(ctx.record.amount.to_raw())
                .ok_or(BondAssemblyError::AmountOverflow)?;
        }
        let sources = funding_total
            .checked_add(bond_debit)
            .ok_or(BondAssemblyError::AmountOverflow)?;
        if sources < msg.fee {
            return Err(BondAssemblyError::InsufficientFunding {
                available: sources,
                required: msg.fee,
            }
            .into());
        }
        // Payout splits across TWO outputs (daemon prunable-tx floor:
        // `vout.size() < 2` rejects), as the credit path splits its change.
        let payout = sources - msg.fee;
        let payout_lo = payout / 2;
        let amounts = [payout_lo, payout - payout_lo];

        // The scalar precondition is CALLED, not restated. `verify_debit_funding`
        // is the mirror of the consensus rule and owns the side: `debit_term`
        // is an `InputTerm`, so the type system already refuses to place the
        // released collateral on the output side.
        //
        // It is fed the sum of the amounts the vouts are ACTUALLY built from,
        // not the `payout` they were derived from. Passing `payout` would make
        // this a tautology — `payout = sources - fee` by the line above, so the
        // equation could not fail — and would step straight past the one bug
        // the split can have: an arithmetic slip that loses or invents a unit
        // between `payout` and the two outputs. Summing what is built is the
        // only version that can go red.
        let output_total = amounts
            .iter()
            .try_fold(0u64, |acc, &v| acc.checked_add(v))
            .ok_or(BondAssemblyError::AmountOverflow)?;
        verify_debit_funding(
            AtomicUnits::from_raw(funding_total),
            AtomicUnits::from_raw(output_total),
            AtomicUnits::from_raw(msg.fee),
            &built,
        )
        .map_err(StakeEngineError::BondBuild)?;

        // ── Step 7: outputs to P's OWN base address — never the principal.
        // This is the archival firewall, not a convenience: `unbond()` is post
        // **plus a decorrelated drain** precisely so returning collateral never
        // draws the P↔principal edge on-chain. Paying the exit straight to the
        // principal would put that edge in one transaction and make the drain's
        // decorrelation pointless.
        //
        // It is also what keeps the retire path's funded gate meaningful.
        // `RetireBondedPersona` refuses the irreversible key wipe while the
        // slot still holds unspent funding (`SkippedFunded`), and these outputs
        // ARE that funding — so the wipe cannot land until the drain has moved
        // them. Paying the exit straight to the principal would leave the slot
        // unfunded the moment the exit confirmed, and the gate that exists to
        // stop a premature wipe would wave it through.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(tx_key_secret.as_mut());
        let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

        let ConstructedVouts {
            output_infos,
            output_keys,
            view_tags,
            kem_blobs,
            leaf_hash_blob,
        } = construct_vouts_to_base(
            keys,
            &tx_key_secret,
            &amounts,
            "exit-output construction",
            |_, _| {},
        )?;

        // ── Step 8: tx_extra — tx pubkey + per-output KEM blobs + the 0x07
        // PQC leaf hashes (without which the exit outputs ingest with a zero
        // `h_pqc` leaf and are unspendable — which on this path would strand
        // the returned collateral).
        let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
        extra.push_pqc_leaf_hashes(leaf_hash_blob);
        let tx_extra = extra.serialize();

        // ── Step 9: re-derive spend bundles, compute key images, build the
        // tx-builder SpendInputs — the shared leg with the bond and emission
        // handlers. Secrets stay inside this frame until they move into the
        // proving closure.
        let prepared = prepare_funding_inputs(keys, msg.funding)?;
        let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
        let funding_gindexes: Vec<shekyl_types::GlobalOutputIndex> =
            prepared.iter().map(|p| p.gindex).collect();

        // ── Step 10: the wire prefix input from the step-5 vin, then the
        // prefix hash. The wire input carries no signature (SA-2b), so the
        // prefix is fully determined here; the surface-A `pqc_auths` signature
        // covers it whole.
        let prefix_bond_input: Input = wire_bond_post_input(built.vin())?;
        let extra_inputs = vec![prefix_bond_input];

        let prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &extra_inputs,
            &output_keys,
            // Every exit output is confidential (wire amount 0) — derived from
            // the count, same as the wire encode below, so the two sites
            // cannot disagree on arity.
            &vec![0; output_keys.len()],
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("prefix hash", e))?;

        // ── Step 11: offload the CPU-bound proving (Bp+ + FCMP membership) to
        // `spawn_blocking`. The debit rides `extra_inputs`, the credit path's
        // `extra_outputs` — one argument apart, and the wrong one is a
        // transaction that balances for a different operation. It is not a
        // choice made here: `debit_term()` returns an `InputTerm`, which only
        // the inputs parameter accepts.
        let mut spend_inputs = Vec::with_capacity(prepared.len());
        let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
        for p in prepared {
            spend_inputs.push(p.spend);
            pqc_pubkeys.push(p.pqc_pubkey);
        }
        let outputs_for_prove = output_infos.clone();
        let tree = msg.tree_ctx.clone();
        let fee = msg.fee;
        let (signed, spend_inputs) = tokio::task::spawn_blocking(move || {
            sign_transaction_with_terms(
                prefix_hash,
                &spend_inputs,
                &outputs_for_prove,
                AtomicUnits::from_raw(fee),
                &[debit_term],
                &[],
                &tree,
            )
            .map(|signed| (signed, spend_inputs))
        })
        .await
        .map_err(|e| BondAssemblyError::build("proving offload join", e))?
        .map_err(|e| BondAssemblyError::build("proving", e))?;

        let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .map_err(|e| BondAssemblyError::build("bulletproof parse", e))?;

        // ── Step 12: assemble the wire input. `pqc_auths` is index-parallel
        // with `vin`, and consensus reads the bond slot at the bond post's own
        // vin index (`tx.pqc_auths[archival_bond_post_index]`), so the spend
        // slots come first and the bond slot last — matching the prefix input
        // order built above.
        //
        // **The bond slot carries `bond_spend_pk`, NOT the identity key.** This
        // is the one place the exit diverges from every credit post, and it is
        // the whole of GF-1 debit authorization: `archival_debit_auth_pin`
        // requires this slot's key to equal the record's COMMITTED
        // `bond_spend_pk` and rejects the identity key by name. Signing a
        // value-out with `hybrid_sign_sk` is exactly what a compromised serving
        // host could do, which is why consensus refuses it.
        let bond_auth_pk = keys
            .bond_spend_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("bond_spend_pk encoding", e))?;

        let mut wire = WireEncodeInput {
            key_images,
            extra_inputs,
            output_amounts: vec![0; output_keys.len()],
            output_keys,
            view_tags,
            tx_extra,
            fee,
            enc_amounts: signed.enc_amounts,
            enc_labels: signed.enc_labels,
            out_commitments: signed.commitments,
            pseudo_outs: signed.pseudo_outs,
            bulletproof,
            reference_block: signed.reference_block,
            fcmp_proof: signed.fcmp_proof,
            // Placeholder auths at real pubkeys (the phase-1 payload hash reads
            // them); the fee-slot pubkeys MOVE in.
            pqc_auths: pqc_pubkeys
                .into_iter()
                .map(|pk| PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: pk,
                })
                .chain(std::iter::once(PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: bond_auth_pk.clone(),
                }))
                .collect(),
            fcmp_layers: signed.tree_depth,
        };

        // ── Step 13: PQC auth completion (fast; stays inline). The spend slots
        // sign with output-derived keys; the bond slot signs with
        // `bond_spend_sk` — the secret half of the key consensus pinned above,
        // under the shared surface-A domain `verify_transaction_pqc_auth`
        // applies to every slot.
        let payload_hashes = phase1_payload_hashes(&wire)
            .map_err(|e| BondAssemblyError::build("phase1 payload hash", e))?;
        if payload_hashes.len() != spend_inputs.len() + 1 {
            return Err(BondAssemblyError::build(
                "phase1 payload hash",
                format!(
                    "expected {} payload hashes, got {}",
                    spend_inputs.len() + 1,
                    payload_hashes.len()
                ),
            )
            .into());
        }
        let mut pqc_auths = sign_pqc_auths(&payload_hashes[..spend_inputs.len()], &spend_inputs)
            .map_err(|e| BondAssemblyError::build("pqc auth signing", e))?;
        let bond_payload_hash = payload_hashes[spend_inputs.len()];
        let bond_sig = HybridEd25519MlDsa
            .sign(
                &keys.bond_spend_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                &bond_payload_hash,
            )
            .map_err(|e| BondAssemblyError::build("debit pqc auth signing", e))?;
        pqc_auths.push(PqcAuth {
            auth_version: 1,
            signature: bond_sig
                .to_canonical_bytes()
                .map_err(|e| BondAssemblyError::build("debit pqc auth encoding", e))?,
            public_key: bond_auth_pk,
        });
        wire.pqc_auths = pqc_auths;
        drop(spend_inputs); // secrets end here; nothing below needs them

        // ── Step 14: encode + mint at the P-1 site ────────────────────────
        let bound_tx = finalize_bond_tx(persona, &wire)?;

        Ok(AssembledUnbondPost {
            bound_tx,
            funding_gindexes,
        })
    }
}

#[cfg(test)]
#[path = "unbond_tests.rs"]
mod tests;
