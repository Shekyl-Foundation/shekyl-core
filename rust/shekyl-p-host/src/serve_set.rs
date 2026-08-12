// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-set: which shards this persona is bonded to answer for, where
//! that list is allowed to come from, and the pin that must succeed before
//! any of them is served.
//!
//! `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 4 names the hazard this
//! module exists to close: nothing structural binds `held_shard_ids` in the
//! **consensus** bond record to local `pin_segment` state, so a `P` that
//! posts holdings and forgets to pin has *its own node* prune the leaf bytes
//! it is obligated to serve — and then fails challenges, and then slashes,
//! an epoch later, for a local bookkeeping mismatch. The failure is silent
//! all the way to the slash, which is what makes a runtime check the wrong
//! shape of defense.

use shekyl_archival_retention::ClaimantBondRecord;
use shekyl_curve_tree::SegmentPin;

/// The shards a persona is bonded to serve, as read back from the chain.
///
/// # Where a serve-set may come from
///
/// The only constructor is [`Self::from_connected_record`], which takes a
/// [`ClaimantBondRecord`] — the *connected* bond record, decoded from the
/// daemon's claim-source reply — never a bare `Vec<u64>`. The production
/// chain is already end-to-end: `get_archival_emission_claim_source` →
/// `EmissionClaimSource::from_json` → `BondContext::record()`, with the
/// reply's `chain_height` as the stamp. Nothing has to be hand-assembled to
/// satisfy this signature. That is the whole
/// point: "what I posted" is not "what connected", and a locally-maintained
/// shard list that drifts from the record is exactly §9.6 item 4's
/// silent-slash path. There is no way to build this type from a list the
/// caller is keeping alongside the record, because the shape that would
/// permit it does not exist.
///
/// **The limit of that guarantee, stated rather than implied.**
/// `ClaimantBondRecord` is an ordinary struct with public fields, so a
/// caller who *wants* to fabricate one can. What this closes is the
/// accidental path — the drifting parallel list, the stale cached `Vec`, the
/// "just pass the ids you already have" call site — which is the one the
/// design names. Making the fabricated path unrepresentable too needs a
/// sealed decoder type minted only by the claim-source decode; that is the
/// wiring slice's work, on the crate that owns the decode, and it belongs
/// there rather than being approximated here.
///
/// # The height stamp
///
/// A serve-set is a snapshot: holdings change on-chain (`HoldingsUpdate`),
/// and new segments freeze continuously — §9.6 item 3's point that `D` is a
/// moving number, not a plateau. [`Self::as_of_height`] records the chain
/// height the record was read at, so a stale set is *distinguishable* from a
/// current one rather than merely being out of date. Nothing here expires a
/// set on its own; the wiring slice refreshes and re-pins, and this stamp is
/// what lets it tell whether it needs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSet {
    shard_ids: Vec<u64>,
    as_of_height: u64,
}

impl ServeSet {
    /// The serve-set implied by a connected bond record read at
    /// `as_of_height`.
    ///
    /// An empty holdings set is legal and is **not** an error here: a
    /// `CompleteTree` node carries no shard ids, and an `Unbond` exit
    /// empties them. [`PinnedServeSet`] is what decides whether an empty
    /// set is worth hosting.
    #[must_use]
    pub fn from_connected_record(record: &ClaimantBondRecord<'_>, as_of_height: u64) -> Self {
        Self {
            shard_ids: record.holdings.shard_ids.as_slice().to_vec(),
            as_of_height,
        }
    }

    /// The bonded shard ids, in the record's own order.
    #[must_use]
    pub fn shard_ids(&self) -> &[u64] {
        &self.shard_ids
    }

    /// The chain height the record was read at.
    #[must_use]
    pub fn as_of_height(&self) -> u64 {
        self.as_of_height
    }

    /// Whether this set carries no shards at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shard_ids.is_empty()
    }
}

/// Why a serve-set could not be pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// A member is frozen but its leaf bytes were already pruned. Pinning
    /// cannot bring bytes back, so this is refused rather than reported
    /// healthy: a persona that starts serving over a set in this state
    /// reaches its challenge epoch unable to answer, and the operator's
    /// first signal is the slash. The remedy is a store rebuild by chain
    /// replay, not a retry.
    ///
    /// Every pruned member is listed, not just the first — an operator
    /// facing a rebuild wants to know the extent of it in one message.
    MembersAlreadyPruned {
        /// Every serve-set member whose bytes are gone.
        shard_ids: Vec<u64>,
    },
    /// The pinner failed (store I/O, a dead actor, a poisoned client). The
    /// serve-set's state is unknown, so the host does not start; pinning is
    /// idempotent, so a retry re-covers whatever was already applied.
    Pinner {
        /// Local diagnostic; never on the wire.
        detail: String,
    },
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MembersAlreadyPruned { shard_ids } => write!(
                f,
                "serve-set members {shard_ids:?} were pruned before they were pinned; \
                 the store must be rebuilt by chain replay before this persona can serve"
            ),
            Self::Pinner { detail } => write!(f, "serve-set pin failed: {detail}"),
        }
    }
}

impl std::error::Error for PinError {}

/// Applies a serve-set's pins.
///
/// A trait rather than a concrete store handle because pinning is a **store
/// write**, and the store's single writer is the wallet's curve-tree actor —
/// the serving host must reach it through that actor, not around it. The
/// production implementor is the actor's handle; tests implement it
/// directly.
///
/// Generic rather than `dyn`: the production implementor round-trips an
/// actor message, so the method is `async`, and there is exactly one
/// implementor per process — nothing here needs the vtable that would cost
/// a boxed future.
///
/// **The `String` error is deliberate, against this codebase's usual typed-
/// error grain.** The failures an implementor can have are its own — a redb
/// fault, a dead kameo actor, a poisoned client — and this crate has no
/// business enumerating them: an error type here would either have to name
/// the curve-tree actor's failure modes (a dependency inversion) or be a
/// catch-all with one variant. What matters to the *caller* is a single
/// bit — the pins are not established, so no host starts — and that
/// distinction is typed, as [`PinError::Pinner`] versus
/// [`PinError::MembersAlreadyPruned`]: retry the first, rebuild the store
/// for the second. The string is the diagnostic riding along, and it never
/// reaches the wire.
pub trait ServeSetPinner {
    /// Pin every member, returning each outcome paired with its shard id.
    ///
    /// Contract (matching `LeafStore::pin_serve_set`, which the production
    /// implementor forwards to): outcomes come back in the caller's order,
    /// [`SegmentPin::AlreadyPruned`] is *reported* rather than raised, and
    /// pinning is idempotent.
    ///
    /// # Errors
    ///
    /// Implementor-defined; surfaced as [`PinError::Pinner`].
    fn pin_serve_set(
        &self,
        shard_ids: &[u64],
    ) -> impl std::future::Future<Output = Result<Vec<(u64, SegmentPin)>, String>> + Send;
}

/// Proof that a serve-set's pins are in place — the ticket
/// [`crate::PersonaServingHost::start`] demands.
///
/// The sealed-witness shape this codebase already uses for
/// `VerifiedTorBinary` (the binary passed its hash gate) and
/// `VanguardsActive` (full vanguards are configured on this incarnation),
/// applied to the third precondition a serving persona has: **its shards
/// will survive the next prune**. [`Self::acquire`] is the only way to mint
/// one, so "the host pinned before it served" is not a startup step someone
/// can reorder — it is the argument type.
///
/// It also carries the [`ServeSet`], so the host holds the record-derived
/// list rather than a second copy of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedServeSet {
    set: ServeSet,
    not_yet_frozen: Vec<u64>,
}

impl PinnedServeSet {
    /// Pin `set` through `pinner` and mint the witness.
    ///
    /// Members that have not frozen yet are pinned and **accepted**: bonding
    /// before a segment freezes is legal by design, and pinning ahead is
    /// what stops a prune from landing in the window between the freeze and
    /// the next re-pin. They are recorded in [`Self::not_yet_frozen`] because
    /// they are not servable *yet* — a shard read for one is an honest miss
    /// until the freeze boundary crosses it, and an operator looking at a
    /// non-zero miss count should be able to tell that apart from a fault.
    ///
    /// # Errors
    ///
    /// [`PinError::MembersAlreadyPruned`] if any member's bytes are already
    /// gone, and [`PinError::Pinner`] if the pin could not be applied.
    pub async fn acquire<P: ServeSetPinner>(pinner: &P, set: ServeSet) -> Result<Self, PinError> {
        let outcomes = pinner
            .pin_serve_set(set.shard_ids())
            .await
            .map_err(|detail| PinError::Pinner { detail })?;

        let pruned: Vec<u64> = outcomes
            .iter()
            .filter(|(_, pin)| *pin == SegmentPin::AlreadyPruned)
            .map(|(shard_id, _)| *shard_id)
            .collect();
        if !pruned.is_empty() {
            return Err(PinError::MembersAlreadyPruned { shard_ids: pruned });
        }

        let not_yet_frozen = outcomes
            .iter()
            .filter(|(_, pin)| *pin == SegmentPin::PinnedNotYetFrozen)
            .map(|(shard_id, _)| *shard_id)
            .collect();
        Ok(Self {
            set,
            not_yet_frozen,
        })
    }

    /// The record-derived set these pins cover.
    #[must_use]
    pub fn serve_set(&self) -> &ServeSet {
        &self.set
    }

    /// Pinned members that have not frozen yet, so are not servable until
    /// they do.
    #[must_use]
    pub fn not_yet_frozen(&self) -> &[u64] {
        &self.not_yet_frozen
    }
}
