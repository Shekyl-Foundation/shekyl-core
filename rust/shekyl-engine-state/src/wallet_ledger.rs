// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `.wallet`-side ledger aggregator.
//!
//! Bundles the six typed blocks — [`LedgerBlock`], [`BookkeepingBlock`],
//! [`TxMetaBlock`], [`SyncStateBlock`], [`StakingBlock`], and
//! [`SendJournalBlock`] — into a single postcard-serialized payload that
//! the wallet-file orchestrator (commit 2h) stores as Region 2 of the
//! `.wallet` file.
//!
//! # Two-tier versioning
//!
//! Two independent version numbers live in this layout, and they evolve
//! on separate schedules:
//!
//! 1. **Bundle `format_version`**, defined here as
//!    [`WALLET_LEDGER_FORMAT_VERSION`]. Bumps only when the aggregator
//!    layout itself changes — a new top-level block added, removed, or
//!    reordered. All other bundle-wide metadata (if any) is pinned here.
//! 2. **Per-block `block_version`**, defined in each block module. Bumps
//!    when a single block's schema evolves without touching the others.
//!    Each block's load path enforces its own version independently; a
//!    mismatch on any block aborts the whole load.
//!
//! The load path checks both tiers:
//!
//! * First, `format_version` — if it disagrees with the binary, fail with
//!   [`WalletLedgerError::UnsupportedFormatVersion`] before trusting any
//!   inner bytes. Rule-81 ("no silent migration") applies here: we do
//!   not opportunistically try to decode as if it were the current
//!   format.
//! * Then, fan out per-block `check_version()` calls and fail fast on the
//!   first mismatch.
//!
//! # Wire format
//!
//! `postcard` over the six blocks in declared field order plus the
//! bundle `format_version`. Every inner block's `block_version` stays
//! within the block's own postcard frame, so a version bump on one
//! block does not accidentally shift the byte offsets of any other
//! block on disk.
//!
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`SyncStateBlock`]: crate::sync_state_block::SyncStateBlock
//! [`StakingBlock`]: crate::staking_block::StakingBlock
//! [`SendJournalBlock`]: crate::send_journal_block::SendJournalBlock

use serde::{Deserialize, Serialize};

use crate::{
    bookkeeping_block::BookkeepingBlock,
    error::WalletLedgerError,
    ledger_block::LedgerBlock,
    send_journal_block::{AbandonEdge, SendInputRef, SendJournalBlock, SendRecipient, SendState},
    staking_block::StakingBlock,
    sync_state_block::SyncStateBlock,
    tx_meta_block::{TxMetaBlock, TxSecretKey, TxSecretKeys},
};

/// Bundle-level `format_version`.
///
/// At V3.0 genesis the bundle shipped as version `3`; FA-8 ships
/// [`WALLET_LEDGER_FORMAT_VERSION`] `6`. Version `1` (pre-flat-namespace) carried a two-level
/// subaddress index in transfer records and extra bookkeeping maps (a
/// dedicated primary-label slot, per-index labels, and account-level tags).
/// Version `2` flattened the index representation and dropped the
/// account-level tag map.
/// Version `3` extends [`crate::transfer::TransferDetails`] with two
/// optional non-secret fields — `source_ciphertext: Option<HybridCiphertext>`
/// and `output_handle: Option<OutputHandle>` — to support the M3b
/// orchestrator-side handle population pass; pre-M3b records carry
/// `None` in both. Version `4` is the M3d
/// `TransferDetails` secret-field removal shape (paired with
/// `LEDGER_BLOCK_VERSION` 4). Version `5` is FA-2 End-state 5:
/// `BOOKKEEPING_BLOCK_VERSION` 3 (subaddress registry removed) and
/// `LEDGER_BLOCK_VERSION` 5 (`TransferDetails::subaddress` removed).
/// Version `6` is FA-8: `BOOKKEEPING_BLOCK_VERSION` 4 (payment
/// requests), `LEDGER_BLOCK_VERSION` 6 (`ReceiveAttribution` on
/// `TransferDetails`). Version `7` is the primary-claim rename:
/// `BOOKKEEPING_BLOCK_VERSION` 5 (`AddressBookEntry::is_subaddress`
/// deleted).
/// Version `8` adds the archival-staking [`StakingBlock`] as a fifth
/// top-level block (`STAKING_BLOCK_VERSION` 1); the aggregator layout
/// itself grew a block, so the bundle bytes shift and the format
/// version bumps.
/// Version `9` is the claim-era retirement (`LEDGER_BLOCK_VERSION` 7).
/// Version `10` adds `TransferDetails::awaiting_confirmation` — the F14
/// persisted awaiting-confirmation lock (`LEDGER_BLOCK_VERSION` 8,
/// `DAEMON_SUBMIT_VERDICT.md` §2.6).
/// Version `11` deletes `TxSecretKeys::additional`
/// (`TX_META_BLOCK_VERSION` 2, WI-RPC-3 rule-15 dead-store removal —
/// single tx secret scalar per tx, no subaddresses, no producer).
/// Version `12` adds `TransferDetails::spending_tx_hash`
/// (`LEDGER_BLOCK_VERSION` 9, WI-RPC-3 F-9 spend-quadruple leg:
/// confirmed spending txid so `tx_meta.tx_keys` retention stays
/// I-2-live for no-change outbound txs).
/// Version `13` adds the dispatch-authored [`SendJournalBlock`] as a
/// sixth top-level block (`SEND_JOURNAL_BLOCK_VERSION` 1,
/// `WALLET_SEND_RECORD.md` PR-SJ-1); the aggregator layout grew a
/// block, so the bundle bytes shift and the format version bumps.
/// Version `14` appends `SendState::Abandoned`
/// (`SEND_JOURNAL_BLOCK_VERSION` 2, `WALLET_SEND_RECORD.md` PR-SJ-3);
/// the append is encoding-additive (discriminant KAT), the bump is
/// rule-42 snapshot pairing.
/// Version `15` removes `TransferDetails::awaiting_confirmation`
/// (`LEDGER_BLOCK_VERSION` 10, PR-SJ-1b): the F14 lock retires from
/// persisted state — journal facts derive it on demand.
/// Each per-block bump (`LEDGER_BLOCK_VERSION`,
/// `BOOKKEEPING_BLOCK_VERSION`) identifies which block is
/// incompatible at load time; the bundle-level bump exists because
/// the on-disk bundle *bytes* themselves shift whenever any nested
/// type's serialized shape changes — even if the aggregator's
/// top-level layout (number of blocks, their order) is untouched.
/// `.cursor/rules/42-serialization-policy.mdc` and
/// `docs/MID_REWIRE_HARDENING.md §3.4` make the pairing strict: a
/// `wallet_ledger.snap` drift implies a `WALLET_LEDGER_FORMAT_VERSION`
/// bump in the same PR, regardless of whether any direct field of
/// `WalletLedger` was touched.
pub const WALLET_LEDGER_FORMAT_VERSION: u32 = 15;

/// The `.wallet`-side ledger bundle: the six typed blocks + a
/// bundle-level `format_version`.
///
/// Deliberately NOT [`Clone`] at the aggregator level because
/// [`LedgerBlock`] and [`TxMetaBlock`] refuse to be cloned (they own
/// `Zeroize`-ing secrets for which clone semantics are ambiguous).
/// Callers that need a snapshot should re-serialize.
///
/// [`LedgerBlock`]: crate::ledger_block::LedgerBlock
/// [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct WalletLedger {
    /// Bundle-level schema version. Always
    /// [`WALLET_LEDGER_FORMAT_VERSION`] on construction; rejected on
    /// load if it does not match.
    pub format_version: u32,

    /// Scanner-derived on-chain ledger: transfers, tip, reorg window.
    pub ledger: LedgerBlock,

    /// User-facing UX state: primary label and address book.
    pub bookkeeping: BookkeepingBlock,

    /// Per-tx side channel: tx secret keys, notes, attributes, pool
    /// observations.
    pub tx_meta: TxMetaBlock,

    /// Scan anchor + pending-tx tracking + daemon context.
    pub sync_state: SyncStateBlock,

    /// Archival-staking persona bookkeeping: cursor + enabled flag +
    /// the reconcilable live-bond hint.
    pub staking: StakingBlock,

    /// Dispatch-authored send records (`WALLET_SEND_RECORD.md`):
    /// recipients, realized fee, carried input set, lifecycle state.
    /// Outside [`LedgerBlock`] by C7 — survives rescan by construction.
    #[serde(default)]
    pub send_journal: SendJournalBlock,
}

impl WalletLedger {
    /// Fresh, empty wallet ledger pinned to the current format version.
    /// Every inner block starts at its own current `block_version`.
    pub fn empty() -> Self {
        Self {
            format_version: WALLET_LEDGER_FORMAT_VERSION,
            ledger: LedgerBlock::empty(),
            bookkeeping: BookkeepingBlock::empty(),
            tx_meta: TxMetaBlock::empty(),
            sync_state: SyncStateBlock::empty(),
            staking: StakingBlock::empty(),
            send_journal: SendJournalBlock::empty(),
        }
    }

    /// Assemble a wallet ledger from its scan-/UX-/meta-side blocks,
    /// pinning the bundle `format_version`. The dispatch-authored
    /// [`SendJournalBlock`] starts empty — callers that need seeded
    /// rows insert after construction. Caller-supplied blocks keep
    /// their own `block_version` values (already current by
    /// construction through each block's `new` / `empty` constructor).
    pub fn new(
        ledger: LedgerBlock,
        bookkeeping: BookkeepingBlock,
        tx_meta: TxMetaBlock,
        sync_state: SyncStateBlock,
        staking: StakingBlock,
    ) -> Self {
        Self {
            format_version: WALLET_LEDGER_FORMAT_VERSION,
            ledger,
            bookkeeping,
            tx_meta,
            sync_state,
            staking,
            send_journal: SendJournalBlock::empty(),
        }
    }

    /// Serialize the full bundle to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize a full bundle from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. Enforces the bundle
    /// `format_version` gate, every inner block's `block_version`
    /// gate, and the aggregator-level invariants owned by
    /// [`crate::invariants`]. Fails fast on the first mismatch so the
    /// diagnostic points at the earliest failure rather than a
    /// downstream symptom.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let ledger: Self = postcard::from_bytes(bytes)?;
        ledger.check_format_version()?;
        ledger.check_all_block_versions()?;
        ledger.check_invariants()?;
        Ok(ledger)
    }

    /// Bundle-level version gate.
    pub fn check_format_version(&self) -> Result<(), WalletLedgerError> {
        if self.format_version != WALLET_LEDGER_FORMAT_VERSION {
            return Err(WalletLedgerError::UnsupportedFormatVersion {
                file: self.format_version,
                binary: WALLET_LEDGER_FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// Fan out per-block version checks. Ordered ledger → bookkeeping
    /// → tx_meta → sync_state → staking → send_journal so failure diagnostics are
    /// predictable.
    pub fn check_all_block_versions(&self) -> Result<(), WalletLedgerError> {
        self.ledger.check_version()?;
        self.bookkeeping.check_version()?;
        self.tx_meta.check_version()?;
        self.sync_state.check_version()?;
        self.staking.check_version()?;
        self.send_journal.check_version()?;
        Ok(())
    }

    /// Persist the WI-RPC-3 retention record for a dispatched tx in one
    /// atomic write: the per-tx secret enters `tx_meta.tx_keys` and the
    /// txid enters `sync_state.pending_tx_hashes` — the I-2 live
    /// reference the secret is born with (`docs/api/wallet_rpc.yaml`
    /// OUTBOUND PREREQUISITE pin 1: the record exists before the tx
    /// bytes can reach the daemon).
    pub fn record_retained_tx_key(&mut self, txid: [u8; 32], secret: TxSecretKey) {
        self.tx_meta
            .tx_keys
            .insert(txid, TxSecretKeys { primary: secret });
        if !self.sync_state.pending_tx_hashes.contains(&txid) {
            self.sync_state.pending_tx_hashes.push(txid);
        }
    }

    /// Birth the send-journal row for a dispatch (same guard as
    /// [`Self::record_retained_tx_key`] — pin-1 form). See
    /// [`SendJournalBlock::record_dispatched`].
    pub fn record_dispatched_send(
        &mut self,
        txid: [u8; 32],
        fee: u64,
        recipients: Vec<SendRecipient>,
        inputs: Vec<SendInputRef>,
    ) {
        let height = self.ledger.height();
        self.send_journal
            .record_dispatched(txid, height, fee, recipients, inputs);
    }

    /// Accepting-verdict write for the journal (`WALLET_SEND_RECORD.md`
    /// C2): stamp `lock_baseline` on the owning row, then re-derive the
    /// F14 cache from journal facts. Fresh accept and `AlreadyInChain`
    /// both route here — the only difference is the baseline height —
    /// so the dual-write of lock + baseline cannot diverge.
    ///
    /// Panics if no journal row exists: dispatch always births the row
    /// before the bytes leave for the daemon.
    pub fn stamp_send_lock_baseline(&mut self, txid: &[u8; 32], baseline: u64) {
        assert!(
            self.send_journal.stamp_lock_baseline(txid, baseline),
            "send-journal row must exist before an accepting verdict (born at dispatch)"
        );
        // Full reconcile: confirm edges handle the rare race where the
        // spend was already observed during the submit round-trip;
        // re-derivation places the F14 locks the field still carries
        // until PR-SJ-1b.
        self.reconcile_send_journal(None);
    }

    /// The user-authored abandon operation (`WALLET_SEND_RECORD.md`
    /// P3-4 / SJ-DQ-8): the journal edge
    /// `Dispatched | PresumedDead → Abandoned` **plus** the I-2
    /// reference migration — the txid leaves
    /// `sync_state.pending_tx_hashes` (the pending set stays a true
    /// live-work set) and the journal row itself becomes the retained
    /// tx secret's live reference
    /// ([`SendState::holds_tx_key_retention`]). `tx_meta.tx_keys` is
    /// never touched (C2: proof material has its own lifecycle — the
    /// named hazard is deleting proof material for a tx that later
    /// confirms).
    ///
    /// Both writes happen under the caller's single ledger guard, so a
    /// crash never splits the edge from the migration (the same
    /// crash-ordering contract every other journal edge rides).
    /// Idempotent: re-abandoning an `Abandoned` row re-runs only the
    /// (idempotent) pending removal.
    ///
    /// Returns the edge outcome plus `was_pending` so a fail-closed
    /// caller can roll back via [`Self::unabandon_send`] when the
    /// durable save fails. Callers that pair this with a durable save
    /// **must** hold the same write guard across edge + save + optional
    /// rollback — abandon does not touch baseline or F14 locks, but a
    /// concurrent refresh/watchdog under a released guard could.
    pub fn abandon_send(&mut self, txid: &[u8; 32]) -> (AbandonEdge, bool) {
        let edge = self.send_journal.mark_abandoned(txid);
        match edge {
            AbandonEdge::Applied { .. } | AbandonEdge::AlreadyAbandoned => {
                let before = self.sync_state.pending_tx_hashes.len();
                self.sync_state.pending_tx_hashes.retain(|h| h != txid);
                let was_pending = self.sync_state.pending_tx_hashes.len() != before;
                (edge, was_pending)
            }
            AbandonEdge::NotFound | AbandonEdge::Forbidden { .. } => (edge, false),
        }
    }

    /// Fail-closed rollback of [`Self::abandon_send`] for a caller whose
    /// durable save failed: restore the previous row state and, when the
    /// abandon removed the pending reference, re-add it.
    ///
    /// **Exclusive-guard contract:** must run under the same write guard
    /// that applied `abandon_send` and attempted the save. Under that
    /// contract no concurrent merge/watchdog can have advanced the row
    /// (confirm) or cleared its baseline, so restoring `state` + pending
    /// is a full pre-abandon restore — abandon itself never mutates
    /// `lock_baseline` or F14 locks.
    ///
    /// Defense in depth: if the row is no longer `Abandoned` (a caller
    /// released the guard and a concurrent path advanced it), this is a
    /// no-op rather than clobbering a confirm or re-adding a stale
    /// pending reference.
    pub fn unabandon_send(&mut self, txid: &[u8; 32], previous: SendState, was_pending: bool) {
        let restored = if let Some(row) = self.send_journal.rows.get_mut(txid) {
            if matches!(row.state, SendState::Abandoned) {
                row.state = previous;
                true
            } else {
                false
            }
        } else {
            false
        };
        if restored && was_pending && !self.sync_state.pending_tx_hashes.contains(txid) {
            self.sync_state.pending_tx_hashes.push(*txid);
        }
    }

    /// Merge post-passes that must share the scan-merge write guard
    /// (crash-ordering: a trigger and its edges persist together):
    /// WI-RPC-3 retention reconciliation (I-2) and the send-journal
    /// reorg/confirm/lock re-derivation (I-5 / P3-1). Called once from
    /// the engine merge path so `merge.rs` does not grow a second
    /// post-pass call site for every new ledger edge.
    pub fn reconcile_after_scan_merge(&mut self, reorg_fork_height: Option<u64>) {
        self.reconcile_tx_key_retention(reorg_fork_height.is_some());
        self.reconcile_send_journal(reorg_fork_height);
    }

    /// Send-journal reconciler (`WALLET_SEND_RECORD.md` P3-1) — the
    /// merge post-pass that keeps the journal and the F14 derived
    /// cache agreeing, and the mechanism that makes rescan
    /// re-application free. Runs under the same write guard as the
    /// scan merge (crash-ordering: a trigger and its edge persist
    /// together), every merge, idempotently:
    ///
    /// 1. **Reorg back-edges**: a `Confirmed { height ≥ fork }` row
    ///    returns to `Dispatched` — the confirming block is gone;
    ///    refresh re-observes or the watchdog resolves. The row keeps
    ///    its `lock_baseline` so step 3 can re-place the F14 locks
    ///    (baseline is cleared only by a deliberate watchdog release).
    /// 2. **Confirm edges** (refresh-authoritative, C3): a transfer
    ///    whose observed `spending_tx_hash` matches a journal row
    ///    moves the row to `Confirmed { spent_height }`. A
    ///    `PresumedDead` row flips here too — the loud late
    ///    confirmation (`PresumedDead` was only ever display). First
    ///    observed height wins; baseline is retained for a later reorg
    ///    re-derivation.
    /// (The former step 3 — per-row lock re-derivation writes — retired
    /// with the `awaiting_confirmation` field at PR-SJ-1b: consumers
    /// derive the lock set on demand from exactly the facts this
    /// reconciler maintains, `SendJournalBlock::derive_f14_locks`, so
    /// there is no cache left to re-apply. The SJ-DQ-4 self-link
    /// defence across a rescan wipe now holds by construction: the
    /// journal survives the wipe and the derivation reads it directly.)
    pub fn reconcile_send_journal(&mut self, reorg_fork_height: Option<u64>) {
        let Self {
            ledger,
            send_journal,
            ..
        } = self;

        if let Some(fork) = reorg_fork_height {
            for row in send_journal.rows.values_mut() {
                if let SendState::Confirmed { height } = row.state {
                    if height >= fork {
                        row.state = SendState::Dispatched;
                    }
                }
            }
        }

        for td in &ledger.transfers {
            let (Some(spending_tx), Some(height)) = (&td.spending_tx_hash, td.spent_height) else {
                continue;
            };
            if let Some(row) = send_journal.rows.get_mut(&spending_tx.to_bytes()) {
                if !matches!(row.state, SendState::Confirmed { .. }) {
                    row.state = SendState::Confirmed { height };
                }
            }
        }
    }

    /// Retire the retention record for a tx the daemon *definitely
    /// refused* (terminal / retryable submit verdict — provably
    /// unrelayed under single-egress, `DAEMON_SUBMIT_VERDICT.md` §2.5):
    /// exposure never began, so the record mirrors a never-submitted
    /// build. `TxSecretKey` zeroizes on drop; removal is the wipe.
    pub fn retire_retained_tx_key(&mut self, txid: &[u8; 32]) {
        self.tx_meta.tx_keys.remove(txid);
        self.sync_state.pending_tx_hashes.retain(|h| h != txid);
    }

    /// WI-RPC-3 retention reconciliation (`docs/api/wallet_rpc.yaml`
    /// OUTBOUND PREREQUISITE, lifecycle pin 2: "DEATH follows I-2 with
    /// the reference set closed by the spend-quadruple").
    ///
    /// Called by the orchestrator after every refresh merge (once the
    /// scan result — including spend detection, which writes
    /// `TransferDetails::spending_tx_hash` — has been applied), with
    /// `reorg_rewound` saying whether that merge performed a reorg
    /// rewind. Two directions:
    ///
    /// 1. **Pending → confirmed.** A txid in
    ///    `sync_state.pending_tx_hashes` that now has a chain reference
    ///    (a transfer row's own `tx_hash`, or a spent row's
    ///    `spending_tx_hash`) has been mined; the pending record's job
    ///    is done and it is removed. The retained secret's liveness
    ///    transfers seamlessly to the chain reference (I-2 holds before
    ///    and after).
    /// 2. **Orphan handling.** A `tx_meta.tx_keys` entry with *no*
    ///    remaining live reference — not chain-referenced, not in the
    ///    scanned pool, not pending, and not held by a journal row in a
    ///    non-terminal-or-abandoned state (the P3-4 leg, which also
    ///    covers the broadcast-accept → confirmation window the retired
    ///    F14-lock leg used to cover). On a
    ///    **rewind** merge such an entry is *not* dead:
    ///    the rewind itself removed its chain references (rows at or
    ///    above the fork, spend un-marking), and the common outcome is
    ///    re-confirmation on the new chain a few blocks later — so the
    ///    txid is **re-pended** instead of collected, returning it to
    ///    the normal lifecycle (direction 1 retires it again when the
    ///    tx re-confirms; a tx that never re-confirms leaves a bounded
    ///    safe-direction residue, the retention policy's deliberate
    ///    trade). On a non-rewind merge no unreferenced entry can
    ///    legitimately exist — the record is created with its pending
    ///    reference in one atomic write and every retiring path leaves
    ///    a successor reference — so collection is the I-2 safety net
    ///    it claims to be.
    ///
    /// Returns `(pending_confirmed, secrets_collected)` for the
    /// caller's diagnostics.
    pub fn reconcile_tx_key_retention(&mut self, reorg_rewound: bool) -> (usize, usize) {
        use std::collections::HashSet;

        // Fast path: with no retained secret and no pending record
        // there is provably nothing to reconcile in either direction —
        // skip the O(transfers) live-set build this method would
        // otherwise pay under the merge's write guard on every refresh
        // (the common receive-only-wallet shape).
        if self.tx_meta.tx_keys.is_empty() && self.sync_state.pending_tx_hashes.is_empty() {
            return (0, 0);
        }

        // Chain references: rebuilt from chain data by any rescan, so
        // retention keyed on them is rescan-coherent by construction.
        let mut chain_referenced: HashSet<[u8; 32]> =
            HashSet::with_capacity(self.ledger.transfers.len() * 2);
        for t in &self.ledger.transfers {
            chain_referenced.insert(t.tx_hash.to_bytes());
            if let Some(spending) = &t.spending_tx_hash {
                chain_referenced.insert(spending.to_bytes());
            }
        }

        // Direction 1: confirmed txids leave the pending list.
        let before = self.sync_state.pending_tx_hashes.len();
        self.sync_state
            .pending_tx_hashes
            .retain(|h| !chain_referenced.contains(h));
        let pending_confirmed = before - self.sync_state.pending_tx_hashes.len();

        // Direction 2: the live set mirrors I-2's exactly
        // (invariants::check_tx_keys_no_orphans).
        let mut live = chain_referenced;
        for h in self.tx_meta.scanned_pool_txs.keys() {
            live.insert(*h);
        }
        for h in &self.sync_state.pending_tx_hashes {
            live.insert(*h);
        }
        // Journal leg (P3-4): a row that holds tx-key retention is itself
        // a live reference — after `abandon_send` migrates the pending
        // entry, this leg keeps the retained secret from being collected
        // as an orphan.
        for (h, row) in &self.send_journal.rows {
            if row.state.holds_tx_key_retention() {
                live.insert(*h);
            }
        }

        if reorg_rewound {
            // Rewind direction: resurrect the pending reference instead
            // of collecting — the references died with the orphaned
            // blocks, not with the tx, and a deleted secret cannot be
            // rebuilt if the tx re-confirms. `!live` implies the txid is
            // not currently pending, so a plain push cannot duplicate.
            let orphaned: Vec<[u8; 32]> = self
                .tx_meta
                .tx_keys
                .keys()
                .filter(|h| !live.contains(*h))
                .copied()
                .collect();
            for h in orphaned {
                self.sync_state.pending_tx_hashes.push(h);
            }
            return (pending_confirmed, 0);
        }

        let before = self.tx_meta.tx_keys.len();
        // `TxSecretKey` zeroizes on drop; removal is the wipe.
        self.tx_meta.tx_keys.retain(|h, _| live.contains(h));
        let secrets_collected = before - self.tx_meta.tx_keys.len();

        (pending_confirmed, secrets_collected)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bookkeeping_block::BOOKKEEPING_BLOCK_VERSION, ledger_block::LEDGER_BLOCK_VERSION,
        staking_block::STAKING_BLOCK_VERSION, sync_state_block::SYNC_STATE_BLOCK_VERSION,
        tx_meta_block::TX_META_BLOCK_VERSION,
    };

    #[test]
    fn empty_bundle_roundtrips_and_pins_versions() {
        let w = WalletLedger::empty();
        assert_eq!(w.format_version, WALLET_LEDGER_FORMAT_VERSION);
        assert_eq!(w.ledger.block_version, LEDGER_BLOCK_VERSION);
        assert_eq!(w.bookkeeping.block_version, BOOKKEEPING_BLOCK_VERSION);
        assert_eq!(w.tx_meta.block_version, TX_META_BLOCK_VERSION);
        assert_eq!(w.sync_state.block_version, SYNC_STATE_BLOCK_VERSION);
        assert_eq!(w.staking.block_version, STAKING_BLOCK_VERSION);

        let bytes = w.to_postcard_bytes().expect("serialize");
        let back = WalletLedger::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back.format_version, WALLET_LEDGER_FORMAT_VERSION);
        assert_eq!(back.ledger.block_version, LEDGER_BLOCK_VERSION);
        assert_eq!(back.bookkeeping.block_version, BOOKKEEPING_BLOCK_VERSION);
        assert_eq!(back.tx_meta.block_version, TX_META_BLOCK_VERSION);
        assert_eq!(back.sync_state.block_version, SYNC_STATE_BLOCK_VERSION);
        assert_eq!(back.staking.block_version, STAKING_BLOCK_VERSION);
    }

    #[test]
    fn empty_bundle_is_byte_stable() {
        let w = WalletLedger::empty();
        let bytes1 = w.to_postcard_bytes().expect("serialize1");
        let back = WalletLedger::from_postcard_bytes(&bytes1).expect("deserialize");
        let bytes2 = back.to_postcard_bytes().expect("serialize2");
        assert_eq!(
            bytes1, bytes2,
            "bundle postcard encoding must be byte-stable"
        );
    }

    #[test]
    fn wrong_format_version_is_refused() {
        // Bundle version mismatch is a distinct error from any block
        // version mismatch, even though the wire shape is identical.
        let mut w = WalletLedger::empty();
        w.format_version = 999;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedFormatVersion { file, binary } => {
                assert_eq!(file, 999);
                assert_eq!(binary, WALLET_LEDGER_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn inner_ledger_block_version_bump_is_refused_by_aggregator() {
        // A stale `LedgerBlock.block_version` inside an otherwise-fresh
        // bundle must still abort the whole load. The aggregator does
        // NOT accept the ledger block silently just because the bundle
        // version is current.
        let mut w = WalletLedger::empty();
        w.ledger.block_version = 42;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "ledger");
                assert_eq!(file, 42);
                assert_eq!(binary, LEDGER_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(ledger), got {other:?}"),
        }
    }

    #[test]
    fn inner_bookkeeping_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.bookkeeping.block_version = 7;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "bookkeeping");
                assert_eq!(file, 7);
                assert_eq!(binary, BOOKKEEPING_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(bookkeeping), got {other:?}"),
        }
    }

    #[test]
    fn inner_tx_meta_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.tx_meta.block_version = 1234;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "tx_meta");
                assert_eq!(file, 1234);
                assert_eq!(binary, TX_META_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(tx_meta), got {other:?}"),
        }
    }

    #[test]
    fn inner_sync_state_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.sync_state.block_version = 99;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "sync_state");
                assert_eq!(file, 99);
                assert_eq!(binary, SYNC_STATE_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(sync_state), got {other:?}"),
        }
    }

    #[test]
    fn inner_staking_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.staking.block_version = 314;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "staking");
                assert_eq!(file, 314);
                assert_eq!(binary, STAKING_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(staking), got {other:?}"),
        }
    }

    #[test]
    fn format_version_check_runs_before_block_version_checks() {
        // If BOTH the bundle version AND an inner block version are
        // wrong, the format-version gate wins — the aggregator fails
        // fast before trusting any inner block's bytes.
        let mut w = WalletLedger::empty();
        w.format_version = 42;
        w.ledger.block_version = 42;
        let bytes = w.to_postcard_bytes().expect("serialize");
        let err = WalletLedger::from_postcard_bytes(&bytes).unwrap_err();
        match err {
            WalletLedgerError::UnsupportedFormatVersion { file, binary } => {
                assert_eq!(file, 42);
                assert_eq!(binary, WALLET_LEDGER_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedFormatVersion to win ordering, got {other:?}"),
        }
    }

    #[test]
    fn truncated_postcard_input_is_refused() {
        let w = WalletLedger::empty();
        let bytes = w.to_postcard_bytes().expect("serialize");
        let chopped = &bytes[..bytes.len() / 2];
        let is_postcard = matches!(
            WalletLedger::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        );
        assert!(is_postcard, "truncated input must hit the postcard branch");
    }

    // ── WI-RPC-3 retention reconciliation ─────────────────────────────

    fn mk_transfer(seed: u8, block_height: u64) -> crate::transfer::TransferDetails {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
        crate::transfer::TransferDetails {
            tx_hash: shekyl_types::TxHash::from_bytes([seed; 32]),
            internal_output_index: u64::from(seed),
            global_output_index: u64::from(seed),
            block_height,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: shekyl_curve_primitives::Commitment::new(Scalar::ONE, 1_000),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: block_height + crate::transfer::SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: crate::ReceiveAttribution::default(),
        }
    }

    fn insert_secret(w: &mut WalletLedger, txid: [u8; 32]) {
        w.tx_meta.tx_keys.insert(
            txid,
            crate::tx_meta_block::TxSecretKeys {
                primary: crate::tx_meta_block::TxSecretKey::new(zeroize::Zeroizing::new(
                    [0x5A; 32],
                )),
            },
        );
    }

    /// Direction 1: a pending txid whose spend was confirmed on-chain
    /// (spent row records `spending_tx_hash`) leaves the pending list;
    /// the secret survives, now chain-referenced. I-2 holds throughout.
    #[test]
    fn reconcile_moves_confirmed_pending_to_chain_reference() {
        let txid = [0x77; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        w.sync_state.pending_tx_hashes.push(txid);
        w.check_invariants().expect("pending ref keeps I-2");

        // Refresh observes the spend: the consumed output's row records
        // the spending txid (the no-change case — no owned output row
        // for `txid` itself).
        let mut spent_row = mk_transfer(0x11, 10);
        spent_row.spent = true;
        spent_row.spent_height = Some(20);
        spent_row.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [0x33; 32],
        ));
        spent_row.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
        w.ledger.transfers.push(spent_row);
        w.ledger.tip.synced_height = 30;

        let (confirmed, collected) = w.reconcile_tx_key_retention(false);
        assert_eq!(confirmed, 1, "pending record retired at confirmation");
        assert_eq!(collected, 0, "secret stays chain-referenced");
        assert!(w.sync_state.pending_tx_hashes.is_empty());
        assert!(w.tx_meta.tx_keys.contains_key(&txid));
        w.check_invariants().expect("I-2 after reconcile");
    }

    /// Direction 2, non-rewind merge: a secret with no remaining
    /// reference is collected — removal is the zeroizing drop.
    #[test]
    fn reconcile_collects_orphaned_secret() {
        let txid = [0x77; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        // No transfers, no pool entry, no pending record: the tx has
        // lost every live reference.
        let (confirmed, collected) = w.reconcile_tx_key_retention(false);
        assert_eq!(confirmed, 0);
        assert_eq!(collected, 1, "orphaned secret is collected");
        assert!(w.tx_meta.tx_keys.is_empty());
        w.check_invariants().expect("I-2 after collection");
    }

    /// Direction 2, rewind merge: an entry orphaned by the rewind is
    /// re-pended, not collected — the tx commonly re-confirms on the
    /// new chain, and a deleted secret cannot serve that proof. The
    /// re-pended entry then retires through direction 1 like any
    /// pending tx once the re-confirmation is observed.
    #[test]
    fn reconcile_repends_rewind_orphan_instead_of_collecting() {
        let txid = [0x77; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        // Post-rewind shape: the confirming rows are gone, the pending
        // record was retired at first confirmation — no reference left.
        let (confirmed, collected) = w.reconcile_tx_key_retention(true);
        assert_eq!(confirmed, 0);
        assert_eq!(collected, 0, "rewind merge never collects");
        assert!(
            w.tx_meta.tx_keys.contains_key(&txid),
            "the secret survives the rewind window"
        );
        assert_eq!(
            w.sync_state.pending_tx_hashes,
            vec![txid],
            "the txid is re-pended exactly once"
        );
        w.check_invariants().expect("I-2 after re-pend");

        // Re-confirmation on the new chain retires the re-pended record
        // through the ordinary direction-1 path.
        let mut spent_row = mk_transfer(0x11, 10);
        spent_row.spent = true;
        spent_row.spent_height = Some(22);
        spent_row.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [0x33; 32],
        ));
        spent_row.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
        w.ledger.transfers.push(spent_row);
        w.ledger.tip.synced_height = 32;
        let (confirmed, collected) = w.reconcile_tx_key_retention(false);
        assert_eq!(confirmed, 1, "re-pended record retires at re-confirmation");
        assert_eq!(collected, 0);
        assert!(w.tx_meta.tx_keys.contains_key(&txid));
        w.check_invariants().expect("I-2 after re-confirmation");
    }

    /// The dispatch-persist / definite-refusal helper pair: `record`
    /// writes secret + pending reference atomically (and is idempotent
    /// on the pending side); `retire` removes both.
    #[test]
    fn record_and_retire_retained_tx_key_round_trip() {
        let txid = [0x77; 32];
        let mut w = WalletLedger::empty();
        w.record_retained_tx_key(
            txid,
            crate::tx_meta_block::TxSecretKey::new(zeroize::Zeroizing::new([0x5A; 32])),
        );
        w.check_invariants().expect("record is I-2-atomic");
        w.record_retained_tx_key(
            txid,
            crate::tx_meta_block::TxSecretKey::new(zeroize::Zeroizing::new([0x5B; 32])),
        );
        assert_eq!(
            w.sync_state.pending_tx_hashes,
            vec![txid],
            "re-record never duplicates the pending reference"
        );

        w.retire_retained_tx_key(&txid);
        assert!(w.tx_meta.tx_keys.is_empty());
        assert!(w.sync_state.pending_tx_hashes.is_empty());
        w.check_invariants().expect("retire leaves no orphan");
    }

    /// A secret held live only by a lock-bearing journal row is not
    /// collected: the spend is network-exposed but unconfirmed, and
    /// the pending record may already be gone. (Formerly the F14-lock
    /// leg; since PR-SJ-1b the journal leg carries this window.)
    #[test]
    fn reconcile_keeps_secret_under_lock_bearing_journal_row() {
        let txid = [0x77; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        w.ledger.transfers.push(mk_transfer(0x11, 10));
        w.ledger.tip.synced_height = 30;
        {
            use crate::send_journal_block::{SendInputRef, SendRecord, SendState};
            w.send_journal.rows.insert(
                txid,
                SendRecord {
                    dispatched_at_height: 20,
                    fee: 5,
                    recipients: Vec::new(),
                    change_amount: 0,
                    inputs: vec![SendInputRef {
                        gindex: 0x11,
                        amount: 1,
                    }],
                    lock_baseline: Some(25),
                    state: SendState::Dispatched,
                },
            );
        }

        let (confirmed, collected) = w.reconcile_tx_key_retention(false);
        assert_eq!(confirmed, 0);
        assert_eq!(collected, 0, "journal-held secret survives");
        assert!(w.tx_meta.tx_keys.contains_key(&txid));
        w.check_invariants().expect("I-2 with the journal leg");
    }

    /// Accepting-verdict path: stamping the journal baseline is the
    /// sole write (C2) — the derived lock view arms with it, and
    /// nothing is written to any ledger row. This is the site both
    /// fresh accept and AlreadyInChain share.
    #[test]
    fn stamp_send_lock_baseline_arms_the_derived_view() {
        use crate::send_journal_block::{SendInputRef, SendRecipient};

        let txid = [0x44; 32];
        let mut w = WalletLedger::empty();
        let mut unlocked = mk_transfer(0x41, 10);
        unlocked.global_output_index = 300;
        w.ledger.transfers.push(unlocked);
        w.ledger.tip.synced_height = 30;
        w.record_dispatched_send(
            txid,
            5,
            vec![SendRecipient {
                address: "shekyl1example".to_owned(),
                amount: 1,
            }],
            vec![SendInputRef {
                gindex: 300,
                amount: 10,
            }],
        );
        assert!(
            w.send_journal.derive_f14_locks().is_empty(),
            "dispatch does not arm the lock — only an accepting verdict does"
        );

        w.stamp_send_lock_baseline(&txid, 25);
        let locks = w.send_journal.derive_f14_locks();
        let lock = locks.get(&300).expect("stamp arms the derived F14 lock");
        assert_eq!(lock.tx_hash.to_bytes(), txid);
        assert_eq!(lock.accepted_at_height, 25);
        assert_eq!(w.send_journal.rows[&txid].lock_baseline, Some(25));
        assert!(
            !w.ledger.transfers[0].is_spendable(30, locks.contains_key(&300)),
            "the armed lock excludes the carried input from selection"
        );
        w.check_invariants().expect("invariants hold after stamp");
    }

    /// The derived lock view's consumer-side precedence (PR-SJ-1b): a
    /// spent carried input is superseded by confirmed evidence at every
    /// consumer (`is_spendable` checks `spent` first), a not-yet-replayed
    /// input locks the moment its row reappears (nothing to re-apply —
    /// the derivation reads the journal, which survives the wipe), and
    /// the derivation itself is pure.
    #[test]
    fn derived_locks_respect_spent_precedence_and_survive_replay_gaps() {
        use crate::send_journal_block::{SendInputRef, SendRecord, SendState};

        let txid = [0x42; 32];
        let mut w = WalletLedger::empty();
        let mut unlocked = mk_transfer(0x21, 10);
        unlocked.global_output_index = 100;
        let mut spent = mk_transfer(0x22, 10);
        spent.global_output_index = 101;
        spent.spent = true;
        spent.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [9u8; 32],
        ));
        spent.spent_height = Some(12);
        w.ledger.transfers.push(unlocked);
        w.ledger.transfers.push(spent);
        w.ledger.tip.synced_height = 30;
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 20,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: vec![
                    SendInputRef {
                        gindex: 100,
                        amount: 1,
                    },
                    SendInputRef {
                        gindex: 101,
                        amount: 1,
                    },
                    SendInputRef {
                        gindex: 999,
                        amount: 1,
                    }, // not replayed yet
                ],
                lock_baseline: Some(25),
                state: SendState::Dispatched,
            },
        );

        let locks = w.send_journal.derive_f14_locks();
        assert_eq!(
            locks.keys().copied().collect::<Vec<_>>(),
            vec![100, 101, 999],
            "the derivation carries every journal input, replayed or not"
        );
        assert!(
            !w.ledger.transfers[0].is_spendable(30, locks.contains_key(&100)),
            "unspent carried input is excluded from selection"
        );
        assert!(
            !w.ledger.transfers[1].is_spendable(30, locks.contains_key(&101)),
            "spent input stays unspendable via `spent`, not the lock"
        );
        assert_eq!(
            locks,
            w.send_journal.derive_f14_locks(),
            "derivation is pure"
        );
        w.check_invariants().expect("invariants hold");
    }

    /// P3-4: `abandon_send` is the journal edge plus the I-2 reference
    /// migration in one guard-atomic operation — pending entry removed,
    /// `tx_keys` untouched, the journal row now the live reference
    /// (retention reconcile does not collect), idempotent on re-call.
    #[test]
    fn abandon_send_migrates_the_retention_reference() {
        use crate::send_journal_block::{AbandonEdge, SendInputRef, SendRecord, SendState};

        let txid = [0x66; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        w.sync_state.pending_tx_hashes.push(txid);
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 20,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: vec![SendInputRef {
                    gindex: 7,
                    amount: 1,
                }],
                lock_baseline: None,
                state: SendState::PresumedDead,
            },
        );
        w.check_invariants().expect("pre-abandon shape is valid");

        let (edge, was_pending) = w.abandon_send(&txid);
        assert_eq!(
            edge,
            AbandonEdge::Applied {
                previous: SendState::PresumedDead
            }
        );
        assert!(was_pending, "the pending entry was migrated");
        assert!(w.sync_state.pending_tx_hashes.is_empty());
        assert_eq!(w.send_journal.rows[&txid].state, SendState::Abandoned);
        assert!(
            w.tx_meta.tx_keys.contains_key(&txid),
            "keys retained (C2) — abandon never touches proof material"
        );
        w.check_invariants()
            .expect("the journal row is the I-2 reference after migration");

        // The merge reconciler must not collect the journal-held secret.
        let (confirmed, collected) = w.reconcile_tx_key_retention(false);
        assert_eq!((confirmed, collected), (0, 0));
        assert!(w.tx_meta.tx_keys.contains_key(&txid));

        // Idempotent re-call: no edge, nothing else changes.
        let (edge, was_pending) = w.abandon_send(&txid);
        assert_eq!(edge, AbandonEdge::AlreadyAbandoned);
        assert!(!was_pending);

        // Unknown txid is named, not collapsed.
        assert_eq!(w.abandon_send(&[0xEE; 32]), (AbandonEdge::NotFound, false));
    }

    /// The fail-closed rollback restores exactly the pre-abandon shape:
    /// previous state back on the row, pending reference re-added.
    #[test]
    fn unabandon_send_restores_the_pre_abandon_shape() {
        use crate::send_journal_block::{AbandonEdge, SendInputRef, SendRecord, SendState};

        let txid = [0x67; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        w.sync_state.pending_tx_hashes.push(txid);
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 20,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: vec![SendInputRef {
                    gindex: 7,
                    amount: 1,
                }],
                lock_baseline: None,
                state: SendState::Dispatched,
            },
        );

        let (edge, was_pending) = w.abandon_send(&txid);
        let AbandonEdge::Applied { previous } = edge else {
            panic!("expected Applied, got {edge:?}");
        };
        w.unabandon_send(&txid, previous, was_pending);

        assert_eq!(w.send_journal.rows[&txid].state, SendState::Dispatched);
        assert_eq!(w.sync_state.pending_tx_hashes, vec![txid]);
        w.check_invariants().expect("rollback restores I-2");
    }

    /// Defense in depth: if a concurrent path advanced the row past
    /// `Abandoned` before rollback, `unabandon_send` must not clobber
    /// the confirm or re-introduce a stale pending reference.
    #[test]
    fn unabandon_send_is_noop_when_row_already_advanced() {
        use crate::send_journal_block::{SendInputRef, SendRecord, SendState};

        let txid = [0x68; 32];
        let mut w = WalletLedger::empty();
        insert_secret(&mut w, txid);
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 20,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: vec![SendInputRef {
                    gindex: 7,
                    amount: 1,
                }],
                lock_baseline: None,
                state: SendState::Confirmed { height: 30 },
            },
        );

        w.unabandon_send(&txid, SendState::Dispatched, true);

        assert_eq!(
            w.send_journal.rows[&txid].state,
            SendState::Confirmed { height: 30 },
            "confirm must not be clobbered by a late unabandon"
        );
        assert!(
            w.sync_state.pending_tx_hashes.is_empty(),
            "stale pending must not be re-added over a confirmed row"
        );
    }

    /// P3-1's lock-bearing set is non-terminal-or-abandoned: an
    /// `Abandoned` row with a retained baseline keeps its carried
    /// input locked in the derived view (the self-link defence for an
    /// abandoned-but-still-landable send), while a released row
    /// (baseline `None`) derives no lock. Since PR-SJ-1b nothing
    /// re-applies — the derivation reads the journal directly.
    #[test]
    fn derived_locks_cover_abandoned_rows_with_baseline() {
        use crate::send_journal_block::{SendInputRef, SendRecord, SendState};

        let armed = [0x51; 32];
        let released = [0x52; 32];
        let mut w = WalletLedger::empty();
        let mut a = mk_transfer(0x21, 10);
        a.global_output_index = 400;
        let mut b = mk_transfer(0x22, 10);
        b.global_output_index = 401;
        w.ledger.transfers.push(a);
        w.ledger.transfers.push(b);
        w.ledger.tip.synced_height = 30;
        for (txid, gindex, baseline) in [(armed, 400, Some(25)), (released, 401, None)] {
            w.send_journal.rows.insert(
                txid,
                SendRecord {
                    dispatched_at_height: 20,
                    fee: 5,
                    recipients: Vec::new(),
                    change_amount: 0,
                    inputs: vec![SendInputRef { gindex, amount: 1 }],
                    lock_baseline: baseline,
                    state: SendState::Abandoned,
                },
            );
        }

        let locks = w.send_journal.derive_f14_locks();
        let lock = locks
            .get(&400)
            .expect("abandoned-with-baseline derives its lock");
        assert_eq!(lock.tx_hash.to_bytes(), armed);
        assert_eq!(lock.accepted_at_height, 25);
        assert!(
            !locks.contains_key(&401),
            "a released abandoned row (baseline None) derives no lock"
        );
        assert!(
            !w.ledger.transfers[0].is_spendable(30, locks.contains_key(&400)),
            "the armed abandoned row's input stays excluded from selection"
        );
        assert!(
            w.ledger.transfers[1].is_spendable(30, locks.contains_key(&401)),
            "the released row's input is selectable again"
        );
        w.check_invariants().expect("invariants hold");
    }

    /// P3-4: a late confirmation un-abandons loudly — the confirm edge
    /// flips `Abandoned → Confirmed` rather than staying wrong.
    #[test]
    fn reconcile_send_journal_unabandons_on_late_confirmation() {
        use crate::send_journal_block::{SendRecord, SendState};

        let txid = [0x53; 32];
        let mut w = WalletLedger::empty();
        let mut spent = mk_transfer(0x31, 10);
        spent.global_output_index = 500;
        spent.spent = true;
        spent.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [7u8; 32],
        ));
        spent.spent_height = Some(19);
        spent.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
        w.ledger.transfers.push(spent);
        w.ledger.tip.synced_height = 30;
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 15,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: Vec::new(),
                lock_baseline: None,
                state: SendState::Abandoned,
            },
        );

        w.reconcile_send_journal(None);
        assert_eq!(
            w.send_journal.rows[&txid].state,
            SendState::Confirmed { height: 19 },
            "late confirmation un-abandons the row"
        );
    }

    /// P3-1: confirm edges are refresh-authoritative (observed
    /// `spending_tx_hash` moves the row to Confirmed — including a loud
    /// late confirmation out of PresumedDead), and a reorg at/below the
    /// confirming height returns the row to Dispatched.
    #[test]
    fn reconcile_send_journal_confirms_reorgs_and_unpresumes() {
        use crate::send_journal_block::{SendRecord, SendState};

        let txid = [0x43; 32];
        let mut w = WalletLedger::empty();
        let mut spent = mk_transfer(0x31, 10);
        spent.global_output_index = 200;
        spent.spent = true;
        spent.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [8u8; 32],
        ));
        spent.spent_height = Some(18);
        spent.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
        w.ledger.transfers.push(spent);
        w.ledger.tip.synced_height = 30;
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 15,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: Vec::new(),
                lock_baseline: None,
                state: SendState::PresumedDead,
            },
        );

        w.reconcile_send_journal(None);
        assert_eq!(
            w.send_journal.rows[&txid].state,
            SendState::Confirmed { height: 18 },
            "late confirmation un-presumes the row"
        );

        // A real reorg's merge rewinds the transfer's spend marking
        // (`handle_reorg` un-marks orphaned confirmed spends) BEFORE the
        // reconciler post-pass runs — model that ordering contract here,
        // else step 2 would correctly re-confirm from the still-marked row.
        {
            let td = &mut w.ledger.transfers[0];
            td.spent = false;
            td.spent_height = None;
            td.spending_tx_hash = None;
        }
        w.reconcile_send_journal(Some(18));
        assert_eq!(
            w.send_journal.rows[&txid].state,
            SendState::Dispatched,
            "a reorg at the confirming height returns the row to Dispatched"
        );
    }
}
