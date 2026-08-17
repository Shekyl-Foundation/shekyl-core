// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read-only wallet JSON-RPC methods (Phase 4b / WI-RPC-4).
//!
//! `get_balance`, `get_primary_address`, `get_transfers`,
//! `get_transfer_by_id`, `get_height`, `get_wallet_info`.

use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_state::{SendJournalBlock, TransferDetails};
use shekyl_rpc_client::Rpc;
use shekyl_scanner::WalletLedgerExt;
use shekyl_types::TxHash;

use crate::error::WalletRpcError;
use crate::params::{parse_optional_object, parse_required_object, require_empty_object};
use crate::project::{
    atomic_units_string, attribution_matches, outgoing_block_height, outgoing_transfer_state,
    outgoing_transfer_view, parse_lookup_id, transfer_state, transfer_view, TransferLookupId,
};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    capability_mode_str, GetBalanceResult, GetHeightResult, GetPrimaryAddressResult,
    GetStakedBalanceResult, GetTransferByIdResult, GetTransfersResult, GetWalletInfoResult,
    ReceiveAttributionFilter, StakingInfoResult, TransferDirection, TransferState, TransferView,
};

/// Optional filters for `get_transfers`.
#[derive(Debug, Default, Deserialize)]
struct GetTransfersParams {
    direction: Option<TransferDirection>,
    state: Option<TransferState>,
    since_height: Option<i64>,
    attribution: Option<ReceiveAttributionFilter>,
}

/// Deterministic order of the merged INCOMING/OUTGOING history list.
///
/// Typed end to end. Ordering on the formatted `id` string instead
/// would sort a transaction's outputs lexicographically — index 10
/// before index 2 — because the index is unpadded decimal.
#[derive(Debug, PartialEq, Eq)]
struct TransferOrder {
    /// Inclusion height; `None` (never mined) sorts after every mined
    /// row, so unsettled sends sit at the tip of the ascending list.
    block_height: Option<i64>,
    /// INCOMING before OUTGOING within one height.
    outgoing: bool,
    /// Transaction hash, compared as bytes.
    tx_hash: [u8; 32],
    /// Output index for INCOMING; `0` for OUTGOING (journal rows are
    /// txid-keyed and have no output index).
    output_index: u64,
}

impl Ord for TransferOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.block_height, other.block_height) {
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
        .then_with(|| self.outgoing.cmp(&other.outgoing))
        .then_with(|| self.tx_hash.cmp(&other.tx_hash))
        .then_with(|| self.output_index.cmp(&other.output_index))
    }
}

impl PartialOrd for TransferOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Does `since_height` exclude a row at this inclusion height?
///
/// `since_height` bounds *inclusion* height. A row that was never mined
/// has no height to compare against and is always returned: excluding
/// it would hide exactly the rows a polling client most needs to see —
/// unsettled, failed and dropped sends — and hide them *permanently*,
/// since a never-mined row can never rise above the watermark. It also
/// keeps the bound monotonic across a reorg, which flips a confirmed
/// send back to `Dispatched` and would otherwise move its height
/// backwards (rule 82).
fn below_since(block_height: Option<u64>, since: Option<u64>) -> bool {
    matches!((block_height, since), (Some(h), Some(min_h)) if h < min_h)
}

/// Merge the scan ledger and the send journal into one ordered history.
///
/// Split out from the handler so the merge, both filters and the order
/// are reachable without an open engine (rule 50).
fn collect_transfers(
    ledger_rows: &[TransferDetails],
    journal: &SendJournalBlock,
    tx_notes: &std::collections::BTreeMap<[u8; 32], String>,
    filters: &GetTransfersParams,
    since: Option<u64>,
) -> Result<Vec<TransferView>, WalletRpcError> {
    let want_incoming = filters
        .direction
        .is_none_or(|d| d == TransferDirection::Incoming);
    let want_outgoing = filters
        .direction
        .is_none_or(|d| d == TransferDirection::Outgoing);

    let mut rows: Vec<(TransferOrder, TransferView)> = Vec::new();

    // Derive once for the whole projection (PR-SJ-1b).
    let spend_locks = journal.spend_locks();

    if want_incoming {
        for td in ledger_rows {
            // Ledger rows are scanner-observed, so always mined.
            if below_since(Some(td.block_height), since) {
                continue;
            }
            if filters
                .state
                .is_some_and(|st| transfer_state(td, &spend_locks) != st)
            {
                continue;
            }
            if filters
                .attribution
                .is_some_and(|f| !attribution_matches(&td.receive_attribution, f))
            {
                continue;
            }
            let view = transfer_view(td, &spend_locks, tx_notes);
            rows.push((
                TransferOrder {
                    block_height: view.block_height,
                    outgoing: false,
                    tx_hash: td.tx_hash.to_bytes(),
                    output_index: td.internal_output_index,
                },
                view,
            ));
        }
    }

    if want_outgoing {
        for (txid, row) in &journal.rows {
            if below_since(outgoing_block_height(row), since) {
                continue;
            }
            if filters
                .state
                .is_some_and(|st| outgoing_transfer_state(row) != st)
            {
                continue;
            }
            // Receive attribution exists on INCOMING rows only (WI-RPC-4):
            // an attribution filter therefore excludes every send.
            if filters.attribution.is_some() {
                continue;
            }
            let view = outgoing_transfer_view(&TxHash::from_bytes(*txid), row, tx_notes)?;
            rows.push((
                TransferOrder {
                    block_height: view.block_height,
                    outgoing: true,
                    tx_hash: *txid,
                    output_index: 0,
                },
                view,
            ));
        }
    }

    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows.into_iter().map(|(_, view)| view).collect())
}

/// Params for `get_transfer_by_id`.
#[derive(Debug, Deserialize)]
struct GetTransferByIdParams {
    id: String,
}

pub(crate) async fn get_balance(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_balance")?;
    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();
    let summary = ledger.balance();
    let result = GetBalanceResult::from(&summary);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_balance: {e}")))
}

pub(crate) async fn get_primary_address(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_primary_address")?;
    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let address = engine
        .primary_address()
        .encode()
        .map_err(|e| WalletRpcError::InternalError(format!("encode address: {e}")))?;
    let result = GetPrimaryAddressResult { address };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_primary_address: {e}")))
}

/// One-round-trip aggregate of live wallet reads (WI-RPC-4).
///
/// CLI `engine_info` is the sole production consumer at land time. No new
/// Engine API — composes balance / height / address / staking_info under
/// one engine hold (+ one daemon height probe).
pub(crate) async fn get_wallet_info(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_wallet_info")?;

    // The serving posture rides out of this same tenant-lock block: it is
    // the embedder's fact (the handle is parked here, not on the engine),
    // and taking it now means the tenant lock is never re-entered under the
    // engine guard below.
    let (name, shared, serving_posture) = {
        let state = tenants.lock().await;
        let name = state
            .tenant
            .open_name()
            .ok_or(WalletRpcError::WalletNotOpen)?
            .to_owned();
        let engine = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
        (name, engine, state.tenant.serving_posture())
    };

    let (identity, balance, staking, wallet_height, restore_height, daemon) = {
        let engine = shared.read().await;

        // Snapshot ledger fields, then drop the ledger guard before the
        // sealed-file staking read. `staking_read_view` takes its own brief
        // `ledger.read()` for `staking_enabled`; nesting that under a live
        // `LedgerReadGuard` deadlocks on non-reentrant `std::sync::RwLock`.
        // Pass the already-observed flag so the balance/enabled half of this
        // aggregate stays coherent with the ledger snapshot above.
        let (balance, wallet_height, restore_height, staking_enabled) = {
            let wallet = engine.ledger();
            let height = wallet.ledger.height();
            let balance = GetBalanceResult::from(&wallet.balance());
            let restore_height =
                i64::try_from(wallet.sync_state.restore_from_height).unwrap_or(i64::MAX);
            let wallet_height = i64::try_from(height).unwrap_or(i64::MAX);
            let staking_enabled = wallet.staking.staking_enabled;
            (balance, wallet_height, restore_height, staking_enabled)
        };
        // After the guard above is dropped (non-reentrant lock): the
        // session-adoption flag rides the same aggregate so a wallet whose
        // staking history was recovered mid-session reports it.
        let recovery_pending_reopen = engine.staking_recovery_pending_reopen();

        let address = engine
            .primary_address()
            .encode()
            .map_err(|e| WalletRpcError::InternalError(format!("encode address: {e}")))?;
        let capability = capability_mode_str(engine.capability()).to_owned();
        let network = match engine.network() {
            shekyl_engine_core::Network::Mainnet => "MAINNET",
            shekyl_engine_core::Network::Testnet => "TESTNET",
            shekyl_engine_core::Network::Stagenet => "STAGENET",
        }
        .to_owned();

        let staking_view = crate::staking::read_view_with_snapshot(
            &engine,
            staking_enabled,
            recovery_pending_reopen,
        )?;
        let staking = StakingInfoResult {
            staking_enabled: staking_view.staking_enabled,
            balance: GetStakedBalanceResult {
                bonded_principal_confirmed: atomic_units_string(
                    staking_view.balance.bonded_principal_confirmed,
                ),
                bonded_principal_pending: atomic_units_string(
                    staking_view.balance.bonded_principal_pending,
                ),
                rewards_received_unspent: atomic_units_string(
                    staking_view.balance.rewards_received_unspent,
                ),
            },
            staked_output_count: i64::try_from(staking_view.outputs.len()).unwrap_or(i64::MAX),
            pscan_synced_height: staking_view
                .pscan_synced_height
                .map(|h| i64::try_from(h.to_raw()).unwrap_or(i64::MAX)),
            recovery_pending_reopen: staking_view.recovery_pending_reopen,
            posture: crate::staking::posture_str(serving_posture),
        };

        let daemon = engine.daemon().clone();

        (
            (name, capability, network, address),
            balance,
            staking,
            wallet_height,
            restore_height,
            daemon,
        )
    };

    let daemon_height = daemon
        .get_height()
        .await
        .ok()
        .map(|h| i64::try_from(h).unwrap_or(i64::MAX));

    let (name, capability, network, address) = identity;
    let result = GetWalletInfoResult {
        name,
        capability,
        network,
        address,
        wallet_height,
        daemon_height,
        restore_height,
        balance,
        staking,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_wallet_info: {e}")))
}

pub(crate) async fn get_transfers(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let filters: GetTransfersParams = parse_optional_object(params, "get_transfers")?;
    let since = match filters.since_height {
        None => None,
        Some(h) => Some(u64::try_from(h).map_err(|_| {
            WalletRpcError::InvalidParams("since_height must be a non-negative integer".into())
        })?),
    };

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();

    let transfers = collect_transfers(
        ledger.ledger.transfers(),
        &ledger.send_journal,
        ledger.tx_meta.notes(),
        &filters,
        since,
    )?;

    let result = GetTransfersResult { transfers };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_transfers: {e}")))
}

pub(crate) async fn get_transfer_by_id(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetTransferByIdParams = parse_required_object(params, "get_transfer_by_id")?;

    // Shape first, before any tenant state: an id this wallet could
    // never have emitted is a malformed request, and answering it with
    // "unknown transfer" would tell a user whose send does exist that
    // it does not (rule 82).
    let lookup = parse_lookup_id(&p.id).ok_or_else(|| {
        WalletRpcError::InvalidParams(
            "id must be `{tx_hash}:{output_index}` for a receive, or a bare 64 \
             lowercase-hex `{tx_hash}` for a send"
                .into(),
        )
    })?;

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();

    let transfer = match lookup {
        TransferLookupId::Incoming {
            tx_hash,
            output_index,
        } => ledger
            .ledger
            .transfers()
            .iter()
            .find(|td| td.tx_hash == tx_hash && td.internal_output_index == output_index)
            .map(|td| transfer_view(td, &ledger.spend_locks(), ledger.tx_meta.notes())),
        TransferLookupId::Outgoing { tx_hash } => ledger
            .send_journal
            .rows
            .get(&tx_hash.to_bytes())
            .map(|row| outgoing_transfer_view(&tx_hash, row, ledger.tx_meta.notes()))
            .transpose()?,
    };

    let result = GetTransferByIdResult {
        transfer: transfer.ok_or(WalletRpcError::UnknownTransferId)?,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_transfer_by_id: {e}")))
}

pub(crate) async fn get_height(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_height")?;
    let shared = require_open_engine(tenants).await?;
    let (wallet_height, daemon) = {
        let engine = shared.read().await;
        let wallet_height = i64::try_from(engine.ledger().ledger.height()).unwrap_or(i64::MAX);
        (wallet_height, engine.daemon().clone())
    };

    // Do not fail the whole call when the daemon is unreachable: the wallet
    // height is local and always meaningful (a user whose own node is down or
    // still syncing must still be able to see their wallet's status). Report
    // daemon_height as null in that case rather than erroring out.
    let daemon_height = daemon
        .get_height()
        .await
        .ok()
        .map(|h| i64::try_from(h).unwrap_or(i64::MAX));

    let result = GetHeightResult {
        wallet_height,
        daemon_height,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_height: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_engine_state::{SendRecipient, SendRecord, SendState};

    fn journal(rows: &[(u8, SendState)]) -> SendJournalBlock {
        let mut block = SendJournalBlock::empty();
        for &(seed, state) in rows {
            block.rows.insert(
                [seed; 32],
                SendRecord {
                    dispatched_at_height: 100,
                    fee: 700,
                    recipients: vec![SendRecipient {
                        address: "shekyl1a".to_owned(),
                        amount: 3_500,
                    }],
                    change_amount: 100,
                    inputs: vec![],
                    lock_baseline: None,
                    state,
                },
            );
        }
        block
    }

    fn filters(
        direction: Option<TransferDirection>,
        state: Option<TransferState>,
    ) -> GetTransfersParams {
        GetTransfersParams {
            direction,
            state,
            since_height: None,
            attribution: None,
        }
    }

    fn ids(views: &[TransferView]) -> Vec<&str> {
        views.iter().map(|v| v.id.as_str()).collect()
    }

    /// Empty tx-note map for the collect-transfers tests that do not
    /// exercise note projection.
    fn no_notes() -> std::collections::BTreeMap<[u8; 32], String> {
        std::collections::BTreeMap::new()
    }

    /// The `direction` filter selects a *side*, and each side is only
    /// reachable from its own source. Inverting the two `want_*`
    /// predicates — the defect that made `direction: OUTGOING` a no-op
    /// before this projection existed — flips both assertions.
    #[test]
    fn direction_filter_selects_the_matching_source() {
        let block = journal(&[(0xab, SendState::Confirmed { height: 250 })]);

        let all = collect_transfers(&[], &block, &no_notes(), &filters(None, None), None)
            .expect("project");
        assert_eq!(ids(&all), vec!["ab".repeat(32)]);

        let outgoing = collect_transfers(
            &[],
            &block,
            &no_notes(),
            &filters(Some(TransferDirection::Outgoing), None),
            None,
        )
        .expect("project");
        assert_eq!(ids(&outgoing), vec!["ab".repeat(32)]);

        // The journal is the OUTGOING source only: asking for INCOMING
        // must never surface a send.
        let incoming = collect_transfers(
            &[],
            &block,
            &no_notes(),
            &filters(Some(TransferDirection::Incoming), None),
            None,
        )
        .expect("project");
        assert!(incoming.is_empty(), "journal rows leaked into INCOMING");
    }

    /// The `state` filter runs against the journal projection, so the
    /// five send lifecycle states are each independently selectable.
    #[test]
    fn state_filter_applies_to_journal_rows() {
        let block = journal(&[
            (0x01, SendState::Dispatched),
            (0x02, SendState::Confirmed { height: 250 }),
            (0x03, SendState::TerminalRejected),
            (0x04, SendState::PresumedDead),
            (0x05, SendState::Abandoned),
        ]);

        for (state, expected_seed) in [
            (TransferState::Pending, "01"),
            (TransferState::Confirmed, "02"),
            (TransferState::Failed, "03"),
            (TransferState::Dropped, "04"),
            (TransferState::Abandoned, "05"),
        ] {
            let got =
                collect_transfers(&[], &block, &no_notes(), &filters(None, Some(state)), None)
                    .expect("project");
            assert_eq!(
                ids(&got),
                vec![expected_seed.repeat(32)],
                "state filter {state:?}"
            );
        }

        // SPENT is receive-side only; no send ever matches it.
        let spent = collect_transfers(
            &[],
            &block,
            &no_notes(),
            &filters(None, Some(TransferState::Spent)),
            None,
        )
        .expect("project");
        assert!(spent.is_empty());
    }

    /// A per-txid note (SJ-DQ-7) is looked up from `TxMetaBlock::notes` and
    /// projected onto the transfer view; a row with no note carries none.
    /// The note is keyed by the bare txid (arm 1: a note is about the
    /// transaction), so the same lookup feeds both directions of a txid.
    #[test]
    fn note_projects_onto_the_transfer_view() {
        let block = journal(&[(0xab, SendState::Confirmed { height: 250 })]);
        let mut notes = no_notes();
        notes.insert([0xab; 32], "rent".to_owned());

        let with =
            collect_transfers(&[], &block, &notes, &filters(None, None), None).expect("project");
        assert_eq!(with.len(), 1);
        assert_eq!(with[0].note.as_deref(), Some("rent"));

        let without = collect_transfers(&[], &block, &no_notes(), &filters(None, None), None)
            .expect("project");
        assert_eq!(without[0].note, None);
    }

    /// Receive attribution exists on INCOMING rows only (WI-RPC-4), so
    /// an `attribution` filter must exclude every send — a journal row
    /// surviving any attribution filter would claim a receive-side fact
    /// about a payment this wallet made.
    #[test]
    fn attribution_filter_excludes_journal_rows() {
        let block = journal(&[(0xab, SendState::Confirmed { height: 250 })]);
        let mut f = filters(None, None);
        f.attribution = Some(ReceiveAttributionFilter::Unattributed);

        let got = collect_transfers(&[], &block, &no_notes(), &f, None).expect("project");
        assert!(
            got.is_empty(),
            "a send matched a receive-attribution filter"
        );
    }

    /// `since_height` bounds inclusion height. A send that was never
    /// mined has no inclusion height, so it survives every watermark —
    /// otherwise a polling client would lose pending, failed and
    /// dropped sends permanently, and lose a confirmed send the moment
    /// a reorg flipped it back to `Dispatched`.
    #[test]
    fn since_height_never_hides_a_send_that_was_never_mined() {
        let block = journal(&[
            (0x01, SendState::Dispatched),
            (0x02, SendState::Confirmed { height: 250 }),
            (0x03, SendState::TerminalRejected),
            (0x04, SendState::PresumedDead),
            (0x05, SendState::Abandoned),
        ]);

        // Watermark far above the dispatch height: the confirmed row is
        // below it and drops out; the four unmined rows stay.
        let got = collect_transfers(&[], &block, &no_notes(), &filters(None, None), Some(1_000))
            .expect("project");
        assert_eq!(
            ids(&got),
            vec![
                "01".repeat(32),
                "03".repeat(32),
                "04".repeat(32),
                "05".repeat(32)
            ]
        );

        // At its own height the confirmed row is included (inclusive bound).
        let at_height =
            collect_transfers(&[], &block, &no_notes(), &filters(None, None), Some(250))
                .expect("project");
        assert!(at_height.iter().any(|v| v.id == "02".repeat(32)));
    }

    /// A row whose recipient amounts do not sum is a corrupt journal
    /// row, not a display condition: the read path reports it instead
    /// of panicking (the workspace builds `panic = "abort"`, so a panic
    /// here would take the whole wallet-rpc process down).
    #[test]
    fn unsummable_recipient_amounts_error_instead_of_panicking() {
        let mut block = journal(&[(0x05, SendState::Dispatched)]);
        let row = block.rows.get_mut(&[0x05; 32]).expect("row");
        row.recipients = vec![
            SendRecipient {
                address: "shekyl1a".to_owned(),
                amount: u64::MAX,
            },
            SendRecipient {
                address: "shekyl1b".to_owned(),
                amount: 1,
            },
        ];

        let err = collect_transfers(&[], &block, &no_notes(), &filters(None, None), None)
            .expect_err("overflowing recipient sum must not project");
        assert!(matches!(err, WalletRpcError::InternalError(_)), "{err:?}");
    }

    /// Ordering is computed from typed fields. Comparing the formatted
    /// `id` string instead would place output index 10 before index 2,
    /// because the index is unpadded decimal.
    #[test]
    fn order_is_by_output_index_not_id_string() {
        let key = |output_index| TransferOrder {
            block_height: Some(100),
            outgoing: false,
            tx_hash: [0xab; 32],
            output_index,
        };
        let mut keys = [key(10), key(2), key(1), key(11)];
        keys.sort();
        assert_eq!(
            keys.iter().map(|k| k.output_index).collect::<Vec<_>>(),
            vec![1, 2, 10, 11]
        );
    }

    /// Merge order: ascending inclusion height, INCOMING before
    /// OUTGOING within a height, and rows that were never mined last —
    /// they have no height, and belong at the tip of the list rather
    /// than sorted in among genuinely mined transfers.
    #[test]
    fn unmined_rows_sort_after_every_mined_row() {
        let row = |block_height, outgoing| TransferOrder {
            block_height,
            outgoing,
            tx_hash: [0x01; 32],
            output_index: 0,
        };
        let mut keys = [
            row(None, true),
            row(Some(250), true),
            row(Some(100), true),
            row(Some(100), false),
        ];
        keys.sort();
        assert_eq!(
            keys.iter()
                .map(|k| (k.block_height, k.outgoing))
                .collect::<Vec<_>>(),
            vec![
                (Some(100), false),
                (Some(100), true),
                (Some(250), true),
                (None, true),
            ]
        );
    }

    /// `since_height` compares inclusion heights only; a row with no
    /// inclusion height is never below the bound.
    #[test]
    fn below_since_ignores_rows_with_no_inclusion_height() {
        assert!(below_since(Some(100), Some(250)));
        assert!(!below_since(Some(250), Some(250)));
        assert!(!below_since(Some(100), None));
        assert!(!below_since(None, Some(250)));
        assert!(!below_since(None, None));
    }
}
