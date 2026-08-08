// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Domain → OpenAPI projections (accounting facts only; no secrets).

use shekyl_engine_core::PendingTx;
use shekyl_engine_core::RefreshSummary;
use shekyl_engine_core::SubmitOutcome;
use shekyl_engine_state::{
    DisputeReason, ReceiveAttribution, SendRecord, SendState, TransferDetails,
};
use shekyl_scanner::BalanceSummary;
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;

use crate::error::WalletRpcError;
use crate::params::parse_hex32;
use crate::types::{
    BuildPendingTxResult, GetBalanceResult, ReceiveAttributionKind, ReceiveAttributionView,
    RefreshResult, RescanBlockchainResult, SubmitPendingTxResult, SubmitVerdictView,
    TransferDirection, TransferState, TransferView,
};

/// Decimal string for OpenAPI `AtomicUnits`.
pub fn atomic_units_string(amount: AtomicUnits) -> String {
    amount.to_raw().to_string()
}

/// Map scanner balance into the locked OpenAPI balance shape.
///
/// `staked` / `claimable_rewards` stay `"0"` until Stage 3 stake methods
/// land (OpenAPI contract). `liquid` mirrors `unlocked` until staking
/// splits liquid from locked principal.
impl From<&BalanceSummary> for GetBalanceResult {
    fn from(b: &BalanceSummary) -> Self {
        let unlocked = atomic_units_string(b.unlocked);
        Self {
            liquid: unlocked.clone(),
            staked: "0".to_owned(),
            unlocked,
            claimable_rewards: "0".to_owned(),
            pending: atomic_units_string(b.awaiting_confirmation),
        }
    }
}

/// Stable transfer id: `{tx_hash_hex}:{internal_output_index}`.
pub fn transfer_id(td: &TransferDetails) -> String {
    format!("{}:{}", td.tx_hash, td.internal_output_index)
}

/// Parse a transfer id back into its `(tx_hash, internal_output_index)`
/// parts — the inverse of [`transfer_id`], kept beside it so the id format
/// has a single home.
///
/// Accepts exactly the canonical form `transfer_id` emits (64 lowercase hex
/// chars per the crate's shared [`parse_hex32`] rule, `:`, decimal index
/// with no leading zeros or sign). Anything else returns `None` — the same
/// ids that per-row string equality against [`transfer_id`] output would
/// have failed to match, so lookups by the parsed parts preserve match
/// semantics while comparing typed fields instead of formatting a fresh id
/// string for every ledger row scanned.
pub fn parse_transfer_id(id: &str) -> Option<(TxHash, u64)> {
    let (hash_hex, idx_str) = id.split_once(':')?;
    let bytes = parse_hex32(hash_hex)?;
    // Canonical decimal only: `u64::from_str` also accepts `+` and leading
    // zeros, which `transfer_id` never emits and string equality would
    // therefore never have matched.
    if idx_str.is_empty()
        || !idx_str.bytes().all(|b| b.is_ascii_digit())
        || (idx_str.len() > 1 && idx_str.starts_with('0'))
    {
        return None;
    }
    let idx: u64 = idx_str.parse().ok()?;
    Some((TxHash::from_bytes(bytes), idx))
}

/// Which side of the history a `get_transfer_by_id` id names.
///
/// The two id grammars are disjoint — INCOMING ids carry a `:`
/// separator, OUTGOING ids are bare 64-char hex — so a well-formed id
/// resolves to exactly one lookup with no ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferLookupId {
    /// `{tx_hash_hex}:{internal_output_index}` — a scan-ledger output.
    Incoming {
        /// Transaction the output belongs to.
        tx_hash: TxHash,
        /// Index of the output within that transaction.
        output_index: u64,
    },
    /// Bare `{tx_hash_hex}` — a send-journal row (txid-keyed, SJ-DQ-7).
    Outgoing {
        /// Transaction the send record is keyed by.
        tx_hash: TxHash,
    },
}

/// Parse a client-supplied `get_transfer_by_id` id.
///
/// `None` means the string is not an id this wallet ever emits, which
/// is a malformed *request* — the caller reports invalid params rather
/// than "unknown transfer". The distinction is user-visible: a person
/// who pastes an uppercase txid must be told the id is not in canonical
/// form, not that the send they are looking at does not exist (rule 82).
pub fn parse_lookup_id(id: &str) -> Option<TransferLookupId> {
    if let Some((tx_hash, output_index)) = parse_transfer_id(id) {
        return Some(TransferLookupId::Incoming {
            tx_hash,
            output_index,
        });
    }
    parse_hex32(id).map(|bytes| TransferLookupId::Outgoing {
        tx_hash: TxHash::from_bytes(bytes),
    })
}

/// Confirmation / spend state of a ledger row.
///
/// Shared by [`transfer_view`] and the `get_transfers` filter so both agree on
/// how a row maps to [`TransferState`] without re-projecting the whole row.
pub fn transfer_state(td: &TransferDetails) -> TransferState {
    if td.spent {
        TransferState::Spent
    } else if td.awaiting_confirmation.is_some() {
        TransferState::Pending
    } else {
        TransferState::Confirmed
    }
}

/// Project ledger receive-attribution to the RPC view (no cleartext labels).
pub fn attribution_view(attr: &ReceiveAttribution) -> ReceiveAttributionView {
    match attr {
        ReceiveAttribution::Unattributed => ReceiveAttributionView {
            kind: ReceiveAttributionKind::Unattributed,
            request_id: None,
            echoed_label_hash: None,
            dispute_reason: None,
        },
        ReceiveAttribution::Matched(id) => ReceiveAttributionView {
            kind: ReceiveAttributionKind::Matched,
            request_id: Some(id.as_u64().to_string()),
            echoed_label_hash: None,
            dispute_reason: None,
        },
        ReceiveAttribution::LabelUnknown { echoed_label_hash } => ReceiveAttributionView {
            kind: ReceiveAttributionKind::LabelUnknown,
            request_id: None,
            echoed_label_hash: Some(hex::encode(echoed_label_hash)),
            dispute_reason: None,
        },
        ReceiveAttribution::ManualMatch(id) => ReceiveAttributionView {
            kind: ReceiveAttributionKind::ManualMatch,
            request_id: Some(id.as_u64().to_string()),
            echoed_label_hash: None,
            dispute_reason: None,
        },
        ReceiveAttribution::Disputed { reason } => ReceiveAttributionView {
            kind: ReceiveAttributionKind::Disputed,
            request_id: None,
            echoed_label_hash: None,
            dispute_reason: Some(dispute_reason_string(reason)),
        },
    }
}

fn dispute_reason_string(reason: &DisputeReason) -> String {
    match reason {
        DisputeReason::WrongLabel => "WrongLabel".to_owned(),
        DisputeReason::WrongAmount => "WrongAmount".to_owned(),
        DisputeReason::Other(s) => format!("Other({s})"),
    }
}

/// Whether a ledger row matches an optional attribution filter.
pub fn attribution_matches(
    attr: &ReceiveAttribution,
    filter: crate::types::ReceiveAttributionFilter,
) -> bool {
    use crate::types::ReceiveAttributionFilter as F;
    matches!(
        (filter, attr),
        (F::Unattributed, ReceiveAttribution::Unattributed)
            | (F::Matched, ReceiveAttribution::Matched(_))
            | (F::LabelUnknown, ReceiveAttribution::LabelUnknown { .. })
            | (F::ManualMatch, ReceiveAttribution::ManualMatch(_))
            | (F::Disputed, ReceiveAttribution::Disputed { .. })
    )
}

/// Project a ledger transfer to the RPC view (no key material).
pub fn transfer_view(td: &TransferDetails) -> TransferView {
    TransferView {
        id: transfer_id(td),
        // Ledger rows are receive-side outputs, so this projection is
        // always INCOMING; outgoing history is projected from the send
        // journal (`outgoing_transfer_view`).
        direction: TransferDirection::Incoming,
        tx_hash: td.tx_hash.to_string(),
        amount: atomic_units_string(td.amount()),
        fee: "0".to_owned(),
        // Ledger rows are scanner-observed, so they are always mined.
        block_height: Some(i64::try_from(td.block_height).unwrap_or(i64::MAX)),
        state: transfer_state(td),
        spent_height: td
            .spent_height
            .map(|h| i64::try_from(h).unwrap_or(i64::MAX)),
        // Receive-side row, so attribution is always meaningful here.
        attribution: Some(attribution_view(&td.receive_attribution)),
    }
}

/// Txid-keyed id for an OUTGOING journal row (SJ-DQ-7 / PR-SJ-2).
pub fn outgoing_transfer_id(txid: &TxHash) -> String {
    txid.to_string()
}

/// Inclusion height of a send, or `None` when it is not on chain.
///
/// Only a refresh-observed `Confirmed { height }` yields a height. The
/// journal also records `dispatched_at_height`, but that is a local
/// sync counter, not an inclusion height: projecting it would put a
/// plausible block number beside a send that was never mined, and would
/// make the projected height move *backwards* when a reorg flips a
/// confirmed row back to `Dispatched` (rule 82).
pub fn outgoing_block_height(row: &SendRecord) -> Option<u64> {
    match row.state {
        SendState::Confirmed { height } => Some(height),
        SendState::Dispatched
        | SendState::TerminalRejected
        | SendState::PresumedDead
        | SendState::Abandoned => None,
    }
}

/// Map journal lifecycle onto the OpenAPI `TransferState` enum.
///
/// Every arm is a distinct user-facing situation; none collapses into
/// another, because each collapse is a different lie (rule 82):
///
/// - `Dispatched` → `PENDING` (in flight; the wallet is still waiting).
/// - `Confirmed` → `CONFIRMED` (refresh observed the spend on chain).
/// - `TerminalRejected` → `FAILED` (daemon refused; never mined — never
///   collapse into `CONFIRMED`).
/// - `PresumedDead` → `DROPPED` (the confirmed-absent watchdog released
///   the input locks — never collapse into `PENDING`, which would say
///   the wallet is still waiting while the same wallet reports those
///   funds spendable again).
/// - `Abandoned` → `ABANDONED` (user-authored give-up, P3-4 — never
///   collapse into `DROPPED`, whose release claim is evidence-backed;
///   an abandoned send's input locks may still be held).
pub fn outgoing_transfer_state(row: &SendRecord) -> TransferState {
    match row.state {
        SendState::Dispatched => TransferState::Pending,
        SendState::Confirmed { .. } => TransferState::Confirmed,
        SendState::TerminalRejected => TransferState::Failed,
        SendState::PresumedDead => TransferState::Dropped,
        SendState::Abandoned => TransferState::Abandoned,
    }
}

/// Project a send-journal row as an OUTGOING `TransferView` (PR-SJ-2).
///
/// Fails rather than panics when the row's recipient amounts do not sum
/// (`SendRecord::sent_amount`): this runs on the read path, and the
/// workspace builds with `panic = "abort"`, so a panic here would take
/// the wallet-rpc process down on a history query.
pub fn outgoing_transfer_view(
    txid: &TxHash,
    row: &SendRecord,
) -> Result<TransferView, WalletRpcError> {
    let sent = row.sent_amount().ok_or_else(|| {
        WalletRpcError::InternalError(format!(
            "send journal row {txid} has recipient amounts that do not sum"
        ))
    })?;
    Ok(TransferView {
        id: outgoing_transfer_id(txid),
        direction: TransferDirection::Outgoing,
        tx_hash: txid.to_string(),
        amount: atomic_units_string(AtomicUnits::from_raw(sent)),
        fee: atomic_units_string(AtomicUnits::from_raw(row.fee)),
        // Crate-wide height projection idiom: OpenAPI heights are int64.
        block_height: outgoing_block_height(row).map(|h| i64::try_from(h).unwrap_or(i64::MAX)),
        state: outgoing_transfer_state(row),
        spent_height: None,
        // Receive attribution is documented "Present on INCOMING rows
        // only" — a send has no receive side to attribute.
        attribution: None,
    })
}

/// Project [`RefreshSummary`] + post-refresh ledger tip to OpenAPI.
pub fn refresh_result(summary: &RefreshSummary, synced_height: u64) -> RefreshResult {
    RefreshResult {
        blocks_processed: i64::try_from(summary.blocks_processed).unwrap_or(i64::MAX),
        transfers_detected: i64::try_from(summary.transfers_detected).unwrap_or(i64::MAX),
        synced_height: i64::try_from(synced_height).unwrap_or(i64::MAX),
        reorg_fork_height: summary
            .reorg
            .as_ref()
            .map(|r| i64::try_from(r.fork_height).unwrap_or(i64::MAX)),
    }
}

/// Project a rescan summary — OpenAPI omits `reorg_fork_height`.
pub fn rescan_result(summary: &RefreshSummary, synced_height: u64) -> RescanBlockchainResult {
    RescanBlockchainResult {
        blocks_processed: i64::try_from(summary.blocks_processed).unwrap_or(i64::MAX),
        transfers_detected: i64::try_from(summary.transfers_detected).unwrap_or(i64::MAX),
        synced_height: i64::try_from(synced_height).unwrap_or(i64::MAX),
    }
}

/// Project the Engine's identity-bearing [`SubmitOutcome`] to OpenAPI
/// `SubmitPendingTxResult` — the projection that makes the contract's
/// `ALREADY_IN_POOL` / `ALREADY_IN_CHAIN` verdicts reachable
/// (`docs/FOLLOWUPS.md` "Phase 4b: `submit_pending_tx` verdict is
/// flattened to `ACCEPTED`", closed with this projection).
///
/// `confirmed_height` is **verdict-scoped**: present iff
/// `ALREADY_IN_CHAIN`, carrying the daemon-claimed confirming height.
/// The claim is untrusted display metadata (`DAEMON_SUBMIT_VERDICT.md`
/// §7.2 rider) — refresh remains the settlement authority, and the
/// field exists only on `SubmitPendingTxResult` (structurally — no
/// refresh-populated view shares it), so a client cannot mistake it
/// for a refresh-observed confirmation.
pub fn submit_pending_tx_result(outcome: &SubmitOutcome) -> SubmitPendingTxResult {
    let tx_hash = outcome.hash().to_string();
    match outcome {
        SubmitOutcome::Accepted { .. } => SubmitPendingTxResult {
            tx_hash,
            verdict: SubmitVerdictView::Accepted,
            confirmed_height: None,
        },
        SubmitOutcome::AlreadyInPool { .. } => SubmitPendingTxResult {
            tx_hash,
            verdict: SubmitVerdictView::AlreadyInPool,
            confirmed_height: None,
        },
        SubmitOutcome::AlreadyInChain { height, .. } => SubmitPendingTxResult {
            tx_hash,
            verdict: SubmitVerdictView::AlreadyInChain,
            confirmed_height: Some(i64::try_from(*height).unwrap_or(i64::MAX)),
        },
    }
}

/// Project [`PendingTx`] to OpenAPI `BuildPendingTxResult`.
pub fn pending_tx_result(tx: &PendingTx) -> BuildPendingTxResult {
    BuildPendingTxResult {
        pending_tx_id: tx.id.raw().to_string(),
        built_at_height: i64::try_from(tx.built_at_height).unwrap_or(i64::MAX),
        built_at_tip_hash: hex::encode(tx.built_at_tip_hash),
        fee: atomic_units_string(tx.fee_atomic_units),
        content_gen: i64::try_from(tx.content_gen).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_units::AtomicUnits;

    #[test]
    fn attribution_view_and_filter_cover_fa8_kinds() {
        use shekyl_engine_state::PaymentRequestId;

        assert_eq!(
            attribution_view(&ReceiveAttribution::Unattributed).kind,
            ReceiveAttributionKind::Unattributed
        );
        assert!(attribution_matches(
            &ReceiveAttribution::Unattributed,
            crate::types::ReceiveAttributionFilter::Unattributed
        ));
        assert!(!attribution_matches(
            &ReceiveAttribution::Unattributed,
            crate::types::ReceiveAttributionFilter::Matched
        ));

        let matched = ReceiveAttribution::Matched(PaymentRequestId(42));
        let view = attribution_view(&matched);
        assert_eq!(view.kind, ReceiveAttributionKind::Matched);
        assert_eq!(view.request_id.as_deref(), Some("42"));
        assert!(attribution_matches(
            &matched,
            crate::types::ReceiveAttributionFilter::Matched
        ));

        let unknown = ReceiveAttribution::LabelUnknown {
            echoed_label_hash: [0xab; 32],
        };
        let view = attribution_view(&unknown);
        assert_eq!(view.kind, ReceiveAttributionKind::LabelUnknown);
        let expected_hash = "ab".repeat(32);
        assert_eq!(
            view.echoed_label_hash.as_deref(),
            Some(expected_hash.as_str())
        );
        assert!(attribution_matches(
            &unknown,
            crate::types::ReceiveAttributionFilter::LabelUnknown
        ));

        // ManualMatch carries the rid like Matched, but under its own kind:
        // a user-authored link must stay distinguishable from a cooperative
        // label match, because only one of them is evidence from the sender.
        let manual = ReceiveAttribution::ManualMatch(PaymentRequestId(7));
        let view = attribution_view(&manual);
        assert_eq!(view.kind, ReceiveAttributionKind::ManualMatch);
        assert_eq!(view.request_id.as_deref(), Some("7"));
        assert_eq!(view.echoed_label_hash, None);
        assert_eq!(view.dispute_reason, None);
        assert!(attribution_matches(
            &manual,
            crate::types::ReceiveAttributionFilter::ManualMatch
        ));
        assert!(!attribution_matches(
            &manual,
            crate::types::ReceiveAttributionFilter::Matched
        ));

        // Disputed renders every DisputeReason arm, including the free-form
        // one whose payload reaches the wire.
        for (reason, expected) in [
            (DisputeReason::WrongLabel, "WrongLabel"),
            (DisputeReason::WrongAmount, "WrongAmount"),
            (
                DisputeReason::Other("paid twice".to_owned()),
                "Other(paid twice)",
            ),
        ] {
            let disputed = ReceiveAttribution::Disputed { reason };
            let view = attribution_view(&disputed);
            assert_eq!(view.kind, ReceiveAttributionKind::Disputed);
            assert_eq!(view.dispute_reason.as_deref(), Some(expected));
            assert_eq!(view.request_id, None);
            assert!(attribution_matches(
                &disputed,
                crate::types::ReceiveAttributionFilter::Disputed
            ));
            assert!(!attribution_matches(
                &disputed,
                crate::types::ReceiveAttributionFilter::Unattributed
            ));
        }

        // Wire pins for the two kinds the filter newly distinguishes.
        let json = serde_json::to_value(attribution_view(&manual)).expect("serialize");
        assert_eq!(json["kind"], "MANUAL_MATCH");
        let json = serde_json::to_value(attribution_view(&ReceiveAttribution::Disputed {
            reason: DisputeReason::WrongAmount,
        }))
        .expect("serialize");
        assert_eq!(json["kind"], "DISPUTED");
        assert_eq!(json["dispute_reason"], "WrongAmount");
    }

    #[test]
    fn parse_transfer_id_roundtrips_canonical_form() {
        let hash_hex = "0a".repeat(32);
        let (hash, idx) = parse_transfer_id(&format!("{hash_hex}:7")).expect("canonical id");
        assert_eq!(hash, TxHash::from_bytes([0x0a; 32]));
        assert_eq!(idx, 7);
        // The parse must accept exactly what transfer_id emits.
        assert_eq!(format!("{hash}:{idx}"), format!("{hash_hex}:7"));

        let (_, zero_idx) = parse_transfer_id(&format!("{hash_hex}:0")).expect("index 0 is valid");
        assert_eq!(zero_idx, 0);
    }

    #[test]
    fn parse_transfer_id_rejects_non_canonical_forms() {
        let hash_hex = "0a".repeat(32);
        // Everything here would also have failed per-row string equality
        // against transfer_id output, so rejecting keeps match semantics.
        for bad in [
            String::new(),
            "no-colon".to_owned(),
            format!("{hash_hex}:"),                     // empty index
            format!("{hash_hex}:+7"),                   // sign not emitted
            format!("{hash_hex}:07"),                   // leading zero not emitted
            format!("{hash_hex}:1x"),                   // non-digit
            format!("{}:1", "0A".repeat(32)),           // uppercase hex not emitted
            format!("{}:1", "0a".repeat(31)),           // short hash
            format!("{}:1", "0a".repeat(33)),           // long hash
            format!("{hash_hex}:99999999999999999999"), // > u64::MAX
        ] {
            assert!(parse_transfer_id(&bad).is_none(), "accepted {bad:?}");
        }
    }

    /// The three Engine verdicts project 1:1 onto the OpenAPI verdict
    /// strings, with `confirmed_height` verdict-scoped: absent on
    /// `ACCEPTED` / `ALREADY_IN_POOL` (the negative control — nothing
    /// but an already-in-chain claim may populate the field), present
    /// with the claimed height on `ALREADY_IN_CHAIN`. Expected wire
    /// strings come from the OpenAPI contract (`wallet_rpc.yaml`
    /// `SubmitPendingTxResult.verdict` enum), not from the projection
    /// code under test.
    #[test]
    fn submit_verdicts_project_one_to_one_with_verdict_scoped_height() {
        let hash = TxHash::from_bytes([0x2b; 32]);
        let hash_hex = "2b".repeat(32);

        let accepted = submit_pending_tx_result(&SubmitOutcome::Accepted { hash });
        assert_eq!(accepted.tx_hash, hash_hex);
        assert_eq!(accepted.verdict, SubmitVerdictView::Accepted);
        assert_eq!(accepted.confirmed_height, None);

        let in_pool = submit_pending_tx_result(&SubmitOutcome::AlreadyInPool { hash });
        assert_eq!(in_pool.tx_hash, hash_hex);
        assert_eq!(in_pool.verdict, SubmitVerdictView::AlreadyInPool);
        assert_eq!(in_pool.confirmed_height, None);

        let in_chain =
            submit_pending_tx_result(&SubmitOutcome::AlreadyInChain { hash, height: 4242 });
        assert_eq!(in_chain.tx_hash, hash_hex);
        assert_eq!(in_chain.verdict, SubmitVerdictView::AlreadyInChain);
        assert_eq!(in_chain.confirmed_height, Some(4242));

        // Wire pins, derived from the contract: the SCREAMING_SNAKE_CASE
        // verdict strings, and `confirmed_height` present as a JSON key
        // iff ALREADY_IN_CHAIN ("Present iff verdict is ALREADY_IN_CHAIN").
        let accepted_json = serde_json::to_value(&accepted).expect("serialize");
        assert_eq!(accepted_json["verdict"], "ACCEPTED");
        assert!(
            accepted_json.get("confirmed_height").is_none(),
            "ACCEPTED must not serialize a confirmed_height key: {accepted_json}"
        );
        let in_pool_json = serde_json::to_value(&in_pool).expect("serialize");
        assert_eq!(in_pool_json["verdict"], "ALREADY_IN_POOL");
        assert!(
            in_pool_json.get("confirmed_height").is_none(),
            "ALREADY_IN_POOL must not serialize a confirmed_height key: {in_pool_json}"
        );
        let in_chain_json = serde_json::to_value(&in_chain).expect("serialize");
        assert_eq!(in_chain_json["verdict"], "ALREADY_IN_CHAIN");
        assert_eq!(in_chain_json["confirmed_height"], 4242);
    }

    /// A daemon-claimed height beyond `i64` saturates instead of
    /// wrapping or erroring — the projection idiom shared with the
    /// other height fields (`i64::try_from(...).unwrap_or(i64::MAX)`).
    #[test]
    fn submit_claimed_height_beyond_i64_saturates() {
        let hash = TxHash::from_bytes([0x2c; 32]);
        let projected = submit_pending_tx_result(&SubmitOutcome::AlreadyInChain {
            hash,
            height: u64::MAX,
        });
        assert_eq!(projected.confirmed_height, Some(i64::MAX));
    }

    #[test]
    fn balance_maps_unlocked_to_liquid() {
        let b = BalanceSummary {
            total: AtomicUnits::from_raw(100),
            unlocked: AtomicUnits::from_raw(40),
            locked_by_timelock: AtomicUnits::from_raw(10),
            frozen: AtomicUnits::ZERO,
            awaiting_confirmation: AtomicUnits::from_raw(5),
        };
        let r = GetBalanceResult::from(&b);
        assert_eq!(r.unlocked, "40");
        assert_eq!(r.liquid, "40");
        assert_eq!(r.pending, "5");
        assert_eq!(r.staked, "0");
        assert_eq!(r.claimable_rewards, "0");
    }

    fn sample_send_record(state: SendState) -> SendRecord {
        use shekyl_engine_state::{SendInputRef, SendRecipient};
        SendRecord {
            dispatched_at_height: 100,
            fee: 700,
            recipients: vec![
                SendRecipient {
                    address: "shekyl1a".to_owned(),
                    amount: 1_000,
                },
                SendRecipient {
                    address: "shekyl1b".to_owned(),
                    amount: 2_500,
                },
            ],
            change_amount: 100,
            inputs: vec![SendInputRef {
                gindex: 7,
                amount: 4_300,
            }],
            lock_baseline: None,
            state,
        }
    }

    /// Every journal lifecycle state gets its own wire value. The two
    /// collapses that rule 82 forbids are pinned negatively: a refused
    /// send must never read CONFIRMED, and a send the watchdog already
    /// gave up on must never read PENDING — the wallet has stopped
    /// waiting and has released those funds for re-spending, so PENDING
    /// would contradict the balance the same wallet reports.
    #[test]
    fn outgoing_state_map_is_honest_for_every_send_state() {
        assert_eq!(
            outgoing_transfer_state(&sample_send_record(SendState::Dispatched)),
            TransferState::Pending
        );
        assert_eq!(
            outgoing_transfer_state(&sample_send_record(SendState::PresumedDead)),
            TransferState::Dropped
        );
        assert_eq!(
            outgoing_transfer_state(&sample_send_record(SendState::Confirmed { height: 200 })),
            TransferState::Confirmed
        );
        assert_eq!(
            outgoing_transfer_state(&sample_send_record(SendState::TerminalRejected)),
            TransferState::Failed
        );
    }

    /// Only a refresh-observed confirmation yields a height. The
    /// journal's `dispatched_at_height` is a local sync counter, and
    /// projecting it would both invent a block number for a tx that was
    /// never mined and make the projected height move backwards when a
    /// reorg flips a confirmed row back to `Dispatched`.
    #[test]
    fn only_confirmed_sends_have_an_inclusion_height() {
        assert_eq!(
            outgoing_block_height(&sample_send_record(SendState::Confirmed { height: 250 })),
            Some(250)
        );
        for unmined in [
            SendState::Dispatched,
            SendState::TerminalRejected,
            SendState::PresumedDead,
        ] {
            assert_eq!(
                outgoing_block_height(&sample_send_record(unmined)),
                None,
                "{unmined:?} must not report an inclusion height"
            );
        }
    }

    #[test]
    fn outgoing_view_projects_txid_id_fee_and_recipient_sum() {
        let txid = TxHash::from_bytes([0xab; 32]);
        let view = outgoing_transfer_view(
            &txid,
            &sample_send_record(SendState::Confirmed { height: 250 }),
        )
        .expect("project");
        assert_eq!(view.id, "ab".repeat(32));
        assert_eq!(view.tx_hash, view.id);
        assert_eq!(view.direction, TransferDirection::Outgoing);
        assert_eq!(view.amount, "3500"); // 1000 + 2500
        assert_eq!(view.fee, "700");
        assert_eq!(view.block_height, Some(250));
        assert_eq!(view.state, TransferState::Confirmed);
        assert_eq!(view.spent_height, None);

        let failed =
            outgoing_transfer_view(&txid, &sample_send_record(SendState::TerminalRejected))
                .expect("project");
        assert_eq!(failed.state, TransferState::Failed);
        assert_eq!(failed.block_height, None);

        // Wire pins: FAILED is a first-class OpenAPI enum value, and a
        // send that was never mined serializes no `block_height` key at
        // all rather than a plausible-looking height (rule 82).
        let json = serde_json::to_value(&failed).expect("serialize");
        assert_eq!(json["state"], "FAILED");
        assert_eq!(json["direction"], "OUTGOING");
        assert!(
            json.get("block_height").is_none(),
            "unmined send must not carry a block_height: {json}"
        );

        let dropped = outgoing_transfer_view(&txid, &sample_send_record(SendState::PresumedDead))
            .expect("project");
        let json = serde_json::to_value(&dropped).expect("serialize");
        assert_eq!(json["state"], "DROPPED");
    }

    /// A row whose recipient amounts do not sum cannot have come from
    /// the journal write path, so the read side reports it rather than
    /// panicking — the workspace builds `panic = "abort"`, which would
    /// turn a history query into a daemon outage.
    #[test]
    fn unsummable_recipient_amounts_do_not_panic_the_read_path() {
        let mut row = sample_send_record(SendState::Dispatched);
        row.recipients[0].amount = u64::MAX;
        let err = outgoing_transfer_view(&TxHash::from_bytes([0xab; 32]), &row)
            .expect_err("overflowing recipient sum must not project");
        assert!(matches!(err, WalletRpcError::InternalError(_)), "{err:?}");
    }

    /// The two id grammars are disjoint, so a well-formed id names
    /// exactly one side of the history.
    #[test]
    fn lookup_id_routes_each_shape_to_its_own_side() {
        let hash_hex = "0a".repeat(32);
        assert_eq!(
            parse_lookup_id(&format!("{hash_hex}:7")),
            Some(TransferLookupId::Incoming {
                tx_hash: TxHash::from_bytes([0x0a; 32]),
                output_index: 7,
            })
        );
        assert_eq!(
            parse_lookup_id(&hash_hex),
            Some(TransferLookupId::Outgoing {
                tx_hash: TxHash::from_bytes([0x0a; 32]),
            })
        );
    }

    /// Ids this wallet never emits are rejected as malformed rather
    /// than answered with "unknown transfer" — including the uppercase
    /// txid a user gets by pasting from a block explorer, where saying
    /// "no such transfer" would be an outright wrong answer about a
    /// send that does exist (rule 82).
    #[test]
    fn lookup_id_rejects_ids_this_wallet_never_emits() {
        for bad in [
            String::new(),
            "no-colon-not-hex".to_owned(),
            "0A".repeat(32),                   // uppercase txid
            "0a".repeat(31),                   // short
            "0a".repeat(33),                   // long
            format!("{}:07", "0a".repeat(32)), // leading zero in index
            format!("{}:", "0a".repeat(32)),   // empty index
        ] {
            assert!(parse_lookup_id(&bad).is_none(), "accepted {bad:?}");
        }
    }
}
