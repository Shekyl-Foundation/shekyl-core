// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Domain → OpenAPI projections (accounting facts only; no secrets).

use shekyl_engine_core::PendingTx;
use shekyl_engine_core::RefreshSummary;
use shekyl_engine_core::SubmitOutcome;
use shekyl_engine_state::{DisputeReason, ReceiveAttribution, TransferDetails};
use shekyl_scanner::BalanceSummary;
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;

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
        // Ledger rows are receive-side outputs; outgoing spends are
        // reflected as Spent state on the same row until a dedicated
        // outgoing history surface lands (WALLET_SEND_RECORD.md / PR-SJ-2).
        direction: TransferDirection::Incoming,
        tx_hash: td.tx_hash.to_string(),
        amount: atomic_units_string(td.amount()),
        fee: "0".to_owned(),
        block_height: i64::try_from(td.block_height).unwrap_or(i64::MAX),
        state: transfer_state(td),
        spent_height: td
            .spent_height
            .map(|h| i64::try_from(h).unwrap_or(i64::MAX)),
        attribution: attribution_view(&td.receive_attribution),
    }
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
}
