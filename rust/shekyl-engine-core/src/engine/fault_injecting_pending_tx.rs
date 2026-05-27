// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `FaultInjecting<P: PendingTxEngine>` — composable failure-injection
//! wrapper for the [`PendingTxEngine`] trait surface (Stage 1 PR 5
//! C7 test substrate).
//!
//! Mirrors [`super::fault_injecting_refresh::FaultInjecting`] and
//! [`super::fault_injecting_ledger::FaultInjecting`]: three independent
//! FIFO queues (one per fallible method), pop-before-delegate semantics,
//! drain inspector, and `debug_assert!` on [`Drop`].

use std::collections::VecDeque;
use std::sync::Mutex;

use super::error::{PendingTxError, SendError, SubmitError};
use super::pending::{PendingTx, ReservationId, TxHash, TxRequest};
use super::traits::pending_tx::PendingTxEngine;

/// Composable failure-injection wrapper over any
/// [`PendingTxEngine`] implementor.
pub(crate) struct FaultInjecting<P: PendingTxEngine> {
    inner: P,
    queued_build_failures: Mutex<VecDeque<SendError>>,
    queued_submit_failures: Mutex<VecDeque<SubmitError>>,
    queued_discard_failures: Mutex<VecDeque<PendingTxError>>,
}

impl<P: PendingTxEngine> FaultInjecting<P> {
    #[allow(dead_code)]
    pub(crate) fn new(inner: P) -> Self {
        Self {
            inner,
            queued_build_failures: Mutex::new(VecDeque::new()),
            queued_submit_failures: Mutex::new(VecDeque::new()),
            queued_discard_failures: Mutex::new(VecDeque::new()),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn queue_build_failure(&self, err: SendError) {
        self.queued_build_failures
            .lock()
            .expect("FaultInjecting build queue poisoned")
            .push_back(err);
    }

    #[allow(dead_code)]
    pub(crate) fn queue_submit_failure(&self, err: SubmitError) {
        self.queued_submit_failures
            .lock()
            .expect("FaultInjecting submit queue poisoned")
            .push_back(err);
    }

    #[allow(dead_code)]
    pub(crate) fn queue_discard_failure(&self, err: PendingTxError) {
        self.queued_discard_failures
            .lock()
            .expect("FaultInjecting discard queue poisoned")
            .push_back(err);
    }

    #[allow(dead_code)]
    pub(crate) fn queued_build_failures(&self) -> usize {
        self.queued_build_failures
            .lock()
            .expect("FaultInjecting build queue poisoned")
            .len()
    }

    #[allow(dead_code)]
    pub(crate) fn queued_submit_failures(&self) -> usize {
        self.queued_submit_failures
            .lock()
            .expect("FaultInjecting submit queue poisoned")
            .len()
    }

    #[allow(dead_code)]
    pub(crate) fn queued_discard_failures(&self) -> usize {
        self.queued_discard_failures
            .lock()
            .expect("FaultInjecting discard queue poisoned")
            .len()
    }
}

impl<P: PendingTxEngine> Drop for FaultInjecting<P> {
    fn drop(&mut self) {
        let build = self
            .queued_build_failures
            .get_mut()
            .map(|q| q.len())
            .unwrap_or(0);
        let submit = self
            .queued_submit_failures
            .get_mut()
            .map(|q| q.len())
            .unwrap_or(0);
        let discard = self
            .queued_discard_failures
            .get_mut()
            .map(|q| q.len())
            .unwrap_or(0);
        let remaining = build + submit + discard;
        debug_assert!(
            remaining == 0,
            "FaultInjecting<P> dropped with {remaining} queued failure(s) un-consumed \
             (build={build}, submit={submit}, discard={discard})"
        );
    }
}

impl<P: PendingTxEngine> PendingTxEngine for FaultInjecting<P> {
    fn build(
        &self,
        request: TxRequest,
    ) -> impl std::future::Future<Output = Result<PendingTx, SendError>> + Send {
        let injected = self
            .queued_build_failures
            .lock()
            .expect("FaultInjecting build queue poisoned")
            .pop_front();
        async move {
            if let Some(err) = injected {
                return Err(err);
            }
            self.inner.build(request).await
        }
    }

    fn submit(
        &self,
        id: ReservationId,
    ) -> impl std::future::Future<Output = Result<TxHash, SubmitError>> + Send {
        let injected = self
            .queued_submit_failures
            .lock()
            .expect("FaultInjecting submit queue poisoned")
            .pop_front();
        async move {
            if let Some(err) = injected {
                return Err(err);
            }
            self.inner.submit(id).await
        }
    }

    fn discard(
        &self,
        id: ReservationId,
        reason: super::diagnostics::DiscardReason,
    ) -> Result<(), PendingTxError> {
        if let Some(err) = self
            .queued_discard_failures
            .lock()
            .expect("FaultInjecting discard queue poisoned")
            .pop_front()
        {
            return Err(err);
        }
        self.inner.discard(id, reason)
    }

    fn signal_mempool_evicted(
        &self,
        rid: ReservationId,
    ) -> Result<(), PendingTxError> {
        self.inner.signal_mempool_evicted(rid)
    }

    fn outstanding(&self) -> usize {
        self.inner.outstanding()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::engine::diagnostics::DiscardReason;
    use crate::engine::pending::FeePriority;
    use crate::engine::traits::PendingTxEngine;

    struct DelegationStub {
        outstanding: AtomicUsize,
    }

    impl DelegationStub {
        const fn new() -> Self {
            Self {
                outstanding: AtomicUsize::new(0),
            }
        }
    }

    impl PendingTxEngine for DelegationStub {
        fn build(
            &self,
            _request: TxRequest,
        ) -> impl std::future::Future<Output = Result<PendingTx, SendError>> + Send {
            self.outstanding.fetch_add(1, Ordering::SeqCst);
            async {
                Ok(PendingTx {
                    id: ReservationId::new(0),
                    built_at_height: 0,
                    built_at_tip_hash: [0u8; 32],
                    fee_atomic_units: 0,
                    snapshot_id: super::super::pending::SnapshotId([0u8; 16]),
                    tx_bytes: Vec::new(),
                    recipients: Vec::new(),
                })
            }
        }

        fn submit(
            &self,
            _id: ReservationId,
        ) -> impl std::future::Future<Output = Result<TxHash, SubmitError>> + Send {
            async {
                Ok(TxHash([1u8; 32]))
            }
        }

        fn discard(
            &self,
            _id: ReservationId,
            _reason: DiscardReason,
        ) -> Result<(), PendingTxError> {
            self.outstanding.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }

        fn signal_mempool_evicted(
            &self,
            _rid: ReservationId,
        ) -> Result<(), PendingTxError> {
            Ok(())
        }

        fn outstanding(&self) -> usize {
            self.outstanding.load(Ordering::SeqCst)
        }
    }

    fn standard_request() -> TxRequest {
        TxRequest {
            recipients: vec![super::super::pending::TxRecipient {
                address: "addr".into(),
                amount_atomic_units: 1,
            }],
            priority: FeePriority::Standard,
            from_subaddress: None,
        }
    }

    #[tokio::test]
    async fn empty_queue_delegates_to_inner() {
        let wrapper = FaultInjecting::new(DelegationStub::new());
        assert_eq!(wrapper.queued_build_failures(), 0);

        let pending = wrapper.build(standard_request()).await.expect("build ok");
        assert_eq!(wrapper.outstanding(), 1);
        let hash = wrapper.submit(pending.id).await.expect("submit ok");
        assert_eq!(hash.0, [1u8; 32]);
        assert_eq!(wrapper.queued_build_failures(), 0);
        assert_eq!(wrapper.queued_submit_failures(), 0);
    }

    #[tokio::test]
    async fn single_build_injection_consumed_then_delegates() {
        let wrapper = FaultInjecting::new(DelegationStub::new());
        wrapper.queue_build_failure(SendError::InsufficientFunds {
            needed: 1,
            available: 0,
        });

        let err = wrapper.build(standard_request()).await.unwrap_err();
        assert!(matches!(err, SendError::InsufficientFunds { .. }));
        assert_eq!(wrapper.queued_build_failures(), 0);

        let pending = wrapper.build(standard_request()).await.expect("second build");
        assert_eq!(wrapper.outstanding(), 1);
        wrapper
            .discard(pending.id, DiscardReason::ConsumerExplicit)
            .expect("discard");
    }

    #[tokio::test]
    async fn multi_injection_fifo_build() {
        let wrapper = FaultInjecting::new(DelegationStub::new());
        wrapper.queue_build_failure(SendError::InsufficientFunds {
            needed: 1,
            available: 0,
        });
        wrapper.queue_build_failure(SendError::CannotSign {
            reason: "fifo-2",
        });

        assert!(matches!(
            wrapper.build(standard_request()).await,
            Err(SendError::InsufficientFunds { .. })
        ));
        assert!(matches!(
            wrapper.build(standard_request()).await,
            Err(SendError::CannotSign { .. })
        ));
        assert!(wrapper.build(standard_request()).await.is_ok());
        assert_eq!(wrapper.queued_build_failures(), 0);
    }

    #[tokio::test]
    async fn submit_and_discard_injection_fifo() {
        let wrapper = FaultInjecting::new(DelegationStub::new());
        let pending = wrapper.build(standard_request()).await.expect("build");

        wrapper.queue_submit_failure(SubmitError::ReservationNotFound {
            reservation_id: pending.id,
        });
        assert!(matches!(
            wrapper.submit(pending.id).await,
            Err(SubmitError::ReservationNotFound { .. })
        ));
        assert!(wrapper.submit(pending.id).await.is_ok());

        wrapper.queue_discard_failure(PendingTxError::ReservationNotFound {
            reservation_id: pending.id,
        });
        assert!(matches!(
            wrapper.discard(pending.id, DiscardReason::ConsumerExplicit),
            Err(PendingTxError::ReservationNotFound { .. })
        ));
        wrapper
            .discard(pending.id, DiscardReason::ConsumerExplicit)
            .expect("delegated discard");
        assert_eq!(wrapper.queued_discard_failures(), 0);
    }

    #[tokio::test]
    async fn queued_build_failures_reflects_drain() {
        let wrapper = FaultInjecting::new(DelegationStub::new());
        wrapper.queue_build_failure(SendError::InsufficientFunds {
            needed: 1,
            available: 0,
        });
        wrapper.queue_build_failure(SendError::CannotSign {
            reason: "fifo-2",
        });
        assert_eq!(wrapper.queued_build_failures(), 2);

        assert!(wrapper.build(standard_request()).await.is_err());
        assert_eq!(wrapper.queued_build_failures(), 1);

        assert!(wrapper.build(standard_request()).await.is_err());
        assert_eq!(wrapper.queued_build_failures(), 0);

        let pending = wrapper.build(standard_request()).await.expect("delegates");
        wrapper
            .discard(pending.id, DiscardReason::ConsumerExplicit)
            .expect("discard");
    }

    #[test]
    #[should_panic(
        expected = "FaultInjecting<P> dropped with 1 queued failure(s) un-consumed"
    )]
    fn drop_debug_assert_on_leftover_build_failure() {
        let wrapper = FaultInjecting::new(DelegationStub::new());
        wrapper.queue_build_failure(SendError::InsufficientFunds {
            needed: 1,
            available: 0,
        });
        drop(wrapper);
    }
}
