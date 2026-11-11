// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node's one end watch ([`Node::ended`](crate::Node::ended)).
//!
//! A long-lived task the node starts can end on its own: chain sync's
//! owner loses its port, the ingest service stops on a fault. The node is
//! then half up. The process runs and the RPC answers, but nothing syncs
//! or nothing connects. Nobody is served by that node, so the daemon
//! stops on it and exits failed (rule 82).
//!
//! Every such task reports its end here, and the daemon waits on this one
//! watch. The first end is the one kept: a later one is usually its
//! consequence. A task that ends because it was asked to stop does not
//! report.

use shekyl_chain_ingest::service::ServiceEnd;
use shekyl_chain_sync_runtime::owner::{EndCause, Ended as SyncEnded};
use tokio::sync::watch;

/// The first fatal end of a task the node owns, with its cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeEnd {
    /// Chain sync's owner ended on its own: the node never syncs again.
    Sync(EndCause),
    /// The ingest service stopped on a fault: the node connects no block
    /// and posts no template.
    Ingest(ServiceEnd),
}

impl std::fmt::Display for NodeEnd {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sync(cause) => write!(formatter, "chain sync stopped: {cause}"),
            Self::Ingest(cause) => write!(formatter, "the ingest service stopped: {cause}"),
        }
    }
}

/// The sending side of the node's end watch. One per node; each producer
/// holds a clone.
#[derive(Clone)]
pub(crate) struct Reporter(watch::Sender<Option<NodeEnd>>);

impl Reporter {
    pub(crate) fn new() -> Self {
        Self(watch::Sender::new(None))
    }

    /// A receiver of the watch: `None` while every task runs.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<NodeEnd>> {
        self.0.subscribe()
    }

    /// Report `end`. Kept only when it is the first.
    pub(crate) fn report(&self, end: NodeEnd) {
        self.0.send_if_modified(|first| {
            if first.is_some() {
                return false;
            }
            *first = Some(end);
            true
        });
    }
}

/// Report the first value of `source` that `fatal` maps to an end, then
/// return. Returns without a report when `source` closes first: its task
/// went without a fatal end.
pub(crate) async fn forward<T: Copy>(
    reporter: Reporter,
    mut source: watch::Receiver<Option<T>>,
    fatal: fn(T) -> Option<NodeEnd>,
) {
    loop {
        let seen = *source.borrow_and_update();
        if let Some(end) = seen.and_then(fatal) {
            reporter.report(end);
            return;
        }
        if source.changed().await.is_err() {
            return;
        }
    }
}

/// Chain sync's owner: a failed end is fatal, a stop it was asked for is
/// not.
pub(crate) const fn sync_end(ended: SyncEnded) -> Option<NodeEnd> {
    match ended {
        SyncEnded::Failed(cause) => Some(NodeEnd::Sync(cause)),
        SyncEnded::Stopped => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime")
    }

    /// The ingest service's fault reaches the node's watch with its cause.
    /// Red edit: drop the ingest forwarder in `Node::open`'s wiring, which
    /// this test mirrors, and the watch stays `None`.
    #[test]
    fn an_ingest_fault_is_the_nodes_end() {
        runtime().block_on(async {
            let reporter = Reporter::new();
            let mut ended = reporter.subscribe();
            let (service, source) = watch::channel(None);
            let task = tokio::spawn(forward(reporter, source, |end| Some(NodeEnd::Ingest(end))));
            assert_eq!(*ended.borrow(), None);
            service.send_replace(Some(ServiceEnd::Connector));
            ended.changed().await.expect("the node's watch is open");
            assert_eq!(
                *ended.borrow(),
                Some(NodeEnd::Ingest(ServiceEnd::Connector))
            );
            task.await.expect("the forwarder returns after its report");
        });
    }

    /// A sync owner that was asked to stop is not an end; one that failed
    /// is.
    #[test]
    fn a_stopped_sync_owner_is_not_an_end_and_a_failed_one_is() {
        runtime().block_on(async {
            let reporter = Reporter::new();
            let ended = reporter.subscribe();
            let (owner, source) = watch::channel(Some(SyncEnded::Stopped));
            let task = tokio::spawn(forward(reporter.clone(), source, sync_end));
            tokio::task::yield_now().await;
            assert_eq!(*ended.borrow(), None, "a stop is not reported");
            owner.send_replace(Some(SyncEnded::Failed(EndCause::PortClosed)));
            task.await.expect("the forwarder returns after its report");
            assert_eq!(*ended.borrow(), Some(NodeEnd::Sync(EndCause::PortClosed)));
        });
    }

    /// The first end is kept: a later one is its consequence.
    #[test]
    fn the_first_end_is_the_one_kept() {
        let reporter = Reporter::new();
        let ended = reporter.subscribe();
        reporter.report(NodeEnd::Ingest(ServiceEnd::Store));
        reporter.report(NodeEnd::Sync(EndCause::TipWatchClosed));
        assert_eq!(*ended.borrow(), Some(NodeEnd::Ingest(ServiceEnd::Store)));
    }

    /// A source that closes without a fatal end reports nothing.
    #[test]
    fn a_source_that_closes_reports_nothing() {
        runtime().block_on(async {
            let reporter = Reporter::new();
            let ended = reporter.subscribe();
            let (service, source) = watch::channel::<Option<ServiceEnd>>(None);
            drop(service);
            forward(reporter, source, |end| Some(NodeEnd::Ingest(end))).await;
            assert_eq!(*ended.borrow(), None);
        });
    }
}
