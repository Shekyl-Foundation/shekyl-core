// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A source the supervisor's wait polls until its sender closes.
//!
//! One rule, for a watch and for a channel. [`until_value`] returns the
//! sender's end once, as `None`, and clears [`Live::open`]. Later polls
//! pend, so a closed sender cannot end another wait. A closed watch
//! answers `changed` at once, every time, and a closed channel's `recv`
//! returns `None` at once, every time. Either would spin the loop if the
//! wait kept polling it.
//!
//! The inner source stays. The driver still borrows a watch and still
//! reads how many events the sink dropped. What leaves the wait is the
//! polling.
//!
//! A new sink joins the wait as a [`Live`] around its receiver and one
//! arm in the select. The bootstrap watch is not one: it also leaves
//! after `Ready` or `Failed`, while its sender may still be held, and a
//! respawn installs another.

use std::future::Future;

use shekyl_tor_control_client::control::{ControlReply, EventReceiver};
use tokio::sync::{mpsc, watch};

/// One source of the wait, polled until its sender closes.
///
/// `open` is private. A closed sender takes the source out, and nothing
/// puts it back: these senders do not reopen.
pub(in super::super) struct Live<T> {
    inner: T,
    /// The sender has not closed, so the wait still polls this source.
    open: bool,
}

impl<T> Live<T> {
    /// A source the wait polls. `inner` is still read through [`Self::source`].
    pub(in super::super) fn new(inner: T) -> Self {
        Self { inner, open: true }
    }

    /// The receiver the driver reads outside the wait.
    pub(in super::super) fn source(&self) -> &T {
        &self.inner
    }

    /// A mutable borrow of the receiver, for a drain outside the wait.
    pub(in super::super) fn source_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Whether the wait still polls this source.
    #[cfg(test)]
    pub(in super::super) fn is_open(&self) -> bool {
        self.open
    }
}

impl<T: Copy> Live<watch::Receiver<T>> {
    /// The next value, or `None` once the sender is gone.
    ///
    /// A value leaves this source in the wait. `None` takes it out.
    /// The value is copied in the same poll that observes it, so a
    /// cancelled wait cannot mark it seen and then drop it.
    pub(in super::super) async fn changed(&mut self) -> Option<T> {
        let Live { open, inner } = self;
        until_value(open, async move {
            match inner.changed().await {
                Err(_) => None,
                Ok(()) => Some(*inner.borrow_and_update()),
            }
        })
        .await
    }
}

impl<T> Live<mpsc::Receiver<T>> {
    /// The next item, or `None` once the sender is gone.
    ///
    /// An item leaves this source in the wait. `None` takes it out.
    pub(in super::super) async fn recv(&mut self) -> Option<T> {
        let Live { open, inner } = self;
        until_value(open, inner.recv()).await
    }
}

impl Live<EventReceiver> {
    /// The next event, or `None` once every sender is gone.
    ///
    /// An event leaves this source in the wait. `None` takes it out.
    /// The driver holds a sender for the life of the wait, so a close
    /// is a sender that was dropped, not an event.
    pub(in super::super) async fn recv(&mut self) -> Option<ControlReply> {
        let Live { open, inner } = self;
        until_value(open, inner.recv()).await
    }
}

/// `next`'s next value, or `None` once and then not again.
///
/// `next` reports a value as `Some` and a closed sender as `None`. A
/// watch's `next` copies the value out before it returns. This function
/// does not await between that return and its own.
async fn until_value<T>(open: &mut bool, next: impl Future<Output = Option<T>>) -> Option<T> {
    if !*open {
        std::future::pending::<()>().await;
    }
    match next.await {
        Some(value) => Some(value),
        None => {
            *open = false;
            None
        }
    }
}
