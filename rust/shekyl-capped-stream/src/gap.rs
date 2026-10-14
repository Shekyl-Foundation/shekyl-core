// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake gap measures the peer's silence (Rick, 2026-10-14).
//!
//! The gap ends at the peer's first complete Levin frame, which the
//! connector's reader marks in a shared flag. The strand's verdict is this
//! node's own work and never ends it. When the gap's wake fires, the frame
//! may already sit in the socket: a driver that resumes after the deadline
//! (its workers held by something else, a stalled log call in the PR-3
//! measurement) sees the wake and the frame at once. Tokio's readiness for
//! the socket is only refreshed when its IO driver turns, so the reader can
//! still report nothing at that moment. [`SilenceGap`] therefore holds a
//! fired wake for one IO driver turn, during which the reader runs first,
//! and only then times the peer out.
//!
//! *Records-was:* the strand's verdict ended the gap, and the wake was
//! honoured as soon as it was seen. A frame that arrived before the
//! deadline timed its peer out whenever this node resumed after it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use tokio::time::Sleep;

/// How long a fired wake waits for the reader. Not a span: tokio's timer
/// fires only after its IO driver has collected the sockets' readiness in
/// the same turn, so any timer is one driver turn. One millisecond is the
/// timer's resolution.
const DRIVER_TURN: Duration = Duration::from_millis(1);

/// One connection's gap, between its wake and the reader's frame flag.
pub struct SilenceGap<W> {
    fired: Option<W>,
    turn: Option<Pin<Box<Sleep>>>,
}

impl<W> Default for SilenceGap<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W> SilenceGap<W> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fired: None,
            turn: None,
        }
    }

    /// `Ready(None)`: the peer's first complete frame arrived, and the gap
    /// is over. `Ready(Some(wake))`: the wake fired, and one IO driver turn
    /// later no frame had been read. Poll the reader before this in the
    /// same pass, and stop polling this once it is ready.
    pub fn poll<F>(
        &mut self,
        frame: &AtomicBool,
        wake: Pin<&mut F>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<W>>
    where
        F: Future<Output = W>,
    {
        if frame.load(Ordering::Acquire) {
            return Poll::Ready(None);
        }
        if self.turn.is_none() {
            let fired = ready!(wake.poll(cx));
            self.fired = Some(fired);
            self.turn = Some(Box::pin(tokio::time::sleep(DRIVER_TURN)));
        }
        if let Some(turn) = self.turn.as_mut() {
            ready!(turn.as_mut().poll(cx));
        }
        if frame.load(Ordering::Acquire) {
            return Poll::Ready(None);
        }
        Poll::Ready(self.fired.take())
    }
}
