// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One log subscriber for this test binary, and a buffer per thread.
//!
//! `tracing` caches each callsite's interest for the process. A
//! thread-local subscriber races every other test that reaches the same
//! callsite with no subscriber: whichever registers it first can cache it
//! as never, and the capture then sees nothing. This subscriber is global
//! from the first [`Capture::open`], and [`Subscriber::register_callsite`]
//! returns [`Interest::sometimes`], so `enabled` is asked on every event
//! and a callsite cannot stick at never. The buffer fills only on a thread
//! inside an open [`Capture`], and only at `error`.
//!
//! [`Capture`] is `!Send`. Holding it across an `.await` keeps the test on
//! the current-thread runtime, which is where the service's tasks run, so
//! the thread that records the fault is the thread that holds the buffer.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

std::thread_local! {
    static CAPTURE: std::cell::RefCell<Option<Vec<(Level, String)>>> =
        const { std::cell::RefCell::new(None) };
}

static NEXT_SPAN: AtomicU64 = AtomicU64::new(1);

/// Installed once. The buffer lives in [`CAPTURE`], not here, so the
/// subscriber stays `Sync` while each test reads only its own thread.
struct Global;

impl Subscriber for Global {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        meta.level() == &Level::ERROR && CAPTURE.with(|slot| slot.borrow().is_some())
    }

    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        let id = NEXT_SPAN.fetch_add(1, Ordering::Relaxed);
        Id::from_u64(id.max(1))
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0 = value.to_owned();
                }
            }

            fn record_debug(
                &mut self,
                field: &tracing::field::Field,
                value: &dyn core::fmt::Debug,
            ) {
                if field.name() == "message" && self.0.is_empty() {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        CAPTURE.with(|slot| {
            if let Some(lines) = slot.borrow_mut().as_mut() {
                lines.push((*event.metadata().level(), message.0));
            }
        });
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(Global)
            .expect("no other global subscriber in this test binary");
    });
}

/// The calling thread's `error` lines, from [`Self::open`] until drop.
///
/// `!Send`: the buffer is the thread's, and a future that holds this
/// across an `.await` stays on the current-thread runtime.
pub(crate) struct Capture {
    _thread: PhantomData<*const ()>,
}

impl Capture {
    /// Start capturing this thread's `error` lines.
    #[must_use]
    pub(crate) fn open() -> Self {
        install();
        CAPTURE.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        Self {
            _thread: PhantomData,
        }
    }

    /// What this thread has logged at `error` since [`Self::open`].
    pub(crate) fn lines(&self) -> Vec<(Level, String)> {
        let _held = self._thread;
        CAPTURE.with(|slot| slot.borrow().clone().unwrap_or_default())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        CAPTURE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
