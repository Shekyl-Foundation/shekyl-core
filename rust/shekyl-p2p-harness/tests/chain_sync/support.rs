// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared by the chain-sync loopback tests.
//!
//! `chain_sync_loopback.rs` drives the scripted peers and the serving
//! queue. `chain_sync_claim_relay.rs` drives the inbound claim and the
//! relay fan-out. Both read the owner's close lines through one
//! subscriber, and both start a node from the spend corpus. A file under
//! `tests/chain_sync/` is not its own test crate.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_chain_sync::SyncState;
use shekyl_draw_rng::SplitMix64;
use shekyl_hash_budget::Budget;
use shekyl_p2p_harness::sync::{substrate, Chain, Corpus, Node, Step};
use shekyl_seam::SyncPayload;
use shekyl_types::BlockHash;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// The ceiling on every wait for something to happen. Each wait returns
/// the moment its condition holds, which here takes seconds to a minute:
/// mostly real RandomX over a corpus's headers. The ceiling is for a
/// loaded runner, where fourteen of these share the cores, and it measures
/// nothing.
pub(crate) const LIMIT: Duration = Duration::from_secs(900);

// ---------------------------------------------------------------- logs --

/// Every close the owner logged: (node tag, session, cause).
pub(crate) static CLOSES: Mutex<Vec<(String, u64, String)>> = Mutex::new(Vec::new());

struct Tag(String);

#[derive(Default)]
struct Fields {
    tag: Option<String>,
    message: String,
    session: Option<u64>,
    cause: Option<String>,
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "session" {
            self.session = Some(value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "tag" {
            self.tag = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "cause" => self.cause = Some(format!("{value:?}")),
            // The owner logs its `Session` by `Display`, the socket id.
            "session" => self.session = format!("{value:?}").parse().ok(),
            "tag" => self.tag = Some(format!("{value:?}").trim_matches('"').to_owned()),
            _ => {}
        }
    }
}

struct Closes;

impl<S> Layer<S> for Closes
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if let (Some(tag), Some(span)) = (fields.tag, ctx.span(id)) {
            span.extensions_mut().insert(Tag(tag));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        if !fields.message.contains("closes a session") {
            return;
        }
        let tag = ctx.event_scope(event).and_then(|scope| {
            scope
                .from_root()
                .find_map(|span| span.extensions().get::<Tag>().map(|tag| tag.0.clone()))
        });
        if let (Some(tag), Some(session), Some(cause)) = (tag, fields.session, fields.cause) {
            CLOSES.lock().expect("closes").push((tag, session, cause));
        }
    }
}

pub(crate) fn logs() {
    let _installed = tracing_subscriber::registry()
        .with(Closes)
        .with(
            tracing_subscriber::fmt::layer()
                .with_test_writer()
                .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
        )
        .try_init();
}

// ------------------------------------------------------------- helpers --

/// The node's draw source: seeded, so a run repeats.
pub(crate) fn rng() -> SplitMix64 {
    SplitMix64::new(0x5EED)
}

/// A peer's handshake claim: its block count and cumulative work.
pub(crate) fn claim(count: u64, work: u128, top: BlockHash) -> SyncPayload {
    SyncPayload {
        current_height: count,
        cumulative_difficulty: u64::try_from(work & u128::from(u64::MAX)).expect("low"),
        cumulative_difficulty_top64: u64::try_from(work >> 64).expect("high"),
        top_id: *top.as_bytes(),
    }
}

/// The claim a chain's own tip makes.
pub(crate) fn claim_of(chain: &Chain) -> SyncPayload {
    let (count, work, top) = chain.tip().expect("a chain");
    claim(count, work, top)
}

/// A store holding `steps`, connected from its own node.
pub(crate) async fn source(tag: &str, corpus: &Corpus, steps: &[Step]) -> Chain {
    let (substrate, _) = substrate();
    let chain = Chain::empty(
        tag,
        corpus.rules(),
        Arc::new(substrate),
        Budget::new(NonZeroUsize::new(4).expect("four")),
    );
    chain.apply(steps).await;
    chain
}

pub(crate) fn spend() -> (Corpus, Vec<Step>) {
    let corpus = Corpus::open("spend-1in-2out");
    let steps = corpus.steps();
    (corpus, steps)
}

pub(crate) async fn wait_synced(node: &Node, count: u64) {
    let synced = node
        .wait(LIMIT, |node| {
            node.state() == SyncState::Synced && node.count() == count
        })
        .await;
    assert!(
        synced,
        "state {:?}, count {} of {count}",
        node.state(),
        node.count()
    );
}
