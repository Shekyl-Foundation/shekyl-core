// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The found-block sink. One thread, started from inside the runtime the
//! door was built on. Each block enters through [`Door::offer_local`]
//! inside [`FoundInbox::answer_with`], so the answer is recorded when the
//! door returns and not when the block is taken off the queue. A full
//! window waits for the reserved seat instead of dropping the block. A
//! closed door answers `Stopped`.

use std::sync::PoisonError;

use shekyl_miner::FoundInbox;
use shekyl_wire::Transaction;

use super::Postings;
use crate::service::{ArrivalTag, Door};

/// The found-block sink's thread. Short enough for a platform thread name.
const THREAD_NAME: &str = "shekyl-found";

/// What became of a block this node mined, when it did not join the chain.
fn say_mined(reply: &crate::service::Reply) {
    use crate::service::Reply;
    match reply {
        Reply::Connected { .. } | Reply::Switched { .. } | Reply::Stopped => {}
        Reply::Refused(verdict) => {
            tracing::error!("a block this node mined was refused: {verdict:?}");
        }
        other => tracing::warn!("a block this node mined did not connect: {other:?}"),
    }
}

/// Sends when the sink leaves its loop, including by a panic.
struct SignalDone(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for SignalDone {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            let _sent = done.send(());
        }
    }
}

/// The sink thread. It ends when the inbox closes or the last sender
/// drops, and the queue is empty. Called from inside the runtime `door`
/// was built on.
pub(crate) fn spawn_sink(
    inbox: FoundInbox,
    door: Door,
    postings: Postings,
    done: tokio::sync::oneshot::Sender<()>,
) -> std::thread::JoinHandle<()> {
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || {
            let _done = SignalDone(Some(done));
            while inbox
                .answer_with(|found| {
                    let bodies = {
                        let kept = postings.lock().unwrap_or_else(PoisonError::into_inner);
                        match kept.get(&found.generation) {
                            Some(kept) => {
                                // Height and parent are this posting's tip. A
                                // block that names another is logged; the door
                                // judges the block, with this posting's bodies.
                                if found.height != kept.job.height
                                    || found.block.header.previous
                                        != kept.job.block.header.previous
                                {
                                    tracing::error!(
                                        generation = found.generation.to_raw(),
                                        "a block this node mined names a generation built for another tip"
                                    );
                                }
                                kept.bodies.clone()
                            }
                            None => Vec::new(),
                        }
                    };
                    // The local-arrival entry waits out a full window. A closed
                    // door answers `Stopped`. Anything else is this node's own
                    // block not joining the chain, and it is said once.
                    let offered = runtime.block_on(door.offer_local(
                        ArrivalTag(found.generation.to_raw()),
                        found.block.serialize(),
                        bodies.iter().map(Transaction::serialize).collect(),
                    ));
                    match offered {
                        Ok(tagged) => say_mined(&tagged.reply),
                        Err(refused) => tracing::error!(
                            "a block this node mined was not accepted at the door: {refused:?}"
                        ),
                    }
                })
                .is_some()
            {}
        })
        .expect("the found-block sink starts")
}
