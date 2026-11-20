// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bundles between nodes, 2015–2017 (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5,
//! `SCS-P25`, `SCS-P27`, `SCS-P28`; `SO-D12` 4b-T).
//!
//! - **A relayed bundle (2015)** is its reference and its body. The body
//!   must be the one its own reference names ([`relayed`]); a pair that is
//!   not is the sender's form failure. A pair that is goes to the queue's
//!   admission, the bundle rule against this node's tip, and is relayed on
//!   only if the queue admitted it. There is no second relay mechanism: a
//!   bundle this node filed and one a peer sent leave by the same 2015
//!   ([`relay_message`]), fluffed, with no stem (`SCS-P25`).
//! - **A body request (2016)** names prunable hashes. It is answered from
//!   the body store, whichever holder keeps a body ([`serve_bundle_bodies`]):
//!   in the order asked, each hash once, the first held body whatever its
//!   size and the rest under the body budget a block response uses.
//! - **A body response (2017)** is accepted by the asker only body by body
//!   against the references it asked for ([`accept_bundle_bodies`]): a hash
//!   it asked for, once, at the length the reference fixes, and on hash
//!   equality. Any other response is the responder's fault, and nothing in
//!   it is kept.

use std::collections::BTreeSet;

use shekyl_archival_retention::{BodyRefused, BundleBody, BundleRef, BundleWireError};
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_levin::{
    HeldBundleBody, NewBundle, PortableMap, RequestBundleBodies, ResponseBundleBodies,
    BODIES_RESPONSE_BYTES, HASH_SIZE,
};
use shekyl_p2p_session::Message;

/// Why a relayed bundle was not taken: each is the sender's form failure,
/// and its session closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayRefused {
    /// The payload is not a 2015.
    Undecodable(String),
    /// The reference does not parse.
    Reference(BundleWireError),
    /// The body is not the one the reference names.
    Body(BodyRefused),
}

/// The bundle a 2015 carries: its reference, and the body that reference
/// names.
///
/// # Errors
///
/// [`RelayRefused`]: the payload, the reference, or the body does not hold.
pub fn relayed(payload: &[u8]) -> Result<(BundleRef, BundleBody), RelayRefused> {
    let message =
        NewBundle::load(payload).map_err(|err| RelayRefused::Undecodable(err.to_string()))?;
    let reference = BundleRef::decode(&message.reference).map_err(RelayRefused::Reference)?;
    let body = reference
        .accept_body(&message.body)
        .map_err(RelayRefused::Body)?;
    Ok((reference, body))
}

/// The 2015 that relays `reference` and `body`.
#[must_use]
pub fn relay_message(reference: &BundleRef, body: &BundleBody) -> Message {
    Message::NewBundle(NewBundle {
        reference: reference.encode(),
        body: body.as_bytes().to_vec(),
    })
}

/// Answer a body request from `store` (module docs).
///
/// # Errors
///
/// The store's own fault. A hash the store holds no body for is not one:
/// it is left out of the answer.
pub fn serve_bundle_bodies(
    store: &ChainStore,
    request: &RequestBundleBodies,
) -> Result<ResponseBundleBodies, StoreError> {
    let snap = store.begin_read()?;
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).unwrap_or(usize::MAX);
    let mut seen = BTreeSet::new();
    let mut bodies = Vec::new();
    let mut sent = 0usize;
    for hash in &request.hashes {
        if !seen.insert(*hash) {
            continue;
        }
        let Some(body) = snap.bundle_body(hash)? else {
            continue;
        };
        let bytes = body.as_bytes();
        let next = sent.saturating_add(bytes.len());
        if !bodies.is_empty() && next > budget {
            break;
        }
        sent = next;
        bodies.push(HeldBundleBody {
            hash: *hash,
            body: bytes.to_vec(),
        });
    }
    Ok(ResponseBundleBodies { bodies })
}

/// Why a body response was refused: the responder's fault, and its
/// session closes. Nothing in a refused response is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodiesRefused {
    /// A body answers a hash that was not asked for.
    Unasked {
        /// The hash the body was sent under.
        hash: [u8; HASH_SIZE],
    },
    /// A hash is answered twice.
    Repeated {
        /// The hash answered twice.
        hash: [u8; HASH_SIZE],
    },
    /// A body is not the one its reference names.
    Body {
        /// The hash the body was sent under.
        hash: [u8; HASH_SIZE],
        /// Why: its length, or its hash.
        refused: BodyRefused,
    },
}

/// The bodies a response carries for the references `asked`, each with its
/// position in `asked` (module docs). A hash not answered is simply absent:
/// the asker asks again, here or elsewhere.
///
/// # Errors
///
/// [`BodiesRefused`] for the first body that is not an answer to `asked`.
pub fn accept_bundle_bodies(
    asked: &[BundleRef],
    response: &ResponseBundleBodies,
) -> Result<Vec<(usize, BundleBody)>, BodiesRefused> {
    let mut answered = BTreeSet::new();
    let mut accepted = Vec::with_capacity(response.bodies.len());
    for held in &response.bodies {
        let Some(index) = asked
            .iter()
            .position(|reference| reference.prunable_hash() == &held.hash)
        else {
            return Err(BodiesRefused::Unasked { hash: held.hash });
        };
        if !answered.insert(held.hash) {
            return Err(BodiesRefused::Repeated { hash: held.hash });
        }
        let body = asked[index]
            .accept_body(&held.body)
            .map_err(|refused| BodiesRefused::Body {
                hash: held.hash,
                refused,
            })?;
        accepted.push((index, body));
    }
    Ok(accepted)
}

#[cfg(test)]
#[path = "bundles_tests.rs"]
mod tests;
