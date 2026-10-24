// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scripted sync peers of CS-Q11.
//!
//! A [`ServingPeer`] answers from a real store through the node's own
//! responder (`shekyl_chain_sync_runtime::serve`), so an honest peer is the server
//! the node itself runs, and each adversary is that server with one answer
//! changed. A [`HeaderChainPeer`] serves a header chain no store holds: a
//! fork only a header path judges.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::ChainStore;
use shekyl_chain_sync_runtime::serve::{serve_bodies, serve_headers};
use shekyl_levin::{
    notify, PortableMap, RequestBodies, RequestHeaders, ResponseBodies, ResponseHeaders,
    SyncCommand, HASH_SIZE, HEADERS_RESPONSE_BYTES,
};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, SkeletonTx, TxBody};

use super::dial::SyncPeer;

/// What a peer was asked.
#[derive(Debug, Default)]
pub struct Seen {
    /// Header requests (2011).
    pub header_requests: AtomicUsize,
    /// Body requests (2013).
    pub body_requests: AtomicUsize,
    /// Anything else the node sent.
    pub other: AtomicUsize,
}

impl Seen {
    /// Header requests so far.
    #[must_use]
    pub fn headers(&self) -> usize {
        self.header_requests.load(Ordering::Acquire)
    }

    /// Body requests so far.
    #[must_use]
    pub fn bodies(&self) -> usize {
        self.body_requests.load(Ordering::Acquire)
    }
}

/// How a [`ServingPeer`] answers a body request.
#[derive(Clone, Debug)]
pub enum Bodies {
    /// As the store holds them.
    Honest,
    /// Every requested block marked unavailable.
    Withhold,
    /// Answered, but held here until the test releases the frames: a peer
    /// slower than the deadline.
    Hold(Arc<Mutex<Vec<Vec<u8>>>>),
    /// Each block carrying a transaction it does not list: a body that is
    /// not its header's (CEN-G2), in a response whose form is sound.
    SubstituteBody,
    /// Each witness replaced by bytes that are not one.
    SubstituteWitness,
    /// Every listed transaction as its skeleton.
    Skeleton,
}

/// A peer serving a real store (module docs).
pub struct ServingPeer {
    store: Arc<ChainStore>,
    bodies: Bodies,
    tip_work: Option<u128>,
    seen: Arc<Seen>,
}

impl ServingPeer {
    /// A peer serving `store`, answering bodies as `bodies` says.
    #[must_use]
    pub fn new(store: Arc<ChainStore>, bodies: Bodies) -> (Self, Arc<Seen>) {
        let seen = Arc::new(Seen::default());
        (
            Self {
                store,
                bodies,
                tip_work: None,
                seen: Arc::clone(&seen),
            },
            seen,
        )
    }

    /// Every header response states `work` as its tip's: a liar's claim,
    /// which a response's `tip_work` replaces.
    #[must_use]
    pub fn stating(mut self, work: u128) -> Self {
        self.tip_work = Some(work);
        self
    }

    fn bodies(&self, request: &RequestBodies) -> ResponseBodies {
        if matches!(self.bodies, Bodies::Withhold) {
            return ResponseBodies {
                bodies: Vec::new(),
                deferred: Vec::new(),
                missed_ids: request.hashes.clone(),
            };
        }
        let mut response = serve_bodies(&self.store, request).expect("the store answers");
        match &self.bodies {
            Bodies::Honest | Bodies::Hold(_) | Bodies::Withhold => {}
            Bodies::SubstituteBody => {
                let extra = self.listed_tx();
                for body in &mut response.bodies {
                    body.txs.push(TxBody::Full(extra.clone()));
                }
            }
            Bodies::SubstituteWitness => {
                for body in &mut response.bodies {
                    body.attestation_witness = vec![0xAB; 64];
                }
            }
            Bodies::Skeleton => {
                for body in &mut response.bodies {
                    let block = Block::from_bytes(&body.block).expect("a stored block");
                    body.txs = block
                        .transaction_hashes
                        .iter()
                        .map(|txid| TxBody::Skeleton(self.skeleton(txid)))
                        .collect();
                }
            }
        }
        response
    }

    /// The first listed transaction the store holds, whole.
    fn listed_tx(&self) -> Vec<u8> {
        let snap = self.store.begin_read().expect("a read");
        let mut height = 0u64;
        loop {
            let block = match snap.block(BlockHeight::from_raw(height)).expect("a read") {
                AtHeight::Recorded(body) => body.block,
                AtHeight::AboveTip => panic!("the chain lists no transaction"),
            };
            if !block.transaction_hashes.is_empty() {
                let request = RequestBodies {
                    hashes: vec![*block.hash().as_bytes()],
                };
                let response = serve_bodies(&self.store, &request).expect("the store answers");
                if let Some(TxBody::Full(bytes)) = response.bodies[0].txs.first() {
                    return bytes.clone();
                }
            }
            height += 1;
        }
    }

    fn skeleton(&self, txid: &shekyl_types::TxHash) -> SkeletonTx {
        let snap = self.store.begin_read().expect("a read");
        let record = snap
            .tx_record(txid)
            .expect("a read")
            .expect("a listed transaction is held");
        SkeletonTx {
            unprunable: record.pruned.clone().into_wire_bytes(),
            prunable_hash: record.prunable_hash,
            pqc_auth_hash: record.pqc_auth_hash,
            archival_len: record.archival_len,
        }
    }
}

impl SyncPeer for ServingPeer {
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        match SyncCommand::from_wire(command) {
            Some(SyncCommand::RequestHeaders) => {
                self.seen.header_requests.fetch_add(1, Ordering::AcqRel);
                let request = RequestHeaders::decode(payload).expect("the node's request decodes");
                let mut response = serve_headers(&self.store, &request).expect("the store answers");
                if let Some(work) = self.tip_work {
                    response.tip_work = work;
                }
                vec![frame(SyncCommand::ResponseHeaders, &response)]
            }
            Some(SyncCommand::RequestBodies) => {
                self.seen.body_requests.fetch_add(1, Ordering::AcqRel);
                let request = RequestBodies::decode(payload).expect("the node's request decodes");
                let response = self.bodies(&request);
                let frame = frame(SyncCommand::ResponseBodies, &response);
                if let Bodies::Hold(held) = &self.bodies {
                    held.lock().expect("held").push(frame);
                    return Vec::new();
                }
                vec![frame]
            }
            _ => {
                self.seen.other.fetch_add(1, Ordering::AcqRel);
                Vec::new()
            }
        }
    }
}

/// A peer serving a header chain from genesis that no store holds. Its
/// body answer is unavailable for every block.
pub struct HeaderChainPeer {
    chain: Vec<(BlockHash, Vec<u8>)>,
    index: HashMap<BlockHash, usize>,
    tip_work: u128,
    seen: Arc<Seen>,
}

impl HeaderChainPeer {
    /// `chain` is every header from genesis, in order; `tip_work` is the
    /// work its responses state.
    #[must_use]
    pub fn new(chain: Vec<(BlockHash, Vec<u8>)>, tip_work: u128) -> (Self, Arc<Seen>) {
        let index = chain
            .iter()
            .enumerate()
            .map(|(height, (hash, _))| (*hash, height))
            .collect();
        let seen = Arc::new(Seen::default());
        (
            Self {
                chain,
                index,
                tip_work,
                seen: Arc::clone(&seen),
            },
            seen,
        )
    }

    fn headers(&self, request: &RequestHeaders) -> ResponseHeaders {
        let start = request.block_ids.iter().find_map(|hash| {
            let hash = BlockHash::from_bytes(*hash);
            if hash == BlockHash::NULL {
                Some(0)
            } else {
                self.index.get(&hash).map(|height| height + 1)
            }
        });
        let Some(start) = start else {
            return ResponseHeaders {
                blobs: Vec::new(),
                tip_work: self.tip_work,
                more: false,
            };
        };
        let max = usize::try_from(HEADERS_RESPONSE_BYTES).unwrap_or(usize::MAX);
        let mut blobs = Vec::new();
        let mut sent = 0usize;
        let mut at = start;
        while let Some((_, blob)) = self.chain.get(at) {
            if sent + blob.len() > max {
                break;
            }
            sent += blob.len();
            blobs.push(blob.clone());
            at += 1;
        }
        ResponseHeaders {
            blobs,
            tip_work: self.tip_work,
            more: at < self.chain.len(),
        }
    }
}

impl SyncPeer for HeaderChainPeer {
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        match SyncCommand::from_wire(command) {
            Some(SyncCommand::RequestHeaders) => {
                self.seen.header_requests.fetch_add(1, Ordering::AcqRel);
                let request = RequestHeaders::decode(payload).expect("the node's request decodes");
                vec![frame(SyncCommand::ResponseHeaders, &self.headers(&request))]
            }
            Some(SyncCommand::RequestBodies) => {
                self.seen.body_requests.fetch_add(1, Ordering::AcqRel);
                let request = RequestBodies::decode(payload).expect("the node's request decodes");
                let response = ResponseBodies {
                    bodies: Vec::new(),
                    deferred: Vec::new(),
                    missed_ids: request.hashes,
                };
                vec![frame(SyncCommand::ResponseBodies, &response)]
            }
            _ => {
                self.seen.other.fetch_add(1, Ordering::AcqRel);
                Vec::new()
            }
        }
    }
}

/// One chain-sync message as a Levin notify.
///
/// # Panics
///
/// The payload does not encode: a harness defect.
#[must_use]
pub fn frame(command: SyncCommand, payload: &impl PortableMap) -> Vec<u8> {
    notify(
        command.wire_id(),
        &payload.store().expect("the payload encodes"),
    )
}

/// A request a peer sends the node, as a Levin notify.
#[must_use]
pub fn request_headers(locator: Vec<[u8; HASH_SIZE]>) -> Vec<u8> {
    frame(
        SyncCommand::RequestHeaders,
        &RequestHeaders { block_ids: locator },
    )
}
