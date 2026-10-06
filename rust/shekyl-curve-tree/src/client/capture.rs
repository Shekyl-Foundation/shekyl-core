// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Path capture: the chunks a membership path reads instead of the chain.
//!
//! The fold ([`CurveTreeClient::fold_block_captures`]) writes a chunk when it
//! closes over a registered output. [`CurveTreeClient::reconcile_captures`]
//! backfills a chunk that had already closed. Assembly asks [`ChunkSpan`]
//! which of those chunks are due.
//!
//! A layer-0 sibling is [`CAPTURED_IDENTITY_BYTES`] laid out by the
//! `CAPTURED_IDENTITY_*_AT` offsets. [`crate::assemble`] decodes that layout
//! in its own function, so the two sides can disagree and a test can see it.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    BlockLeaves, CaptureReconciliation, ClientError, CurveTreeClient, ExpectedOutput,
    OwnedRegistration, OwnershipSync,
};
use crate::frontier::{FoldedChunk, Frontier};
use crate::recon::drained_sorted;
use crate::segment::outputs_per_node;
use crate::store::CapturedChunk;
use crate::types::{BlockHeight, Gindex, LeafEntry, OneTimePubkey, TreePosition};
use shekyl_fcmp::tree::{
    build_layers, layer_count_for_leaves, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};
use shekyl_types::TxHash;

/// Width of one curve element in a capture body: a compressed point or a scalar.
pub(crate) const CURVE_ELEMENT_BYTES: usize = 32;

/// Start of `O` in a layer-0 sibling.
pub(crate) const CAPTURED_IDENTITY_OUTPUT_KEY_AT: usize = 0;
/// Start of `C` in a layer-0 sibling.
pub(crate) const CAPTURED_IDENTITY_COMMITMENT_AT: usize = CURVE_ELEMENT_BYTES;
/// Start of `CM.x` in a layer-0 sibling.
pub(crate) const CAPTURED_IDENTITY_CM_X_AT: usize = CURVE_ELEMENT_BYTES * 2;
/// `O ‖ C ‖ CM.x`. `I` is `Hp(O)` and is derived at assembly, never stored.
pub(crate) const CAPTURED_IDENTITY_BYTES: usize = CURVE_ELEMENT_BYTES * 3;

/// One child of a layer `>= 1` chunk, the width the frontier folded.
pub(crate) const NODE_CHILD_BYTES: usize = CURVE_ELEMENT_BYTES;

/// Inclusive leaf range one chunk covers.
///
/// Built only from the fold schedule ([`outputs_per_node`]), so a start and
/// an end cannot be paired by hand. A chunk is closed when
/// [`Self::is_closed`] — `end_leaf` strictly below the drained count — which
/// is the comparison the capture key, the rollback, and the backfill share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChunkSpan {
    start: u64,
    end_leaf: u64,
}

impl ChunkSpan {
    /// The chunk at `layer` that contains `position`, whether or not it has
    /// closed.
    pub(crate) fn covering(position: u64, layer: u8) -> Self {
        let covered = coverage(layer);
        let start = position / covered * covered;
        let end_leaf = start
            .checked_add(covered)
            .and_then(|past| past.checked_sub(1))
            .expect("a chunk's end fits u64");
        Self { start, end_leaf }
    }

    /// [`Self::covering`] when that chunk has closed under `drained_count`.
    pub(crate) fn due(position: u64, layer: u8, drained_count: u64) -> Option<Self> {
        let span = Self::covering(position, layer);
        span.is_closed(drained_count).then_some(span)
    }

    /// The span of a chunk the fold just closed at `end_leaf`.
    pub(crate) fn closed(end_leaf: u64, layer: u8) -> Self {
        let covered = coverage(layer);
        let start = end_leaf
            .checked_add(1)
            .and_then(|past| past.checked_sub(covered))
            .expect("a closed chunk's span starts at or above zero");
        Self { start, end_leaf }
    }

    /// Closed means `end_leaf` is strictly below the drained count.
    pub(crate) fn is_closed(self, drained_count: u64) -> bool {
        self.end_leaf < drained_count
    }

    pub(crate) fn holds(self, position: u64) -> bool {
        self.start <= position && position <= self.end_leaf
    }

    pub(crate) fn start(self) -> u64 {
        self.start
    }

    pub(crate) fn end_leaf(self) -> u64 {
        self.end_leaf
    }

    /// Leaves the chunk covers once closed. Equal to [`outputs_per_node`]
    /// of its layer.
    pub(crate) fn covered(self) -> u64 {
        self.end_leaf - self.start + 1
    }
}

fn coverage(layer: u8) -> u64 {
    u64::try_from(outputs_per_node(layer)).expect("node capacity fits u64")
}

/// Append one sibling: `O ‖ C ‖ CM.x` at the `CAPTURED_IDENTITY_*_AT` offsets.
///
/// A drained leaf always has a commitment (`try_build_leaf` required
/// `i < outPk.size()`). A short *row set* is a different failure — pruning
/// can produce it — and that one is refused by the caller, not expected away.
pub(crate) fn push_captured_identity(bytes: &mut Vec<u8>, entry: &LeafEntry) {
    let mut row = [0u8; CAPTURED_IDENTITY_BYTES];
    row[CAPTURED_IDENTITY_OUTPUT_KEY_AT..CAPTURED_IDENTITY_COMMITMENT_AT]
        .copy_from_slice(entry.identity.output_key.as_bytes());
    row[CAPTURED_IDENTITY_COMMITMENT_AT..CAPTURED_IDENTITY_CM_X_AT].copy_from_slice(
        entry
            .identity
            .commitment
            .expect("a drained leaf carries a commitment")
            .as_bytes(),
    );
    row[CAPTURED_IDENTITY_CM_X_AT..CAPTURED_IDENTITY_BYTES].copy_from_slice(&entry.cm_x());
    bytes.extend_from_slice(&row);
}

/// Node-chunk body: the frontier's children, in order, `NODE_CHILD_BYTES` each.
pub(crate) fn node_chunk_bytes(children: &[[u8; NODE_CHILD_BYTES]]) -> Vec<u8> {
    children.iter().flatten().copied().collect()
}

/// What one ingested block captured, ready for the block transaction.
pub(crate) struct BlockCaptures {
    /// Rows keyed by the leaf position at which the chunk closed.
    pub(crate) rows: Vec<(TreePosition, Vec<CapturedChunk>)>,
    /// Owned leaves this block drained, as `(position, gindex)`.
    ///
    /// Applied to the registry only after the store commit. The fold already
    /// saw them, so a chunk that closed over a leaf draining in this block
    /// was written.
    pub(crate) pending_owned: Vec<(u64, Gindex)>,
}

impl CurveTreeClient {
    /// Capture this output's membership-path material as the fold closes the
    /// chunks over it.
    ///
    /// The wallet calls this for each output it owns. Registration is
    /// idempotent. The return value says whether the leaf has already
    /// drained: capture rides the fold, and a leaf folds once
    /// ([`OwnedRegistration`]).
    ///
    /// A `gindex` this client has never seen is
    /// [`OwnedRegistration::BeforeDrain`]. The scanner may name an output
    /// from a block this client has not ingested, and the registry is matched
    /// against each leaf at its own drain.
    ///
    /// # Who calls this
    ///
    /// The batch form [`Self::sync_owned`], from the refresh (everything the
    /// wallet holds, every pass) and from the curve-tree actor (a spend's
    /// inputs, before it assembles them). An input reaches
    /// [`Self::assemble_paths`] registered or not at all; there is no
    /// unregistered route.
    ///
    /// # Errors
    ///
    /// [`ClientError::Poisoned`] if a partially-applied rollback left memory
    /// inconsistent with the store. The verdict is read from `entries`, so a
    /// poisoned client could answer `BeforeDrain` for a leaf that has drained
    /// and report nothing owed.
    /// [`ClientError::RegistrationIdentityMismatch`] when `entries` already
    /// holds a different output key at `gindex`.
    #[must_use = "a registration after the drain owes captures to reconciliation"]
    pub fn register_owned(
        &mut self,
        gindex: Gindex,
        output_key: OneTimePubkey,
    ) -> Result<OwnedRegistration, ClientError> {
        self.ensure_live()?;
        if let Some(held) = Self::held_output(&self.entries, gindex) {
            if held != output_key {
                return Err(ClientError::RegistrationIdentityMismatch {
                    gindex,
                    expected: output_key,
                    got: held,
                });
            }
        }
        let resolved: BTreeSet<Gindex> = self.owned_positions.values().copied().collect();
        Ok(self.register_checked(gindex, output_key, &resolved))
    }

    /// [`Self::register_owned`] after its checks, against a precomputed set
    /// of resolved gindexes so a batch does not rescan `owned_positions` per
    /// output.
    fn register_checked(
        &mut self,
        gindex: Gindex,
        output_key: OneTimePubkey,
        resolved: &BTreeSet<Gindex>,
    ) -> OwnedRegistration {
        let held = self.owned_outputs.get(&gindex) == Some(&output_key);
        // An insert replaces, which is how a rescan rebinds a gindex after a
        // reorg without a separate retraction.
        self.owned_outputs.insert(gindex, output_key);
        let Some(tip) = self.ingested_tip_height else {
            return if held {
                OwnedRegistration::AlreadyHeld
            } else {
                OwnedRegistration::BeforeDrain
            };
        };
        let cutoff = Self::drained_through(tip);
        // `entries` is strictly increasing in `gindex`.
        let drained = self
            .entries
            .binary_search_by(|h| h.gindex.cmp(&gindex))
            .is_ok_and(|i| self.entries[i].maturity <= cutoff);
        if held && (!drained || resolved.contains(&gindex)) {
            OwnedRegistration::AlreadyHeld
        } else if drained {
            OwnedRegistration::AfterDrain
        } else {
            OwnedRegistration::BeforeDrain
        }
    }

    /// Register a batch of owned outputs and reconcile **once** if any of
    /// them is owed captures.
    ///
    /// This is the call the wallet makes on every refresh with everything it
    /// holds, and the one the curve-tree actor makes with a spend's inputs
    /// before assembling them — so the capture path is total: an input
    /// reaches [`Self::assemble_paths`] registered, or not at all. Idempotent
    /// and cheap when nothing changed: a re-offer of a held, served pair is
    /// [`OwnedRegistration::AlreadyHeld`] and triggers nothing.
    ///
    /// A pair the client cannot accept — it holds a *different* output at
    /// that gindex — is collected in [`OwnershipSync::stale`] rather than
    /// failing the batch. That is the normal outcome of a scan lagging the
    /// tree across a reorg, and the remedy is the caller's own rescan, which
    /// re-offers the right key. Nothing is poisoned by it.
    ///
    /// # Errors
    ///
    /// [`ClientError::Poisoned`]; and whatever
    /// [`Self::reconcile_captures`] refuses with, if a reconciliation ran.
    /// Replace the outputs the wallet expects the chain to carry
    /// ([`ExpectedOutput`]), for [`Self::ingest_block`] to register as it
    /// sees their transactions.
    ///
    /// Replaced whole, not merged: the wallet derives the set on every pass
    /// from its records of unconfirmed transactions, so an expectation ends
    /// when its record does. Registrations already made from an earlier set
    /// are not touched — they are owned outputs now, held in the registry
    /// like any other. An expectation for a transaction the client has
    /// *already* ingested is not resolved here: the client keeps no
    /// transaction hashes for ingested leaves, and resolving by key alone
    /// would reopen the copied-key case this type exists to close. Such an
    /// output is registered by its pair, later, when the wallet learns its
    /// gindex (§11.13 names that window).
    ///
    /// # Errors
    ///
    /// [`ClientError::Poisoned`].
    pub fn set_expected_outputs(&mut self, expected: &[ExpectedOutput]) -> Result<(), ClientError> {
        self.ensure_live()?;
        let mut by_tx: BTreeMap<TxHash, Vec<(u64, OneTimePubkey)>> = BTreeMap::new();
        for output in expected {
            by_tx
                .entry(output.tx_hash)
                .or_default()
                .push((output.vout, output.output_key));
        }
        self.expected_outputs = by_tx;
        Ok(())
    }

    /// How many expected outputs this client has seen arrive under a
    /// different key than the wallet named (none of them registered), since
    /// it was opened.
    #[must_use]
    pub fn expected_output_mismatches(&self) -> u64 {
        self.expected_output_mismatches
    }

    /// The expected outputs this block carries, as the pairs to register.
    ///
    /// Called by [`Self::ingest_block`] once the block's gindexes are
    /// assigned and before anything is committed. A transaction is looked
    /// up by its hash; each expected `vout` of it is confirmed against the
    /// key the transaction actually carries there, and a confirmed output
    /// that became a leaf is returned with the gindex it was just given.
    /// Every `vout` consumes a gindex whether or not it becomes a leaf
    /// (`collect_block_leaves`), which is why the gindex is counted here
    /// rather than read off `new_leaves`.
    ///
    /// A key that does not match is counted and skipped, never an error:
    /// the hash is the block feed's and only the key is the wallet's own, so
    /// a feed that mislabels a transaction can cost the wallet an early
    /// registration and nothing else. A `vout` the transaction does not
    /// have is treated the same way.
    ///
    /// # Errors
    ///
    /// [`ClientError::TxHashMissing`] when expectations are live and a
    /// transaction arrives without its hash.
    pub(super) fn match_expected_outputs(
        &mut self,
        block: &BlockLeaves<'_>,
        new_leaves: &[LeafEntry],
    ) -> Result<Vec<(Gindex, OneTimePubkey)>, ClientError> {
        let mut matched = Vec::new();
        if self.expected_outputs.is_empty() {
            return Ok(matched);
        }
        let mut gindex = self.next_gindex;
        for (tx_index, tx) in block.txs.iter().enumerate() {
            let first_gindex = gindex;
            gindex += u64::try_from(tx.outputs.len()).expect("a transaction's vout count fits u64");
            let Some(tx_hash) = tx.tx_hash else {
                return Err(ClientError::TxHashMissing {
                    height: block.height,
                    tx_index,
                });
            };
            let Some(expected) = self.expected_outputs.get(&tx_hash) else {
                continue;
            };
            for (vout, output_key) in expected {
                let confirmed = usize::try_from(*vout)
                    .ok()
                    .and_then(|i| tx.outputs.get(i))
                    .is_some_and(|raw| raw.output_key == *output_key);
                if !confirmed {
                    self.expected_output_mismatches += 1;
                    continue;
                }
                let gindex = Gindex::from_raw(first_gindex + vout);
                // Only a leaf can be captured; an output that consumed an
                // index without becoming one has no path to prepare.
                if new_leaves.iter().any(|leaf| leaf.gindex == gindex) {
                    matched.push((gindex, *output_key));
                }
            }
        }
        Ok(matched)
    }

    pub fn sync_owned(
        &mut self,
        outputs: &[(Gindex, OneTimePubkey)],
    ) -> Result<OwnershipSync, ClientError> {
        self.ensure_live()?;
        let resolved: BTreeSet<Gindex> = self.owned_positions.values().copied().collect();
        let mut sync = OwnershipSync::default();
        for (gindex, output_key) in outputs {
            if let Some(held) = Self::held_output(&self.entries, *gindex) {
                if held != *output_key {
                    sync.stale.push(*gindex);
                    continue;
                }
            }
            match self.register_checked(*gindex, *output_key, &resolved) {
                OwnedRegistration::BeforeDrain => sync.before_drain += 1,
                OwnedRegistration::AfterDrain => sync.after_drain += 1,
                OwnedRegistration::AlreadyHeld => sync.already_held += 1,
            }
        }
        if sync.after_drain > 0 {
            sync.reconciliation = Some(self.reconcile_captures()?);
        }
        Ok(sync)
    }

    /// Write every capture an owned output is due and the store lacks.
    ///
    /// A capture that is due and missing is a late registration, whatever
    /// made it late. Resume is the mass case: the registry does not persist,
    /// so after every resume each held output is
    /// [`OwnedRegistration::AfterDrain`]. Late discovery — the scanner names
    /// an output after its chunks have closed — is the other.
    ///
    /// A pre-capture store cannot be opened
    /// ([`crate::store::StoreError::SchemaVersionMismatch`] is a strict
    /// equality). A crash between a fold and its capture cannot happen:
    /// captures ride the block's own transaction.
    ///
    /// Due coordinates are [`ChunkSpan::due`]. The call reads the table
    /// before it hashes. On a normal resume every due chunk is present,
    /// [`CaptureReconciliation::leaves_rebuilt`] is zero, and the cost is one
    /// read per distinct `end_leaf`. Only a missing chunk is rebuilt, from
    /// the leaves under its own span.
    ///
    /// The owned positions are recomputed from `drained_sorted` and must
    /// contain every position the fold recorded. A held position the
    /// recomputation does not produce is [`ClientError::OwnedPositionDrift`].
    ///
    /// What remains `O(n)` is that sort. It goes with `entries` at increment 7.
    /// Register every held output, then call this once. The batch commits in
    /// one transaction. Re-offering identical bytes is a no-op.
    ///
    /// # Errors
    ///
    /// [`ClientError::Poisoned`]; [`ClientError::OwnedPositionDrift`];
    /// [`ClientError::Store`], including
    /// [`crate::store::StoreError::ConflictingCapture`] when a recomputed
    /// chunk disagrees with one already stored;
    /// [`ClientError::CaptureIdentitiesIncomplete`] from a short leaf span.
    pub fn reconcile_captures(&mut self) -> Result<CaptureReconciliation, ClientError> {
        self.ensure_live()?;
        let Some(tip) = self.ingested_tip_height else {
            return Ok(CaptureReconciliation::default());
        };
        let cutoff = Self::drained_through(tip);
        let drained = drained_sorted(&self.entries, cutoff);
        let drained_count = u64::try_from(drained.len()).expect("drained count fits u64");

        let mut positions: BTreeMap<u64, Gindex> = BTreeMap::new();
        for (position, entry) in drained.iter().enumerate() {
            if self.owned_outputs.get(&entry.gindex) == Some(&entry.identity.output_key) {
                positions.insert(
                    u64::try_from(position).expect("a drain position fits u64"),
                    entry.gindex,
                );
            }
        }
        // The whole mapping, not the key set. Two registered outputs whose
        // positions swapped between the fold's order and `drained_sorted`'s
        // leave both keys present, so a key-only comparison would overwrite
        // `owned_positions` with the other order and every capture over
        // either leaf would be keyed on the wrong one.
        if let Some((stale, _)) = self
            .owned_positions
            .iter()
            .find(|(held, gindex)| positions.get(held) != Some(gindex))
        {
            return Err(ClientError::OwnedPositionDrift { position: *stale });
        }

        let depth = layer_count_for_leaves(drained_count);
        let mut held: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut owed: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for position in positions.keys() {
            for layer in 0..depth {
                let Some(span) = ChunkSpan::due(*position, layer, drained_count) else {
                    continue;
                };
                let end_leaf = span.end_leaf();
                let present = match held.get(&end_leaf) {
                    Some(layers) => layers.contains(&layer),
                    None => {
                        let rows = self
                            .store
                            .captured_chunks(TreePosition::from_raw(end_leaf))?;
                        let layers: Vec<u8> = rows.iter().map(|c| c.layer).collect();
                        let present = layers.contains(&layer);
                        held.insert(end_leaf, layers);
                        present
                    }
                };
                let already = owed
                    .get(&end_leaf)
                    .is_some_and(|layers| layers.contains(&layer));
                if !present && !already {
                    owed.entry(end_leaf).or_default().push(layer);
                }
            }
        }

        let mut missing: Vec<(TreePosition, Vec<CapturedChunk>)> = Vec::new();
        let mut leaves_rebuilt = 0u64;
        let mut chunks_written = 0usize;
        for (end_leaf, layers) in owed {
            let mut chunks = Vec::with_capacity(layers.len());
            for layer in layers {
                let (chunk, read) = self.rebuild_chunk(end_leaf, layer)?;
                leaves_rebuilt += read;
                chunks.push(chunk);
            }
            chunks_written += chunks.len();
            missing.push((TreePosition::from_raw(end_leaf), chunks));
        }
        self.store.merge_captured_chunk_rows(&missing)?;

        let resolved = positions.len() - self.owned_positions.len();
        self.owned_positions = positions;
        Ok(CaptureReconciliation {
            positions_resolved: resolved,
            rows_written: missing.len(),
            chunks_written,
            leaves_rebuilt,
        })
    }

    /// Advance `frontier` over `drained` and return the capture rows the
    /// block transaction must merge.
    ///
    /// `frontier` is the caller's clone. A hash failure leaves the live
    /// frontier untouched. Layer-0 bodies are read here, ahead of the
    /// transaction, because that read can fail; a node chunk is the children
    /// the fold just reported.
    ///
    /// # Errors
    ///
    /// [`ClientError::Frontier`] when a leaf does not hash;
    /// [`ClientError::CaptureIdentitiesIncomplete`] when a closing layer-0
    /// chunk is short of its width; [`ClientError::Store`] on a read failure.
    pub(crate) fn fold_block_captures(
        &self,
        height: BlockHeight,
        drained: &[LeafEntry],
        frontier: &mut Frontier,
    ) -> Result<BlockCaptures, ClientError> {
        let base = frontier.leaf_count();
        let pending_owned: Vec<(u64, Gindex)> = drained
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                self.owned_outputs.get(&entry.gindex) == Some(&entry.identity.output_key)
            })
            .map(|(i, entry)| {
                (
                    base + u64::try_from(i).expect("a block's drain count fits u64"),
                    entry.gindex,
                )
            })
            .collect();

        let mut leaf_chunk_ends: Vec<u64> = Vec::new();
        let mut node_captures: Vec<(u64, CapturedChunk)> = Vec::new();
        for entry in drained {
            frontier
                .push_leaf_observed(&entry.leaf, &mut |chunk| {
                    if !chunk_holds_owned(&chunk, &self.owned_positions, &pending_owned) {
                        return;
                    }
                    if chunk.layer == 0 {
                        leaf_chunk_ends.push(chunk.end_leaf);
                    } else {
                        node_captures.push((
                            chunk.end_leaf,
                            CapturedChunk {
                                layer: chunk.layer,
                                bytes: node_chunk_bytes(chunk.children),
                            },
                        ));
                    }
                })
                .map_err(|source| ClientError::Frontier { height, source })?;
        }

        // One row per `end_leaf`. A cascade closes several layers on one
        // leaf, and they share a key.
        let mut by_end: BTreeMap<u64, Vec<CapturedChunk>> = BTreeMap::new();
        for end_leaf in leaf_chunk_ends {
            let bytes = self.captured_leaf_identities(end_leaf, base, drained)?;
            by_end
                .entry(end_leaf)
                .or_default()
                .push(CapturedChunk { layer: 0, bytes });
        }
        for (end_leaf, chunk) in node_captures {
            by_end.entry(end_leaf).or_default().push(chunk);
        }
        let rows = by_end
            .into_iter()
            .map(|(end_leaf, chunks)| (TreePosition::from_raw(end_leaf), chunks))
            .collect();
        Ok(BlockCaptures {
            rows,
            pending_owned,
        })
    }

    /// The output key `entries` holds at `gindex`, if any.
    ///
    /// Binary search on the strictly-increasing `gindex` order.
    pub(super) fn held_output(entries: &[LeafEntry], gindex: Gindex) -> Option<OneTimePubkey> {
        entries
            .binary_search_by(|held| held.gindex.cmp(&gindex))
            .ok()
            .map(|i| entries[i].identity.output_key)
    }

    fn rebuild_chunk(&self, end_leaf: u64, layer: u8) -> Result<(CapturedChunk, u64), ClientError> {
        let span = ChunkSpan::closed(end_leaf, layer);
        let entries = self.store.read_drained_range(
            TreePosition::from_raw(span.start()),
            TreePosition::from_raw(span.end_leaf()),
        )?;
        let want = usize::try_from(span.covered()).expect("a chunk span fits usize");
        if entries.len() != want {
            return Err(ClientError::CaptureIdentitiesIncomplete {
                end_leaf,
                want,
                got: entries.len(),
            });
        }
        let bytes = if layer == 0 {
            let mut bytes = Vec::with_capacity(want * CAPTURED_IDENTITY_BYTES);
            for entry in &entries {
                push_captured_identity(&mut bytes, entry);
            }
            bytes
        } else {
            let mut scalars = Vec::with_capacity(entries.len() * SCALARS_PER_LEAF);
            for entry in &entries {
                for scalar in entry.leaf.chunks_exact(CURVE_ELEMENT_BYTES) {
                    let mut word = [0u8; CURVE_ELEMENT_BYTES];
                    word.copy_from_slice(scalar);
                    scalars.push(word);
                }
            }
            let sub = build_layers(&scalars);
            let children = &sub[usize::from(layer) - 1];
            debug_assert_eq!(
                children.len(),
                shekyl_fcmp::tree::chunk_width(layer),
                "an aligned span yields exactly one chunk's worth of children"
            );
            node_chunk_bytes(children)
        };
        Ok((CapturedChunk { layer, bytes }, span.covered()))
    }

    /// Layer-0 body for the chunk that closed at `end_leaf`.
    ///
    /// Positions below `base` come from the store. Positions from `base` up
    /// come from `drained`, this block's leaves, which the store has not
    /// committed yet.
    fn captured_leaf_identities(
        &self,
        end_leaf: u64,
        base: u64,
        drained: &[LeafEntry],
    ) -> Result<Vec<u8>, ClientError> {
        let span = ChunkSpan::closed(end_leaf, 0);
        let width = usize::try_from(span.covered()).expect("leaf chunk width fits usize");
        debug_assert_eq!(width, SELENE_CHUNK_WIDTH);
        let mut bytes = Vec::with_capacity(width * CAPTURED_IDENTITY_BYTES);
        if span.start() < base {
            let last = (base - 1).min(span.end_leaf());
            let stored = self.store.read_drained_range(
                TreePosition::from_raw(span.start()),
                TreePosition::from_raw(last),
            )?;
            for entry in &stored {
                push_captured_identity(&mut bytes, entry);
            }
        }
        for position in span.start().max(base)..=span.end_leaf() {
            let offset =
                usize::try_from(position - base).expect("a block's drain index fits usize");
            push_captured_identity(&mut bytes, &drained[offset]);
        }
        let got = bytes.len() / CAPTURED_IDENTITY_BYTES;
        if got != width {
            return Err(ClientError::CaptureIdentitiesIncomplete {
                end_leaf,
                want: width,
                got,
            });
        }
        Ok(bytes)
    }
}

/// Does this closed chunk's leaf span hold an owned position?
fn chunk_holds_owned(
    chunk: &FoldedChunk<'_>,
    resolved: &BTreeMap<u64, Gindex>,
    pending: &[(u64, Gindex)],
) -> bool {
    let span = ChunkSpan::closed(chunk.end_leaf, chunk.layer);
    resolved
        .range(span.start()..=span.end_leaf())
        .next()
        .is_some()
        || pending.iter().any(|(position, _)| span.holds(*position))
}
