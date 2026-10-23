// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle rule's fixture: an in-memory [`BundleView`] and a producer
//! that builds a valid bundle end to end against it.
//!
//! # What this fixture is, by the mock charter (`50-testing.mdc`)
//!
//! [`FixtureBundleView`] is a struct of maps with a `BundleView` impl. It
//! computes nothing: a draw count, a `0x0C` commitment, a block hash, a
//! visibly-short flag and a drawable epoch are values a test put there. It
//! earns its keep in the charter's first two jobs and claims no third:
//!
//! 1. **Predicate logic and verification over plain values.** The window,
//!    the bitmap against a count, the record count, `attempt < K`,
//!    `anchor < h`, the order of the checks. The cryptography is not
//!    faked: [`BundleWorld`] generates real scheme-3 keys and signs the
//!    commitment and every receipt through the production signer, and the
//!    verifier opens the real `0x0C` hash.
//! 2. **Faults a store will not exhibit on demand.** [`FixtureBundleView::fault`]
//!    fails one named read; the assertion is the fault arm, never a
//!    verdict.
//!
//! **What it cannot witness:** that a store's `count(h)`, its `0x0C`, its
//! issued counts or its `h_open(E)` drawable epoch are what the chain derived.
//! Those are facts about a chain, and a constructed view answering them
//! tests the construction. Their witness is `SO-D12`'s view on its store,
//! driven by real blocks, when the cutover lands. Until then the bundle
//! rule is tested for its own logic and **untested for parity**.
//!
//! [`BundleWorld`] is construction through production paths for exactly
//! that purpose: the same `select_draw`, `challenge_nonce`, `draw_commit`
//! and signer a challenger will use. Where a test must not lean on one of
//! those — the selection and nonce vectors — it passes the specification's
//! own value in ([`BundleWorld::record_signed_over`]).

use core::cell::RefCell;
use core::convert::Infallible;
use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::{
    challenge_nonce, draw_commit, pass_countersignature_message, select_draw, BundleBody,
    BundleKept, BundleRecord, BundleRef, DrawableEpoch, DrawablePair, PassBitmap,
    BUNDLE_SIGNATURE_LEN, BUNDLE_WITNESS_KEY_LEN,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSecretKey, HybridEd25519FnDsa};
use shekyl_crypto_pq::signature::{
    SignatureScheme as _, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_BUNDLE,
};
use shekyl_types::archival::ReceiptSignPk;
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use crate::archival::BundleView;
use crate::rule_set::RuleSet;

/// Which of [`BundleView`]'s reads a fixture names: to fault it, and in
/// the log of reads a judgement made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BundleRead {
    /// [`BundleView::draw_count`].
    DrawCount,
    /// [`BundleView::draw_commitment`].
    DrawCommitment,
    /// [`BundleView::block_hash`].
    BlockHash,
    /// [`BundleView::visibly_short`].
    VisiblyShort,
    /// [`BundleView::revealed`].
    Revealed,
    /// [`BundleView::drawable_epoch`].
    DrawableEpoch,
}

/// The fault a [`FixtureBundleView`] raises, naming the read that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleReadFaulted(pub BundleRead);

/// A chain's bundle-relevant facts in memory. Every field is public: a
/// test says what the chain holds by writing it.
#[derive(Clone, Debug, Default)]
pub struct FixtureBundleView {
    /// The highest block the chain has. [`BundleView::block_hash`] answers
    /// `None` above it.
    pub tip: BlockHeight,
    /// Block hashes that are not [`fixture_block_hash`] of their height.
    pub hashes: BTreeMap<BlockHeight, BlockHash>,
    /// `count(h)`. A height with no entry has no draw state.
    pub counts: BTreeMap<BlockHeight, u32>,
    /// Each block's `0x0C`.
    pub commitments: BTreeMap<BlockHeight, [u8; 32]>,
    /// The `(h, index)` at which a pair is visibly short.
    pub short: BTreeSet<(BlockHeight, u64)>,
    /// The blocks whose bundle is already admitted.
    pub revealed: BTreeSet<BlockHeight>,
    /// The `h_open(E)` drawable epochs, by the epoch asked for.
    pub drawable_epochs: BTreeMap<SettlementEpoch, DrawableEpoch>,
    /// The one read that faults, if any.
    pub fault: Option<BundleRead>,
    /// Every read made, in order.
    pub reads: RefCell<Vec<BundleRead>>,
}

/// The hash the fixture chain has at `height` unless a test says
/// otherwise: the height, little-endian, then `0xB1` to 32 bytes.
#[must_use]
pub fn fixture_block_hash(height: BlockHeight) -> BlockHash {
    let mut bytes = [0xB1u8; 32];
    bytes[..8].copy_from_slice(&height.to_raw().to_le_bytes());
    BlockHash::from_bytes(bytes)
}

/// `reference` naming another prunable hash: the kept part as it was, the
/// hash replaced. What a block that committed to other prunable bytes
/// carries, and what a reference to bytes nobody holds looks like. Shared
/// by the verifier and section tests.
#[must_use]
pub fn with_hash(reference: &BundleRef, prunable_hash: [u8; 32]) -> BundleRef {
    BundleRef::new(reference.kept().clone(), prunable_hash)
}

impl FixtureBundleView {
    fn read(&self, read: BundleRead) -> Result<(), BundleReadFaulted> {
        self.reads.borrow_mut().push(read);
        if self.fault == Some(read) {
            return Err(BundleReadFaulted(read));
        }
        Ok(())
    }

    /// The reads made since the last call, in order.
    pub fn take_reads(&self) -> Vec<BundleRead> {
        core::mem::take(&mut *self.reads.borrow_mut())
    }

    /// The hash the chain has at `height`: a test's override, or
    /// [`fixture_block_hash`]. `None` above the tip — the answer
    /// [`BundleView::block_hash`] gives, without recording a read. The
    /// receipt signer uses this, so a transcript is over a hash the
    /// verifier can be shown.
    fn chain_block_hash(&self, height: BlockHeight) -> Option<BlockHash> {
        if height > self.tip {
            None
        } else {
            Some(
                self.hashes
                    .get(&height)
                    .copied()
                    .unwrap_or_else(|| fixture_block_hash(height)),
            )
        }
    }
}

impl BundleView for FixtureBundleView {
    type Fault = BundleReadFaulted;

    fn draw_count(&self, h: BlockHeight) -> Result<Option<u32>, BundleReadFaulted> {
        self.read(BundleRead::DrawCount)?;
        Ok(self.counts.get(&h).copied())
    }

    fn draw_commitment(&self, h: BlockHeight) -> Result<Option<[u8; 32]>, BundleReadFaulted> {
        self.read(BundleRead::DrawCommitment)?;
        Ok(self.commitments.get(&h).copied())
    }

    fn block_hash(&self, height: BlockHeight) -> Result<Option<BlockHash>, BundleReadFaulted> {
        self.read(BundleRead::BlockHash)?;
        Ok(self.chain_block_hash(height))
    }

    fn visibly_short(&self, h: BlockHeight, index: u64) -> Result<bool, BundleReadFaulted> {
        self.read(BundleRead::VisiblyShort)?;
        Ok(self.short.contains(&(h, index)))
    }

    fn revealed(&self, h: BlockHeight) -> Result<bool, BundleReadFaulted> {
        self.read(BundleRead::Revealed)?;
        Ok(self.revealed.contains(&h))
    }

    fn drawable_epoch(
        &self,
        epoch: SettlementEpoch,
    ) -> Result<Option<&DrawableEpoch>, BundleReadFaulted> {
        self.read(BundleRead::DrawableEpoch)?;
        Ok(self.drawable_epochs.get(&epoch))
    }
}

/// One persona of the fixture: its id, its receipt key pair, the shards
/// it holds.
pub struct FixturePersona {
    /// The persona's canonical id. Arbitrary bytes: nothing here derives
    /// it from an identity key.
    pub persona: PCanonicalId,
    /// The receipt public key, as a bond record carries it.
    pub receipt_public_key: ReceiptSignPk,
    /// The receipt secret key.
    pub receipt_secret_key: FnDsaHybridSecretKey,
    /// The shards it holds at `h_open(E)`.
    pub shards: Vec<u64>,
}

/// A producer, three personas and the chain they are on: enough to build
/// a bundle for one block `h` that [`verify_bundle`](crate::verify_bundle)
/// admits, and every near miss of one.
///
/// `D` is eight pairs over three personas. In canonical order:
///
/// | index | persona | shard |
/// | --- | --- | --- |
/// | 0, 1, 2 | `0x10 × 32` | 0, 1, 2 |
/// | 3, 4, 5 | `0x20 × 32` | 0, 1, 5 |
/// | 6, 7 | `0x30 × 32` | 3, 7 |
pub struct BundleWorld {
    /// The chain. The world's own facts are already in it.
    pub view: FixtureBundleView,
    /// The block whose producer draws.
    pub h: BlockHeight,
    /// The draw seed.
    pub seed: [u8; 32],
    /// `count(h)`.
    pub count: u32,
    /// The witness public key's canonical bytes.
    pub witness_public_key: [u8; BUNDLE_WITNESS_KEY_LEN],
    /// The witness secret key.
    pub witness_secret_key: FnDsaHybridSecretKey,
    /// The personas, ascending by id.
    pub personas: Vec<FixturePersona>,
}

impl BundleWorld {
    /// The block the world's bundle is for: 100 blocks into epoch 2 of the
    /// genesis schedule, far enough above genesis that an honest anchor
    /// (`h − 720` and below) exists.
    pub const H: BlockHeight = BlockHeight::from_raw(20_100);

    /// The seed the world reveals unless a test names another.
    pub const SEED: [u8; 32] = [0x5E; 32];

    /// A world whose block [`Self::H`] has `count` draws, under
    /// [`Self::SEED`], on a chain whose tip is `h + 1000`.
    #[must_use]
    pub fn new(count: u32) -> Self {
        Self::with(Self::H, Self::SEED, count, &RuleSet::GENESIS)
    }

    /// A world for block `h` with `count` draws under `seed`, with its
    /// drawable epoch filed under `epoch(h)` of `rule_set`.
    ///
    /// # Panics
    ///
    /// If key generation or the drawable epoch's construction fails — a defect
    /// of the fixture, not a state a test asked for.
    #[must_use]
    pub fn with(h: BlockHeight, seed: [u8; 32], count: u32, rule_set: &RuleSet) -> Self {
        let persona = |n: u8, shards: &[u64]| {
            let (public, secret) =
                HybridEd25519FnDsa::keypair_from_seeds(&[n; 32], &[n.wrapping_add(0x80); 32])
                    .expect("fixture receipt keygen");
            FixturePersona {
                persona: PCanonicalId::from_bytes([n; 32]),
                receipt_public_key: public.to_receipt_sign_pk(),
                receipt_secret_key: secret,
                shards: shards.to_vec(),
            }
        };
        let personas = vec![
            persona(0x10, &[0, 1, 2]),
            persona(0x20, &[0, 1, 5]),
            persona(0x30, &[3, 7]),
        ];
        let (witness_public, witness_secret_key) =
            HybridEd25519FnDsa::keypair_from_seeds(&[0xA1; 32], &[0xA2; 32])
                .expect("fixture witness keygen");
        let witness_public_key: [u8; BUNDLE_WITNESS_KEY_LEN] = witness_public
            .to_canonical_bytes()
            .try_into()
            .expect("the canonical key length");

        let epoch = rule_set.settlement_schedule().epoch_at(h);
        let drawable = DrawableEpoch::new(
            epoch,
            personas.iter().map(|p| (p.persona, &p.receipt_public_key)),
            personas.iter().flat_map(|p| {
                p.shards.iter().map(|shard| DrawablePair {
                    persona: p.persona,
                    shard: ShardId::from_raw(*shard),
                })
            }),
        )
        .expect("every fixture pair has a key");

        let mut view = FixtureBundleView {
            tip: BlockHeight::from_raw(h.to_raw() + 1_000),
            ..FixtureBundleView::default()
        };
        view.counts.insert(h, count);
        view.commitments
            .insert(h, draw_commit(&witness_public_key, &seed));
        view.drawable_epochs.insert(epoch, drawable);

        Self {
            view,
            h,
            seed,
            count,
            witness_public_key,
            witness_secret_key,
            personas,
        }
    }

    /// The anchor an honest read of this block carries: `h − 721`.
    #[must_use]
    pub fn honest_anchor(&self) -> BlockHeight {
        BlockHeight::from_raw(self.h.to_raw() - 721)
    }

    /// The drawable epoch the world filed for `epoch(h)`.
    ///
    /// # Panics
    ///
    /// If a test removed it.
    #[must_use]
    pub fn drawable_epoch(&self) -> &DrawableEpoch {
        self.view
            .drawable_epochs
            .values()
            .next()
            .expect("the world's drawable epoch")
    }

    /// The index draw `j` selects on this chain, by the production
    /// selection over the view's own answers.
    ///
    /// # Panics
    ///
    /// If `h` is above the fixture chain's tip, or the drawable set is empty.
    #[must_use]
    pub fn selected(&self, draw: u32) -> u64 {
        let hash = self
            .view
            .chain_block_hash(self.h)
            .expect("the block is at or below the fixture chain's tip");
        // The fixture's short read cannot fail, and the type says so: the
        // `Err` arm is uninhabited, so the `let` is irrefutable.
        let Ok(selected) = select_draw(
            &self.seed,
            hash.as_bytes(),
            draw,
            self.drawable_epoch().len(),
            |index| Ok::<_, Infallible>(self.view.short.contains(&(self.h, index))),
        );
        selected.expect("a non-empty set selects").index
    }

    /// The record an honest producer files for draw `j` read on its
    /// `attempt`-th read: the derived pair's persona signs the transcript
    /// over the recomputed nonce, anchored at [`Self::honest_anchor`].
    #[must_use]
    pub fn record(&self, draw: u32, attempt: u8) -> BundleRecord {
        self.record_anchored(draw, attempt, self.honest_anchor())
    }

    /// [`Self::record`] with the anchor named.
    ///
    /// # Panics
    ///
    /// If `h` or `anchor` is above the fixture chain's tip.
    #[must_use]
    pub fn record_anchored(&self, draw: u32, attempt: u8, anchor: BlockHeight) -> BundleRecord {
        let hash = self
            .view
            .chain_block_hash(self.h)
            .expect("the block is at or below the fixture chain's tip");
        let nonce = challenge_nonce(&self.seed, hash.as_bytes(), draw, attempt);
        let index = self.selected(draw);
        self.record_signed_over(index, attempt, anchor, &nonce)
    }

    /// A record for the pair at `index`, signed by that pair's persona
    /// over a transcript with **this** nonce. The door for a test that
    /// supplies the nonce or the index from the specification's tables
    /// rather than from the functions under test.
    ///
    /// # Panics
    ///
    /// If `index` is outside the world's drawable epoch or signing fails.
    #[must_use]
    pub fn record_signed_over(
        &self,
        index: u64,
        attempt: u8,
        anchor: BlockHeight,
        nonce: &[u8; 32],
    ) -> BundleRecord {
        let pair = self.drawable_epoch().pair(index).expect("an index in D");
        let signer = self
            .personas
            .iter()
            .find(|p| p.persona == pair.persona)
            .expect("the pair's persona");
        self.record_signed_by(
            &signer.receipt_secret_key,
            pair.shard.to_raw(),
            attempt,
            anchor,
            nonce,
        )
    }

    /// A record for `shard_id` signed by `secret_key` — any key, the door
    /// for a receipt under the wrong one.
    ///
    /// # Panics
    ///
    /// If `anchor` is above the fixture chain's tip — the view would
    /// answer no hash, so there is no transcript to sign — or if signing
    /// fails.
    #[must_use]
    pub fn record_signed_by(
        &self,
        secret_key: &FnDsaHybridSecretKey,
        shard_id: u64,
        attempt: u8,
        anchor: BlockHeight,
        nonce: &[u8; 32],
    ) -> BundleRecord {
        let delivery_digest = [0xDD; 32];
        let anchor_hash = self
            .view
            .chain_block_hash(anchor)
            .expect("anchor is at or below the fixture chain's tip");
        let transcript = pass_countersignature_message(
            shekyl_archival_retention::PassStream::Economy,
            nonce,
            anchor,
            anchor_hash.as_bytes(),
            shard_id,
            &delivery_digest,
        );
        let receipt: [u8; BUNDLE_SIGNATURE_LEN] = HybridEd25519FnDsa
            .sign(secret_key, SCHEME_DOMAIN_RECEIPT, &transcript)
            .expect("fixture receipt signing")
            .to_canonical_bytes()
            .try_into()
            .expect("the canonical signature length");
        BundleRecord {
            attempt,
            anchor_height: anchor,
            delivery_digest,
            receipt,
        }
    }

    /// The bundle an honest producer files when exactly `passes` passed,
    /// each on its first read.
    ///
    /// # Panics
    ///
    /// If a pass is at or beyond the world's count.
    #[must_use]
    pub fn bundle(&self, passes: &[u32]) -> (BundleRef, BundleBody) {
        let mut ascending = passes.to_vec();
        ascending.sort_unstable();
        let records: Vec<BundleRecord> = ascending.iter().map(|j| self.record(*j, 0)).collect();
        let bitmap =
            PassBitmap::from_passes(self.count, ascending).expect("passes below the count");
        self.assemble(bitmap, &records)
    }

    /// A bundle with this bitmap and these records, whatever they are,
    /// signed by the witness: what a producer that files a defective
    /// bundle sends. The reference is the body's own.
    ///
    /// # Panics
    ///
    /// If signing fails.
    #[must_use]
    pub fn assemble(
        &self,
        passes: PassBitmap,
        records: &[BundleRecord],
    ) -> (BundleRef, BundleBody) {
        let kept = BundleKept {
            h: self.h,
            seed: self.seed,
            passes,
        };
        let records_bytes: Vec<u8> = records.iter().flat_map(BundleRecord::encode).collect();
        let commitment = kept.commitment(&records_bytes);
        let signature: [u8; BUNDLE_SIGNATURE_LEN] = HybridEd25519FnDsa
            .sign(
                &self.witness_secret_key,
                SCHEME_DOMAIN_WITNESS_BUNDLE,
                &commitment,
            )
            .expect("fixture witness signing")
            .to_canonical_bytes()
            .try_into()
            .expect("the canonical signature length");
        let body = BundleBody::new(&self.witness_public_key, &signature, records);
        (BundleRef::of(&kept, &body), body)
    }
}
