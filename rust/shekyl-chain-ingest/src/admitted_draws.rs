// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Admitted draws on a scenario chain (`SO-D12` 4b).
//!
//! The settlement chains mine through here. Each block commits to a
//! [`DriverWitness`] this driver holds — the stand-in for the node's
//! witness ring, whose key never leaves it — and a block that draws files
//! its bundle. The next block carries that bundle as its section and
//! `validate` admits it ([`Driven::connect_admitting`]). Which draws pass
//! is the caller's ([`Passes`]): a withheld draw is filed with no record,
//! so its bit is clear and the admitted bundle files it as a miss. The
//! chain's issued-draw indexes are what a later assertion reads.
//!
//! Two boundaries are substituted, and only those two. The witness is
//! [`DriverWitness`]. A persona's serve is its receipt signed directly
//! ([`signed_record`](shekyl_chain_rules::harness::bundle::signed_record)):
//! the verifier checks the receipt and the anchor, not the bytes served.

use std::collections::BTreeSet;

use shekyl_archival_retention::{
    assemble_bundle, challenge_nonce, draw_commit, sign_bundle_commitment, support_challenge_nonce,
    BundleKept, BundleRecord, PassBitmap, PassStream, BUNDLE_WITNESS_KEY_LEN, CHALLENGE_READS,
};
use shekyl_bundle_producer::DrawTarget;
use shekyl_chain_rules::harness::bundle::{signed_record, Anchor};
use shekyl_chain_rules::EpochFloor;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSecretKey, HybridEd25519FnDsa};
use shekyl_harness_spender::Persona;
use shekyl_types::archival::{DrawCommitment, COUNTED_DRAWS};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use zeroize::Zeroizing;

use crate::chain_drive::Driven;
use crate::connector::{BundleOffered, LearnDraws, Learned, OfferBundle};
use crate::scenario::{FreeHash, Mined, Scenario};

/// The first read of a draw. Admission refuses an attempt at or past
/// [`CHALLENGE_READS`].
const FIRST_READ_ATTEMPT: u8 = 0;

const _: () = assert!(FIRST_READ_ATTEMPT < CHALLENGE_READS);

/// Flips a witness tag into its second keygen seed, so the two seeds
/// differ for every tag.
const WITNESS_SEED_MASK: u8 = 0x5A;

/// A witness this driver holds: the key every block it mines commits to,
/// and a seed per height. It stands in for the node's witness ring
/// (`shekyl_bundle_producer::WitnessRing`), whose key never leaves it:
/// these chains test settlement over admitted draws, not the producer.
pub(crate) struct DriverWitness {
    public: [u8; BUNDLE_WITNESS_KEY_LEN],
    secret: FnDsaHybridSecretKey,
    tag: u8,
}

impl DriverWitness {
    pub(crate) fn new(tag: u8) -> Self {
        let (public, secret) =
            HybridEd25519FnDsa::keypair_from_seeds(&[tag; 32], &[tag ^ WITNESS_SEED_MASK; 32])
                .expect("keygen");
        Self {
            public: public
                .to_canonical_bytes()
                .try_into()
                .expect("the canonical key width"),
            secret,
            tag,
        }
    }

    /// The seed of the block at `h`: distinct per height, so each block's
    /// draws are its own.
    fn seed(&self, h: BlockHeight) -> [u8; 32] {
        let mut seed = [self.tag; 32];
        let height = h.to_raw().to_le_bytes();
        seed[..height.len()].copy_from_slice(&height);
        seed
    }

    fn commitment(&self, h: BlockHeight) -> DrawCommitment {
        DrawCommitment::from_bytes(draw_commit(&self.public, &self.seed(h)))
    }
}

/// Whether the draw `target` of the block at `h` passes: its holder serves
/// the read and its receipt is filed. `false` is a holder that withholds:
/// the draw is filed with no record.
pub(crate) type Passes<'a> = &'a dyn Fn(BlockHeight, &DrawTarget) -> bool;

/// Every draw passes.
pub(crate) fn every_draw_passes(_: BlockHeight, _: &DrawTarget) -> bool {
    true
}

/// What [`serve_to`] does with the block at `h`.
struct ServeAt {
    /// Mine the block.
    mine: bool,
    /// File its draws when it drew any. The block mined only to admit
    /// the previous bundle does not file.
    file: bool,
}

/// `until` is the first height the caller did not ask to settle. It is
/// mined only when `waiting` — the previous block filed a bundle this
/// block has to admit — and that block's own draws are not filed.
/// Nothing above `until` is mined.
fn serve_at(h: BlockHeight, until: BlockHeight, waiting: bool) -> ServeAt {
    let mine = h < until || (h == until && waiting);
    ServeAt {
        mine,
        file: mine && h < until,
    }
}

/// Mine empty blocks up to `until`, every one committed to `witness`, and
/// file each drawing block's bundle so the next block admits it. Each
/// block goes through [`Driven::connect_admitting`], so a round-tripping
/// drive pops and reconnects it too.
///
/// Each learned draw passes when `passes` says so, signed by the persona
/// among `signers` that holds the shard; otherwise it is withheld. The
/// bundle format carries both streams even when one of them drew nothing.
///
/// # Panics
///
/// If a block does not land, if the connector cannot derive a block's
/// draws, if a passing draw's persona is not among `signers`, if a drawing
/// block has no parent, or if the queue or the next block refuses a bundle.
pub(crate) async fn serve_to(
    drive: &mut Driven,
    witness: &DriverWitness,
    signers: &[&Persona],
    passes: Passes<'_>,
    until: BlockHeight,
) {
    let mut waiting = false;
    loop {
        let h = drive.height();
        let at = serve_at(h, until, waiting);
        if !at.mine {
            return;
        }
        let block = mine_one(drive, witness, h, waiting).await;
        if !at.file {
            return;
        }
        waiting = file_draws(drive, witness, signers, passes, h, block.hash).await;
        if waiting {
            // The filed bundle is a write beside a block: the queue holds
            // it after the block that drew it. A round trip's next pop
            // compares against the store it left.
            drive.wrote_beside_a_block().await;
        }
    }
}

/// [`serve_to`] over a straight scenario chain, every draw a pass.
pub(crate) async fn mine_serving(
    scenario: Scenario<FreeHash>,
    mined: Vec<Mined>,
    witness: &DriverWitness,
    signers: &[&Persona],
    until: BlockHeight,
) -> (Scenario<FreeHash>, Vec<Mined>) {
    let mut drive = Driven::begin(scenario, mined);
    serve_to(&mut drive, witness, signers, &every_draw_passes, until).await;
    drive.into_parts()
}

/// Mine the block at `h`. `admit` is that the previous block filed a
/// bundle, which this block carries and reveals.
async fn mine_one(
    drive: &mut Driven,
    witness: &DriverWitness,
    h: BlockHeight,
    admit: bool,
) -> Mined {
    drive.scenario.commit_next(witness.commitment(h));
    let (block, admitted) = drive
        .connect_admitting(Vec::new())
        .await
        .unwrap_or_else(|outcome| panic!("block {h} lands: {outcome}"));
    assert_eq!(
        admitted.len(),
        usize::from(admit),
        "block {h} admits the bundle filed for it, and only that"
    );
    assert_eq!(block.height, h);
    block
}

/// Learn `h`'s draws and, when it drew, file the bundle. Returns whether
/// a bundle is now waiting for the next block.
async fn file_draws(
    drive: &Driven,
    witness: &DriverWitness,
    signers: &[&Persona],
    passes: Passes<'_>,
    h: BlockHeight,
    hash: BlockHash,
) -> bool {
    let scenario = &drive.scenario;
    let mined = &drive.chain;
    let seed = witness.seed(h);
    let learned = scenario
        .connector()
        .ask(LearnDraws {
            h,
            hash,
            seed: Zeroizing::new(seed),
        })
        .await
        .expect("the connector answers");
    let Learned::Targets(targets) = learned else {
        panic!("the draws of block {h} are derived: {learned:?}");
    };
    if targets.draws.is_empty() {
        return false;
    }
    let parent = h
        .checked_sub_count(BlockCount::ONE)
        .expect("a drawing block has a parent");
    let anchor = Anchor {
        height: parent,
        hash: mined[usize::try_from(parent.to_raw()).expect("a test chain's length")].hash,
    };
    let filed = file_passes(h, &targets.draws, &seed, &hash, anchor, signers, passes);
    let kept = BundleKept {
        h,
        seed,
        passes: filed.economy,
        support: filed.support,
    };
    let (reference, body) = assemble_bundle(
        &scenario.network_id(),
        &kept,
        &filed.records,
        &witness.public,
        |commitment| sign_bundle_commitment(&witness.secret, commitment),
    )
    .expect("the witness signs");
    let offered = scenario
        .connector()
        .ask(OfferBundle { reference, body })
        .await
        .expect("the connector answers");
    assert!(
        matches!(offered, BundleOffered::Queued { h: queued, .. } if queued == h),
        "the bundle for block {h} is queued: {offered:?}"
    );
    true
}

/// Both streams of one block, each draw passed or withheld by `passes`.
/// Economy records precede support records: the bitmaps' order.
struct FiledPasses {
    economy: PassBitmap,
    support: PassBitmap,
    records: Vec<BundleRecord>,
}

fn file_passes(
    h: BlockHeight,
    targets: &[DrawTarget],
    seed: &[u8; 32],
    block_hash: &BlockHash,
    anchor: Anchor,
    signers: &[&Persona],
    passes: Passes<'_>,
) -> FiledPasses {
    let filing = Filing {
        h,
        seed,
        block_hash,
        anchor,
        signers,
        passes,
    };
    let (economy, mut records) = filing.stream(PassStream::Economy, targets);
    let (support, support_records) = filing.stream(PassStream::Support, targets);
    records.extend(support_records);
    FiledPasses {
        economy,
        support,
        records,
    }
}

/// What filing one block's draws reads.
struct Filing<'a> {
    h: BlockHeight,
    seed: &'a [u8; 32],
    block_hash: &'a BlockHash,
    anchor: Anchor,
    signers: &'a [&'a Persona],
    passes: Passes<'a>,
}

impl Filing<'_> {
    /// One stream's bitmap and records: a record for each draw that
    /// passes, none for one withheld.
    fn stream(
        &self,
        stream: PassStream,
        targets: &[DrawTarget],
    ) -> (PassBitmap, Vec<BundleRecord>) {
        let drawn: Vec<&DrawTarget> = targets
            .iter()
            .filter(|target| target.stream == stream)
            .collect();
        let mut passed = Vec::with_capacity(drawn.len());
        let mut records = Vec::with_capacity(drawn.len());
        for target in &drawn {
            if !(self.passes)(self.h, target) {
                continue;
            }
            let signer = self
                .signers
                .iter()
                .find(|persona| persona.id() == target.persona)
                .unwrap_or_else(|| {
                    panic!("persona {:?} passed and is not a signer", target.persona)
                });
            let nonce = match stream {
                PassStream::Economy => {
                    challenge_nonce(self.seed, self.block_hash, target.draw, FIRST_READ_ATTEMPT)
                }
                PassStream::Support => support_challenge_nonce(
                    self.seed,
                    self.block_hash,
                    target.draw,
                    FIRST_READ_ATTEMPT,
                ),
            };
            records.push(signed_record(
                &signer.keys().receipt_sign_sk,
                stream,
                &nonce,
                self.anchor,
                target.shard.to_raw(),
                FIRST_READ_ATTEMPT,
            ));
            passed.push(target.draw);
        }
        let count = u32::try_from(drawn.len()).expect("a block's draws fit u32");
        let bitmap = PassBitmap::from_passes(count, passed).expect("passes below the count");
        (bitmap, records)
    }
}

/// The epoch's issued-draw index, and nothing else: `pair` is the only
/// pair, it was issued at least [`COUNTED_DRAWS`], and every one of those
/// draws passed.
///
/// The index is the evidence (rule 47). The schedule derivation says why
/// to expect a pair to be full; this read is what the chain recorded.
///
/// # Panics
///
/// If the store does not read, or the index does not say that.
pub(crate) fn assert_issued_pair(
    scenario: &Scenario<FreeHash>,
    epoch: SettlementEpoch,
    pair: (PCanonicalId, ShardId),
) {
    let issued = scenario
        .store()
        .begin_read()
        .expect("snapshot")
        .issued_draws(epoch, EpochFloor::NONE)
        .expect("the index reads");
    assert!(
        !issued.is_empty(),
        "epoch {epoch} issued no draws; the index the assertion reads is absent"
    );
    let mut others = BTreeSet::new();
    let mut of_pair = 0usize;
    for draw in &issued {
        if (draw.persona, draw.shard) != pair {
            others.insert((draw.persona, draw.shard));
            continue;
        }
        assert!(
            draw.state.passed,
            "a draw of {pair:?} in epoch {epoch} did not pass: {draw:?}"
        );
        of_pair += 1;
    }
    assert!(
        others.is_empty(),
        "epoch {epoch} issued a pair other than {pair:?}: {others:?}"
    );
    assert!(
        of_pair >= COUNTED_DRAWS,
        "{pair:?} has {of_pair} issued draws in epoch {epoch}, under its {COUNTED_DRAWS} counted"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `until` stops the miner. Red edit: file the block at `until`
    /// (the next epoch's draws are then admitted inside the call).
    #[test]
    fn until_is_a_hard_stop() {
        let until = BlockHeight::from_raw(1);
        let before = BlockHeight::ZERO;
        let past = until + BlockCount::ONE;

        let settling = serve_at(before, until, false);
        assert!(settling.mine, "a height below until is mined");
        assert!(settling.file, "a height below until files its draws");

        let idle = serve_at(until, until, false);
        assert!(!idle.mine, "until is not mined when nothing is waiting");
        assert!(!idle.file);

        let admitting = serve_at(until, until, true);
        assert!(admitting.mine, "until is mined to admit the bundle waiting");
        assert!(!admitting.file, "the admitting block's draws are not filed");

        let beyond = serve_at(past, until, true);
        assert!(!beyond.mine, "nothing past until is mined");
        assert!(!beyond.file);
    }
}
