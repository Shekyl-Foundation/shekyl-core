// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The record check both streams of one bundle share.
//!
//! [`super::verify_bundle`] binds every set bit — economy, then support —
//! and this module judges that list in three passes. Step 7 is the
//! `attempt` of every record. The anchor of every record is the next
//! pass: `anchor_height < h`, then the anchor's block hash. Step 8, the
//! receipt, runs only after both of those have accepted every record.
//! A later `attempt` or anchor is therefore the refusal even when an
//! earlier receipt would not verify, and a missing receipt key cannot
//! hide an earlier `attempt`.
//!
//! The two streams differ in the nonce and in where the receipt key
//! comes from. They do not differ in the order of the checks.

use shekyl_archival_retention::{
    challenge_nonce, select_support_shard, support_challenge_nonce, verify_receipt_transcript,
    BundleBody, BundleRecord, DrawableEpoch, PassStream, CHALLENGE_READS,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, FnDsaHybridSignature};
use shekyl_types::archival::ReceiptSignPk;
use shekyl_types::BlockHash;

use super::{
    BundleInvalid, BundleKept, BundleRefused, BundleUnanswered, BundleView, DerivedDraw,
    SupportObservation,
};

/// One set bit, bound to the body record that carries it.
///
/// Economy bits name an index in the drawable epoch. Support bits carry
/// the seat's receipt key. Neither key is opened until the receipt pass.
pub(super) struct BoundPass {
    stream: PassStream,
    draw: u32,
    record: BundleRecord,
    shard: u64,
    key: PassKey,
}

/// Where the receipt pass opens this record's key.
enum PassKey {
    /// [`DrawableEpoch::receipt_key`] at this index.
    Economy { index: u64 },
    /// The complete tree's receipt key, as the roster holds it.
    Support(ReceiptSignPk),
}

impl BoundPass {
    /// An economy set bit. `index` is the pair's position in `D`.
    pub(super) fn economy(draw: u32, record: BundleRecord, index: u64, shard: u64) -> Self {
        Self {
            stream: PassStream::Economy,
            draw,
            record,
            shard,
            key: PassKey::Economy { index },
        }
    }

    /// A support set bit. `key` is the seat's, cloned so the roster the
    /// view returned can drop before the receipt pass runs.
    pub(super) fn support(draw: u32, record: BundleRecord, shard: u64, key: ReceiptSignPk) -> Self {
        Self {
            stream: PassStream::Support,
            draw,
            record,
            shard,
            key: PassKey::Support(key),
        }
    }
}

/// Attempt, then anchor, then receipt, over `passes` in the order bound.
///
/// `drawable` is the epoch the economy keys are opened against. A support
/// only bundle has none. An economy pass without it is unanswered: the
/// key has nowhere to come from.
pub(super) fn judge_passes<V: BundleView>(
    view: &V,
    kept: &BundleKept,
    hash_at_h: &[u8; 32],
    passes: &[BoundPass],
    drawable: Option<&DrawableEpoch>,
) -> Result<(), BundleRefused<V::Fault>> {
    // 7. `attempt < K`, every record, before any anchor hash or receipt.
    for pass in passes {
        if pass.record.attempt >= CHALLENGE_READS {
            return Err(invalid(BundleInvalid::Attempt { draw: pass.draw }));
        }
    }

    // Anchors, every record, before any receipt. The hash read is the
    // view's; a height it cannot answer is the hole, and it surfaces
    // here rather than after a receipt that would also have failed.
    let mut anchors = Vec::with_capacity(passes.len());
    for pass in passes {
        if pass.record.anchor_height >= kept.h {
            return Err(invalid(BundleInvalid::Anchor { draw: pass.draw }));
        }
        let Some(anchor_hash) = view.block_hash(pass.record.anchor_height)? else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::BlockHash {
                height: pass.record.anchor_height,
            }));
        };
        anchors.push(anchor_hash);
    }

    // 8. Receipts, in the same order. The key is opened here, so a
    // missing key cannot hide an earlier attempt or anchor.
    for (pass, anchor_hash) in passes.iter().zip(anchors) {
        verify_one(kept, hash_at_h, pass, &anchor_hash, drawable)?;
    }
    Ok(())
}

fn verify_one<F>(
    kept: &BundleKept,
    hash_at_h: &[u8; 32],
    pass: &BoundPass,
    anchor_hash: &BlockHash,
    drawable: Option<&DrawableEpoch>,
) -> Result<(), BundleRefused<F>> {
    let unanswered = || {
        Err(BundleRefused::Unanswered(BundleUnanswered::Draw {
            draw: pass.draw,
        }))
    };
    match &pass.key {
        PassKey::Economy { index } => {
            let Some(drawable) = drawable else {
                return unanswered();
            };
            let Some(key) = drawable.receipt_key(*index) else {
                return unanswered();
            };
            let nonce = challenge_nonce(&kept.seed, hash_at_h, pass.draw, pass.record.attempt);
            verify_transcript(pass, anchor_hash, key, &nonce)
        }
        PassKey::Support(receipt_key) => {
            let Ok(key) = FnDsaHybridPublicKey::from_receipt_sign_pk(receipt_key) else {
                return unanswered();
            };
            let nonce =
                support_challenge_nonce(&kept.seed, hash_at_h, pass.draw, pass.record.attempt);
            verify_transcript(pass, anchor_hash, &key, &nonce)
        }
    }
}

fn verify_transcript<F>(
    pass: &BoundPass,
    anchor_hash: &BlockHash,
    key: &FnDsaHybridPublicKey,
    nonce: &[u8; 32],
) -> Result<(), BundleRefused<F>> {
    let Ok(receipt) = FnDsaHybridSignature::from_canonical_bytes(&pass.record.receipt) else {
        return Err(invalid(BundleInvalid::Receipt { draw: pass.draw }));
    };
    if verify_receipt_transcript(
        key,
        pass.stream,
        nonce,
        pass.record.anchor_height,
        anchor_hash.as_bytes(),
        pass.shard,
        &pass.record.delivery_digest,
        &receipt,
    )
    .is_err()
    {
        return Err(invalid(BundleInvalid::Receipt { draw: pass.draw }));
    }
    Ok(())
}

fn invalid<F>(why: BundleInvalid) -> BundleRefused<F> {
    BundleRefused::Invalid(why)
}

/// The economy set bits, in bitmap order, ahead of the support bits.
///
/// A set bit's index is below `draws.len()` by the bitmap's construction
/// when the block issued economy draws, and there are none when it did
/// not. A record short of the set bits is [`BundleInvalid::RecordCount`]:
/// the count check above is the same fact, and this is the belt under the
/// zip.
pub(super) fn bind_economy<F>(
    passes: &mut Vec<BoundPass>,
    kept: &BundleKept,
    body: &BundleBody,
    draws: &[DerivedDraw],
) -> Result<(), BundleRefused<F>> {
    let expected = kept.passes.popcount();
    let mut bound = 0u32;
    for (draw, record) in kept.passes.iter_set().zip(body.records()) {
        if bound == expected {
            break;
        }
        // A `u32` into a `usize` is lossless on every target the workspace
        // builds for.
        let Some(derived) = usize::try_from(draw).ok().and_then(|at| draws.get(at)) else {
            return Err(invalid(BundleInvalid::RecordCount));
        };
        passes.push(BoundPass::economy(
            draw,
            record,
            derived.index,
            derived.pair.shard.to_raw(),
        ));
        bound += 1;
    }
    if bound != expected {
        return Err(invalid(BundleInvalid::RecordCount));
    }
    Ok(())
}

/// One support draw of `h`: the seat the roster puts at `j` and the
/// shard the draw names.
pub(super) struct SeatDraw {
    pub(super) draw: u32,
    pub(super) persona: shekyl_types::PCanonicalId,
    pub(super) shard: shekyl_types::ShardId,
    pub(super) receipt_key: ReceiptSignPk,
}

/// Every support draw of `h` when it issued `issued`: seat `j` of the
/// roster, and `select_support_shard` over the archive width. The
/// verifier ([`bind_support`]) and the producer
/// ([`super::draw_targets`]) both derive the support stream here.
///
/// Zero issued reads nothing. A roster whose length is not `issued` is
/// [`BundleInvalid::Count`]: the stated count and the seats disagree.
pub(super) fn support_seats<V: BundleView>(
    view: &V,
    h: shekyl_types::BlockHeight,
    seed: &[u8; 32],
    hash_at_h: &[u8; 32],
    issued: u32,
) -> Result<Vec<SeatDraw>, BundleRefused<V::Fault>> {
    if issued == 0 {
        return Ok(Vec::new());
    }
    let Some(roster) = view.support_roster(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::Draw {
            draw: 0,
        }));
    };
    if roster.len() != usize::try_from(issued).unwrap_or(usize::MAX) {
        return Err(invalid(BundleInvalid::Count));
    }
    let Some(width) = view.archive_width(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::Draw {
            draw: 0,
        }));
    };
    let mut seats = Vec::with_capacity(roster.len());
    for (draw, seat) in (0..issued).zip(roster) {
        let Some(shard) = select_support_shard(seed, hash_at_h, &seat.persona, draw, width) else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::Draw { draw }));
        };
        seats.push(SeatDraw {
            draw,
            persona: seat.persona,
            shard: shekyl_types::ShardId::from_raw(shard),
            receipt_key: seat.receipt_key,
        });
    }
    Ok(seats)
}

/// The support observations, and the set-bit records appended to `passes`.
///
/// An empty bitmap is an empty list and reads nothing more: the width
/// check already proved the block issued none. Clear bits are observations
/// and not records. [`judge_passes`] judges the attempts, the anchors and
/// the receipts, over both streams together.
pub(super) fn bind_support<V: BundleView>(
    view: &V,
    kept: &BundleKept,
    body: &BundleBody,
    hash_at_h: &[u8; 32],
    economy_records: usize,
    passes: &mut Vec<BoundPass>,
) -> Result<Vec<SupportObservation>, BundleRefused<V::Fault>> {
    let seats = support_seats(view, kept.h, &kept.seed, hash_at_h, kept.support.count())?;
    let mut records = body.records().skip(economy_records);
    let mut observations = Vec::with_capacity(seats.len());
    for seat in seats {
        let passed = kept.support.get(seat.draw);
        if passed {
            let Some(record) = records.next() else {
                return Err(invalid(BundleInvalid::RecordCount));
            };
            passes.push(BoundPass::support(
                seat.draw,
                record,
                seat.shard.to_raw(),
                seat.receipt_key,
            ));
        }
        observations.push(SupportObservation {
            persona: seat.persona,
            shard: seat.shard,
            draw: seat.draw,
            passed,
        });
    }
    Ok(observations)
}
