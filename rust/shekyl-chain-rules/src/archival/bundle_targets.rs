// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The draws a producer reads (`SO-D12` increment 4c).
//!
//! One shape from selection through the read: [`Drawn`]. Economy and
//! support select differently, and [`DrawOrigin`] is that difference.
//! The stream is derived from the origin, so it is not stored twice.
//! [`draw_targets`] calls the verifier's [`select_pairs`](super::select_pairs)
//! and [`support_seats`](super::records::support_seats), so the pair a
//! producer reads is the pair the verifier derives.

use shekyl_archival_retention::PassStream;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId, ShardId};

use super::{drawable_for, records, select_pairs, BundleRefused, BundleUnanswered, BundleView};
use crate::rule_set::RuleSet;

/// Where a draw was selected. The two streams are not the same selection,
/// and the economy index is the visibly-short pin the verifier compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrawOrigin {
    /// Step 6: pair `index` of `D(epoch(h))`.
    Economy {
        /// The pair's position in `D`.
        index: u64,
    },
    /// The roster's seat. The shard is the support selection's.
    Support,
}

impl DrawOrigin {
    /// The pass stream this origin is drawn on.
    #[must_use]
    pub const fn stream(self) -> PassStream {
        match self {
            Self::Economy { .. } => PassStream::Economy,
            Self::Support => PassStream::Support,
        }
    }
}

/// One draw of `h`, as its producer reads it.
///
/// Economy draws come first, then support draws, each in draw-index order.
/// `draw` restarts at zero on each stream: it is the bit in that stream's
/// bitmap, not a position in [`DrawTargets::draws`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drawn {
    /// The draw index `j` within its stream.
    pub draw: u32,
    /// Whom to read.
    pub persona: PCanonicalId,
    /// Which shard.
    pub shard: ShardId,
    /// The receipt key the record's receipt verifies under.
    pub receipt_key: FnDsaHybridPublicKey,
    /// Which selection produced this draw.
    pub origin: DrawOrigin,
}

impl Drawn {
    /// The pass stream, from [`Self::origin`].
    #[must_use]
    pub const fn stream(&self) -> PassStream {
        self.origin.stream()
    }
}

/// Everything the producer of `h` reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawTargets {
    /// The block.
    pub h: BlockHeight,
    /// `block_hash(h)`: the selection's and the nonce's input.
    pub hash: BlockHash,
    /// Economy draws, then support draws. Each stream is in draw-index
    /// order, and its length is that bitmap's count.
    pub draws: Vec<Drawn>,
}

/// The draws of `h` under `seed`, derived exactly as [`super::verify_bundle`]
/// derives them: step 6's selection over `D(epoch(h))` at the issued
/// counts visible at `h`, and the support stream's seats and shards.
///
/// The producer of `h` calls this once `h` is on its chain, with the
/// seed it drew. Nothing here judges a bundle: the window, the reveal and
/// the commitment are the queue's admission, which runs [`super::verify_bundle`]
/// on what the producer files.
///
/// A key that does not decode is the draw unanswered, as step 8 treats
/// it: the producer cannot read under it, and the verifier would not open
/// a record under it either.
///
/// # Errors
///
/// [`BundleRefused::Unanswered`] when the view has no count, no hash, no
/// drawable epoch, no roster or no archive width for a stream that issued
/// draws; [`BundleRefused::View`] for the view's own fault. Never
/// [`BundleRefused::Invalid`]: there is no bundle to refuse.
pub fn draw_targets<V: BundleView>(
    view: &V,
    h: BlockHeight,
    seed: &[u8; 32],
    rule_set: &RuleSet,
) -> Result<DrawTargets, BundleRefused<V::Fault>> {
    let Some(count) = view.draw_count(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::DrawCount {
            height: h,
        }));
    };
    let Some(issued) = view.support_count(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::DrawCount {
            height: h,
        }));
    };
    let Some(hash) = view.block_hash(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::BlockHash {
            height: h,
        }));
    };
    let mut draws = Vec::new();
    if count != 0 {
        let epoch = rule_set.settlement_schedule().epoch_at(h);
        let Some(drawable) = drawable_for(view, epoch)? else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::DrawableEpoch {
                epoch,
            }));
        };
        let pairs = select_pairs(view, drawable, h, seed, hash.as_bytes(), count)?;
        draws.reserve(pairs.len());
        for (draw, (index, pair)) in (0..count).zip(pairs) {
            let Some(receipt_key) = drawable.receipt_key(index) else {
                return Err(BundleRefused::Unanswered(BundleUnanswered::Draw { draw }));
            };
            draws.push(Drawn {
                draw,
                persona: pair.persona,
                shard: pair.shard,
                receipt_key: receipt_key.clone(),
                origin: DrawOrigin::Economy { index },
            });
        }
    }
    for seat in records::support_seats(view, h, seed, hash.as_bytes(), issued)? {
        let Ok(receipt_key) = FnDsaHybridPublicKey::from_receipt_sign_pk(&seat.receipt_key) else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::Draw {
                draw: seat.draw,
            }));
        };
        draws.push(Drawn {
            draw: seat.draw,
            persona: seat.persona,
            shard: seat.shard,
            receipt_key,
            origin: DrawOrigin::Support,
        });
    }
    Ok(DrawTargets { h, hash, draws })
}
