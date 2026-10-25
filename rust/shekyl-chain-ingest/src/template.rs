// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node's one block template (`DRS_X_STORE_FLIP.md` DX-Q3, N2).
//!
//! The tip follower builds it for the block after the tip, and the miner
//! and `get_block_template` read the job it posts. Nothing else builds a
//! block for this node.
//!
//! **One snapshot.** [`produce`] takes a [`ReadSnapshot`] and no store, so
//! every operand is that snapshot's: the chain facts
//! ([`chain_facts_on`]), the seed and the target ([`claim_next`]), the
//! next epoch's seed ([`next_seed`]), and the pool's selection over the
//! snapshot's view. A connect that lands while the template is built
//! changes none of them.
//!
//! **The listing.** The pool's candidates are offered in `select`'s order
//! to the reward-aware [`Fill`] priced at [`COINBASE_RESERVE`], and listed
//! only if it admits them. The chain snapshot is open first. The pool lock
//! is taken to copy the shown entries, dropped while `tx_against` runs over
//! the copy, and taken again for the eviction; a body the pool stopped
//! showing in between posts nothing, and the follower builds again. `build`
//! then prices the coinbase over that listing, once. Candidates the parent refuses are evicted (CEN-M10).
//!
//! **The secrets.** The coinbase's transaction secret is drawn from the OS
//! for each template, and the draw commitment is
//! [`commit_and_discard`]'s: neither is kept, and neither is derived from
//! anything another template shares.
//!
//! **The extra nonce.** Every coinbase reserves its eight bytes, zeroed;
//! the job carries their offset and the header nonce's.

use std::sync::{Mutex, PoisonError};

use rand::RngCore;
use shekyl_archival_retention::{commit_and_discard, empty_attestation_root};
use shekyl_block_template::{
    build, EmissionOperands, Fill, MinerKeys, Template, TemplateContext, TemplateError,
};
use shekyl_chain_rules::{Fault, RuleSet};
use shekyl_chain_store::store::{ReadSnapshot, SnapshotView, StoreError};
use shekyl_economics::EconomicParams;
use shekyl_mempool::{select_shown, Evicted, Pool};
use shekyl_miner::{Job, ListedBody};
use shekyl_types::{AttestationRoot, BlockHash, Timestamp, TxHash};
use shekyl_wire::transaction::COINBASE_RESERVE;
use shekyl_wire::tx_extra::COINBASE_NONCE_BYTES;
use shekyl_wire::Transaction;
use zeroize::Zeroizing;

use crate::connector::{chain_facts_on, ChainFacts, FactsStop};
use crate::router::{claim_next, next_seed, ClaimStop};
use crate::schedule::ChainRules;

/// A template, as the follower posts it.
#[derive(Debug)]
pub(crate) struct Produced {
    /// The job: the block and what a miner reads beside it.
    pub(crate) job: Job,
    /// The listed bodies, in the block's order.
    pub(crate) transactions: Vec<Transaction>,
    /// The block weight the coinbase was priced at, coinbase included.
    pub(crate) block_weight: u64,
    /// The penalised gross emission the coinbase was priced at.
    pub(crate) block_reward: shekyl_units::AtomicUnits,
    /// The built coinbase's weight. The fill priced the listing at
    /// [`COINBASE_RESERVE`], which is at least this.
    pub(crate) coinbase_weight: u64,
    /// What CEN-M10 took from the pool after the selection.
    pub(crate) evicted: Vec<(TxHash, Evicted)>,
}

/// Why [`produce`] built nothing.
#[derive(Debug)]
pub(crate) enum NoTemplate {
    /// The chain facts could not be read.
    Facts(FactsStop),
    /// The seed, the target or the next seed could not be claimed.
    Claim(ClaimStop),
    /// The seed for the next block is not one the caches hold yet.
    SeedNotHeld,
    /// The pool's selection could not read the chain.
    Selection(Fault<StoreError>),
    /// The pool file faulted while evicting what the parent refused.
    PoolFile(StoreError),
    /// The OS random source failed, for the coinbase secret or the draw.
    Random(String),
    /// The block could not be priced or assembled.
    Build(TemplateError),
    /// The built coinbase reserves no extra nonce: a defect in `build`.
    NoNonceSlot,
    /// The pool's entries were last judged against another tip than this
    /// template's parent. Selecting would refuse, and evict, entries valid
    /// at the tip they were judged at; the follower builds again.
    PoolOnAnotherTip,
    /// A listed body left the pool between the producer's two locks; the
    /// follower builds again, without it.
    BodyGone,
}

impl From<TemplateError> for NoTemplate {
    fn from(error: TemplateError) -> Self {
        Self::Build(error)
    }
}

/// What the producer pays and prices with, besides the chain.
pub(crate) struct Producer<'a> {
    /// The rules in force by height.
    pub(crate) rules: ChainRules,
    /// Whom the coinbase pays.
    pub(crate) keys: &'a MinerKeys,
    /// The economics the validator judges by.
    pub(crate) params: &'a EconomicParams,
    /// The producer's clock: the header's timestamp is no earlier, and is
    /// past the chain's median (`template_timestamp`).
    pub(crate) now: Timestamp,
    /// A test acts on the pool between the producer's two locks.
    #[cfg(test)]
    pub(crate) between_locks: Option<&'a BetweenLocks<'a>>,
}

/// What a test does to the pool between the producer's two locks.
#[cfg(test)]
pub(crate) type BetweenLocks<'a> = dyn Fn(&Mutex<Pool>) + Sync + 'a;

/// The same hook, held by the service across wakes. `Send` so a build can
/// take it onto a blocking thread; the producer borrows it as
/// [`BetweenLocks`].
#[cfg(test)]
pub(crate) type HeldBetweenLocks = dyn Fn(&Mutex<Pool>) + Send + Sync;

/// Build the template for the block after `snap`'s tip (module docs).
///
/// `holds` says whether the seed caches hold a seed. `pool` is the pool.
/// The snapshot is taken under its lock, the selection runs after the
/// lock is dropped, and the eviction takes the lock again. `None` lists
/// no bodies. `snap` is begun before either lock.
///
/// # Errors
///
/// [`NoTemplate`].
pub(crate) fn produce(
    snap: &ReadSnapshot<'_>,
    producer: &Producer<'_>,
    pool: Option<&Mutex<Pool>>,
    holds: impl FnOnce(&BlockHash) -> bool,
) -> Result<Produced, NoTemplate> {
    let facts = chain_facts_on(snap).map_err(NoTemplate::Facts)?;
    let (height, seed, target) = claim_next(snap, producer.rules).map_err(NoTemplate::Claim)?;
    debug_assert_eq!(height, facts.connecting, "one snapshot, one tip");
    if !holds(&seed) {
        return Err(NoTemplate::SeedNotHeld);
    }
    let next_seed = next_seed(snap, height).map_err(NoTemplate::Claim)?;
    let rule_set = producer.rules.in_force(height);
    let secrets = Secrets::draw()?;
    let Listing {
        bodies: listed,
        summaries,
        evicted,
    } = match pool {
        None => Listing::default(),
        Some(pool) => list(snap, producer, &facts, &rule_set, pool)?,
    };
    let template = secrets.build(producer, &facts, &rule_set, &listed)?;
    let offsets = template
        .block
        .blob_offsets()
        .ok_or(NoTemplate::NoNonceSlot)?;
    let reward = template
        .miner_emission
        .checked_add(template.miner_fee_income)
        .ok_or(NoTemplate::Build(TemplateError::AmountOverflow))?;
    let coinbase_weight = u64::try_from(template.block.miner_transaction.weight())
        .map_err(|_| NoTemplate::Build(TemplateError::WeightOverflow))?;
    Ok(Produced {
        job: Job {
            block: template.block,
            height,
            seed,
            difficulty: target.difficulty(),
            offsets,
            next_seed,
            reward,
            median_weight: facts.medians.effective_median.to_raw(),
            already_generated: facts.parent_coins_generated,
            listed: summaries,
        },
        transactions: template.transactions,
        block_weight: template.block_weight,
        block_reward: template.block_reward,
        coinbase_weight,
        evicted,
    })
}

/// The bodies the fill admits, and what CEN-M10 evicted.
#[derive(Default)]
struct Listing {
    /// In `select`'s order.
    bodies: Vec<Transaction>,
    /// Each body's id, weight and fee, in the same order.
    summaries: Vec<ListedBody>,
    /// After the selection.
    evicted: Vec<(TxHash, Evicted)>,
}

/// The bodies the fill admits, in `select`'s order, and what CEN-M10
/// evicted after the selection.
///
/// The chain snapshot is already open. The pool lock is taken to copy the
/// shown entries and to confirm they were judged at this parent, then
/// dropped for `tx_against`, then taken again for the eviction. A tip move
/// between the two locks evicts nothing. A listed body the pool stopped
/// showing between them — a make-room eviction, a same-tip reconcile, a
/// flush — posts nothing and evicts nothing ([`NoTemplate::BodyGone`]): a
/// job must not name a body an outside miner's `submit_block` cannot find,
/// and the follower builds again without it.
fn list(
    snap: &ReadSnapshot<'_>,
    producer: &Producer<'_>,
    facts: &ChainFacts,
    rule_set: &RuleSet,
    pool: &Mutex<Pool>,
) -> Result<Listing, NoTemplate> {
    let reserve = u64::try_from(COINBASE_RESERVE)
        .map_err(|_| NoTemplate::Build(TemplateError::WeightOverflow))?;
    let mut fill = Fill::empty(
        facts.medians.effective_median.to_raw(),
        reserve,
        facts.parent_coins_generated.to_raw(),
        facts.tx_volume,
        producer.params,
    )
    .map_err(|error| NoTemplate::Build(TemplateError::Emission(error)))?;
    let bound = fill.bodies_weight_bound();
    let view = SnapshotView::new(snap);
    let shown = {
        let pool = pool.lock().unwrap_or_else(PoisonError::into_inner);
        if !judged_at_parent(&pool, facts.previous) {
            return Err(NoTemplate::PoolOnAnotherTip);
        }
        pool.shown_bodies()
    };
    let selected = select_shown(&shown, &view, rule_set, bound, |weight, fee| {
        fill.admit(weight, fee)
    })
    .map_err(NoTemplate::Selection)?;
    #[cfg(test)]
    if let Some(between) = producer.between_locks {
        between(pool);
    }
    let refused: Vec<TxHash> = selected.refused.iter().map(|(txid, _)| *txid).collect();
    let evicted = {
        let mut pool = pool.lock().unwrap_or_else(PoisonError::into_inner);
        if !judged_at_parent(&pool, facts.previous) {
            return Err(NoTemplate::PoolOnAnotherTip);
        }
        let gone = {
            let view = pool.relay_view();
            selected.transactions.iter().any(|body| {
                !view
                    .record(&body.id)
                    .is_some_and(|record| shekyl_mempool::shown(&record))
            })
        };
        if gone {
            return Err(NoTemplate::BodyGone);
        }
        let listed: Vec<TxHash> = selected.transactions.iter().map(|body| body.id).collect();
        pool.evict(&refused, &listed)
            .map_err(NoTemplate::PoolFile)?
    };
    let summaries = selected
        .transactions
        .iter()
        .map(|body| ListedBody {
            id: body.id,
            weight: body.weight,
            fee: body.fee,
        })
        .collect();
    let bodies = selected
        .transactions
        .into_iter()
        .map(|body| body.tx)
        .collect();
    Ok(Listing {
        bodies,
        summaries,
        evicted,
    })
}

/// Whether the pool's last judgement is this template's parent.
fn judged_at_parent(pool: &Pool, parent: BlockHash) -> bool {
    pool.judged_at().is_some_and(|tip| tip.hash == parent)
}

/// One template's secrets: the coinbase's transaction secret and its draw
/// commitment. The build takes a wiped copy of the secret.
struct Secrets {
    tx_key: Zeroizing<[u8; 32]>,
    draw: shekyl_types::archival::DrawCommitment,
}

impl Secrets {
    fn draw() -> Result<Self, NoTemplate> {
        let mut tx_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(tx_key.as_mut())
            .map_err(|e| NoTemplate::Random(e.to_string()))?;
        let draw = commit_and_discard().map_err(|e| NoTemplate::Random(e.to_string()))?;
        Ok(Self { tx_key, draw })
    }

    fn build(
        &self,
        producer: &Producer<'_>,
        facts: &ChainFacts,
        rule_set: &RuleSet,
        listed: &[Transaction],
    ) -> Result<Template, TemplateError> {
        // Copied cell to cell: no bare copy of the secret on this stack.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        tx_key_secret.copy_from_slice(self.tx_key.as_ref());
        build(&TemplateContext {
            height: facts.connecting,
            previous: facts.previous,
            curve_tree_root: facts.curve_tree_root,
            // This node mints no attestation records, so every template
            // commits the empty set's root (CEN-B4's witness-less arm).
            attestation_root: AttestationRoot::from_bytes(empty_attestation_root()),
            major_version: rule_set.header_major_version(),
            now: producer.now,
            median_timestamp: facts.median_timestamp,
            unlock_window: rule_set.mined_money_unlock_window(),
            emission: EmissionOperands {
                already_generated_coins: facts.parent_coins_generated,
                total_burned: facts.total_burned,
                median_weight: facts.medians.effective_median.to_raw(),
                tx_volume: facts.tx_volume,
                closed_shards: facts.closed_shards,
            },
            params: producer.params,
            miner: producer.keys,
            tx_key_secret,
            extra_nonce: [0; COINBASE_NONCE_BYTES],
            draw_commitment: self.draw,
            listed,
        })
    }
}
