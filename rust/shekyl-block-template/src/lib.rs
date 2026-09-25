// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Block-template assembly (TXE-F8; DRS-E6 slice 6 commit 1b).
//!
//! # What a block template is, by design
//!
//! A **candidate block for height `h` on a tip `T`** that the validator
//! admits without being asked — the honest producer's half of the contract
//! `shekyl-chain-rules` judges. Stated against the census rather than
//! against the C++ `create_block_template` (the two questions the slice
//! answers are *what does the C++ template do* and *what should ours do by
//! design*; this file is the second):
//!
//! - **Header.** `previous` is `T`'s identity (CEN-A2; the null hash at
//!   genesis). `curve_tree_root` is the tree state **at** `h` — after `T`
//!   drained, before this block does (CEN-B5). `major_version` is the rule
//!   set's (CEN-B1). `timestamp` is the least the chain admits and no
//!   earlier than the clock: `max(now, median + 1)` — strictly above the
//!   median (CEN-C2, `DAA_LWMA1.md` §5.5's *strictly greater*) — **and
//!   checked against CEN-C1's bound with the owner's predicate**
//!   (`shekyl_difficulty::is_timestamp_below_ftl`), not reasoned about.
//!   The bound is reachable: each accepted block was within FTL of *its*
//!   acceptance clock, so a window stamped near the limit carries a median
//!   ahead of when its blocks landed, and a producer whose clock runs
//!   behind can find `median + 1 > now + FTL`. That template is one its
//!   own validator refuses, so the builder refuses first
//!   ([`TemplateError::TimestampBeyondFutureLimit`]). `nonce` is zero: the
//!   template is what the miner searches, not the result.
//!   `attestation_root` is the caller's — the archival lane owns the credit
//!   wire; the template carries the root, it does not derive one.
//! - **Coinbase.** One `txin_gen` (CEN-F1) claiming `h` (CEN-F5);
//!   `unlock_time = h + window` (CEN-F6); `CTTypeNull` with one committed
//!   base per output (CEN-F3); **one output** above genesis (CEN-F4);
//!   canonical output key (CEN-F9) and a mask that is not
//!   `zeroCommit(amount)` (CEN-F10); the amount is exactly the miner's leg
//!   of the penalised emission plus the miner's share of the listed fees
//!   (CEN-F18 over CEN-F13/F14/F15/F16/F17/F20's operands). The `extra` is
//!   the coinbase grammar's one layout (CEN-I20): pubkey, nonce, one KEM
//!   blob, one leaf blob.
//! - **Body.** `transaction_hashes` are the listed bodies' identities, in
//!   the order listed (CEN-A3/A4); the weight the reward was penalised at
//!   is the weight the block carries, coinbase included (CEN-F14's
//!   operand; connect refuses `!=`, CEN-F14b) — the assembly is a fixed
//!   point in the coinbase's own size, sought in at most
//!   [`MAX_REPRICING_PASSES`] passes. Below the effective median the
//!   reward is weight-independent and the second pass settles it. In the
//!   penalty zone the only variable is the amount's varint (one to ten
//!   bytes): each pass moves the weight by at most nine bytes, so it
//!   settles unless the reward sits **exactly** on a varint boundary and
//!   the two weights trade places — a two-cycle with no fixed point, which
//!   no pass budget resolves. That case is reachable (a penalty slope of a
//!   few million atomic units per byte against a boundary such as `2^49`)
//!   and both producers refuse it loudly — the C++ at its `try_count`
//!   budget of ten (`blockchain.cpp:1830`), this crate at the same budget
//!   ([`TemplateError::WeightNotConverged`]) — rather than emit a template
//!   connect refuses. Neither pads `extra` back to the estimate: the
//!   coinbase extra is a closed grammar (CEN-I20). **The refusal is a
//!   point, not a wall:** it is a function of supply *and* weight, and at
//!   a supply inside the band the amount still falls with weight at
//!   ~10⁶ atomic units per byte, so it crosses each boundary in a window
//!   about one byte wide — three body weights in three hundred thousand
//!   cycle, and a settling one is a byte away. A producer that meets it
//!   builds a different body; `already_generated` is never stalled on it.
//!
//! # What the crate does not do
//!
//! It **reads no chain.** Every operand — the tip, the root, the emission
//! prefix sums, the median weight, the volume window, the listed bodies —
//! arrives in a [`TemplateContext`] the caller composed from the owner
//! crates. That is C2-R8 principle 3 applied to production: the store
//! persists consensus facts the owners compute and never computes them;
//! neither does this crate read them back. `check_chain_rules_no_store.sh`
//! holds the dependency closure to that. It does not **mine**: PoW is the
//! miner's (the nonce search over the returned block), and difficulty is
//! CEN-D4's — a template does not know the target and does not need to.
//! It does not **select** transactions: which bodies to list is mempool
//! policy, and policy is not consensus.
//!
//! # How it is tested, by design
//!
//! The validator is the falsifier. `tests` builds a template on a harness
//! chain and passes it through `form → validate`; every landed 4.F/4.B/4.C
//! row is a row the template can fail, and the coverage record says which
//! rows judged it. What the validator has not landed (CEN-F18 waits on
//! CEN-G6's median, slice 7) the tests state as the identity it will
//! falsify — the amount equals the owners' split on the same operands —
//! so the claim is written down where the row's landing will contradict
//! it if the template drifts. Byte-parity with `create_block_template` is
//! a separate witness (`CHAIN_RULES_SLICE_6.md` §5.3), not this file's.

use core::fmt;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_crypto_pq::output::construct_output;
use shekyl_crypto_pq::CryptoError;
use shekyl_difficulty::is_timestamp_below_ftl;
use shekyl_economics::{
    compute_emission_split, compute_fee_burn, paid_block_reward, CirculatingSupply, EconomicParams,
    EmissionError, FrozenSegmentCount, SupplyInvariantViolation, TxVolume,
};
use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, CurveTreeRoot, Timestamp, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::block::{Block, BlockHeader};
use shekyl_wire::transaction::{Ct, CtBase, Input, Output, Transaction, TxPrefix};
use shekyl_wire::tx_extra::{self, CoinbaseBuildError, COINBASE_NONCE_BYTES};
use zeroize::Zeroizing;

/// The keys a coinbase output is paid to: the miner's Edwards spend key
/// and the two halves of the hybrid KEM encapsulation target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerKeys {
    /// The recipient's Edwards spend public key (`B`).
    pub spend_public: [u8; 32],
    /// X25519 half of the hybrid KEM target.
    pub x25519_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ml_kem_ek: Vec<u8>,
}

/// The emission and fee-burn operands at the connecting height — what
/// CEN-F13/F14/F15/F17/F20 read, composed by the caller from the owner
/// crates (prefix sums are the store's *record*; the definitions are
/// `shekyl-economics`' and `shekyl-chain-rules`').
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionOperands {
    /// Gross emission before this block (CEN-F13's `already_generated_coins`).
    pub already_generated_coins: AtomicUnits,
    /// Total burned before this block; with the above, the circulating
    /// supply the fee burn escalates on (CEN-F17).
    pub total_burned: AtomicUnits,
    /// The effective median block weight (CEN-F14, CEN-G6's operand).
    pub median_weight: u64,
    /// The transaction-volume window ending at the parent (CEN-F20).
    pub tx_volume: TxVolume,
    /// Frozen-segment count for the burn escalation (CEN-F17).
    pub frozen_segments: FrozenSegmentCount,
    /// The height the staker share's decay is measured from (CEN-F21).
    pub emission_split_epoch: BlockHeight,
}

/// Everything a template is a function of. Pure: two contexts with the same
/// operands produce byte-identical blocks.
///
/// Not `Clone`: the context carries the coinbase secret `r`, and a clone is a
/// second copy of a secret the compiler cannot see wiped (rule 35; the
/// `AllKeysBlob` shape). A caller wanting two templates builds two contexts.
/// `Debug` is redacted for the same field.
pub struct TemplateContext<'a> {
    /// The height this block connects at (`tip + 1`; `0` at genesis).
    pub height: BlockHeight,
    /// The tip's identity ([`BlockHash::NULL`] at genesis) — CEN-A2.
    pub previous: BlockHash,
    /// The curve-tree state **at** `height` — CEN-B5.
    pub curve_tree_root: CurveTreeRoot,
    /// The archival attestation root the header carries.
    pub attestation_root: AttestationRoot,
    /// Header version pair — CEN-B1 reads the major.
    pub major_version: u8,
    /// Header minor version.
    pub minor_version: u8,
    /// The producer's clock; the header's timestamp is no earlier.
    pub now: Timestamp,
    /// The median timestamp CEN-C2 will compare against:
    /// `shekyl_chain_rules::mtp_median_at` at `height`, which is `None`
    /// **only at genesis** — from height 1 the window is right-padded with
    /// genesis and a median exists however short the chain. A producer that
    /// passes `None` on a short chain claims its bare clock and builds a
    /// block C2 refuses whenever that clock trails the padded median.
    pub median_timestamp: Option<Timestamp>,
    /// Coinbase maturity window — CEN-F6's `unlock_time = height + window`.
    pub unlock_window: BlockCount,
    /// Emission operands at `height`.
    pub emission: EmissionOperands,
    /// Economic parameters (`config/economics_params.json`'s record).
    pub params: &'a EconomicParams,
    /// Whom the coinbase pays.
    pub miner: &'a MinerKeys,
    /// The coinbase transaction secret `r`, wiped when the context drops.
    /// Randomness is the caller's: a template is deterministic in it, and
    /// a test can pin it.
    pub tx_key_secret: Zeroizing<[u8; 32]>,
    /// The `0x02` nonce field's bytes (a pool's extra-nonce slot).
    pub extra_nonce: [u8; COINBASE_NONCE_BYTES],
    /// The bodies to list, in block order. Each must carry a fee
    /// (`Ct::Fcmp`): a coinbase-shaped body cannot be listed.
    pub listed: &'a [Transaction],
}

impl fmt::Debug for TemplateContext<'_> {
    /// Every operand but the secret; the secret prints as `[redacted]` so a
    /// panic message or a log line never carries `r`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateContext")
            .field("height", &self.height)
            .field("previous", &self.previous)
            .field("curve_tree_root", &self.curve_tree_root)
            .field("attestation_root", &self.attestation_root)
            .field("major_version", &self.major_version)
            .field("minor_version", &self.minor_version)
            .field("now", &self.now)
            .field("median_timestamp", &self.median_timestamp)
            .field("unlock_window", &self.unlock_window)
            .field("emission", &self.emission)
            .field("params", &self.params)
            .field("miner", &self.miner)
            .field("tx_key_secret", &"[redacted]")
            .field("extra_nonce", &self.extra_nonce)
            .field("listed", &self.listed.len())
            .finish()
    }
}

/// A built template: the block (nonce zero) and the listed bodies it
/// hashes, plus the figures the coinbase was priced at, so a caller can
/// record them without re-deriving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    /// The candidate block, nonce `0`.
    pub block: Block,
    /// The listed bodies, in the order `block.transaction_hashes` names them.
    pub transactions: Vec<Transaction>,
    /// The block weight the reward was penalised at, coinbase included.
    pub block_weight: u64,
    /// The penalised gross emission (`paid_block_reward`) — what CEN-F13
    /// records as this block's generation.
    pub block_reward: AtomicUnits,
    /// The miner's leg of the emission split (CEN-F16).
    pub miner_emission: AtomicUnits,
    /// The listed fees, summed.
    pub total_fees: AtomicUnits,
    /// The miner's share of the fees after the burn (CEN-F17).
    pub miner_fee_income: AtomicUnits,
    /// The fees destroyed by the burn (CEN-F17's `actually_destroyed`) —
    /// what connect records as this block's `burned`.
    pub fees_burned: AtomicUnits,
}

/// Why a context yields no template. Every arm is a *caller* condition —
/// an operand that cannot be priced or a body that cannot be listed — not
/// a consensus verdict; the validator's refusals are the rules crate's.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// A listed body has no fee (`Ct::Null`): coinbase-shaped bodies are not
    /// listable.
    #[error("listed transaction {index} carries no fee (Ct::Null); only spends are listable")]
    ListedWithoutFee {
        /// Position in `listed`.
        index: usize,
    },
    /// The listed fees sum past `u64`.
    #[error("listed fees overflow u64")]
    FeeOverflow,
    /// `height + unlock_window` overflows: no coinbase satisfies CEN-F6 at
    /// this height (the rule's own sum overflows and refuses).
    #[error("unlock_time = {height} + {window} overflows u64 (CEN-F6 cannot hold)")]
    UnlockOverflow {
        /// The connecting height.
        height: u64,
        /// The maturity window.
        window: u64,
    },
    /// The emission cannot be priced at these operands.
    #[error("block reward cannot be priced: {0}")]
    Emission(#[from] EmissionError),
    /// `total_burned > already_generated_coins` — the caller's record is
    /// inconsistent.
    #[error("circulating supply cannot be derived: {0}")]
    Supply(#[from] SupplyInvariantViolation),
    /// `miner_emission + miner_fee_income` overflows.
    #[error("coinbase amount overflows u64")]
    AmountOverflow,
    /// The block weight (bodies plus coinbase) does not fit `u64`.
    #[error("block weight overflows u64")]
    WeightOverflow,
    /// Output construction refused the miner's keys.
    #[error("coinbase output construction failed: {0:?}")]
    Output(CryptoError),
    /// The assembled `extra` fails the coinbase grammar it was built for.
    #[error("coinbase extra fails the grammar: {0}")]
    Extra(#[from] CoinbaseBuildError),
    /// The coinbase's own weight did not settle within
    /// [`MAX_REPRICING_PASSES`]: the reward sits on a varint boundary in
    /// the penalty zone and the two weights trade places (crate docs). The
    /// C++ fails the same case at the same budget.
    #[error(
        "coinbase weight did not converge in {MAX_REPRICING_PASSES} passes \
         (last priced at {priced}, carries {carried})"
    )]
    WeightNotConverged {
        /// The block weight the last pass priced at.
        priced: u64,
        /// The block weight the last pass produced.
        carried: u64,
    },
    /// `max(now, median + 1)` is past CEN-C1's bound on the producer's own
    /// clock: the window's median runs more than FTL ahead of `now`. The
    /// validator would refuse the template; the builder refuses first.
    #[error(
        "timestamp {timestamp} is beyond the future limit of clock {now} (CEN-C1); \
         the window's median {median} runs ahead of this producer"
    )]
    TimestampBeyondFutureLimit {
        /// The timestamp the template would have claimed.
        timestamp: u64,
        /// The producer's clock.
        now: u64,
        /// The median that forced the claim.
        median: u64,
    },
    /// The window's median is `u64::MAX`: CEN-C2 admits only a timestamp
    /// strictly above it, and there is none. No template exists for this
    /// chain state; refused on that ground rather than emitted for the
    /// validator to refuse.
    #[error("the window's median {median} has no successor (CEN-C2); no timestamp is admissible")]
    MedianHasNoSuccessor {
        /// The median at the ceiling.
        median: u64,
    },
}

/// The re-pricing budget: the C++ `try_count != 10` (`blockchain.cpp:1830`).
/// Pinned to the same figure so the one reachable non-convergence — a
/// varint-boundary two-cycle — is refused by both producers, never
/// produced by one and declined by the other.
pub const MAX_REPRICING_PASSES: usize = 10;

/// Build the template for `cx`. See the crate documentation for what the
/// result satisfies by construction.
///
/// # Errors
///
/// A [`TemplateError`] when an operand cannot be priced or a body cannot be
/// listed; never on a consensus question — those are the validator's.
pub fn build(cx: &TemplateContext<'_>) -> Result<Template, TemplateError> {
    let total_fees = listed_fees(cx.listed)?;
    let tx_hashes: Vec<TxHash> = cx.listed.iter().map(Transaction::hash).collect();
    let bodies_weight = cx.listed.iter().try_fold(0u64, |acc, tx| {
        acc.checked_add(weight_of(tx)?)
            .ok_or(TemplateError::WeightOverflow)
    })?;

    // The reward is penalised at the block's weight, and the block's weight
    // includes the coinbase that carries the reward (CEN-F14b: connect
    // refuses a block priced at one weight and carrying another). Price at
    // the bodies' weight plus a coinbase carrying that price; while the
    // coinbase's own size moves (the amount's varint), re-price at the
    // weight the block actually has — heavier or lighter — until the two
    // meet or the budget runs out. The first pass prices without a
    // coinbase and is always short by one; the loop is what settles it.
    let (paid, block_weight) = {
        let mut priced_at = bodies_weight;
        let mut settled = None;
        for _ in 0..MAX_REPRICING_PASSES {
            let paid = price_and_pay(cx, priced_at, total_fees)?;
            let carried = bodies_weight
                .checked_add(weight_of(&paid.coinbase)?)
                .ok_or(TemplateError::WeightOverflow)?;
            if carried == priced_at {
                settled = Some((paid, carried));
                break;
            }
            priced_at = carried;
        }
        match settled {
            Some(settled) => settled,
            None => {
                // `priced_at` is the last carried weight; one more pricing
                // at it names the pair that would not meet.
                let paid = price_and_pay(cx, priced_at, total_fees)?;
                let carried = bodies_weight
                    .checked_add(weight_of(&paid.coinbase)?)
                    .ok_or(TemplateError::WeightOverflow)?;
                return Err(TemplateError::WeightNotConverged {
                    priced: priced_at,
                    carried,
                });
            }
        }
    };

    let block = Block {
        header: BlockHeader {
            major_version: cx.major_version,
            minor_version: cx.minor_version,
            timestamp: template_timestamp(cx.now, cx.median_timestamp)?,
            previous: cx.previous,
            nonce: 0,
            curve_tree_root: cx.curve_tree_root,
            attestation_root: cx.attestation_root,
        },
        miner_transaction: paid.coinbase,
        transaction_hashes: tx_hashes,
    };

    Ok(Template {
        block,
        transactions: cx.listed.to_vec(),
        block_weight,
        block_reward: paid.block_reward,
        miner_emission: paid.miner_emission,
        total_fees,
        miner_fee_income: paid.miner_fee_income,
        fees_burned: paid.fees_burned,
    })
}

/// The header timestamp a template claims: `max(now, median + 1)`, checked
/// against CEN-C1's bound on the producer's own clock.
///
/// CEN-C2 admits a timestamp strictly above the median of the window
/// (`DAA_LWMA1.md` §5.5); `median + 1` is the least such value. When `now`
/// is already above the median, `now` is the claim. CEN-C1 admits a
/// timestamp no further than FTL past the judging clock; the claim is
/// held to that with the rule's own predicate
/// ([`is_timestamp_below_ftl`]) against `now` — a producer whose window
/// median runs more than FTL ahead of its clock cannot build an admissible
/// block, and is told so rather than handed one the validator refuses. A
/// median at `u64::MAX` has no successor and is refused on that ground
/// before the FTL check.
///
/// `median` is `None` at genesis only — `mtp_median_at`'s contract, which
/// pads a short window with genesis rather than declining to answer.
///
/// # Errors
///
/// [`TemplateError::MedianHasNoSuccessor`] when the median is `u64::MAX`;
/// [`TemplateError::TimestampBeyondFutureLimit`] when the claim exceeds
/// `now + FTL`.
pub fn template_timestamp(now: Timestamp, median: Option<Timestamp>) -> Result<u64, TemplateError> {
    // No median — genesis: the claim is the clock, and a clock is within
    // FTL of itself.
    let Some(median) = median else {
        return Ok(now.to_raw());
    };
    // CEN-C2 wants strictly above the median; a median at the ceiling has
    // no successor and no template can satisfy the rule. Refused here on
    // its own ground — not left to the FTL check, which a clock at the
    // same ceiling would pass (review of #852).
    let least_above =
        median
            .to_raw()
            .checked_add(1)
            .ok_or(TemplateError::MedianHasNoSuccessor {
                median: median.to_raw(),
            })?;
    let claim = now.to_raw().max(least_above);
    if is_timestamp_below_ftl(Timestamp::from_raw(claim), now) {
        Ok(claim)
    } else {
        Err(TemplateError::TimestampBeyondFutureLimit {
            timestamp: claim,
            now: now.to_raw(),
            median: median.to_raw(),
        })
    }
}

/// The tx public key `r·G` for the coinbase secret `r` — the `0x01` field.
/// The reduced scalar lives in a [`Zeroizing`] for the one multiplication
/// (`curve25519-dalek`'s `zeroize` feature is what makes that wipe real).
#[must_use]
pub fn tx_pubkey(tx_key_secret: &[u8; 32]) -> [u8; 32] {
    let r = Zeroizing::new(Scalar::from_bytes_mod_order(*tx_key_secret));
    EdwardsPoint::mul_base(&r).compress().to_bytes()
}

/// A priced-and-paid coinbase with the figures it was priced from.
struct Paid {
    coinbase: Transaction,
    block_reward: AtomicUnits,
    miner_emission: AtomicUnits,
    miner_fee_income: AtomicUnits,
    fees_burned: AtomicUnits,
}

/// Price the reward at `block_weight` and pay it in a coinbase.
fn price_and_pay(
    cx: &TemplateContext<'_>,
    block_weight: u64,
    total_fees: AtomicUnits,
) -> Result<Paid, TemplateError> {
    let e = &cx.emission;
    // CEN-F13/F14/F15/F20: the penalised gross emission at this weight.
    let block_reward = paid_block_reward(
        e.median_weight,
        block_weight,
        e.already_generated_coins.to_raw(),
        e.tx_volume,
        cx.params,
    )?;
    // CEN-F16/F21: the miner's leg of the split.
    let split = compute_emission_split(
        block_reward,
        cx.height.to_raw(),
        e.emission_split_epoch.to_raw(),
    );
    // CEN-F17: the miner's share of the fees after the burn.
    let supply = CirculatingSupply::derive(e.already_generated_coins, e.total_burned)?;
    let burn = compute_fee_burn(
        total_fees.to_raw(),
        e.tx_volume,
        supply,
        e.frozen_segments,
        cx.params,
    );
    // CEN-F18: the coinbase pays exactly this.
    let amount = split
        .miner_emission
        .checked_add(burn.miner_fee_income)
        .ok_or(TemplateError::AmountOverflow)?;

    let coinbase = coinbase(cx, amount)?;
    Ok(Paid {
        coinbase,
        block_reward: AtomicUnits::from_raw(block_reward),
        miner_emission: AtomicUnits::from_raw(split.miner_emission),
        miner_fee_income: AtomicUnits::from_raw(burn.miner_fee_income),
        fees_burned: AtomicUnits::from_raw(burn.actually_destroyed),
    })
}

/// The coinbase paying `amount` to `cx.miner` in one output.
fn coinbase(cx: &TemplateContext<'_>, amount: u64) -> Result<Transaction, TemplateError> {
    let height = cx.height.to_raw();
    let window = cx.unlock_window.to_raw();
    // CEN-F6: `unlock_time = height + window`, and no coinbase satisfies it
    // where the sum overflows.
    let unlock_time = height
        .checked_add(window)
        .ok_or(TemplateError::UnlockOverflow { height, window })?;

    // CEN-F4: one output. CEN-F9/F10 hold by construction of the output
    // — a canonical key and a mask derived from the shared secret, which
    // is not `zeroCommit(amount)`.
    let od = construct_output(
        &cx.tx_key_secret,
        &cx.miner.x25519_pk,
        &cx.miner.ml_kem_ek,
        &cx.miner.spend_public,
        amount,
        0,
    )
    .map_err(TemplateError::Output)?;

    let mut kem_blob =
        Vec::with_capacity(od.kem_ciphertext_x25519.len() + od.kem_ciphertext_ml_kem.len());
    kem_blob.extend_from_slice(&od.kem_ciphertext_x25519);
    kem_blob.extend_from_slice(&od.kem_ciphertext_ml_kem);
    let leaf_blob = od.pqc_leaf.entry_bytes();

    // CEN-I20: the grammar's one constructor, which refuses what admission
    // would.
    let extra = tx_extra::build_coinbase_extra(
        tx_pubkey(&cx.tx_key_secret),
        &cx.extra_nonce,
        1,
        &kem_blob,
        &leaf_blob,
    )?;

    Ok(Transaction {
        prefix: TxPrefix {
            unlock_time,
            // CEN-F1/F5: one `txin_gen` claiming the connecting height.
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount,
                key: od.output_key,
                view_tag: od.view_tag_prefilter,
            }],
            extra,
        },
        // CEN-F3: `CTTypeNull`, one committed base per output.
        ct: Ct::Null(CtBase {
            enc_amounts: vec![od.enc_amount_wire().to_bytes()],
            enc_labels: vec![od.enc_label_wire().to_bytes()],
            commitments: vec![od.commitment],
        }),
    })
}

/// The listed fees, summed; a body without a fee is not listable.
fn listed_fees(listed: &[Transaction]) -> Result<AtomicUnits, TemplateError> {
    let mut total = AtomicUnits::ZERO;
    for (index, tx) in listed.iter().enumerate() {
        let fee = match &tx.ct {
            Ct::Fcmp { fee, .. } => *fee,
            Ct::Null(_) => return Err(TemplateError::ListedWithoutFee { index }),
        };
        total = total
            .checked_add(AtomicUnits::from_raw(fee))
            .ok_or(TemplateError::FeeOverflow)?;
    }
    Ok(total)
}

/// A body's weight as `u64`.
fn weight_of(tx: &Transaction) -> Result<u64, TemplateError> {
    u64::try_from(tx.weight()).map_err(|_| TemplateError::WeightOverflow)
}

#[cfg(test)]
mod tests;
