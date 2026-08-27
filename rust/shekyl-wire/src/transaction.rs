// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Shekyl transaction (genesis `version = 3`) — coinbase + FCMP++ spend.
//!
//! Layout (GENESIS_TX_WIRE_FORMAT.md §9.3-§9.9), in the **genesis dense tag scheme**
//! (§2.0; matches the renumbered C++ oracle — landed via PR #168):
//!
//! ```text
//! Transaction := V(version=3) TxPrefix Ct
//! TxPrefix    := V(unlock_time) vec(Input) vec(Output) V(extra_len) extra[extra_len]
//! Input(gen)       := 0x00 V(height)
//! Input(spend)     := 0x01 V(amount) vec(V key_offset) key_image[32]   # txin_to_key / fcmp
//! Input(serve_cr.) := 0x02 ...                                         # archival serve_credit
//! Input(bond_post) := 0x03 ...                                         # archival bond_post
//! Input(emission)  := 0x04 V(blob_len) canonical_bytes[blob_len]       # archival reward_emission (opaque)
//! Output      := V(amount) 0x00 key[32] view_tag(1)                  # tagged_key (sole genesis output)
//! Ct(Null)    := 0x00 enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]   # coinbase
//! Ct(Fcmp)    := 0x01 V(fee) referenceBlock[32]
//!                enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]
//!                PqcAuths(nvin)  Prunable
//! PqcAuth     := auth_version(1) scheme_id(1) flags(u16 LE) V(pk_len) pk V(sig_len) sig
//! Prunable    := V(nbp) nbp×BpPlus V(tree_depth) V(proof_len) fcmp_proof[] pseudoOuts[n_spend×32]
//! BpPlus      := A A1 B r1 s1 d1 (6×32) V(L_len) L[..×32] V(R_len) R[..×32]   # V restored from outPk
//! ```
//!
//! `pqc_auths` has **no length prefix** — its count is `nvin` (the C++
//! `PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), …)`). `pseudoOuts` also has no
//! length prefix, but its count is `n_spend` — the number of **`ToKey` (key-image)
//! inputs only**. A bond-post input occupies a `pqc_auths` slot but carries no
//! pseudo-out (its cleartext `bond_credit` rides the CT balance instead:
//! `Σ pseudoOuts = Σ out_masks + fee + bond_credit`). The reward-emission input is
//! the same shape on the other side of the ledger: a `pqc_auths` slot, no
//! pseudo-out, its cleartext `total_reward` entering the CT balance input-side
//! (`Σ pseudoOuts + total_reward·H = Σ out_masks + fee·H`,
//! `src/fcmp/ct_semantics.cpp` `verCtSemanticsEmission`). For a pure spend
//! `n_spend == nvin`, so the counts only diverge on bond-post / emission txs.
//! Source: `src/fcmp/ct_types.h` (`serialize_ctsig_base` / `serialize_ctsig_prunable`,
//! `BulletproofPlus`), `src/cryptonote_basic/cryptonote_basic.h` (`pqc_authentication`,
//! tx-level between base and prunable).

use std::io::{self, BufRead, Read, Write};

use shekyl_crypto_hash::keccak256;

use crate::bytes::{read_array, read_byte};
use crate::hash::hash_concat;
use crate::varint::{read_varint, write_varint};
use crate::READ_LEN_CAP;

/// Genesis transaction version (kept deliberately; `V4` = future lattice-only).
pub const TX_VERSION: u64 = 3;

// Genesis dense tag scheme (GENESIS_TX_WIRE_FORMAT.md §2.0 / §5 gate-(c)). Tags are
// numbered dense from 0x00; matches the renumbered C++ oracle VARIANT_TAGs and ct enum.
/// `txin_gen` tag — coinbase generation input.
pub const TAG_INPUT_GEN: u8 = 0x00;
/// `txin_to_key`/`txin_fcmp` tag — the FCMP++ spend input (the `key_offsets`-drop
/// reshape is a separate gate-(c) cut; the tag is dense here).
pub const TAG_INPUT_TO_KEY: u8 = 0x01;
/// `txout_to_tagged_key` tag — the sole genesis output type.
pub const TAG_OUTPUT_TAGGED_KEY: u8 = 0x00;
/// `Null` confidential-transaction type — the coinbase ct (carries a committed base).
pub const CT_TYPE_NULL: u8 = 0x00;
/// `FcmpPlusPlusPqc` confidential-transaction type — the spend ct.
pub const CT_TYPE_FCMP: u8 = 0x01;
/// `txin_archival_serve_credit_response` tag (gate-2, non-spending).
pub const TAG_INPUT_SERVE_CREDIT: u8 = 0x02;
/// `txin_archival_bond_post` tag (gate-4). JoinMarket (credit) and Unbond
/// (debit) are the wallet-constructible archival kinds; Rebond and
/// HoldingsUpdate have verify arms and no producer yet.
pub const TAG_INPUT_BOND_POST: u8 = 0x03;
/// `txin_archival_reward_emission` tag (C-1) — an opaque canonical blob whose
/// codec is owned by `shekyl-archival-retention::emission_wire`
/// (`VIN_TYPE_ARCHIVAL_REWARD_EMISSION`); mirrors the C++
/// `TXIN_ARCHIVAL_REWARD_EMISSION_WIRE_TAG` (`cryptonote_basic.h:296`). The blob's
/// **leading byte echoes this tag** — the transport guard the C++ deserializer
/// enforces (`cryptonote_basic.h:302-310`) and [`Input::read`] mirrors.
pub const TAG_INPUT_ARCHIVAL_REWARD_EMISSION: u8 = 0x04;

/// `post_kind` value for a JoinMarket archival bond post.
/// `bond_spend_pk` is present on the wire iff `post_kind == JOINMARKET` (§9.11).
pub const BOND_POST_KIND_JOINMARKET: u8 = 0;
/// `holdings.kind` for a compact shard-set (carries an explicit shard list).
pub const HOLDINGS_SHARD_SET_COMPACT: u8 = 0;
/// `holdings.kind` for the complete tree (carries no shard list).
pub const HOLDINGS_COMPLETE_TREE: u8 = 1;

/// Transport bound on the emission `canonical_bytes` blob
/// (`config::ARCHIVAL_EMISSION_VIN_MAX_BYTES`, `src/cryptonote_config.h:308`).
/// Deliberately the C++ transport cap verbatim (1 MiB > [`MAX_TX_SIZE`]): the wire
/// layer mirrors the oracle's accept/reject exactly, and the tx-size bound rejects
/// the oversized *transaction* independently.
pub const ARCHIVAL_EMISSION_VIN_MAX_BYTES: usize = 1024 * 1024;

/// Consensus bound: max shards in a compact holdings set (`bond_wire.rs`).
const MAX_HOLDINGS_SHARDS: usize = 4096;
/// Consensus bound: max branch scalars per path layer (`wire.rs`).
const MAX_BRANCH_SCALARS: usize = 256;
/// Consensus bound: max path layers per curve (`wire.rs`).
const MAX_PATH_LAYERS: usize = 64;

// §10 resource bounds (structural; the chain-context rules of §13 — double-spend,
// CT balance, referenceBlock window, per-arm pqc_auths semantics — are the
// consensus layer's job, not the wire serializer's).
/// Max key-image (fcmp) inputs per tx (`FCMP_MAX_INPUTS_PER_TX`).
pub const MAX_FCMP_INPUTS: usize = 8;
/// Max outputs per tx (`BULLETPROOF_PLUS_MAX_OUTPUTS`).
pub const MAX_OUTPUTS: usize = 16;
/// Max Bp+ `|L|` / `|R|` — `6 + log2(MAX_OUTPUTS)`. A well-formed aggregated Bp+
/// has `|L| == |R| == 6 + ceil(log2(n_padded))` with `n_padded ≤ MAX_OUTPUTS`, so
/// this is the largest length any valid proof carries; the C++ deserializer
/// rejects above it (`n_bulletproof_plus_max_amounts`, ct_types.cpp: `L_size <=
/// 6 + extra_bits`). The exact per-tx value is output-count-coupled and enforced
/// by [`Transaction::validate`].
pub const MAX_BP_LR_LEN: usize = 6 + MAX_OUTPUTS.ilog2() as usize;
// The C++ oracle guards the same derivation with "log2(max_outputs) is out of
// date" (`(1ULL << extra_bits) == max_outputs`); mirror it so a MAX_OUTPUTS bump
// that breaks the power-of-two assumption fails loudly here too.
const _: () = assert!(
    MAX_OUTPUTS.is_power_of_two(),
    "MAX_BP_LR_LEN derivation requires MAX_OUTPUTS to be a power of two"
);
/// Max `tx_extra` bytes for a non-coinbase tx (`MAX_TX_EXTRA_SIZE`).
pub const MAX_TX_EXTRA: usize = 24_576;
/// Max serialized transaction size (`CRYPTONOTE_MAX_TX_SIZE`) — the hard
/// parse/DoS cap. The **binding** relay/consensus bound for a single tx is
/// the (much tighter) [`TX_WEIGHT_LIMIT`].
pub const MAX_TX_SIZE: usize = 1_000_000;
/// Minimum block weight (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`,
/// `src/cryptonote_config.h`) — the full-reward zone every block gets
/// regardless of the dynamic median.
pub const MIN_BLOCK_WEIGHT: usize = 300_000;
/// Coinbase blob reserve (`CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE`)
/// subtracted from the per-tx weight limit.
pub const COINBASE_BLOB_RESERVED_SIZE: usize = 600;
/// Per-transaction weight limit (`get_transaction_weight_limit`,
/// `src/cryptonote_core/tx_verification_utils.cpp`): half the minimum block
/// weight minus the coinbase reserve. A compile-time constant on Shekyl
/// (v3-from-genesis: `HF_VERSION_PER_BYTE_FEE = 1`, so the `/ 2` arm always
/// applies — the daemon-rpc submit facts pin the same 149 400 value from the
/// C++ side). Tx weight is the serialized size plus the Bp+ verification
/// clawback ([`bp_plus_weight_clawback`]); the mempool refuses any tx whose
/// weight exceeds this, so builders must bound against it, never against
/// [`MAX_TX_SIZE`].
pub const TX_WEIGHT_LIMIT: usize = MIN_BLOCK_WEIGHT / 2 - COINBASE_BLOB_RESERVED_SIZE;
const _: () = assert!(
    TX_WEIGHT_LIMIT == 149_400,
    "TX_WEIGHT_LIMIT must equal the C++ get_transaction_weight_limit value \
     pinned by the daemon-rpc submit facts"
);
/// `unlock_time` block-height sentinel: `>=` this is the (rejected) timestamp form.
pub const UNLOCK_TIME_BLOCK_SENTINEL: u64 = 500_000_000;

// PQC blob bounds — consensus accept/reject parity with the C++ oracle
// (`src/cryptonote_config.h`). A hybrid public key / signature is `x25519 ‖ ML-DSA-65`;
// the tx-level `pqc_auths` blobs may aggregate up to `MAX_MULTISIG_PARTICIPANTS` of
// them. These are tighter than `READ_LEN_CAP` and are the values the daemon rejects
// above, so the parser must match.
// MSW-1: shekyl-wire keeps a minimal runtime dependency surface (crypto-hash
// only — crypto-pq is dev-only, by design), so these are retyped twins of the
// canonical `shekyl_crypto_pq::multisig` values rather than imports. They are
// pinned equal to the canonical source by the cross-crate test in
// `tests/pqc_consts_match_crypto_pq.rs` — the Rust↔Rust analog of the C++↔Rust
// cross-language KAT: the only mechanism that catches the two sides drifting.
/// Single hybrid public-key length — twin of `SINGLE_KEY_CANONICAL_LEN`. Used
/// for the exact bond-post `hybrid_public_key` / `bond_spend_pk` length checks.
pub const PQC_HYBRID_SINGLE_KEY_LEN: usize = 1996;
/// Single hybrid signature length — twin of `SINGLE_SIG_CANONICAL_LEN`.
pub const PQC_HYBRID_SINGLE_SIG_LEN: usize = 3385;

/// Transport bound on a serve-credit vin's opaque `canonical_bytes` (kept
/// half, `RF-D1`): `tag(1) + p_id(32) + shard varint(≤10) + epoch varint(≤10)
/// + Ed25519(64)`. The Rust codec (`shekyl-archival-retention::wire`) is the
/// only parser of the interior; this is the C++-twin allocation ceiling
/// (`ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES` in `cryptonote_config.h`).
pub const ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES: usize = 1 + 32 + 10 + 10 + 64;

/// Transport bound on one pruned pass record (`RF-D1`): two branch-layer
/// kinds of at most `MAX_PATH_LAYERS` layers × `MAX_BRANCH_SCALARS` scalars
/// (each layer carries a varint width, each kind a varint count), plus the
/// ML-DSA-65 leg. A DoS ceiling for the opaque blob, not a layout claim — the
/// interior is the retention codec's.
pub const ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES: usize =
    2 * (10 + MAX_PATH_LAYERS * (10 + MAX_BRANCH_SCALARS * 32)) + 3309;

// Twins of `cryptonote_config.h`'s `ARCHIVAL_SERVE_CREDIT_{VIN,PRUNED}_MAX_BYTES`,
// pinned to the same literals on both sides: a change to either formula fails
// one side's assertion until the other is moved with it.
const _: () = assert!(ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES == 117);
const _: () = assert!(ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES == 1_053_185);
/// Max tx-level `pqc_auths` public-key / signature blob — the DoS ceilings.
/// Round, generous, DECOUPLED from MAX (correctness is the exact-length
/// container parse in crypto-pq / verify_multisig, not these bounds). Twins of
/// crypto-pq's `PQC_MAX_*_BLOB`. The old `2 + MAX·LEN` fossil formula is
/// deleted — it rejected a legal 5-of-5 in the deserializer (F-1's exact site).
pub const PQC_MAX_PUBLIC_KEY_BLOB: usize = 16384;
/// See `PQC_MAX_PUBLIC_KEY_BLOB`.
pub const PQC_MAX_SIGNATURE_BLOB: usize = 32768;

/// The Bp+ weight clawback as a pure function of the padded output count — the C++
/// `get_transaction_weight_clawback` (`cryptonote_format_utils.cpp:93`); `0` for ≤ 2
/// padded outputs. This is the single source of the formula: [`Transaction::weight`]
/// applies it to the count derived from the proof, and the wallet fee predictor
/// (`shekyl-engine-core`) applies it to the count derived a-priori from `n_out`, so the
/// two can never drift. Callers pass an already-bounded `n_padded_outputs`
/// (≤ [`MAX_OUTPUTS`] for any valid tx); `saturating_mul` keeps it overflow-safe.
#[must_use]
pub fn bp_plus_weight_clawback(n_padded_outputs: usize) -> usize {
    if n_padded_outputs <= 2 {
        return 0;
    }
    // bp_base = (32 * (6 + 7*2)) / 2 = 320.
    const BP_BASE: usize = (32 * (6 + 7 * 2)) / 2;
    // nlr = smallest value with `1 << nlr >= n_padded`, then `+ 6` (the proof's |L|).
    let mut nlr = 0u32;
    while (1usize << nlr) < n_padded_outputs {
        nlr += 1;
    }
    let bp_size = 32 * (6 + 2 * (nlr as usize + 6));
    // C++ asserts `bp_base * n_padded >= bp_size`; clamp to 0 rather than panic on a
    // malformed proof — consensus weight must not overflow on adversarial input.
    let gross = BP_BASE.saturating_mul(n_padded_outputs);
    if gross < bp_size {
        return 0;
    }
    (gross - bp_size) * 4 / 5
}

/// Read a varint-length-prefixed opaque byte blob, capped against `READ_LEN_CAP`.
fn read_len_prefixed<R: Read>(r: &mut R, what: &str) -> io::Result<Vec<u8>> {
    read_len_prefixed_bounded(r, what, READ_LEN_CAP)
}

/// Read a varint-length-prefixed opaque byte blob, rejecting (before allocating) any
/// declared length above `max`. Use a consensus-specific `max` for fields the C++
/// oracle bounds tighter than `READ_LEN_CAP` — e.g. the PQC key/sig blobs.
fn read_len_prefixed_bounded<R: Read>(r: &mut R, what: &str, max: usize) -> io::Result<Vec<u8>> {
    let len: usize = read_varint(r)?;
    if len > max {
        return Err(io::Error::other(format!(
            "shekyl-wire: {what} length {len} exceeds cap {max}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a length-prefixed blob whose declared length must equal `expected` —
/// for fixed-size canonical encodings (hybrid PQC keys) where a shorter value
/// is malformed, not a smaller valid one. Rejects before allocating.
fn read_len_prefixed_exact<R: Read>(r: &mut R, what: &str, expected: usize) -> io::Result<Vec<u8>> {
    let len: usize = read_varint(r)?;
    if len != expected {
        return Err(io::Error::other(format!(
            "shekyl-wire: {what} length {len} != canonical {expected}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read `count` fixed 32-byte points (no per-element length prefix).
///
/// The speculative pre-allocation is **clamped**: `count` reaches here validated only
/// loosely on some paths (pseudoOuts is sized by the input count, which the prefix
/// parser caps at `READ_LEN_CAP`), so reserving `count` up front would be a
/// hostile-input pre-alloc DoS (~32 MiB for a declared 1M). Every legitimate point vector is
/// `<= MAX_BRANCH_SCALARS`, so the clamp right-sizes real inputs while bounding the
/// reserve; the loop still pushes from a finite reader, so an oversized `count` fails
/// on the missing bytes rather than on allocation.
fn read_points<R: Read>(r: &mut R, count: usize) -> io::Result<Vec<[u8; 32]>> {
    let mut v = Vec::with_capacity(count.min(MAX_BRANCH_SCALARS));
    for _ in 0..count {
        v.push(read_array::<32, _>(r)?);
    }
    Ok(v)
}

/// A `Write` sink that discards its input and only tallies the byte count — lets
/// [`Transaction::serialized_len`] measure the wire size without materializing the
/// blob (the `MAX_TX_SIZE` check would otherwise allocate up to ~1 MiB per call).
#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The branch-layer codec that used to live here moved with the opening into
// the pruned record's opaque blob; `shekyl-archival-retention::wire` is its
// only home now (rule 15). `MAX_PATH_LAYERS` / `MAX_BRANCH_SCALARS` survive
// solely to size `ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES`.

/// A transaction input.
///
/// Genesis arms modelled here: the coinbase `gen` input, the FCMP++ spend
/// (`txin_to_key`), and the archival arms (`serve_credit`, `bond_post`,
/// `reward_emission`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
    /// Coinbase generation input: the block height.
    Gen(u64),
    /// FCMP++ spend input (`txin_to_key`, dense tag `0x01`). At genesis `amount == 0`
    /// and `key_offsets` is empty (membership is via the curve tree, not a ring), but
    /// the wire still serializes both — round-tripped faithfully (the §5 item-3
    /// `txin_fcmp` reshape that drops them is a deferred gate-(c) cut).
    ToKey {
        /// Cleartext amount (`0` for FCMP++).
        amount: u64,
        /// Ring offsets (empty for FCMP++).
        key_offsets: Vec<u64>,
        /// Key image (linking tag / nullifier).
        key_image: [u8; 32],
    },
    /// Archival serve-credit response (dense tag `0x02`) — the KEPT half of a
    /// pass record as an opaque blob, `RF-D1` / rule 40. `canonical_bytes` is
    /// the complete retention-codec encoding, leading tag byte included, the
    /// same shape as [`Input::ArchivalRewardEmission`].
    ServeCredit {
        /// Complete Rust canonical encoding of the kept half (tag included).
        canonical_bytes: Vec<u8>,
    },
    /// Archival bond-post (dense tag `0x03`, gate-4). JoinMarket and Unbond
    /// are wallet-constructible; the kind byte is `BondPostKind`.
    BondPost(Box<BondPost>),
    /// Archival reward-emission (dense tag `0x04`, C-1) — the complete Rust
    /// canonical encoding as an **opaque blob**, leading wire tag `0x04` included.
    /// This crate is transport only, matching the C++ posture
    /// (`cryptonote_basic.h:283-311`): `shekyl-archival-retention::emission_wire`
    /// owns the codec, the parse, and every structural bound; the transport guard
    /// here is the allocation bound + the wire-tag echo, and a blob passing it can
    /// still be garbage — the emission parser is the validator. Like a bond-post,
    /// this input occupies a `pqc_auths` slot but no pseudo-out slot (module
    /// header; C++ `count_spend_inputs`, `cryptonote_basic.h:322`).
    ArchivalRewardEmission {
        /// The complete `emission_wire.rs` canonical encoding (leading `0x04` included).
        canonical_bytes: Vec<u8>,
    },
}

/// The emission-blob transport guard (`cryptonote_basic.h:302-310`): length in
/// `2..=`[`ARCHIVAL_EMISSION_VIN_MAX_BYTES`], leading byte echoing the wire tag.
/// One source for the two sites that must agree — [`Input::read`] (accept/reject
/// parity with the C++ deserializer) and `validate_context_free_pruned`'s per-arm
/// pass (the in-memory gate that keeps a hand-built tx round-trippable).
fn check_emission_blob(canonical_bytes: &[u8]) -> io::Result<()> {
    if canonical_bytes.len() < 2 || canonical_bytes.len() > ARCHIVAL_EMISSION_VIN_MAX_BYTES {
        return Err(io::Error::other(format!(
            "shekyl-wire: emission canonical_bytes length {} outside 2..={ARCHIVAL_EMISSION_VIN_MAX_BYTES}",
            canonical_bytes.len()
        )));
    }
    if canonical_bytes[0] != TAG_INPUT_ARCHIVAL_REWARD_EMISSION {
        return Err(io::Error::other(format!(
            "shekyl-wire: emission canonical_bytes leading byte {:#04x} != wire tag \
             {TAG_INPUT_ARCHIVAL_REWARD_EMISSION:#04x}",
            canonical_bytes[0]
        )));
    }
    Ok(())
}

impl Input {
    /// Key-imaged spend (`txin_to_key`). Twin of C++ `txin_to_key`.
    #[must_use]
    pub fn is_spend(&self) -> bool {
        matches!(self, Input::ToKey { .. })
    }

    /// Serve-credit vin (kept half of a pass record). Twin of C++
    /// `txin_archival_serve_credit_response`.
    #[must_use]
    pub fn is_serve_credit(&self) -> bool {
        matches!(self, Input::ServeCredit { .. })
    }

    /// Write the input.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Input::Gen(height) => {
                w.write_all(&[TAG_INPUT_GEN])?;
                write_varint(*height, w)
            }
            Input::ToKey {
                amount,
                key_offsets,
                key_image,
            } => {
                w.write_all(&[TAG_INPUT_TO_KEY])?;
                write_varint(*amount, w)?;
                write_varint(key_offsets.len(), w)?;
                for offset in key_offsets {
                    write_varint(*offset, w)?;
                }
                w.write_all(key_image)
            }
            Input::ServeCredit { canonical_bytes } => {
                // C++ `FIELD(canonical_bytes)` encoding, as for the emission arm.
                w.write_all(&[TAG_INPUT_SERVE_CREDIT])?;
                write_varint(canonical_bytes.len(), w)?;
                w.write_all(canonical_bytes)
            }
            Input::BondPost(bp) => {
                w.write_all(&[TAG_INPUT_BOND_POST])?;
                bp.write(w)
            }
            Input::ArchivalRewardEmission { canonical_bytes } => {
                // Faithful write (bounds are `validate`'s job, per the
                // `Transaction::serialize` posture): varint length + blob, the
                // C++ `FIELD(canonical_bytes)` encoding.
                w.write_all(&[TAG_INPUT_ARCHIVAL_REWARD_EMISSION])?;
                write_varint(canonical_bytes.len(), w)?;
                w.write_all(canonical_bytes)
            }
        }
    }

    /// Read an input.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Input> {
        let tag = read_byte(r)?;
        match tag {
            TAG_INPUT_GEN => Ok(Input::Gen(read_varint(r)?)),
            TAG_INPUT_TO_KEY => {
                let amount = read_varint(r)?;
                let n_offsets: usize = read_varint(r)?;
                if n_offsets > READ_LEN_CAP {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: key_offsets count {n_offsets} exceeds parse cap {READ_LEN_CAP}"
                    )));
                }
                let mut key_offsets = Vec::new();
                for _ in 0..n_offsets {
                    key_offsets.push(read_varint(r)?);
                }
                Ok(Input::ToKey {
                    amount,
                    key_offsets,
                    key_image: read_array(r)?,
                })
            }
            TAG_INPUT_SERVE_CREDIT => {
                let canonical_bytes = read_len_prefixed_bounded(
                    r,
                    "serve_credit canonical_bytes",
                    ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES,
                )?;
                check_serve_credit_blob(&canonical_bytes)?;
                Ok(Input::ServeCredit { canonical_bytes })
            }
            TAG_INPUT_BOND_POST => Ok(Input::BondPost(Box::new(BondPost::read(r)?))),
            TAG_INPUT_ARCHIVAL_REWARD_EMISSION => {
                let canonical_bytes = read_len_prefixed_bounded(
                    r,
                    "emission canonical_bytes",
                    ARCHIVAL_EMISSION_VIN_MAX_BYTES,
                )?;
                check_emission_blob(&canonical_bytes)?;
                Ok(Input::ArchivalRewardEmission { canonical_bytes })
            }
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported input tag {other:#04x}"
            ))),
        }
    }
}

/// Holdings descriptor for a bond post (`bond_wire.rs` `HoldingsDescriptor`).
///
/// The `kind` byte and the shard-id list are coupled on the wire — only the compact
/// form carries a list — so they are one enum, not a `{ kind, shard_ids }` pair. That
/// makes the `kind`/list mismatch the wire cannot represent (a complete-tree holding
/// with a stray shard list, which the old `write` silently dropped) unconstructable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Holdings {
    /// Compact shard set (`kind` `0x00`) — carries an explicit shard-id list.
    ShardSetCompact(Vec<u64>),
    /// Complete tree (`kind` `0x01`) — no shard list on the wire.
    CompleteTree,
}

impl Holdings {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Holdings::ShardSetCompact(shard_ids) => {
                w.write_all(&[HOLDINGS_SHARD_SET_COMPACT])?;
                write_varint(shard_ids.len(), w)?;
                for shard in shard_ids {
                    write_varint(*shard, w)?;
                }
            }
            Holdings::CompleteTree => w.write_all(&[HOLDINGS_COMPLETE_TREE])?,
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<Holdings> {
        match read_byte(r)? {
            HOLDINGS_SHARD_SET_COMPACT => {
                let count: usize = read_varint(r)?;
                if count > MAX_HOLDINGS_SHARDS {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: holdings shard count {count} exceeds {MAX_HOLDINGS_SHARDS}"
                    )));
                }
                let mut shard_ids = Vec::new();
                for _ in 0..count {
                    shard_ids.push(read_varint(r)?);
                }
                // Duplicate-free: holdings are "a set on the wire". The
                // retention decoder (bond_wire::ShardSet) rejects a repeated id;
                // this oracle enforces the same rule independently, so the two
                // decoders cannot diverge on validity (a wire the retention
                // verify rejects must not decode here as accepted). Sorted
                // scratch copy — the accepted wire preserves insertion order.
                let mut sorted = shard_ids.clone();
                sorted.sort_unstable();
                if let Some(pair) = sorted.windows(2).find(|w| w[0] == w[1]) {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: holdings shard id {} appears more than once",
                        pair[0]
                    )));
                }
                Ok(Holdings::ShardSetCompact(shard_ids))
            }
            HOLDINGS_COMPLETE_TREE => Ok(Holdings::CompleteTree),
            other => Err(io::Error::other(format!(
                "shekyl-wire: invalid holdings kind {other}"
            ))),
        }
    }
}

/// Shape check on a serve-credit vin's opaque `canonical_bytes` — the kept half
/// of a pass record (`RF-D1`). Mirrors [`check_emission_blob`]: length ceiling
/// and the leading tag byte, nothing about the interior. The interior has ONE
/// parser, `shekyl-archival-retention::wire`; C++ indexes the vin through the
/// `shekyl_archival_serve_credit_extract` FFI (tagged blob, whole) and reads
/// nothing else.
///
/// This is why the typed `ServeCredit` struct this crate briefly carried is
/// gone: it was a second codec of one layout, and two codecs of one layout
/// drift (rule 15). `shekyl-wire` models the C++ *transport* of the blob;
/// the bytes inside are someone else's to define.
fn check_serve_credit_blob(canonical_bytes: &[u8]) -> io::Result<()> {
    if canonical_bytes.len() < 2 || canonical_bytes.len() > ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES {
        return Err(io::Error::other(format!(
            "shekyl-wire: serve_credit canonical_bytes length {} outside 2..={ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES}",
            canonical_bytes.len()
        )));
    }
    if canonical_bytes[0] != TAG_INPUT_SERVE_CREDIT {
        return Err(io::Error::other(format!(
            "shekyl-wire: serve_credit canonical_bytes leading byte {:#04x} != wire tag \
             {TAG_INPUT_SERVE_CREDIT:#04x}",
            canonical_bytes[0]
        )));
    }
    Ok(())
}

/// Shape check on one pruned pass record (`RF-D1`), the opaque per-vin blob in
/// the prunable region. Bounded, non-empty; interior is the retention codec's.
fn check_serve_credit_pruned_blob(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES {
        return Err(io::Error::other(format!(
            "shekyl-wire: serve_credit pruned record length {} outside 1..={ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES}",
            bytes.len()
        )));
    }
    Ok(())
}

/// The `post_kind` discriminant of a [`BondPost`], with its coupled payload.
///
/// Only the JoinMarket post carries `bond_spend_pk` on the wire (§9.11), so the
/// coupling lives in the type: `JoinMarket` *always* has the key and `Other` *never*
/// does. That makes both silent round-trip hazards of the old `{ post_kind: u8,
/// bond_spend_pk: Option<_> }` shape — a non-JoinMarket post whose `Some` key `write`
/// dropped, and a JoinMarket post whose missing key `write` errored on — impossible
/// to construct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BondPostKind {
    /// JoinMarket post (`post_kind` `0x00`) — carries `bond_spend_pk`, the
    /// GF-1 debit authorizer (§9.11). The credit path; Unbond is `Other(2)`.
    JoinMarket {
        /// The GF-1 debit authorizer hybrid public key.
        bond_spend_pk: Vec<u8>,
    },
    /// Any non-JoinMarket post kind — no `bond_spend_pk` on the wire. The byte must
    /// not be the JoinMarket tag (`Other` is non-JoinMarket by construction; `write`
    /// rejects `Other(JOINMARKET)`).
    Other(u8),
}

/// Archival bond-post payload (dense tag `0x03`, gate-4 §3.4.1).
/// The `post_kind`/`bond_spend_pk` coupling (§9.11) is carried in [`BondPostKind`]:
/// JoinMarket carries the key; every other archival kind is `Other(tag)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BondPost {
    /// `P`'s canonical hybrid public key.
    pub hybrid_public_key: Vec<u8>,
    /// `P`'s canonical id.
    pub p_canonical_id: [u8; 32],
    /// The post kind and its coupled `bond_spend_pk` (§9.11).
    pub kind: BondPostKind,
    /// Holdings served.
    pub holdings: Holdings,
    /// Public bonded total (== `bond_credit` == `bond_floor` for JoinMarket).
    pub bonded_total_atomic: u64,
    /// Public bond credit.
    pub bond_credit: u64,
    /// Public bond debit (`0` for JoinMarket).
    pub bond_debit: u64,
}

impl BondPost {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        w.write_all(&self.p_canonical_id)?;
        match &self.kind {
            BondPostKind::JoinMarket { bond_spend_pk } => {
                w.write_all(&[BOND_POST_KIND_JOINMARKET])?;
                write_varint(bond_spend_pk.len(), w)?;
                w.write_all(bond_spend_pk)?;
            }
            BondPostKind::Other(post_kind) => {
                // `Other` is non-JoinMarket by contract; reusing the JoinMarket tag
                // would make `write` emit a `bond_spend_pk`-less blob that `read`
                // would then try to parse as JoinMarket (consuming the holdings bytes
                // as the key). Reject the misconstruction rather than emit it.
                if *post_kind == BOND_POST_KIND_JOINMARKET {
                    return Err(io::Error::other(
                        "shekyl-wire: BondPostKind::Other must not use the JoinMarket tag \
                         (use BondPostKind::JoinMarket)",
                    ));
                }
                w.write_all(&[*post_kind])?;
            }
        }
        self.holdings.write(w)?;
        write_varint(self.bonded_total_atomic, w)?;
        write_varint(self.bond_credit, w)?;
        write_varint(self.bond_debit, w)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<BondPost> {
        let hybrid_public_key =
            read_len_prefixed_exact(r, "bond_post hybrid_public_key", PQC_HYBRID_SINGLE_KEY_LEN)?;
        let p_canonical_id = read_array(r)?;
        let post_kind = read_byte(r)?;
        // `read` never yields `Other(JOINMARKET)`: the JoinMarket tag always takes the
        // first arm, so the `write` guard above only fires on a hand-built value.
        let kind = if post_kind == BOND_POST_KIND_JOINMARKET {
            BondPostKind::JoinMarket {
                bond_spend_pk: read_len_prefixed_exact(
                    r,
                    "bond_spend_pk",
                    PQC_HYBRID_SINGLE_KEY_LEN,
                )?,
            }
        } else {
            BondPostKind::Other(post_kind)
        };
        let holdings = Holdings::read(r)?;
        Ok(BondPost {
            hybrid_public_key,
            p_canonical_id,
            kind,
            holdings,
            bonded_total_atomic: read_varint(r)?,
            bond_credit: read_varint(r)?,
            bond_debit: read_varint(r)?,
        })
    }

    /// In-memory consensus-bound check — mirrors the per-field `read` caps and the
    /// `write` JoinMarket-tag guard, so a hand-built arm passes
    /// [`Transaction::validate`] iff it would serialize-and-re-parse intact.
    fn validate(&self) -> io::Result<()> {
        if self.hybrid_public_key.len() != PQC_HYBRID_SINGLE_KEY_LEN {
            return Err(io::Error::other(format!(
                "shekyl-wire: bond_post hybrid_public_key {} != canonical {PQC_HYBRID_SINGLE_KEY_LEN}",
                self.hybrid_public_key.len()
            )));
        }
        match &self.kind {
            BondPostKind::JoinMarket { bond_spend_pk } => {
                if bond_spend_pk.len() != PQC_HYBRID_SINGLE_KEY_LEN {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: bond_post bond_spend_pk {} != canonical {PQC_HYBRID_SINGLE_KEY_LEN}",
                        bond_spend_pk.len()
                    )));
                }
            }
            // `Other` must not reuse the JoinMarket tag — `write` would emit a
            // bond_spend_pk-less blob that re-parses as JoinMarket (a mis-parse).
            BondPostKind::Other(post_kind) => {
                if *post_kind == BOND_POST_KIND_JOINMARKET {
                    return Err(io::Error::other(
                        "shekyl-wire: BondPostKind::Other must not use the JoinMarket tag",
                    ));
                }
            }
        }
        if let Holdings::ShardSetCompact(shard_ids) = &self.holdings {
            if shard_ids.len() > MAX_HOLDINGS_SHARDS {
                return Err(io::Error::other(format!(
                    "shekyl-wire: bond_post holdings shard count {} exceeds {MAX_HOLDINGS_SHARDS}",
                    shard_ids.len()
                )));
            }
        }
        Ok(())
    }
}

/// A transaction output (`tagged_key`).
///
/// `view_tag` is mandatory — `tagged_key` is the sole genesis output type
/// (GENESIS_TX_WIRE_FORMAT.md §2.2), so a view-tag-less output is unrepresentable
/// (no `Option`). `amount` is cleartext for the coinbase output and `0` for a
/// confidential spend output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
    /// Cleartext amount for the coinbase output; `0` for confidential outputs.
    pub amount: u64,
    /// The one-time output key.
    pub key: [u8; 32],
    /// Scan fast-reject prefilter byte.
    pub view_tag: u8,
}

impl Output {
    /// Write the output.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.amount, w)?;
        w.write_all(&[TAG_OUTPUT_TAGGED_KEY])?;
        w.write_all(&self.key)?;
        w.write_all(&[self.view_tag])
    }

    /// Read an output.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Output> {
        let amount = read_varint(r)?;
        let tag = read_byte(r)?;
        match tag {
            TAG_OUTPUT_TAGGED_KEY => Ok(Output {
                amount,
                key: read_array(r)?,
                view_tag: read_byte(r)?,
            }),
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported output tag {other:#04x} (only tagged_key)"
            ))),
        }
    }
}

/// The committed confidential-transaction base arrays, sized by output count.
///
/// Present for **both** the coinbase `Null` type and the `Fcmp` spend — the C++
/// `serialize_ctsig_base` writes `enc_amounts` / `enc_labels` / `outPk` for both
/// so every output gets a tree-leaf commitment (ct_types.h:209-280).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CtBase {
    /// Per-output encrypted amounts (8-byte value + 1-byte tag).
    pub enc_amounts: Vec<[u8; 9]>,
    /// Per-output encrypted labels (fixed-size, real-or-zero, never elided; §2.3).
    pub enc_labels: Vec<[u8; 9]>,
    /// Per-output commitments.
    pub commitments: Vec<[u8; 32]>,
}

impl CtBase {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for amount in &self.enc_amounts {
            w.write_all(amount)?;
        }
        for label in &self.enc_labels {
            w.write_all(label)?;
        }
        for commitment in &self.commitments {
            w.write_all(commitment)?;
        }
        Ok(())
    }

    fn read<R: Read>(outputs: usize, r: &mut R) -> io::Result<CtBase> {
        let mut enc_amounts = Vec::new();
        let mut enc_labels = Vec::new();
        for _ in 0..outputs {
            enc_amounts.push(read_array::<9, _>(r)?);
        }
        for _ in 0..outputs {
            enc_labels.push(read_array::<9, _>(r)?);
        }
        Ok(CtBase {
            enc_amounts,
            enc_labels,
            commitments: read_points(r, outputs)?,
        })
    }
}

/// Per-input PQC authentication (`cryptonote_basic.h` `pqc_authentication`),
/// serialized at **tx level** between the ct base and the prunable section.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PqcAuth {
    /// Authentication version (consensus requires `1`).
    pub auth_version: u8,
    /// Scheme id (`1` single, `2` multisig).
    pub scheme_id: u8,
    /// Flags (consensus requires `0`; unknown bits rejected).
    pub flags: u16,
    /// Canonical `HybridPublicKey` blob.
    pub hybrid_public_key: Vec<u8>,
    /// Canonical `HybridSignature` blob.
    pub hybrid_signature: Vec<u8>,
}

impl PqcAuth {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&[self.auth_version, self.scheme_id])?;
        w.write_all(&self.flags.to_le_bytes())?;
        write_varint(self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        write_varint(self.hybrid_signature.len(), w)?;
        w.write_all(&self.hybrid_signature)
    }

    /// The PQC **header** — `auth_version ‖ scheme_id ‖ flags(u16 LE) ‖ varint(pk_len) ‖
    /// hybrid_public_key`, with **no signature bytes**. This is the `pqc_header(i)`
    /// component of the per-input PQC signing preimage
    /// (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.5 / C++ `tx_pqc_verify.cpp:109-124`): a
    /// signature signs over its own header, so the header must exclude it. Identical to
    /// [`Self::write`] up to and including the public key.
    fn header_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&[self.auth_version, self.scheme_id])?;
        w.write_all(&self.flags.to_le_bytes())?;
        write_varint(self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<PqcAuth> {
        let auth_version = read_byte(r)?;
        let scheme_id = read_byte(r)?;
        let flags = u16::from_le_bytes(read_array::<2, _>(r)?);
        let hybrid_public_key =
            read_len_prefixed_bounded(r, "pqc hybrid_public_key", PQC_MAX_PUBLIC_KEY_BLOB)?;
        let hybrid_signature =
            read_len_prefixed_bounded(r, "pqc hybrid_signature", PQC_MAX_SIGNATURE_BLOB)?;
        Ok(PqcAuth {
            auth_version,
            scheme_id,
            flags,
            hybrid_public_key,
            hybrid_signature,
        })
    }
}

/// An aggregated Bulletproof+ (`ct_types.h` `BulletproofPlus`). `V` is not
/// serialized (restored from `outPk`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BpPlus {
    /// `A`.
    pub a: [u8; 32],
    /// `A1`.
    pub a1: [u8; 32],
    /// `B`.
    pub b: [u8; 32],
    /// `r1`.
    pub r1: [u8; 32],
    /// `s1`.
    pub s1: [u8; 32],
    /// `d1`.
    pub d1: [u8; 32],
    /// `L` vector.
    pub l: Vec<[u8; 32]>,
    /// `R` vector.
    pub r: Vec<[u8; 32]>,
}

impl BpPlus {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.a)?;
        w.write_all(&self.a1)?;
        w.write_all(&self.b)?;
        w.write_all(&self.r1)?;
        w.write_all(&self.s1)?;
        w.write_all(&self.d1)?;
        write_varint(self.l.len(), w)?;
        for point in &self.l {
            w.write_all(point)?;
        }
        write_varint(self.r.len(), w)?;
        for point in &self.r {
            w.write_all(point)?;
        }
        Ok(())
    }

    /// Parse a single Bp+ from a complete blob, requiring exact consumption. The
    /// tx-builder uses this to map a `shekyl_oxide` `Bulletproof` — which serializes to
    /// the identical byte layout (`a‖a1‖b‖r1‖s1‖d1‖vec(L)‖vec(R)`) — into the wire
    /// `BpPlus` during the spend-encode migration; the format identity is pinned by a
    /// round-trip test in shekyl-tx-builder.
    pub fn from_bytes(blob: &[u8]) -> io::Result<BpPlus> {
        let mut cursor: &[u8] = blob;
        let bp = Self::read(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::other(
                "shekyl-wire: trailing bytes after Bp+ blob",
            ));
        }
        Ok(bp)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<BpPlus> {
        let a = read_array(r)?;
        let a1 = read_array(r)?;
        let b = read_array(r)?;
        let r1 = read_array(r)?;
        let s1 = read_array(r)?;
        let d1 = read_array(r)?;
        // Parse-parity with the C++ deserializer: `serialize_ctsig_prunable`
        // (ct_types.h:338) fails deserialization unless every proof has
        // `6 <= |L| == |R| <= 6 + log2(BULLETPROOF_PLUS_MAX_OUTPUTS)`
        // (`n_bulletproof_plus_max_amounts` returns 0 otherwise). The remaining
        // output-count coupling — `|L| == 6 + ceil(log2(next_pow2(n_out)))` —
        // needs the full tx and lives in [`Transaction::validate`].
        let l_len: usize = read_varint(r)?;
        if !(6..=MAX_BP_LR_LEN).contains(&l_len) {
            return Err(io::Error::other(format!(
                "shekyl-wire: Bp+ |L| {l_len} outside consensus range 6..={MAX_BP_LR_LEN}"
            )));
        }
        let l = read_points(r, l_len)?;
        let r_len: usize = read_varint(r)?;
        if r_len != l_len {
            return Err(io::Error::other(format!(
                "shekyl-wire: Bp+ |R| {r_len} != |L| {l_len}"
            )));
        }
        let r_points = read_points(r, r_len)?;
        Ok(BpPlus {
            a,
            a1,
            b,
            r1,
            s1,
            d1,
            l,
            r: r_points,
        })
    }
}

/// FCMP++ prunable proof data (`ct_types.h` `serialize_ctsig_prunable`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Prunable {
    /// Bulletproof+ proofs (genesis: exactly one — `nbp == 1`).
    pub bulletproofs: Vec<BpPlus>,
    /// Curve-tree depth the FCMP++ proof is relative to.
    pub tree_depth: u64,
    /// Opaque FCMP++ membership+SAL proof bytes (interior frozen by reference, §6 Q6).
    pub fcmp_proof: Vec<u8>,
    /// Re-blinded pseudo-out commitments, one per **`ToKey` (spend) input**. A
    /// bond-post input carries no pseudo-out — its cleartext `bond_credit` term
    /// rides the CT balance directly (blockchain.cpp bond-post arm pins
    /// `pseudoOuts.size() == num_spend`).
    pub pseudo_outs: Vec<[u8; 32]>,
    /// The pruned half of each pass record as an opaque blob, in
    /// **serve-credit-vin order, one per serve-credit vin** (`RF-D1`). No
    /// record COUNT on the wire — it is the vin count — but each record
    /// carries its own byte length, because C++ transports these bytes without
    /// parsing them and must still hand each vin's slice to the verifier.
    ///
    /// Empty for every shape but the serve-credit one, and for that shape it is
    /// the *only* populated member — `bulletproofs`, `fcmp_proof` and
    /// `pseudo_outs` are all empty there by consensus mandate
    /// (`tx_verification_utils.cpp:117-124`), because a non-spending tx has no
    /// outputs to range-prove and no membership to prove.
    pub serve_credit_pruned: Vec<Vec<u8>>,
}

impl Prunable {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.bulletproofs.len(), w)?;
        for bp in &self.bulletproofs {
            bp.write(w)?;
        }
        write_varint(self.tree_depth, w)?;
        write_varint(self.fcmp_proof.len(), w)?;
        w.write_all(&self.fcmp_proof)?;
        for pseudo_out in &self.pseudo_outs {
            w.write_all(pseudo_out)?;
        }
        // Last, keyed by position to the serve-credit vins; each blob
        // length-prefixed (C++ `FIELD(std::vector<uint8_t>)` encoding).
        for record in &self.serve_credit_pruned {
            write_varint(record.len(), w)?;
            w.write_all(record)?;
        }
        Ok(())
    }

    fn read<R: Read>(
        spend_inputs: usize,
        serve_credit_inputs: usize,
        r: &mut R,
    ) -> io::Result<Prunable> {
        let nbp: usize = read_varint(r)?;
        if nbp > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: nbp {nbp} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        let mut bulletproofs = Vec::new();
        for _ in 0..nbp {
            bulletproofs.push(BpPlus::read(r)?);
        }
        let tree_depth = read_varint(r)?;
        let fcmp_proof = read_len_prefixed(r, "fcmp_proof")?;
        // pseudoOuts: one per ToKey (spend) input, no length prefix. A bond-post
        // input contributes no pseudo-out (module header / blockchain.cpp pin).
        let pseudo_outs = read_points(r, spend_inputs)?;
        // One per serve-credit vin, no length prefix — the count comes from the
        // prefix, which is already parsed.
        let mut serve_credit_pruned = Vec::with_capacity(serve_credit_inputs);
        for _ in 0..serve_credit_inputs {
            let record = read_len_prefixed_bounded(
                r,
                "serve_credit pruned record",
                ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES,
            )?;
            check_serve_credit_pruned_blob(&record)?;
            serve_credit_pruned.push(record);
        }
        Ok(Prunable {
            bulletproofs,
            tree_depth,
            fcmp_proof,
            pseudo_outs,
            serve_credit_pruned,
        })
    }
}

/// The confidential-transaction section.
#[derive(Clone, PartialEq, Eq, Debug)]
// The Fcmp variant is intrinsically larger than Null (it carries the proofs);
// boxing would only move the bytes behind a pointer for no consumer benefit.
#[allow(clippy::large_enum_variant)]
pub enum Ct {
    /// Coinbase confidential section (type 0x00): committed base only.
    Null(CtBase),
    /// FCMP++ confidential section (dense ct type `0x01`). Covers the full spend
    /// (per-input `pqc_auths` + a `prunable` proof), the storage-pruned spend
    /// (`pqc_auths` present, `prunable` [`None`]), and the serve-credit form
    /// (empty `pqc_auths`, `prunable` holding only pruned pass records, §2.5 /
    /// `RF-D1`). Shape is typed off the vin, never off which of these is
    /// absent (GENESIS_TX_WIRE_FORMAT.md §9.8 / §4).
    Fcmp {
        /// Transaction fee.
        fee: u64,
        /// Block hash anchoring the curve-tree root the proof is against.
        reference_block: [u8; 32],
        /// Committed base arrays (per output).
        base: CtBase,
        /// Per-input PQC authentication (count == `nvin`, no length prefix; empty
        /// in the serve-credit form — the countersignature rides the vin).
        pqc_auths: Vec<PqcAuth>,
        /// Prunable region. `None` only for the storage-pruned *spend* form
        /// (daemon `get_transactions prune:true`). Serve-credit carries
        /// [`Some`] with only `serve_credit_pruned` populated.
        prunable: Option<Prunable>,
    },
}

impl Ct {
    /// Write the ct section.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Ct::Null(base) => {
                w.write_all(&[CT_TYPE_NULL])?;
                base.write(w)
            }
            Ct::Fcmp {
                fee,
                reference_block,
                base,
                pqc_auths,
                prunable,
            } => {
                w.write_all(&[CT_TYPE_FCMP])?;
                write_varint(*fee, w)?;
                w.write_all(reference_block)?;
                base.write(w)?;
                // tx-level pqc_auths: count == nvin, no length prefix (empty in
                // the serve-credit form).
                for auth in pqc_auths {
                    auth.write(w)?;
                }
                // prunable follows iff present (absent only for the
                // storage-pruned spend form).
                if let Some(prunable) = prunable {
                    prunable.write(w)?;
                }
                Ok(())
            }
        }
    }

    /// Read the ct section. `inputs`/`outputs` (the vin/vout counts) size the
    /// per-input/per-output arrays that carry no length prefix; `spend_inputs`
    /// (the `ToKey` subset of vin) sizes `pseudoOuts`, which a bond-post input
    /// does not contribute to (module header). `serve_credit_only` is the vin
    /// shape ([`TxPrefix::is_serve_credit_only`]), not a stream-position fact.
    /// Takes a [`BufRead`] so the EOF-tolerant tail (§9.8) can be detected
    /// without consuming bytes.
    pub fn read<R: BufRead>(
        inputs: usize,
        spend_inputs: usize,
        serve_credit_inputs: usize,
        serve_credit_only: bool,
        outputs: usize,
        r: &mut R,
    ) -> io::Result<Ct> {
        let ct_type = read_byte(r)?;
        match ct_type {
            CT_TYPE_NULL => Ok(Ct::Null(CtBase::read(outputs, r)?)),
            CT_TYPE_FCMP => {
                let fee = read_varint(r)?;
                let reference_block = read_array(r)?;
                let base = CtBase::read(outputs, r)?;
                // EOF-tolerant tail (§9.8 / §4). A genuine spend that ends
                // after the base is the storage-pruned form with empty
                // `pqc_auths` *and* no prunable — only reachable on a
                // malformed blob; the live storage-pruned spend still
                // carries `pqc_auths` and hits the second EOF check below.
                // Serve-credit is **not** this case: after RF-D1 it has a
                // prunable region, so bytes remain after the base.
                if r.fill_buf()?.is_empty() {
                    return Ok(Ct::Fcmp {
                        fee,
                        reference_block,
                        base,
                        pqc_auths: Vec::new(),
                        prunable: None,
                    });
                }
                // Typed off the vin, exactly as the C++ oracle does
                // (`cryptonote_basic.h`, `RF-D9`). Deciding a transaction's
                // shape from how far a stream has been consumed is what made
                // that side unwritable; the same heuristic would make this
                // side unreadable.
                let mut pqc_auths = Vec::new();
                if !serve_credit_only {
                    for _ in 0..inputs {
                        pqc_auths.push(PqcAuth::read(r)?);
                    }
                }
                // EOF after pqc_auths ⇒ the **storage-pruned full-spend form**:
                // the daemon's pruned fetch (`get_transactions prune:true`)
                // keeps consensus pqc_auths but drops the prunable proof
                // (cryptonote_basic.h gates `rctsig_prunable` on `!pruned`).
                // Serve-credit never takes this arm: it skipped pqc_auths
                // and still has pruned-record bytes to read.
                let prunable = if r.fill_buf()?.is_empty() {
                    None
                } else {
                    Some(Prunable::read(spend_inputs, serve_credit_inputs, r)?)
                };
                Ok(Ct::Fcmp {
                    fee,
                    reference_block,
                    base,
                    pqc_auths,
                    prunable,
                })
            }
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported ct type {other:#04x}"
            ))),
        }
    }
}

/// The transaction prefix (everything hashed into the prefix hash).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxPrefix {
    /// Additional timelock (block height; `0` = none). A varint on the wire.
    pub unlock_time: u64,
    /// Transaction inputs.
    pub inputs: Vec<Input>,
    /// Transaction outputs.
    pub outputs: Vec<Output>,
    /// Opaque extra blob (the PQC `tx_extra` internal structure is a later slice).
    pub extra: Vec<u8>,
}

impl TxPrefix {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.unlock_time, w)?;
        write_varint(self.inputs.len(), w)?;
        for input in &self.inputs {
            input.write(w)?;
        }
        write_varint(self.outputs.len(), w)?;
        for output in &self.outputs {
            output.write(w)?;
        }
        write_varint(self.extra.len(), w)?;
        w.write_all(&self.extra)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<TxPrefix> {
        let unlock_time = read_varint(r)?;

        let n_inputs: usize = read_varint(r)?;
        if n_inputs > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: input count {n_inputs} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        let mut inputs = Vec::new();
        for _ in 0..n_inputs {
            inputs.push(Input::read(r)?);
        }

        // Outputs are capped at the structural maximum (not the loose `READ_LEN_CAP`):
        // no valid tx exceeds `MAX_OUTPUTS`, and rejecting here bounds the per-output
        // `CtBase` allocation (`enc_amounts`/`enc_labels`/`commitments`) that follows,
        // so a hostile count can't drive ~50 B/output of allocation before `validate`.
        let n_outputs: usize = read_varint(r)?;
        if n_outputs > MAX_OUTPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: output count {n_outputs} exceeds {MAX_OUTPUTS}"
            )));
        }
        let mut outputs = Vec::new();
        for _ in 0..n_outputs {
            outputs.push(Output::read(r)?);
        }

        let extra = read_len_prefixed(r, "extra")?;

        Ok(TxPrefix {
            unlock_time,
            inputs,
            outputs,
            extra,
        })
    }

    /// Parse the opaque `extra` blob into structured `tx_extra` fields (§9.6a).
    /// `extra` is kept opaque for round-trip; this is the additive structured view.
    pub fn parse_extra(&self) -> io::Result<Vec<crate::tx_extra::TxExtraField>> {
        crate::tx_extra::parse(&self.extra)
    }

    /// Twin of C++ `count_spend_inputs`.
    #[must_use]
    pub fn spend_input_count(&self) -> usize {
        self.inputs.iter().filter(|i| i.is_spend()).count()
    }

    /// Twin of C++ `count_serve_credit_inputs`.
    #[must_use]
    pub fn serve_credit_input_count(&self) -> usize {
        self.inputs.iter().filter(|i| i.is_serve_credit()).count()
    }

    /// Twin of C++ `classify_archival_tx(vin).kind == serve_credit_only`:
    /// non-empty vin, every input a serve-credit. The shape is a property of
    /// the prefix, not of what is absent from the confidential section.
    #[must_use]
    pub fn is_serve_credit_only(&self) -> bool {
        !self.inputs.is_empty() && self.inputs.iter().all(Input::is_serve_credit)
    }
}

/// A Shekyl transaction (version 3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    /// The transaction prefix.
    pub prefix: TxPrefix,
    /// The confidential-transaction section.
    pub ct: Ct,
}

impl Transaction {
    /// Write the transaction.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(TX_VERSION, w)?;
        self.prefix.write(w)?;
        self.ct.write(w)
    }

    /// Read the transaction.
    pub fn read<R: BufRead>(r: &mut R) -> io::Result<Transaction> {
        let version: u64 = read_varint(r)?;
        if version != TX_VERSION {
            return Err(io::Error::other(format!(
                "shekyl-wire: transaction version {version} != {TX_VERSION}"
            )));
        }
        let prefix = TxPrefix::read(r)?;
        // Counts taken from the prefix, never carried on the wire: spend vins
        // size pseudoOuts, serve-credit vins size the pruned pass-record array.
        let ct = Ct::read(
            prefix.inputs.len(),
            prefix.spend_input_count(),
            prefix.serve_credit_input_count(),
            prefix.is_serve_credit_only(),
            prefix.outputs.len(),
            r,
        )?;
        Ok(Transaction { prefix, ct })
    }

    /// Serialize the transaction to a fresh `Vec<u8>`.
    ///
    /// This is a **faithful** encoding of the in-memory value, not a validity gate:
    /// the I/O is infallible, but a hand-built tx with out-of-range fields (counts
    /// past the parse caps, oversized PQC blobs, a fee-only/spend shape mismatch) can
    /// serialize to bytes [`Self::from_bytes`] would then reject. Call
    /// [`Self::validate`] first when you need a guaranteed-round-trippable blob;
    /// values obtained from `from_bytes` are already in range and always round-trip.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out)
            .expect("writing to a Vec is infallible");
        out
    }

    /// The serialized byte length, measured **without allocating** the blob (writes
    /// into a counting sink). Used for the `MAX_TX_SIZE` bound in [`Self::validate`].
    pub fn serialized_len(&self) -> usize {
        let mut counter = CountingWriter::default();
        self.write(&mut counter)
            .expect("counting write is infallible");
        counter.bytes
    }

    /// The consensus **transaction weight** — the serialized size **plus** the
    /// bulletproof-plus clawback, mirroring the C++ `get_transaction_weight`
    /// (`blob_size + bp_clawback`, `cryptonote_format_utils.cpp:292`). The clawback is
    /// a verification-cost *penalty* added for a Bp+ covering more than two (padded)
    /// outputs — so weight is **not** the serialized length, and weight ≥ size always.
    /// It is `0` for the genesis ≤2-output spend shapes and for any non-spend (coinbase
    /// `Null`, fee-only `Fcmp`). This is the value the daemon charges fees and block
    /// weight against, so a wallet fee estimate must match it.
    pub fn weight(&self) -> usize {
        self.serialized_len() + self.bp_plus_clawback()
    }

    /// Bp+ weight clawback for this tx: derive the padded output count from each proof's
    /// `L` length — the daemon's `n_bulletproof_plus_max_amounts` (`|L| = 6 +
    /// ceil(log2(n_padded))`, so `n_padded = 1 << (|L| − 6)`, summed across proofs;
    /// genesis carries one) — then apply [`bp_plus_weight_clawback`]. Returns `0` for a
    /// non-spend / fee-only ct (no prunable).
    fn bp_plus_clawback(&self) -> usize {
        let Ct::Fcmp {
            prunable: Some(prunable),
            ..
        } = &self.ct
        else {
            return 0;
        };
        // `BpPlus::read` bounds `|L|` to `6..=MAX_BP_LR_LEN` and `validate()` pins it
        // exactly by the output count, but `weight()` is also reachable on a hand-built
        // (never-parsed, not-yet-validated) tx — so the shift must not overflow, which
        // would panic on invalid input (DoS). Clamp each proof to `MAX_OUTPUTS`: exact
        // for any valid tx (`n_padded ≤ MAX_OUTPUTS`) and merely bounded for an invalid
        // one, which `validate()` / `MAX_TX_SIZE` rejects regardless.
        let n_padded: usize = prunable
            .bulletproofs
            .iter()
            .map(|bp| {
                let bits = bp.l.len().saturating_sub(6);
                if bits >= MAX_OUTPUTS.ilog2() as usize {
                    MAX_OUTPUTS
                } else {
                    1usize << bits
                }
            })
            .sum::<usize>()
            .min(MAX_OUTPUTS);
        bp_plus_weight_clawback(n_padded)
    }

    /// The FCMP++ **`signable_tx_hash`** — the prefix hash the membership/SAL proof
    /// signs (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.2; the C++ `cn_fast_hash` over the
    /// `transaction_prefix`). It **includes the version**: the C++ `transaction_prefix`
    /// serializes `VARINT(version)` first, so this is
    /// `keccak256(varint(TX_VERSION) ‖ TxPrefix::write)` — the same `varint(3) ‖
    /// prefix` composition [`Self::write`] emits at the head of the tx.
    pub fn prefix_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        write_varint(TX_VERSION, &mut buf).expect("writing to a Vec is infallible");
        self.prefix
            .write(&mut buf)
            .expect("writing to a Vec is infallible");
        keccak256(&buf)
    }

    /// Per-input PQC signing-preimage hashes — the `signed_hash(i)` each input's PQC
    /// auth (ML-DSA + ed25519) signs (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1; C++
    /// `get_transaction_signed_payload`, `tx_pqc_verify.cpp:58-152`):
    ///
    /// ```text
    /// payload(i)     = prefix_blob ‖ ct_base_blob ‖ prunable_hash ‖ pqc_header(i) ‖ all_key_hashes
    /// signed_hash(i) = keccak256(payload(i))
    /// ```
    /// - `prefix_blob`    = `varint(TX_VERSION) ‖ TxPrefix::write` (same as [`Self::prefix_hash`]'s input)
    /// - `ct_base_blob`  = `CT_TYPE_FCMP ‖ varint(fee) ‖ reference_block ‖ CtBase::write`
    ///   (mirrors the [`Ct::Fcmp`] write head exactly — §1.3, referenceBlock in *base*)
    /// - `prunable_hash`  = `keccak256(Prunable::write)` (the digest, not the blob — §1.4)
    /// - `pqc_header(i)`  = the i-th auth header, **no signature** (`PqcAuth::header_write` — §1.5)
    /// - `all_key_hashes` = `‖ over every auth: keccak256(hybrid_public_key)` (binds every
    ///   input's key into every signature)
    ///
    /// Returns one hash per `pqc_auths` entry — `== nvin` for a valid spend, whose arity
    /// `Transaction::validate` couples (the count is not re-checked here, so a hand-built
    /// tx with mismatched arity yields one hash per auth regardless). Returns an empty vec
    /// for any non-spend shape — a `Null` ct, or a fee-only `Fcmp` with no prunable /
    /// empty `pqc_auths` — which carries no per-input PQC signature.
    pub fn pqc_signing_payload_hashes(&self) -> Vec<[u8; 32]> {
        let Ct::Fcmp {
            fee,
            reference_block,
            base,
            pqc_auths,
            prunable: Some(prunable),
        } = &self.ct
        else {
            return Vec::new();
        };
        if pqc_auths.is_empty() {
            return Vec::new();
        }

        // prefix_blob = varint(TX_VERSION) ‖ TxPrefix::write
        let mut prefix_blob = Vec::new();
        write_varint(TX_VERSION, &mut prefix_blob).expect("Vec write is infallible");
        self.prefix
            .write(&mut prefix_blob)
            .expect("Vec write is infallible");

        // ct_base_blob = CT_TYPE_FCMP ‖ varint(fee) ‖ reference_block ‖ CtBase::write —
        // byte-for-byte the head `Ct::Fcmp::write` emits before pqc_auths/prunable.
        let mut ct_base_blob = Vec::new();
        ct_base_blob.push(CT_TYPE_FCMP);
        write_varint(*fee, &mut ct_base_blob).expect("Vec write is infallible");
        ct_base_blob.extend_from_slice(reference_block);
        base.write(&mut ct_base_blob)
            .expect("Vec write is infallible");

        // prunable_hash = keccak256(Prunable::write)
        let mut prunable_blob = Vec::new();
        prunable
            .write(&mut prunable_blob)
            .expect("Vec write is infallible");
        let prunable_hash = keccak256(&prunable_blob);

        // all_key_hashes = concat over EVERY auth of keccak256(hybrid_public_key)
        let mut all_key_hashes = Vec::with_capacity(pqc_auths.len() * 32);
        for auth in pqc_auths {
            all_key_hashes.extend_from_slice(&keccak256(&auth.hybrid_public_key));
        }

        pqc_auths
            .iter()
            .map(|auth| {
                let mut payload = Vec::new();
                payload.extend_from_slice(&prefix_blob);
                payload.extend_from_slice(&ct_base_blob);
                payload.extend_from_slice(&prunable_hash);
                auth.header_write(&mut payload)
                    .expect("Vec write is infallible");
                payload.extend_from_slice(&all_key_hashes);
                keccak256(&payload)
            })
            .collect()
    }

    /// Parse a transaction from a complete blob, requiring **exact consumption**
    /// (GENESIS_TX_WIRE_FORMAT.md §12 — trailing bytes are rejected).
    ///
    /// Rejects blobs larger than `MAX_TX_SIZE` up front, so this entry point is a
    /// DoS-bounded decode (no allocation proportional to an over-cap input). This is
    /// the size guard only — full consensus validity (shape couplings, key-image
    /// order, arm rules) is still [`Self::validate`]'s job.
    pub fn from_bytes(blob: &[u8]) -> io::Result<Transaction> {
        if blob.len() > MAX_TX_SIZE {
            return Err(io::Error::other(format!(
                "shekyl-wire: tx blob {} exceeds {MAX_TX_SIZE}",
                blob.len()
            )));
        }
        let mut cursor = blob;
        let tx = Transaction::read(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::other(format!(
                "shekyl-wire: {} trailing byte(s) after transaction (§12 exact-consumption)",
                cursor.len()
            )));
        }
        Ok(tx)
    }

    /// The consensus transaction hash (`keccak256` over component hashes,
    /// GENESIS_TX_WIRE_FORMAT.md §11): **3-part** for the coinbase (`Null`) —
    /// `H(prefix) · H(base) · null_hash`; **4-part** for an FCMP++ spend —
    /// `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`. `H(prefix)` includes
    /// the version varint (the first field of the C++ `transaction_prefix`).
    pub fn hash(&self) -> [u8; 32] {
        let mut prefix_buf = Vec::new();
        write_varint(TX_VERSION, &mut prefix_buf).expect("Vec write is infallible");
        self.prefix
            .write(&mut prefix_buf)
            .expect("Vec write is infallible");
        let h_prefix = keccak256(&prefix_buf);

        match &self.ct {
            Ct::Null(base) => {
                let mut base_buf = vec![CT_TYPE_NULL];
                base.write(&mut base_buf).expect("Vec write is infallible");
                hash_concat(&[h_prefix, keccak256(&base_buf), [0u8; 32]])
            }
            Ct::Fcmp {
                fee,
                reference_block,
                base,
                pqc_auths,
                prunable,
            } => {
                let mut base_buf = vec![CT_TYPE_FCMP];
                write_varint(*fee, &mut base_buf).expect("Vec write is infallible");
                base_buf.extend_from_slice(reference_block);
                base.write(&mut base_buf).expect("Vec write is infallible");
                let h_base = keccak256(&base_buf);

                // Per the C++ oracle (format_utils.cpp:1137/1163-1182): **4-part**
                // `{prefix, base, pqc_auths, prunable}` iff `has_pqc && !pqc_auths
                // .empty()`, where `has_pqc = version>=3 && vin[0] != gen`; otherwise
                // **3-part** `{prefix, base, prunable}`. The prunable component is
                // `H(prunable)` when present, else the null hash (the fee-only /
                // serve-credit form — its live-oracle hash parity is pending a captured
                // blob, as for the spend KAT).
                let h_prunable = match prunable {
                    Some(prunable) => {
                        let mut prunable_buf = Vec::new();
                        prunable
                            .write(&mut prunable_buf)
                            .expect("Vec write is infallible");
                        keccak256(&prunable_buf)
                    }
                    None => [0u8; 32],
                };

                // `has_pqc` excludes the (malformed) gen-first shape, exactly as the
                // oracle does — so a `gen` input + `Fcmp` ct hashes 3-part like a
                // coinbase rather than misclassifying as a spend.
                let first_is_gen = matches!(self.prefix.inputs.first(), Some(Input::Gen(_)));
                if pqc_auths.is_empty() || first_is_gen {
                    hash_concat(&[h_prefix, h_base, h_prunable])
                } else {
                    // The pqc component mirrors the oracle's generic `std::vector`
                    // serializer (format_utils.cpp:1169), whose `begin_array(cnt)`
                    // writes the element **count as a leading varint** before the
                    // entries — unlike the tx *body*, where the count is implicit
                    // (`vin.size()`, no prefix). Both must match their respective C++
                    // paths; they legitimately differ.
                    let mut auth_buf = Vec::new();
                    write_varint(pqc_auths.len(), &mut auth_buf).expect("Vec write is infallible");
                    for auth in pqc_auths {
                        auth.write(&mut auth_buf).expect("Vec write is infallible");
                    }
                    hash_concat(&[h_prefix, h_base, keccak256(&auth_buf), h_prunable])
                }
            }
        }
    }

    /// Structural / canonical-form validation for an ingested **pruned** transaction:
    /// the context-free reject set that does **not** depend on the prunable proof
    /// section being present (GENESIS_TX_WIRE_FORMAT.md §10 + the pruned-safe parts of
    /// §12/§13).
    ///
    /// This is the single ingestion gate the scan/refresh boundary
    /// (`shekyl-engine-core::engine::block_fetch`) runs on every block/transaction blob
    /// an untrusted daemon serves. The wallet fetches *pruned* transactions (the
    /// prunable proof — Bp+, fcmp_proof, pseudoOuts — dropped), so the full
    /// [`Self::validate`] cannot run here: its prunable-coupled branch rejects a
    /// key-image-bearing spend whose prunable has been dropped, by design.
    ///
    /// It mirrors the **context-free** rejects of the C++ oracle's
    /// `core::check_tx_semantic` + `Blockchain::check_tx_inputs` +
    /// `check_inputs_types_supported` (verified by a differential read, 2026-06-21):
    /// resource bounds (§10), the arm-mixing matrix (gen sole / coinbase, serve_credit
    /// all-or-none + fee-only, ≤1 bond_post, ≤1 emission not mixing with bond_post),
    /// `Null` ct iff coinbase, empty
    /// `key_offsets`, strictly-descending key images (rejecting in-tx duplicates),
    /// per-arm archival bounds, the committed-base arity, and the `unlock_time`
    /// block-height form. The prunable-coupled checks — `nbp == 1`, the per-input
    /// `pqc_auths` / `pseudoOuts` counts, `>= 2` outputs for a spend, and the fee-only
    /// no-prunable shape — are [`Self::validate`]-only; they need the complete tx.
    ///
    /// **Out of scope** — deferred to the consensus/crypto layer because they need
    /// elliptic-curve math (which this crate intentionally has no dependency for) or
    /// chain state:
    /// - key-image **domain** validity — `ki != identity`, in the prime-order subgroup
    ///   (`check_tx_inputs_keyimages_domain`);
    /// - output public-key / commitment-mask validity (`check_outs_valid`,
    ///   `check_commitment_mask_valid`) — curve checks;
    /// - the FCMP++ membership proof, CT balance, double-spend, the referenceBlock
    ///   window, and the coinbase reward / exact `unlock_time` / height (all chain-state);
    /// - the coinbase reward **balance** — the consensus layer's
    ///   `validate_miner_transaction` (the money-overflow *sum* itself is checked
    ///   below: the loud emission-claim reward vout made non-zero non-coinbase
    ///   amounts legal, so the C++ `check_money_overflow` parity is load-bearing).
    pub fn validate_context_free_pruned(&self) -> io::Result<()> {
        if self.prefix.inputs.is_empty() {
            return Err(io::Error::other("shekyl-wire: transaction has no inputs"));
        }
        let n_out = self.prefix.outputs.len();
        // Upper bound is structural; the lower bound is shape-aware (a spend/coinbase
        // has >=1 output, the fee-only serve-credit form has 0) — enforced per-ct below.
        if n_out > MAX_OUTPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: output count {n_out} exceeds {MAX_OUTPUTS}"
            )));
        }
        // C++ `check_money_overflow` (`core::check_tx_semantic` →
        // `check_outs_overflow`): the output-amount sum must not overflow. This
        // was vacuous while every non-coinbase wire amount was 0; the loud
        // emission-claim reward vout (C-1) legitimized non-zero non-coinbase
        // amounts, so the checked sum is now the accept/reject-parity arm for
        // hostile loud amounts the C++ daemon rejects.
        self.prefix
            .outputs
            .iter()
            .try_fold(0u64, |sum, out| sum.checked_add(out.amount))
            .ok_or_else(|| {
                io::Error::other(
                    "shekyl-wire: output amounts overflow u64 (check_money_overflow parity)",
                )
            })?;
        // §2.5 coinbase shape: a `gen` input is coinbase-only and must be the sole
        // input. Reject `gen` mixed with any other input — otherwise a tx like
        // `[Gen, ToKey, …]` would be misclassified as coinbase and skip the
        // non-coinbase tx_extra cap below.
        let gen_count = self
            .prefix
            .inputs
            .iter()
            .filter(|input| matches!(input, Input::Gen(_)))
            .count();
        if gen_count > 0 && self.prefix.inputs.len() != 1 {
            return Err(io::Error::other(
                "shekyl-wire: gen input must be the sole input (coinbase shape, §2.5)",
            ));
        }
        let is_coinbase = gen_count == 1;
        // §2.5 / C++ `check_inputs_types_supported` — the (context-free) arm-mixing
        // matrix. Mirror the oracle's rejects exactly, no stricter:
        let serve_credit_count = self.prefix.serve_credit_input_count();
        let bond_post_count = self
            .prefix
            .inputs
            .iter()
            .filter(|i| matches!(i, Input::BondPost(_)))
            .count();
        let emission_count = self
            .prefix
            .inputs
            .iter()
            .filter(|i| matches!(i, Input::ArchivalRewardEmission { .. }))
            .count();
        // serve_credit is non-spending — it must not mix with any spend/bond/gen arm.
        // The oracle allows **multiple** serve_credits, only rejecting the *mixing*
        // (check_inputs_types_supported:720), so the rule is "all-or-none", not
        // "exactly one".
        if serve_credit_count > 0 {
            if !self.prefix.is_serve_credit_only() {
                return Err(io::Error::other(
                    "shekyl-wire: serve_credit must not mix with other input arms (§2.5)",
                ));
            }
            // The shape check, INVERTED by `RF-D1`: a serve-credit tx now
            // carries a prunable region. It used to be identified by the
            // absence of one.
            //
            // What stayed true: no outputs, empty `pqc_auths`, and none of the
            // spend-proof material (`bulletproofs`, `fcmp_proof`,
            // `pseudo_outs`), all of which consensus requires empty
            // (`tx_verification_utils.cpp:117-124`) because a non-spending tx
            // has nothing to range-prove and no membership to prove.
            //
            // What changed: the region is now `Some`, holding exactly one
            // pruned pass record per serve-credit vin.
            let shape_ok = self.prefix.outputs.is_empty()
                && match &self.ct {
                    Ct::Fcmp {
                        pqc_auths,
                        prunable: Some(p),
                        ..
                    } => {
                        pqc_auths.is_empty()
                            && p.bulletproofs.is_empty()
                            && p.fcmp_proof.is_empty()
                            && p.pseudo_outs.is_empty()
                            && p.serve_credit_pruned.len() == serve_credit_count
                    }
                    _ => false,
                };
            if !shape_ok {
                return Err(io::Error::other(
                    "shekyl-wire: serve_credit tx must be fee-only — no outputs, empty \
                     pqc_auths, no spend-proof material, and exactly one pruned pass \
                     record per serve-credit vin (§2.5, RF-D1)",
                ));
            }
            if let Ct::Fcmp {
                prunable: Some(p), ..
            } = &self.ct
            {
                for record in &p.serve_credit_pruned {
                    check_serve_credit_pruned_blob(record)?;
                }
            }
        }
        // At most one bond_post per tx (check_inputs_types_supported:726). bond_post may
        // share a tx with fcmp spends (the bond-post shape) but not serve_credit — the
        // latter is already rejected by the all-serve_credit rule above.
        if bond_post_count > 1 {
            return Err(io::Error::other(
                "shekyl-wire: at most one bond_post input per tx (§2.5)",
            ));
        }
        // Emission mixing (C-1, Q3 arity 1 / Q11): at most one emission vin
        // (check_inputs_types_supported:731), and it must not mix with a bond_post
        // (:737) — key-imaged `ToKey` fee spends are the only permitted
        // co-residents. serve_credit co-residency is already rejected by the
        // all-serve_credit rule above; gen co-residency by the sole-gen rule.
        if emission_count > 1 {
            return Err(io::Error::other(
                "shekyl-wire: at most one emission input per tx (§2.5)",
            ));
        }
        if emission_count == 1 && bond_post_count > 0 {
            return Err(io::Error::other(
                "shekyl-wire: emission must not mix with a bond_post input (§2.5)",
            ));
        }
        // tx_extra bound (the coinbase extra is unbounded in C++; cap non-coinbase).
        if !is_coinbase && self.prefix.extra.len() > MAX_TX_EXTRA {
            return Err(io::Error::other(format!(
                "shekyl-wire: tx_extra {} exceeds {MAX_TX_EXTRA}",
                self.prefix.extra.len()
            )));
        }
        let size = self.serialized_len();
        if size > MAX_TX_SIZE {
            return Err(io::Error::other(format!(
                "shekyl-wire: tx size {size} exceeds {MAX_TX_SIZE}"
            )));
        }
        if self.prefix.unlock_time >= UNLOCK_TIME_BLOCK_SENTINEL {
            return Err(io::Error::other(format!(
                "shekyl-wire: unlock_time {} is the timestamp form (block-height only)",
                self.prefix.unlock_time
            )));
        }
        // §10 input cap — the C++ bound (`FCMP_MAX_INPUTS_PER_TX`) is on the **total**
        // `vin.size()`, not just the key-image subset (blockchain.cpp:3618), so a
        // bond_post's funding inputs + the post input all count. Coinbase (`[gen]`) is
        // a single input and uses the non-fcmp path, so scope this to non-coinbase.
        if !is_coinbase && self.prefix.inputs.len() > MAX_FCMP_INPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: {} inputs exceed {MAX_FCMP_INPUTS}",
                self.prefix.inputs.len()
            )));
        }
        // §12 canonical-form on the spend (`txin_to_key` / fcmp) inputs, matching the
        // C++ oracle (blockchain.cpp check_tx_inputs):
        //  - `key_offsets` MUST be empty — FCMP++ carries no ring offsets; the field is
        //    vestigial until the §5 reshape removes it (blockchain.cpp:3715/3700).
        //  - key-image-bearing inputs strictly **descending** by key image:
        //    `memcmp(ki, last) >= 0 → reject` (blockchain.cpp:3656). One rule, two
        //    guarantees — rejects unsorted AND in-tx duplicate key images. No-key-image
        //    arms (`gen`/`serve_credit`/`bond_post`/`emission`) are exempt.
        let mut key_images: Vec<&[u8; 32]> = Vec::new();
        for input in &self.prefix.inputs {
            if let Input::ToKey {
                key_offsets,
                key_image,
                ..
            } = input
            {
                if !key_offsets.is_empty() {
                    return Err(io::Error::other(
                        "shekyl-wire: spend input has non-empty key_offsets \
                         (FCMP++ has no ring offsets; §12)",
                    ));
                }
                key_images.push(key_image);
            }
        }
        for pair in key_images.windows(2) {
            if pair[0] <= pair[1] {
                return Err(io::Error::other(
                    "shekyl-wire: key images not strictly descending (§12)",
                ));
            }
        }
        // Per-arm in-memory bound checks for the archival inputs — the consensus caps
        // that `read` enforces inline (path layers, branch scalars, hybrid blobs,
        // holdings shard count, the JoinMarket-tag coupling). Without these a hand-built
        // arm could pass `validate` yet serialize to bytes `from_bytes` rejects.
        for input in &self.prefix.inputs {
            match input {
                Input::BondPost(bp) => bp.validate()?,
                Input::ArchivalRewardEmission { canonical_bytes } => {
                    check_emission_blob(canonical_bytes)?
                }
                Input::ServeCredit { canonical_bytes } => check_serve_credit_blob(canonical_bytes)?,
                _ => {}
            }
        }
        // Committed-base arity is shape-aware per §2.5 (full spend / bond-post /
        // fee-only-serve-credit); the prunable-coupled length couplings (pqc_auths /
        // pseudoOuts per input) move to `validate`, which has the complete tx.
        let base = match &self.ct {
            Ct::Null(base) => {
                // §2.5: a `Null` ct carries no proof material and is **coinbase-only**;
                // a non-coinbase tx must be `Fcmp`. Without this, a tx with `ToKey`
                // (spend) inputs + a `Null` ct would pass structural validation while
                // being consensus-invalid.
                if !is_coinbase {
                    return Err(io::Error::other(
                        "shekyl-wire: Null ct is coinbase-only; a non-coinbase tx must be Fcmp (§2.5)",
                    ));
                }
                if n_out == 0 {
                    return Err(io::Error::other("shekyl-wire: coinbase has no outputs"));
                }
                base
            }
            Ct::Fcmp {
                base, pqc_auths, ..
            } => {
                // §2.5: the coinbase is `Null`-only — an `Fcmp` ct on a coinbase (a
                // `gen` input) is the dual of the check above.
                if is_coinbase {
                    return Err(io::Error::other(
                        "shekyl-wire: coinbase must carry a Null ct, not Fcmp (§2.5)",
                    ));
                }
                // Per-auth blob bounds — consensus accept-parity with the C++
                // deserialization caps (`PqcAuth::read` rejects oversized blobs on the
                // wire; `PqcAuth::write` is faithful, so this is the in-memory gate that
                // keeps a constructed tx from later failing parse). Empty for the
                // fee-only / pruned form, so this is a no-op there. The prunable-coupled
                // per-input *count* checks live in `validate` (the complete tx).
                for auth in pqc_auths {
                    if auth.hybrid_public_key.len() > PQC_MAX_PUBLIC_KEY_BLOB {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: pqc_auth public key {} exceeds {PQC_MAX_PUBLIC_KEY_BLOB}",
                            auth.hybrid_public_key.len()
                        )));
                    }
                    if auth.hybrid_signature.len() > PQC_MAX_SIGNATURE_BLOB {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: pqc_auth signature {} exceeds {PQC_MAX_SIGNATURE_BLOB}",
                            auth.hybrid_signature.len()
                        )));
                    }
                }
                base
            }
        };
        // The committed base arrays are per-output (count == nvout).
        if base.enc_amounts.len() != n_out
            || base.enc_labels.len() != n_out
            || base.commitments.len() != n_out
        {
            return Err(io::Error::other(format!(
                "shekyl-wire: ct base arrays (enc_amounts={}, enc_labels={}, \
                 commitments={}) must each equal output count {n_out}",
                base.enc_amounts.len(),
                base.enc_labels.len(),
                base.commitments.len()
            )));
        }
        // §10 anti-deanonymization: a spend (a key-image-bearing tx) must have >= 2
        // outputs (blockchain.cpp:3599-3602). Pruned-safe — outputs survive pruning and
        // the spend is identified by its key-image inputs, not the dropped prunable proof
        // — so it is enforced at ingestion, not only in `validate`. Checked after the ct
        // shape so a malformed-ct error still surfaces first. Coinbase / fee-only forms
        // carry no key image (exempt); a bond_post's >= 2 rule is prunable-coupled.
        if !key_images.is_empty() && n_out < 2 {
            return Err(io::Error::other(format!(
                "shekyl-wire: spend has {n_out} output(s), needs >= 2"
            )));
        }
        Ok(())
    }

    /// Full context-free canonical validation: [`Self::validate_context_free_pruned`]
    /// plus the prunable-proof-coupled checks that require a complete (non-pruned)
    /// transaction — `nbp == 1`, the Bp+ `|L|`/`|R|` round count pinned exactly by
    /// the output count, the per-input `pqc_auths` / `pseudoOuts` counts, the
    /// `>= 2`-output anti-deanonymization rule for a spend, and the fee-only
    /// no-prunable shape. Use this on a *complete* tx; the scan/refresh boundary, which
    /// ingests pruned txs, calls [`Self::validate_context_free_pruned`] instead.
    ///
    /// The bond_post `pseudoOuts`↔spend-subset coupling (formerly a §13 F1/F3
    /// forward obligation) is **pinned exactly** here: `pseudo_outs.len()` must
    /// equal the `ToKey` input count for every shape, bond-post included
    /// (`GENESIS_TX_WIRE_FORMAT.md` §1.1 coupling closure, 2026-07-05).
    pub fn validate(&self) -> io::Result<()> {
        self.validate_context_free_pruned()?;
        // Prunable-coupled checks: spend-proof completeness that needs the full,
        // non-pruned tx. The pruned ingestion validator above intentionally skips
        // these — the daemon drops the prunable proof on the wallet's pruned fetch.
        if let Ct::Fcmp {
            pqc_auths,
            prunable,
            ..
        } = &self.ct
        {
            let n_in = self.prefix.inputs.len();
            let n_out = self.prefix.outputs.len();
            let n_ki = self.prefix.spend_input_count();
            // Serve-credit also carries a prunable region (`RF-D1`), so
            // "a prunable proof is present" no longer identifies a spend.
            // Typed off the vin, same predicate as parse.
            match prunable {
                // Spend / bond-post: a prunable proof is present AND the tx is
                // not the non-spending serve-credit shape.
                Some(prunable) if !self.prefix.is_serve_credit_only() => {
                    // >= 2 outputs (anti-deanonymization; blockchain.cpp:3599-3602).
                    // Spends are already gated in `validate_context_free_pruned` (keyed
                    // on key-image inputs, pruned-safe); this guards a bond_post, whose
                    // >= 2 rule is prunable-coupled (a fee-only bond_post is 0-output).
                    if n_out < 2 {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: spend/bond_post has {n_out} output(s), needs >= 2"
                        )));
                    }
                    // pqc_auths are per-input (count == nvin): one slot per input,
                    // including the bond_post slot (§2.5 / §13).
                    if pqc_auths.len() != n_in {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: pqc_auths {} != input count {n_in}",
                            pqc_auths.len()
                        )));
                    }
                    // §10: exactly one aggregated Bp+.
                    if prunable.bulletproofs.len() != 1 {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: nbp {} != 1",
                            prunable.bulletproofs.len()
                        )));
                    }
                    // §10 canonical-form corollary: for a well-formed aggregated Bp+
                    // the round count is fully determined by the output count —
                    // `|L| == |R| == 6 + ceil(log2(next_pow2(n_out)))`. The daemon
                    // enforces both directions: `n_padded >= n_out` at parse
                    // (`n_bulletproof_plus_max_amounts < outputs` fails
                    // deserialization, ct_types.h:338) and `n_padded < 2·n_out` at
                    // verify (`n_bulletproof_amounts_base`'s V/L tightness,
                    // ct_types.cpp:234-235, with `V` restored from outPk == n_out).
                    // Without this a tx with a valid output count but an
                    // inconsistent `|L|` passes local validation and dies at the
                    // daemon — a local↔daemon divergence surfacing at submit.
                    let bp = &prunable.bulletproofs[0];
                    // `n_out >= 2` was checked above, so the log2 is well-defined.
                    let expected_lr = 6 + n_out.next_power_of_two().trailing_zeros() as usize;
                    if bp.l.len() != expected_lr || bp.r.len() != expected_lr {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: Bp+ |L|/|R| ({}/{}) != {expected_lr} \
                             required by {n_out} output(s)",
                            bp.l.len(),
                            bp.r.len()
                        )));
                    }
                    // pseudoOuts: one per ToKey (spend) input, exactly. For a pure
                    // fcmp spend this is `pseudoOuts == num_inputs` (blockchain.cpp
                    // spend arm); for a bond-post tx it is the spend subset only
                    // (blockchain.cpp bond-post arm pins `pseudoOuts == num_spend`;
                    // the bond input's cleartext bond_credit rides the CT balance,
                    // not a pseudo-out). Closes the §13 (F1/F3) forward obligation
                    // the earlier exemption deferred.
                    if prunable.pseudo_outs.len() != n_ki {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: pseudoOuts {} != spend (ToKey) input count {n_ki}",
                            prunable.pseudo_outs.len()
                        )));
                    }
                }
                // Fee-only / serve-credit: no SPEND-proof material, no outputs,
                // pqc_auths empty (the classical countersignature rides the
                // vin, §9.10).
                //
                // Reached two ways after `RF-D1`: a genuinely absent prunable
                // region, or the serve-credit shape — whose region exists but
                // holds only pruned pass records, never a spend proof. The
                // arm's checks are the same for both, because what it asserts
                // is the absence of *spend* material, not the absence of a
                // region.
                _ => {
                    if n_out != 0 {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: fee-only ct (no prunable) must have no \
                             outputs, found {n_out}"
                        )));
                    }
                    if !pqc_auths.is_empty() {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: fee-only ct (no prunable) must carry empty \
                             pqc_auths, found {}",
                            pqc_auths.len()
                        )));
                    }
                    // No prunable proof ⇒ no key-image (spend) inputs: a spend requires
                    // a prunable. (The storage-pruned full-spend form — ki inputs,
                    // prunable dropped, external prunable hash — is post-genesis,
                    // handled by §4 `into_full`, not the wire parser.)
                    if n_ki != 0 {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: {n_ki} key-image input(s) but no prunable proof"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether this is a coinbase (miner) transaction: a sole `gen` input (§2.5). The
    /// `Null`-ct coupling is enforced by [`Self::validate_context_free_pruned`]; this is
    /// the input-shape predicate the block parser and the non-miner ingestion path use
    /// to classify a tx — e.g. to reject a coinbase served by `get_transactions`, where
    /// the coinbase is instead embedded in the block blob.
    pub fn is_coinbase(&self) -> bool {
        matches!(self.prefix.inputs.as_slice(), [Input::Gen(_)])
    }

    /// Typed-view conversion (`GENESIS_TX_WIRE_FORMAT.md` §4): succeed only if this tx
    /// carries prunable **spend-proof** data, yielding a [`FullTransaction`] whose
    /// `prunable` is *guaranteed* present. Returns [`PrunedError`] for a coinbase
    /// `Null` ct, a storage-pruned spend, or a serve-credit tx — the last of those
    /// *has* a prunable region after `RF-D1`, but it holds pass records, not an
    /// FCMP++ proof. Typed off the vin, not off `prunable.is_some()`.
    ///
    /// This is the **one boundary** where "pruned tx where full required" is made
    /// unrepresentable — consensus code that requires a full spend takes a
    /// `FullTransaction`, without threading a `Pruned`/`NotPruned` generic through every
    /// consumer (the honest parse result keeps `prunable` as an `Option<Prunable>` on the
    /// `Ct::Fcmp` confidential section).
    pub fn into_full(self) -> Result<FullTransaction, PrunedError> {
        if self.prefix.is_serve_credit_only() {
            return Err(PrunedError);
        }
        match &self.ct {
            Ct::Fcmp {
                prunable: Some(_), ..
            } => Ok(FullTransaction(self)),
            _ => Err(PrunedError),
        }
    }
}

/// The error from [`Transaction::into_full`]: the transaction carries no prunable
/// spend-proof (coinbase `Null`, storage-pruned spend, or serve-credit).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrunedError;

impl core::fmt::Display for PrunedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("transaction carries no prunable proof data (pruned or non-spend)")
    }
}

impl std::error::Error for PrunedError {}

/// A [`Transaction`] *guaranteed* to carry prunable **spend-proof** data — the typed
/// view produced by [`Transaction::into_full`] (`GENESIS_TX_WIRE_FORMAT.md` §4).
/// Constructible only through that conversion, so serve-credit (pass records in the
/// prunable region) and storage-pruned spends are unrepresentable here.
/// Derefs to the underlying [`Transaction`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FullTransaction(Transaction);

impl FullTransaction {
    /// The prunable proof data, guaranteed present by this type's invariant.
    pub fn prunable(&self) -> &Prunable {
        match &self.0.ct {
            Ct::Fcmp {
                prunable: Some(prunable),
                ..
            } => prunable,
            // Only constructed via `Transaction::into_full`, which rejects any tx with
            // no prunable; this arm is unreachable.
            _ => unreachable!("FullTransaction invariant: prunable is present"),
        }
    }

    /// Consume back into the underlying [`Transaction`].
    pub fn into_inner(self) -> Transaction {
        self.0
    }
}

impl core::ops::Deref for FullTransaction {
    type Target = Transaction;
    fn deref(&self) -> &Transaction {
        &self.0
    }
}
