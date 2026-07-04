// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase A — Rust-native admission, no FFI
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.1; parity-matrix rows §8
//! dispatched **A**).
//!
//! Everything here is deterministic over the submitted bytes: hex decode,
//! blob-size cap, `shekyl-wire` parse with exact consumption,
//! **byte-canonicality** (re-serialize == input, the F24 hardening that
//! forecloses non-canonical-encoding txid divergence before it can exist),
//! `Transaction::validate()`, the explicit coinbase-submit rejection (the
//! one live `tx_sanity_check` residue, §8.8), the pool-policy statics
//! (`unlock_time == 0` row P1; the serve-credit zero-fee consensus pin,
//! row N6's static leg), the bond-post structural statics
//! (`ver_non_input_consensus` rows N7's context-free legs), and the
//! key-image domain check (row M8 thin-port). Any failure is
//! `Rejected{Malformed}` — deterministically permanent for these bytes —
//! and C++ is never touched.
//!
//! This is the named front-line untrusted-input surface (§7.6): the §10
//! fuzz target drives [`parse_submission`] with arbitrary strings.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use shekyl_types::{BlockHash, TxHash};
use shekyl_wire::transaction::{Ct, Input, Transaction, MAX_TX_SIZE};

use shekyl_rpc_types::{RejectCause, SubmitVerdict};

/// Shape class of an admissible submission, decided by the input-arm mix
/// (which `shekyl-wire::validate` has already constrained to the §2.5
/// matrix). Phase C keys its check set off this: the ref-age window and
/// membership proof apply to the spending shapes only — the C++ oracle
/// never consults `referenceBlock` for a serve-credit-only tx
/// (`blockchain.cpp:3565-3609` runs no ref checks on that arm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitTxKind {
    /// Regular FCMP++ spend: every input is `txin_to_key`.
    Spend,
    /// Bond-post: one `bond_post` input plus ≥ 1 `txin_to_key` funding
    /// inputs (spending shape; runs the K battery over the funding inputs).
    BondPost,
    /// Fee-only serve-credit: every input is `serve_credit` — non-spending,
    /// no outputs, zero fee by consensus.
    ServeCreditOnly,
}

/// A submission that cleared Phase A: parsed, canonical, statically valid,
/// with the facts later phases need already extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSubmission {
    /// The exact bytes (post hex-decode) — the blob the commit shim stores,
    /// byte-identical to what the engine verified (checked below).
    pub blob: Vec<u8>,
    /// The parsed transaction.
    pub tx: Transaction,
    /// Canonical engine txid (`shekyl-wire` hash; authoritative for the
    /// verdict path per §3.4, release-checked against C++ at commit).
    pub txid: TxHash,
    /// Key images of the `txin_to_key` inputs, in vin order (strictly
    /// descending, enforced by `validate()`). Empty for serve-credit-only.
    pub key_images: Vec<[u8; 32]>,
    /// The wire `referenceBlock` hash. Meaningful for the spending shapes;
    /// present-but-unconsulted for serve-credit-only (oracle parity).
    pub reference_block: BlockHash,
    /// Transaction fee (the `Ct::Fcmp` fee field; 0 for serve-credit-only).
    pub fee: u64,
    /// Consensus transaction weight (serialized size + Bp+ clawback) — the
    /// value the fee floor and weight rule charge against (row I3).
    pub weight: u64,
    /// Shape class for Phase C's check-set dispatch.
    pub kind: SubmitTxKind,
}

/// A Phase-A refusal: wire verdict `Rejected{Malformed}` plus the
/// daemon-side diagnostic (`reason`) for the operator log. The reason
/// never crosses the RPC boundary — §2.2's wire minimalism deleted the
/// `detail` field; operators read logs, wallets read causes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseAReject {
    /// Operator-facing diagnostic, logged daemon-side only.
    pub reason: String,
}

impl PhaseAReject {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// The wire verdict this refusal maps to — always `Malformed` (§3.1:
    /// every Phase-A failure is deterministically permanent for the bytes).
    pub fn verdict(&self) -> SubmitVerdict {
        SubmitVerdict::Rejected {
            cause: RejectCause::Malformed,
        }
    }
}

/// Run Phase A over the submitted hex string.
///
/// On success the transaction is structurally and statically admissible:
/// canonical bytes, canonical shape, known arm mix, valid key-image
/// domain, coinbase excluded, pool statics honored. On failure the
/// submission is `Rejected{Malformed}` with a logged reason; nothing
/// beyond this function has run, so a failure here provably cost no lock
/// and no FFI call.
pub fn parse_submission(tx_hex: &str) -> Result<ParsedSubmission, PhaseAReject> {
    // Bound the decode before allocating: a hex string longer than
    // 2 × MAX_TX_SIZE cannot decode to an admissible blob (row I1's
    // DoS-bounded-decode property, enforced ahead of the allocation
    // rather than after it).
    if tx_hex.len() > MAX_TX_SIZE * 2 {
        return Err(PhaseAReject::new(format!(
            "tx_blob hex length {} exceeds the {} cap",
            tx_hex.len(),
            MAX_TX_SIZE * 2
        )));
    }
    let blob = hex::decode(tx_hex)
        .map_err(|e| PhaseAReject::new(format!("tx_blob is not valid hex: {e}")))?;

    // Parse: size cap + exact consumption (trailing bytes rejected) —
    // rows I1/I2/N1/N2 and the dense-tag arm gate (row M2).
    let tx = Transaction::from_bytes(&blob)
        .map_err(|e| PhaseAReject::new(format!("tx parse failed: {e}")))?;

    // Byte-canonicality (F24 hardening): the parsed value must re-serialize
    // to the exact submitted bytes. A non-canonical encoding (over-long
    // varint, etc.) would otherwise hash differently C++-side than the
    // canonical re-encoding, and the engine's txid would silently diverge
    // from the pool's — rejected here so the divergence class is
    // unrepresentable past Phase A.
    if tx.serialize() != blob {
        return Err(PhaseAReject::new(
            "tx blob is not the canonical serialization of its parse",
        ));
    }

    // Full context-free canonical validation (`shekyl-wire`): structural
    // bounds, arm-mixing matrix, Null-ct-iff-coinbase, empty key_offsets,
    // strictly-descending key images, per-arm archival bounds, committed-
    // base arity, prunable couplings (rows M1-M6, M9, O1-O5, K0-K3, K5,
    // N6's shape leg, and the §10 resource caps).
    tx.validate()
        .map_err(|e| PhaseAReject::new(format!("tx validation failed: {e}")))?;

    // Explicit coinbase-submit rejection (§8.8 rows S1-S3's live residue):
    // a miner tx arrives embedded in a block, never via RPC submit.
    if tx.is_coinbase() {
        return Err(PhaseAReject::new(
            "coinbase transactions cannot be submitted",
        ));
    }

    // Pool-policy static (row P1): pool admission requires unlock_time == 0
    // exactly (`add_tx`'s nonzero_unlock_time reject, tx_pool.cpp:204-211).
    // validate() only bounds it to the block-height form; the pool pin is
    // stricter.
    if tx.prefix.unlock_time != 0 {
        return Err(PhaseAReject::new(format!(
            "nonzero unlock_time {} (pool policy requires 0)",
            tx.prefix.unlock_time
        )));
    }

    // Arm-mix classification. validate() has already enforced the §2.5
    // matrix (serve-credit all-or-none, ≤ 1 bond-post, gen sole ⇒ rejected
    // above), so this is a total match over the remaining shapes.
    let mut n_to_key = 0usize;
    let mut n_serve_credit = 0usize;
    let mut n_bond_post = 0usize;
    let mut key_images: Vec<[u8; 32]> = Vec::new();
    for input in &tx.prefix.inputs {
        match input {
            Input::ToKey { key_image, .. } => {
                n_to_key += 1;
                key_images.push(*key_image);
            }
            Input::ServeCredit(_) => n_serve_credit += 1,
            Input::BondPost(_) => n_bond_post += 1,
            Input::Gen(_) => {
                // Unreachable: gen-mixed rejected by validate(), gen-sole
                // rejected by the coinbase gate above. Keep it a loud
                // refusal rather than an unreachable!() panic — Phase A is
                // the untrusted-input surface (§7.6) and must not be
                // panickable by construction.
                return Err(PhaseAReject::new("gen input in a non-coinbase submission"));
            }
        }
    }
    let kind = if n_serve_credit > 0 {
        // validate(): serve-credit never mixes; all inputs are serve-credit.
        SubmitTxKind::ServeCreditOnly
    } else if n_bond_post == 1 {
        SubmitTxKind::BondPost
    } else {
        SubmitTxKind::Spend
    };

    // The ct section: coinbase (Null) is already rejected, so this is
    // always Fcmp — but stay non-panicking per the §7.6 posture.
    let (fee, reference_block) = match &tx.ct {
        Ct::Fcmp {
            fee,
            reference_block,
            ..
        } => (*fee, BlockHash::from_bytes(*reference_block)),
        Ct::Null(_) => {
            return Err(PhaseAReject::new("Null ct on a non-coinbase submission"));
        }
    };

    // Serve-credit consensus statics (row N6's static legs, pinned at
    // `tx_verification_utils.cpp:120-139` / `blockchain.cpp:3565-3597`):
    // zero fee is a consensus rule for the non-spending arm. The
    // no-outputs / no-pqc-auths / no-prunable shape is already validate()'s
    // fee-only coupling; the fee pin is the engine's to add.
    if kind == SubmitTxKind::ServeCreditOnly && fee != 0 {
        return Err(PhaseAReject::new(format!(
            "serve-credit tx must carry zero fee, found {fee}"
        )));
    }

    // Bond-post structural statics (row N7's context-free legs, pinned at
    // `tx_verification_utils.cpp:151-153` / `blockchain.cpp:3635-3649`):
    // ≥ 1 txin_to_key funding input, and pseudoOuts arity == funding-input
    // count (validate() exempts the bond-post shape from its pure-spend
    // pseudoOuts rule, so the engine owns this arity).
    //
    // Known consequence, deliberate: the C++ *wire* layer pins
    // `pseudoOuts == vin.size()` (rctTypes.h:399-401, mirrored by
    // `shekyl-wire`'s per-input read), while this consensus rule demands
    // `== funding count` — contradictory whenever a bond-post input is
    // present, so every wire-parseable funded bond-post rejects here
    // exactly as it rejects at `ver_non_input_consensus` in C++. Parity
    // preserved; the resolution is the §13 (F1/F3) wire reshape, not an
    // engine-side relaxation.
    if kind == SubmitTxKind::BondPost {
        if n_to_key == 0 {
            return Err(PhaseAReject::new(
                "bond-post tx requires at least one txin_to_key funding input",
            ));
        }
        if let Ct::Fcmp {
            prunable: Some(prunable),
            ..
        } = &tx.ct
        {
            if prunable.pseudo_outs.len() != n_to_key {
                return Err(PhaseAReject::new(format!(
                    "bond-post pseudoOuts count {} != funding input count {n_to_key}",
                    prunable.pseudo_outs.len()
                )));
            }
        }
    }

    // Spending shapes must carry a non-empty membership proof (row K11's
    // static leg; `blockchain.cpp:3682-3687` and the regular-path
    // equivalent). validate() guarantees `prunable` is present whenever
    // key images exist; emptiness of the proof bytes is the engine's gate.
    if matches!(kind, SubmitTxKind::Spend | SubmitTxKind::BondPost) {
        let proof_empty = match &tx.ct {
            Ct::Fcmp {
                prunable: Some(prunable),
                ..
            } => prunable.fcmp_proof.is_empty(),
            _ => true,
        };
        if proof_empty {
            return Err(PhaseAReject::new("spending tx has an empty FCMP++ proof"));
        }
    }

    // Key-image domain (row M8 thin-port of
    // `core::check_tx_inputs_keyimages_domain`, cryptonote_core.cpp:
    // 1041-1057): non-identity AND in the prime-order subgroup
    // (`l·ki == identity`). The engine additionally requires the canonical
    // compressed encoding (re-compress == input): the C++ oracle's
    // `ge_frombytes_vartime` tolerates a subset of non-canonical encodings,
    // but admission-side strictness is safe — a wallet-built tx always
    // carries canonical points, and the descending-order rule (§12) is
    // byte-order over exactly this encoding.
    for (i, ki) in key_images.iter().enumerate() {
        let point = CompressedEdwardsY(*ki)
            .decompress()
            .ok_or_else(|| PhaseAReject::new(format!("key image {i} is not a curve point")))?;
        if point.compress().as_bytes() != ki {
            return Err(PhaseAReject::new(format!(
                "key image {i} is a non-canonical point encoding"
            )));
        }
        if point.is_identity() {
            return Err(PhaseAReject::new(format!("key image {i} is the identity")));
        }
        if !point.is_torsion_free() {
            return Err(PhaseAReject::new(format!(
                "key image {i} is outside the prime-order subgroup"
            )));
        }
    }

    // Canonical engine txid (§3.4) and consensus weight (row I3), both
    // over the validated canonical bytes.
    let txid = TxHash::from_bytes(tx.hash());
    let weight = tx.weight() as u64;

    Ok(ParsedSubmission {
        blob,
        tx,
        txid,
        key_images,
        reference_block,
        fee,
        weight,
        kind,
    })
}
