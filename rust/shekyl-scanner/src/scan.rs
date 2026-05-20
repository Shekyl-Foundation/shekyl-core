// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Block and transaction scanning pipeline using hybrid PQC KEM.
//!
//! Scans `ScannableBlock`s for outputs belonging to the wallet's view pair,
//! using the Shekyl V3 two-component key derivation:
//!
//! 1. Parse `tx_extra` for PQC KEM ciphertext (tag 0x06)
//! 2. X25519 DH pre-filter via view tag (rejects ~99.6% of non-matching outputs)
//! 3. Full hybrid KEM decap + HKDF via `scan_output_recover`
//! 4. Subaddress lookup via recovered spend key `B' = O - ho*G - y*T`
//! 5. Key image computation via native Rust (no FFI)

use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use shekyl_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    transaction::{Pruned, Transaction},
};
use shekyl_rpc::ScannableBlock;

use shekyl_crypto_pq::{
    kem::{HybridCiphertext, ML_KEM_768_CT_LEN},
    key_image::KeyImage,
    output::{compute_output_key_image, scan_output_recover},
};
use shekyl_generators::hash_to_point;

use crate::{extra::Extra, output::*, GuaranteedViewPair, SubaddressIndex, ViewPair};

const X25519_CT_BYTES: usize = 32;
const HYBRID_KEM_CT_BYTES: usize = X25519_CT_BYTES + ML_KEM_768_CT_LEN;

/// Maximum number of outputs a single transaction may carry under
/// Shekyl V3 consensus, mirroring the FCMP++ Bulletproofs+ commitment
/// cap.
///
/// # Defense-in-depth posture
///
/// The scanner enforces this bound at `InternalScanner::scan_transaction`
/// entry — *before* any per-output decap or key-image derivation runs —
/// so that an adversarial daemon delivering oversized transactions
/// cannot inflate the wallet's per-tx scan-time budget. Consensus
/// validation will eventually reject any such transaction, but the
/// scanner does not depend on that timing: it bounds its own per-tx
/// loop independently. The check is O(1) (single integer compare) and
/// converts the §3.1 sub-block lock-latency reasoning from "unbounded
/// per-tx work under adversarial daemon block crafting" to "bounded
/// per-tx work with N ≤ [`MAX_OUTPUTS`] by construction", which is
/// what the F11-S audit-trail measurement in PR 4 §5.4.9 binds
/// against. See `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §3.1
/// and the C4 F11-S measurement commit-body for the full rationale.
///
/// # Cross-references
///
/// Three mirror sites name the same `16` constant in the workspace.
/// The canonical source of truth is
/// [`shekyl_generators::MAX_BULLETPROOF_COMMITMENTS`] — the value the
/// Bulletproofs+ CRS is generated against; loosening it without
/// regenerating generators would break verification. The other
/// mirrors are:
///
/// - `shekyl_tx_builder::MAX_OUTPUTS` — builder-side prover cap (a
///   transaction signer cannot construct a tx with more outputs than
///   the BP+ CRS supports). Not an intra-doc link because
///   `shekyl-scanner` does not depend on `shekyl-tx-builder`.
/// - This constant — scanner-side defense-in-depth gate.
///
/// The single-direction `const_assert!` below couples this constant
/// to the canonical bound; a future bump of
/// `MAX_BULLETPROOF_COMMITMENTS` will fire a build error here until
/// the scanner gate is intentionally re-decided.
pub const MAX_OUTPUTS: usize = 16;

// Single-direction enforcement against the canonical source of truth.
// `shekyl_generators::MAX_BULLETPROOF_COMMITMENTS` is the
// Bulletproofs+ CRS size; the scanner gate must agree by construction.
// `shekyl-tx-builder` carries its own assertion against the same
// canonical, so a future loosening of the canonical bound fires CI in
// every mirror crate independently rather than triangulating through
// any single crate.
const _: () = assert!(
    MAX_OUTPUTS == shekyl_generators::MAX_BULLETPROOF_COMMITMENTS,
    "shekyl-scanner MAX_OUTPUTS must match shekyl_generators::MAX_BULLETPROOF_COMMITMENTS (Bulletproofs+ CRS size)",
);

/// A recovered output with all PQC secrets populated at scan time.
///
/// Carries the HKDF-derived secrets (ho, y, z, k_amount), combined shared secret,
/// and key image so that `TransferDetails` can be fully populated without
/// re-derivation. Implements `ZeroizeOnDrop` — secrets are wiped when this
/// struct leaves scope.
///
/// In addition to the secret residue, the struct preserves the **public
/// on-chain residue** the engine post-pass needs to reconstruct an
/// `OutputDetectionInput` (per
/// `docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §3): the per-output
/// hybrid ciphertext, view tag, encrypted amount, and amount tag. These
/// fields are **non-secret** (structurally public on-chain data) and
/// skip wipe via `#[zeroize(skip)]`, matching the `key_image` /
/// `amount` discipline. They are scoped `pub(crate)` so the scanner
/// can produce them, while the orchestrator reads them via the
/// dedicated accessors below.
#[derive(ZeroizeOnDrop)]
pub struct RecoveredWalletOutput {
    pub(crate) base: WalletOutput,
    pub(crate) ho: Zeroizing<[u8; 32]>,
    pub(crate) y: Zeroizing<[u8; 32]>,
    pub(crate) z: Zeroizing<[u8; 32]>,
    pub(crate) k_amount: Zeroizing<[u8; 32]>,
    pub(crate) combined_shared_secret: Zeroizing<[u8; 64]>,
    /// Per-output key image. Public on-chain double-spend identifier;
    /// see [`KeyImage`]'s doc-comment — public derivative of a secret,
    /// the secret is the wipe-on-drop concern (the typed wrapper does
    /// **not** impl [`Zeroize`] for that reason). `#[zeroize(skip)]`
    /// matches the `amount` field's pattern: structurally non-secret
    /// values that survive `Drop`'s wipe pass.
    #[zeroize(skip)]
    pub(crate) key_image: KeyImage,
    /// Recovered amount from KEM decryption.
    #[zeroize(skip)]
    pub(crate) amount: u64,
    /// Per-output hybrid ciphertext (X25519 || ML-KEM-768). Public
    /// on-chain residue. The engine post-pass re-decapsulates against
    /// it to produce the deterministic `OutputHandle`.
    #[zeroize(skip)]
    pub(crate) source_ciphertext: HybridCiphertext,
    /// One-byte view tag carried in the on-chain output. Public.
    #[zeroize(skip)]
    pub(crate) view_tag: u8,
    /// Encrypted amount bytes from `RctSignaturesBase::encrypted_amounts`.
    /// Public on-chain residue.
    #[zeroize(skip)]
    pub(crate) enc_amount: [u8; 8],
    /// One-byte amount tag carried alongside `enc_amount`. Public.
    #[zeroize(skip)]
    pub(crate) amount_tag: u8,
}

impl Zeroize for RecoveredWalletOutput {
    fn zeroize(&mut self) {
        self.base.zeroize();
        self.ho.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.k_amount.zeroize();
        self.combined_shared_secret.zeroize();
        // `self.key_image`, `self.amount`, `self.source_ciphertext`,
        // `self.view_tag`, `self.enc_amount`, `self.amount_tag` are
        // public on-chain data, not secret — they deliberately skip
        // wipe per the field-level `#[zeroize(skip)]` discipline above.
    }
}

impl RecoveredWalletOutput {
    pub fn wallet_output(&self) -> &WalletOutput {
        &self.base
    }
    pub fn ho(&self) -> &[u8; 32] {
        &self.ho
    }
    pub fn y(&self) -> &[u8; 32] {
        &self.y
    }
    pub fn z(&self) -> &[u8; 32] {
        &self.z
    }
    pub fn k_amount(&self) -> &[u8; 32] {
        &self.k_amount
    }
    pub fn combined_shared_secret(&self) -> &[u8; 64] {
        &self.combined_shared_secret
    }
    pub fn key_image(&self) -> &KeyImage {
        &self.key_image
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    /// The public on-chain hybrid ciphertext (X25519 || ML-KEM-768)
    /// preserved from scan time. Consumed by the engine post-pass in
    /// `shekyl-engine-core::engine::merge` to reconstruct
    /// `OutputDetectionInput` and call `KeyEngine::try_claim_output`.
    pub fn source_ciphertext(&self) -> &HybridCiphertext {
        &self.source_ciphertext
    }
    /// One-byte view tag carried in the on-chain output.
    pub fn view_tag(&self) -> u8 {
        self.view_tag
    }
    /// Encrypted amount bytes from `RctSignaturesBase::encrypted_amounts`.
    pub fn enc_amount(&self) -> &[u8; 8] {
        &self.enc_amount
    }
    /// One-byte amount tag carried alongside `enc_amount`.
    pub fn amount_tag(&self) -> u8 {
        self.amount_tag
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(base: WalletOutput, amount: u64) -> Self {
        Self {
            base,
            ho: Zeroizing::new([0u8; 32]),
            y: Zeroizing::new([0u8; 32]),
            z: Zeroizing::new([0u8; 32]),
            k_amount: Zeroizing::new([0u8; 32]),
            combined_shared_secret: Zeroizing::new([0u8; 64]),
            key_image: KeyImage::from_canonical_bytes([0u8; 32]),
            amount,
            // Synthetic test fixtures don't exercise the engine
            // post-pass: residue is carried through `RecoveredWalletOutput`
            // → `DetectedTransfer` → `ScanResult` for the post-pass
            // (`engine::merge::populate_engine_handle_fields`) to
            // populate `td.source_ciphertext` and derive
            // `td.output_handle`, but the in-tree tests that
            // construct `RecoveredWalletOutput` via `new_for_test`
            // assert on accumulator/balance behaviour, not on these
            // residue fields. Empty defaults are fine; future tests
            // that DO assert on the engine post-pass should populate
            // real ciphertext bytes so the derived `output_handle`
            // is meaningful.
            source_ciphertext: HybridCiphertext {
                x25519: [0u8; 32],
                ml_kem: Vec::new(),
            },
            view_tag: 0,
            enc_amount: [0u8; 8],
            amount_tag: 0,
        }
    }
}

/// A collection of recovered outputs from a block scan.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Timelocked(pub(crate) Vec<RecoveredWalletOutput>);

impl Timelocked {
    /// Create a Timelocked collection from a vector of outputs.
    pub fn from_vec(outputs: Vec<RecoveredWalletOutput>) -> Self {
        Self(outputs)
    }

    /// Consume the wrapper and return all outputs.
    #[must_use]
    pub fn into_inner(mut self) -> Vec<RecoveredWalletOutput> {
        let mut res = vec![];
        core::mem::swap(&mut self.0, &mut res);
        res
    }

    /// The number of outputs in this collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Errors when scanning a block.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ScanError {
    /// The block was for an unsupported protocol version.
    #[error("unsupported protocol version ({0})")]
    UnsupportedProtocol(u8),
    /// The ScannableBlock was invalid.
    #[error("invalid scannable block ({0})")]
    InvalidScannableBlock(&'static str),
}

#[derive(Clone)]
struct InternalScanner {
    pair: ViewPair,
    spend_secret: Zeroizing<[u8; 32]>,
    subaddresses: HashMap<CompressedPoint, Option<SubaddressIndex>>,
}

impl Zeroize for InternalScanner {
    fn zeroize(&mut self) {
        self.pair.zeroize();
        self.spend_secret.zeroize();
        for (mut key, mut value) in self.subaddresses.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
}
impl Drop for InternalScanner {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for InternalScanner {}

impl InternalScanner {
    fn new(pair: ViewPair, spend_secret: Zeroizing<[u8; 32]>) -> Self {
        let mut subaddresses = HashMap::new();
        subaddresses.insert(pair.spend().compress().into(), None);
        Self {
            pair,
            spend_secret,
            subaddresses,
        }
    }

    fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
        let (spend, _) = self.pair.subaddress_keys(subaddress);
        self.subaddresses
            .insert(spend.compress().into(), Some(subaddress));
    }

    fn scan_transaction(
        &self,
        output_index_for_first_ringct_output: u64,
        tx_hash: [u8; 32],
        tx: &Transaction<Pruned>,
    ) -> Result<Timelocked, ScanError> {
        // Defense-in-depth size gate (PR 4 §3.1 / F11-S substrate). The
        // wallet's trust model treats the daemon as adversarial; a
        // hostile daemon could (pre-consensus rejection) deliver
        // transactions whose output count exceeds the FCMP++
        // Bulletproofs+ CRS size and inflate the per-tx scan budget
        // arbitrarily. Bound the per-tx work at the scanner's own
        // entry rather than depending on consensus validation timing.
        //
        // Skip-and-log shape: an oversized transaction is silently
        // skipped (returns the empty `Timelocked`) and a `WARN` event
        // fires for observability. Engine-side diagnostic emission
        // (`RefreshDiagnostic::DaemonMalformed { kind: ExcessiveOutputs }`)
        // lands in PR 4 C4 via a pre-pass over the block's per-tx
        // output counts inside `produce_scan_result`; the scanner
        // does not depend on the engine-core's `DiagnosticSink` trait
        // to preserve the existing layering.
        let output_count = tx.prefix().outputs.len();
        if output_count > MAX_OUTPUTS {
            tracing::warn!(
                target: "shekyl_scanner::scan",
                output_count,
                max_outputs = MAX_OUTPUTS,
                "scanner: skipping transaction with excessive output count (defense-in-depth gate; consensus would also reject)"
            );
            return Ok(Timelocked(vec![]));
        }

        if tx.version() != 2 {
            return Ok(Timelocked(vec![]));
        }

        let Ok(extra) = Extra::read(&mut tx.prefix().extra.as_slice()) else {
            return Ok(Timelocked(vec![]));
        };

        let kem_ct_blob = extra.pqc_kem_ciphertext();
        let payment_id = extra.payment_id();

        let mut res = vec![];
        for (o, output) in tx.prefix().outputs.iter().enumerate() {
            let Some(output_key_point) = output.key.decompress() else {
                continue;
            };
            let output_key_bytes = output_key_point.compress().to_bytes();

            let view_tag_on_chain: u8 = output.view_tag.unwrap_or(0);

            let (enc_amount, amount_tag_on_chain, commitment_bytes) = match &tx {
                Transaction::V2 {
                    proofs: Some(ref proofs),
                    ..
                } => match proofs.base.encrypted_amounts.get(o) {
                    Some(ea) => {
                        let c = proofs.base.commitments.get(o).ok_or(
                            ScanError::InvalidScannableBlock(
                                "proofs without a commitment per output",
                            ),
                        )?;
                        (ea.amount, ea.amount_tag, c.0)
                    }
                    None => continue,
                },
                _ => {
                    if output.amount.is_some() {
                        ([0u8; 8], 0u8, [0u8; 32])
                    } else {
                        continue;
                    }
                }
            };

            // --- Try KEM path (tag 0x06) ---
            let Some(blob) = kem_ct_blob else { continue };
            let ct_offset = o * HYBRID_KEM_CT_BYTES;
            if blob.len() < ct_offset + HYBRID_KEM_CT_BYTES {
                continue;
            }

            let ct_slice = &blob[ct_offset..ct_offset + HYBRID_KEM_CT_BYTES];
            let ct_x25519: &[u8; 32] = ct_slice[..X25519_CT_BYTES]
                .try_into()
                .expect("slice is exactly 32 bytes");
            let ct_ml_kem = &ct_slice[X25519_CT_BYTES..];
            debug_assert_eq!(ct_ml_kem.len(), ML_KEM_768_CT_LEN);

            let Ok(recovered) = scan_output_recover(
                self.pair.x25519_sk(),
                self.pair.ml_kem_dk(),
                ct_x25519,
                ct_ml_kem,
                &output_key_bytes,
                &commitment_bytes,
                &enc_amount,
                amount_tag_on_chain,
                view_tag_on_chain,
                o as u64,
            ) else {
                continue;
            };

            // --- Subaddress lookup via recovered spend key B' ---
            let recovered_b_compressed: CompressedPoint =
                CompressedPoint(recovered.recovered_spend_key);
            let Some(subaddress) = self.subaddresses.get(&recovered_b_compressed) else {
                continue;
            };
            let subaddress = *subaddress;

            let amount = recovered.amount;
            let commitment = Commitment::new(
                curve25519_dalek::Scalar::from_canonical_bytes(recovered.z)
                    .expect("z from wide_reduce is always canonical"),
                amount,
            );

            // --- Key image: KI = x * Hp(O) where x = ho + b ---
            let hp_of_o = hash_to_point(output_key_bytes);
            let hp_bytes = hp_of_o.compress().to_bytes();

            let ki_result = compute_output_key_image(
                &recovered.combined_ss,
                o as u64,
                &self.spend_secret,
                &hp_bytes,
            );
            let key_image = match ki_result {
                Ok(r) => r.key_image,
                Err(_) => continue,
            };

            // V3 does not use encrypted payment IDs. Pass through as-is.
            let decrypted_payment_id = payment_id;

            let global_index = output_index_for_first_ringct_output
                .checked_add(o as u64)
                .ok_or(ScanError::InvalidScannableBlock(
                    "transaction's output's index isn't representable as a u64",
                ))?;

            let base_output = WalletOutput {
                absolute_id: AbsoluteId {
                    transaction: tx_hash,
                    index_in_transaction: o as u64,
                },
                relative_id: RelativeId {
                    index_on_blockchain: global_index,
                },
                data: OutputData {
                    key: output_key_point,
                    key_offset: curve25519_dalek::Scalar::from_canonical_bytes(recovered.ho)
                        .expect("ho from wide_reduce is always canonical"),
                    commitment,
                },
                metadata: Metadata {
                    additional_timelock: tx.prefix().additional_timelock,
                    subaddress,
                    payment_id: decrypted_payment_id,
                    arbitrary_data: extra.arbitrary_data(),
                },
                staking: output.staking,
            };

            res.push(RecoveredWalletOutput {
                base: base_output,
                ho: Zeroizing::new(recovered.ho),
                y: Zeroizing::new(recovered.y),
                z: Zeroizing::new(recovered.z),
                k_amount: Zeroizing::new(recovered.k_amount),
                combined_shared_secret: Zeroizing::new(recovered.combined_ss),
                key_image,
                amount,
                source_ciphertext: HybridCiphertext {
                    x25519: *ct_x25519,
                    ml_kem: ct_ml_kem.to_vec(),
                },
                view_tag: view_tag_on_chain,
                enc_amount,
                amount_tag: amount_tag_on_chain,
            });
        }

        Ok(Timelocked(res))
    }

    fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
        let ScannableBlock {
            block,
            transactions,
            output_index_for_first_ringct_output,
        } = block;
        if block.transactions.len() != transactions.len() {
            Err(ScanError::InvalidScannableBlock(
                "scanning a ScannableBlock with more/less transactions than it should have",
            ))?;
        }
        let Some(mut output_index_for_first_ringct_output) = output_index_for_first_ringct_output
        else {
            return Ok(Timelocked(vec![]));
        };

        if block.header.hardfork_version < 1 {
            Err(ScanError::UnsupportedProtocol(
                block.header.hardfork_version,
            ))?;
        }

        let mut txs_with_hashes = vec![(
            block.miner_transaction().hash(),
            Transaction::<Pruned>::from(block.miner_transaction().clone()),
        )];
        for (hash, tx) in block.transactions.iter().zip(transactions) {
            txs_with_hashes.push((*hash, tx));
        }

        let mut res = Timelocked(vec![]);
        for (hash, tx) in txs_with_hashes {
            {
                let mut this_txs_outputs = vec![];
                core::mem::swap(
                    &mut self
                        .scan_transaction(output_index_for_first_ringct_output, hash, &tx)?
                        .0,
                    &mut this_txs_outputs,
                );
                res.0.extend(this_txs_outputs);
            }

            if matches!(tx, Transaction::V2 { .. }) {
                output_index_for_first_ringct_output += u64::try_from(tx.prefix().outputs.len())
                    .expect("couldn't convert amount of outputs (usize) to u64")
            }
        }

        // Note: Shekyl V3 dropped the legacy unencrypted PaymentId variant outright.
        // `PaymentId::read` refuses marker byte 0 at parse time, so `output.metadata.payment_id`
        // is guaranteed to be either `None` or `Some(encrypted_8_bytes)` — no runtime strip
        // pass is needed here.

        Ok(res)
    }
}

/// A transaction scanner using hybrid PQC KEM (X25519 + ML-KEM-768).
///
/// Scans blocks for outputs belonging to this wallet. When an output is found,
/// its key MUST be checked against the local database for prior observation
/// (burning bug protection).
///
/// The scanner computes key images at scan time. All HKDF-derived secrets
/// (ho, y, z, k_amount) are stored in the returned `RecoveredWalletOutput`
/// to avoid re-derivation at sign time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scanner(InternalScanner);

impl Scanner {
    /// Create a Scanner from a ViewPair and the wallet's spend secret key.
    ///
    /// The spend secret is needed to compute key images at scan time
    /// (KI = (ho + b) * Hp(O)).
    pub fn new(pair: ViewPair, spend_secret: Zeroizing<[u8; 32]>) -> Self {
        Self(InternalScanner::new(pair, spend_secret))
    }

    /// Register a subaddress to scan for.
    pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
        self.0.register_subaddress(subaddress)
    }

    /// Scan a block for outputs belonging to this wallet.
    pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
        self.0.scan(block)
    }
}

/// A scanner that guarantees scanned outputs are spendable (burning-bug immune).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GuaranteedScanner(InternalScanner);

impl GuaranteedScanner {
    /// Create a GuaranteedScanner from a GuaranteedViewPair and spend secret.
    pub fn new(pair: GuaranteedViewPair, spend_secret: Zeroizing<[u8; 32]>) -> Self {
        Self(InternalScanner::new(pair.0, spend_secret))
    }

    /// Register a subaddress to scan for.
    pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
        self.0.register_subaddress(subaddress)
    }

    /// Scan a block for outputs belonging to this wallet.
    pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
        self.0.scan(block)
    }
}

/// Tests for the scanner-side defense-in-depth size gate on
/// [`InternalScanner::scan_transaction`] (PR 4 §3.1 / F11-S
/// substrate). The gate skips any transaction whose output count
/// exceeds [`MAX_OUTPUTS`] before any per-output decap runs and emits
/// a `WARN`-level tracing event for observability. These tests pin
/// the behavioural contract: skip-and-log shape, return value
/// `Ok(Timelocked::empty())`, and event firing at the documented
/// target. They live in the same module as [`InternalScanner`]
/// because the type is module-private; the established
/// `crate::tests` location is for behavioural tests of public
/// surfaces.
#[cfg(test)]
mod gate_tests {
    use std::sync::{Arc, Mutex};

    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use tracing::{
        span::{Attributes, Id, Record},
        Event, Level, Metadata, Subscriber,
    };

    use shekyl_oxide::transaction::{
        Input, Output, Pruned, Timelock, Transaction, TransactionPrefix,
    };

    use super::*;
    use crate::view_pair::ViewPair;

    /// A minimal [`tracing::Subscriber`] that records every event's
    /// `(Level, target)` pair into a shared vector. The
    /// implementation is intentionally hand-rolled to avoid pulling
    /// `tracing-subscriber` (or `tracing-test`) in as a dev
    /// dependency for a single assertion. Span lifecycle methods are
    /// no-ops; the gate-firing tests only care about events.
    #[derive(Clone, Default)]
    struct EventCapture {
        events: Arc<Mutex<Vec<(Level, &'static str)>>>,
    }

    impl Subscriber for EventCapture {
        fn enabled(&self, _meta: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
            // `Id::from_u64(0)` is reserved by `tracing`; any other
            // non-zero value satisfies the contract for a subscriber
            // that does not track per-span identity.
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let meta = event.metadata();
            self.events
                .lock()
                .expect("event-capture mutex poisoned")
                .push((*meta.level(), meta.target()));
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    /// Build an [`InternalScanner`] with placeholder keys. The gate
    /// fires before any cryptographic state is touched, so the
    /// scanner only needs to construct successfully — the
    /// [`ViewPair`] torsion check is satisfied by the basepoint, and
    /// the empty PQC key material is never read on the gate path.
    fn placeholder_scanner() -> InternalScanner {
        let pair = ViewPair::new(
            ED25519_BASEPOINT_POINT,
            Zeroizing::new(Scalar::ONE),
            Zeroizing::new([0u8; 32]),
            Zeroizing::new(Vec::new()),
        )
        .expect("basepoint is torsion-free");
        InternalScanner::new(pair, Zeroizing::new([0u8; 32]))
    }

    /// Build a non-miner v2 `Transaction<Pruned>` with the requested
    /// number of outputs. The output bytes themselves are placeholder
    /// (zero key, no view tag); they are never inspected on the gate
    /// path (the gate fires before per-output decap), and on the
    /// at-boundary test path the zero key fails to decompress so
    /// each output iteration `continue`s without recovering anything.
    fn synthesize_tx(output_count: usize) -> Transaction<Pruned> {
        let outputs = (0..output_count)
            .map(|_| Output {
                amount: None,
                key: CompressedPoint([0u8; 32]),
                view_tag: None,
                staking: None,
            })
            .collect();
        Transaction::V2 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::None,
                // Non-miner classification — [`Input::ToKey`] (rather
                // than [`Input::Gen`]) so the tx is treated as a
                // normal user transaction subject to the per-tx
                // output cap documented on [`MAX_OUTPUTS`]. The
                // input fields are placeholders; `scan_transaction`
                // never inspects the input vector.
                inputs: vec![Input::ToKey {
                    amount: None,
                    key_offsets: vec![1],
                    key_image: CompressedPoint([0u8; 32]),
                }],
                outputs,
                extra: vec![],
            },
            proofs: None,
        }
    }

    #[test]
    fn skips_transaction_with_output_count_above_max() {
        let scanner = placeholder_scanner();
        let tx = synthesize_tx(MAX_OUTPUTS + 1);

        let capture = EventCapture::default();
        let result = tracing::subscriber::with_default(capture.clone(), || {
            scanner.scan_transaction(0, [0u8; 32], &tx)
        });

        let timelocked = result.expect("gate skips the tx without surfacing a ScanError");
        assert!(
            timelocked.is_empty(),
            "gate must return Timelocked::empty() for oversized transactions"
        );

        let events = capture
            .events
            .lock()
            .expect("event-capture mutex poisoned")
            .clone();
        let warn_at_target = events
            .iter()
            .any(|(level, target)| *level == Level::WARN && *target == "shekyl_scanner::scan");
        assert!(
            warn_at_target,
            "gate must emit a WARN-level tracing event at target `shekyl_scanner::scan` (events seen: {events:?})"
        );
    }

    #[test]
    fn admits_transaction_at_exact_max_outputs() {
        // Boundary check: the gate fires on STRICTLY greater than
        // `MAX_OUTPUTS`. A transaction with exactly `MAX_OUTPUTS`
        // outputs proceeds past the gate and into the normal scan
        // path (which will, with placeholder keys / empty extra,
        // surface no owned outputs but does NOT short-circuit at
        // the gate).
        let scanner = placeholder_scanner();
        let tx = synthesize_tx(MAX_OUTPUTS);

        let capture = EventCapture::default();
        let result = tracing::subscriber::with_default(capture.clone(), || {
            scanner.scan_transaction(0, [0u8; 32], &tx)
        });

        let timelocked =
            result.expect("at-boundary tx scans without ScanError under placeholder keys");
        assert!(
            timelocked.is_empty(),
            "placeholder keys recover no owned outputs, so the Timelocked is empty by absence-of-match, not by gate-trigger"
        );

        let events = capture
            .events
            .lock()
            .expect("event-capture mutex poisoned")
            .clone();
        let warn_at_target = events
            .iter()
            .any(|(level, target)| *level == Level::WARN && *target == "shekyl_scanner::scan");
        assert!(
            !warn_at_target,
            "gate must NOT fire at the boundary (output_count == MAX_OUTPUTS); WARN events seen: {events:?}"
        );
    }
}
