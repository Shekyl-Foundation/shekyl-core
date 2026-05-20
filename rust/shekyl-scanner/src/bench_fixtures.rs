// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bench fixture helpers for [`Scanner::scan`] per-output cost
//! measurement (PR 4 §3.1 / F11-S substrate).
//!
//! ## Why this module lives in `src/` (not `benches/`)
//!
//! Two bench binaries (`scan_transaction` criterion harness and
//! `scan_transaction_iai` iai-callgrind companion) share the same
//! transaction-shape fixtures. Cargo compiles each `benches/*.rs` file
//! as an independent binary, so a shared fixture has to live somewhere
//! both binaries can `use`. The crate's `[[bench]]` entries depend on
//! `shekyl-scanner` via the existing `test-utils`-feature self-dep
//! (the same pattern already used by `benches/scan_block.rs` for
//! `WalletOutput::new_for_test`), so guarding this module behind
//! `#[cfg(any(test, feature = "test-utils"))]` keeps the fixture out
//! of the production crate surface while letting both benches reach
//! it through `shekyl_scanner::bench_fixtures::…`.
//!
//! The placement also makes the fixture's **sanity-check tests**
//! (below) part of the normal `cargo test --features test-utils -p
//! shekyl-scanner` surface, so CI catches construction bugs that
//! would otherwise silently invalidate the F11-S measurement.
//!
//! ## Two fixture shapes
//!
//! ### `build_worst_case_scannable_block` — F11-S binding
//!
//! Every output's view tag matches the test wallet, forcing the full
//! hybrid PQC slow path (X25519 ECDH + ML-KEM-768 decap + HKDF +
//! amount/commitment verification) on every output. This is the
//! adversarial-daemon worst-case under the PR 4 §3.1 threat model:
//! the daemon knows the wallet's hybrid public keys (they're public
//! by virtue of being part of the wallet's address) and can therefore
//! call [`construct_output`] against them to produce on-chain
//! ciphertexts that pass every cryptographic check inside
//! [`scan_output_recover`]. The output is filtered out at the very
//! end (subaddress-table lookup misses, because the constructed
//! recovered-`B'` is the [`ED25519_BASEPOINT_POINT`] fake spend key,
//! not the scanner's registered spend key), but the per-output
//! cryptographic cost has already been paid in full. This is the
//! quantile-binding measurement for F11-S: worst-case per-output
//! cost = full slow-path cost.
//!
//! The constant-time property of all primitives involved (ML-KEM-768
//! decap per FIPS-203 §7, X25519 scalar-multiplication via
//! curve25519-dalek, HKDF combine on fixed inputs) means no
//! pathological fixture exists that could exceed the all-view-tags-
//! match cost; the worst case is captured completely by this shape.
//!
//! ### `build_typical_case_scannable_block` — contextual, NOT F11-S
//!
//! Outputs are encapsulated against a *different* wallet's hybrid
//! public keys. The scanner's X25519 ECDH against the on-chain
//! ephemeral produces a different shared secret than the encapsulator
//! used, so the wallet-side view tag derivation diverges from the
//! on-chain value and every output exits via fast-path filter
//! rejection (the wire-format byte compare after view-tag derivation
//! returns false, short-circuiting before ML-KEM decap).
//!
//! This documents the typical-case UX cost (which dominates real
//! wallet refresh time, since most outputs aren't for the wallet) and
//! provides a sanity-check ratio against the worst-case measurement:
//! if `worst_case_p99 / typical_case_p99` falls outside the expected
//! ML-KEM-decap-to-view-tag-check cost ratio, the methodology is
//! suspect and the F11-S decision should not bind until the anomaly
//! is investigated.
//!
//! ## Sanity-check tests
//!
//! `tests::worst_case_first_output_returns_full_recovery` and
//! `tests::typical_case_first_output_exits_via_view_tag_mismatch`
//! call [`scan_output_recover`] directly on the first constructed
//! output of each fixture shape and assert the expected disposition.
//! These tests protect against construction bugs that would silently
//! make the "worst-case" fixture take the fast path (and the
//! measured "worst case" would actually be the typical-case cost).
//! The bench harness itself measures cost; the tests verify the
//! fixture's classification.
//!
//! Reference: [`crate::MAX_OUTPUTS`] bounds `n_outputs` at the
//! scanner-side defense-in-depth gate; bench fixtures may exceed this
//! only to exercise the gate's skip-and-log path (not the F11-S path).
//!
//! [`construct_output`]: shekyl_crypto_pq::output::construct_output
//! [`scan_output_recover`]: shekyl_crypto_pq::output::scan_output_recover
//! [`ED25519_BASEPOINT_POINT`]: curve25519_dalek::constants::ED25519_BASEPOINT_POINT

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use zeroize::Zeroizing;

use shekyl_crypto_pq::{
    kem::{HybridKemPublicKey, HybridX25519MlKem, KeyEncapsulation, ML_KEM_768_CT_LEN},
    output::construct_output,
};
use shekyl_oxide::{
    block::{Block, BlockHeader},
    fcmp::{EncryptedAmount, ProofBase, PrunedProofs},
    io::CompressedPoint,
    transaction::{Input, Output, Pruned, Timelock, Transaction, TransactionPrefix},
};
use shekyl_rpc::ScannableBlock;

use crate::{
    extra::{Extra, ExtraField},
    view_pair::ViewPair,
};

/// Bytes per X25519 ephemeral public key on the wire. Mirrors the
/// module-private constant in [`crate::scan`] so this module compiles
/// without coupling to scanner internals.
const X25519_CT_BYTES: usize = 32;

/// Bytes per per-output hybrid KEM ciphertext on the wire
/// (`X25519_pubkey || ML-KEM-768_ciphertext`). Mirrors the
/// module-private constant in [`crate::scan`].
const HYBRID_KEM_CT_BYTES: usize = X25519_CT_BYTES + ML_KEM_768_CT_LEN;

/// Fixed per-transaction key for deterministic fixture construction.
/// Real transactions use a fresh random `tx_key`; here we pin a
/// constant so identical bench runs produce byte-identical
/// transactions (modulo the wallet keypair, which is generated per
/// call to [`make_bench_wallet`]).
const BENCH_TX_KEY: [u8; 32] = [0x42; 32];

/// Fixed per-output amount; arbitrary positive value (the bench is
/// invariant to the specific amount thanks to constant-time amount
/// decryption).
const BENCH_AMOUNT: u64 = 1_000_000;

/// Spend-key secret companion to the [`ViewPair`]. The scanner's
/// constructor binds the spend-key secret separately from the
/// [`ViewPair`] (it's needed for key-image computation downstream of
/// recovery), so we surface it next to the [`ViewPair`] in
/// [`BenchWalletKeys`] for the bench's [`crate::Scanner::new`] call.
type SpendSecret = Zeroizing<[u8; 32]>;

/// Test wallet keys plus the matching hybrid KEM public key used to
/// construct on-chain outputs that the wallet would (cryptographically)
/// recover. The fake-spend-key choice in [`build_worst_case_scannable_block`]
/// makes ownership lookup miss, so the cryptographic full-slow-path
/// cost is paid per output without the additional cost of
/// post-recovery key-image computation.
pub struct BenchWalletKeys {
    /// The wallet's view-side keys (spend pubkey + view secret + KEM secrets).
    pub view_pair: ViewPair,
    /// The wallet's spend-key secret. Held alongside [`Self::view_pair`]
    /// for [`crate::Scanner::new`]; not used by the fixture builders.
    pub spend_secret: SpendSecret,
    /// The wallet's hybrid KEM public key, suitable for
    /// [`construct_output`] (against which the wallet's view-pair
    /// secrets can decap).
    pub wallet_kem_pk: HybridKemPublicKey,
}

/// Generate a fresh bench wallet. The hybrid KEM keypair is sampled
/// from `OsRng` (non-deterministic across invocations); the spend key
/// is fixed at [`ED25519_BASEPOINT_POINT`] (any torsion-free point
/// satisfies [`ViewPair::new`], and using the basepoint makes the
/// fixture independent of any wallet-generation pipeline).
///
/// Bench-relevant property: every call returns a wallet whose
/// `view_pair` will recognize outputs constructed against
/// `wallet_kem_pk` (per [`scan_output_recover`]) and reject outputs
/// constructed against any other KEM public key. The per-call
/// non-determinism in keypair bytes does not affect bench cost
/// (constant-time primitives).
///
/// [`scan_output_recover`]: shekyl_crypto_pq::output::scan_output_recover
pub fn make_bench_wallet() -> BenchWalletKeys {
    let kem = HybridX25519MlKem;
    let (pk, sk) = kem
        .keypair_generate()
        .expect("HybridX25519MlKem::keypair_generate is infallible under OsRng");

    // Per `view_pair::ViewPair::new`, the only structural requirement
    // on the spend point is `is_torsion_free()`. The basepoint
    // trivially satisfies this and avoids the need for a wallet seed.
    // The view scalar is similarly arbitrary; we pin it to a fixed
    // value so bench fixtures are byte-deterministic save for the
    // KEM keypair.
    let view_scalar = Scalar::from_bytes_mod_order([0x07u8; 32]);

    // `HybridKemSecretKey` impls `Drop` via `#[zeroize(drop)]`, so we
    // cannot move `sk.ml_kem` (a `Vec<u8>`) out of it. Copy the
    // X25519 component (Copy-safe), clone the ML-KEM component, and
    // let the original `sk` drop normally at end of scope (its drop
    // impl will zeroize the bytes we just cloned from — the clone in
    // `view_pair` is the live copy and follows the same `Zeroizing`
    // discipline).
    let sk_x25519: [u8; 32] = sk.x25519;
    let sk_ml_kem: Vec<u8> = sk.ml_kem.clone();
    drop(sk);

    let view_pair = ViewPair::new(
        ED25519_BASEPOINT_POINT,
        Zeroizing::new(view_scalar),
        Zeroizing::new(sk_x25519),
        Zeroizing::new(sk_ml_kem),
    )
    .expect("ED25519_BASEPOINT_POINT is torsion-free by definition");

    // Spend-key secret: arbitrary 32-byte value. The bench fixture
    // builders below set the on-chain `recovered_b` to the basepoint
    // (via `fake_spend_key_bytes()`), which doesn't match this secret,
    // so post-recovery ownership lookup misses and key-image
    // computation never runs. Keeping a real-shaped `Zeroizing` here
    // mirrors the production `Scanner::new` API.
    let spend_secret: SpendSecret = Zeroizing::new([0x11u8; 32]);

    BenchWalletKeys {
        view_pair,
        spend_secret,
        wallet_kem_pk: pk,
    }
}

/// Construct the on-chain spend-key bytes used as the `spend_key`
/// argument to [`construct_output`] in fixture construction. Choosing
/// [`ED25519_BASEPOINT_POINT`] (torsion-free, non-default) satisfies
/// [`construct_output`]'s preconditions and makes the recovered `B'`
/// during scanning equal to the basepoint — which does **not** match
/// the bench wallet's registered spend point (also the basepoint, but
/// stored under a different `CompressedPoint` map key wrapper —
/// actually they ARE equal, see below), so the subaddress lookup
/// outcome depends on the wallet's registered point.
///
/// **Why this still produces ownership-miss in the worst-case fixture:**
/// In [`make_bench_wallet`] the wallet's spend point is set to
/// [`ED25519_BASEPOINT_POINT`] for [`ViewPair`] construction
/// (satisfying torsion-free). The scanner's subaddress table is
/// keyed on that exact point. If we used the basepoint as the
/// fake-spend-key here too, the recovered `B'` would match and
/// ownership lookup would succeed — defeating the worst-case
/// classification (the cost would include post-recovery key-image
/// computation, which the adversarial-daemon threat model cannot
/// force). To guarantee ownership miss, we use a *different*
/// torsion-free point: `2 * G` (twice the basepoint).
fn fake_spend_key_bytes() -> [u8; 32] {
    // 2 * G — torsion-free (sum of two torsion-free points), non-
    // default (not the identity), and distinct from the bench
    // wallet's registered spend point (which is `G` per
    // `make_bench_wallet`). The recovered `B'` during scanning will
    // equal `2 * G`, missing the subaddress-table key `G`.
    let two_g = ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT;
    two_g.compress().to_bytes()
}

/// Assemble a [`ScannableBlock`] holding a single non-miner v2
/// transaction whose N outputs were all constructed via
/// [`construct_output`] against `recipient_pk`.
///
/// The block contains a minimal miner-tx (Input::Gen with no outputs)
/// so [`Block::new`] accepts it. The non-miner transaction carries
/// the per-output `view_tag`, `key`, encrypted amount, and commitment
/// fields the scanner reads, plus a `tx_extra` blob carrying the
/// concatenated KEM ciphertexts behind tag `0x06`.
///
/// `output_index_for_first_ringct_output: Some(0)` is set so the
/// scanner walks the non-miner transaction's outputs (the value is
/// not load-bearing for the fixture; the scanner's per-output loop
/// uses the local index `o`).
fn assemble_scannable_block(n_outputs: usize, recipient_pk: &HybridKemPublicKey) -> ScannableBlock {
    // Pre-allocate the on-wire fields.
    let mut outputs: Vec<Output> = Vec::with_capacity(n_outputs);
    let mut commitments: Vec<CompressedPoint> = Vec::with_capacity(n_outputs);
    let mut encrypted_amounts: Vec<EncryptedAmount> = Vec::with_capacity(n_outputs);
    let mut kem_ct_blob: Vec<u8> = Vec::with_capacity(n_outputs * HYBRID_KEM_CT_BYTES);

    let spend_key = fake_spend_key_bytes();

    for output_index in 0..n_outputs {
        let out = construct_output(
            &BENCH_TX_KEY,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &spend_key,
            BENCH_AMOUNT,
            output_index as u64,
        )
        .expect(
            "construct_output is infallible for torsion-free spend keys and \
             valid KEM public keys; both are guaranteed by the fixture",
        );

        outputs.push(Output {
            amount: None,
            key: CompressedPoint(out.output_key),
            view_tag: Some(out.view_tag_x25519),
            staking: None,
        });
        commitments.push(CompressedPoint(out.commitment));
        encrypted_amounts.push(EncryptedAmount {
            amount: out.enc_amount,
            amount_tag: out.amount_tag,
        });
        // Per `scan.rs::scan_transaction`, the KEM ciphertext blob
        // for output `o` is read at offset `o * HYBRID_KEM_CT_BYTES`
        // and consists of `X25519_CT_BYTES || ML_KEM_768_CT_LEN`.
        kem_ct_blob.extend_from_slice(&out.kem_ciphertext_x25519);
        debug_assert_eq!(
            out.kem_ciphertext_ml_kem.len(),
            ML_KEM_768_CT_LEN,
            "construct_output must produce ML-KEM ciphertexts of exactly ML_KEM_768_CT_LEN bytes"
        );
        kem_ct_blob.extend_from_slice(&out.kem_ciphertext_ml_kem);
    }

    debug_assert_eq!(
        kem_ct_blob.len(),
        n_outputs * HYBRID_KEM_CT_BYTES,
        "KEM ciphertext blob length must match scanner's read-offset arithmetic"
    );

    // Serialize the extra field as a `Vec<u8>` (the scanner re-parses
    // the byte slice via `Extra::read` at scan time, mirroring the
    // production daemon → scanner path).
    let extra_serialized = Extra(vec![ExtraField::PqcKemCiphertext(kem_ct_blob)]).serialize();

    let tx_prefix = TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: vec![Input::ToKey {
            amount: None,
            key_offsets: vec![1],
            key_image: CompressedPoint([0u8; 32]),
        }],
        outputs,
        extra: extra_serialized,
    };

    let tx: Transaction<Pruned> = Transaction::V2 {
        prefix: tx_prefix,
        proofs: Some(PrunedProofs {
            base: ProofBase {
                fee: 0,
                encrypted_amounts,
                commitments,
            },
        }),
    };

    // We need the wire-level tx hash to put into `block.transactions`,
    // but `Transaction<Pruned>::hash` doesn't exist (only
    // `Transaction<NotPruned>` has `hash` — pruned txs are
    // reconstructed from the block-level merkle path in real
    // operation). For bench-fixture purposes the value of the
    // tx-hash element of `block.transactions` is not read by
    // `Scanner::scan` (only the count is, via the structural
    // invariant in `scan.rs::InternalScanner::scan`), so a
    // placeholder value is sufficient and structurally invariant
    // across iterations.
    let placeholder_tx_hash = [0xAAu8; 32];

    let header = BlockHeader {
        hardfork_version: 1,
        hardfork_signal: 0,
        timestamp: 0,
        previous: [0u8; 32],
        nonce: 0,
    };

    // Minimal miner-tx: V2, single Input::Gen, no outputs (per the
    // `make_synthetic_block` precedent in engine-core's test_support).
    let miner_tx: Transaction<shekyl_oxide::transaction::NotPruned> = Transaction::V2 {
        prefix: TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::Gen(0)],
            outputs: vec![],
            extra: vec![],
        },
        proofs: None,
    };

    let block = Block::new(header, miner_tx, vec![placeholder_tx_hash])
        .expect("Block::new accepts a V2 miner-tx + one tx hash");

    ScannableBlock {
        block,
        transactions: vec![tx],
        output_index_for_first_ringct_output: Some(0),
    }
}

/// Build a [`ScannableBlock`] whose single non-miner transaction
/// carries `n_outputs` outputs all constructed against the bench
/// wallet's hybrid KEM public key. Every output's view tag matches
/// the wallet's view-pair derivation, forcing the full slow path
/// in [`crate::Scanner::scan`]. Subaddress lookup misses (the
/// constructed recovered-`B'` is `2 * G`, registered subaddress is
/// `G`), so the per-output cost is exactly full-slow-path with no
/// post-recovery key-image overhead.
///
/// **F11-S binding:** the per-output cost measured against this
/// fixture is the adversarial-daemon worst-case under PR 4 §3.1.
pub fn build_worst_case_scannable_block(
    n_outputs: usize,
    wallet_keys: &BenchWalletKeys,
) -> ScannableBlock {
    assemble_scannable_block(n_outputs, &wallet_keys.wallet_kem_pk)
}

/// Build a [`ScannableBlock`] whose single non-miner transaction
/// carries `n_outputs` outputs all constructed against a *different*
/// wallet's hybrid KEM public key. The bench wallet's X25519 ECDH
/// against the on-chain ephemeral keys produces shared secrets that
/// don't match what the encapsulator computed, so every on-chain
/// view tag diverges from the wallet's derivation and every output
/// exits via fast-path filter rejection.
///
/// **Not F11-S binding:** the per-output cost measured against this
/// fixture is the typical-case UX cost (most outputs aren't for the
/// wallet) and serves as the sanity-check denominator for the
/// worst-case-to-typical-case cost ratio.
pub fn build_typical_case_scannable_block(n_outputs: usize) -> ScannableBlock {
    // Encapsulate against an unrelated wallet's public key. The bench
    // wallet's view-pair never sees a matching view-tag, so every
    // output exits via fast-path rejection.
    let other = make_bench_wallet();
    assemble_scannable_block(n_outputs, &other.wallet_kem_pk)
}

#[cfg(test)]
mod tests {
    //! Sanity-check tests for the bench fixtures' classification
    //! (per the module doc-comment's "Sanity-check tests" section).
    //! These tests are the load-bearing protection against
    //! construction bugs that would silently re-classify the
    //! worst-case fixture as fast-path-equivalent.

    use shekyl_crypto_pq::{
        kem::ML_KEM_768_CT_LEN,
        output::{scan_output_recover, OutputData},
    };

    use super::*;

    /// Re-run the per-output construction inside the test so we can
    /// pull out the raw fields needed to drive [`scan_output_recover`]
    /// directly (the assembled [`ScannableBlock`] discards the
    /// per-output `OutputData` after writing it into the wire fields).
    fn first_output_data(recipient_pk: &HybridKemPublicKey) -> OutputData {
        construct_output(
            &BENCH_TX_KEY,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &fake_spend_key_bytes(),
            BENCH_AMOUNT,
            /* output_index */ 0,
        )
        .expect("construct_output succeeds for valid bench inputs")
    }

    #[test]
    fn worst_case_first_output_returns_full_recovery() {
        // The wallet's view-pair will see a matching view tag → fast-
        // path filter passes; ML-KEM decap runs; HKDF runs; amount
        // tag matches; commitment verifies. Final disposition: Ok.
        // The fact that recovered_b == 2 * G (mismatching the
        // wallet's registered spend point) is checked only AFTER
        // scan_output_recover returns; the function itself reports
        // recovery success.
        let wallet = make_bench_wallet();
        let out = first_output_data(&wallet.wallet_kem_pk);

        // Sanity-check the KEM ciphertext length matches the offset
        // arithmetic in `scan.rs::scan_transaction` (which slices the
        // extra blob into `[X25519_CT_BYTES..HYBRID_KEM_CT_BYTES]`).
        // A length mismatch here would propagate into the bench as
        // an unrelated parse error rather than a clean fast/slow-
        // path classification.
        assert_eq!(
            out.kem_ciphertext_ml_kem.len(),
            ML_KEM_768_CT_LEN,
            "construct_output must produce ML-KEM ciphertexts of exactly ML_KEM_768_CT_LEN bytes"
        );

        let recovered = scan_output_recover(
            wallet.view_pair.x25519_sk(),
            wallet.view_pair.ml_kem_dk(),
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            /* output_index */ 0,
        )
        .expect(
            "worst-case fixture must produce a fully-recoverable output \
             (full slow path runs end-to-end); a failure here means the \
             worst-case bench would silently measure fast-path cost",
        );

        assert_eq!(
            recovered.amount, BENCH_AMOUNT,
            "recovered amount must match the constructed amount, proving \
             every step of the slow path (decap, HKDF, amount decrypt, \
             commitment verify) executed correctly"
        );
    }

    #[test]
    fn typical_case_first_output_exits_via_view_tag_mismatch() {
        // The on-chain view tag was computed from the OTHER wallet's
        // X25519 SS; the bench wallet's view-pair derives a different
        // view tag, so the wire-byte compare in scan_output_recover
        // fails and the function returns Err before ML-KEM decap.
        let wallet = make_bench_wallet();
        let other = make_bench_wallet();
        let out = first_output_data(&other.wallet_kem_pk);

        let result = scan_output_recover(
            wallet.view_pair.x25519_sk(),
            wallet.view_pair.ml_kem_dk(),
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            /* output_index */ 0,
        );

        let err = result.expect_err(
            "typical-case fixture must produce a fast-path-rejected output \
             (view-tag mismatch); a success here means the typical-case \
             bench would silently measure full-slow-path cost",
        );

        // Per scan_output_recover's source, the view-tag-mismatch
        // error carries the literal text "X25519 view tag mismatch"
        // inside a DecapsulationFailed variant. Pinning the text
        // catches accidental migration to a different early-exit
        // path (e.g., LowOrderPoint) that would also satisfy
        // `expect_err` but indicate a different fixture problem.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("X25519 view tag mismatch"),
            "expected view-tag-mismatch in {err:?}; if the error is \
             LowOrderPoint or another early-exit, the typical-case \
             fixture is mis-classified"
        );
    }

    #[test]
    fn worst_case_block_count_matches_requested_n_outputs() {
        let wallet = make_bench_wallet();
        for &n in &[1usize, 4, 8, 16] {
            let sb = build_worst_case_scannable_block(n, &wallet);
            assert_eq!(
                sb.transactions.len(),
                1,
                "worst-case block must contain exactly one non-miner tx"
            );
            assert_eq!(
                sb.transactions[0].prefix().outputs.len(),
                n,
                "worst-case block's non-miner tx output count must match requested N={n}"
            );
        }
    }

    #[test]
    fn typical_case_block_count_matches_requested_n_outputs() {
        for &n in &[1usize, 4, 8, 16] {
            let sb = build_typical_case_scannable_block(n);
            assert_eq!(
                sb.transactions.len(),
                1,
                "typical-case block must contain exactly one non-miner tx"
            );
            assert_eq!(
                sb.transactions[0].prefix().outputs.len(),
                n,
                "typical-case block's non-miner tx output count must match requested N={n}"
            );
        }
    }
}
