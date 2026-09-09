// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `LocalKeys`: the M3a in-process implementor of [`KeyEngine`].
//!
//! Per [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`] §4.1, `LocalKeys` is
//! the Stage 1 production implementor of the [`KeyEngine`] trait surface.
//! It owns the wallet's [`AllKeysBlob`] privately and exposes the
//! workflow-shape operations the orchestrator consumes — without any
//! per-output secret material crossing the trait boundary.
//!
//! # State shape
//!
//! `LocalKeys` carries five pieces of state:
//!
//! - [`Self::keys`] (`AllKeysBlob`): the wallet's complete key material.
//!   `AllKeysBlob` is `ZeroizeOnDrop`; secrets are wiped when `LocalKeys`
//!   is dropped.
//! - [`Self::account_public_address`]: cached at construction;
//!   trait-method [`KeyEngine::account_public_address`] returns a borrow.
//! - [`Self::derived`]: pre-decompressed cryptographic forms of the
//!   spend public key and view scalar, computed once at construction
//!   to avoid per-call decompression / mod-order-reduction costs.
//!
//! # Primary-account claim contract (FA-2)
//!
//! `try_claim_output` claims outputs when the recovered spend key
//! `B' = O - ho*G - y*T` equals the wallet's primary spend public key
//! `D = b*G` (`AllKeysBlob::spend_pk`). Signing uses the matching witness
//! `x = ho + b` — the **base** spend key, **no claim offset** — via
//! [`LocalKeys::derive_primary_source_secrets_bundle`]. (The earlier
//! `x = ho + b + m₀` was wrong: it had no matching `m₀·G` in the on-chain
//! output key and broke the SAL open; see `output_claim` module docs. The
//! `m₀` derivation is retained genesis-locked only as the future
//! multi-account substrate, with no V3.0 production caller.)
//!
//! # Stage-4 swap-in
//!
//! At Stage 4, `LocalKeys` is replaced by `ActorRef<KeyActor>` at
//! `KeyEngine` bound sites. `LocalKeys` itself is deleted; its state
//! aggregate becomes the actor's owned state. Trait method signatures
//! do not change.
//!
//! # M3a commit 4b: stub-bearing methods
//!
//! [`KeyEngine::sign_transaction`] returns
//! [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`] pending
//! PR 5's finalization of `TxToSign`'s shape (the per-input
//! public-on-chain data and FCMP++ tree-branch context that
//! `shekyl_tx_builder::sign_transaction` requires).
//!
//! The stub return-path is tested; the remaining trait surface
//! (`account_public_address`, `try_claim_output`) is exercised
//! end-to-end against `construct_output`-produced ciphertexts.
//!
//! [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_3_KEY_ENGINE.md
//! [`KeyEngine`]: super::traits::key::KeyEngine
//! [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`]: super::error::KeyEngineError::SignTransactionTraitSurfaceIncomplete

// Only the signing/index-sensitivity tests derive `D + m_i·G`; the production
// claim path uses the base spend key (`x = ho + b`, no offset).
#[cfg(test)]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, Scalar};
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::derivation::derive_output_secrets;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::keys::SpendPublicKey;
use shekyl_crypto_pq::output::{
    compute_output_key_image, recover_combined_ss, scan_output_recover,
};
#[cfg(test)]
use shekyl_crypto_pq::output_claim::output_spend_offset_scalar;
use shekyl_curve_generators::biased_hash_to_point;
use shekyl_units::AtomicUnits;
use zeroize::Zeroizing;

use super::error::KeyEngineError;
use super::traits::key::{
    AccountPublicAddress, KeyEngine, OutputClaim, OutputClaimResult, OutputDetectionInput,
    SourceSecretsBundle, TxSignatures, TxToSign,
};

/// Cryptographic forms of the wallet's account-level public material,
/// pre-computed at construction so per-call paths do not pay the
/// decompression / mod-order-reduction cost.
struct DerivedScalars {
    /// View scalar `a` (Ed25519) — derived from
    /// `AllKeysBlob::view_sk.as_canonical_bytes()` via
    /// `Scalar::from_bytes_mod_order` (the canonical bytes are already
    /// reduced mod the Ed25519 group order). Wrapped in [`Zeroizing`]
    /// so the in-memory copy is wiped when `LocalKeys` is dropped, in
    /// addition to `AllKeysBlob`'s own wipe path.
    ///
    /// Used only by the signing/index-sensitivity tests (which derive
    /// `D + m_i·G`); the production claim path uses `x = ho + b` (no offset).
    /// Gated `#[cfg(test)]` so non-test builds neither store nor materialize
    /// this view-secret-derived copy (`35-secure-memory.mdc`: no unnecessary
    /// secret duplication).
    #[cfg(test)]
    view_scalar: Zeroizing<Scalar>,

    /// Public spend point `B = b*G` — decompressed from
    /// `AllKeysBlob::spend_pk`. Signing tests derive `D + m₀*G` from this
    /// point; production claim path compares bare `spend_pk` directly.
    #[cfg_attr(not(test), allow(dead_code))]
    spend_public: EdwardsPoint,
}

/// The M3a in-process `KeyEngine` implementor.
///
/// See the module-level docstring for the structural rationale.
///
/// **Visibility.** `pub` for the same reason
/// [`super::local_ledger::LocalLedger`] is `pub`: the bench surface
/// (gated behind `bench-internals`) names this type as the
/// `KeyEngine` implementor in the
/// `engine_trait_bench_key_account_public_address{,_iai}` pair.
/// Field access remains private; method access on the type is
/// `pub(crate)` for inherent methods and gated by the `pub(crate)
/// trait KeyEngine` for trait methods.
///
/// **Constructor scope.** In production builds (without the
/// `bench-internals` feature enabled), the type has no public
/// constructor — `from_keys_blob` is `pub(crate)` and the
/// test/bench helper [`LocalKeys::from_test_seed`] is gated by
/// `#[cfg(any(test, feature = "bench-internals"))]`. When the
/// `bench-internals` feature IS enabled (an internal-use-only
/// feature flag, gated for benches), the `from_test_seed`
/// constructor becomes `pub` to let the bench compilation unit
/// build a deterministic fixture. This pattern matches
/// [`super::local_ledger::LocalLedger::populate_for_bench`]
/// exactly: bench-only `pub` widening under a feature flag the
/// public API contract explicitly disclaims.
#[allow(dead_code)] // M3a wires the implementor; orchestrator integration lands in M3c+.
pub struct LocalKeys {
    /// Wallet key material. `AllKeysBlob` is `ZeroizeOnDrop` so this
    /// field is wiped on drop.
    pub(crate) keys: AllKeysBlob,

    /// Cached account-level public address material. Returned by
    /// reference from [`KeyEngine::account_public_address`].
    account_public_address: AccountPublicAddress,

    /// Pre-computed cryptographic forms of the wallet's account-level
    /// keys. See [`DerivedScalars`].
    derived: DerivedScalars,
}

impl LocalKeys {
    /// Construct a [`LocalKeys`] from a fully-derived [`AllKeysBlob`].
    ///
    /// Production constructor — called by `Engine::open_full` /
    /// `Engine::create` (orchestrator-side wiring lands in M3c+) once
    /// the keys blob has been re-derived from the master seed via
    /// [`shekyl_crypto_pq::account::rederive_account`].
    ///
    /// Pre-computes the view scalar, the spend public point, and the
    /// account-public-address aggregate.
    ///
    /// # Panics
    ///
    /// Panics if `keys.spend_pk` does not decompress to a valid
    /// Ed25519 point. This indicates wallet-state corruption: the
    /// spend public key was produced by `rederive_account` from a
    /// canonical scalar via `ED25519_BASEPOINT_TABLE * scalar`, which
    /// always produces a decompressable point. Per the §5.1
    /// `RuntimeFailure` discipline that `LocalLedger` adopts for lock
    /// poisoning, the correct response to corrupt wallet state is
    /// process termination, not silent continuation.
    pub(crate) fn from_keys_blob(keys: AllKeysBlob) -> Self {
        // Test-only: the view scalar feeds the index-sensitivity helpers; the
        // production claim path never reads it (`x = ho + b`, no offset), so we
        // do not materialize this view-secret copy in non-test builds.
        #[cfg(test)]
        let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(
            *keys.view_sk.as_canonical_bytes(),
        ));
        let spend_public = CompressedEdwardsY(*keys.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("AllKeysBlob::spend_pk decompresses (rederive_account guarantees canonicity)");

        let account_public_address = AccountPublicAddress {
            pqc_public_key: keys.pqc_public_key.to_vec(),
            classical_address_bytes: keys.classical_address_bytes.to_vec(),
        };

        Self {
            keys,
            account_public_address,
            derived: DerivedScalars {
                #[cfg(test)]
                view_scalar,
                spend_public,
            },
        }
    }

    /// Test-only constructor: derive a wallet from a 32-byte raw seed
    /// on the testnet.
    ///
    /// Drives [`shekyl_crypto_pq::account::rederive_account`] with
    /// `(DerivationNetwork::Testnet, SeedFormat::Raw32)` against a
    /// 64-byte master seed whose first 32 bytes are `seed`. Produces
    /// a deterministic [`LocalKeys`] suitable for unit tests; the
    /// resulting wallet is not usable on mainnet (raw-seed format is
    /// rejected on mainnet at the derivation layer).
    ///
    /// Also available to bench targets via the `bench-internals` feature
    /// (`#[cfg(any(test, feature = "bench-internals"))]`) so the
    /// `engine_trait_bench_key_account_public_address{,_iai}` pair can
    /// construct a `LocalKeys` fixture without widening the production
    /// surface. Same Path-A discipline as
    /// `benches/common/engine_fixture.rs` applies: bench targets reuse
    /// the test constructor through a narrow feature gate, but the
    /// constructor stays `pub(crate)` and the visibility expansion is
    /// confined to the `bench-internals` feature.
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn from_test_seed(seed: [u8; 32]) -> Self {
        use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};

        let (_master_seed, blob) =
            generate_account_from_raw_seed(&seed, DerivationNetwork::Testnet)
                .expect("test rederivation succeeds for raw32 testnet seeds");
        Self::from_keys_blob(blob)
    }

    /// Re-derive the per-input [`SourceSecretsBundle`] from the
    /// on-chain hybrid ciphertext and the engine-owned spend-secret
    /// material — the M3b D1 Layer-2 derivation per
    /// [`STAGE_1_PR_3_MIGRATION_PLAN.md`] §3.2.1.
    ///
    /// Composes the Layer-1 transform-shaped primitive
    /// [`recover_combined_ss`] (which performs hybrid X25519 +
    /// ML-KEM-768 re-decap and HKDF-SHA-512 combination on the
    /// view-side secret material the engine owns) with the
    /// state-shaped derivation chain that produces a
    /// `sign_transaction`-ready bundle:
    ///
    /// 1. **Layer 1 — `combined_ss`** ← `recover_combined_ss(view_x25519_sk,
    ///    ml_kem_dk, ciphertext)`. Pure crypto; no engine state. Errors
    ///    propagate as
    ///    [`KeyEngineError::SourceCiphertextDecapsulationFailed`]
    ///    (low-order point, decap failure, malformed ciphertext bytes
    ///    — every case modelled as corrupted or tampered persisted
    ///    state per that variant's docstring).
    /// 2. **Per-output secrets** ← `derive_output_secrets(combined_ss,
    ///    output_index)`. HKDF-SHA-512 expansion keyed by
    ///    `combined_ss` and bound to the output's position. Returns
    ///    `(ho, y, z, k_amount, ...)`; this method consumes the first
    ///    three (the bundle's secret triple) and discards the rest
    ///    (the discarded fields wipe via `OutputSecrets`'s
    ///    `ZeroizeOnDrop` impl when the local binding is dropped).
    /// 3. **Per-input spend scalar** ← `x = ho + b` where `b` is the
    ///    engine-owned account spend secret. **No claim offset:** outputs are
    ///    paid to the base spend key `D = b·G`, so the SAL opening
    ///    `O = x·G + y·T` and the key image `KI = x·Hp(O)` both bind to `b`
    ///    (an `m₀` term would have no matching `m₀·G` in `O`). Computed with
    ///    `Scalar` arithmetic in canonical encoding; the result's
    ///    little-endian byte form is the bundle's
    ///    [`SourceSecretsBundle::spend_key_x`] field.
    /// 4. **Bundle assembly.** `(spend_key_x, spend_key_y, commitment_mask,
    ///    combined_ss, output_index)` packed into the
    ///    [`SourceSecretsBundle`] return value, with each
    ///    secret-bearing field wrapped in [`Zeroizing`] per
    ///    `35-secure-memory.mdc`.
    ///
    /// # Determinism
    ///
    /// For a fixed engine state (same view secret, ML-KEM dk, spend
    /// secret), the same `(source_ciphertext, output_index)` pair always
    /// produces the same bundle bytes.
    /// This is the byte-identical-derivation property that M3b's
    /// commit-8 property test pins.
    ///
    /// # Memory hygiene
    ///
    /// - All cryptographic intermediates (the recovered combined
    ///   secret, the per-output `OutputSecrets`, the `b`-scalar
    ///   derivation, the `m_i` scalar, the assembled `x`-scalar)
    ///   live in stack frames that wipe on drop via `Zeroize` /
    ///   `ZeroizeOnDrop` discipline. The returned bundle owns
    ///   the externally-visible secret bytes; the implementor's
    ///   stack frame retains nothing.
    /// - The 64-byte combined shared secret is copied into a
    ///   `Zeroizing<Vec<u8>>` for the bundle (`SharedSecret` itself
    ///   wipes when its local binding drops; the bundle's copy wipes
    ///   when the bundle drops).
    ///
    /// # `pub(crate)`
    ///
    /// Method is `pub(crate)` because (a) [`SourceSecretsBundle`] and
    /// [`KeyEngineError`] are themselves `pub(crate)` per the M3a
    /// Round 4a visibility decision, and (b) the only legitimate
    /// consumers are inside `shekyl-engine-core` —
    /// `LocalKeys::sign_transaction`'s body (M3b commit 7+) and the
    /// byte-identical-derivation property test (M3b commit 8). No
    /// out-of-crate caller has a use case for this primitive.
    ///
    /// [`STAGE_1_PR_3_MIGRATION_PLAN.md`]: ../../../../../docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md
    /// [`recover_combined_ss`]: shekyl_crypto_pq::output::recover_combined_ss
    /// [`SourceSecretsBundle`]: super::traits::key::SourceSecretsBundle
    pub(crate) fn derive_primary_source_secrets_bundle(
        &self,
        source_ciphertext: &HybridCiphertext,
        output_index: u64,
    ) -> Result<SourceSecretsBundle, KeyEngineError> {
        let combined_ss = recover_combined_ss(
            self.keys.view_sk.as_canonical_bytes(),
            self.keys.ml_kem_dk.as_canonical_bytes(),
            &source_ciphertext.x25519,
            &source_ciphertext.ml_kem,
        )?;

        let secrets = derive_output_secrets(&combined_ss.0, output_index);

        // Engine-owned per-input spend scalar `x = ho + b`.
        //
        // This MUST equal the key-image spend scalar — `compute_output_key_image`
        // (shekyl-crypto-pq) computes `KI = (ho + b)·Hp(O)`, no offset — and it
        // MUST satisfy the SAL output-key opening `O = x·G + y·T`. The on-chain
        // output key is `O = ho·G + B + y·T` where `B` is the *base* spend key
        // `b·G`: the primary address publishes the base key (no offset), so
        // senders/miners pay to `b·G` (a miner constructing a coinbase has no
        // way to add a view-secret-derived offset). Hence `x·G = O − y·T = (ho + b)·G`.
        //
        // A pre-existing `+ m₀` term (the residual CryptoNote subaddress offset)
        // overshot every *real*, scanner-derived spend by `m₀·G`, so the SAL
        // `OpenedInputTuple::open` failed (`(x·G + y·T) ≠ O~`). It survived
        // because every prior test fed a synthetic `(x, y)` that satisfied the
        // relation by construction; this is the first scanner-derived spend.
        // Each intermediate `Scalar` is wrapped in `Zeroizing<…>` so the
        // canonical-byte materializations the operation goes through
        // wipe on drop alongside the bundle's external view of `x`.
        let ho_scalar: Zeroizing<Scalar> = Zeroizing::new(
            Option::from(Scalar::from_canonical_bytes(secrets.ho))
                .expect("ho from wide_reduce is always canonical (per derive_output_secrets)"),
        );
        let b_scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(
            *self.keys.spend_sk.as_canonical_bytes(),
        ));
        let x_scalar: Zeroizing<Scalar> = Zeroizing::new(*ho_scalar + *b_scalar);
        let spend_key_x = Zeroizing::new(x_scalar.to_bytes());

        Ok(SourceSecretsBundle {
            spend_key_x,
            spend_key_y: Zeroizing::new(secrets.y),
            commitment_mask: Zeroizing::new(secrets.z),
            combined_ss: Zeroizing::new(combined_ss.0.to_vec()),
            output_index,
        })
    }
}

impl KeyEngine for LocalKeys {
    type Error = KeyEngineError;

    fn account_public_address(&self) -> &AccountPublicAddress {
        &self.account_public_address
    }

    async fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> Result<OutputClaimResult, Self::Error> {
        // Stage 1: hybrid decap + amount recovery + B' computation.
        // `scan_output_recover` returns `Err` for any rejection
        // (low-order point, view-tag mismatch, decap failure, commitment
        // mismatch); per the trait contract, every cryptographic-level
        // rejection maps to `NotMine` rather than a structural error.
        let Ok(recovered) = scan_output_recover(
            self.keys.view_sk.as_canonical_bytes(),
            self.keys.ml_kem_dk.as_canonical_bytes(),
            &input.ciphertext.x25519,
            &input.ciphertext.ml_kem,
            &input.output_key,
            &input.commitment,
            &input.enc_amount,
            input.amount_tag_on_chain,
            &input.enc_label,
            input.label_tag_on_chain,
            input.view_tag.0[0],
            input.output_index,
        ) else {
            return Ok(OutputClaimResult::NotMine);
        };

        // Stage 2: primary-account check via recovered spend key `B'`.
        // FA-2: claim only when `B'` matches the wallet's primary spend
        // public key (`AllKeysBlob::spend_pk`).
        let recovered_spend_pk =
            SpendPublicKey::from_canonical_bytes(recovered.recovered_spend_key);
        if recovered_spend_pk != self.keys.spend_pk {
            return Ok(OutputClaimResult::NotMine);
        }

        // Stage 3: key image. `KI = x * Hp(O)` where `x = ho + b` and `Hp` is the
        // *biased* hash-to-point — the canonical FCMP++ key-image generator
        // (`shekyl_fcmp::tree::key_image_generator`). `compute_output_key_image`
        // validates `Hp(O)` (must be torsion-free, non-identity); a failure here
        // is a malformed output_key, surfaced as `NotMine`.
        let hp_of_o = biased_hash_to_point(input.output_key);
        let hp_bytes = hp_of_o.compress().to_bytes();

        let Ok(ki_result) = compute_output_key_image(
            &recovered.combined_ss,
            input.output_index,
            self.keys.spend_sk.as_canonical_bytes(),
            &hp_bytes,
        ) else {
            return Ok(OutputClaimResult::NotMine);
        };
        let key_image = ki_result.key_image;

        // Stage 4: deterministic OutputHandle derivation. cSHAKE256
        // keyed by the view secret; same `(view_secret, tx_hash,
        // output_index)` always produces the same handle (per §7.12 /
        // M3a Commit 2's reference vectors).
        let handle = derive_output_handle(
            self.keys.view_sk.as_canonical_bytes(),
            &input.tx_hash,
            input.output_index,
        );

        Ok(OutputClaimResult::Mine(OutputClaim {
            handle,
            key_image,
            // `recovered.amount` is the cleartext amount off the crypto-pq
            // decryption edge (raw `u64`); wrap it at the boundary.
            amount_atomic_units: AtomicUnits::from_raw(recovered.amount),
        }))
    }

    async fn sign_transaction(&self, tx: TxToSign) -> Result<TxSignatures, Self::Error> {
        super::sign_bridge::sign_tx(self, &tx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "local_keys_tests.rs"]
mod tests;
