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
//! - [`Self::network`]: the wallet's bound network. Used by
//!   [`KeyEngine::derive_subaddress`] when constructing a recipient
//!   `ShekylAddress` (PR-5+).
//! - [`Self::derived`]: pre-decompressed cryptographic forms of the
//!   spend public key and view scalar, computed once at construction
//!   to avoid per-call decompression / mod-order-reduction costs.
//! - [`Self::state`]: a [`RwLock`]-guarded subaddress registry that
//!   maps recovered spend keys (`B' = O - ho*G - y*T`) to their
//!   corresponding [`SubaddressIndex`]. Pre-populated with the
//!   primary subaddress at construction; lazily extended by
//!   [`KeyEngine::derive_subaddress`] calls.
//!
//! # Why the registry maps `B'` rather than the subaddress index
//!
//! `try_claim_output`'s post-decap step recovers the spend key
//! `B' = O - ho*G - y*T` (per `shekyl_crypto_pq::output::scan_output_recover`),
//! which is the bytes-level identity of the subaddress that *received*
//! the output. The registry's job is "given B', tell me which subaddress
//! index produced it" — a reverse lookup. The forward-lookup
//! (subaddress index → spend public key) lives in
//! [`shekyl_crypto_pq::subaddress::subaddress_keys`]; the registry caches
//! the forward result keyed for reverse lookup.
//!
//! # Lock shape
//!
//! `RwLock<LocalKeysState>` (synchronous, not `tokio::sync::RwLock`)
//! per the same rationale `LocalLedger` uses (see `local_ledger.rs`):
//! the registry mutation paths are pure synchronous bookkeeping; no
//! `.await` runs while the write guard is held. The trait method
//! signatures (`async fn try_claim_output`, etc.) are awaitable for
//! Stage-4-actor flexibility, but the M3a implementor completes
//! synchronously inside the future.
//!
//! # Stage-4 swap-in
//!
//! At Stage 4, `LocalKeys` is replaced by `ActorRef<KeyActor>` at
//! `KeyEngine` bound sites. `LocalKeys` itself is deleted; its state
//! aggregate becomes the actor's owned state. The `RwLock` is removed
//! because the actor mailbox serializes access. Trait method signatures
//! do not change.
//!
//! # M3a commit 4b: stub-bearing methods
//!
//! Two trait methods return [`KeyEngineError`] variants in M3a because
//! their underlying infrastructure is genuinely-deferred (not
//! implementation laziness):
//!
//! - [`KeyEngine::derive_subaddress`] with [`SubaddressPurpose::Recipient`]
//!   returns [`KeyEngineError::RecipientSubaddressKemKeygenNotImplemented`]
//!   pending `shekyl_crypto_pq::subaddress::derive_subaddress_kem_keypair`
//!   (per-subaddress hybrid X25519+ML-KEM-768 keygen, tracked in §6.4 of
//!   the design doc).
//! - [`KeyEngine::sign_transaction`] returns
//!   [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`] pending
//!   PR 5's finalization of `TxToSign`'s shape (the per-input
//!   public-on-chain data and FCMP++ tree-branch context that
//!   `shekyl_tx_builder::sign_transaction` requires).
//!
//! Both return-paths are tested as stub-validation; the remaining trait
//! surface (`account_public_address`, `derive_subaddress(_, Audit)`,
//! `try_claim_output`) is exercised end-to-end against
//! `construct_output`-produced ciphertexts.
//!
//! [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_3_KEY_ENGINE.md
//! [`KeyEngine`]: super::traits::key::KeyEngine
//! [`SubaddressPurpose::Recipient`]: super::traits::key::SubaddressPurpose::Recipient
//! [`KeyEngineError::RecipientSubaddressKemKeygenNotImplemented`]: super::error::KeyEngineError::RecipientSubaddressKemKeygenNotImplemented
//! [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`]: super::error::KeyEngineError::SignTransactionTraitSurfaceIncomplete

use std::collections::HashMap;
use std::sync::RwLock;

use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, Scalar};
use zeroize::Zeroizing;

use shekyl_address::Network;
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::derivation::derive_output_secrets;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::keys::{SpendPublicKey, ViewPublicKey};
use shekyl_crypto_pq::output::{
    compute_output_key_image, recover_combined_ss, scan_output_recover,
};
use shekyl_crypto_pq::subaddress::{subaddress_derivation_scalar, subaddress_keys};
use shekyl_engine_state::SubaddressIndex;
use shekyl_oxide::generators::hash_to_point;

use super::error::KeyEngineError;
use super::traits::key::{
    AccountPublicAddress, KeyEngine, OutputClaim, OutputClaimResult, OutputDetectionInput,
    SourceSecretsBundle, SubaddressFor, SubaddressKeyPair, SubaddressPurpose, TxSignatures,
    TxToSign,
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
    view_scalar: Zeroizing<Scalar>,

    /// Public spend point `B = b*G` — decompressed from
    /// `AllKeysBlob::spend_pk`. Public material; no zeroize discipline.
    spend_public: EdwardsPoint,
}

/// Mutable wallet-state-shaped aggregate guarded by [`LocalKeys::state`].
///
/// Today this is a single field; future M3 commits (handle table for
/// the deterministic-handle pathway, per-subaddress amount-spent
/// counters) accrete here as load-bearing state arrives. Co-locating
/// future state with the registry behind one lock matches the
/// `LocalLedger` precedent — the lock's job is to serialize the
/// engine's mutable bookkeeping, not to gate per-field reads.
struct LocalKeysState {
    /// Reverse-lookup table: recovered spend key `B'` (typed
    /// [`SpendPublicKey`]) → [`SubaddressIndex`] that produces it.
    ///
    /// Pre-populated at construction with the primary address
    /// (`SubaddressIndex::PRIMARY` ↔ `AllKeysBlob::spend_pk` —
    /// the bare account spend key `D`, matching what
    /// `account.rs::rederive_account` packs into
    /// `classical_address_bytes`). For `idx >= 1`,
    /// `KeyEngine::derive_subaddress` inserts additional entries
    /// lazily as the orchestrator derives them via the per-index
    /// derivation `D + m_i * G`; outputs to not-yet-derived
    /// subaddresses surface as `OutputClaimResult::NotMine`
    /// (the wallet's contract is "claim outputs to subaddresses
    /// you've derived"; a not-yet-derived subaddress is, by
    /// construction, not expected to receive outputs).
    subaddress_registry: HashMap<SpendPublicKey, SubaddressIndex>,
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
    keys: AllKeysBlob,

    /// Cached account-level public address material. Returned by
    /// reference from [`KeyEngine::account_public_address`].
    account_public_address: AccountPublicAddress,

    /// Wallet's bound network. Used by
    /// [`KeyEngine::derive_subaddress`] (PR-5+ recipient-context
    /// payloads) when constructing the encoded `ShekylAddress`.
    #[allow(dead_code)] // Consumed once `derive_subaddress(_, Recipient)` lands.
    network: Network,

    /// Pre-computed cryptographic forms of the wallet's account-level
    /// keys. See [`DerivedScalars`].
    derived: DerivedScalars,

    /// `RwLock`-guarded mutable state. See [`LocalKeysState`].
    state: RwLock<LocalKeysState>,
}

impl LocalKeys {
    /// Construct a [`LocalKeys`] from a fully-derived [`AllKeysBlob`]
    /// and the wallet's bound [`Network`].
    ///
    /// Production constructor — called by `Engine::open_full` /
    /// `Engine::create` (orchestrator-side wiring lands in M3c+) once
    /// the keys blob has been re-derived from the master seed via
    /// [`shekyl_crypto_pq::account::rederive_account`].
    ///
    /// Pre-computes the view scalar, the spend public point, and the
    /// account-public-address aggregate; pre-registers the primary
    /// subaddress in the reverse-lookup registry.
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
    #[allow(dead_code)] // orchestrator wiring lands in M3c+ when LocalKeys is bound at Engine::open_full / ::create.
    pub(crate) fn from_keys_blob(keys: AllKeysBlob, network: Network) -> Self {
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

        let mut subaddress_registry = HashMap::new();
        subaddress_registry.insert(keys.spend_pk, SubaddressIndex::PRIMARY);

        Self {
            keys,
            account_public_address,
            network,
            derived: DerivedScalars {
                view_scalar,
                spend_public,
            },
            state: RwLock::new(LocalKeysState {
                subaddress_registry,
            }),
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
        Self::from_keys_blob(blob, Network::Testnet)
    }

    /// Reverse-lookup helper: given the recovered spend public key
    /// returned by `scan_output_recover` (constructed as a typed
    /// [`SpendPublicKey`] at the engine boundary), return the
    /// matching [`SubaddressIndex`] if any.
    fn lookup_subaddress(&self, recovered_spend: &SpendPublicKey) -> Option<SubaddressIndex> {
        self.state
            .read()
            .expect("LocalKeys lock not poisoned")
            .subaddress_registry
            .get(recovered_spend)
            .copied()
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
    /// 3. **Subaddress derivation scalar** ← `m_i =
    ///    subaddress_derivation_scalar(view_scalar,
    ///    subaddress_idx.to_canonical_bytes())`. Genesis-locked
    ///    cSHAKE256 derivation per
    ///    `shekyl-crypto-pq::subaddress::subaddress_derivation_scalar`.
    ///    For [`SubaddressIndex::PRIMARY`] this is `m_0 = H(... || 0u32)`;
    ///    bundle composition treats `idx == 0` as a regular index
    ///    because at the bundle level the subaddress offset enters
    ///    additively (no special-casing).
    /// 4. **Per-input spend scalar** ← `x = ho + b + m_i` where `b`
    ///    is the engine-owned account spend secret. Computed with
    ///    `Scalar` arithmetic in canonical encoding; the result's
    ///    little-endian byte form is the bundle's
    ///    [`SourceSecretsBundle::spend_key_x`] field.
    /// 5. **Bundle assembly.** `(spend_key_x, spend_key_y, commitment_mask,
    ///    combined_ss, output_index)` packed into the
    ///    [`SourceSecretsBundle`] return value, with each
    ///    secret-bearing field wrapped in [`Zeroizing`] per
    ///    `35-secure-memory.mdc`.
    ///
    /// # Determinism
    ///
    /// For a fixed engine state (same view secret, ML-KEM dk, spend
    /// secret), the same `(source_ciphertext, output_index,
    /// subaddress_idx)` triple always produces the same bundle bytes.
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
    /// [`SubaddressIndex::PRIMARY`]: shekyl_engine_state::SubaddressIndex::PRIMARY
    #[allow(dead_code)] // Consumers land in M3b commits 7-8 (engine post-pass + property test)
    pub(crate) fn derive_source_secrets_bundle(
        &self,
        source_ciphertext: &HybridCiphertext,
        output_index: u64,
        subaddress_idx: SubaddressIndex,
    ) -> Result<SourceSecretsBundle, KeyEngineError> {
        let combined_ss = recover_combined_ss(
            self.keys.view_sk.as_canonical_bytes(),
            self.keys.ml_kem_dk.as_canonical_bytes(),
            &source_ciphertext.x25519,
            &source_ciphertext.ml_kem,
        )?;

        let secrets = derive_output_secrets(&combined_ss.0, output_index);

        // Engine-owned per-input spend scalar `x = ho + b + m_i`.
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
        let m_i: Zeroizing<Scalar> = Zeroizing::new(subaddress_derivation_scalar(
            &self.derived.view_scalar,
            &subaddress_idx.to_canonical_bytes(),
        ));
        let x_scalar: Zeroizing<Scalar> = Zeroizing::new(*ho_scalar + *b_scalar + *m_i);
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

    fn derive_subaddress(
        &self,
        idx: SubaddressIndex,
        purpose: SubaddressPurpose,
    ) -> Result<SubaddressFor, Self::Error> {
        match purpose {
            SubaddressPurpose::Audit => {
                // PRIMARY is the wallet's base address — the encoded
                // `classical_address_bytes` packs `version || spend_pk || view_pk`
                // directly from `AllKeysBlob`'s base keys (per
                // `shekyl_crypto_pq::account::rederive_account`), and the
                // reverse-lookup registry pre-registers `keys.spend_pk` against
                // `SubaddressIndex::PRIMARY` at construction. Returning the base
                // account keys here keeps `derive_subaddress(PRIMARY, _)`
                // consistent with both the encoded address and the registry;
                // routing PRIMARY through `subaddress_keys` would compute
                // `D + m_0*G`, a different point that does not match either.
                //
                // Subaddresses for `idx >= 1` follow the per-index derivation.
                let (spend_pk, view_pk) = if idx.is_primary() {
                    (self.keys.spend_pk, self.keys.view_pk)
                } else {
                    let (spend_point, view_point) = subaddress_keys(
                        &self.derived.view_scalar,
                        &self.derived.spend_public,
                        &idx.to_canonical_bytes(),
                    );
                    (
                        SpendPublicKey::from_canonical_bytes(spend_point.compress().to_bytes()),
                        ViewPublicKey::from_canonical_bytes(view_point.compress().to_bytes()),
                    )
                };

                self.state
                    .write()
                    .expect("LocalKeys lock not poisoned")
                    .subaddress_registry
                    .entry(spend_pk)
                    .or_insert(idx);

                Ok(SubaddressFor::Audit(SubaddressKeyPair {
                    spend_pk,
                    view_pk,
                }))
            }
            // The trait's `SubaddressPurpose` is `#[non_exhaustive]`; future
            // variants (e.g. `PqcRecipient` per §3.1.3) accrete additively.
            // Until per-subaddress hybrid KEM keygen lands in
            // `shekyl_crypto_pq::subaddress::derive_subaddress_kem_keypair`,
            // `Recipient` (and any future recipient-shaped variant) returns the
            // named-infrastructure-gap error.
            _ => Err(KeyEngineError::RecipientSubaddressKemKeygenNotImplemented),
        }
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

        // Stage 2: subaddress lookup via recovered spend key `B'`. A
        // miss means the recovered key matches no derived subaddress
        // — surface as `NotMine` (the wallet only claims outputs sent
        // to subaddresses it has derived).
        let recovered_spend_pk =
            SpendPublicKey::from_canonical_bytes(recovered.recovered_spend_key);
        if self.lookup_subaddress(&recovered_spend_pk).is_none() {
            return Ok(OutputClaimResult::NotMine);
        }

        // Stage 3: key image. `KI = x * Hp(O)` where `x = ho + b`.
        // `compute_output_key_image` validates `Hp(O)` (must be
        // torsion-free, non-identity); a failure here is a malformed
        // output_key, surfaced as `NotMine`.
        let hp_of_o = hash_to_point(input.output_key);
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
            amount_atomic_units: recovered.amount,
        }))
    }

    async fn sign_transaction(&self, _tx: &TxToSign) -> Result<TxSignatures, Self::Error> {
        // M3a stub — TxToSign's PR-5-pinned shape doesn't carry the
        // per-input public-on-chain data (output_key, commitment,
        // amount, h_pqc) and FCMP++ tree-branch context (leaf_chunk,
        // c1_layers, c2_layers) that `shekyl_tx_builder::sign_transaction`
        // requires for SpendInput construction. The bridge lands in
        // PR 5 once `TxToSign`'s shape is finalized; until then this
        // surface is recognized-but-not-bridgeable.
        //
        // See `KeyEngineError::SignTransactionTraitSurfaceIncomplete`'s
        // doc-comment for the full named-infrastructure-gap rationale.
        Err(KeyEngineError::SignTransactionTraitSurfaceIncomplete)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! End-to-end tests for the M3a `LocalKeys` impl.
    //!
    //! Per the user's "test substrate exercises real impls end-to-end"
    //! disposition (ratified during M3a Commit 4 design):
    //!
    //! * Real-impl methods get round-trip tests against
    //!   `shekyl_crypto_pq::output::construct_output`-produced inputs
    //!   (constructed sender-side, claimed receiver-side via
    //!   `try_claim_output`).
    //! * Stub-bearing methods get one-each test verifying the named
    //!   `KeyEngineError` variant is returned.
    //! * The deterministic-handle property (same `(view_secret,
    //!   tx_hash, output_index)` → same `OutputHandle`) is verified
    //!   by re-claiming the same input and observing the handle stays
    //!   stable.

    use super::*;
    use shekyl_crypto_pq::output::construct_output;

    /// Standard test seed; every test uses this unless it specifically
    /// exercises seed-divergence behavior.
    const TEST_SEED: [u8; 32] = [7u8; 32];

    /// Standard tx-key secret used by the sender-side `construct_output`
    /// call. The actual value doesn't matter for receiver-side
    /// recovery — the recipient only sees the resulting ciphertext.
    const TEST_TX_KEY_SECRET: [u8; 32] = [11u8; 32];

    /// Build a synthetic on-chain output paid to the wallet's primary
    /// address, packaged as the `OutputDetectionInput` shape the trait
    /// surface consumes.
    ///
    /// Returns `(input, expected_amount)` so tests can compare the
    /// recovered amount.
    fn build_paid_to_self(
        keys: &LocalKeys,
        output_index: u64,
        amount: u64,
        tx_hash: [u8; 32],
    ) -> (OutputDetectionInput, u64) {
        use crate::engine::traits::key::ViewTag;
        use shekyl_crypto_pq::kem::HybridCiphertext;

        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            keys.keys.spend_pk.as_canonical_bytes(),
            amount,
            output_index,
        )
        .expect("construct_output succeeds for self-paid synthetic output");

        let input = OutputDetectionInput {
            ciphertext: HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            },
            output_key: constructed.output_key,
            commitment: constructed.commitment,
            view_tag: ViewTag([constructed.view_tag_x25519]),
            enc_amount: constructed.enc_amount,
            amount_tag_on_chain: constructed.amount_tag,
            enc_label: constructed.enc_label,
            label_tag_on_chain: constructed.label_tag,
            output_index,
            tx_hash,
        };
        (input, amount)
    }

    // ─────────────────────────────────────────────────────────────────
    // M3c-via-C inline test fixtures
    //
    // Helpers used by `engine_derived_bundle_signs_through_tx_builder_end_to_end`
    // to build a verifier-acceptable single-leaf-chunk FCMP++ tree at
    // `tree_depth = 1`. Mirrors the construction in
    // `shekyl-fcmp/src/proof.rs::tests::prove_verify_roundtrip`
    // field-for-field; that test is the source of truth for the recipe
    // and any drift here surfaces as a verifier rejection in the M3c
    // test rather than a silent miscompare.
    //
    // Inlined per `STAGE_1_PR_3_M3C_PREFLIGHT.md` §3.1 (R1) — the
    // shekyl-fcmp/tx-builder test fixtures are crate-private
    // `#[cfg(test)]` and unreachable from `shekyl-engine-core`'s test
    // tree; promoting them is out of scope for an additive test caller.
    // ─────────────────────────────────────────────────────────────────

    /// Build the synthetic single-leaf-chunk Selene tree root for a
    /// `tree_depth = 1` FCMP++ proof. The tree is the leaf chunk
    /// itself (no branch layers); the root is `SELENE_HASH_INIT +
    /// multiexp(generators, [O.x, I.x, C.x, h_pqc] for each leaf)`.
    ///
    /// Inputs are the leaf-chunk entries in the same order they appear
    /// in `SpendInput.leaf_chunk` and `ProveInput.leaf_chunk_outputs`.
    /// `h_pqc` bytes must be canonical Selene scalar encodings (use
    /// [`make_synthetic_h_pqc_bytes`]).
    ///
    /// # Panics
    ///
    /// Panics if `SELENE_FCMP_GENERATORS.generators.g_bold_slice()`
    /// has fewer than `leaves.len() * 4` entries (the helper consumes
    /// 4 generators per leaf — one each for `O.x`, `I.x`, `C.x`, and
    /// `h_pqc`). The assertion is a defensive guard against future
    /// fixture-expansion regressions; the current 9-fixture sweep
    /// (`n_in ∈ {1, 2, 3}`) tops out at 12 generator indices, well
    /// within the FCMP++ generator-slice capacity.
    fn build_synthetic_single_chunk_tree_root(
        leaves: &[(EdwardsPoint, EdwardsPoint, EdwardsPoint, [u8; 32])],
    ) -> [u8; 32] {
        use ciphersuite::{
            group::{ff::PrimeField, GroupEncoding},
            Ciphersuite,
        };
        use dalek_ff_group::EdwardsPoint as DfgEdwardsPoint;
        use ec_divisors::DivisorCurve;
        use helioselene::Selene;
        use multiexp::multiexp_vartime;
        use shekyl_fcmp_plus_plus::SELENE_FCMP_GENERATORS;
        use shekyl_generators::SELENE_HASH_INIT;

        let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
        let needed = leaves.len() * 4;
        assert!(
            generators.len() >= needed,
            "SELENE_FCMP_GENERATORS.g_bold_slice() has {} entries; \
             single-leaf-chunk tree-root construction needs {} (4 per leaf, \
             {} leaves). Increase the generator slice or shrink the leaf \
             count before adding fixtures past this bound.",
            generators.len(),
            needed,
            leaves.len(),
        );
        let mut terms: Vec<(<Selene as ciphersuite::Ciphersuite>::F, _)> =
            Vec::with_capacity(needed);

        let mut g_idx = 0usize;
        for (o, i, c, h_pqc) in leaves {
            let o_dfg = DfgEdwardsPoint(*o);
            let i_dfg = DfgEdwardsPoint(*i);
            let c_dfg = DfgEdwardsPoint(*c);
            terms.push((
                <DfgEdwardsPoint as DivisorCurve>::to_xy(o_dfg)
                    .expect("output_key is on-curve")
                    .0,
                generators[g_idx],
            ));
            g_idx += 1;
            terms.push((
                <DfgEdwardsPoint as DivisorCurve>::to_xy(i_dfg)
                    .expect("key_image_gen is on-curve")
                    .0,
                generators[g_idx],
            ));
            g_idx += 1;
            terms.push((
                <DfgEdwardsPoint as DivisorCurve>::to_xy(c_dfg)
                    .expect("commitment is on-curve")
                    .0,
                generators[g_idx],
            ));
            g_idx += 1;
            let h_pqc_field: <Selene as Ciphersuite>::F =
                Option::from(<Selene as Ciphersuite>::F::from_repr(*h_pqc))
                    .expect("h_pqc bytes must be canonical Selene scalar");
            terms.push((h_pqc_field, generators[g_idx]));
            g_idx += 1;
        }

        let root_point: <Selene as ciphersuite::Ciphersuite>::G =
            *SELENE_HASH_INIT + multiexp_vartime(&terms);
        root_point.to_bytes()
    }

    /// Generate a canonical Selene scalar's byte representation for
    /// use as an `h_pqc` leaf field, derived deterministically from
    /// `seed`. The byte expansion goes through `Field25519::wide_reduce`
    /// so the result is guaranteed to round-trip through `from_repr`
    /// regardless of `seed`. The returned bytes do not need to be a
    /// real `H(pqc_pk)` for the M3c-via-C test — the FCMP++ verifier
    /// accepts any consistent `h_pqc` value because the proof binds
    /// `pqc_pk_hashes` as a public input rather than re-deriving it
    /// from a real PQC public key.
    ///
    /// Determinism is intentional: tests should be reproducible, and
    /// the property M3c pins is invariant under the specific h_pqc
    /// values chosen.
    fn make_synthetic_h_pqc_bytes(seed: u64) -> [u8; 32] {
        use ciphersuite::group::ff::PrimeField;
        let mut buf = [0u8; 64];
        buf[..8].copy_from_slice(&seed.to_le_bytes());
        // Splash the seed across the high half too so adjacent seeds
        // produce well-separated field elements (avoids accidental
        // structural correlation when the 9-fixture sweep runs).
        buf[32..40].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
        // `wide_reduce` is `Field25519`'s inherent constructor (not on
        // the `Field` trait); calling through `<Selene as Ciphersuite>::F`
        // does not resolve. The Selene scalar field IS `Field25519`.
        let h_pqc_field = dalek_ff_group::FieldElement::wide_reduce(buf);
        h_pqc_field.to_repr()
    }

    /// Build a recipient `OutputInfo` record by constructing a fresh
    /// output to the wallet's primary address (so the
    /// `(commitment_mask, amount, enc_amount)` triple is internally
    /// consistent and the resulting Pedersen commitment is on-curve).
    /// The recipient identity does not matter for what M3c-via-C pins
    /// — the test only exercises `tx_builder::sign_transaction`'s
    /// output-side wiring (commitment construction, BP+ range proof,
    /// ECDH-encoded amount echo).
    fn make_recipient_output_info(
        keys: &LocalKeys,
        amount: u64,
        output_index: u64,
    ) -> shekyl_tx_builder::types::OutputInfo {
        use shekyl_tx_builder::types::OutputInfo;

        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            keys.keys.spend_pk.as_canonical_bytes(),
            amount,
            output_index,
        )
        .expect("construct_output succeeds for synthetic recipient");
        OutputInfo {
            dest_key: constructed.output_key,
            amount,
            commitment_mask: constructed.z,
            enc_amount: {
                let mut enc = [0u8; 9];
                enc[..8].copy_from_slice(&constructed.enc_amount);
                enc[8] = constructed.amount_tag;
                enc
            },
            enc_label: {
                let mut enc = [0u8; 9];
                enc[..8].copy_from_slice(&constructed.enc_label);
                enc[8] = constructed.label_tag;
                enc
            },
        }
    }

    /// Compute the Ed25519 key image `L = I * x` for the verifier's
    /// public input. Mirrors `shekyl_crypto_pq::output::compute_output_key_image`
    /// without going through `OutputClaim` so the test can assemble
    /// the verifier inputs directly from the engine bundle.
    fn compute_test_key_image(output_key: [u8; 32], spend_key_x: [u8; 32]) -> [u8; 32] {
        let i_point = shekyl_generators::biased_hash_to_point(output_key);
        let x_scalar = Scalar::from_canonical_bytes(spend_key_x)
            .expect("spend_key_x from bundle is canonical");
        (i_point * x_scalar).compress().to_bytes()
    }

    #[test]
    fn account_public_address_returns_cached_material() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let addr = keys.account_public_address();
        assert_eq!(addr.classical_address_bytes.len(), 65);
        assert_eq!(addr.pqc_public_key.len(), 1216);
        // Stable across repeated calls.
        let addr2 = keys.account_public_address();
        assert_eq!(addr.classical_address_bytes, addr2.classical_address_bytes);
        assert_eq!(addr.pqc_public_key, addr2.pqc_public_key);
    }

    #[test]
    fn derive_subaddress_audit_returns_real_keys() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let idx = SubaddressIndex::new(7);
        let SubaddressFor::Audit(pair) = keys
            .derive_subaddress(idx, SubaddressPurpose::Audit)
            .expect("audit derivation is real-impl")
        else {
            panic!("audit purpose must return SubaddressFor::Audit");
        };
        // Spend and view bytes are 32 bytes each; non-zero (the primary
        // would be zero only on a degenerate seed, and idx=7 is even
        // less likely).
        assert_ne!(pair.spend_pk.as_canonical_bytes(), &[0u8; 32]);
        assert_ne!(pair.view_pk.as_canonical_bytes(), &[0u8; 32]);
    }

    /// `derive_subaddress(PRIMARY, Audit)` returns the wallet's base
    /// account keys — the same `(spend_pk, view_pk)` packed into
    /// `AllKeysBlob::classical_address_bytes`. Without the
    /// `is_primary()` special-case in
    /// [`LocalKeys::derive_subaddress`], the routing through
    /// `subaddress_keys` would compute `(D + m_0*G, a*(D + m_0*G))`,
    /// which is not what the encoded primary address refers to and not
    /// what the reverse-lookup registry holds against
    /// `SubaddressIndex::PRIMARY`. This test pins the contract.
    #[test]
    fn derive_subaddress_primary_audit_returns_base_account_keys() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);

        let base_spend_pk = keys.keys.spend_pk;
        let base_view_pk = keys.keys.view_pk;

        // The bare-account spend key matches the encoded primary address.
        let encoded = &keys.account_public_address.classical_address_bytes;
        assert_eq!(&encoded[1..33], base_spend_pk.as_canonical_bytes());
        assert_eq!(&encoded[33..65], base_view_pk.as_canonical_bytes());

        let SubaddressFor::Audit(pair) = keys
            .derive_subaddress(SubaddressIndex::PRIMARY, SubaddressPurpose::Audit)
            .expect("audit derivation is real-impl for PRIMARY")
        else {
            panic!("audit purpose must return SubaddressFor::Audit");
        };
        assert_eq!(
            pair.spend_pk, base_spend_pk,
            "PRIMARY's spend_pk must match the wallet's base spend key D"
        );
        assert_eq!(
            pair.view_pk, base_view_pk,
            "PRIMARY's view_pk must match the wallet's base view key a*G"
        );

        // And it must differ from the per-index derivation `D + m_0*G`
        // — confirming the special-case is load-bearing.
        let (derived_spend_point, _) = subaddress_keys(
            &keys.derived.view_scalar,
            &keys.derived.spend_public,
            &SubaddressIndex::PRIMARY.to_canonical_bytes(),
        );
        let derived_spend_pk =
            SpendPublicKey::from_canonical_bytes(derived_spend_point.compress().to_bytes());
        assert_ne!(
            pair.spend_pk, derived_spend_pk,
            "PRIMARY's audit keys must NOT match the idx=0 per-index derivation"
        );
    }

    #[test]
    fn derive_subaddress_audit_is_deterministic() {
        let keys_a = LocalKeys::from_test_seed(TEST_SEED);
        let keys_b = LocalKeys::from_test_seed(TEST_SEED);
        let idx = SubaddressIndex::new(42);
        let SubaddressFor::Audit(pair_a) = keys_a
            .derive_subaddress(idx, SubaddressPurpose::Audit)
            .unwrap()
        else {
            unreachable!()
        };
        let SubaddressFor::Audit(pair_b) = keys_b
            .derive_subaddress(idx, SubaddressPurpose::Audit)
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(pair_a.spend_pk, pair_b.spend_pk);
        assert_eq!(pair_a.view_pk, pair_b.view_pk);
    }

    #[test]
    fn derive_subaddress_recipient_returns_named_gap_stub() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let idx = SubaddressIndex::new(3);
        let err = keys
            .derive_subaddress(idx, SubaddressPurpose::Recipient)
            .expect_err("recipient purpose is stub-bearing in M3a");
        assert!(matches!(
            err,
            KeyEngineError::RecipientSubaddressKemKeygenNotImplemented
        ));
    }

    #[tokio::test]
    async fn try_claim_output_happy_path_for_primary_subaddress() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let (input, expected_amount) = build_paid_to_self(&keys, 0, 12345, [3u8; 32]);

        let result = keys
            .try_claim_output(&input)
            .await
            .expect("real impl returns Ok on a self-paid output");

        match result {
            OutputClaimResult::Mine(claim) => {
                assert_eq!(claim.amount_atomic_units, expected_amount);
                assert_ne!(claim.key_image.as_bytes(), &[0u8; 32]);
            }
            _ => panic!("OutputClaimResult::Mine expected for self-paid output"),
        }
    }

    #[tokio::test]
    async fn try_claim_output_handle_is_deterministic() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let (input, _) = build_paid_to_self(&keys, 0, 12345, [3u8; 32]);

        let handle_1 = match keys.try_claim_output(&input).await.unwrap() {
            OutputClaimResult::Mine(c) => c.handle,
            _ => unreachable!(),
        };
        let handle_2 = match keys.try_claim_output(&input).await.unwrap() {
            OutputClaimResult::Mine(c) => c.handle,
            _ => unreachable!(),
        };
        assert_eq!(
            handle_1, handle_2,
            "deterministic-handle pathway: same input must produce same handle"
        );
    }

    #[tokio::test]
    async fn try_claim_output_different_tx_hash_yields_different_handle() {
        // The handle is keyed on (view_secret, tx_hash, output_index);
        // varying tx_hash must vary the handle.
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let (input_a, _) = build_paid_to_self(&keys, 0, 12345, [1u8; 32]);
        let (input_b, _) = build_paid_to_self(&keys, 0, 12345, [2u8; 32]);

        let handle_a = match keys.try_claim_output(&input_a).await.unwrap() {
            OutputClaimResult::Mine(c) => c.handle,
            _ => unreachable!(),
        };
        let handle_b = match keys.try_claim_output(&input_b).await.unwrap() {
            OutputClaimResult::Mine(c) => c.handle,
            _ => unreachable!(),
        };
        assert_ne!(handle_a, handle_b);
    }

    #[tokio::test]
    async fn try_claim_output_for_other_wallet_returns_not_mine() {
        // Build a `LocalKeys` from one seed; receive a payment built
        // for a wallet derived from a different seed. The view-tag
        // pre-filter rejects the output cheaply; trait surface
        // surfaces as `NotMine`.
        let receiver_keys = LocalKeys::from_test_seed(TEST_SEED);
        let other_keys = LocalKeys::from_test_seed([99u8; 32]);

        let (input_for_other, _) = build_paid_to_self(&other_keys, 0, 12345, [3u8; 32]);

        let result = receiver_keys
            .try_claim_output(&input_for_other)
            .await
            .unwrap();
        assert!(matches!(result, OutputClaimResult::NotMine));
    }

    #[tokio::test]
    async fn try_claim_output_for_unregistered_subaddress_returns_not_mine() {
        // The output is paid to the wallet's idx=7 subaddress, but the
        // orchestrator never called `derive_subaddress(7, _)` so the
        // registry has no entry for idx=7's spend key. Per the
        // module-level "the wallet only claims outputs to subaddresses
        // it has derived" contract, the result is `NotMine`.
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let idx = SubaddressIndex::new(7);

        // Compute the idx=7 subaddress's spend public key without
        // going through `derive_subaddress` (so the registry is not
        // populated).
        let (spend_point, _) = subaddress_keys(
            &keys.derived.view_scalar,
            &keys.derived.spend_public,
            &idx.to_canonical_bytes(),
        );
        let subaddr_spend_pk = spend_point.compress().to_bytes();

        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            &subaddr_spend_pk,
            999,
            0,
        )
        .expect("construct_output succeeds against subaddress spend pk");

        use crate::engine::traits::key::ViewTag;
        use shekyl_crypto_pq::kem::HybridCiphertext;
        let input = OutputDetectionInput {
            ciphertext: HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            },
            output_key: constructed.output_key,
            commitment: constructed.commitment,
            view_tag: ViewTag([constructed.view_tag_x25519]),
            enc_amount: constructed.enc_amount,
            amount_tag_on_chain: constructed.amount_tag,
            enc_label: constructed.enc_label,
            label_tag_on_chain: constructed.label_tag,
            output_index: 0,
            tx_hash: [0u8; 32],
        };

        let result = keys.try_claim_output(&input).await.unwrap();
        assert!(matches!(result, OutputClaimResult::NotMine));
    }

    #[tokio::test]
    async fn try_claim_output_after_derive_subaddress_succeeds() {
        // The post-condition of "register subaddress, then claim
        // output paid to it" is `Mine`. This exercises the lazy
        // registry-population path that real wallets follow.
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let idx = SubaddressIndex::new(7);

        // Register idx=7.
        let SubaddressFor::Audit(pair) = keys
            .derive_subaddress(idx, SubaddressPurpose::Audit)
            .unwrap()
        else {
            unreachable!()
        };

        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            pair.spend_pk.as_canonical_bytes(),
            777,
            0,
        )
        .unwrap();

        use crate::engine::traits::key::ViewTag;
        use shekyl_crypto_pq::kem::HybridCiphertext;
        let input = OutputDetectionInput {
            ciphertext: HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            },
            output_key: constructed.output_key,
            commitment: constructed.commitment,
            view_tag: ViewTag([constructed.view_tag_x25519]),
            enc_amount: constructed.enc_amount,
            amount_tag_on_chain: constructed.amount_tag,
            enc_label: constructed.enc_label,
            label_tag_on_chain: constructed.label_tag,
            output_index: 0,
            tx_hash: [4u8; 32],
        };

        let result = keys.try_claim_output(&input).await.unwrap();
        match result {
            OutputClaimResult::Mine(claim) => assert_eq!(claim.amount_atomic_units, 777),
            _ => panic!("Mine expected after subaddress registration"),
        }
    }

    /// Smoke test for `derive_source_secrets_bundle` (M3b D1 Layer 2):
    /// against a `construct_output`-produced ciphertext, the method
    /// returns `Ok(bundle)` with the expected combined-secret length
    /// and is deterministic across repeated calls.
    ///
    /// Bit-level cross-validation against the legacy derivation path
    /// is the byte-identical-derivation property test in M3b commit 8;
    /// this smoke test pins the basic functional shape so commit 8's
    /// failures localize to derivation drift rather than method
    /// plumbing.
    #[test]
    fn derive_source_secrets_bundle_returns_deterministic_bundle() {
        use shekyl_crypto_pq::kem::HybridCiphertext;

        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let output_index = 3u64;
        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            keys.keys.spend_pk.as_canonical_bytes(),
            12345,
            output_index,
        )
        .unwrap();
        let ciphertext = HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };

        let bundle_a = keys
            .derive_source_secrets_bundle(&ciphertext, output_index, SubaddressIndex::PRIMARY)
            .expect("derive_source_secrets_bundle succeeds for self-paid synthetic output");
        let bundle_b = keys
            .derive_source_secrets_bundle(&ciphertext, output_index, SubaddressIndex::PRIMARY)
            .expect("repeat derivation also succeeds");

        assert_eq!(bundle_a.combined_ss.len(), 64);
        assert_eq!(bundle_a.output_index, output_index);
        assert_eq!(bundle_a.spend_key_x, bundle_b.spend_key_x);
        assert_eq!(bundle_a.spend_key_y, bundle_b.spend_key_y);
        assert_eq!(bundle_a.commitment_mask, bundle_b.commitment_mask);
        assert_eq!(*bundle_a.combined_ss, *bundle_b.combined_ss);
    }

    /// `derive_source_secrets_bundle` rejects a corrupted source
    /// ciphertext via [`KeyEngineError::SourceCiphertextDecapsulationFailed`].
    /// Tampering the X25519 component to a low-order point
    /// (`u = 0` is the canonical low-order example) drives the
    /// Layer-1 [`recover_combined_ss`] rejection path.
    #[test]
    fn derive_source_secrets_bundle_rejects_low_order_x25519_component() {
        use shekyl_crypto_pq::kem::HybridCiphertext;

        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            keys.keys.spend_pk.as_canonical_bytes(),
            1,
            0,
        )
        .unwrap();
        let tampered = HybridCiphertext {
            x25519: [0u8; 32], // low-order Montgomery point u=0
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };

        let err = keys
            .derive_source_secrets_bundle(&tampered, 0, SubaddressIndex::PRIMARY)
            .expect_err("low-order X25519 component must be rejected");
        assert!(matches!(
            err,
            KeyEngineError::SourceCiphertextDecapsulationFailed(_)
        ));
    }

    /// Byte-identical-derivation property test (M3b D5) — pins the
    /// engine-side composition `LocalKeys::derive_source_secrets_bundle`
    /// against the legacy scanner-side derivation chain that
    /// `shekyl_crypto_pq::output::scan_output_recover` realizes.
    ///
    /// # Property
    ///
    /// For every `(output_index, tx_hash, subaddress_idx)` triple, the
    /// bundle returned by `LocalKeys::derive_source_secrets_bundle`
    /// — which composes [`recover_combined_ss`],
    /// [`derive_output_secrets`], and the subaddress / spend-secret
    /// arithmetic — must be byte-identical to a bundle composed by
    /// hand from `scan_output_recover`'s `RecoveredOutput` against the
    /// same inputs. Both chains share the same Layer-1
    /// `decap_ml_kem_and_combine` helper inside `shekyl-crypto-pq`
    /// (validated by the C1 Layer-1 unit test in
    /// `shekyl-crypto-pq/tests/recover_combined_ss.rs`); this test
    /// extends the property to the engine's Layer-2 composition.
    ///
    /// # Why this property is load-bearing
    ///
    /// Per `STAGE_1_PR_3_M3B_PREFLIGHT.md` §3.2 / §D5, the engine
    /// post-pass populates `TransferDetails.source_ciphertext` so that
    /// later spend-side derivation can re-recover the bundle from the
    /// on-chain ciphertext alone (no scanner-side intermediate state is
    /// trusted). For that recovery to be sound, the re-derived bundle
    /// must equal the bundle the scanner would have computed at
    /// detection time. This test pins that equality so a future
    /// implementation drift on either chain (a constant rename, a
    /// salt change, an arithmetic-order swap) fails here rather than
    /// at sign-time on a real transaction.
    ///
    /// # Coverage
    ///
    /// - 8 distinct `(output_index, tx_hash)` pairs to exercise the
    ///   `derive_output_secrets` HKDF-SHA-512 context-binding paths.
    /// - 3 distinct `subaddress_idx` values (PRIMARY, idx=1, idx=42)
    ///   to exercise `subaddress_derivation_scalar`'s cSHAKE256
    ///   binding to the index byte representation. PRIMARY exercises
    ///   the `idx=0` path; idx=1 and idx=42 exercise non-zero
    ///   derivations including a value above `u8::MAX` to cover the
    ///   little-endian encoding in `to_canonical_bytes`.
    /// - 24 total derivations (8 × 3) — the pre-flight's "at least 3,
    ///   preferably 8+" lower bound is exceeded.
    ///
    /// Per the M3a Round 4a `pub(crate)` visibility lock on
    /// [`LocalKeys`], [`SourceSecretsBundle`], and [`KeyEngineError`],
    /// this property test lives inside `local_keys.rs`'s
    /// `mod tests` rather than the `tests/byte_identical_derivation.rs`
    /// integration-test placement the pre-flight estimated.
    /// Integration tests run as external crates and cannot reach
    /// `pub(crate)`; expanding visibility for one test contradicts the
    /// visibility lock. The property the test pins is identical
    /// regardless of file placement.
    ///
    /// [`recover_combined_ss`]: shekyl_crypto_pq::output::recover_combined_ss
    /// [`derive_output_secrets`]: shekyl_crypto_pq::derivation::derive_output_secrets
    /// [`SourceSecretsBundle`]: super::traits::key::SourceSecretsBundle
    /// [`KeyEngineError`]: super::error::KeyEngineError
    #[test]
    fn derive_source_secrets_bundle_byte_identical_against_legacy_chain() {
        use shekyl_crypto_pq::kem::HybridCiphertext;
        use shekyl_crypto_pq::output::scan_output_recover;

        let keys = LocalKeys::from_test_seed(TEST_SEED);

        // 8 distinct (output_index, tx_hash) inputs. tx_hash is
        // populated for completeness even though the bundle derivation
        // does not depend on it (the handle does); covering distinct
        // tx_hash values protects against accidental future coupling.
        let inputs: [(u64, [u8; 32]); 8] = [
            (0, [0x11u8; 32]),
            (1, [0x22u8; 32]),
            (7, [0x33u8; 32]),
            (42, [0x44u8; 32]),
            (255, [0x55u8; 32]),
            (256, [0x66u8; 32]),
            (1_000_000, [0x77u8; 32]),
            (u64::MAX, [0x88u8; 32]),
        ];
        let subaddress_indices = [
            SubaddressIndex::PRIMARY,
            SubaddressIndex::new(1),
            SubaddressIndex::new(42),
        ];

        // The wallet's primary spend key is the recipient for each
        // synthetic output. The chain's binding to subaddress_idx
        // enters at `m_i` only — `construct_output` is unaware of
        // subaddress indexing, so a single ciphertext can be used
        // across all idx values for the bundle-arithmetic check.
        for (output_index, tx_hash) in inputs.iter().copied() {
            let constructed = construct_output(
                &TEST_TX_KEY_SECRET,
                &keys.keys.x25519_pk,
                &keys.keys.ml_kem_ek,
                keys.keys.spend_pk.as_canonical_bytes(),
                12_345u64.wrapping_add(output_index),
                output_index,
            )
            .expect("construct_output succeeds for self-paid synthetic output");

            let ciphertext = HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            };

            // Legacy chain: drive `scan_output_recover` end-to-end and
            // assemble a SourceSecretsBundle by hand from its outputs
            // and the engine-owned spend secret + subaddress scalar.
            let recovered = scan_output_recover(
                keys.keys.view_sk.as_canonical_bytes(),
                keys.keys.ml_kem_dk.as_canonical_bytes(),
                &constructed.kem_ciphertext_x25519,
                &constructed.kem_ciphertext_ml_kem,
                &constructed.output_key,
                &constructed.commitment,
                &constructed.enc_amount,
                constructed.amount_tag,
                &constructed.enc_label,
                constructed.label_tag,
                constructed.view_tag_x25519,
                output_index,
            )
            .expect("scan_output_recover succeeds for self-paid synthetic output");

            for &subaddress_idx in &subaddress_indices {
                // Hand-composed legacy bundle: spend_key_x = ho + b + m_i.
                let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(recovered.ho))
                    .expect("ho from wide_reduce is canonical");
                let b_scalar: Scalar =
                    Scalar::from_bytes_mod_order(*keys.keys.spend_sk.as_canonical_bytes());
                let m_i: Scalar = subaddress_derivation_scalar(
                    &keys.derived.view_scalar,
                    &subaddress_idx.to_canonical_bytes(),
                );
                let legacy_x_scalar: Scalar = ho_scalar + b_scalar + m_i;
                let legacy_x = legacy_x_scalar.to_bytes();

                // New chain: engine-side composition.
                let new_bundle = keys
                    .derive_source_secrets_bundle(&ciphertext, output_index, subaddress_idx)
                    .expect("derive_source_secrets_bundle succeeds against own ciphertext");

                let context = format!(
                    "output_index={output_index}, tx_hash[0]={:#04x}, subaddress_idx={subaddress_idx:?}",
                    tx_hash[0]
                );

                // Field-by-field byte equality. Each assertion names the
                // bundle field so a regression localizes to the chain
                // step the field is sourced from.
                assert_eq!(
                    *new_bundle.spend_key_x, legacy_x,
                    "spend_key_x byte-identity violated ({context})"
                );
                assert_eq!(
                    *new_bundle.spend_key_y, recovered.y,
                    "spend_key_y byte-identity violated ({context})"
                );
                assert_eq!(
                    *new_bundle.commitment_mask, recovered.z,
                    "commitment_mask byte-identity violated ({context})"
                );
                assert_eq!(
                    new_bundle.combined_ss.as_slice(),
                    &recovered.combined_ss[..],
                    "combined_ss byte-identity violated ({context})"
                );
                assert_eq!(
                    new_bundle.output_index, output_index,
                    "output_index passthrough violated ({context})"
                );
            }
        }
    }

    /// End-to-end M3c-via-C: drive an engine-derived
    /// [`SourceSecretsBundle`] through `tx_builder::sign_transaction`
    /// and assert the resulting `SignedProofs` is verifier-acceptable
    /// at every level.
    ///
    /// # What this test pins
    ///
    /// **Layer 1 — cryptographic chain (this test's scope).** The
    /// pipeline `engine bundle → SpendInput → tx_builder ::
    /// sign_transaction → BP+ verify + FCMP++ verify` succeeds
    /// end-to-end, and the engine-derived `SpendInput` is byte-
    /// identical (field-by-field) to a hand-composed legacy
    /// `SpendInput` sourced from `scan_output_recover` plus
    /// `(ho + b + m_i)` (the same legacy chain M3b D5 uses). This is
    /// the load-bearing property the M3a [`KeyEngine`] decoupling
    /// claims: the engine's bundle is sufficient to drive the
    /// existing tx-builder cryptographic pipeline without any
    /// information loss versus the legacy chain.
    ///
    /// SpendInput byte-equality at the input layer is strictly
    /// stronger than `commitments` / `enc_amounts` byte-equality at
    /// the signer-output layer: the latter follows from the former
    /// plus `tx_builder::sign_transaction`'s deterministic
    /// `OutputInfo → commitments` mapping, while the former
    /// additionally catches a class of regressions where two
    /// `SpendInput`s differ in fields that don't affect commitments /
    /// enc_amounts but do affect future signature behavior or future
    /// field additions.
    ///
    /// # What this test does NOT pin
    ///
    /// **Layer 2 — `KeyEngine::sign_transaction` trait method.** The
    /// trait-surface contract (engine-state ownership inside the
    /// async impl, error mapping, pre/post-condition discipline) is
    /// PR-5 scope — `TxToSign.outputs` and
    /// `TxToSign.fcmp_plus_plus_context` are currently named-gap
    /// stubs and the trait method returns
    /// [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`].
    /// This test bypasses the trait surface and calls
    /// [`tx_builder::sign_transaction`] directly per
    /// `STAGE_1_PR_3_M3C_PREFLIGHT.md` §2 (Option C).
    ///
    /// **Layer 3 — message envelope / actor mailbox.** The
    /// orchestrator-engine boundary is per-trait function calls in
    /// PR 3; whether PR 6+ promotes the boundary to actor messaging
    /// is an architectural decision orthogonal to the cryptographic
    /// property pinned here. The cryptographic chain in Layer 1 is
    /// invariant under that decision: bundle → SpendInput →
    /// SignedProofs is the same data flow whether each step is a
    /// function call, a trait method, an awaitable Future, or a
    /// message.
    ///
    /// # Relationship to M3b D5
    ///
    /// `derive_source_secrets_bundle_byte_identical_against_legacy_chain`
    /// (M3b D5) and this test pin complementary properties at
    /// adjacent layers — this is intentional layered coverage, not
    /// redundant or asymmetric coverage.
    ///
    /// M3b D5 verifies bundle-byte identity (engine bundle ≡ legacy
    /// bundle field-by-field). It does not exercise recovery — its
    /// synthetic outputs are paid to the wallet's bare primary
    /// spend key, so the bundle's `spend_key_x = ho + b + m_i`
    /// cannot recover the on-chain `O = (ho + b)*G + y*T`. The
    /// mismatch is invisible at the byte-identity layer and
    /// irrelevant to what M3b D5 claims.
    ///
    /// M3c-via-C (this test) verifies recovery-correctness end-to-
    /// end through `tx_builder::sign_transaction` and the BP+ /
    /// FCMP++ verifiers. Recovery requires the bundle's spend
    /// scalars to actually open the on-chain output, which forces
    /// the recipient to be `subaddress_keys(idx)` for *every* idx
    /// including PRIMARY (see the `recipient_spend_pk` derivation
    /// below for why M3b D5's bare-`spend_pk` shortcut would not
    /// work here).
    ///
    /// A regression that affects only bundle bytes surfaces in
    /// M3b D5; a regression that affects only the bundle →
    /// SpendInput → SignedProofs end-to-end chain surfaces here.
    /// The two together pin the bundle layer's property at both
    /// the contract level (byte-identity) and the consumption level
    /// (verifier acceptance).
    ///
    /// # Workspace-coverage note
    ///
    /// This test is currently the workspace's sole end-to-end
    /// successful-execution coverage of `tx_builder::sign_transaction`.
    /// `shekyl-tx-builder/src/tests.rs` covers only validation-error
    /// paths (every call asserts `Err(...)`); the
    /// `transfer_e2e.rs` / `transfer_e2e_iai.rs` benches explicitly
    /// elide the full sign because the FCMP++ tree-fixture is not
    /// checked in (their scope-note documents this gap). The
    /// `shekyl-fcmp::proof::tests::prove_verify_roundtrip` test
    /// exercises FCMP++ prove + verify directly, bypassing the
    /// BP+ / cofactor / amount-encryption / pseudo-output-balancing
    /// pipeline that `sign_transaction` composes. This test's
    /// engine-path call is what closes that gap until M3d lands the
    /// trait-surface call site that subsumes it.
    ///
    /// An earlier draft of this test (superseded during pre-flight
    /// review by the Trim-1 disposition documented in
    /// `STAGE_1_PR_3_M3C_PREFLIGHT.md` §2.1.1) issued a parallel
    /// sign call with legacy-derived `SpendInput`s for a stricter
    /// `commitments` / `enc_amounts` byte-equality check at the
    /// signer-output layer. That structure has been replaced by
    /// SpendInput byte-equality at the input layer (strictly stronger
    /// property; ~45% runtime reduction). The trade-off accepted:
    /// the workspace now has 1× coverage of `sign_transaction`'s
    /// success path (this test's engine call) instead of 2× (engine +
    /// legacy parallel). The 1× reduction is named-and-accepted
    /// given M3d removes the legacy bundle-derivation chain entirely;
    /// the engine path is the load-bearing path going forward and
    /// the redundant second exercise of the same signer would only
    /// have decaying value.
    ///
    /// # Test fixture sweep
    ///
    /// 9 combinations: `n_in ∈ {1, 2, 3}` × `subaddress_idx ∈
    /// {PRIMARY, 1, 42}`. For each combination the test:
    ///
    /// 1. Constructs `n_in` outputs paid to `subaddress_keys(idx)`
    ///    (every recipient — including PRIMARY — uses the
    ///    `subaddress_keys` derivation because the bundle composition
    ///    bakes `m_i` in additively for every idx, so the recipient
    ///    must include `m_i * G` for `O = (ho + b + m_i) * G + y * T`
    ///    to recover with `bundle.spend_key_x = ho + b + m_i`).
    /// 2. Recovers each output via `scan_output_recover` and composes
    ///    a hand-derived legacy bundle for the parallel-path call.
    /// 3. Derives the engine bundle via
    ///    [`derive_source_secrets_bundle`].
    /// 4. Builds a single-leaf-chunk Selene tree at `tree_depth = 1`
    ///    containing all `n_in` entries (each engine SpendInput
    ///    references the same chunk, with its own
    ///    `(output_key, commitment)` selecting which entry it is
    ///    spending). `h_pqc` values come from
    ///    [`make_synthetic_h_pqc_bytes`] — synthetic-but-canonical
    ///    Selene scalars; the FCMP++ verifier accepts any consistent
    ///    `h_pqc` because `pqc_pk_hashes` is a public input rather
    ///    than re-derived from a real PQC public key in-circuit.
    /// 5. Asserts engine `SpendInput` byte-identity vs the hand-
    ///    composed legacy `SpendInput` field-by-field at the input
    ///    layer.
    /// 6. Calls [`tx_builder::sign_transaction`] *once* on the engine
    ///    path with the assembled outputs, fee, and `TreeContext`.
    /// 7. Asserts:
    ///    - **Functional success.** The sign call returns `Ok(_)`.
    ///    - **Verifier acceptance.** The engine-path
    ///      `bulletproof_plus` deserializes via
    ///      `Bulletproof::read_plus` and verifies via
    ///      `Bulletproof::verify` against the un-cofactored output
    ///      commitment points; the engine-path `fcmp_proof` verifies
    ///      via `shekyl_fcmp::proof::verify` against the engine-
    ///      derived key images, the proof's pseudo-outputs, the
    ///      synthetic `h_pqc` Selene scalars, the synthetic single-
    ///      leaf-chunk tree root, and the same `signable_tx_hash`
    ///      passed to the prover.
    ///    - **Echo-passthrough.** `reference_block` and `tree_depth`
    ///      from the input `TreeContext` are echoed unchanged in
    ///      `SignedProofs`.
    ///
    /// # Why the test lives here, not in `tests/`
    ///
    /// Same reason as
    /// [`derive_source_secrets_bundle_byte_identical_against_legacy_chain`]:
    /// [`LocalKeys`], [`SourceSecretsBundle`], and the
    /// `Zeroizing<...>` field accessors are `pub(crate)` per the M3a
    /// Round 4a visibility lock. Integration tests run as external
    /// crates and cannot reach `pub(crate)`; expanding visibility
    /// for one test contradicts the lock. The
    /// [`docs/FOLLOWUPS.md`] amendment in this PR's final commit
    /// co-locates the re-location of this test with the M3b D5
    /// re-location at the "`KeyEngine` widens to `pub`" trigger.
    ///
    /// [`derive_source_secrets_bundle`]: super::traits::key::KeyEngine::derive_source_secrets_bundle
    /// [`KeyEngine`]: super::traits::key::KeyEngine
    /// [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`]: super::error::KeyEngineError::SignTransactionTraitSurfaceIncomplete
    /// [`LocalKeys`]: super::local_keys::LocalKeys
    /// [`SourceSecretsBundle`]: super::traits::key::SourceSecretsBundle
    /// [`tx_builder::sign_transaction`]: shekyl_tx_builder::sign::sign_transaction
    #[test]
    #[allow(non_snake_case)]
    fn engine_derived_bundle_signs_through_tx_builder_end_to_end() {
        use rand_core::OsRng;
        use shekyl_bulletproofs::Bulletproof;
        use shekyl_crypto_pq::kem::HybridCiphertext;
        use shekyl_fcmp::proof::{verify, KeyImage, ShekylFcmpProof};
        use shekyl_fcmp::PqcLeafScalar;
        use shekyl_io::CompressedPoint;
        use shekyl_primitives::Commitment;
        use shekyl_tx_builder::{sign_transaction, LeafEntry, SpendInput, TreeContext};

        let keys = LocalKeys::from_test_seed(TEST_SEED);

        let n_in_values: [usize; 3] = [1, 2, 3];
        let subaddress_indices = [
            SubaddressIndex::PRIMARY,
            SubaddressIndex::new(1),
            SubaddressIndex::new(42),
        ];

        let tree_depth: u8 = 1;
        let signable_tx_hash = [0xC3u8; 32];
        let reference_block = [0xD4u8; 32];
        let fee: u64 = 1_000;

        for &n_in in &n_in_values {
            for &subaddress_idx in &subaddress_indices {
                let context = format!("n_in={n_in}, subaddress_idx={}", subaddress_idx.get());

                // Recipient = subaddress_keys(idx). Used uniformly for
                // every idx including PRIMARY: the bundle composition
                // adds m_i additively for every idx (per
                // `derive_source_secrets_bundle` step 4 docstring),
                // so the recipient must include m_i * G for
                // `O = (ho + b + m_i)*G + y*T` to recover with
                // `bundle.spend_key_x = ho + b + m_i`.
                let (recipient_point, _) = subaddress_keys(
                    &keys.derived.view_scalar,
                    &keys.derived.spend_public,
                    &subaddress_idx.to_canonical_bytes(),
                );
                let recipient_spend_pk = recipient_point.compress().to_bytes();

                // ── Build inputs ───────────────────────────────────
                let mut input_amounts: Vec<u64> = Vec::with_capacity(n_in);
                let mut leaf_chunk: Vec<LeafEntry> = Vec::with_capacity(n_in);
                let mut engine_bundles: Vec<_> = Vec::with_capacity(n_in);
                let mut legacy_bundles: Vec<_> = Vec::with_capacity(n_in);

                for input_idx in 0..n_in {
                    let output_index = input_idx as u64;
                    let amount = 100_000u64 + 50_000 * output_index;
                    input_amounts.push(amount);

                    let constructed = construct_output(
                        &TEST_TX_KEY_SECRET,
                        &keys.keys.x25519_pk,
                        &keys.keys.ml_kem_ek,
                        &recipient_spend_pk,
                        amount,
                        output_index,
                    )
                    .expect("construct_output succeeds for synthetic recipient");

                    let ciphertext = HybridCiphertext {
                        x25519: constructed.kem_ciphertext_x25519,
                        ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
                    };

                    // Legacy chain (parallel): scan_output_recover →
                    // hand-composed (ho + b + m_i). Same recipe as
                    // `derive_source_secrets_bundle_byte_identical_against_legacy_chain`.
                    let recovered = scan_output_recover(
                        keys.keys.view_sk.as_canonical_bytes(),
                        keys.keys.ml_kem_dk.as_canonical_bytes(),
                        &constructed.kem_ciphertext_x25519,
                        &constructed.kem_ciphertext_ml_kem,
                        &constructed.output_key,
                        &constructed.commitment,
                        &constructed.enc_amount,
                        constructed.amount_tag,
                        &constructed.enc_label,
                        constructed.label_tag,
                        constructed.view_tag_x25519,
                        output_index,
                    )
                    .expect("scan_output_recover succeeds for self-paid synthetic output");
                    let ho_scalar: Scalar =
                        Option::from(Scalar::from_canonical_bytes(recovered.ho))
                            .expect("ho from wide_reduce is canonical");
                    let b_scalar: Scalar =
                        Scalar::from_bytes_mod_order(*keys.keys.spend_sk.as_canonical_bytes());
                    let m_i: Scalar = subaddress_derivation_scalar(
                        &keys.derived.view_scalar,
                        &subaddress_idx.to_canonical_bytes(),
                    );
                    let legacy_x_bytes = (ho_scalar + b_scalar + m_i).to_bytes();
                    let legacy_y_bytes = recovered.y;
                    let legacy_z_bytes = recovered.z;
                    let legacy_combined_ss = recovered.combined_ss;

                    // Engine chain.
                    let engine_bundle = keys
                        .derive_source_secrets_bundle(&ciphertext, output_index, subaddress_idx)
                        .expect("engine derive_source_secrets_bundle must succeed");

                    // Self-check: re-assert M3b D5 byte-identity at
                    // the bundle layer so a regression here is
                    // attributed correctly (engine bundle vs legacy
                    // chain) before the verifier disposition fires.
                    assert_eq!(
                        *engine_bundle.spend_key_x, legacy_x_bytes,
                        "engine vs legacy spend_key_x mismatch ({context}, input={input_idx})"
                    );
                    assert_eq!(
                        *engine_bundle.spend_key_y, legacy_y_bytes,
                        "engine vs legacy spend_key_y mismatch ({context}, input={input_idx})"
                    );
                    assert_eq!(
                        *engine_bundle.commitment_mask, legacy_z_bytes,
                        "engine vs legacy commitment_mask mismatch ({context}, input={input_idx})"
                    );
                    assert_eq!(
                        engine_bundle.combined_ss.as_slice(),
                        &legacy_combined_ss[..],
                        "engine vs legacy combined_ss mismatch ({context}, input={input_idx})"
                    );

                    // Build leaf chunk entry. Each entry's
                    // `key_image_gen` MUST equal `biased_hash_to_point(O)`
                    // because tx_builder recomputes it that way
                    // internally (`compute_key_image_gen`) and the
                    // FCMP++ in-circuit constraint binds the leaf-
                    // stored value to the prover's claim.
                    let h_pqc = make_synthetic_h_pqc_bytes(
                        (n_in as u64) * 1_000_000
                            + u64::from(subaddress_idx.get()) * 1_000
                            + (input_idx as u64),
                    );
                    leaf_chunk.push(LeafEntry {
                        output_key: constructed.output_key,
                        key_image_gen: shekyl_generators::biased_hash_to_point(
                            constructed.output_key,
                        )
                        .compress()
                        .to_bytes(),
                        commitment: constructed.commitment,
                        h_pqc,
                    });

                    legacy_bundles.push((
                        legacy_x_bytes,
                        legacy_y_bytes,
                        legacy_z_bytes,
                        legacy_combined_ss,
                    ));
                    engine_bundles.push(engine_bundle);
                }

                // Compute the synthetic single-leaf-chunk tree root
                // from the assembled chunk.
                let tree_leaves: Vec<_> = leaf_chunk
                    .iter()
                    .map(|e| {
                        let o = CompressedEdwardsY(e.output_key)
                            .decompress()
                            .expect("output_key is on-curve");
                        let i = CompressedEdwardsY(e.key_image_gen)
                            .decompress()
                            .expect("key_image_gen is on-curve");
                        let c = CompressedEdwardsY(e.commitment)
                            .decompress()
                            .expect("commitment is on-curve");
                        (o, i, c, e.h_pqc)
                    })
                    .collect();
                let tree_root = build_synthetic_single_chunk_tree_root(&tree_leaves);
                let tree = TreeContext {
                    reference_block,
                    tree_root,
                    tree_depth,
                };

                // ── Build SpendInputs ───────────────────────────────
                let mk_spendinput = |i: usize,
                                     spend_key_x: [u8; 32],
                                     spend_key_y: [u8; 32],
                                     commitment_mask: [u8; 32],
                                     combined_ss: Vec<u8>|
                 -> SpendInput {
                    SpendInput {
                        output_key: leaf_chunk[i].output_key,
                        commitment: leaf_chunk[i].commitment,
                        amount: input_amounts[i],
                        spend_key_x,
                        spend_key_y,
                        commitment_mask,
                        h_pqc: leaf_chunk[i].h_pqc,
                        combined_ss,
                        output_index: i as u64,
                        leaf_chunk: leaf_chunk.clone(),
                        c1_layers: vec![],
                        c2_layers: vec![],
                    }
                };

                let engine_inputs: Vec<SpendInput> = engine_bundles
                    .iter()
                    .enumerate()
                    .map(|(i, b)| {
                        // Read `combined_ss` directly out of the
                        // `Zeroizing`-wrapped engine bundle into the
                        // `SpendInput` (which itself zeroizes
                        // `combined_ss` on `Drop` per
                        // `tx_builder::types::SpendInput::drop`). No
                        // intermediate unprotected `Vec<u8>` lingers
                        // for the test's lifetime — addresses Copilot
                        // review on PR #38 against the prior
                        // `combined_ss_inputs: Vec<Vec<u8>>` shape.
                        mk_spendinput(
                            i,
                            *b.spend_key_x,
                            *b.spend_key_y,
                            *b.commitment_mask,
                            b.combined_ss.to_vec(),
                        )
                    })
                    .collect();

                let legacy_inputs: Vec<SpendInput> = legacy_bundles
                    .iter()
                    .enumerate()
                    .map(|(i, (x, y, z, ss))| mk_spendinput(i, *x, *y, *z, ss.to_vec()))
                    .collect();

                // ── SpendInput byte-equality (input layer) ──────────
                //
                // Field-by-field equality between engine-derived and
                // legacy-derived SpendInputs. This is strictly stronger
                // than the post-Trim-1-superseded `commitments` /
                // `enc_amounts` byte-equality at the signer-output
                // layer: byte-equality at the SpendInput layer plus
                // the determinism of `tx_builder::sign_transaction`'s
                // `OutputInfo → commitments` mapping implies output-
                // layer byte-equality, AND additionally guards
                // against a class of regressions where two SpendInputs
                // differ in fields that don't affect commitments /
                // enc_amounts but do affect signature behavior or
                // future field additions. See the Trim-1 disposition
                // note in the docstring's "Workspace-coverage note"
                // section.
                assert_eq!(
                    engine_inputs.len(),
                    legacy_inputs.len(),
                    "engine vs legacy SpendInput vec length mismatch ({context})"
                );
                for (i, (e, l)) in engine_inputs.iter().zip(legacy_inputs.iter()).enumerate() {
                    assert_eq!(
                        e.output_key, l.output_key,
                        "SpendInput.output_key mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.commitment, l.commitment,
                        "SpendInput.commitment mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.amount, l.amount,
                        "SpendInput.amount mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.spend_key_x, l.spend_key_x,
                        "SpendInput.spend_key_x mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.spend_key_y, l.spend_key_y,
                        "SpendInput.spend_key_y mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.commitment_mask, l.commitment_mask,
                        "SpendInput.commitment_mask mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.h_pqc, l.h_pqc,
                        "SpendInput.h_pqc mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.combined_ss, l.combined_ss,
                        "SpendInput.combined_ss mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.output_index, l.output_index,
                        "SpendInput.output_index mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.leaf_chunk.len(),
                        l.leaf_chunk.len(),
                        "SpendInput.leaf_chunk length mismatch ({context}, input={i})"
                    );
                    for (j, (ec, lc)) in e.leaf_chunk.iter().zip(l.leaf_chunk.iter()).enumerate() {
                        assert_eq!(
                            ec.output_key, lc.output_key,
                            "leaf_chunk[{j}].output_key mismatch ({context}, input={i})"
                        );
                        assert_eq!(
                            ec.key_image_gen, lc.key_image_gen,
                            "leaf_chunk[{j}].key_image_gen mismatch ({context}, input={i})"
                        );
                        assert_eq!(
                            ec.commitment, lc.commitment,
                            "leaf_chunk[{j}].commitment mismatch ({context}, input={i})"
                        );
                        assert_eq!(
                            ec.h_pqc, lc.h_pqc,
                            "leaf_chunk[{j}].h_pqc mismatch ({context}, input={i})"
                        );
                    }
                    assert_eq!(
                        e.c1_layers, l.c1_layers,
                        "SpendInput.c1_layers mismatch ({context}, input={i})"
                    );
                    assert_eq!(
                        e.c2_layers, l.c2_layers,
                        "SpendInput.c2_layers mismatch ({context}, input={i})"
                    );
                }

                // ── Build outputs (one self-paid output sweeping all funds minus fee) ──
                //
                // The recipient output's `output_index` is shifted by
                // an offset large enough to never collide with any
                // input's `output_index` in the sweep. Without the
                // offset, when the input and output share the same
                // (combined_ss, output_index) the HKDF-derived
                // commitment masks are equal, and FCMP++'s
                // rerandomization scalar `r_c = a_i - z_in` collapses
                // to zero (single-input/single-output case), which
                // surfaces as `ScalarDecompositionFailed` from the
                // upstream prover. The collision is a fixture quirk,
                // not a property failure: in production each output
                // uses an ephemeral tx-key so input/output combined_ss
                // differ even at matching indices.
                let input_total: u64 = input_amounts.iter().sum();
                let output_total = input_total.checked_sub(fee).unwrap_or_else(|| {
                    panic!(
                        "fixture invariant violated: input_total ({input_total}) < fee ({fee}) \
                         ({context}); a future fixture-table edit must keep \
                         `sum(input_amounts) >= fee`"
                    )
                });
                let recipient_output_index: u64 = (n_in as u64) + 100;
                let outputs = vec![make_recipient_output_info(
                    &keys,
                    output_total,
                    recipient_output_index,
                )];

                // ── Sign engine path (sole sign call; legacy parallel
                //    sign call removed per the Trim-1 disposition) ───
                let signed_engine =
                    sign_transaction(signable_tx_hash, &engine_inputs, &outputs, fee, &tree)
                        .unwrap_or_else(|e| {
                            panic!("engine-bundle sign_transaction must succeed ({context}): {e:?}")
                        });

                // ── Echo-passthrough ────────────────────────────────
                assert_eq!(
                    signed_engine.reference_block, reference_block,
                    "reference_block echo violated ({context})"
                );
                assert_eq!(
                    signed_engine.tree_depth, tree_depth,
                    "tree_depth echo violated ({context})"
                );

                // ── Verifier acceptance: Bulletproof+ ───────────────
                // BP+ verify takes the un-cofactored commitment
                // points (`mask*G + amount*H` without the factor-8
                // multiplication tx_builder applies for the
                // SignedProofs.commitments echo). Recompute from
                // OutputInfo to ensure we feed the right shape.
                let bp_commitments: Vec<CompressedPoint> = outputs
                    .iter()
                    .map(|out| {
                        let mask = Scalar::from_canonical_bytes(out.commitment_mask)
                            .expect("commitment_mask from OutputInfo is canonical");
                        let c = Commitment::new(mask, out.amount);
                        CompressedPoint::from(c.calculate().compress().to_bytes())
                    })
                    .collect();
                let bp = Bulletproof::read_plus(&mut signed_engine.bulletproof_plus.as_slice())
                    .unwrap_or_else(|e| panic!("bulletproof_plus deserializes ({context}): {e:?}"));
                let mut rng = OsRng;
                assert!(
                    bp.verify(&mut rng, &bp_commitments),
                    "BP+ verifier must accept engine-signed range proof ({context})"
                );

                // ── Verifier acceptance: FCMP++ ─────────────────────
                let key_images: Vec<KeyImage> = engine_inputs
                    .iter()
                    .map(|inp| {
                        KeyImage::from_canonical_bytes(compute_test_key_image(
                            inp.output_key,
                            inp.spend_key_x,
                        ))
                    })
                    .collect();
                let pqc_pk_hashes: Vec<PqcLeafScalar> = engine_inputs
                    .iter()
                    .map(|inp| PqcLeafScalar(inp.h_pqc))
                    .collect();
                let proof = ShekylFcmpProof {
                    data: signed_engine.fcmp_proof.clone(),
                    num_inputs: u32::try_from(n_in).expect("n_in is bounded by the [1, 3] sweep"),
                    tree_depth,
                };
                let result = verify(
                    &proof,
                    &key_images,
                    &signed_engine.pseudo_outs,
                    &pqc_pk_hashes,
                    &tree.tree_root,
                    tree.tree_depth,
                    signable_tx_hash,
                );
                assert!(
                    matches!(result, Ok(true)),
                    "FCMP++ verifier must accept engine-signed proof ({context}): {result:?}"
                );
            }
        }
    }

    /// Cross-seed isolation: the byte-identical-derivation property
    /// holds within a wallet, but the bundle bytes diverge across
    /// distinct seeds even when the on-chain ciphertext is identical.
    /// This guards against a regression where the bundle accidentally
    /// drops its dependency on engine-owned secret material.
    ///
    /// # Why "diverge" rather than "fail"
    ///
    /// ML-KEM-768 implements **implicit rejection** per FIPS 203: a
    /// decap failure does not propagate as an error; it returns a
    /// deterministic dummy shared secret derived from the ciphertext
    /// and the decap key. This is the IND-CCA2 property that prevents
    /// an attacker from distinguishing "wrong wallet" from "tampered
    /// ciphertext" via timing / error-channel oracles.
    /// `derive_source_secrets_bundle` consequently succeeds even
    /// against a ciphertext encapsulated to a different wallet — but
    /// the resulting bundle is junk (the combined_ss is the dummy
    /// secret; the spend_key_x / _y / commitment_mask cascade off
    /// it). The cross-seed isolation property is "the junk bundle
    /// differs byte-for-byte from the legitimate bundle," not "the
    /// function refuses."
    #[test]
    fn derive_source_secrets_bundle_diverges_across_distinct_seeds() {
        use shekyl_crypto_pq::kem::HybridCiphertext;

        let keys_a = LocalKeys::from_test_seed(TEST_SEED);
        let keys_b = LocalKeys::from_test_seed([0xAAu8; 32]);

        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &keys_a.keys.x25519_pk,
            &keys_a.keys.ml_kem_ek,
            keys_a.keys.spend_pk.as_canonical_bytes(),
            777,
            5,
        )
        .unwrap();
        let ciphertext_for_a = HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };

        let bundle_a = keys_a
            .derive_source_secrets_bundle(&ciphertext_for_a, 5, SubaddressIndex::PRIMARY)
            .expect("wallet_a recovers its own ciphertext");

        // wallet_b's re-decap engages ML-KEM-768 implicit rejection;
        // the call succeeds but yields a junk bundle.
        let bundle_b = keys_b
            .derive_source_secrets_bundle(&ciphertext_for_a, 5, SubaddressIndex::PRIMARY)
            .expect("ML-KEM-768 implicit rejection — succeeds with junk bundle");

        // Junk vs legitimate: the secret-bearing fields must differ.
        // (combined_ss is the load-bearing one; the rest cascade off
        // it via derive_output_secrets, so they all diverge as a
        // package.)
        assert_ne!(
            bundle_a.combined_ss.as_slice(),
            bundle_b.combined_ss.as_slice(),
            "combined_ss must differ across wallets even with identical ciphertext"
        );
        assert_ne!(
            *bundle_a.spend_key_x, *bundle_b.spend_key_x,
            "spend_key_x must differ across wallets"
        );
        assert_ne!(
            *bundle_a.spend_key_y, *bundle_b.spend_key_y,
            "spend_key_y must differ across wallets"
        );
        assert_ne!(
            *bundle_a.commitment_mask, *bundle_b.commitment_mask,
            "commitment_mask must differ across wallets"
        );

        // Sanity: bundle_a's bytes are not all-zero (regression guard
        // against a future "field accidentally never written" defect).
        assert_ne!(*bundle_a.spend_key_x, [0u8; 32]);
        assert_ne!(*bundle_a.spend_key_y, [0u8; 32]);
        assert_ne!(*bundle_a.commitment_mask, [0u8; 32]);
        assert_eq!(bundle_a.combined_ss.len(), 64);
        assert!(bundle_a.combined_ss.iter().any(|&b| b != 0));
    }

    #[tokio::test]
    async fn sign_transaction_returns_named_gap_stub() {
        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let tx = TxToSign {
            inputs: vec![],
            outputs: vec![],
            fcmp_plus_plus_context: crate::engine::traits::key::FcmpPlusPlusContext {},
        };
        let err = keys
            .sign_transaction(&tx)
            .await
            .expect_err("sign_transaction is stub-bearing in M3a");
        assert!(matches!(
            err,
            KeyEngineError::SignTransactionTraitSurfaceIncomplete
        ));
    }
}
