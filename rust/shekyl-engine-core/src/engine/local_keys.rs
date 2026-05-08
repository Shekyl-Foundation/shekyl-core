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
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::output::{compute_output_key_image, scan_output_recover};
use shekyl_crypto_pq::subaddress::subaddress_keys;
use shekyl_engine_state::SubaddressIndex;
use shekyl_oxide::generators::hash_to_point;

use super::error::KeyEngineError;
use super::traits::key::{
    AccountPublicAddress, KeyEngine, OutputClaim, OutputClaimResult, OutputDetectionInput,
    SubaddressFor, SubaddressKeyPair, SubaddressPurpose, TxSignatures, TxToSign,
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
    /// Reverse-lookup table: recovered spend key `B'` (32-byte
    /// compressed Ed25519 point bytes) → [`SubaddressIndex`] that
    /// produces it.
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
    subaddress_registry: HashMap<[u8; 32], SubaddressIndex>,
}

/// The M3a in-process [`KeyEngine`] implementor.
///
/// See the module-level docstring for the structural rationale.
#[allow(dead_code)] // M3a wires the implementor; orchestrator integration lands in M3c+.
pub(crate) struct LocalKeys {
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
        let spend_public = CompressedEdwardsY(keys.spend_pk)
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
    #[cfg(test)]
    pub(crate) fn from_test_seed(seed: [u8; 32]) -> Self {
        use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};

        let (_master_seed, blob) =
            generate_account_from_raw_seed(&seed, DerivationNetwork::Testnet)
                .expect("test rederivation succeeds for raw32 testnet seeds");
        Self::from_keys_blob(blob, Network::Testnet)
    }

    /// Reverse-lookup helper: given the recovered spend key bytes
    /// returned by `scan_output_recover`, return the matching
    /// [`SubaddressIndex`] if any.
    fn lookup_subaddress(&self, recovered_spend: &[u8; 32]) -> Option<SubaddressIndex> {
        self.state
            .read()
            .expect("LocalKeys lock not poisoned")
            .subaddress_registry
            .get(recovered_spend)
            .copied()
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
                        spend_point.compress().to_bytes(),
                        view_point.compress().to_bytes(),
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
            &self.keys.ml_kem_dk,
            &input.ciphertext.x25519,
            &input.ciphertext.ml_kem,
            &input.output_key,
            &input.commitment,
            &input.enc_amount,
            input.amount_tag_on_chain,
            input.view_tag.0[0],
            input.output_index,
        ) else {
            return Ok(OutputClaimResult::NotMine);
        };

        // Stage 2: subaddress lookup via recovered spend key `B'`. A
        // miss means the recovered key matches no derived subaddress
        // — surface as `NotMine` (the wallet only claims outputs sent
        // to subaddresses it has derived).
        if self
            .lookup_subaddress(&recovered.recovered_spend_key)
            .is_none()
        {
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
            &self.keys.spend_sk,
            &hp_bytes,
        ) else {
            return Ok(OutputClaimResult::NotMine);
        };
        let key_image = KeyImage::from_canonical_bytes(ki_result.key_image);

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
            &keys.keys.spend_pk,
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
            output_index,
            tx_hash,
        };
        (input, amount)
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
        assert_ne!(pair.spend_pk, [0u8; 32]);
        assert_ne!(pair.view_pk, [0u8; 32]);
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
        assert_eq!(&encoded[1..33], &base_spend_pk[..]);
        assert_eq!(&encoded[33..65], &base_view_pk[..]);

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
        let derived_spend_pk = derived_spend_point.compress().to_bytes();
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
            &pair.spend_pk,
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
            output_index: 0,
            tx_hash: [4u8; 32],
        };

        let result = keys.try_claim_output(&input).await.unwrap();
        match result {
            OutputClaimResult::Mine(claim) => assert_eq!(claim.amount_atomic_units, 777),
            _ => panic!("Mine expected after subaddress registration"),
        }
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
