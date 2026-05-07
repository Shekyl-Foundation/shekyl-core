// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `KeyEngine` trait surface.
//!
//! Per [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`] §4, `KeyEngine` is the
//! wallet-side trait that owns `AllKeysBlob` privately and exposes
//! workflow-shape operations to the orchestrator. The structural property
//! the trait delivers is **secrets confined to the engine**: per-output
//! spending material (the secret-key derivative `x = ho + b`, the SAL
//! component `y`, the amount-blinding factor, the X25519 raw shared
//! secret, the 64-byte hybrid shared secret, all HKDF intermediates) lives
//! inside the implementor's stack frame or its workflow-internal handle
//! table; none of it crosses the trait boundary. The orchestrator
//! interacts with claimed outputs through opaque [`OutputHandle`]
//! references whose unforgeability is rooted in a deterministic cSHAKE256
//! derivation per [`derive_output_handle`].
//!
//! # Round 4a visibility
//!
//! Per [`super::mod`]'s visibility note, the trait ships `pub(crate)`
//! until the JSON-RPC server cutover at V3.2. Stage 1's consumer is
//! [`Engine<S>`](super::super::Engine), which lives inside this crate.
//!
//! # Workflow-shape, not primitive-shape
//!
//! The trait surface exposes actor-message granularity operations
//! (`try_claim_output`, `sign_transaction`) rather than primitive-grain
//! operations (raw ECDH, raw decap, per-message signing). Cryptographic
//! intermediates — including hybrid types from `shekyl-crypto-pq`
//! ([`HybridCiphertext`], `HybridSharedSecret`, etc.) — never cross the
//! trait boundary; they live transiently inside the implementor's stack
//! frame, zeroized on drop. See [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`]
//! §3.1.1 for the structural rationale.
//!
//! # `SourceSecretsBundle` is transitional
//!
//! [`TxInputSigningContext::source_secrets`] is a transitional bridge
//! field for M3a. The bundle's *shape* documents the contract — what
//! per-input secrets [`KeyEngine::sign_transaction`] needs from the
//! caller — and is stable across the migration. The bundle's *source*
//! evolves:
//!
//! - **M3a (this commit's bridge):** the orchestrator populates the
//!   bundle from [`TransferDetails`]'s existing secret-bearing fields
//!   before `sign_transaction` is called. The trait method extracts the
//!   secrets from the bundle and routes them into
//!   [`shekyl_tx_builder::sign_transaction`].
//! - **M3b+ (deterministic-handle pathway):** the orchestrator passes a
//!   `source_ciphertext: HybridCiphertext` instead, and the
//!   implementor derives the bundle internally from `(view_secret,
//!   source_ciphertext, output_index)`. The trait surface changes
//!   (field rename); the bundle's shape stays stable.
//!
//! Localizing the M3b churn to bundle-population sites — rather than
//! to the trait signature and every implementor — is the M3a /
//! M3b sequencing's load-bearing property. See
//! [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`] §3.1 / §3.2.
//!
//! [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_3_KEY_ENGINE.md
//! [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`]: ../../../../../docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md
//! [`Engine<S>`]: super::super::Engine
//! [`HybridCiphertext`]: shekyl_crypto_pq::kem::HybridCiphertext
//! [`TransferDetails`]: shekyl_engine_state::TransferDetails

use shekyl_address::ShekylAddress;
use shekyl_crypto_pq::handle::OutputHandle;
use shekyl_crypto_pq::kem::{HybridCiphertext, HybridKemPublicKey};
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_engine_state::SubaddressIndex;
use zeroize::Zeroizing;

use crate::engine::error::KeyEngineError;

// --- Constants -------------------------------------------------------------

/// View-tag width in bytes, pinned per
/// `STAGE_1_PR_3_KEY_ENGINE.md` §3.3 Sub-bundle A's
/// `VIEW_TAG_BYTES` row (A4 disposition Round 3 §3.1.4).
///
/// 1 byte matches `shekyl_crypto_pq::derivation::derive_view_tag_x25519`'s
/// `u8` return type and bounds the X25519-only pre-filter false-positive
/// rate to 2⁻⁸ per output. A future widening migration would bump this
/// constant and the underlying HKDF salt suffix
/// (`HKDF_SALT_VIEW_TAG_X25519`'s `-v1`) together.
pub(crate) const VIEW_TAG_BYTES: usize = 1;

// --- Address aliases -------------------------------------------------------

/// Re-export of the workspace's parsed structured address type for use
/// at the trait surface. Closes the §3.3 Sub-bundle B "open question:
/// `Address` type provenance" with the existing
/// [`shekyl_address::ShekylAddress`] type.
pub(crate) type Address = ShekylAddress;

// --- Trait-surface message shapes (§3.3 Sub-bundle B) ----------------------

/// Account-level public address material. Stable for the wallet's
/// lifetime; cheap; touches no secrets.
///
/// Per `STAGE_1_PR_3_KEY_ENGINE.md` §3.3 Sub-bundle A, mirrors
/// `AllKeysBlob`'s public side: the 1216-byte ML-KEM-768 PK and the
/// 65-byte classical address bytes. Returned by
/// [`KeyEngine::account_public_address`] as `&AccountPublicAddress`
/// — the one trait method that hands out a borrowed reference rather
/// than an owned message, because address material is not bound to
/// any per-call context.
#[derive(Clone, Debug)]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct AccountPublicAddress {
    /// ML-KEM-768 public key (1216 bytes per FIPS 203).
    pub pqc_public_key: Vec<u8>,
    /// Encoded classical address bytes.
    pub classical_address_bytes: Vec<u8>,
}

/// View tag bytes from a hybrid ciphertext.
///
/// Newtype around `[u8; VIEW_TAG_BYTES]`. The view tag's purpose at the
/// `KeyEngine` boundary is to type-distinguish view-tag bytes from
/// arbitrary 1-byte fields in the surrounding types. `[u8; N]` shape
/// rather than a typed hash output is intentional — view tags are
/// short publicly-comparable bytestrings, not opaque hashes that need
/// verification machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct ViewTag(pub(crate) [u8; VIEW_TAG_BYTES]);

/// Input to [`KeyEngine::try_claim_output`].
///
/// Bundles the per-output detection context the scanner extracts from a
/// single on-chain output. The fields group into four cohorts; the
/// implementor consumes each cohort by routing it to a specific
/// cryptographic primitive.
///
/// All fields are public on-chain data (or per-output public encodings
/// thereof); none impose a `Zeroize` discipline on the receiver.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct OutputDetectionInput {
    // --- Cryptographic inputs to `scan_output_recover` ---------------------
    /// The hybrid ciphertext (X25519 ephemeral + ML-KEM ciphertext).
    pub ciphertext: HybridCiphertext,
    /// The output's public key `O` (32-byte compressed Edwards point).
    /// Consumed by `scan_output_recover` for the `B' = O - ho*G - y*T`
    /// recovered-spend-key computation.
    pub output_key: [u8; 32],
    /// The Pedersen commitment `C` (32-byte compressed Edwards point).
    /// Consumed by `scan_output_recover` for `C == z*G + amount*H`
    /// commitment verification.
    pub commitment: [u8; 32],

    // --- Pre-filter optimization ------------------------------------------
    /// The view tag, used by `try_claim_output`'s impl for the X25519
    /// pre-filter check.
    pub view_tag: ViewTag,

    // --- On-chain context for amount recovery and per-output identity ----
    /// Encrypted amount bytes (8-byte XOR-encrypted little-endian u64).
    pub enc_amount: [u8; 8],
    /// Amount-tag byte from the on-chain encrypted-amounts proof; used
    /// by `scan_output_recover` to validate amount integrity.
    pub amount_tag_on_chain: u8,
    /// The output's index within its containing transaction. Used for
    /// HKDF context binding inside `try_claim_output`'s impl and as
    /// part of the `OutputHandle` derivation context.
    pub output_index: u64,

    // --- Transaction-level context for OutputHandle derivation -----------
    /// The containing transaction's hash, consumed by
    /// [`shekyl_crypto_pq::handle::derive_output_handle`] alongside the
    /// view secret and `output_index` to produce the deterministic
    /// 16-byte handle. Raw `[u8; 32]` (rather than a typed `TxHash`
    /// newtype) for consistency with the workspace-wide raw-bytes
    /// pattern for transaction hashes; introducing a
    /// workspace-wide `TxHash` newtype is tracked separately.
    pub tx_hash: [u8; 32],
}

/// Result of a [`KeyEngine::try_claim_output`] call.
///
/// `Mine` carries the structured non-secret claim payload; `NotMine`
/// carries no data. Most outputs are `NotMine` in real scanning; the
/// X25519 pre-filter rejects them cheaply inside `try_claim_output`'s
/// impl without entering the handle-table insertion path.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) enum OutputClaimResult {
    Mine(OutputClaim),
    NotMine,
}

/// Structured non-secret claim payload from a successful output
/// detection.
///
/// **No fields are secret-bearing.** The per-output spending secrets
/// (the secret-key derivative, the amount-blinding factor, and HKDF-
/// derived intermediate material) live inside the implementor's
/// workflow-internal handle table keyed by `handle`; they are not
/// exposed to the orchestrator. The fields below are public on-chain
/// data ([`OutputClaim::key_image`]) and balance-display data
/// ([`OutputClaim::amount_atomic_units`]); neither imposes a
/// `Zeroize` discipline on the receiver.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct OutputClaim {
    /// Opaque reference to the per-output spending capability.
    /// Stored by the orchestrator against the claimed output's
    /// long-lived record; passed back into `sign_transaction` via
    /// [`TxInputSigningContext::handle`] at spend time. See
    /// [`OutputHandle`] for the unforgeability and privacy
    /// considerations.
    pub handle: OutputHandle,
    /// The output's key image. Public on-chain after spend.
    pub key_image: KeyImage,
    /// The decrypted output amount (atomic units). Non-secret; the
    /// orchestrator displays it as part of the wallet's balance
    /// presentation and uses it to drive transaction-build amount
    /// accounting.
    pub amount_atomic_units: u64,
}

// --- Subaddress derivation message shapes ----------------------------------

/// Purpose argument to [`KeyEngine::derive_subaddress`].
///
/// Selects which [`SubaddressFor`] variant the trait method returns.
/// New purposes accrete additively in V3.x (e.g., `PqcRecipient` for
/// hybrid-augmented audit subaddresses); the `#[non_exhaustive]`
/// annotation gives existing call sites a compile-time signal when
/// new variants land.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) enum SubaddressPurpose {
    /// Recipient context: encoded address + KEM public key for senders
    /// to encapsulate against. Used by payment-URI / QR-code
    /// generation paths.
    Recipient,
    /// Audit context: canonical spend / view public-key pair. Used by
    /// export / backup / inspection paths.
    Audit,
}

/// Discriminated return type from [`KeyEngine::derive_subaddress`].
///
/// Each variant pairs with a [`SubaddressPurpose`] variant; the
/// `#[non_exhaustive]` annotation accretes additively with
/// `SubaddressPurpose`.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) enum SubaddressFor {
    Recipient(RecipientSubaddress),
    Audit(SubaddressKeyPair),
}

/// Recipient-context subaddress payload.
///
/// Returned by `derive_subaddress(idx, SubaddressPurpose::Recipient)`.
/// Carries everything a sender needs to encapsulate to this
/// subaddress: the encoded address (for display / UI / parsing at
/// recipient input) and the hybrid KEM public key (for hybrid
/// encapsulation at transaction-build time).
///
/// **Per-subaddress derivation.** Both components of `kem_pk` are
/// bound to `(view_secret, subaddress_index)` per
/// `STAGE_1_PR_3_KEY_ENGINE.md` §3.1.3. Carrying a wallet-level
/// ML-KEM PK in the encoded subaddress would make any two encodings
/// from the same wallet trivially linkable via direct byte
/// comparison; per-subaddress derivation is rule-forced by
/// `00-mission.mdc`'s priority hierarchy.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct RecipientSubaddress {
    /// Encoded address. Parsed structured form so the type system
    /// catches encoding errors at compile time.
    pub encoded: Address,
    /// The hybrid KEM public key (X25519 + ML-KEM-768) the sender
    /// encapsulates against. Public; not zeroized.
    pub kem_pk: HybridKemPublicKey,
}

/// Audit-context subaddress payload.
///
/// Returned by `derive_subaddress(idx, SubaddressPurpose::Audit)`.
/// Carries the canonical classical spend / view public-key pair for
/// the subaddress index; used by export / backup paths.
///
/// **Today's classical-only shape.** Per `30-cryptography.mdc`'s
/// hybrid-by-default rule, a future V3.x shape may extend the audit
/// payload with the hybrid KEM PK (mirroring
/// [`RecipientSubaddress::kem_pk`]). The extension lands as an
/// additional field on `SubaddressKeyPair` (or, if the audit
/// payload's V3.x shape diverges further, as a new variant on
/// [`SubaddressFor`] + [`SubaddressPurpose`]); the `#[non_exhaustive]`
/// annotation on the enums absorbs the additive variant without
/// breaking existing call sites.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct SubaddressKeyPair {
    pub spend_pk: [u8; 32],
    pub view_pk: [u8; 32],
}

// --- Sign-transaction message shapes ---------------------------------------

/// Per-input signing context for [`KeyEngine::sign_transaction`].
///
/// References the per-output spending capability via [`Self::handle`]
/// — the opaque handle returned by an earlier
/// [`KeyEngine::try_claim_output`] call — and carries the transitional
/// [`Self::source_secrets`] bundle through which the orchestrator
/// supplies the per-input secret material today. **The exact field
/// shape is pinned in PR 5** (`PendingTxEngine`); PR 3 forward-
/// declares with the constraint that one field is `handle:
/// OutputHandle`.
///
/// # `source_secrets` is transitional
///
/// See the module-level docstring's "`SourceSecretsBundle` is
/// transitional" section. M3a's bridge consumes the bundle directly;
/// M3b's deterministic-handle pathway replaces this field with
/// `source_ciphertext: HybridCiphertext` and derives the bundle
/// internally inside the implementor.
#[derive(Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct TxInputSigningContext {
    /// Opaque reference to the per-output spending capability.
    /// Resolved by `sign_transaction`'s impl against the implementor's
    /// workflow-internal handle table.
    pub handle: OutputHandle,
    /// **Transitional bridge field.** The orchestrator populates this
    /// from [`TransferDetails`]'s secret-bearing fields before
    /// `sign_transaction` is called. M3b replaces this field with
    /// `source_ciphertext: HybridCiphertext` and derives the bundle
    /// inside the implementor.
    ///
    /// [`TransferDetails`]: shekyl_engine_state::TransferDetails
    pub source_secrets: SourceSecretsBundle,
}

/// Transitional secrets bundle for the M3a `sign_transaction` bridge.
///
/// **Documents the contract** — these are the per-input secret
/// materials [`KeyEngine::sign_transaction`] needs to produce a
/// signature against an FCMP++ input. The shape stays stable across
/// the migration; only the *source* of these materials evolves:
///
/// - **M3a (this commit's bridge):** populated from
///   [`TransferDetails`]'s existing secret-bearing fields by the
///   orchestrator before `sign_transaction` is called.
/// - **M3b+ (deterministic-handle pathway):** populated by deriving
///   from `(view_secret, source_ciphertext, output_index)` per the
///   engine's internal derivation chain. M3b removes the
///   `TransferDetails`-side population sites and replaces with
///   `source_ciphertext`-driven derivation.
///
/// Future signing implementors (Ledger hardware, multisig, future
/// PQ-aware variants) all consume the same bundle shape — the bundle
/// defines *what* secrets are needed without coupling to *where*
/// they originate. Localizing the M3b churn to the bundle-population
/// logic — rather than spreading it across the trait surface and
/// every implementor — is the load-bearing property of this
/// transitional field.
///
/// # Field correspondence with `shekyl_tx_builder::SpendInput`
///
/// Each field maps directly to the corresponding `SpendInput` secret
/// field consumed by [`shekyl_tx_builder::sign_transaction`]:
///
/// - [`Self::spend_key_x`] ↔ `SpendInput::spend_key_x`
/// - [`Self::spend_key_y`] ↔ `SpendInput::spend_key_y`
/// - [`Self::commitment_mask`] ↔ `SpendInput::commitment_mask`
/// - [`Self::combined_ss`] ↔ `SpendInput::combined_ss`
/// - [`Self::output_index`] ↔ `SpendInput::output_index`
///
/// The public on-chain components of `SpendInput` (`output_key`,
/// `commitment`, `amount`, `h_pqc`, `leaf_chunk`, `c1_layers`,
/// `c2_layers`) ride on the surrounding [`TxInputSigningContext`] /
/// [`TxToSign`] message shapes, not in this bundle — they are not
/// secrets.
///
/// [`TransferDetails`]: shekyl_engine_state::TransferDetails
/// [`shekyl_tx_builder::sign_transaction`]: shekyl_tx_builder::sign_transaction
#[derive(Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct SourceSecretsBundle {
    /// Output-key secret `x` where `O = x*G + y*T`. 32-byte canonical
    /// little-endian Ed25519 scalar encoding.
    pub spend_key_x: Zeroizing<[u8; 32]>,
    /// SAL output-key secret `y` where `O = x*G + y*T`. 32-byte
    /// canonical little-endian Ed25519 scalar encoding.
    pub spend_key_y: Zeroizing<[u8; 32]>,
    /// Pedersen commitment mask `z` where `C = z*G + amount*H`.
    /// 32-byte canonical little-endian Ed25519 scalar encoding.
    pub commitment_mask: Zeroizing<[u8; 32]>,
    /// Combined hybrid KEM shared secret (X25519 || ML-KEM-768) for
    /// PQC key derivation. The 64-byte concatenation expected by
    /// `shekyl-crypto-pq`'s HKDF chain.
    pub combined_ss: Zeroizing<Vec<u8>>,
    /// Output index within the containing transaction. Binds the PQC
    /// key derivation to a specific output position.
    pub output_index: u64,
}

/// Input to [`KeyEngine::sign_transaction`].
///
/// Bundles all per-input signing context, per-output context, and
/// FCMP++ context the signing pass needs. **The exact field shape
/// depends on FCMP++ context details and is finalized in PR 5
/// (`PendingTxEngine`)** alongside that trait's transaction-build
/// workflow; the shape declared here is PR-3-side stub adequate for
/// trait extraction but not for actual transaction construction.
#[derive(Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct TxToSign {
    /// Per-input signing context (one entry per spend input).
    pub inputs: Vec<TxInputSigningContext>,
    /// Per-output context (commitment, amount-blinding factor,
    /// destination subaddress kem_pk). Pinned in PR 5.
    pub outputs: Vec<TxOutputContext>,
    /// FCMP++ transaction-level context (reference block, anchor
    /// data, etc.). Pinned in PR 5.
    pub fcmp_plus_plus_context: FcmpPlusPlusContext,
}

/// Per-output signing context. **Forward declaration; pinned in PR 5
/// (`PendingTxEngine`).**
#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct TxOutputContext {}

/// FCMP++ transaction-level signing context. **Forward declaration;
/// pinned in PR 5 (`PendingTxEngine`).**
#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct FcmpPlusPlusContext {}

/// Output of [`KeyEngine::sign_transaction`].
///
/// Carries hybrid signatures per-input, FCMP++ witnesses, and any
/// other signature-class output the signing pass produces. All fields
/// are public (signatures are public by definition); no `Zeroizing`
/// discipline applies.
#[derive(Debug)]
#[non_exhaustive]
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; consumers land in M3c+.
pub(crate) struct TxSignatures {
    /// Per-input hybrid signature bundle.
    pub per_input: Vec<TxInputSignature>,
    /// FCMP++ membership-proof witnesses, one per input.
    pub fcmp_plus_plus_witnesses: Vec<FcmpPlusPlusWitness>,
}

/// Per-input hybrid signature payload. **Forward declaration;
/// pinned in PR 5 (`PendingTxEngine`).**
#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct TxInputSignature {}

/// FCMP++ membership-proof witness. **Forward declaration; pinned
/// in PR 5 (`PendingTxEngine`).**
#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct FcmpPlusPlusWitness {}

// --- Trait surface ---------------------------------------------------------

/// Engine-side view of wallet key material (§2.1).
///
/// Owns `AllKeysBlob` privately; no other actor sees raw key
/// material. Per the §1.3 inlining-for-audit rationale, every key
/// operation should inline into one audited compilation unit. The
/// trait surface is workflow-shape: it exposes actor-message
/// granularity operations ([`Self::try_claim_output`],
/// [`Self::sign_transaction`]) rather than primitive-grain
/// operations (raw ECDH, raw decap, per-message signing).
/// Cryptographic intermediates — including hybrid types from
/// `shekyl-crypto-pq` — never cross the trait boundary; they live
/// transiently inside the implementor's stack frame, zeroized on
/// drop. See `STAGE_1_PR_3_KEY_ENGINE.md` §3.1.1 for the structural
/// rationale.
///
/// # Supertrait bounds
///
/// - `Send + Sync + 'static` — `KeyEngine` instances are shared
///   across orchestration futures by `Arc<K>`. The Stage 1
///   implementor `LocalKeys` (lands in M3a Commit 4) carries
///   `AllKeysBlob` under interior mutability if needed; the
///   Stage 4 actor implementor satisfies the same bounds via
///   `ActorRef<KeyActor>`.
/// - **Not** `Clone` — implementors wrap `AllKeysBlob` (which is
///   `ZeroizeOnDrop`) and are shared by `Arc`, not by clone.
///
/// # `type Error: Into<KeyEngineError>`
///
/// The trait declares an associated [`Self::Error`] type for forward
/// compatibility. M3a Commit 3 ships [`KeyEngineError`] with empty
/// starter shape per `STAGE_1_PR_3_KEY_ENGINE.md` §7.2; variants
/// accrete from the implementor's actual failure modes during M3a
/// Commit 4's `LocalKeys` work. The bound is the named landing pad
/// for additive variants per §8.2.
#[allow(dead_code)] // M3a Commit 4 introduces the implementor; pre-impl trait surface is
                    // referenced via doc-tests only at this commit.
pub(crate) trait KeyEngine: Send + Sync + 'static {
    /// Implementor-specific error. Convertible into
    /// [`KeyEngineError`] so [`Engine<S>`](super::super::Engine)
    /// orchestration code can propagate uniform errors regardless
    /// of implementor.
    type Error: Into<KeyEngineError>;

    /// Account-level public address material. Cheap; does not touch
    /// secrets. Stable for the wallet's lifetime — the only trait
    /// method returning a borrowed reference rather than an owned
    /// message, because address material is not bound to any per-call
    /// context.
    ///
    /// # Cancellation
    ///
    /// Class **a** (synchronous read with no side effect). Not
    /// awaitable; cancellation is not a concept on this method.
    ///
    /// # Idempotency
    ///
    /// **Yes.** A snapshot read of the implementor's stored public
    /// material; repeated calls observe equivalent values.
    fn account_public_address(&self) -> &AccountPublicAddress;

    /// Derive a subaddress for a specific purpose.
    ///
    /// `purpose = SubaddressPurpose::Recipient` returns
    /// `SubaddressFor::Recipient(RecipientSubaddress { encoded, kem_pk })`
    /// (encoded address + hybrid KEM PK for senders to encapsulate
    /// against; used by payment-URI / QR-code generation paths).
    ///
    /// `purpose = SubaddressPurpose::Audit` returns
    /// `SubaddressFor::Audit(SubaddressKeyPair { spend_pk, view_pk })`
    /// (canonical classical spend / view PK pair; used by export /
    /// backup / inspection paths).
    ///
    /// # Recipient purpose — derivation cost
    ///
    /// The X25519 component of `kem_pk` derives via the existing
    /// classical-Monero subaddress-derivation machinery (cheap;
    /// scalar arithmetic). The ML-KEM-768 component derives via
    /// deterministic keygen seeded by
    /// `HKDF-Expand(view_secret, SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT
    /// || subaddress_index_le_bytes)` per
    /// `STAGE_1_PR_3_KEY_ENGINE.md` §3.1.3 / §3.3 Sub-bundle A.
    /// Total cost is dominated by ML-KEM-768 KeyGen (~50 µs on
    /// commodity hardware). **Audit purpose** has the same
    /// X25519-derivation cost as Recipient and skips the ML-KEM
    /// keygen path entirely.
    ///
    /// # Cancellation
    ///
    /// Class **a** (synchronous compute, no side effect).
    ///
    /// # Idempotency
    ///
    /// **Yes.** Deterministic in `(view_secret, subaddress_index,
    /// purpose)`; repeated calls produce equivalent
    /// `SubaddressFor` values.
    fn derive_subaddress(
        &self,
        idx: SubaddressIndex,
        purpose: SubaddressPurpose,
    ) -> Result<SubaddressFor, Self::Error>;

    /// Workflow: try to claim an on-chain output for this wallet.
    ///
    /// Bundles X25519 view-tag pre-filter + hybrid decap + HKDF
    /// chain + key-image computation + handle-table insertion behind
    /// a single trait boundary. The [`OutputDetectionInput`] carries
    /// the per-output detection context (hybrid ciphertext, view
    /// tag, output index) sourced from the scanner's per-output
    /// extraction.
    ///
    /// On a successful detection, the implementor inserts the
    /// per-output spending material (secret-key derivative,
    /// amount-blinding factor, any HKDF-derived intermediates needed
    /// for spend construction) into its workflow-internal handle
    /// table and returns
    /// `OutputClaimResult::Mine(OutputClaim { handle, key_image,
    /// amount_atomic_units })`. On a rejected detection (X25519
    /// pre-filter mismatch, or post-decap validity check failure),
    /// returns `OutputClaimResult::NotMine`. Most outputs are
    /// `NotMine` in real scanning; the X25519 pre-filter rejects
    /// them cheaply without entering the handle-table insertion
    /// path.
    ///
    /// # No secret material crosses the trait boundary
    ///
    /// The X25519 raw shared secret (32 bytes), the 64-byte hybrid
    /// shared secret, HKDF intermediate keying material, the
    /// per-output secret-key derivative, and the amount-blinding
    /// factor all stay inside this method's stack frame or inside
    /// the implementor's handle table; none cross the trait
    /// boundary. The [`OutputClaim`] returned to the orchestrator
    /// carries only an opaque [`OutputHandle`] reference plus
    /// non-secret on-chain metadata
    /// ([`OutputClaim::key_image`],
    /// [`OutputClaim::amount_atomic_units`]). This is the
    /// load-bearing security property the handle-indirected
    /// workflow shape delivers.
    ///
    /// # Cancellation
    ///
    /// Class **b** (potentially side-effecting via handle-table
    /// insertion). Awaitable for future-async implementor
    /// flexibility; the M3a Stage 1 implementor `LocalKeys`
    /// completes synchronously inside the future.
    ///
    /// # Idempotency
    ///
    /// **Conditionally.** A `NotMine` result is fully idempotent.
    /// A `Mine` result inserts into the handle table; a re-call on
    /// the same `OutputDetectionInput` either re-binds the same
    /// `OutputHandle` (deterministic-handle pathway, M3b+) or
    /// returns a fresh handle on each call (counter-based pathway,
    /// not adopted). The deterministic-handle pathway is the
    /// committed direction.
    fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> impl std::future::Future<Output = Result<OutputClaimResult, Self::Error>> + Send;

    /// Workflow: sign a fully-prepared transaction.
    ///
    /// The [`TxToSign`] parameter bundles all per-input signing
    /// context (`Vec<TxInputSigningContext>`), per-output context
    /// (`Vec<TxOutputContext>`), and FCMP++ transaction-level
    /// context ([`FcmpPlusPlusContext`]). Each
    /// [`TxInputSigningContext`] references its per-output spending
    /// capability via `handle: OutputHandle` (the opaque reference
    /// returned by an earlier [`Self::try_claim_output`] call); the
    /// implementor resolves the handle internally to recover the
    /// per-output spending material needed to produce the per-input
    /// signature.
    ///
    /// # M3a transitional bridge
    ///
    /// Per the module-level "`SourceSecretsBundle` is transitional"
    /// section, M3a Commit 4's `LocalKeys::sign_transaction`
    /// extracts secrets from each
    /// `TxInputSigningContext::source_secrets` and routes them into
    /// [`shekyl_tx_builder::sign_transaction`]. M3b's
    /// deterministic-handle pathway replaces `source_secrets` with
    /// `source_ciphertext` and derives the bundle internally; the
    /// trait's contract for what secrets `sign_transaction` needs
    /// stays stable.
    ///
    /// # Validation contract
    ///
    /// The implementor validates: (i) handle resolution succeeds
    /// for every `TxInputSigningContext.handle` in `tx.inputs`;
    /// (ii) the per-input signature can be produced from the
    /// resolved per-output secret material; (iii) the FCMP++
    /// witness can be produced from the resolved spending material
    /// against `tx.fcmp_plus_plus_context`. The implementor does
    /// **not** validate amount accounting, fee calculation,
    /// recipient-address validity, or transaction structural
    /// well-formedness beyond what the type system enforces — these
    /// are caller-side preconditions per
    /// `STAGE_1_PR_3_KEY_ENGINE.md` §3.1.4 (Pattern-2 spec-silent-
    /// junctions).
    ///
    /// # Cancellation
    ///
    /// Class **b** (computational; produces signature material).
    /// Implementors complete or fail atomically — partial signature
    /// material is never returned.
    ///
    /// # Idempotency
    ///
    /// **Implementation-defined per replay-rejection contract**
    /// (Pattern-6 cluster, §7). The deterministic-handle pathway
    /// may reject double-spend attempts at the handle layer; the
    /// counter-based pathway treats each call independently. The
    /// committed direction is replay-rejection at handle resolution.
    fn sign_transaction(
        &self,
        tx: &TxToSign,
    ) -> impl std::future::Future<Output = Result<TxSignatures, Self::Error>> + Send;
}
