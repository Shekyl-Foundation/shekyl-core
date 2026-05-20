// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`ViewMaterial`]: the view-and-spend secret bundle handed to
//! [`RefreshEngine`](super::traits::RefreshEngine) implementors at
//! construction time.
//!
//! Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §3.1 +
//! §5.4.7 R4 (a-instance-scoped), `ViewMaterial` is constructed
//! once by the orchestrator from
//! [`AllKeysBlob`] under
//! the existing key read-guard, then moved into
//! `LocalRefresh::new` (Phase 0b binding form per §4) for the
//! refresh-instance's lifetime. The orchestrator never holds a
//! second copy after the move; the type's wipe-on-drop chain runs
//! when the implementor drops (today: at wallet lock; Stage 4:
//! at actor shutdown), wiping the secret material from memory.
//!
//! # Threat-model framing (§3.1)
//!
//! The §3.1 binding routing master-secret isolation through
//! `ViewMaterial` is the architectural-inheritance correction
//! (`16-architectural-inheritance.mdc` §"The inherited-architecture
//! rule"): the orchestrator is the secret-bearer at the Stage 1
//! boundary, but the secrets are exposed to the producer only via
//! the type-defined surface. The producer-side code receives the
//! bundle as a single owned move and cannot duplicate it (the type
//! deliberately does not derive [`Clone`]; see "Not `Clone`" below).
//! The Stage 4 actor-mesh cutover preserves this contract:
//! `LocalRefresh` migrates from orchestrator-owned to actor-owned;
//! `ViewMaterial` crosses the actor envelope at construction and
//! drops with the actor body.
//!
//! # Field shape (Phase 0a binding form per §4)
//!
//! The five fields are exactly those that
//! `build_scanner_from_keys` today extracts from `&AllKeysBlob` at
//! `crate::engine::refresh`; `ViewMaterial` is the named type
//! carrying them across the producer boundary so the producer
//! never re-derives them from `AllKeysBlob` and the orchestrator
//! does not need to re-hold the master keys past the move.
//!
//! - `spend_pub: EdwardsPoint` — the wallet's account-level spend
//!   public key, decompressed once at construction; held for
//!   `Scanner` view-tag pre-filtering. Public material; not wrapped
//!   in [`Zeroizing`]. [`EdwardsPoint`] does implement [`Zeroize`]
//!   under the `curve25519-dalek/zeroize` feature, so the wipe
//!   chain still clears these bytes (cheap defense-in-depth; the
//!   spend public key is recoverable from the wallet's
//!   `AllKeysBlob` and so leaks no secret).
//! - `view_scalar: Zeroizing<Scalar>` — the wallet's account-level
//!   view secret scalar. Wrapped in [`Zeroizing`] so the
//!   `Scanner`'s internal copy is wiped on drop independent of
//!   `ViewMaterial`'s outer drop (the standard
//!   `35-secure-memory.mdc` §"Prefer derived" composition pattern;
//!   double-wipe of already-zero bytes is idempotent).
//! - `x25519_sk: Zeroizing<[u8; 32]>` — the wallet's account-level
//!   X25519 secret key (hybrid KEM half).
//! - `ml_kem_dk: Zeroizing<Vec<u8>>` — the wallet's account-level
//!   ML-KEM-768 decapsulation key (hybrid KEM half). Heap-allocated;
//!   the [`Zeroizing`] wrapper wipes the heap bytes on drop. The
//!   `Vec`'s length is the secret's footprint and cannot be moved
//!   or freed in a way that resurfaces the wiped bytes.
//! - `spend_secret: Zeroizing<[u8; 32]>` — the wallet's
//!   account-level spend secret. Required for key-image computation
//!   inside the producer's per-output match path.
//!
//! # Not `Clone` (per `21-reversion-clause-discipline.mdc`)
//!
//! `ViewMaterial` deliberately does not derive [`Clone`]. The
//! a-instance-scoped lifetime story (§5.4.7 R4) is that the
//! producer holds a single instance for its lifetime; cloning is
//! not part of the contract. The [`Zeroizing<Vec<u8>>`](Zeroizing)
//! field for `ml_kem_dk` in particular would allocate a second
//! heap region on clone, doubling the secret's exposure window
//! without a named caller's need.
//!
//! Reopen criterion: if a future `RefreshEngine` implementor
//! (e.g., a hypothetical multi-scanner shape per §5.4.3 R-pin
//! futures) requires a second `ViewMaterial` copy in flight at the
//! same time, the disposition is reopened with explicit
//! threat-model justification, not by reflex `derive(Clone)`. The
//! canonical template for this discipline is the
//! `AllKeysBlob`'s "Not `Clone`" disposition at
//! `rust/shekyl-crypto-pq/src/account.rs`.
//!
//! # No `Debug` impl
//!
//! Per `35-secure-memory.mdc`, secret-bearing types do not
//! implement [`Debug`]. Logging or formatting `ViewMaterial` is a
//! contract violation by construction; the compiler enforces it.
//!
//! # `Zeroize` derive + manual `ZeroizeOnDrop` impl
//!
//! The derived [`Zeroize`] implementation wipes every field
//! ([`EdwardsPoint`] via curve25519-dalek's `zeroize` feature;
//! [`Zeroizing`] fields via their own
//! [`Zeroize`] impls). [`ZeroizeOnDrop`] is implemented manually
//! (paired with a hand-written [`Drop`] that calls
//! [`Zeroize::zeroize`]) because [`EdwardsPoint`] implements
//! [`Zeroize`] but not [`ZeroizeOnDrop`] — `derive(ZeroizeOnDrop)`
//! would fail the trait-bound check on the field. The manual form
//! delivers the same observable contract: every field's bytes are
//! cleared at scope exit.
//!
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md

use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, scalar::Scalar};
use shekyl_crypto_pq::account::AllKeysBlob;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::error::{IoError, RefreshError};

/// Per-instance view-and-spend material handed to
/// [`RefreshEngine`](super::traits::RefreshEngine) implementors at
/// construction.
///
/// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.7 R4
/// (a-instance-scoped), the orchestrator constructs this type once
/// from [`AllKeysBlob`] and
/// moves it into `LocalRefresh::new` (Phase 0b binding form per
/// §4); the type's wipe-on-drop chain runs when the implementor
/// drops, clearing the secret material.
///
/// See the module-level rustdoc for the full threat-model framing,
/// the field-by-field discipline, the "Not `Clone`" disposition,
/// and the `Zeroize` / `ZeroizeOnDrop` derivation discipline.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
#[derive(Zeroize)]
pub struct ViewMaterial {
    /// Account-level spend public key, decompressed.
    ///
    /// Public material; not secret. Wiped on drop as defense in
    /// depth (the `curve25519-dalek/zeroize` feature provides
    /// the [`Zeroize`] impl for [`EdwardsPoint`]).
    pub spend_pub: EdwardsPoint,

    /// Account-level view secret scalar. Used by the producer's
    /// `Scanner` for view-tag matching and shared-secret
    /// derivation.
    pub view_scalar: Zeroizing<Scalar>,

    /// Account-level X25519 secret key (the elliptic-curve half of
    /// the hybrid KEM). Consumed by the producer's per-output
    /// hybrid decapsulation path.
    pub x25519_sk: Zeroizing<[u8; 32]>,

    /// Account-level ML-KEM-768 decapsulation key (the lattice
    /// half of the hybrid KEM). Heap-allocated; the wrapper wipes
    /// the heap bytes on drop.
    pub ml_kem_dk: Zeroizing<Vec<u8>>,

    /// Account-level spend secret. Required for key-image
    /// computation inside the producer's per-output match path
    /// (per `shekyl-scanner`'s `Scanner` interface).
    pub spend_secret: Zeroizing<[u8; 32]>,
}

impl ViewMaterial {
    /// Construct a [`ViewMaterial`] from the wallet's
    /// [`AllKeysBlob`].
    ///
    /// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.7 R4
    /// (a-instance-scoped), this is the orchestrator's single
    /// construction site: called from `Engine::assemble` (and the
    /// test-only `replace_*` helpers) under the freshly-derived
    /// `AllKeysBlob`, then moved into
    /// `LocalRefresh::new` for the refresh-instance's lifetime.
    /// After the move the orchestrator never reads the constructed
    /// `ViewMaterial` again; it is exposed to the producer only
    /// through the [`RefreshEngine`](super::traits::RefreshEngine)
    /// trait surface.
    ///
    /// # Field derivation
    ///
    /// The five fields are extracted verbatim from `keys`:
    ///
    /// - `spend_pub`: `keys.spend_pk` decompressed once
    ///   ([`CompressedEdwardsY::decompress`]) — fails with
    ///   [`RefreshError::Io`] if the compressed point bytes are not
    ///   a canonical Edwards point.
    /// - `view_scalar`: `Scalar::from_bytes_mod_order(keys.view_sk
    ///   bytes)` — `view_sk` is stored as canonical 32-byte little-
    ///   endian, reduction is a no-op on canonical input but
    ///   `from_bytes_mod_order` is the safe choice for round-tripping
    ///   serialized scalars.
    /// - `x25519_sk`: copy of `keys.view_sk` bytes — `view_sk` and
    ///   the X25519 secret key are the same 32-byte material (the
    ///   wallet's view secret double-duties as the X25519 private
    ///   scalar via the birational mapping at derivation time).
    /// - `ml_kem_dk`: copy of `keys.ml_kem_dk.as_canonical_bytes()`
    ///   into an owned `Vec<u8>`.
    /// - `spend_secret`: copy of `keys.spend_sk` canonical bytes.
    ///
    /// All [`Zeroizing`] wrappers ensure the temporary copies are
    /// wiped on drop; the source `AllKeysBlob` is unaffected.
    ///
    /// # Errors
    ///
    /// - [`RefreshError::Io`] with [`IoError::Scanner`] when
    ///   `keys.spend_pk` is not a canonical Edwards point or does
    ///   not decompress to a curve point. Defensive: `AllKeysBlob`
    ///   construction validates the spend public key, so reaching
    ///   this branch indicates corruption of in-memory key state.
    ///
    /// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
    pub fn try_from_keys(keys: &AllKeysBlob) -> Result<Self, RefreshError> {
        let spend_pub = CompressedEdwardsY::from_slice(keys.spend_pk.as_canonical_bytes())
            .map_err(|e| {
                RefreshError::Io(IoError::Scanner {
                    detail: format!("AllKeysBlob.spend_pk is not a valid CompressedEdwardsY: {e}"),
                })
            })?
            .decompress()
            .ok_or_else(|| {
                RefreshError::Io(IoError::Scanner {
                    detail: "AllKeysBlob.spend_pk does not decompress to a curve point".to_string(),
                })
            })?;

        let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(
            *keys.view_sk.as_canonical_bytes(),
        ));
        let x25519_sk: Zeroizing<[u8; 32]> = Zeroizing::new(*keys.view_sk.as_canonical_bytes());
        let ml_kem_dk: Zeroizing<Vec<u8>> =
            Zeroizing::new(keys.ml_kem_dk.as_canonical_bytes().to_vec());
        let spend_secret: Zeroizing<[u8; 32]> = Zeroizing::new(*keys.spend_sk.as_canonical_bytes());

        Ok(Self {
            spend_pub,
            view_scalar,
            x25519_sk,
            ml_kem_dk,
            spend_secret,
        })
    }
}

impl Drop for ViewMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ViewMaterial {}
