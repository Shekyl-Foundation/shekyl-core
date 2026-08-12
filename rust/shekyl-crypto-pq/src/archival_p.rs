// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `ARCHIVAL_P_DERIVE_V1`: frozen derivation of an archival staking persona `P`.
//!
//! This module is the **single source of truth** for how a Shekyl archival
//! staking persona (`P`) derives its keys from a wallet's `master_seed_64`.
//! It is the cryptographic foundation of the archival-bond construction flow
//! (`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`) and the firewall gate-6 design
//! (`docs/design/ARCHIVAL_FIREWALL_GATE6.md` §§9.3–9.6). The derivation is
//! frozen and pinned in CI by the `ARCHIVAL_P_DERIVE_V1` KAT suite
//! (`docs/test_vectors/ARCHIVAL_P_DERIVE_V1/`).
//!
//! # Why this is genesis-frozen
//!
//! A bond is recoverable only if every wallet — on every architecture — rederives
//! `P`'s keys byte-identically from the same `(master_seed_64, network, format,
//! p_slot)`. A single differing bit on `aarch64` means an ARM-phone user cannot
//! recover their own bond. This is the **third** cross-arch-deterministic primitive
//! (after `reward_arithmetic` and the standoff draw), and the highest-stakes one:
//! the `aarch64` qemu lane runs the KAT precisely to catch a platform divergence
//! before it freezes.
//!
//! # Pipeline overview
//!
//! ```text
//!  master_seed_64  ──HKDF-SHA-512(salt_for(net,fmt), info = LABEL ‖ 0x00 ‖ p_slot_le32)──┐
//!                                                                                        │
//!   ┌─── Receive address (scalar consumers) ────────────────────────────────────────────┤
//!   │  spend_wide (L=64) ── wide_reduce ── Ed25519 spend scalar ─→ spend_pk/spend_sk      │
//!   │  view_wide  (L=64) ── wide_reduce ── Ed25519 view  scalar ─→ view_pk/view_sk        │
//!   │                                                          └─ montgomery → x25519_pk  │
//!   │  kem_d_z    (L=64) ── SHA3-ChaCha ── ML-KEM-768 KG ─→ ml_kem_ek/ml_kem_dk           │
//!   │                                                                                     │
//!   ├─── Public identity (seed consumers) ────────────────────────────────────────────────┤
//!   │  account_sign_seed (L=32) ─ SigningKey::from_bytes ─┐                                  │
//!   │  ml_dsa_seed       (L=32) ─ keygen_from_seed ───────┴─→ hybrid_sign_pk/sk (= bond_id) │
//!   │                                                                                       │
//!   ├─── Debit authority (GF-1, seed consumers) ──────────────────────────────────────────┤
//!   │  bond_spend_ed_seed     (L=32) ─ SigningKey::from_bytes ─┐                             │
//!   │  bond_spend_ml_dsa_seed (L=32) ─ keygen_from_seed ───────┴─→ bond_spend_pk/sk         │
//!   │                                                                                       │
//!   └─── Serving identity (GF-9, seed consumer — not an ArchivalPKeys field) ───────────────┘
//!      hs_id_seed             (L=32) ─ SigningKey::from_bytes ─→ ed25519 pk → v3 .onion (serve)
//! ```
//!
//! # Scalar-vs-seed (the byte that gates this primitive)
//!
//! The `HybridEd25519MlDsa` scheme ([`crate::signature`]) is **seed-keyed**:
//! `SigningKey::from_bytes` treats its 32-byte input as an RFC 8032 seed and
//! derives the signing scalar as `clamp(SHA512(seed))`. A `wide_reduce_to_scalar`
//! output is a *scalar*, not a seed — feeding scalar bytes in as a seed re-hashes
//! them into a different key. Therefore:
//!
//! - The **receive-address** halves (`spend_wide`, `view_wide`) stay `L=64`
//!   wide-reduce-to-scalar, because they feed genuine scalar consumers
//!   (`spend·B`, `montgomery(view)`).
//! - Every **hybrid** half (`account_sign_seed`, `bond_spend_ed_seed`, plus the
//!   two ML-DSA seeds) is `L=32` and consumed as a seed, matching every other
//!   hybrid in the codebase ([`crate::derivation`], multisig).
//!
//! The identity hybrid uses its **own** `account_sign_seed` rather than reusing
//! the address spend scalar. This is privacy-positive, not merely hygienic:
//! `hybrid_sign_pk` rides the wire as the public `P_pubkey`
//! (`ARCHIVAL_FIREWALL_GATE6.md` §9.6); reusing the address spend pubkey would
//! leak the receive-address spend key to every bond-table observer and couple the
//! public identity to the reward address. Identity, receive address, and debit
//! authority are three independently-derived bundles under distinct labels — the
//! GF-1-carve separation principle (`ARCHIVAL_FIREWALL_GATE6.md` §9.3/§9.4).
//!
//! # Info-string construction (frozen)
//!
//! `info = LABEL ‖ 0x00 ‖ p_slot.to_le_bytes()`. The single-byte `0x00` separator
//! is locked into the wire from genesis so that adding a future label can never
//! produce a `(LABEL, p_slot)` collision against an existing label whose bytes are
//! a prefix of another (`ARCHIVAL_FIREWALL_GATE6.md` §9.3 info-string note).

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use ed25519_dalek::SigningKey;
use fips204::traits::SerDes as _;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::account::{
    ml_kem_keypair_from_d_z, salt_for, wide_reduce_to_scalar, DerivationNetwork, SeedFormat,
    MASTER_SEED_BYTES,
};
use crate::derivation::keygen_from_seed;
use crate::kem::ML_KEM_768_EK_LEN;
use crate::keys::{MlKem768DecapKey, SpendPublicKey, SpendSecret, ViewPublicKey, ViewSecret};
use crate::montgomery;
use crate::signature::{HybridPublicKey, HybridSecretKey, ML_DSA_65_SECRET_KEY_LENGTH};
use crate::CryptoError;

// --- frozen info labels ------------------------------------------------------
//
// Every label is versioned `-v1` and bumps only on a documented hard-fork /
// identity redesign. The forbidden principal-path labels (`shekyl-ed25519-spend`,
// `shekyl-ed25519-view`, `shekyl-ml-kem-768`, the `shekyl-output-derive-v1` /
// `shekyl-pqc-output` tree) must never appear on the `P` path
// (`ARCHIVAL_FIREWALL_GATE6.md` §9.3).

/// HKDF info-label for `P`'s Ed25519 **address** spend scalar (`L=64`, wide-reduce).
pub const ARCHIVAL_P_SPEND_INFO: &[u8] = b"shekyl-archival-p-ed25519-spend-v1";

/// HKDF info-label for `P`'s Ed25519 **address** view scalar (`L=64`, wide-reduce).
pub const ARCHIVAL_P_VIEW_INFO: &[u8] = b"shekyl-archival-p-ed25519-view-v1";

/// HKDF info-label for `P`'s ML-KEM-768 `d_z` (`L=64`, SHA3-ChaCha intermediary).
pub const ARCHIVAL_P_KEM_INFO: &[u8] = b"shekyl-archival-p-ml-kem-768-v1";

/// HKDF info-label for `P`'s **identity** Ed25519 hybrid half (`L=32`, RFC 8032 seed).
/// Dedicated seed — *not* the address spend scalar (see module doc / §9.3).
pub const ARCHIVAL_P_ACCOUNT_SIGN_INFO: &[u8] = b"shekyl-archival-p-ed25519-account-sign-v1";

/// HKDF info-label for `P`'s **identity** ML-DSA-65 hybrid half (`L=32`, keygen seed).
pub const ARCHIVAL_P_ML_DSA_INFO: &[u8] = b"shekyl-archival-p-ml-dsa-65-v1";

/// HKDF info-label for the GF-1 `bond_spend` Ed25519 hybrid half (`L=32`, RFC 8032 seed).
pub const ARCHIVAL_P_BOND_SPEND_ED_INFO: &[u8] = b"shekyl-archival-p-bond-spend-ed25519-v1";

/// HKDF info-label for the GF-1 `bond_spend` ML-DSA-65 hybrid half (`L=32`, keygen seed).
pub const ARCHIVAL_P_BOND_SPEND_ML_DSA_INFO: &[u8] = b"shekyl-archival-p-bond-spend-ml-dsa-65-v1";

/// HKDF info-label for `P`'s **serving-side v3 onion (HS) identity** Ed25519 half
/// (`L=32`, RFC 8032 seed) — GF-9 (`ARCHIVAL_FIREWALL_GATE6.md` §10.7 / §10.13).
///
/// The `.onion` is `p_slot`-bound and seed-derived, so it rotates with the persona
/// and never bridges a rotation. Like every sibling label it is **network-scoped**
/// (`salt = salt_for(net, fmt)`): the same wallet serves at *different* `.onion`s on
/// mainnet vs testnet/stagenet, so a persona's serving identity never links across
/// networks. That is a deliberate, frozen choice — not incidental — and the KAT's
/// `hs_id_network_separation` vector pins it un-regenerate-around-ably. **Hyphen-
/// normalized** from §10.7's proposed `shekyl.archival.p.hs_id.v1` (dots) per the
/// §10.13 carry — the dotted form is outside §9.3's hyphen-convention
/// non-prefix-free safety family. Consumer: the serving path expands this seed to
/// tor's `ED25519-V3` expanded-private key and hands it to tor via `ADD_ONION`
/// (`shekyl-tor`'s `control::onion`); `crypto-pq` owns only the seed. That
/// production path is **forthcoming** (2d-2 SP-T3); today only the disposable
/// SP-T3 spike exercises it.
pub const ARCHIVAL_P_HS_ID_INFO: &[u8] = b"shekyl-archival-p-hs-id-ed25519-v1";

/// Single-byte separator between the info label and the little-endian `p_slot`.
/// Frozen into the wire from genesis (`ARCHIVAL_FIREWALL_GATE6.md` §9.3).
pub const ARCHIVAL_P_INFO_SEPARATOR: u8 = 0x00;

// --- info-string + HKDF helpers ---------------------------------------------

/// Build the frozen HKDF `info` string: `LABEL ‖ 0x00 ‖ p_slot.to_le_bytes()`.
fn p_info(label: &[u8], p_slot: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 1 + 4);
    out.extend_from_slice(label);
    out.push(ARCHIVAL_P_INFO_SEPARATOR);
    out.extend_from_slice(&p_slot.to_le_bytes());
    out
}

/// HKDF-Expand `master_seed` to 64 bytes under `(net, fmt)` salt and the
/// `(label, p_slot)` info. The 64-byte form is wide-reduced by scalar consumers.
fn p_expand_64(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    label: &[u8],
    p_slot: u32,
) -> Zeroizing<[u8; 64]> {
    let salt = salt_for(net, fmt);
    let info = p_info(label, p_slot);
    let hk = Hkdf::<Sha512>::new(Some(&salt), master_seed);
    let mut out = [0u8; 64];
    hk.expand(&info, &mut out)
        .expect("64 bytes < HKDF-SHA-512 max output");
    Zeroizing::new(out)
}

/// HKDF-Expand `master_seed` to 32 bytes under `(net, fmt)` salt and the
/// `(label, p_slot)` info. The 32-byte form is an RFC 8032 / ML-DSA keygen seed.
fn p_expand_32(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    label: &[u8],
    p_slot: u32,
) -> Zeroizing<[u8; 32]> {
    let salt = salt_for(net, fmt);
    let info = p_info(label, p_slot);
    let hk = Hkdf::<Sha512>::new(Some(&salt), master_seed);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("32 bytes < HKDF-SHA-512 max output");
    Zeroizing::new(out)
}

// --- per-row intermediate derivations (KAT Tier-1 pins) ----------------------

/// `P` address spend 64-byte intermediate; wide-reduce via [`wide_reduce_to_scalar`].
#[must_use]
pub fn derive_p_spend_wide(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 64]> {
    p_expand_64(master_seed, net, fmt, ARCHIVAL_P_SPEND_INFO, p_slot)
}

/// `P` address view 64-byte intermediate; wide-reduce via [`wide_reduce_to_scalar`].
#[must_use]
pub fn derive_p_view_wide(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 64]> {
    p_expand_64(master_seed, net, fmt, ARCHIVAL_P_VIEW_INFO, p_slot)
}

/// `P` ML-KEM `d_z` 64-byte intermediate; feeds [`ml_kem_keypair_from_d_z`].
#[must_use]
pub fn derive_p_kem_d_z(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 64]> {
    p_expand_64(master_seed, net, fmt, ARCHIVAL_P_KEM_INFO, p_slot)
}

/// `P` identity Ed25519 RFC 8032 seed (32 B).
#[must_use]
pub fn derive_p_account_sign_seed(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 32]> {
    p_expand_32(master_seed, net, fmt, ARCHIVAL_P_ACCOUNT_SIGN_INFO, p_slot)
}

/// `P` identity ML-DSA-65 keygen seed (32 B).
#[must_use]
pub fn derive_p_ml_dsa_seed(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 32]> {
    p_expand_32(master_seed, net, fmt, ARCHIVAL_P_ML_DSA_INFO, p_slot)
}

/// GF-1 `bond_spend` Ed25519 RFC 8032 seed (32 B).
#[must_use]
pub fn derive_p_bond_spend_ed_seed(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 32]> {
    p_expand_32(master_seed, net, fmt, ARCHIVAL_P_BOND_SPEND_ED_INFO, p_slot)
}

/// GF-1 `bond_spend` ML-DSA-65 keygen seed (32 B).
#[must_use]
pub fn derive_p_bond_spend_ml_dsa_seed(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 32]> {
    p_expand_32(
        master_seed,
        net,
        fmt,
        ARCHIVAL_P_BOND_SPEND_ML_DSA_INFO,
        p_slot,
    )
}

/// `P` serving-side v3 onion (HS) identity Ed25519 RFC 8032 seed (32 B) — GF-9.
///
/// `p_slot`-bound and seed-derived (`ARCHIVAL_FIREWALL_GATE6.md` §10.7), so the
/// persona's `.onion` rotates with the slot. Its consumer expands it to tor's
/// `ED25519-V3` expanded-private key for `ADD_ONION`.
///
/// **Premise REFUTED 2026-08-12 (SH-2) — this IS an [`ArchivalPKeys`] field
/// now.** The prior ruling was "serving-only, deliberately *not* an
/// `ArchivalPKeys` field … rederived from `(master_seed, net, fmt, p_slot)` on
/// each serve, exactly like the other secrets". That is a coherent design for a
/// serving path co-resident with the wallet, which is the architecture that
/// existed when it was written. Model D then put the serving host on the far
/// side of a boundary the master seed does not cross — `StakeEngine::on_start`
/// says it outright, "the seed never reaches the actor under Model D" — and the
/// comment did not move with it. Rederive-on-each-serve is not a slower path or
/// a worse one; it is **not a reachable path**, and a persona that cannot
/// re-derive its serving identity cannot publish the `.onion` its bond
/// obligates it to answer on.
///
/// **Wrong in both directions from one stale premise, which is the case worth
/// keeping.** Read literally, the comment also invited an implementer to hand
/// `master_seed_64` to the serving process alongside `bond_spend_ed` /
/// `bond_spend_ml_dsa` — so it pointed at a custody hazard the architecture had
/// already closed while describing a mechanism the architecture had already
/// removed. It read as authoritative and the code it described could not run.
/// A comment that survives the architecture it documents is not a stale note;
/// it is an instruction to rebuild the thing that was deleted.
///
/// The line the bundle drew was one label short of what serving needs, so the
/// fix moves the line rather than crossing it: the seed is derived with every
/// other persona secret, while the master still exists, and travels in the same
/// per-slot bundle. §7.2(iii)'s custody boundary is untouched — it governs
/// StakeEngine→serving-host, and the host still receives only an expanded
/// `OnionIdentity`, never this seed.
///
/// # Callers
///
/// **One legitimate production caller: bundle assembly**
/// ([`derive_archival_p_keys`]). Any other production call site is, by
/// construction, a path taking the master seed for serving purposes — the
/// hazard above. The one that survives is
/// `shekyl-sp-t3-spike/src/onion_key.rs`, which takes `master_seed_64` because
/// it was written against the architecture this note refutes; it is on the
/// spike's own deletion surface (rule 15, "deleted or fully rewritten before
/// TJ-B") and goes with it. **The W₂ rig that replaces the spike must take an
/// `OnionIdentity` from a bundle, not a master seed.**
///
/// The KATs call this directly and *should*: deriving the value independently
/// of the bundle is what makes the bundle's field assertable against the same
/// pinned vector, so the two producers cannot drift.
///
/// The derived Ed25519 **public** key (`SigningKey::from_bytes(seed)
/// .verifying_key()`) is the v3 onion address's public key; the
/// `ARCHIVAL_P_DERIVE_V1` KAT pins both the seed and that public key, since a
/// cross-arch divergence there would leave an ARM user's persona unreachable at
/// its advertised `.onion`.
#[must_use]
pub fn derive_p_hs_id_seed(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Zeroizing<[u8; 32]> {
    p_expand_32(master_seed, net, fmt, ARCHIVAL_P_HS_ID_INFO, p_slot)
}

// --- hybrid keypair assembly -------------------------------------------------

/// Build a seed-keyed hybrid `(public, secret)` pair from a 32-byte Ed25519 RFC
/// 8032 seed and a 32-byte ML-DSA-65 keygen seed. Matches the per-output
/// construction in [`crate::derivation`] exactly so the wire encoding is shared.
fn build_hybrid(
    ed_seed: &[u8; 32],
    ml_dsa_seed: &[u8; 32],
) -> Result<(HybridPublicKey, HybridSecretKey), CryptoError> {
    let ed_signing = SigningKey::from_bytes(ed_seed);
    let ed_verifying = ed_signing.verifying_key();

    let (ml_pk, ml_sk) = keygen_from_seed(ml_dsa_seed)?;

    // `ml_sk.into_bytes()` briefly materializes a stack-resident
    // `[u8; ML_DSA_65_SECRET_KEY_LENGTH]` by value (upstream `fips204` API);
    // wrap it in `Zeroizing` so the temporary is wiped after the move into the
    // `ZeroizeOnDrop` `HybridSecretKey` Vec (same discipline as
    // `account.rs::ml_kem_keypair_from_d_z`'s decap-key temporary).
    let ml_sk_bytes: Zeroizing<[u8; ML_DSA_65_SECRET_KEY_LENGTH]> =
        Zeroizing::new(ml_sk.into_bytes());

    let public = HybridPublicKey {
        ed25519: ed_verifying.to_bytes(),
        ml_dsa: ml_pk.into_bytes().to_vec(),
    };
    let secret = HybridSecretKey {
        ed25519: ed_seed.to_vec(),
        ml_dsa: ml_sk_bytes.to_vec(),
    };

    public.validate()?;
    secret.validate()?;
    Ok((public, secret))
}

// --- ArchivalPKeys -----------------------------------------------------------

/// Every key `P` holds, rederived from `(master_seed_64, network, format, p_slot)`.
///
/// Mirrors `ARCHIVAL_FIREWALL_GATE6.md` §9.4. `p_canonical_id` is intentionally
/// **not** a field: it is computed downstream by
/// `shekyl-archival-retention::id::p_canonical_id_from_hybrid_pubkey` over
/// [`Self::hybrid_bond_id`]'s canonical bytes (`crypto-pq` must not depend on
/// `archival-retention`). The `ARCHIVAL_P_DERIVE_V1` KAT pins the id and the
/// `archival-retention` cross-check proves the two cSHAKE paths agree.
///
/// # Wipe-on-drop
///
/// The container is **not** a single `#[derive(ZeroizeOnDrop)]` because
/// [`HybridPublicKey`] and the typed public-key wrappers do not implement
/// `Zeroize` (and carry no secret). Instead every secret-bearing field is
/// individually `ZeroizeOnDrop` — `spend_sk` / `view_sk` ([`SpendSecret`] /
/// [`ViewSecret`]), `ml_kem_dk` ([`MlKem768DecapKey`]), and `hybrid_sign_sk` /
/// `bond_spend_sk` ([`HybridSecretKey`]) and `hs_id_seed` ([`Zeroizing`]) — so each wipes on drop via its own
/// destructor. This is the rule-35 per-field discipline applied to a struct that
/// also holds non-`Zeroize` public material.
///
/// **Not persisted at rest.** Persist only `p_slot` (and the public
/// `p_canonical_id`); rederive every secret on wallet open.
pub struct ArchivalPKeys {
    /// Persona slot index; the only value persisted (besides public id material).
    pub p_slot: u32,

    /// Ed25519 address spend public key (`P`'s receive address).
    pub spend_pk: SpendPublicKey,
    /// Ed25519 address spend secret scalar.
    pub spend_sk: SpendSecret,
    /// Ed25519 address view public key.
    pub view_pk: ViewPublicKey,
    /// Ed25519 address view secret scalar.
    pub view_sk: ViewSecret,

    /// ML-KEM-768 account encapsulation key.
    pub ml_kem_ek: [u8; ML_KEM_768_EK_LEN],
    /// ML-KEM-768 account decapsulation key.
    pub ml_kem_dk: MlKem768DecapKey,

    /// X25519 public key, `montgomery(view_pk)` — same birational map as principal.
    pub x25519_pk: [u8; 32],

    /// Public identity hybrid key (= `hybrid_bond_id`). Rides the wire as `P_pubkey`.
    pub hybrid_sign_pk: HybridPublicKey,
    /// Public identity hybrid secret (Ed25519 RFC 8032 seed + ML-DSA-65 secret).
    pub hybrid_sign_sk: HybridSecretKey,

    /// GF-1 bond-debit authorizer hybrid public key.
    pub bond_spend_pk: HybridPublicKey,
    /// GF-1 bond-debit authorizer hybrid secret.
    pub bond_spend_sk: HybridSecretKey,

    /// GF-9 serving-side v3 onion identity **seed** (32 B), from
    /// [`derive_p_hs_id_seed`].
    ///
    /// **The seed, deliberately — not the expanded key.** RFC 8032 expansion
    /// to tor's `ED25519-V3` blob is `shekyl-tor`'s format and it already owns
    /// that step (`OnionIdentity::from_hs_id_seed`), so the 32-byte seed is the
    /// correct boundary object: it keeps this crate ignorant of Tor's key
    /// encoding, and keeps the expansion in exactly one place rather than two
    /// that can disagree. The bundle stopping one step short of something
    /// directly usable is the point, not an omission.
    ///
    /// Carried here because a serving persona must be able to publish its
    /// `.onion` for the life of its bond, and under Model D the master seed is
    /// gone after derivation — see [`derive_p_hs_id_seed`] for the refuted
    /// "rederive on each serve" premise and the caller discipline that follows
    /// from it.
    pub hs_id_seed: Zeroizing<[u8; 32]>,
}

impl ArchivalPKeys {
    /// The bond-record identity public key. Identical to `hybrid_sign_pk`; the
    /// accessor enforces the §9.4 invariant `hybrid_bond_id == hybrid_sign_pk`
    /// structurally rather than carrying a second copy.
    #[must_use]
    pub fn hybrid_bond_id(&self) -> &HybridPublicKey {
        &self.hybrid_sign_pk
    }

    /// The public key pair a JoinMarket bond post carries, as one value:
    /// `P`'s identity key and the GF-1 bond-debit authorizer, same-persona by
    /// construction. This is the **only** producer of [`BondPostKeys`], so the
    /// two same-typed roles can be neither transposed nor mixed across
    /// personas by a caller — the pairing the pre-SA-2b `&ArchivalPKeys`
    /// builder parameter made structural, kept without handing the secret
    /// bundle to a public-only constructor (rule 36).
    #[must_use]
    pub fn bond_post_keys(&self) -> BondPostKeys<'_> {
        BondPostKeys {
            identity_pk: self.hybrid_bond_id(),
            bond_spend_pk: &self.bond_spend_pk,
        }
    }
}

/// Public-only key pair for constructing a JoinMarket bond post.
///
/// Fields are private and the sole producer is
/// [`ArchivalPKeys::bond_post_keys`]: holding one is a structural witness that
/// `identity_pk` and `bond_spend_pk` are the *same persona's* keys in the
/// *right roles* — two free `&HybridPublicKey` parameters would let a
/// transposed or cross-persona call compile and produce a self-consistent vin
/// whose mistake surfaces only at daemon-side authorization (or worse, as a
/// committed record whose GF-1 debit key can never unlock the bond).
#[derive(Clone, Copy, Debug)]
pub struct BondPostKeys<'a> {
    identity_pk: &'a HybridPublicKey,
    bond_spend_pk: &'a HybridPublicKey,
}

impl BondPostKeys<'_> {
    /// `P`'s public identity (`hybrid_bond_id` / `hybrid_sign_pk`) — the key
    /// the bond record is named by and credit paths authorize against.
    #[must_use]
    pub fn identity_pk(&self) -> &HybridPublicKey {
        self.identity_pk
    }

    /// The GF-1 bond-debit authorizer, JoinMarket-committed and immutable for
    /// the record's life.
    #[must_use]
    pub fn bond_spend_pk(&self) -> &HybridPublicKey {
        self.bond_spend_pk
    }
}

/// Derive the full `ArchivalPKeys` bundle for persona slot `p_slot`.
///
/// `master_seed` is the wallet's normalized 64-byte master seed; `(net, fmt)`
/// must be a permitted pair (same gate as [`crate::account::rederive_account`]).
/// Byte-for-byte deterministic across architectures — pinned by the
/// `ARCHIVAL_P_DERIVE_V1` KAT on the `aarch64` qemu lane.
pub fn derive_archival_p_keys(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: u32,
) -> Result<ArchivalPKeys, CryptoError> {
    if !net.permitted_seed_format(fmt) {
        return Err(CryptoError::InvalidInput(format!(
            "{net:?} does not permit {fmt:?} seed format"
        )));
    }

    // --- Receive address: Ed25519 spend (scalar consumer) ---
    let spend_wide = derive_p_spend_wide(master_seed, net, fmt, p_slot);
    let spend_scalar = wide_reduce_to_scalar(&spend_wide);
    let spend_sk = SpendSecret::from_bytes(*spend_scalar.as_bytes());
    let spend_pub = ED25519_BASEPOINT_TABLE * &spend_scalar;
    let spend_pk = SpendPublicKey::from_canonical_bytes(*spend_pub.compress().as_bytes());

    // --- Receive address: Ed25519 view (scalar consumer) ---
    let view_wide = derive_p_view_wide(master_seed, net, fmt, p_slot);
    let view_scalar = wide_reduce_to_scalar(&view_wide);
    let view_sk = ViewSecret::from_bytes(*view_scalar.as_bytes());
    let view_pub = ED25519_BASEPOINT_TABLE * &view_scalar;
    let view_pk = ViewPublicKey::from_canonical_bytes(*view_pub.compress().as_bytes());
    let x25519_pk = montgomery::ed25519_pk_to_x25519_pk(view_pk.as_canonical_bytes())?;

    // --- Receive address: ML-KEM-768 (SHA3-ChaCha intermediary) ---
    let d_z = derive_p_kem_d_z(master_seed, net, fmt, p_slot);
    let (ml_kem_ek, ml_kem_dk) = ml_kem_keypair_from_d_z(&d_z)?;

    // --- Public identity hybrid (seed consumers) ---
    let account_sign_seed = derive_p_account_sign_seed(master_seed, net, fmt, p_slot);
    let ml_dsa_seed = derive_p_ml_dsa_seed(master_seed, net, fmt, p_slot);
    let (hybrid_sign_pk, hybrid_sign_sk) = build_hybrid(&account_sign_seed, &ml_dsa_seed)?;

    // --- GF-9 serving-side onion identity seed (expanded by shekyl-tor) ---
    let hs_id_seed = derive_p_hs_id_seed(master_seed, net, fmt, p_slot);

    // --- GF-1 bond-debit authorizer hybrid (seed consumers) ---
    let bond_ed_seed = derive_p_bond_spend_ed_seed(master_seed, net, fmt, p_slot);
    let bond_ml_dsa_seed = derive_p_bond_spend_ml_dsa_seed(master_seed, net, fmt, p_slot);
    let (bond_spend_pk, bond_spend_sk) = build_hybrid(&bond_ed_seed, &bond_ml_dsa_seed)?;

    Ok(ArchivalPKeys {
        p_slot,
        spend_pk,
        spend_sk,
        view_pk,
        view_sk,
        ml_kem_ek,
        ml_kem_dk,
        x25519_pk,
        hybrid_sign_pk,
        hybrid_sign_sk,
        bond_spend_pk,
        bond_spend_sk,
        hs_id_seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

    fn keys() -> ArchivalPKeys {
        derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
            .expect("derive P keys")
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = keys();
        let b = keys();
        assert_eq!(
            a.hybrid_sign_pk.to_canonical_bytes().unwrap(),
            b.hybrid_sign_pk.to_canonical_bytes().unwrap()
        );
        assert_eq!(
            a.bond_spend_pk.to_canonical_bytes().unwrap(),
            b.bond_spend_pk.to_canonical_bytes().unwrap()
        );
        assert_eq!(
            a.spend_pk.as_canonical_bytes(),
            b.spend_pk.as_canonical_bytes()
        );
    }

    #[test]
    fn hybrid_bond_id_is_the_identity_key() {
        let k = keys();
        assert_eq!(
            k.hybrid_bond_id().to_canonical_bytes().unwrap(),
            k.hybrid_sign_pk.to_canonical_bytes().unwrap(),
            "hybrid_bond_id must equal hybrid_sign_pk (§9.4)"
        );
    }

    /// GF-1-carve independence: the identity key, the debit authorizer, and the
    /// address spend key are derived under distinct labels and must be distinct
    /// keys. A future label-drift that collapsed two of them would trip here.
    #[test]
    fn identity_debit_and_address_keys_are_independent() {
        let k = keys();
        assert_ne!(
            k.hybrid_sign_pk.ed25519, k.bond_spend_pk.ed25519,
            "identity and bond-spend Ed25519 halves must differ"
        );
        assert_ne!(
            k.hybrid_sign_pk.ml_dsa, k.bond_spend_pk.ml_dsa,
            "identity and bond-spend ML-DSA halves must differ"
        );
        // The identity Ed25519 half is a dedicated seed, NOT the address spend
        // pubkey — the privacy property the §9.3 resolution establishes.
        assert_ne!(
            &k.hybrid_sign_pk.ed25519,
            k.spend_pk.as_canonical_bytes(),
            "identity Ed25519 must not equal the address spend pubkey (privacy)"
        );
    }

    /// Label-sensitivity negative: wrong label → wrong key. This proves the
    /// GF-1-carve independence is delivered by domain separation in the HKDF
    /// `info`, not merely asserted — the standoff-trap discipline applied to
    /// label drift. A change to any label string flips the derived bytes.
    #[test]
    fn wrong_label_yields_different_key() {
        // Same (seed, net, fmt, slot); only the label differs.
        let account = p_expand_32(
            &MASTER,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            ARCHIVAL_P_ACCOUNT_SIGN_INFO,
            0,
        );
        let bond = p_expand_32(
            &MASTER,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            ARCHIVAL_P_BOND_SPEND_ED_INFO,
            0,
        );
        assert_ne!(
            account.as_slice(),
            bond.as_slice(),
            "distinct labels must give distinct seeds"
        );

        // A one-byte label perturbation must also diverge.
        let mut tweaked = ARCHIVAL_P_ACCOUNT_SIGN_INFO.to_vec();
        let last = tweaked.len() - 1;
        tweaked[last] ^= 0x01;
        let perturbed = p_expand_32(
            &MASTER,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            &tweaked,
            0,
        );
        assert_ne!(
            account.as_slice(),
            perturbed.as_slice(),
            "a 1-byte label change must change the seed"
        );

        // GF-9 serving key is a distinct label from the identity account-sign seed:
        // the two L=32 Ed25519 seeds under the same (seed, net, fmt, slot) must
        // differ, or the serving `.onion` would leak the on-chain identity key.
        let hs_id = derive_p_hs_id_seed(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0);
        assert_ne!(
            account.as_slice(),
            hs_id.as_slice(),
            "hs-id serving seed must differ from the identity account-sign seed"
        );
    }

    /// `p_slot` separation: distinct slots derive distinct personas.
    #[test]
    fn distinct_slots_yield_distinct_personas() {
        let k0 = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
            .unwrap();
        let k1 = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 1)
            .unwrap();
        assert_ne!(
            k0.hybrid_sign_pk.to_canonical_bytes().unwrap(),
            k1.hybrid_sign_pk.to_canonical_bytes().unwrap()
        );
        assert_ne!(
            k0.spend_pk.as_canonical_bytes(),
            k1.spend_pk.as_canonical_bytes()
        );
    }

    /// The frozen info-string layout: `LABEL ‖ 0x00 ‖ p_slot_le32`.
    #[test]
    fn info_string_layout_is_frozen() {
        let info = p_info(ARCHIVAL_P_SPEND_INFO, 0x0403_0201);
        let mut expected = ARCHIVAL_P_SPEND_INFO.to_vec();
        expected.push(0x00);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(info, expected);
    }

    /// The seed format gate rejects an impermissible (network, format) pair.
    #[test]
    fn rejects_impermissible_seed_format() {
        let r = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Raw32, 0);
        assert!(r.is_err(), "mainnet must reject raw32");
    }
}
