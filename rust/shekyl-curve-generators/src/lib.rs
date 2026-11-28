// Provenance: forked from monero-oxide (Shekyl-Foundation/monero-oxide, fcmp++
// lineage), originally `shekyl-oxide/generators`, last vendored at 2753111c50.
// Relocated to a first-party shekyl-* crate in the shekyl-oxide un-vendor (slice 2);
// no longer upstream-tracked. See docs/design/SHEKYL_OXIDE_UNVENDOR.md. The `b"Monero
// …"` separators below are consensus-frozen — see docs/FROZEN_DOMAIN_SEPARATORS.md.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{alloc::format, string::String, sync::LazyLock, vec::Vec};

use sha3::{Digest, Keccak256};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsBasepointTable, EdwardsPoint},
    scalar::Scalar,
    traits::{BasepointTable, Identity},
};
use group::{prime::PrimeGroup, GroupEncoding};
use helioselene::{Helios, HeliosPoint, Selene, SelenePoint};

use shekyl_curve_io::{write_varint, CompressedPoint};

mod hash_to_point;
pub use hash_to_point::{biased_hash_to_point, hash_to_point};

#[cfg(test)]
mod tests;

fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Monero's `H` generator.
///
/// Contrary to convention (`G` for values, `H` for randomness), `H` is used by Monero for amounts
/// within Pedersen commitments.
#[allow(non_snake_case)]
pub static H: LazyLock<EdwardsPoint> = LazyLock::new(|| {
    CompressedPoint::from(keccak256(&ED25519_BASEPOINT_POINT.compress().to_bytes()))
        .decompress()
        .expect("known on-curve point wasn't on-curve")
        .mul_by_cofactor()
});

static H_POW_2_CELL: LazyLock<[EdwardsPoint; 64]> = LazyLock::new(|| {
    let mut res = [*H; 64];
    for i in 1..64 {
        res[i] = res[i - 1] + res[i - 1];
    }
    res
});
/// Monero's `H` generator, multiplied by 2**i for i in 1 ..= 64.
///
/// This table is useful when working with amounts, which are u64s.
#[allow(non_snake_case)]
pub fn H_pow_2() -> &'static [EdwardsPoint; 64] {
    &H_POW_2_CELL
}

// FROZEN DST (genesis) — every `b"Monero …"` / `"Monero …"` byte-string below is a
// consensus-frozen domain separator: it is hashed to derive a generator point the
// FCMP++ proofs verify against (pinned by the `tests::frozen_points` KAT). Changing a
// byte moves the point and silently invalidates proofs. These are NOT rule-93
// (`MONERO_*` identifier) targets — a rebrand/`MONERO_`→`SHEKYL_` sweep must skip
// them. See docs/FROZEN_DOMAIN_SEPARATORS.md.

/// Monero's `T`, used to blind the key-image commitment present within output keys.
pub static T: LazyLock<EdwardsPoint> =
    LazyLock::new(|| hash_to_point(keccak256(b"Monero Generator T"))); // FROZEN DST

/// FCMP++s's key-image generator blinding generator `U`.
pub static FCMP_PLUS_PLUS_U: LazyLock<EdwardsPoint> =
    LazyLock::new(|| hash_to_point(keccak256(b"Monero FCMP++ Generator U"))); // FROZEN DST

/// FCMP++s's randomness commitment generator `V`.
pub static FCMP_PLUS_PLUS_V: LazyLock<EdwardsPoint> =
    LazyLock::new(|| hash_to_point(keccak256(b"Monero FCMP++ Generator V"))); // FROZEN DST

/// Shekyl's PQC leaf-commitment key generator `G_k`: the leaf's 4th scalar is the
/// Wei25519 x-coordinate of `CM = k·G_k + r·J` with `k = H_ℓ(hybrid_pk)`; the
/// verifier recomputes `K = k·G_k` from the key the spend reveals (`PL-D3`,
/// `docs/design/FCMP_SPEND_LINKABILITY.md` §6.2). NUMS by construction, like `T`.
pub static PQC_LEAF_COMMITMENT_G_K: LazyLock<EdwardsPoint> = LazyLock::new(|| {
    hash_to_point(keccak256(b"Shekyl PQC leaf commitment generator G_k")) // FROZEN DST
});

/// Shekyl's PQC leaf-commitment blind generator `J` (`CM = k·G_k + r·J`); the
/// in-circuit opening leg proves `K + r·J = CM` over this generator's table.
/// NUMS by construction, like `T`.
pub static PQC_LEAF_COMMITMENT_J: LazyLock<EdwardsPoint> = LazyLock::new(|| {
    hash_to_point(keccak256(b"Shekyl PQC leaf commitment generator J")) // FROZEN DST
});

/// Precomputed fixed-base table for [`PQC_LEAF_COMMITMENT_G_K`]: every output's
/// leaf commitment computes `k·G_k`, and every verifier recomputes `K = k·G_k`,
/// so the multiply is fixed-base on both sides. Built from the frozen point —
/// the frozen-point tests assert table-mul equals plain-mul, so the table
/// cannot drift from its generator.
pub static PQC_LEAF_COMMITMENT_G_K_TABLE: LazyLock<EdwardsBasepointTable> =
    LazyLock::new(|| EdwardsBasepointTable::create(&PQC_LEAF_COMMITMENT_G_K));

/// Precomputed fixed-base table for [`PQC_LEAF_COMMITMENT_J`] (`r·J` in
/// `CM = k·G_k + r·J`). Same pinning as [`PQC_LEAF_COMMITMENT_G_K_TABLE`].
pub static PQC_LEAF_COMMITMENT_J_TABLE: LazyLock<EdwardsBasepointTable> =
    LazyLock::new(|| EdwardsBasepointTable::create(&PQC_LEAF_COMMITMENT_J));

/// Decompress a published PQC leaf commitment point and check it is a
/// canonical, prime-order, non-identity point — the admission rule's content
/// check for the `tx_extra` `0x07` field (`PL-D3`,
/// `docs/design/FCMP_SPEND_LINKABILITY.md` §6.2). Returns the point on success.
///
/// One home: `shekyl-wire` applies it at relay and connect, `shekyl-crypto-pq`
/// re-exports it for the wallet's scan-time check and the tests of the
/// derivation that produces the point.
#[must_use]
pub fn pqc_leaf_point_valid(point: &[u8; 32]) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(*point).decompress()?;
    if p.compress().to_bytes() != *point {
        return None; // non-canonical encoding
    }
    if !p.is_torsion_free() || p == EdwardsPoint::identity() {
        return None;
    }
    Some(p)
}

/// The fewest FCMP++ layers a spend proves under: the leaf layer and one
/// branch above it. An empty tree has one layer and nothing to spend.
pub const MIN_SPEND_LAYERS: u8 = 2;

/// The deepest curve tree the protocol admits (`ICD-R9`,
/// `docs/design/CEN_I4_INPUT_CAP_DERIVATION.md`).
///
/// Derived in two steps. The floor is `shekyl_wire::transaction::weight::
/// TREE_DEPTH_FLOOR`, set on the chain's own write budget. This value is then
/// the deepest tree that needs no more generators than the floor does: past
/// the floor the margin is free up to here, and at the ceiling the chain
/// accepts no new outputs, so a raise is a hard fork. `shekyl-wire` computes
/// the derivation and asserts it equals this at compile time; the constant
/// lives here because this crate sits below the wire and sizes its tables by
/// it.
pub const MAX_TREE_DEPTH: u8 = 14;

/// The Selene generators the protocol builds: the largest row count any legal
/// transaction's proof needs, at any legal depth (`ICD-R2`). `shekyl-wire`
/// computes that need from the weight limit and asserts it equals this at
/// compile time, so a weight-limit change fails the build until this moves.
///
/// **Not a consensus change when it moves.** A proof over `n` padded rows uses
/// the first `n` generators (`Generators::reduce`), and each generator's
/// derivation string and index are frozen, so a longer or shorter table agrees
/// with this one on every index both hold (`tests::frozen_points`).
pub const FCMP_SELENE_GENERATORS: usize = 8192;

/// The Helios generators the protocol builds; see [`FCMP_SELENE_GENERATORS`].
pub const FCMP_HELIOS_GENERATORS: usize = 4096;

/// FCMP++ layer count the size formula accepts: one layer through
/// [`MAX_TREE_DEPTH`].
///
/// One layer is a tree with nothing to spend. The formula still has a length
/// there, which a fee estimate and a synthetic proof measure. A spend that
/// can be mined is the narrower [`SpendLayers`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProofLayers(u8);

impl ProofLayers {
    /// The one-layer tree. Nothing can be spent under it.
    pub const ONE: Self = Self(1);

    /// A layer count the formula covers.
    #[must_use]
    pub const fn new(layers: u8) -> Option<Self> {
        if layers >= 1 && layers <= MAX_TREE_DEPTH {
            Some(Self(layers))
        } else {
            None
        }
    }

    /// A layer count already known to be in range.
    ///
    /// In a const context an out-of-range count fails the build. At runtime
    /// it is a caller bug: an untrusted depth is [`Self::new`].
    #[must_use]
    pub const fn known(layers: u8) -> Self {
        match Self::new(layers) {
            Some(layers) => layers,
            None => panic!("FCMP layer count is outside 1..=MAX_TREE_DEPTH"),
        }
    }

    /// The layer count.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// FCMP++ layer count consensus can mine a spend at (`ICD-R9`).
///
/// Every value is a [`ProofLayers`]. The range starts at [`MIN_SPEND_LAYERS`]
/// because an empty tree has one layer and nothing to spend.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SpendLayers(u8);

impl SpendLayers {
    /// The shallowest tree a spend can prove under.
    pub const SHALLOWEST: Self = Self(MIN_SPEND_LAYERS);

    /// The deepest tree the protocol admits.
    pub const DEEPEST: Self = Self(MAX_TREE_DEPTH);

    /// A layer count consensus can mine a spend at.
    #[must_use]
    pub const fn new(layers: u8) -> Option<Self> {
        if layers >= MIN_SPEND_LAYERS && layers <= MAX_TREE_DEPTH {
            Some(Self(layers))
        } else {
            None
        }
    }

    /// A layer count already known to be a spend depth. See [`ProofLayers::known`].
    #[must_use]
    pub const fn known(layers: u8) -> Self {
        match Self::new(layers) {
            Some(layers) => layers,
            None => panic!("spend layer count is outside MIN_SPEND_LAYERS..=MAX_TREE_DEPTH"),
        }
    }

    /// The layer count.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// This spend depth as a proof-formula depth. Infallible: every spend
    /// depth is inside [`ProofLayers`].
    #[must_use]
    pub const fn as_proof(self) -> ProofLayers {
        ProofLayers(self.0)
    }

    /// Every spend depth, shallowest first.
    pub fn each() -> impl Iterator<Item = Self> {
        (MIN_SPEND_LAYERS..=MAX_TREE_DEPTH).map(Self)
    }
}

/// Compressed `k·G` on Ed25519.
///
/// Canonical, torsion-free, and the identity only at `k = 0`. The chain
/// mutation that adds inputs past the cap uses `k` from 2, so each copy has
/// its own key image and CEN-H11 holds.
#[must_use]
pub fn compressed_basepoint_multiple(k: u64) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * Scalar::from(k))
        .compress()
        .to_bytes()
}

/// Whether a proof of `inputs` inputs over `layers` fits the generator tables.
///
/// The one bound the prover and the verifier both read, so a proof that can
/// be built can be verified. `inputs` is an untrusted count: the first
/// comparison bounds it before `ipa_rows` multiplies it, since every input
/// needs at least one row. `layers` is already a [`ProofLayers`].
#[must_use]
pub const fn fcmp_fits_generators(inputs: usize, layers: ProofLayers) -> bool {
    if inputs == 0 || inputs > FCMP_SELENE_GENERATORS {
        return false;
    }
    let (selene, helios) =
        full_chain_membership_proofs::Fcmp::<()>::ipa_rows(inputs, layers.get() as usize);
    selene <= FCMP_SELENE_GENERATORS && helios <= FCMP_HELIOS_GENERATORS
}

/// The maximum amount of commitments provable for within a single Bulletproof(+).
pub const MAX_BULLETPROOF_COMMITMENTS: usize = 16;
/// The amount of bits a value within a commitment may use.
pub const COMMITMENT_BITS: usize = 64;

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
pub struct BulletproofGenerators {
    /// The G (bold) vector of generators.
    pub G: Vec<EdwardsPoint>,
    /// The H (bold) vector of generators.
    pub H: Vec<EdwardsPoint>,
}

impl BulletproofGenerators {
    /// Generate generators as needed for Bulletproofs(+), as Monero does.
    ///
    /// Consumers should not call this function ad-hoc, yet call it within a build script or use a
    /// once-initialized static.
    pub fn new(dst: &'static [u8]) -> Self {
        // The maximum amount of bits used within a single range proof.
        const MAX_MN: usize = MAX_BULLETPROOF_COMMITMENTS * COMMITMENT_BITS;

        let mut preimage = H.compress().to_bytes().to_vec();
        preimage.extend(dst);

        let mut res = Self {
            G: Vec::with_capacity(MAX_MN),
            H: Vec::with_capacity(MAX_MN),
        };
        for i in 0..MAX_MN {
            // We generate a pair of generators per iteration
            let i = 2 * i;

            let mut even = preimage.clone();
            write_varint(&i, &mut even).expect("write failed but <Vec as io::Write> doesn't fail");
            res.H.push(biased_hash_to_point(keccak256(&even)));

            let mut odd = preimage.clone();
            write_varint(&(i + 1), &mut odd)
                .expect("write failed but <Vec as io::Write> doesn't fail");
            res.G.push(biased_hash_to_point(keccak256(&odd)));
        }
        res
    }
}

// Sample a uniform non-identity on-curve point via rejection sampling.
//
// This is intended for generating constants and is fine to require many iterations accordingly.
fn rejection_sampling_hash_to_curve<G: PrimeGroup + GroupEncoding<Repr = [u8; 32]>>(
    buf: &[u8],
) -> G {
    let mut buf = keccak256(buf);
    loop {
        // Check this is a valid point
        if let Some(point) = Option::<G>::from(G::from_bytes(&buf)) {
            // Check the point is canonically encoded, which `from_bytes` doesn't guarantee, and not the
            // identity point
            if (point.to_bytes() == buf) && (!bool::from(point.is_identity())) {
                return point;
            }
        }
        buf = keccak256(&buf);
    }
}

/// The hash-initialization generator for Helios hashes.
pub static HELIOS_HASH_INIT: LazyLock<HeliosPoint> = LazyLock::new(|| {
    // FROZEN DST
    rejection_sampling_hash_to_curve::<HeliosPoint>(b"Monero Helios Hash Initializer")
});

/// The hash-initialization generator for Selene hashes.
pub static SELENE_HASH_INIT: LazyLock<SelenePoint> = LazyLock::new(|| {
    // FROZEN DST
    rejection_sampling_hash_to_curve::<SelenePoint>(b"Monero Selene Hash Initializer")
});

/// Container struct for FCMP generators.
pub struct FcmpGenerators<C: ciphersuite::Ciphersuite> {
    /// The underlying generators.
    pub generators: generalized_bulletproofs::Generators<C>,
}
impl<C: ciphersuite::Ciphersuite> FcmpGenerators<C>
where
    C::G: GroupEncoding<Repr = [u8; 32]>,
{
    fn id() -> String {
        String::from_utf8(C::ID.to_vec()).expect("Helios/Selene din't have a UTF-8 ID")
    }

    // FROZEN DST (genesis) — the `"Monero {id} …"` templates below derive the FCMP
    // generator tables (pinned by `tests::frozen_points`); not rule-93 targets.
    fn g_h(id: &str) -> (C::G, C::G) {
        (
            rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G").as_bytes()), // FROZEN DST
            rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H").as_bytes()), // FROZEN DST
        )
    }

    fn new_generator_pair(id: &str, i: usize) -> (C::G, C::G) {
        (
            rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G {i}").as_bytes()), // FROZEN DST
            rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H {i}").as_bytes()), // FROZEN DST
        )
    }

    fn new_internal_singlethreaded(generators: usize) -> Self {
        let id = Self::id();
        let (g, h) = Self::g_h(&id);
        let mut g_bold = Vec::with_capacity(generators);
        let mut h_bold = Vec::with_capacity(generators);
        for i in 0..generators {
            let (g_bold_i, h_bold_i) = Self::new_generator_pair(&id, i);
            g_bold.push(g_bold_i);
            h_bold.push(h_bold_i);
        }
        Self {
            generators: generalized_bulletproofs::Generators::new(g, h, g_bold, h_bold)
                .expect("uniformly sampled points couldn't instantiate generators"),
        }
    }

    #[cfg(feature = "std")]
    fn new_internal_multithreaded(generators: usize) -> Option<Self> {
        let id = Self::id();
        let (g, h) = Self::g_h(&id);

        use group::Group;
        use std::thread;

        let threads = {
            let threads = thread::available_parallelism().ok()?;
            // Don't use more threads than generators
            let threads = usize::from(threads).min(generators);
            // Only use an amount of threads which are a power of two
            let next_power_of_two = threads.next_power_of_two();
            // If `threads` was already a power of two, return it as-is
            if threads == next_power_of_two {
                threads
            } else {
                // Return the largest power of two less than threads
                next_power_of_two / 2
            }
        };

        // This will be a perfect division as `threads` is a smaller or equal power of two than
        // `generators`
        let generators_per_thread = generators / threads;
        debug_assert_eq!(
            generators.next_power_of_two(),
            generators,
            "generators wasn't a power of two"
        );
        assert_eq!(
            generators_per_thread * threads,
            generators,
            "generating the wrong amount of generators"
        );

        let mut g_bold = vec![C::G::identity(); generators];
        let mut h_bold = vec![C::G::identity(); generators];
        thread::scope(|scope| {
            let mut g_bold_slice: &mut [_] = g_bold.as_mut();
            let mut h_bold_slice: &mut [_] = h_bold.as_mut();
            for i in 0..threads {
                let id = &id;
                let i = i * generators_per_thread;
                let local_g_bold_slice;
                (local_g_bold_slice, g_bold_slice) =
                    g_bold_slice.split_at_mut(generators_per_thread);
                let local_h_bold_slice;
                (local_h_bold_slice, h_bold_slice) =
                    h_bold_slice.split_at_mut(generators_per_thread);
                scope.spawn(move || {
                    for j in 0..generators_per_thread {
                        (local_g_bold_slice[j], local_h_bold_slice[j]) =
                            Self::new_generator_pair(id, i + j);
                    }
                });
            }
        });

        Some(Self {
            generators: generalized_bulletproofs::Generators::new(g, h, g_bold, h_bold)
                .expect("uniformly sampled points couldn't instantiate generators"),
        })
    }

    fn new_internal(generators: usize) -> Self {
        #[cfg(feature = "std")]
        let res = Self::new_internal_multithreaded(generators)
            .unwrap_or_else(|| Self::new_internal_singlethreaded(generators));
        #[cfg(not(feature = "std"))]
        let res = Self::new_internal_singlethreaded(generators);
        res
    }
}

impl FcmpGenerators<Helios> {
    /// Generate generators as needed for FCMPs.
    ///
    /// Consumers should not call this function ad-hoc, yet call it within a build script or use a
    /// once-initialized static.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_internal(FCMP_HELIOS_GENERATORS)
    }
}

impl FcmpGenerators<Selene> {
    /// Generate generators as needed for FCMPs.
    ///
    /// Consumers should not call this function ad-hoc, yet call it within a build script or use a
    /// once-initialized static.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_internal(FCMP_SELENE_GENERATORS)
    }
}
