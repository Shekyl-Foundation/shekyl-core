#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{sync::LazyLock, vec::Vec, string::String, alloc::format};

use sha3::{Digest, Keccak256};

use group::{prime::PrimeGroup, GroupEncoding};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint};
use helioselene::{HeliosPoint, SelenePoint, Helios, Selene};

use shekyl_io::{write_varint, CompressedPoint};

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
  for i in 1 .. 64 {
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

/// Monero's `T`, used to blind the key-image commitment present within output keys.
pub static T: LazyLock<EdwardsPoint> =
  LazyLock::new(|| hash_to_point(keccak256(b"Monero Generator T")));

/// FCMP++s's key-image generator blinding generator `U`.
pub static FCMP_PLUS_PLUS_U: LazyLock<EdwardsPoint> =
  LazyLock::new(|| hash_to_point(keccak256(b"Monero FCMP++ Generator U")));

/// FCMP++s's randomness commitment generator `V`.
pub static FCMP_PLUS_PLUS_V: LazyLock<EdwardsPoint> =
  LazyLock::new(|| hash_to_point(keccak256(b"Monero FCMP++ Generator V")));

/// The maximum amount of input tuples provable for within a single FCMP.
// https://github.com/seraphis-migration/monero
//  /blob/8bf178a3009ee066001189d05869445bdf4ed28c/src/cryptonote_config.h#L217
pub const MAX_FCMP_INPUTS: usize = 128;
/// The maximum amount of layers supported within a FCMP.
///
/// The FCMP itself theoretically supports an unbounded amount of layers, with exponential growth
/// in set size as additional layers are added. The size of the proof (for each input) still grows
/// linearly with the amount of layers, requiring a sufficiently-large constant reference string.
/// This constant is used to generate the constant reference string, and it's that which bounds the
/// amount of layers supported.
///
/// Theoretically, the generators could be dynamically built/extended at runtime to remove this
/// limit, yet this offers such a large set size it will never be reached.
// https://github.com/seraphis-migration/monero
//  /blob/8bf178a3009ee066001189d05869445bdf4ed28c/src/cryptonote_config.h#L222
pub const MAX_FCMP_LAYERS: usize = 12;

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

    let mut res = Self { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
    for i in 0 .. MAX_MN {
      // We generate a pair of generators per iteration
      let i = 2 * i;

      let mut even = preimage.clone();
      write_varint(&i, &mut even).expect("write failed but <Vec as io::Write> doesn't fail");
      res.H.push(biased_hash_to_point(keccak256(&even)));

      let mut odd = preimage.clone();
      write_varint(&(i + 1), &mut odd).expect("write failed but <Vec as io::Write> doesn't fail");
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
  rejection_sampling_hash_to_curve::<HeliosPoint>(b"Monero Helios Hash Initializer")
});

/// The hash-initialization generator for Selene hashes.
pub static SELENE_HASH_INIT: LazyLock<SelenePoint> = LazyLock::new(|| {
  rejection_sampling_hash_to_curve::<SelenePoint>(b"Monero Selene Hash Initializer")
});

const FCMP_GENERATORS: (usize, usize) =
  full_chain_membership_proofs::Fcmp::<()>::ipa_rows(MAX_FCMP_INPUTS, MAX_FCMP_LAYERS);
const FCMP_SELENE_GENERATORS: usize = FCMP_GENERATORS.0;
const FCMP_HELIOS_GENERATORS: usize = FCMP_GENERATORS.1;

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

  fn g_h(id: &str) -> (C::G, C::G) {
    (
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G").as_bytes()),
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H").as_bytes()),
    )
  }

  fn new_generator_pair(id: &str, i: usize) -> (C::G, C::G) {
    (
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G {i}").as_bytes()),
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H {i}").as_bytes()),
    )
  }

  fn new_internal_singlethreaded(generators: usize) -> Self {
    let id = Self::id();
    let (g, h) = Self::g_h(&id);
    let mut g_bold = Vec::with_capacity(generators);
    let mut h_bold = Vec::with_capacity(generators);
    for i in 0 .. generators {
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

    use std::thread;
    use group::Group;

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
      for i in 0 .. threads {
        let id = &id;
        let i = i * generators_per_thread;
        let local_g_bold_slice;
        (local_g_bold_slice, g_bold_slice) = g_bold_slice.split_at_mut(generators_per_thread);
        let local_h_bold_slice;
        (local_h_bold_slice, h_bold_slice) = h_bold_slice.split_at_mut(generators_per_thread);
        scope.spawn(move || {
          for j in 0 .. generators_per_thread {
            (local_g_bold_slice[j], local_h_bold_slice[j]) = Self::new_generator_pair(id, i + j);
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
