// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! fips203 rounds Decompress to the nearest integer, as FIPS 203 eq. 4.8 and
//! §2.3 require. Releases before 0.5.0 rounded up, so against a crafted key
//! pair a correctly encapsulated ciphertext decapsulated to the
//! implicit-rejection key `J(z || c)` instead of the shared secret. This is
//! upstream's own regression vector (fips203 0.5.0
//! `tests/regressions.rs` `decaps_decompress_rounding_512`), held here so the
//! exact pin cannot move to a release that rounds up without a red test.
//!
//! The vector is ML-KEM-512; Shekyl uses ML-KEM-768 through the same crate
//! and the same Decompress. No KeyGen produces this key pair: t_hat =
//! (NTT(277), 0), rho = 0, s_hat = 0, z = 0x07^32. Encapsulating m = 0 gives
//! three c2 coefficients equal to 4; Decompress_4(4) is 832, which Compress_1
//! maps to bit 0, while rounding up gives 833, which maps to bit 1, so the
//! re-encryption check would fail. Expected values from kyber-py 1.2.0 and
//! pq-crystals/kyber `standard` (d5b791c), as upstream cites them.

use fips203::ml_kem_512;
use fips203::traits::{Decaps as _, Encaps as _, SerDes as _};
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};

/// An RNG that yields zeros: encapsulating m = 0.
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand::Error> {
        out.fill(0);
        Ok(())
    }
}

impl CryptoRng for ZeroRng {}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn decaps_rounds_decompress_to_nearest() {
    let mut ek = [0u8; ml_kem_512::EK_LEN];
    for chunk in ek[..384].chunks_exact_mut(3) {
        chunk.copy_from_slice(&[0x15, 0x01, 0x00]); // ByteEncode_12 of the pair (277, 0)
    }
    let mut dk = [0u8; ml_kem_512::DK_LEN];
    dk[768..1568].copy_from_slice(&ek);
    dk[1568..1600].copy_from_slice(&Sha3_256::digest(ek));
    dk[1600..].fill(0x07);

    let ek = ml_kem_512::EncapsKey::try_from_bytes(ek).expect("ek passes the modulus check");
    let dk = ml_kem_512::DecapsKey::try_from_bytes(dk).expect("dk passes the hash check");

    let (k_enc, ct) = ek.try_encaps_with_rng(&mut ZeroRng).expect("encaps");
    let k_dec = dk.try_decaps(&ct).expect("decaps");

    assert_eq!(
        Sha3_256::digest(ct.into_bytes()).to_vec(),
        unhex("5824de534eab92fac7c6cd9dbb143633d956ec178e22862c02858174645966cc")
    );
    let shared = unhex("50b09012b43149cae6b95d77db1295c29bfdb0a3cdae9d3e99b93fcb37b0f1d9");
    assert_eq!(k_enc.into_bytes().to_vec(), shared);
    // Rounding up gives J(z || c) =
    // 98f37c7692544aca18102d5a96c0fc719f69adc7541d499bb56164066f63c154.
    assert_eq!(k_dec.into_bytes().to_vec(), shared);
}
