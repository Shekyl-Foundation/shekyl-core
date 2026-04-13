#![no_main]
use libfuzzer_sys::fuzz_target;

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use shekyl_bulletproofs::Bulletproof;
use shekyl_io::CompressedPoint;
use shekyl_primitives::Commitment;

fuzz_target!(|data: &[u8]| {
    if data.len() < 41 {
        return;
    }

    let n_outputs = ((data[0] as usize) % 15) + 1;
    let needed = 1 + n_outputs * (32 + 8);
    if data.len() < needed {
        return;
    }

    let mut offset = 1;
    let mut commitments = Vec::with_capacity(n_outputs);

    for _ in 0..n_outputs {
        let mut mask_bytes = [0u8; 32];
        mask_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let amount = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let mask = Scalar::from_bytes_mod_order(mask_bytes);
        if mask == Scalar::ZERO {
            return;
        }

        commitments.push(Commitment::new(mask, amount));
    }

    let proof = match Bulletproof::prove_plus(&mut OsRng, commitments.clone()) {
        Ok(p) => p,
        Err(_) => return,
    };

    let compressed: Vec<CompressedPoint> = commitments
        .iter()
        .map(|c| {
            let pt = c.calculate().mul_by_cofactor();
            CompressedPoint(pt.compress().to_bytes())
        })
        .collect();

    let valid = proof.verify(&mut OsRng, &compressed);
    assert!(valid, "BP+ proof generated from valid masks/amounts must verify");
});
