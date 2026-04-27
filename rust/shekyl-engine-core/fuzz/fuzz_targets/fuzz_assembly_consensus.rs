#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 192 {
        return;
    }
    use shekyl_engine_core::multisig::v31::invariants::check_assembly_consensus;
    use shekyl_engine_core::multisig::v31::prover::SignatureShare;

    let n = std::cmp::min((data[0] % 7) as usize + 2, data.len() / 96);
    let mut shares = Vec::new();

    for i in 0..n {
        let base = 1 + i * 96;
        if base + 96 > data.len() {
            break;
        }
        shares.push(SignatureShare {
            signer_index: i as u8,
            hybrid_sig: vec![0; 64],
            tx_hash_commitment: data[base..base + 32].try_into().unwrap_or([0; 32]),
            fcmp_proof_commitment: data[base + 32..base + 64]
                .try_into()
                .unwrap_or([0; 32]),
            bp_plus_proof_commitment: data[base + 64..base + 96]
                .try_into()
                .unwrap_or([0; 32]),
        });
    }

    if shares.len() >= 2 {
        let _ = check_assembly_consensus(&shares);
    }
});
