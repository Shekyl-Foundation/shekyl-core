#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 200 {
        return;
    }
    use shekyl_engine_core::multisig::v31::prover::{
        EquivocationProof, ProverInputProof, ProverOutput,
    };

    let proof_a = ProverOutput {
        prover_index: data[0],
        intent_hash: data[1..33].try_into().unwrap_or([0; 32]),
        fcmp_proofs: vec![ProverInputProof {
            input_global_index: u64::from_le_bytes(
                data[33..41].try_into().unwrap_or([0; 8]),
            ),
            fcmp_proof: data[41..141].to_vec(),
            key_image: data[141..173].try_into().unwrap_or([0; 32]),
        }],
        prover_sig: vec![0; 64],
    };

    let mut proof_b = proof_a.clone();
    if data.len() > 200 {
        proof_b.fcmp_proofs[0].fcmp_proof = data[173..].to_vec();
    }

    let ep = EquivocationProof {
        prover_index: data[0],
        intent_hash: data[1..33].try_into().unwrap_or([0; 32]),
        proof_a,
        proof_b,
    };
    let _ = ep.is_valid();
});
