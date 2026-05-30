#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 130 {
        return;
    }
    use shekyl_engine_core::multisig::v31::counter_proof::{
        CounterProof, CounterProofChainView, CounterProofVerifyResult, verify_counter_proof,
    };

    struct FuzzChain<'a>(&'a [u8]);
    impl<'a> CounterProofChainView for FuzzChain<'a> {
        fn block_hash_at(&self, _: u64) -> Option<[u8; 32]> {
            if self.0.first().map(|&b| b > 128).unwrap_or(false) {
                Some(self.0[1..33].try_into().unwrap_or([0; 32]))
            } else {
                None
            }
        }
        fn tx_at_position(&self, _: u64, _: u16) -> Option<[u8; 32]> {
            if self.0.first().map(|&b| b > 128).unwrap_or(false) {
                Some(self.0[33..65].try_into().unwrap_or([0; 32]))
            } else {
                None
            }
        }
        fn tx_all_scheme_id_2(&self, _: &[u8; 32]) -> Option<bool> {
            self.0.get(65).map(|&b| b > 128)
        }
        fn is_tracked_unspent(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
            self.0.get(66).map(|&b| b > 128).unwrap_or(false)
        }
    }

    let proof = CounterProof {
        sender_index: data[0],
        advancing_to: u64::from_le_bytes(data[1..9].try_into().unwrap_or([0; 8])),
        tx_hash: data[9..41].try_into().unwrap_or([0; 32]),
        block_height: u64::from_le_bytes(data[41..49].try_into().unwrap_or([0; 8])),
        block_hash: data[49..81].try_into().unwrap_or([0; 32]),
        tx_position: u16::from_le_bytes(data[81..83].try_into().unwrap_or([0; 2])),
        consumed_inputs: vec![data[83..115].try_into().unwrap_or([0; 32])],
        resulting_outputs: vec![data[115..130].try_into().unwrap_or([0; 15])
            .iter().chain(&[0u8; 17]).copied().collect::<Vec<u8>>()
            .try_into().unwrap_or([0; 32])],
        intent_hash: [0; 32],
        sender_sig: vec![0; 64],
    };

    let chain = FuzzChain(data);
    let _ = verify_counter_proof(&proof, &[0xFF; 32], 0, &chain);
});
