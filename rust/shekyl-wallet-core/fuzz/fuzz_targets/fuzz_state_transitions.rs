#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use shekyl_wallet_core::multisig::v31::state::{IntentState, TrackedIntent};

    let states = [
        IntentState::Proposed,
        IntentState::Verified,
        IntentState::ProverReady,
        IntentState::Signed,
        IntentState::Assembled,
        IntentState::Broadcast,
        IntentState::Rejected,
        IntentState::TimedOut,
    ];

    let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
    for &b in data {
        let target = states[(b as usize) % states.len()];
        let _ = ti.transition(target);
    }
});
