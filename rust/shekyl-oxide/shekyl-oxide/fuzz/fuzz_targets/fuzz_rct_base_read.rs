#![no_main]
use libfuzzer_sys::fuzz_target;
use shekyl_oxide::fcmp::ProofBase;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let outputs = (data[0] as usize % 4) + 1;
    let _ = ProofBase::read(outputs, &mut &data[1..]);
});
