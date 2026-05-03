#![no_main]
use libfuzzer_sys::fuzz_target;
use shekyl_oxide::fcmp::PrunableProof;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let inputs = (data[0] as usize % 4) + 1;
    let payload = &data[1..];
    let _ = PrunableProof::read(inputs, &mut &*payload);
});
