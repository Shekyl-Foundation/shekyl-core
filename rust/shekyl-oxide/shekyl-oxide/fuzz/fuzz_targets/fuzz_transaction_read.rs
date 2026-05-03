#![no_main]
use libfuzzer_sys::fuzz_target;
use shekyl_oxide::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    let _ = Transaction::read(&mut &*data);
});
