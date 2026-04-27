#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 50 {
        return;
    }
    use shekyl_engine_core::multisig::v31::heartbeat::{Heartbeat, HeartbeatTracker};

    let n = (data[0] % 7) + 2;
    let mut tracker = HeartbeatTracker::new(n);

    let sender_index = data[1] % n;
    let timestamp = u64::from_le_bytes(data[2..10].try_into().unwrap_or([0; 8]));
    let mut intent = [0u8; 32];
    intent.copy_from_slice(&data[10..42]);
    let counter = u64::from_le_bytes(data[42..50].try_into().unwrap_or([0; 8]));

    let hb = Heartbeat {
        sender_index,
        timestamp,
        last_seen_intent: intent,
        observed_relay_ops: vec!["op1".into()],
        local_tx_counter: counter,
        sig: vec![],
    };

    let _ = tracker.record(&hb, &[0xAA; 32], 5, 1000);
    let _ = tracker.check_missing(2000, 0);
});
