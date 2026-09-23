// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Rust half of the LV-2b 2002 differential. Writes one file per shape
//! into $LV2B_OUT; `compare.sh` cmp's them against `fixtures/` (epee's).
//!
//! Copy into `rust/shekyl-levin/tests/` to run. See README.md.
use shekyl_levin::{NewTransactions, PortableMap};
use std::io::Write as _;

fn out_dir() -> String {
    std::env::var("LV2B_OUT").expect("set LV2B_OUT to the output directory")
}

fn blob(n: usize, seed: u8) -> Vec<u8> {
    // Must match the C++ harness exactly: index is widened, NOT wrapped at u8.
    (0..n).map(|i| b'a' + ((i + seed as usize) % 26) as u8).collect()
}

fn emit(label: &str, v: &NewTransactions) {
    let bytes = v.store().expect("store");
    let mut f = std::fs::File::create(format!("{}/{label}.bin", out_dir())).expect("create");
    f.write_all(&bytes).expect("write");
    println!("{label:<16} {} bytes", bytes.len());
}

#[test]
fn measure() {
    let sp = |n: usize| vec![b' '; n];
    emit("carrier_shape", &NewTransactions { txs: vec![b"tx1".to_vec()], padding: Vec::new(), dandelionpp_fluff: false });
    emit("fluff_default", &NewTransactions { txs: vec![b"tx1".to_vec()], padding: Vec::new(), dandelionpp_fluff: true });
    emit("padded_8sp", &NewTransactions { txs: vec![b"tx1".to_vec()], padding: sp(8), dandelionpp_fluff: false });
    emit("empty_txs", &NewTransactions { txs: Vec::new(), padding: Vec::new(), dandelionpp_fluff: false });
    emit("realistic_2byte", &NewTransactions {
        txs: vec![blob(1500, 1), blob(1487, 2), blob(1613, 3)], padding: sp(900), dandelionpp_fluff: true });
    emit("wide_4byte", &NewTransactions {
        txs: vec![blob(20000, 4)], padding: sp(16400), dandelionpp_fluff: false });
    emit("boundary_63_64", &NewTransactions {
        txs: vec![blob(63, 5)], padding: sp(64), dandelionpp_fluff: true });
}
