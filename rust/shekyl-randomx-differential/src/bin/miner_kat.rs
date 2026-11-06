// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `miner-kat <blob-ascii> [expected-hash-hex]`
//!
//! The miner-shaped known answer (`RANDOMX_V2_PHASE3_PLAN.md` §7.2 #3):
//! the C library alone, as a miner runs it (the CPU's flags, fast mode,
//! v2, a full dataset filled on every core), hashes `<blob-ascii>` under
//! seed `0x01..=0x20`. Nothing else is called: no Rust verifier, no
//! harness corpus, no consensus code, only `randomx-v2-sys`. With
//! `[expected-hash-hex]` (64 hex digits) the run fails unless the hash
//! equals it; without, it prints the hash (capture).

use std::env;
use std::os::raw::c_ulong;
use std::process::ExitCode;
use std::ptr;
use std::thread;

use randomx_v2_sys::{
    randomx_alloc_cache, randomx_alloc_dataset, randomx_calculate_hash, randomx_create_vm,
    randomx_dataset_item_count, randomx_destroy_vm, randomx_get_flags, randomx_init_cache,
    randomx_init_dataset, randomx_release_cache, randomx_release_dataset, RandomxCache,
    RandomxDataset, RANDOMX_FLAG_FULL_MEM, RANDOMX_FLAG_V2,
};

#[derive(Clone, Copy)]
struct FillTarget {
    dataset: *mut RandomxDataset,
    cache: *mut RandomxCache,
}

// SAFETY: each thread fills a disjoint range; the scope joins them all
// before the cache is released.
unsafe impl Send for FillTarget {}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (blob, expected) = match args.as_slice() {
        [blob] => (blob.as_bytes(), None),
        [blob, hex] if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
            (blob.as_bytes(), Some(hex.to_ascii_lowercase()))
        }
        _ => {
            eprintln!("usage: miner-kat <blob-ascii> [expected-hash-hex (64 hex digits)]");
            return ExitCode::FAILURE;
        }
    };
    println!("RandomX v2 miner-shaped full-dataset known answer [pin aaafe71]");
    println!(
        "  seed 0x01..0x20, blob {} bytes, one ~2 080 MiB dataset",
        blob.len()
    );
    let seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i + 1).expect("32 fits u8"));
    let mut hash = [0u8; 32];
    // SAFETY: every pointer the library returns is checked before use and
    // released once; the fill threads are joined before the cache goes.
    unsafe {
        let flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2;
        let cache = randomx_alloc_cache(flags);
        if cache.is_null() {
            eprintln!("FATAL: randomx_alloc_cache failed");
            return ExitCode::FAILURE;
        }
        randomx_init_cache(cache, seed.as_ptr().cast(), seed.len());
        let dataset = randomx_alloc_dataset(flags);
        if dataset.is_null() {
            eprintln!("FATAL: randomx_alloc_dataset failed (~2 080 MiB)");
            return ExitCode::FAILURE;
        }
        let target = FillTarget { dataset, cache };
        let items: c_ulong = randomx_dataset_item_count();
        let cores = thread::available_parallelism().map_or(1, usize::from);
        let threads = c_ulong::try_from(cores).unwrap_or(1).clamp(1, items.max(1));
        thread::scope(|scope| {
            let mut start: c_ulong = 0;
            for t in 0..threads {
                let count = items / threads + c_ulong::from(t < items % threads);
                let range_start = start;
                scope.spawn(move || {
                    let target = target;
                    randomx_init_dataset(target.dataset, target.cache, range_start, count);
                });
                start += count;
            }
        });
        randomx_release_cache(cache);
        let vm = randomx_create_vm(flags, ptr::null_mut(), dataset);
        if vm.is_null() {
            eprintln!("FATAL: randomx_create_vm(FULL_MEM|V2) failed");
            randomx_release_dataset(dataset);
            return ExitCode::FAILURE;
        }
        randomx_calculate_hash(
            vm,
            blob.as_ptr().cast(),
            blob.len(),
            hash.as_mut_ptr().cast(),
        );
        randomx_destroy_vm(vm);
        randomx_release_dataset(dataset);
    }
    let got: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    match expected {
        None => {
            println!("CAPTURE: {got}");
            ExitCode::SUCCESS
        }
        Some(want) if want == got => {
            println!("PASS: the full-dataset hash is the expected {got}");
            ExitCode::SUCCESS
        }
        Some(want) => {
            eprintln!("FAIL: the full-dataset hash is {got}, expected {want}");
            ExitCode::FAILURE
        }
    }
}
