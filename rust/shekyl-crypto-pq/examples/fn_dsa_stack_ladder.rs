// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stack each scheme-3 operation needs (`docs/design/FN_DSA_HYBRID.md`
//! §9.1, `BENCHMARK_ALIGNMENT.md` `BA-T33`).
//!
//! # Why not a thread of the size under test
//!
//! Rust raises a requested thread stack to the C library's minimum
//! (`std::sys::thread::unix`: `max(stack, __pthread_get_minstack)`), and
//! glibc's minimum is 16 KiB on x86_64 but 128 KiB on aarch64, plus a page
//! and the thread-local storage. A thread asked for 16 KiB on the floor
//! device gets about 132 KiB, so a ladder of thread sizes cannot see any
//! need below that. Painting the stack, or asking the thread its real size,
//! would see it, and both need `unsafe`, which this workspace allows only
//! in `shekyl-ffi` (rules 25 and 45).
//!
//! # What this does instead
//!
//! Every measurement runs on a thread of [`THREAD_STACK`] bytes, far above
//! any minimum. A first child, `probe`, recurses through frames of
//! [`BURN_FRAME`] bytes and prints each frame's depth below the thread's
//! first frame until it overflows; the last depth printed is how deep a
//! frame can go. Then, budget by budget from [`FIRST_BUDGET`] in
//! [`STEP`]-byte steps, a child recurses until only that budget is left
//! below it and runs the operation there. A child that overflows aborts, so
//! each budget is its own process; the first budget whose child exits 0 is
//! the figure. Depths are read from the addresses of locals, which safe
//! code may take and compare but never dereference. The figure is an upper
//! bound on the need within one step, give or take one burn frame.
//!
//! ```text
//! fn_dsa_stack_ladder                         every operation, one TSV line each
//! fn_dsa_stack_ladder probe                   one child: print depths to overflow
//! fn_dsa_stack_ladder rung OP DEPTH BUDGET    one child: OP with BUDGET left
//! ```
//!
//! The profile is the build's: run it from a debug and a release build for
//! the two columns of §9.1. Operations:
//!
//! - `sign`: `HybridEd25519FnDsa::sign`, the per-call production entry.
//! - `hold_key`: `FnDsaHybridSigner::new`, the one decode of a held key.
//! - `sign_held`: `FnDsaHybridSigner::sign` with the key already held.
//! - `verify`: `HybridEd25519FnDsa::verify`.
//! - `keygen`: `HybridEd25519FnDsa::keypair_from_seeds`.
//! - `persona`: `derive_archival_p_keys` for one slot, which the receipt
//!   key's generation is part of (`FND-12`).

use std::hint::black_box;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, ExitCode, Stdio};

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSigner, HybridEd25519FnDsa};
use shekyl_crypto_pq::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT};
use shekyl_crypto_pq::CryptoError;

const OPERATIONS: [&str; 6] = [
    "sign",
    "hold_key",
    "sign_held",
    "verify",
    "keygen",
    "persona",
];
/// The measuring thread's stack: far above every platform's minimum, so the
/// size asked for is the size received.
const THREAD_STACK: usize = 8 * 1024 * 1024;
/// One burn frame. Small beside every figure, so a budget lands within a
/// frame of where it was asked for.
const BURN_FRAME: usize = 1024;
const FIRST_BUDGET: usize = 4 * 1024;
const STEP: usize = 4 * 1024;
/// Far above anything §9.1 found; a ladder that reaches it is a finding.
const LAST_BUDGET: usize = 4 * 1024 * 1024;

const MESSAGE: [u8; 128] = [0xA5; 128];
const ED25519_SEED: [u8; 32] = [0x11; 32];
const FN_DSA_SEED: [u8; 32] = [0x22; 32];
const MASTER: [u8; MASTER_SEED_BYTES] = [0x33; MASTER_SEED_BYTES];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_] => ladder(),
        [_, mode] if mode == "probe" => probe(),
        [_, mode, op, depth, budget] if mode == "rung" => {
            match (depth.parse::<usize>(), budget.parse::<usize>()) {
                (Ok(depth), Ok(budget)) => rung(op, depth, budget),
                _ => usage(),
            }
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: fn_dsa_stack_ladder [probe | rung OP DEPTH BUDGET]");
    ExitCode::from(2)
}

/// Where a local lies. Taken and compared, never dereferenced.
fn address_of<T>(value: &T) -> usize {
    std::ptr::from_ref(value) as usize
}

/// Every operation's smallest passing budget, as `op<TAB>bytes<TAB>kib`.
fn ladder() -> ExitCode {
    let Ok(me) = std::env::current_exe() else {
        eprintln!("cannot locate this binary to run its children");
        return ExitCode::from(2);
    };
    let Some(depth) = deepest_frame(&me) else {
        eprintln!("the probe printed no depth");
        return ExitCode::FAILURE;
    };
    println!(
        "# deepest frame {depth} bytes below the thread's first, on a {THREAD_STACK}-byte stack"
    );
    println!("op\tbytes\tkib");
    for op in OPERATIONS {
        let mut budget = FIRST_BUDGET;
        let found = loop {
            if budget > LAST_BUDGET {
                break None;
            }
            // A child that overflows aborts with a signal; its stderr says
            // so and is dropped here: only the exit status is read.
            let status = Command::new(&me)
                .args(["rung", op, &depth.to_string(), &budget.to_string()])
                .stderr(Stdio::null())
                .status();
            match status {
                Ok(status) if status.success() => break Some(budget),
                Ok(_) => budget += STEP,
                Err(error) => {
                    eprintln!("{op}: cannot start a child: {error}");
                    return ExitCode::FAILURE;
                }
            }
        };
        match found {
            Some(bytes) => println!("{op}\t{bytes}\t{}", bytes / 1024),
            None => {
                println!("{op}\tnone\tover {}", LAST_BUDGET / 1024);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// Runs the probe child and returns the last depth it printed before it
/// overflowed.
fn deepest_frame(me: &std::path::Path) -> Option<usize> {
    let mut child = Command::new(me)
        .arg("probe")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let last = BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| line.parse::<usize>().ok())
        .last();
    // The probe ends by overflowing, so its exit status is that abort and is
    // not read; a child that cannot be reaped is a failed probe.
    child.wait().ok()?;
    last
}

/// The probe child: recurse until the stack runs out, printing each frame's
/// depth below the thread's first frame. It does not return.
fn probe() -> ExitCode {
    let handle = std::thread::Builder::new()
        .stack_size(THREAD_STACK)
        .spawn(|| {
            let anchor = 0_u8;
            let top = address_of(&anchor);
            let mut out = std::io::stdout().lock();
            descend(top, &mut out);
        });
    match handle.map(std::thread::JoinHandle::join) {
        Ok(_) => ExitCode::FAILURE,
        Err(_) => ExitCode::from(2),
    }
}

#[inline(never)]
fn descend(top: usize, out: &mut impl Write) {
    let pad = [0_u8; BURN_FRAME];
    let here = address_of(black_box(&pad));
    let depth = top.saturating_sub(here);
    // A write that fails ends the probe early; the ladder then has a
    // shallower depth and reports larger budgets, never smaller.
    if writeln!(out, "{depth}").and_then(|()| out.flush()).is_err() || depth > THREAD_STACK {
        return;
    }
    descend(top, out);
    black_box(&pad);
}

/// Recurse until the current frame is `target` bytes below `top`, then run
/// `operation` there.
#[inline(never)]
fn burn_to(top: usize, target: usize, operation: &mut dyn FnMut() -> bool) -> bool {
    let pad = [0_u8; BURN_FRAME];
    let here = address_of(black_box(&pad));
    let passed = if top.saturating_sub(here) >= target {
        operation()
    } else {
        burn_to(top, target, operation)
    };
    black_box(&pad);
    passed
}

/// One child: `op` with `budget` bytes of stack left below it.
fn rung(op: &str, depth: usize, budget: usize) -> ExitCode {
    let Some(target) = depth.checked_sub(budget) else {
        return ExitCode::FAILURE;
    };
    let (public, secret) =
        HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).expect("keygen");
    let signature = HybridEd25519FnDsa
        .sign(&secret, SCHEME_DOMAIN_RECEIPT, &MESSAGE)
        .expect("sign");
    let mut held = FnDsaHybridSigner::new(&secret).expect("the generated key decodes");

    let mut operation = || -> bool {
        let outcome: Result<(), CryptoError> = match op {
            "sign" => HybridEd25519FnDsa
                .sign(&secret, SCHEME_DOMAIN_RECEIPT, &MESSAGE)
                .map(drop),
            "hold_key" => FnDsaHybridSigner::new(&secret).map(drop),
            "sign_held" => held.sign(SCHEME_DOMAIN_RECEIPT, &MESSAGE).map(drop),
            "verify" => {
                HybridEd25519FnDsa.verify(&public, SCHEME_DOMAIN_RECEIPT, &MESSAGE, &signature)
            }
            "keygen" => {
                HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).map(drop)
            }
            "persona" => {
                derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
                    .map(drop)
            }
            _ => Err(CryptoError::InvalidInput(format!(
                "no operation named {op}"
            ))),
        };
        outcome.is_ok()
    };

    let passed = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(THREAD_STACK)
            .spawn_scoped(scope, || {
                let anchor = 0_u8;
                let top = address_of(&anchor);
                burn_to(top, target, &mut operation)
            })
            .map(std::thread::ScopedJoinHandle::join)
    });
    match passed {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
