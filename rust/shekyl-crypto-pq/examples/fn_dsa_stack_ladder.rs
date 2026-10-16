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
//! the figure. The probe counts only if it ended in the runtime's
//! stack-overflow abort, and a rung that fails any other way stops the
//! ladder rather than counting as too small a budget. Depths are read from the addresses of locals, which safe
//! code may take and compare but never dereference. A figure is good to
//! about one step either way: the budgets come in steps, and the probe's
//! last printed depth leaves some room below it that is not counted, so
//! the stack actually left at a budget is a little more than the budget.
//!
//! The figure is the stack the call itself consumes below its caller. An
//! operation's inputs (a key, a signature) are made before the measuring
//! thread starts and owned by the operation on the heap, as a production
//! caller's are: the stake actor holds its keys in heap-allocated bundles
//! and passes references. Each child makes only the inputs its operation
//! reads.
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
use std::io::Write;
use std::process::{Command, ExitCode};

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSigner, HybridEd25519FnDsa};
use shekyl_crypto_pq::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT};

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
    let depth = match deepest_frame(&me) {
        Ok(depth) => depth,
        Err(why) => {
            eprintln!("the probe is not usable: {why}");
            return ExitCode::FAILURE;
        }
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
            let rung = run_child(&me, &["rung", op, &depth.to_string(), &budget.to_string()]);
            match rung {
                Ok((Ending::Passed, _)) => break Some(budget),
                Ok((Ending::Overflowed, _)) => budget += STEP,
                // Anything else is not a verdict on the budget: a setup that
                // failed, an operation that returned an error, a signal from
                // elsewhere. Climbing past it would report a need the
                // operation does not have.
                Ok((Ending::Other(why), _)) | Err(why) => {
                    eprintln!("{op} at a {budget}-byte budget ended without a verdict: {why}");
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
fn deepest_frame(me: &std::path::Path) -> Result<usize, String> {
    let (ending, stdout) = run_child(me, &["probe"])?;
    // A probe that stopped for any reason but running out of stack reports a
    // shallower depth than the thread has, so every rung would leave more
    // stack than its budget and the ladder would understate every need.
    match ending {
        Ending::Overflowed => {}
        Ending::Passed => return Err("it returned instead of overflowing".into()),
        Ending::Other(why) => return Err(why),
    }
    let text = String::from_utf8(stdout).map_err(|_| "its output is not text".to_string())?;
    let mut last = None;
    for line in text.lines() {
        let depth = line
            .parse::<usize>()
            .map_err(|_| format!("it printed {line:?}, which is not a depth"))?;
        last = Some(depth);
    }
    last.ok_or_else(|| "it printed no depth".to_string())
}

/// How a child ended.
enum Ending {
    /// Exit status 0.
    Passed,
    /// The Rust runtime's stack-overflow abort: its message on stderr and,
    /// on Unix, the abort signal.
    Overflowed,
    /// Anything else, with what was seen.
    Other(String),
}

/// `SIGABRT`, which the Rust runtime raises after reporting an overflow.
/// Its value is 6 on every Unix this tool is run on.
#[cfg(unix)]
const SIGABRT: i32 = 6;

/// The marker the Rust runtime writes to stderr when a thread overflows its
/// stack, before it aborts.
const OVERFLOW_MARKER: &str = "has overflowed its stack";

/// Run this binary with `args` and say how it ended, with its stdout.
fn run_child(me: &std::path::Path, args: &[&str]) -> Result<(Ending, Vec<u8>), String> {
    let output = Command::new(me)
        .args(args)
        .output()
        .map_err(|error| format!("cannot start a child: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let ending = if output.status.success() {
        Ending::Passed
    } else if stderr.contains(OVERFLOW_MARKER) && aborted(&output.status) {
        Ending::Overflowed
    } else {
        Ending::Other(format!("{}; stderr: {}", output.status, stderr.trim()))
    };
    Ok((ending, output.stdout))
}

#[cfg(unix)]
fn aborted(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal() == Some(SIGABRT)
}

#[cfg(not(unix))]
fn aborted(status: &std::process::ExitStatus) -> bool {
    !status.success()
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
    // A write that fails ends the probe without an overflow, and the ladder
    // refuses a probe that did not overflow: a shallower depth would leave
    // every rung more stack than its budget.
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

/// The operation named `op`, with the inputs it reads made here and owned by
/// the returned closure on the heap. Only what `op` reads is made, so a
/// rung pays no setup it does not use. `None` for an unknown name or a
/// setup that failed.
fn operation(op: &str) -> Option<Box<dyn FnMut() -> bool + Send>> {
    let keypair = || HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).ok();
    let operation: Box<dyn FnMut() -> bool + Send> = match op {
        "sign" => {
            let (_, secret) = keypair()?;
            Box::new(move || {
                HybridEd25519FnDsa
                    .sign(&secret, SCHEME_DOMAIN_RECEIPT, &MESSAGE)
                    .is_ok()
            })
        }
        "hold_key" => {
            let (_, secret) = keypair()?;
            Box::new(move || FnDsaHybridSigner::new(&secret).is_ok())
        }
        "sign_held" => {
            let (_, secret) = keypair()?;
            let mut held = FnDsaHybridSigner::new(&secret).ok()?;
            Box::new(move || held.sign(SCHEME_DOMAIN_RECEIPT, &MESSAGE).is_ok())
        }
        "verify" => {
            let (public, secret) = keypair()?;
            let signature = HybridEd25519FnDsa
                .sign(&secret, SCHEME_DOMAIN_RECEIPT, &MESSAGE)
                .ok()?;
            Box::new(move || {
                HybridEd25519FnDsa
                    .verify(&public, SCHEME_DOMAIN_RECEIPT, &MESSAGE, &signature)
                    .is_ok()
            })
        }
        "keygen" => {
            Box::new(|| HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).is_ok())
        }
        "persona" => Box::new(|| {
            derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
                .is_ok()
        }),
        _ => return None,
    };
    Some(operation)
}

/// One child: `op` with `budget` bytes of stack left below it.
fn rung(op: &str, depth: usize, budget: usize) -> ExitCode {
    let Some(target) = depth.checked_sub(budget) else {
        return ExitCode::FAILURE;
    };
    let Some(mut operation) = operation(op) else {
        eprintln!("no operation named {op}, or its setup failed");
        return ExitCode::from(2);
    };

    let passed = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(THREAD_STACK)
            .spawn_scoped(scope, || {
                let anchor = 0_u8;
                let top = address_of(&anchor);
                burn_to(top, target, &mut *operation)
            })
            .map(std::thread::ScopedJoinHandle::join)
    });
    match passed {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
