// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stack each scheme-3 operation needs, found by a ladder
//! (`docs/design/FN_DSA_HYBRID.md` §9.1, `BENCHMARK_ALIGNMENT.md` `BA-T33`).
//!
//! For each operation, rung by rung from 16 KiB in 8 KiB steps, this binary
//! runs itself again as a child that performs the operation once on a thread
//! of exactly that stack size. A thread that overflows its stack aborts the
//! process, so each rung is its own process, and the first rung whose child
//! exits 0 is reported. That figure is an upper bound on the need, within one
//! step. Setup (key generation, signing the message to verify) runs on the
//! child's main thread, outside the measured one.
//!
//! ```text
//! fn_dsa_stack_ladder                 every operation, one TSV line each
//! fn_dsa_stack_ladder rung OP BYTES   one child: OP on a BYTES-byte stack
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
const FIRST_RUNG: usize = 16 * 1024;
const STEP: usize = 8 * 1024;
/// Far above anything §9.1 found; a ladder that reaches it is a finding.
const LAST_RUNG: usize = 4 * 1024 * 1024;

const MESSAGE: [u8; 128] = [0xA5; 128];
const ED25519_SEED: [u8; 32] = [0x11; 32];
const FN_DSA_SEED: [u8; 32] = [0x22; 32];
const MASTER: [u8; MASTER_SEED_BYTES] = [0x33; MASTER_SEED_BYTES];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_] => ladder(),
        [_, mode, op, bytes] if mode == "rung" => match bytes.parse::<usize>() {
            Ok(bytes) => rung(op, bytes),
            Err(_) => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: fn_dsa_stack_ladder [rung OP BYTES]");
    ExitCode::from(2)
}

/// Every operation's smallest passing rung, as `op<TAB>bytes<TAB>KiB`.
fn ladder() -> ExitCode {
    let Ok(me) = std::env::current_exe() else {
        eprintln!("cannot locate this binary to run its rungs");
        return ExitCode::from(2);
    };
    println!("op\tbytes\tkib");
    for op in OPERATIONS {
        let mut bytes = FIRST_RUNG;
        let found = loop {
            if bytes > LAST_RUNG {
                break None;
            }
            // A child that overflows aborts with a signal; its stderr says
            // so, and is dropped here: only the exit status is read.
            let status = Command::new(&me)
                .args(["rung", op, &bytes.to_string()])
                .stderr(std::process::Stdio::null())
                .status();
            match status {
                Ok(status) if status.success() => break Some(bytes),
                Ok(_) => bytes += STEP,
                Err(error) => {
                    eprintln!("{op}: cannot start a rung: {error}");
                    return ExitCode::FAILURE;
                }
            }
        };
        match found {
            Some(bytes) => println!("{op}\t{bytes}\t{}", bytes / 1024),
            None => {
                println!("{op}\tnone\tover {}", LAST_RUNG / 1024);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// One child: `op` once on a thread of `bytes` bytes of stack.
fn rung(op: &str, bytes: usize) -> ExitCode {
    let (public, secret) =
        HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).expect("keygen");
    let signature = HybridEd25519FnDsa
        .sign(&secret, SCHEME_DOMAIN_RECEIPT, &MESSAGE)
        .expect("sign");
    let mut held = FnDsaHybridSigner::new(&secret).expect("the generated key decodes");

    let outcome = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(bytes)
            .spawn_scoped(scope, || match op {
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
                "persona" => derive_archival_p_keys(
                    &MASTER,
                    DerivationNetwork::Mainnet,
                    SeedFormat::Bip39,
                    0,
                )
                .map(drop),
                _ => Err(shekyl_crypto_pq::CryptoError::InvalidInput(format!(
                    "no operation named {op}"
                ))),
            })
            .map(std::thread::ScopedJoinHandle::join)
    });
    match outcome {
        Ok(Ok(Ok(()))) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
