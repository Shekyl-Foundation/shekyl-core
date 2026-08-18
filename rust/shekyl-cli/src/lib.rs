// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! shekyl-cli internals, exposed as a library so integration tests can
//! drive the RPC session directly. The binary entry point is `main.rs`.

pub mod commands;
pub mod daemon;
pub mod display;
pub mod network_posture;
pub mod resolve;
pub mod rpc_client;
pub mod session;
pub mod validate;

/// Prompt for a password without echoing it.
///
/// Returns the secret in a `Zeroizing` wrapper so it is wiped when the caller
/// drops it, on every path including `?` and unwinding (rule 35). The
/// bare-`String` version put that obligation on each caller's return paths.
pub fn prompt_password(
    prompt: &str,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    rpassword::prompt_password(prompt)
        .map(zeroize::Zeroizing::new)
        .map_err(Into::into)
}
