// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! shekyl-cli internals, exposed as a library so integration tests can
//! drive the RPC session directly. The binary entry point is `main.rs`.

pub mod commands;
pub mod daemon;
pub mod display;
pub mod resolve;
pub mod rpc_client;
pub mod session;
pub mod validate;

/// Prompt for a password without echoing it.
pub fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    rpassword::prompt_password(prompt).map_err(Into::into)
}
