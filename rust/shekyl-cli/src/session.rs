// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL session state.
//!
//! `ReplSession` lives on the REPL loop's stack frame. It is never shared
//! and never leaks into RPC-level state. With the wallet2-era account model
//! deleted (WI-RPC-2b), the only session-local presentation state left is
//! the prompt.

/// Local session state for the interactive REPL.
#[derive(Default)]
pub struct ReplSession {}

impl ReplSession {
    pub fn new() -> Self {
        Self {}
    }

    /// Build the REPL prompt string.
    pub fn prompt(&self, wallet_open: bool) -> String {
        if wallet_open {
            "shekyl-cli [wallet]> ".to_string()
        } else {
            "shekyl-cli> ".to_string()
        }
    }
}
