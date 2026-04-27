// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL session state.
//!
//! `ReplSession` lives on the REPL loop's stack frame. It is never shared,
//! never `Send`, and never leaks into engine-level or RPC-level state.
//! The engine RPC layer is stateless with respect to accounts -- every call
//! takes an explicit `account_index`. The session default is purely a UI
//! convenience resolved at parse time.

/// Local session state for the interactive REPL.
///
/// Owned by the REPL loop's stack. Mutated only by `account default N`.
pub struct ReplSession {
    pub default_account: u32,
}

impl Default for ReplSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplSession {
    pub fn new() -> Self {
        Self { default_account: 0 }
    }

    /// Build the REPL prompt string, reflecting the current default account.
    pub fn prompt(&self, engine_open: bool) -> String {
        if !engine_open {
            return "shekyl-cli> ".to_string();
        }
        if self.default_account == 0 {
            "shekyl-cli [engine]> ".to_string()
        } else {
            format!("shekyl-cli [engine@acct{}]> ", self.default_account)
        }
    }
}
