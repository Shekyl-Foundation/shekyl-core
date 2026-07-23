// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL prompt rendering.
//!
//! With the wallet2-era account model deleted (WI-RPC-2b), the REPL carries no
//! session-local state: the prompt is a pure function of whether a wallet is
//! open, so it is a free function rather than a method on an empty struct.

/// Build the REPL prompt string.
pub fn prompt(wallet_open: bool) -> String {
    if wallet_open {
        "shekyl-cli [wallet]> ".to_string()
    } else {
        "shekyl-cli> ".to_string()
    }
}
