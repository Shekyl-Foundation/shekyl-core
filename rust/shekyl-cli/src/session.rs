// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL prompt rendering.
//!
//! With the wallet2-era account model deleted (WI-RPC-2b), the REPL carries no
//! session-local state: the prompt is a pure function of the network and the
//! open wallet's name, so it is a free function rather than a method on an
//! empty struct.

/// Build the REPL prompt string: `testnet:miner> ` with a wallet open,
/// `mainnet> ` without one.
///
/// The network is **always** shown (CU-1): there is no persistent network
/// setting, so the prompt is the one place an operator sees which network
/// this session spends on — a testnet habit must never look like mainnet.
pub fn prompt(network: &str, wallet: Option<&str>) -> String {
    match wallet {
        Some(name) => format!("{network}:{name}> "),
        None => format!("{network}> "),
    }
}

#[cfg(test)]
mod tests {
    use super::prompt;

    /// The prompt always names the network; a wallet name joins it with `:`.
    #[test]
    fn the_prompt_always_names_the_network() {
        assert_eq!(prompt("mainnet", None), "mainnet> ");
        assert_eq!(prompt("testnet", Some("miner")), "testnet:miner> ");
        assert_eq!(prompt("stagenet", None), "stagenet> ");
    }
}
