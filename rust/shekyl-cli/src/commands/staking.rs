// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking commands over the WI-RPC-1 staking surface (WI-RPC-2b):
//! `stake`, `staked_balance`, `staked_outputs`, `staking_info`.
//!
//! The user asks to stake; the protocol dance (persona derivation, P-scan,
//! bond assembly, dispatch) stays hidden per rule 81. Read commands surface
//! the never-conflated staked-balance breakdown exactly as the RPC reports
//! it.

use serde_json::{json, Value};

use super::{confirm, opt_amount, read_password, require_open};
use crate::rpc_client::{params, RpcSession};

/// The exact phrase a foundation stake requires, typed by the operator.
///
/// **A typed phrase rather than y/n, deliberately** (D-4). The action is
/// capital-locking and its obligation is unbounded and permanent; a
/// keystroke that means "yes" to every prompt is exactly the reflex that
/// should not be able to reach it. Typing a sentence about serving without
/// reward is a different act from dismissing a dialog.
///
/// Compared after trimming surrounding whitespace only — a trailing space
/// or a stray newline from a terminal is not a different intent, while any
/// other difference is.
const FOUNDATION_PHRASE: &str = "serve without reward";

pub fn cmd_stake(rpc: &RpcSession, foundation: bool) {
    if !require_open(rpc) {
        return;
    }
    if foundation {
        cmd_stake_foundation(rpc);
        return;
    }
    println!("Staking bonds your wallet's funds as staking principal.");
    println!("The bond posts on-chain and the principal locks until unbonding.");
    if !confirm("Make this wallet a staker?") {
        println!("Staking cancelled.");
        return;
    }
    // Load-bearing, not UX: a mid-session wallet holds no seed, and only a
    // credentialed reopen re-materializes it for the persona derivation.
    let Some(password) = read_password("Wallet password: ") else {
        return;
    };
    println!("Staking (this may take a while)...");
    let result = rpc.call(
        "stake",
        params::Stake {
            password: &password,
        },
    );

    match result {
        Ok(val) => {
            let slot = val
                .get("slot")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let resumed = val
                .get("resumed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if resumed {
                println!("Resumed an in-flight stake (slot {slot}).");
            } else {
                println!("Stake sealed (slot {slot}).");
            }
            println!("The bond will be dispatched to the network automatically.");
            println!("Track it with \"staking_info\".");
        }
        Err(e) => rpc.report("Failed to stake", &e),
    }
}

/// `stake --complete-tree-foundation` — the CLI half of D-4's gate.
///
/// Prints the terms, requires them typed back, and only then sends the
/// acknowledgment. The terms are **not** written here: they come from
/// [`shekyl_wallet_rpc::FOUNDATION_POSTURE_WARNING`], the same constant the
/// `-29506` refusal body carries and the published contract pins, so the
/// operator reads exactly what a wrapper's user would read. A second copy
/// in this file is the drift this arrangement exists to prevent.
fn cmd_stake_foundation(rpc: &RpcSession) {
    println!("{}", shekyl_wallet_rpc::FOUNDATION_POSTURE_WARNING);
    println!();
    eprint!("Type exactly: {FOUNDATION_PHRASE}\n> ");
    drop(std::io::Write::flush(&mut std::io::stderr()));
    let mut typed = String::new();
    if std::io::stdin().read_line(&mut typed).is_err() {
        println!("Foundation staking cancelled.");
        return;
    }
    if typed.trim() != FOUNDATION_PHRASE {
        // Nothing is sent. The wallet is untouched, and the operator is
        // told which half failed rather than being left to guess whether
        // the stake went through.
        println!("Phrase did not match. Foundation staking cancelled; nothing was sent.");
        return;
    }

    let Some(password) = read_password("Wallet password: ") else {
        return;
    };
    println!("Staking as a Foundation CompleteTree node (this may take a while)...");
    let result = rpc.call(
        "stake",
        params::StakeFoundation {
            password: &password,
            posture: "foundation_complete_tree",
            acknowledge_non_earning_unbounded: true,
        },
    );

    match result {
        Ok(val) => {
            let slot = val
                .get("slot")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            println!("Foundation CompleteTree stake sealed (slot {slot}).");
            println!("This node now owes the whole frozen corpus and earns nothing for it.");
            println!("The bond will be dispatched to the network automatically.");
            println!("Track it with \"staking_info\".");
        }
        Err(e) => rpc.report("Failed to stake", &e),
    }
}

pub fn cmd_staked_balance(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_staked_balance", json!({})) {
        Ok(val) => print_staked_balance(&val, ""),
        Err(e) => rpc.report("Failed to get staked balance", &e),
    }
}

fn print_staked_balance(balance: &Value, indent: &str) {
    let field = |name: &str| opt_amount(balance, name);
    println!(
        "{indent}Bonded principal (confirmed): {} SKL",
        field("bonded_principal_confirmed")
    );
    println!(
        "{indent}Bonded principal (pending):   {} SKL",
        field("bonded_principal_pending")
    );
    println!(
        "{indent}Rewards received, unspent:    {} SKL",
        field("rewards_received_unspent")
    );
}

pub fn cmd_staked_outputs(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_staked_outputs", json!({})) {
        Ok(val) => {
            let outputs = val.get("staked_outputs").and_then(|v| v.as_array());
            let Some(outputs) = outputs.filter(|a| !a.is_empty()) else {
                println!("No staked outputs.");
                return;
            };
            println!(
                "{:<14} {:>18} {:>6} {:>14}",
                "Output", "Amount (SKL)", "Slot", "Unlock height"
            );
            for o in outputs {
                let gindex = o.get("gindex").and_then(|v| v.as_str()).unwrap_or("?");
                let amount = opt_amount(o, "amount");
                let slot = o
                    .get("p_slot")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(-1);
                let unlock = o
                    .get("unlock_height")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                println!("{gindex:<14} {amount:>18} {slot:>6} {unlock:>14}");
            }
        }
        Err(e) => rpc.report("Failed to get staked outputs", &e),
    }
}

pub fn cmd_staking_info(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("staking_info", json!({})) {
        Ok(val) => {
            let enabled = val
                .get("staking_enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            println!("Staking enabled: {}", if enabled { "yes" } else { "no" });
            if !enabled {
                println!("Use \"stake\" to make this wallet a staker.");
                // Still printed: omitting the line on a non-staker reads
                // as though the question were never asked (rule 82).
                print_serving_posture(&val);
                return;
            }
            if let Some(balance) = val.get("balance") {
                println!("Staked balance:");
                print_staked_balance(balance, "  ");
            }
            let count = val
                .get("staked_output_count")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            println!("Staked outputs:  {count}");
            match val
                .get("pscan_synced_height")
                .and_then(serde_json::Value::as_i64)
            {
                Some(h) => println!("Staking scan height: {h}"),
                None => println!("Staking scan height: not yet scanned"),
            }
            // Always rendered, including the absent case: "not serving" is
            // the reading an operator most needs and the one that would
            // otherwise be invisible — a bonded wallet showing no posture
            // line at all reads as though the question were not asked
            // (rule 82). The non-earning parenthetical rides the foundation
            // arm every time it is shown, so the terms stay attached to the
            // posture rather than living only in the one-time warning.
            print_serving_posture(&val);
        }
        Err(e) => rpc.report("Failed to get staking info", &e),
    }
}

/// Wire `posture` → the line an operator reads.
///
/// Isolated so the disabled-wallet early return and the enabled path
/// cannot drift, and so an unknown spelling can be asserted as echoed
/// rather than downgraded to "not serving".
fn serving_posture_display(posture: Option<&str>) -> String {
    match posture {
        Some("foundation_complete_tree") => "Foundation CompleteTree (non-earning)".to_owned(),
        Some("market") => "market".to_owned(),
        // An unknown spelling is a newer server talking to an older
        // CLI. Echo it rather than claiming "not serving", which
        // would be a false negative about a node that IS serving.
        Some(other) => other.to_owned(),
        None => "not serving".to_owned(),
    }
}

fn print_serving_posture(val: &Value) {
    let posture = val.get("posture").and_then(Value::as_str);
    println!("Serving posture:     {}", serving_posture_display(posture));
}

#[cfg(test)]
mod tests {
    use super::{serving_posture_display, FOUNDATION_PHRASE};
    use shekyl_wallet_rpc::FOUNDATION_POSTURE_WARNING;

    /// **The phrase shown and the phrase required are one string.**
    ///
    /// The warning's closing line instructs the operator to type the
    /// phrase, and [`FOUNDATION_PHRASE`] is what the prompt compares
    /// against — two spellings of one fact. The warning is pinned to
    /// `docs/api/wallet_rpc.yaml`, so a contract-side reword lands here
    /// without touching this file: an operator would then be shown one
    /// phrase while being required to type another, which is an
    /// unpassable gate on the one command whose gate is the point.
    ///
    /// Asserted rather than interpolated. Building the warning with a
    /// `format!` would make the served text no longer *verbatim* §5 —
    /// the property the round ratified and the yaml gate enforces — so
    /// the two stay separately readable and a test keeps them equal.
    #[test]
    fn the_required_phrase_is_the_phrase_the_warning_shows() {
        assert!(
            FOUNDATION_POSTURE_WARNING.contains(FOUNDATION_PHRASE),
            "the warning must instruct exactly the phrase the prompt \
             accepts; they have drifted"
        );

        // The gate must be able to fail: a phrase the warning does not
        // contain has to be rejected, or the assertion above would pass
        // over any string at all.
        assert!(!FOUNDATION_POSTURE_WARNING.contains("serve for profit"));
    }

    #[test]
    fn serving_posture_renders_the_contract_spellings() {
        assert_eq!(serving_posture_display(None), "not serving");
        assert_eq!(serving_posture_display(Some("market")), "market");
        assert_eq!(
            serving_posture_display(Some("foundation_complete_tree")),
            "Foundation CompleteTree (non-earning)"
        );
        assert_eq!(
            serving_posture_display(Some("future_arm")),
            "future_arm",
            "unknown spellings are echoed, never downgraded to not serving"
        );
    }
}
