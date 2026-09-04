// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking commands over the WI-RPC-1 staking surface (WI-RPC-2b):
//! `stake`, `staked_balance`, `staked_outputs`, `staking_info` — plus the
//! WI-RPC-5 archival principal actions `stake_in`, `drain_balance`, `drain`.
//!
//! The user asks to stake; the protocol dance (persona derivation, P-scan,
//! bond assembly, dispatch) stays hidden per rule 81. Read commands surface
//! the never-conflated staked-balance breakdown exactly as the RPC reports
//! it. The WI-RPC-5 actions carry no fee/destination/slot parameters by
//! contract — the parser refuses flag-shaped tokens before anything reaches
//! the wire, and the copy talks about "staking funds" and "this wallet",
//! never personas or slots (rule 81).

use serde_json::{json, Value};
use shekyl_wallet_rpc::types::{
    CollectUnstakedResult, DrainResult, DrainVerdictView, UnstakeResult,
};

use super::{
    confirm, confirm_interactive, format_amount, opt_amount, read_password, require_open, transfers,
};
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

/// `stake_in <amount>` — fund the staking balance with an ordinary principal
/// transfer (WI-RPC-5).
///
/// The GF-7 change-co-presence disclosure prints BEFORE anything is built:
/// the transaction carries this wallet's own change output next to the
/// staking fund, an open linkage question this PR ships with a warning
/// rather than a fix (carrier: bond-funding-separation, `docs/FOLLOWUPS.md`).
/// The user must see it before deciding, not on a receipt.
///
/// After the disclosure the flow IS the transfer flow — `stake_in` returns a
/// `build_pending_tx`-shaped reservation, confirmed with the actual fee and
/// then submitted or discarded through the shared helpers.
pub fn cmd_stake_in(rpc: &RpcSession, amount: u64) {
    if !require_open(rpc) {
        return;
    }
    println!("Stake-in adds funds to your staking balance with an ordinary transfer");
    println!("from this wallet.");
    println!();
    println!("Privacy note: like any send, this transaction also returns change to");
    println!("this wallet. An observer who can already link that change output to");
    println!("you could connect it to the staking funds in the same transaction.");
    println!();

    let response = match rpc.call("stake_in", json!({ "amount": amount.to_string() })) {
        Ok(v) => v,
        Err(e) => {
            rpc.report("Failed to prepare the stake-in", &e);
            return;
        }
    };
    let Some(built) = transfers::take_built_pending_tx(rpc, &response) else {
        return;
    };

    // The confirmation must not understate the debit: the transfer carries
    // `amount + cover`, so a summary of Amount + Fee alone would confirm a
    // smaller send than the one that fires (and `stake_in 0` would confirm a
    // "zero" send that debits real money). Only the BOUND is shown — from
    // the enforcing constant, never a hardcoded figure — because disclosing
    // the exact draw before sending would let a discard-and-rebuild loop
    // steer the cover distribution the privacy property depends on.
    println!("Stake-in summary:");
    println!("  Amount: {} SKL", format_amount(amount));
    println!("  Fee:    {} SKL", built.fee_skl);
    println!();
    println!(
        "A randomized privacy amount (less than {} SKL) is sent on top of the",
        format_amount(shekyl_wallet_rpc::COVER_RUNG_ATOMIC)
    );
    println!("amount above. It stays yours: it becomes part of your staking balance.");
    println!("It is chosen automatically and cannot be shown before sending.");

    if !confirm_interactive("Fund staking with this transfer?", "stake in") {
        transfers::discard_declined(rpc, &built);
        return;
    }
    transfers::submit_pending(rpc, &built);
}

/// `drain_balance` — how much staking money can be moved back to this
/// wallet (WI-RPC-5).
///
/// Two-armed by contract (F-D2 / rule 82): while the wallet cannot yet
/// anchor the drainable set it says so — it NEVER prints a zero, which
/// would read as "nothing to drain" and be indistinguishable from an
/// empty pool.
pub fn cmd_drain_balance(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_drain_balance", json!({})) {
        Ok(val) => match val.get("status").and_then(Value::as_str) {
            Some("ready") => println!(
                "Staking funds available to move back to this wallet: {} SKL",
                opt_amount(&val, "spendable")
            ),
            Some("syncing") => {
                println!("The drainable amount is not known yet — the wallet is still syncing.");
                println!("Run \"refresh\" and try again.");
            }
            _ => eprintln!("Malformed get_drain_balance response."),
        },
        Err(e) => rpc.report("Failed to read the drainable balance", &e),
    }
}

/// `drain <amount>` — move staking funds back to this wallet (WI-RPC-5).
///
/// One shot: unlike `transfer`/`stake_in` there is no build-then-confirm
/// reservation on the server, so the CLI confirms BEFORE firing — a drain
/// cannot be discarded once sent. No fee or destination is shown as a
/// choice because none exists (rule 81 / the anti-fingerprint pin): the fee
/// is set automatically and the funds can only come back to this wallet.
pub fn cmd_drain(rpc: &RpcSession, amount: u64) {
    if !require_open(rpc) {
        return;
    }
    // Refused locally, before the confirm prompt: a zero drain would
    // otherwise print "This moves 0.000000000 SKL", ask for confirmation,
    // and fire a request the server refuses as malformed (-32602).
    if amount == 0 {
        println!("Nothing to move: the amount must be greater than zero.");
        return;
    }
    println!(
        "This moves {} SKL of your staking funds back to this wallet's balance.",
        format_amount(amount)
    );
    println!("The network fee is set automatically and is paid from the staking");
    println!("funds on top of this amount.");

    if !confirm_interactive("Move these funds?", "drain") {
        println!("Drain cancelled; nothing was sent.");
        return;
    }

    println!("Sending (this may take a while)...");
    match rpc.call("drain", json!({ "amount": amount.to_string() })) {
        // Decoded through the server's own result type (the `cmd_transfer`
        // discipline): a new verdict arm fails this build instead of
        // silently rendering as a plain success.
        Ok(val) => match serde_json::from_value::<DrainResult>(val.clone()) {
            Ok(result) => match result.verdict {
                DrainVerdictView::Broadcast => {
                    println!("Drain sent: {}", result.tx_hash);
                    println!(
                        "The funds arrive in this wallet's balance after the network \
                         confirms the transaction."
                    );
                }
                // The height is the daemon's claim, not an observation of
                // ours — say "reported" so the user reads it as such.
                DrainVerdictView::AlreadyInChain => match result.confirmed_height {
                    Some(h) => println!(
                        "An identical earlier drain is already confirmed on chain \
                         (reported height {h}): {}",
                        result.tx_hash
                    ),
                    None => println!(
                        "An identical earlier drain is already confirmed on chain: {}",
                        result.tx_hash
                    ),
                },
            },
            // A server newer than this CLI, or a malformed reply: the drain
            // still went through — never swallow the hash.
            Err(_) => {
                let tx_hash = val.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("?");
                println!("Drain sent (verdict not recognized): {tx_hash}");
            }
        },
        Err(e) => rpc.report("Failed to drain", &e),
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

/// `unstake` — post the terminal exit for the staked bond (PR-C).
///
/// **The irreversible step**: once the exit confirms on-chain, the bond is
/// permanently closed — the collateral releases to the staking side, and
/// staking again means a whole new bond. The CLI confirms BEFORE firing
/// (prompts are CLI-side, not RPC-side), and the prompt names the
/// irreversibility rather than reading like an ordinary send. No amount,
/// fee, or target is shown as a choice because none exists: the exit
/// releases the whole bond, the fee is set automatically, and the wallet
/// picks the bonded stake to exit (rule 81 — no slot vocabulary).
pub fn cmd_unstake(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    println!("Unstaking posts the permanent exit for this wallet's staked bond.");
    println!("This cannot be undone: once the exit confirms, the bond is closed");
    println!("for good, and staking again later means posting a whole new bond.");
    println!("The released funds return to your staking balance first; collect");
    println!("them to this wallet afterwards with \"collect_unstaked\".");

    if !confirm_interactive("Post the permanent exit?", "unstake") {
        println!("Unstake cancelled; nothing was sent.");
        return;
    }

    println!("Posting the exit (this may take a while)...");
    match rpc.call("unstake", json!({})) {
        Ok(val) => match serde_json::from_value::<UnstakeResult>(val.clone()) {
            Ok(result) => match result.verdict {
                DrainVerdictView::Broadcast => {
                    println!("Exit posted: {}", result.tx_hash);
                    println!("When the network confirms it, run \"collect_unstaked\" to move");
                    println!("the released funds back into this wallet's balance.");
                }
                // Already confirmed: "wait for confirmation" would contradict
                // the line above it — the wait here is for the
                // wallet's own scan to observe the existing confirmation.
                DrainVerdictView::AlreadyInChain => {
                    println!("An identical exit is already confirmed: {}", result.tx_hash);
                    println!("Run \"collect_unstaked\" to move the released funds back into");
                    println!("this wallet's balance (it may take a moment for the wallet's");
                    println!("own scan to observe the confirmation).");
                }
            },
            Err(_) => eprintln!("Malformed unstake response: {val}"),
        },
        Err(e) => rpc.report("Failed to unstake", &e),
    }
}

/// `collect_unstaked` — move the released exit collateral back to this
/// wallet's balance, one pass at a time (PR-C).
///
/// The amount is not asked for and cannot be shown up front: each pass
/// sweeps everything currently spendable (the engine computes the exact
/// figure so nothing is left stranded), and the reply says what moved and
/// what still remains. **A success is not completion** — the reply's
/// two-part completion fact (this persona's remainder, plus whether an
/// earlier exit's pool remains) is what this command renders explicitly
/// rather than letting "sent" read as "done".
pub fn cmd_collect_unstaked(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    println!("This collects your released staking funds back into this wallet's");
    println!("balance. The network fee is set automatically and paid from the");
    println!("collected funds; large collections may take more than one pass.");

    if !confirm_interactive("Collect the released funds?", "collect_unstaked") {
        println!("Collection cancelled; nothing was sent.");
        return;
    }

    println!("Collecting (this may take a while)...");
    match rpc.call("collect_unstaked", json!({})) {
        Ok(val) => match serde_json::from_value::<CollectUnstakedResult>(val.clone()) {
            Ok(result) => match result {
                CollectUnstakedResult::Swept {
                    tx_hash,
                    swept,
                    remainder,
                    another_pool_remains,
                } => {
                    println!(
                        "Collection sent: {} ({} SKL on the way to this wallet).",
                        tx_hash,
                        format_amount_str(&swept),
                    );
                    if remainder == "0" && another_pool_remains {
                        // The swept persona is done, but the exit lane is
                        // not: a previously exited persona still holds
                        // funds. Per-slot "0" must never read as lane-wide
                        // completion.
                        println!(
                            "This collection is complete, but released funds from an \
                             earlier exit still remain."
                        );
                        println!("Run \"collect_unstaked\" again once this pass confirms.");
                    } else if remainder == "0" {
                        println!(
                            "Nothing further remains: once this confirms, the \
                             collection is complete."
                        );
                    } else {
                        println!(
                            "{} SKL still remains in the staking balance (not yet \
                             spendable, or beyond this pass's size).",
                            format_amount_str(&remainder)
                        );
                        println!("Run \"collect_unstaked\" again once this pass confirms.");
                    }
                }
                CollectUnstakedResult::NothingLeft => {
                    println!("Nothing left to collect: the exit's funds are already in");
                    println!("this wallet (or on their way in a previous pass).");
                }
            },
            Err(_) => eprintln!("Malformed collect_unstaked response: {val}"),
        },
        Err(e) => rpc.report("Failed to collect", &e),
    }
}

/// Render a decimal atomic-units string through the shared display format;
/// echo the raw string if it does not parse (display metadata only — never
/// worth failing the command over).
fn format_amount_str(atomic: &str) -> String {
    atomic
        .parse::<u64>()
        .map(format_amount)
        .unwrap_or_else(|_| atomic.to_owned())
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
