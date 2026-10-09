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

use crate::outcome::{failed, refusal, CommandFailed, CommandResult, Presentation};
use serde_json::{json, Value};
use shekyl_wallet_rpc::types::{
    CollectUnstakedResult, DrainResult, DrainVerdictView, UnstakeResult,
};

use super::{format_amount, opt_amount, require_open, transfers};
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
pub const FOUNDATION_PHRASE: &str = "serve without reward";

/// The operator has accepted the Foundation terms.
///
/// A terminal run types [`FOUNDATION_PHRASE`] after the warning. A script
/// passes the same phrase as `--acknowledge`. Either way this returns before
/// the wallet is opened, so a refusal writes nothing.
pub fn accept_foundation_terms(
    presentation: &Presentation,
    acknowledge: Option<&str>,
) -> Result<(), CommandFailed> {
    // The terms print before either check, and before the wallet opens.
    // A script that already passed `--acknowledge` still has to say them.
    // JSON stdout is the command transcript, so the disclosure is not an
    // envelope line.
    presentation.disclose(shekyl_wallet_rpc::FOUNDATION_POSTURE_WARNING);
    if !presentation.interactive() {
        return if acknowledge == Some(FOUNDATION_PHRASE) {
            Ok(())
        } else {
            Err(refusal(format!(
                "A script must pass --acknowledge \"{FOUNDATION_PHRASE}\" with \
                 --complete-tree-foundation. Nothing was written."
            )))
        };
    }
    eprint!("Type exactly: {FOUNDATION_PHRASE}\n> ");
    let _flushed = std::io::Write::flush(&mut std::io::stderr());
    let mut typed = String::new();
    if std::io::stdin().read_line(&mut typed).is_err() || typed.trim() != FOUNDATION_PHRASE {
        return Err(refusal(
            "Foundation staking cancelled. Unbounded disk, no reward. Nothing was written.",
        ));
    }
    Ok(())
}

/// Post the Foundation CompleteTree bond. The caller checked the phrase and
/// still holds the password. One `stake` call; the password is the caller's.
pub fn post_foundation_stake(rpc: &RpcSession, password: &str) -> CommandResult {
    match rpc.call(
        "stake",
        params::StakeFoundation {
            password,
            posture: "foundation_complete_tree",
            acknowledge_non_earning_unbounded: true,
        },
    ) {
        Ok(_) => Ok(json!({"sealed": true})),
        Err(e) => Err(rpc.report("Failed to stake", &e)),
    }
}

pub(crate) fn show_foundation(_val: &Value) {
    println!("Foundation CompleteTree stake sealed.");
    println!("This node owes the whole frozen corpus and earns nothing for it.");
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
pub fn cmd_stake_in(
    rpc: &RpcSession,
    presentation: &Presentation,
    amount: u64,
    yes: bool,
) -> CommandResult {
    require_open(rpc)?;
    presentation.say("Stake-in adds funds to your staking balance with an ordinary transfer");
    presentation.say("from this wallet.");
    presentation.say("");
    presentation.say("Privacy note: like any send, this transaction also returns change to");
    presentation.say("this wallet. An observer who can already link that change output to");
    presentation.say("you could connect it to the staking funds in the same transaction.");
    presentation.say("");

    let response = match rpc.call("stake_in", json!({ "amount": amount.to_string() })) {
        Ok(v) => v,
        Err(e) => {
            return Err(rpc.report("Failed to prepare the stake-in", &e));
        }
    };
    let built = transfers::take_built_pending_tx(rpc, &response)?;

    // The confirmation must not understate the debit: the transfer carries
    // `amount + cover`, so a summary of Amount + Fee alone would confirm a
    // smaller send than the one that fires (and `stake_in 0` would confirm a
    // "zero" send that debits real money). Only the BOUND is shown — from
    // the enforcing constant, never a hardcoded figure — because disclosing
    // the exact draw before sending would let a discard-and-rebuild loop
    // steer the cover distribution the privacy property depends on.
    presentation.say("Stake-in summary:");
    presentation.say(format!("  Amount: {} SKL", format_amount(amount)));
    presentation.say(format!("  Fee:    {} SKL", built.fee_skl));
    presentation.say("");
    presentation.say(format!(
        "A randomized privacy amount (less than {} SKL) is sent on top of the",
        format_amount(shekyl_wallet_rpc::COVER_RUNG_ATOMIC)
    ));
    presentation.say("amount above. It stays yours: it becomes part of your staking balance.");
    presentation.say("It is chosen automatically and cannot be shown before sending.");

    if let Err(error) = super::confirm_money(
        presentation,
        "Fund staking with this transfer?",
        "stake add",
        yes,
    ) {
        transfers::discard_declined(rpc, &built)?;
        return Err(error);
    }
    transfers::submit_pending(rpc, &built)
}

/// `drain_balance` — how much staking money can be moved back to this
/// wallet (WI-RPC-5).
///
/// Two-armed by contract (F-D2 / rule 82): while the wallet cannot yet
/// anchor the drainable set it says so — it NEVER prints a zero, which
/// would read as "nothing to drain" and be indistinguishable from an
/// empty pool.
pub fn cmd_drain_balance(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_drain_balance", json!({})) {
        Ok(val) => match val.get("status").and_then(Value::as_str) {
            Some("ready" | "syncing") => Ok(val),
            _ => failed("Malformed get_drain_balance response."),
        },
        Err(e) => Err(rpc.report("Failed to read the drainable balance", &e)),
    }
}

pub(crate) fn show_drain_balance(val: &Value) {
    match val.get("status").and_then(Value::as_str) {
        Some("ready") => println!(
            "Staking funds available to move back to this wallet: {} SKL",
            opt_amount(val, "spendable")
        ),
        Some("syncing") => {
            println!("The drainable amount is not known yet — the wallet is still syncing.");
            println!("Run \"wallet refresh\" and try again.");
        }
        _ => {}
    }
}

/// `drain <amount>` — move staking funds back to this wallet (WI-RPC-5).
///
/// One shot: unlike `transfer`/`stake_in` there is no build-then-confirm
/// reservation on the server, so the CLI confirms BEFORE firing — a drain
/// cannot be discarded once sent. No fee or destination is shown as a
/// choice because none exists (rule 81 / the anti-fingerprint pin): the fee
/// is set automatically and the funds can only come back to this wallet.
pub fn cmd_drain(
    rpc: &RpcSession,
    presentation: &Presentation,
    amount: u64,
    yes: bool,
) -> CommandResult {
    require_open(rpc)?;
    // Refused locally, before the confirm prompt: a zero drain would
    // otherwise print "This moves 0.000000000 SKL", ask for confirmation,
    // and fire a request the server refuses as malformed (-32602).
    if amount == 0 {
        return failed("Nothing to move: the amount must be greater than zero.");
    }
    presentation.say(format!(
        "This moves {} SKL of your staking funds back to this wallet's balance.",
        format_amount(amount)
    ));
    presentation.say("The network fee is set automatically and is paid from the staking");
    presentation.say("funds on top of this amount.");

    super::confirm_money(presentation, "Move these funds?", "stake return", yes)?;

    presentation.say("Sending (this may take a while)...");
    match rpc.call("drain", json!({ "amount": amount.to_string() })) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to return staking funds", &e)),
    }
}

pub(crate) fn show_drain(val: &Value) {
    match serde_json::from_value::<DrainResult>(val.clone()) {
        Ok(result) => match result.verdict {
            DrainVerdictView::Broadcast => {
                println!("Return sent: {}", result.tx_hash);
                println!(
                    "The funds arrive in this wallet's balance after the network \
                     confirms the transaction."
                );
            }
            DrainVerdictView::AlreadyInChain => match result.confirmed_height {
                Some(h) => println!(
                    "An identical earlier return is already confirmed on chain \
                     (reported height {h}): {}",
                    result.tx_hash
                ),
                None => println!(
                    "An identical earlier return is already confirmed on chain: {}",
                    result.tx_hash
                ),
            },
        },
        Err(_) => {
            let tx_hash = val.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Return sent (verdict not recognized): {tx_hash}");
        }
    }
}

pub fn cmd_staked_balance(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_staked_balance", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to get staked balance", &e)),
    }
}

pub(crate) fn show_staked_balance(val: &Value) {
    print_staked_balance(val, "");
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

pub fn cmd_staked_outputs(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_staked_outputs", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to get staked outputs", &e)),
    }
}

pub(crate) fn show_staked_outputs(val: &Value) {
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
        let slot = o.get("p_slot").and_then(Value::as_i64).unwrap_or(-1);
        let unlock = o.get("unlock_height").and_then(Value::as_i64).unwrap_or(0);
        println!("{gindex:<14} {amount:>18} {slot:>6} {unlock:>14}");
    }
}

pub fn cmd_staking_info(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("staking_info", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to get staking info", &e)),
    }
}

pub(crate) fn show_staking_info(val: &Value) {
    let enabled = val
        .get("staking_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    println!("Staking enabled: {}", if enabled { "yes" } else { "no" });
    if !enabled {
        println!("Use \"stake\" to make this wallet a staker.");
        print_serving_posture(val);
        return;
    }
    if let Some(balance) = val.get("balance") {
        println!("Staked balance:");
        print_staked_balance(balance, "  ");
    }
    let count = val
        .get("staked_output_count")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    println!("Staked outputs:  {count}");
    match val.get("pscan_synced_height").and_then(Value::as_i64) {
        Some(h) => println!("Staking scan height: {h}"),
        None => println!("Staking scan height: not yet scanned"),
    }
    print_serving_posture(val);
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

/// `stake release` — post the terminal Release for the staked bond (PR-C).
///
/// The RPC method is still `unstake`. The word a person types is release.
///
/// **The irreversible step**: once the release confirms on-chain, the bond is
/// permanently closed — the collateral returns to the staking side, and
/// staking again means a whole new bond. The CLI confirms BEFORE firing
/// (prompts are CLI-side, not RPC-side), and the prompt names the
/// irreversibility rather than reading like an ordinary send. No amount,
/// fee, or target is shown as a choice because none exists: the release
/// covers the whole bond, the fee is set automatically, and the wallet
/// picks the bonded stake (rule 81 — no slot vocabulary).
pub fn cmd_unstake(rpc: &RpcSession, presentation: &Presentation, yes: bool) -> CommandResult {
    require_open(rpc)?;
    presentation.say("Release posts the permanent close of this wallet's staked bond.");
    presentation.say("This cannot be undone: once the release confirms, the bond is closed");
    presentation.say("for good, and staking again later means posting a whole new bond.");
    presentation.say("The released funds return to your staking balance first; collect");
    presentation.say("them to this wallet afterwards with \"stake collect\".");

    super::confirm_money(presentation, "Post the release?", "stake release", yes)?;

    presentation.say("Posting the release (this may take a while)...");
    // The server object is the result. Human formatting decodes it once.
    // An unrecognized verdict is still a posted transaction: the hash is
    // shown rather than dropped. That arm is the newer-server case, not
    // an unused branch.
    match rpc.call("unstake", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to release", &e)),
    }
}

pub(crate) fn show_release(val: &Value) {
    match serde_json::from_value::<UnstakeResult>(val.clone()) {
        Ok(result) => match result.verdict {
            DrainVerdictView::Broadcast => {
                println!("Release posted: {}", result.tx_hash);
                println!("When the network confirms it, run \"stake collect\" to move");
                println!("the released funds back into this wallet's balance.");
            }
            DrainVerdictView::AlreadyInChain => {
                println!(
                    "An identical release is already confirmed: {}",
                    result.tx_hash
                );
                println!("Run \"stake collect\" to move the released funds back into");
                println!("this wallet's balance (it may take a moment for the wallet's");
                println!("own scan to observe the confirmation).");
            }
        },
        Err(_) => {
            let tx_hash = val.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Release posted (verdict not recognized): {tx_hash}");
        }
    }
}

/// `stake collect` — move the released exit collateral back to this
/// wallet's balance, one pass at a time (PR-C).
///
/// The amount is not asked for and cannot be shown up front: each pass
/// sweeps everything currently spendable (the engine computes the exact
/// figure so nothing is left stranded), and the reply says what moved and
/// what still remains. **A success is not completion** — the reply's
/// two-part completion fact (this persona's remainder, plus whether
/// another exit's pool remains) is what this command renders explicitly
/// rather than letting "sent" read as "done".
pub fn cmd_collect_unstaked(
    rpc: &RpcSession,
    presentation: &Presentation,
    yes: bool,
) -> CommandResult {
    require_open(rpc)?;
    presentation.say("This collects your released staking funds back into this wallet's");
    presentation.say("balance. The network fee is set automatically and paid from the");
    presentation.say("collected funds; large collections may take more than one pass.");

    super::confirm_money(
        presentation,
        "Collect the released funds?",
        "stake collect",
        yes,
    )?;

    presentation.say("Collecting (this may take a while)...");
    match rpc.call("collect_unstaked", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to collect", &e)),
    }
}

pub(crate) fn show_collect(val: &Value) {
    match serde_json::from_value::<CollectUnstakedResult>(val.clone()) {
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
                    swept.to_atomic_units().to_skl_string(),
                );
                if remainder.to_atomic_units().is_zero() && another_pool_remains {
                    println!(
                        "This collection is complete, but released funds from \
                         another release still remain."
                    );
                    println!("Run \"stake collect\" again once this pass confirms.");
                } else if remainder.to_atomic_units().is_zero() {
                    println!(
                        "Nothing further remains: once this confirms, the \
                         collection is complete."
                    );
                } else {
                    println!(
                        "{} SKL still remains in the staking balance (not yet \
                         spendable, or beyond this pass's size).",
                        remainder.to_atomic_units().to_skl_string()
                    );
                    println!("Run \"stake collect\" again once this pass confirms.");
                }
            }
            CollectUnstakedResult::NothingLeft => {
                println!("Nothing left to collect: the release's funds are already in");
                println!("this wallet (or on their way in a previous pass).");
            }
        },
        Err(_) => {
            let tx_hash = val.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Collection sent (reply not recognized): {tx_hash}");
        }
    }
}

fn print_serving_posture(val: &Value) {
    let posture = val.get("posture").and_then(Value::as_str);
    println!("Serving posture:     {}", serving_posture_display(posture));
    if let Some(line) = serving_priority_line(val.get("serving_priority_not_lowered")) {
        println!("{line}");
    }
}

/// The operator line for a serving host that could not lower its priority.
///
/// Absent and zero are the steady readings and print nothing: no lifecycle
/// is parked, or every serving thread that has started was lowered. A
/// positive count is the failure, and the line says serving is still up
/// and where the cause is written.
fn serving_priority_line(field: Option<&Value>) -> Option<String> {
    let count = field.and_then(Value::as_u64)?;
    if count == 0 {
        return None;
    }
    let threads = if count == 1 { "thread" } else { "threads" };
    Some(format!(
        "Serving could not lower its priority on {count} {threads}. \
         It is still serving. The wallet log names the reason."
    ))
}

/// Bare `stake`: this wallet's posture and the returnable amount.
pub fn cmd_stake_read(rpc: &RpcSession) -> CommandResult {
    let info = cmd_staking_info(rpc)?;
    let drain = if rpc.is_open() {
        cmd_drain_balance(rpc)?
    } else {
        Value::Null
    };
    Ok(json!({"staking_info": info, "drain_balance": drain}))
}

pub(crate) fn show_stake(val: &Value) {
    if let Some(info) = val.get("staking_info") {
        show_staking_info(info);
    }
    if let Some(drain) = val.get("drain_balance") {
        if !drain.is_null() {
            show_drain_balance(drain);
        }
    }
}

/// `stake join` names a shard set and does not post it. Wallet-RPC `stake`
/// still takes a posture, not shard ids, and a market call answers -29505.
pub fn cmd_stake_join(_rpc: &crate::rpc_client::RpcSession, shard_ids: &[u64]) -> CommandResult {
    let listed = shard_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    failed(format!(
        "stake join {listed}: nothing was written. Posting a chosen set of \
         shards is not available yet."
    ))
}

#[cfg(test)]
mod tests {
    use super::{serving_posture_display, serving_priority_line, FOUNDATION_PHRASE};
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

    #[test]
    fn a_priority_failure_is_said_once_it_happens() {
        use serde_json::json;

        assert_eq!(serving_priority_line(None), None);
        assert_eq!(serving_priority_line(Some(&json!(0))), None);
        assert_eq!(
            serving_priority_line(Some(&json!(1))).as_deref(),
            Some(
                "Serving could not lower its priority on 1 thread. \
                 It is still serving. The wallet log names the reason."
            )
        );
        assert_eq!(
            serving_priority_line(Some(&json!(3))).as_deref(),
            Some(
                "Serving could not lower its priority on 3 threads. \
                 It is still serving. The wallet log names the reason."
            )
        );
    }
}
