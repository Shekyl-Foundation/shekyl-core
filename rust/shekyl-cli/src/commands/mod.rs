// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL command loop, dispatch, and shared helpers for shekyl-cli.
//!
//! Every command executes through the [`crate::rpc_client::RpcSession`]
//! JSON-RPC surface (Shape B). The wallet2-era commands with no Shekyl-native
//! equivalent were deleted in WI-RPC-2b (they refuse with guidance at parse
//! time, see [`crate::resolve`]); commands whose native surface is designed
//! but not yet landed answer with a RESERVED message naming what gates them.

mod balance;
mod chain;
mod fees;
mod lifecycle;
mod receiving;
pub mod scripted;
mod staking;
mod transfers;

use crate::daemon::DaemonClient;
use crate::rpc_client::RpcSession;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

const HELP_TEXT: &str = "\
Wallet lifecycle:
  create <filename>                   Create a new wallet
  open <filename>                     Open an existing wallet
  close                               Close the current wallet
  restore <filename> <seed...>        Restore wallet from mnemonic seed
  password                            Change wallet password
  refresh                             Sync with the daemon
  status                              Show wallet and daemon sync heights

Address and balance:
  address                             Show the wallet's primary address
  balance                             Show balance breakdown

Transfers:
  transfer <amount> <address>         Send SKL to an address
    [--priority N]                    0-1 economy, 2 standard, 3+ priority
    [--no-confirm]                    Skip confirmation (non-TTY only)
  transfers                           Show recent transactions
  show_transfer <txid>                Show details for a transaction
  fee [--inputs N] [--outputs N]      Show fee quotes and size estimate

Receiving (payment requests):
  request new <amount> <label>        Create a payment request (shekyl: URI)
    [--expiry <height>]               Optional absolute expiry height
  requests list [pending|matched|all] List payment requests
  make_uri [--amount X] [--label L]   Compose a shekyl: payment URI
    [--address ADDR]                  Defaults to the wallet's address
  parse_uri <uri>                     Decode a shekyl: payment URI

Staking:
  stake                               Make this wallet a staker
  staked_balance                      Show the staked-balance breakdown
  staked_outputs                      List unspent staking-side outputs
  staking_info                        Show staking state and scan height
  chain_health                        Show daemon/chain health (separate conn)

Meta:
  version                             Show CLI and wallet-RPC versions
  help                                Show this help
  exit / quit                         Exit shekyl-cli

Not yet available (the RPC surface is designed but has not landed; see
docs/FOLLOWUPS.md): rescan, transaction proofs (get/check_tx_key,
get/check_tx_proof, get/check_reserve_proof), message signing
(sign/verify), and the offline cold-signing workflow
(describe/sign/submit_transfer, transfer --do-not-relay).";

/// RESERVED-surface refusal: the command is part of the target set, but the
/// wallet-RPC method that would back it has not landed. Names the gate so
/// the user (and the FOLLOWUPS reader) can tell it apart from a deletion.
fn reserved(cmd: &str, gate: &str) {
    eprintln!(
        "{cmd}: not available yet — gated on {gate} (docs/FOLLOWUPS.md, WI-RPC-2b deferrals)."
    );
}

pub fn repl(
    rpc: RpcSession,
    daemon_client: Option<DaemonClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::resolve::{self, ResolvedCommand};

    let mut rl = DefaultEditor::new()?;
    let hist = history_path().unwrap_or_default();

    if rl.load_history(&hist).is_err() {
        // No history file yet -- that's fine on first run.
    }

    println!("Welcome to shekyl-cli. Type \"help\" for commands.");

    loop {
        let prompt = crate::session::prompt(rpc.is_open());

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let first_token = line.split_whitespace().next().unwrap_or("");
                if !crate::display::is_secret_command(first_token) {
                    let _ = rl.add_history_entry(line);
                }

                match resolve::parse(line) {
                    ResolvedCommand::Help => println!("{HELP_TEXT}"),
                    ResolvedCommand::Exit => break,

                    // Lifecycle
                    ResolvedCommand::Create { filename } => {
                        lifecycle::cmd_create(&rpc, &filename);
                    }
                    ResolvedCommand::Open { filename } => {
                        lifecycle::cmd_open(&rpc, &filename);
                    }
                    ResolvedCommand::Close => lifecycle::cmd_close(&rpc),
                    ResolvedCommand::Restore {
                        filename,
                        seed_words,
                    } => {
                        lifecycle::cmd_restore(&rpc, &filename, &seed_words);
                    }
                    ResolvedCommand::Refresh => lifecycle::cmd_refresh(&rpc),
                    ResolvedCommand::Save => {
                        println!(
                            "Wallet state is persisted automatically (crash-atomically) \
                             after every operation; there is nothing to save."
                        );
                    }
                    ResolvedCommand::Status => lifecycle::cmd_status(&rpc),
                    ResolvedCommand::Password => lifecycle::cmd_password(&rpc),
                    ResolvedCommand::Rescan { .. } => {
                        reserved("rescan", "the native rescan RPC surface");
                    }

                    // Balance / address
                    ResolvedCommand::Balance => balance::cmd_balance(&rpc),
                    ResolvedCommand::Address => balance::cmd_address(&rpc),

                    // Transfers
                    ResolvedCommand::Transfer {
                        dest,
                        amount,
                        priority,
                        do_not_relay,
                        no_confirm,
                    } => {
                        if do_not_relay {
                            reserved(
                                "transfer --do-not-relay",
                                "the offline cold-signing workflow",
                            );
                        } else {
                            transfers::cmd_transfer(&rpc, amount, &dest, priority, no_confirm);
                        }
                    }
                    ResolvedCommand::Transfers => transfers::cmd_transfers(&rpc),
                    ResolvedCommand::ShowTransfer { txid } => {
                        transfers::cmd_show_transfer(&rpc, &txid);
                    }

                    // Receiving (WI-RPC-1 surface)
                    ResolvedCommand::RequestNew {
                        amount,
                        label,
                        expiry,
                    } => {
                        receiving::cmd_request_new(&rpc, amount, &label, expiry);
                    }
                    ResolvedCommand::RequestsList { filter } => {
                        receiving::cmd_requests_list(&rpc, filter.as_deref());
                    }
                    ResolvedCommand::HistoryIncomingUnattributed => {
                        reserved(
                            "history incoming",
                            "an unattributed-receives RPC surface (FA-8)",
                        );
                    }
                    ResolvedCommand::MakeUri {
                        address,
                        amount,
                        label,
                    } => {
                        receiving::cmd_make_uri(&rpc, address.as_deref(), amount, label.as_deref());
                    }
                    ResolvedCommand::ParseUri { uri } => receiving::cmd_parse_uri(&rpc, &uri),

                    // Staking (WI-RPC-1 surface)
                    ResolvedCommand::Stake => staking::cmd_stake(&rpc),
                    ResolvedCommand::StakedBalance => staking::cmd_staked_balance(&rpc),
                    ResolvedCommand::StakedOutputs => staking::cmd_staked_outputs(&rpc),
                    ResolvedCommand::StakingInfo => staking::cmd_staking_info(&rpc),

                    // Fees (WI-RPC-1 surface)
                    ResolvedCommand::Fee {
                        n_inputs,
                        n_outputs,
                    } => fees::cmd_fee(&rpc, n_inputs, n_outputs),

                    ResolvedCommand::ChainHealth => {
                        chain::cmd_chain_health(daemon_client.as_ref());
                    }

                    // Proofs (RESERVED)
                    ResolvedCommand::GetTxKey { .. }
                    | ResolvedCommand::CheckTxKey { .. }
                    | ResolvedCommand::GetTxProof { .. }
                    | ResolvedCommand::CheckTxProof { .. }
                    | ResolvedCommand::GetReserveProof { .. }
                    | ResolvedCommand::CheckReserveProof { .. } => {
                        reserved("proofs", "the transaction-proof RPC surface");
                    }

                    // Signing (RESERVED)
                    ResolvedCommand::Sign { .. } | ResolvedCommand::Verify { .. } => {
                        reserved("sign/verify", "the message-signing RPC surface");
                    }

                    // Offline signing (RESERVED)
                    ResolvedCommand::DescribeTransfer { .. }
                    | ResolvedCommand::SignTransfer { .. }
                    | ResolvedCommand::SubmitTransfer { .. } => {
                        reserved("offline signing", "the offline cold-signing workflow");
                    }

                    // Meta
                    ResolvedCommand::Version => cmd_version(&rpc),
                    ResolvedCommand::EngineInfo => {
                        reserved("engine_info", "a native wallet-info RPC surface");
                    }

                    ResolvedCommand::Unknown { cmd } => {
                        eprintln!("Unknown command: {cmd}. Type \"help\" for available commands.");
                    }
                    ResolvedCommand::Diagnostic { message } => {
                        eprintln!("{message}");
                    }
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("Input error: {e}");
                break;
            }
        }
    }

    let _ = rl.save_history(&hist);
    // Closes any open wallet and stops the self-hosted server (removing its
    // private UDS socket directory).
    rpc.shutdown();
    Ok(())
}

/// `version`: CLI version, plus the connected wallet-RPC server's version
/// when reachable.
fn cmd_version(rpc: &RpcSession) {
    println!("shekyl-cli {}", env!("CARGO_PKG_VERSION"));
    match rpc.call("get_version", serde_json::json!({})) {
        Ok(val) => {
            let server = val.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            let api = val.get("api_version").and_then(|v| v.as_i64()).unwrap_or(0);
            println!("shekyl-wallet-rpc {server} (api v{api})");
        }
        Err(e) => eprintln!("wallet RPC unreachable: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Confirmation helpers
// ---------------------------------------------------------------------------

/// Standard confirmation: "Type 'yes' to confirm: "
pub(crate) fn confirm(prompt: &str) -> bool {
    eprint!("{prompt} Type 'yes' to confirm: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == "yes"
}

// ---------------------------------------------------------------------------
// Shared helpers used by submodule command handlers
// ---------------------------------------------------------------------------

fn history_path() -> Option<String> {
    dirs::data_local_dir().map(|mut p| {
        p.push("shekyl-cli");
        let _ = std::fs::create_dir_all(&p);
        p.push("history.txt");
        p.to_string_lossy().into_owned()
    })
}

pub(crate) fn require_open(rpc: &RpcSession) -> bool {
    if !rpc.is_open() {
        eprintln!("No wallet is open. Use \"open <filename>\" or \"create <filename>\" first.");
        return false;
    }
    true
}

pub(crate) fn require_closed(rpc: &RpcSession) -> bool {
    if rpc.is_open() {
        eprintln!("A wallet is already open. Use \"close\" first.");
        return false;
    }
    true
}

pub(crate) fn read_password(prompt: &str) -> Option<String> {
    match crate::prompt_password(prompt) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("Failed to read password: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Amount formatting and parsing (9-decimal SKL precision, 10^9 atomic units)
// ---------------------------------------------------------------------------

/// Render a raw atomic-unit amount as a fixed-precision SKL string.
///
/// Routes through [`shekyl_units::AtomicUnits::to_skl_string`] so the
/// atomic-units-per-SKL relationship (`10^9`) is single-sourced from
/// `config/economics_params.json`. This replaces the inherited Monero `10^12`
/// constant, which overflowed `u64` on Shekyl's `2^32` whole-SKL supply.
pub fn format_amount(atomic: u64) -> String {
    shekyl_units::AtomicUnits::from_raw(atomic).to_skl_string()
}

/// Render an OpenAPI `AtomicUnits` decimal string as SKL, falling back to
/// the raw string when it does not parse as `u64`.
pub(crate) fn format_amount_str(atomic: &str) -> String {
    match atomic.parse::<u64>() {
        Ok(v) => format_amount(v),
        Err(_) => atomic.to_owned(),
    }
}

/// Read an optional `AtomicUnits` string field from a JSON object and render it
/// as SKL, falling back to `"?"` when the field is absent or non-string. The
/// single home for the receiving/staking/fee row-formatting idiom.
pub(crate) fn opt_amount(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(format_amount_str)
        .unwrap_or_else(|| "?".to_owned())
}

/// Parse a user-entered SKL string into raw atomic units.
///
/// Routes through [`shekyl_units::AtomicUnits::from_skl_str`], which rejects
/// (rather than truncates) over-precise input and errors on overflow. Returns
/// `None` on any parse error to preserve the existing `Option`-based call
/// sites.
pub fn parse_amount(s: &str) -> Option<u64> {
    shekyl_units::AtomicUnits::from_skl_str(s)
        .ok()
        .map(|a| a.to_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount() {
        // 9-decimal (10^9) SKL display, single-sourced via `shekyl-units`.
        assert_eq!(format_amount(0), "0.000000000");
        assert_eq!(format_amount(1_000_000_000), "1.000000000");
        assert_eq!(format_amount(1_500_000_000), "1.500000000");
        assert_eq!(format_amount(123_456_789), "0.123456789");
    }

    #[test]
    fn test_format_amount_str() {
        assert_eq!(format_amount_str("1000000000"), "1.000000000");
        assert_eq!(format_amount_str("not-a-number"), "not-a-number");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1"), Some(1_000_000_000));
        assert_eq!(parse_amount("1.5"), Some(1_500_000_000));
        assert_eq!(parse_amount("0.000000001"), Some(1));
        assert_eq!(parse_amount("1.0"), Some(1_000_000_000));
        assert_eq!(parse_amount("abc"), None);
        assert_eq!(parse_amount("1.0000000001"), None); // >9 decimal places
    }

    #[test]
    fn test_parse_format_roundtrip() {
        for val in [0, 1, 999_999_999, 1_000_000_000, 123_456_789_012_345] {
            let formatted = format_amount(val);
            let parsed = parse_amount(&formatted).expect("roundtrip should succeed");
            assert_eq!(val, parsed, "roundtrip failed for {val}");
        }
    }
}
