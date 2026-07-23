// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL command loop, dispatch, and shared helpers for shekyl-cli.
//!
//! Every command executes through the [`crate::rpc_client::RpcSession`]
//! JSON-RPC surface (WI-RPC-2a). Commands whose native RPC method has not
//! landed yet answer with a uniform "not available" stub; they are either
//! migrated or deleted in WI-RPC-2b.

mod balance;
mod chain;
mod lifecycle;
mod transfers;

use crate::daemon::DaemonClient;
use crate::rpc_client::RpcSession;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

const HELP_TEXT: &str = "\
Engine lifecycle:
  create <filename>                   Create a new engine
  open <filename>                     Open an existing engine
  close                               Close the current engine
  restore <filename> <seed...>        Restore engine from mnemonic seed
  password                            Change engine password
  rescan [hard]                       Rescan blockchain (hard = lose metadata)
  refresh                             Sync with the daemon
  save                                Save engine to disk
  status                              Show sync height and engine state
  engine_info                         Show engine info (no filename)

Accounts and addresses:
  account show                        List accounts (default marked with *)
  account default <N>                 Set session default account
  account new [label]                 Create a new account
  address                             Show primary address
  address new [label]                 Alias for account new
  balance [--account N]               Show balance (unlocked, locked)

Transfers:
  transfer <amount> <address>         Send SKL to an address
    [--account N] [--priority N]      (optional flags)
    [--do-not-relay]                  Create but don't broadcast (offline use)
    [--no-confirm]                    Skip confirmation (non-TTY only)
  transfers [--account N]             Show recent transactions
  show_transfer <txid>                Show details for a transaction
  sweep_all <address>                 Sweep all outputs to address
    [--account N] [--priority N]      (explicit --account required)

Payment requests (FA-8, feature-flagged cooperative path):
  request new <amount> <label>        Create off-chain payment request (stub)
  requests list                       List payment requests (stub)
  history incoming --unattributed     Show unattributed receives (stub)

Staking:
  chain_health                        Show daemon/chain health (separate conn)

Keys (secret-displaying commands excluded from history):
  seed                                Display mnemonic seed
  viewkey                             Display view key
  spendkey                            Display spend key
  export_key_images [file]            Export key images to file
    [--all] [--since-height N]        Scope control
  import_key_images <file>            Import key images from file

Proofs:
  get_tx_key <txid>                   Get transaction secret key
  check_tx_key <txid> <key> <addr>    Verify a transaction key
  get_tx_proof <txid> <addr> [msg]    Generate a tx proof
  check_tx_proof <txid> <addr> <sig>  Verify a tx proof
  get_reserve_proof [amount] [msg]    Generate a reserve proof
  check_reserve_proof <addr> <sig>    Verify a reserve proof

Signing:
  sign <message>                      Sign a message with spend key
  verify <addr> <msg> <sig>           Verify a signed message
  NOTE: Signatures use Shekyl-specific domain separation
        (ShekylMessageSignature) and are NOT compatible with Monero.

Offline signing (cold-engine workflow):
  describe_transfer <unsigned_hex>    Inspect an unsigned transaction
  sign_transfer <hex> [--file path]   Sign an unsigned transaction (full engine)
  submit_transfer <signed_hex>        Broadcast a signed transaction

Meta:
  version                             Show shekyl-cli version
  help                                Show this help
  exit / quit                         Exit shekyl-cli

Global flags (use with any command):
  --account N                         Override session default account";

/// Uniform WI-RPC-2a stub for commands whose native RPC surface has not
/// landed. Each is either migrated or deleted (with help-text rewrite) in
/// WI-RPC-2b.
fn stub(cmd: &str) {
    eprintln!(
        "{cmd}: not available yet — this command has no native wallet-RPC \
         surface (WI-RPC-2a transitional stub)."
    );
}

/// Warn when a wallet2-era `--account N` selector is used: Shekyl has no
/// account/subaddress model (rule 60; WI-RPC-1 pin 1).
fn warn_account_flag(account_index: u32) {
    if account_index != 0 {
        eprintln!(
            "Note: accounts were removed; --account {account_index} is ignored \
             (the wallet has a single primary address)."
        );
    }
}

pub fn repl(
    rpc: RpcSession,
    daemon_client: Option<DaemonClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::resolve::{self, ResolvedCommand};
    use crate::session::ReplSession;

    let mut rl = DefaultEditor::new()?;
    let hist = history_path().unwrap_or_default();

    if rl.load_history(&hist).is_err() {
        // No history file yet -- that's fine on first run.
    }

    println!("Welcome to shekyl-cli. Type \"help\" for commands.");

    let session = ReplSession::new();

    loop {
        let prompt = session.prompt(rpc.is_open());

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

                let resolved = resolve::parse(line, &session);

                match resolved {
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
                    ResolvedCommand::Save => stub("save"),
                    ResolvedCommand::Status => lifecycle::cmd_status(&rpc),
                    ResolvedCommand::Password => lifecycle::cmd_password(&rpc),
                    ResolvedCommand::Rescan { .. } => stub("rescan"),

                    // Balance / address
                    ResolvedCommand::Balance { account_index } => {
                        warn_account_flag(account_index);
                        balance::cmd_balance(&rpc);
                    }
                    ResolvedCommand::Address { account_index } => {
                        warn_account_flag(account_index);
                        balance::cmd_address(&rpc);
                    }

                    // Account management (no account model in Shekyl)
                    ResolvedCommand::AccountShow
                    | ResolvedCommand::AccountDefault { .. }
                    | ResolvedCommand::AccountNew { .. } => stub("account"),

                    // Transfers
                    ResolvedCommand::Transfer {
                        account_index,
                        dest,
                        amount,
                        priority,
                        do_not_relay,
                        no_confirm,
                    } => {
                        warn_account_flag(account_index);
                        if do_not_relay {
                            stub("transfer --do-not-relay");
                        } else {
                            transfers::cmd_transfer(&rpc, amount, &dest, priority, no_confirm);
                        }
                    }
                    ResolvedCommand::Transfers { account_index } => {
                        warn_account_flag(account_index);
                        transfers::cmd_transfers(&rpc);
                    }
                    ResolvedCommand::ShowTransfer { txid } => {
                        transfers::cmd_show_transfer(&rpc, &txid);
                    }
                    ResolvedCommand::SweepAll { .. } => stub("sweep_all"),

                    // Payment requests (un-stubbed over WI-RPC-1 in 2b)
                    ResolvedCommand::RequestNew { .. } => stub("request new"),
                    ResolvedCommand::RequestsList => stub("requests list"),
                    ResolvedCommand::HistoryIncomingUnattributed { .. } => {
                        stub("history incoming");
                    }

                    ResolvedCommand::ChainHealth => {
                        chain::cmd_chain_health(daemon_client.as_ref());
                    }

                    // Keys (secret egress is deliberately absent from the RPC)
                    ResolvedCommand::Seed => stub("seed"),
                    ResolvedCommand::Viewkey => stub("viewkey"),
                    ResolvedCommand::Spendkey => stub("spendkey"),
                    ResolvedCommand::ExportKeyImages { .. } => stub("export_key_images"),
                    ResolvedCommand::ImportKeyImages { .. } => stub("import_key_images"),

                    // Proofs
                    ResolvedCommand::GetTxKey { .. } => stub("get_tx_key"),
                    ResolvedCommand::CheckTxKey { .. } => stub("check_tx_key"),
                    ResolvedCommand::GetTxProof { .. } => stub("get_tx_proof"),
                    ResolvedCommand::CheckTxProof { .. } => stub("check_tx_proof"),
                    ResolvedCommand::GetReserveProof { .. } => stub("get_reserve_proof"),
                    ResolvedCommand::CheckReserveProof { .. } => stub("check_reserve_proof"),

                    // Signing
                    ResolvedCommand::Sign { .. } => stub("sign"),
                    ResolvedCommand::Verify { .. } => stub("verify"),

                    // Offline signing
                    ResolvedCommand::DescribeTransfer { .. } => stub("describe_transfer"),
                    ResolvedCommand::SignTransfer { .. } => stub("sign_transfer"),
                    ResolvedCommand::SubmitTransfer { .. } => stub("submit_transfer"),

                    // Meta
                    ResolvedCommand::Version => cmd_version(&rpc),
                    ResolvedCommand::EngineInfo => stub("engine_info"),

                    ResolvedCommand::Unknown { cmd } => {
                        eprintln!("Unknown command: {cmd}. Type \"help\" for available commands.");
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
