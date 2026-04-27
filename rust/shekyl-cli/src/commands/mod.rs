// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL command loop, dispatch, and shared helpers for shekyl-cli.

mod balance;
mod keys;
mod lifecycle;
mod offline;
mod proofs;
mod sign;
mod staking;
mod transfers;

use crate::daemon::DaemonClient;
use crate::engine::EngineContext;
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
  address [--subaddr-index N]         Show address
  address new [label]                 Create a new subaddress
  balance [--account N]               Show balance (unlocked, locked)

Transfers:
  transfer <amount> <address>         Send SKL to an address
    [--account N] [--priority N]      (optional flags)
    [--subaddr-indices N,M,...]       Source subaddresses
    [--do-not-relay]                  Create but don't broadcast (offline use)
    [--no-confirm]                    Skip confirmation (non-TTY only)
  transfers [--account N]             Show recent transactions
  show_transfer <txid>                Show details for a transaction
  sweep_all <address>                 Sweep all outputs to address
    [--account N] [--priority N]      (explicit --account required)
    [--subaddr-indices N,M,...]       Source subaddresses

Staking:
  stake <amount> [tier]               Stake SKL
  unstake [--account N]               Unstake
  claim [--account N]                 Claim staking rewards
  staking_info [--account N]          Show staking status
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
  --account N                         Override session default account
  --subaddr-index N                   Specific subaddress
  --subaddr-indices N,M,...           Multiple source subaddresses";

pub fn repl(
    ctx: EngineContext,
    _daemon_client: Option<DaemonClient>,
    _debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::resolve::{self, ResolvedCommand};
    use crate::session::ReplSession;

    let mut rl = DefaultEditor::new()?;
    let hist = history_path().unwrap_or_default();

    if rl.load_history(&hist).is_err() {
        // No history file yet -- that's fine on first run.
    }

    println!("Welcome to shekyl-cli. Type \"help\" for commands.");

    let mut session = ReplSession::new();

    loop {
        let prompt = session.prompt(ctx.is_open());

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
                    ResolvedCommand::Exit => {
                        if ctx.is_open() {
                            if let Err(e) = ctx.close() {
                                eprintln!("Warning: failed to close engine: {e}");
                            }
                        }
                        break;
                    }

                    // Lifecycle
                    ResolvedCommand::Create { filename } => {
                        lifecycle::cmd_create(&ctx, &[&filename]);
                    }
                    ResolvedCommand::Open { filename } => {
                        lifecycle::cmd_open(&ctx, &[&filename]);
                    }
                    ResolvedCommand::Close => lifecycle::cmd_close(&ctx),
                    ResolvedCommand::Restore {
                        filename,
                        seed_words,
                    } => {
                        let mut args: Vec<&str> = vec![&filename];
                        args.extend(seed_words.iter().map(|s| s.as_str()));
                        lifecycle::cmd_restore(&ctx, &args);
                    }
                    ResolvedCommand::Refresh => lifecycle::cmd_refresh(&ctx),
                    ResolvedCommand::Save => lifecycle::cmd_save(&ctx),
                    ResolvedCommand::Status => lifecycle::cmd_status(&ctx),

                    // Balance / address
                    ResolvedCommand::Balance { account_index, .. } => {
                        balance::cmd_balance(&ctx, account_index);
                    }
                    ResolvedCommand::Address { account_index, .. } => {
                        balance::cmd_address(&ctx, account_index);
                    }

                    // Account management
                    ResolvedCommand::AccountShow => {
                        if !require_open(&ctx) {
                            continue;
                        }
                        match ctx.json_rpc("get_accounts", "{}") {
                            Ok(val) => {
                                if let Some(accts) =
                                    val.get("subaddress_accounts").and_then(|a| a.as_array())
                                {
                                    for acct in accts {
                                        let idx = acct
                                            .get("account_index")
                                            .and_then(|i| i.as_u64())
                                            .unwrap_or(0);
                                        let balance = acct
                                            .get("balance")
                                            .and_then(|b| b.as_u64())
                                            .unwrap_or(0);
                                        let label = acct
                                            .get("label")
                                            .and_then(|l| l.as_str())
                                            .unwrap_or("");
                                        let marker = if idx as u32 == session.default_account {
                                            " *"
                                        } else {
                                            ""
                                        };
                                        println!(
                                            "  Account {idx}{marker}: {label} ({})",
                                            format_amount(balance)
                                        );
                                    }
                                }
                            }
                            Err(e) => eprintln!("Failed to get accounts: {e}"),
                        }
                    }
                    ResolvedCommand::AccountDefault { index } => {
                        if !require_open(&ctx) {
                            continue;
                        }
                        match ctx.json_rpc("get_accounts", "{}") {
                            Ok(val) => {
                                let count = val
                                    .get("subaddress_accounts")
                                    .and_then(|a| a.as_array())
                                    .map(|a| a.len() as u32)
                                    .unwrap_or(0);
                                if index >= count {
                                    eprintln!("Account {index} does not exist. Use 'account show' to list accounts.");
                                } else {
                                    session.default_account = index;
                                    println!("Session default account is now {index}.");
                                    println!("Destructive operations (sweep, stake, unstake, key export) still require --account explicitly.");
                                }
                            }
                            Err(e) => eprintln!("Failed to get accounts: {e}"),
                        }
                    }
                    ResolvedCommand::AccountNew { label } => {
                        if !require_open(&ctx) {
                            continue;
                        }
                        let params = serde_json::json!({ "label": label }).to_string();
                        match ctx.json_rpc("create_account", &params) {
                            Ok(val) => {
                                let idx = val
                                    .get("account_index")
                                    .and_then(|i| i.as_u64())
                                    .unwrap_or(0);
                                let addr =
                                    val.get("address").and_then(|a| a.as_str()).unwrap_or("?");
                                println!("Created account {idx}: {addr}");
                            }
                            Err(e) => eprintln!("Failed to create account: {e}"),
                        }
                    }

                    // Transfers
                    ResolvedCommand::Transfer {
                        account_index,
                        dest,
                        amount,
                        ..
                    } => {
                        let amount_str = format_amount(amount);
                        let dest_ref: &str = &dest;
                        transfers::cmd_transfer(&ctx, &[&amount_str, dest_ref], account_index);
                    }
                    ResolvedCommand::Transfers { account_index } => {
                        transfers::cmd_transfers(&ctx, account_index);
                    }

                    // Keys
                    ResolvedCommand::Seed => keys::cmd_seed(&ctx),

                    // Engine ops
                    ResolvedCommand::Password => lifecycle::cmd_password(&ctx),
                    ResolvedCommand::Rescan { hard } => lifecycle::cmd_rescan(&ctx, hard),
                    ResolvedCommand::ShowTransfer { txid } => {
                        transfers::cmd_show_transfer(&ctx, &txid);
                    }
                    ResolvedCommand::SweepAll {
                        account_index,
                        subaddr_indices,
                        dest,
                        priority,
                    } => {
                        transfers::cmd_sweep_all(
                            &ctx,
                            account_index,
                            &subaddr_indices,
                            &dest,
                            priority,
                        );
                    }

                    // Staking
                    ResolvedCommand::Stake {
                        account_index,
                        tier,
                        amount,
                    } => {
                        staking::cmd_stake(&ctx, account_index, tier, amount);
                    }
                    ResolvedCommand::Unstake { account_index } => {
                        staking::cmd_unstake(&ctx, account_index);
                    }
                    ResolvedCommand::Claim { account_index } => {
                        staking::cmd_claim(&ctx, account_index);
                    }
                    ResolvedCommand::StakingInfo { account_index } => {
                        staking::cmd_staking_info(&ctx, account_index);
                    }
                    ResolvedCommand::ChainHealth => {
                        staking::cmd_chain_health(_daemon_client.as_ref());
                    }

                    // Keys
                    ResolvedCommand::Viewkey => keys::cmd_viewkey(&ctx),
                    ResolvedCommand::Spendkey => keys::cmd_spendkey(&ctx),
                    ResolvedCommand::ExportKeyImages {
                        filename,
                        all,
                        since_height,
                        account_index,
                    } => {
                        keys::cmd_export_key_images(
                            &ctx,
                            &filename,
                            all,
                            since_height,
                            account_index,
                        );
                    }
                    ResolvedCommand::ImportKeyImages { filename } => {
                        keys::cmd_import_key_images(&ctx, &filename);
                    }

                    // Proofs
                    ResolvedCommand::GetTxKey { txid } => {
                        proofs::cmd_get_tx_key(&ctx, &txid);
                    }
                    ResolvedCommand::CheckTxKey {
                        txid,
                        tx_key,
                        address,
                    } => {
                        proofs::cmd_check_tx_key(&ctx, &txid, &tx_key, &address);
                    }
                    ResolvedCommand::GetTxProof {
                        txid,
                        address,
                        message,
                    } => {
                        proofs::cmd_get_tx_proof(&ctx, &txid, &address, message.as_deref());
                    }
                    ResolvedCommand::CheckTxProof {
                        txid,
                        address,
                        signature,
                        message,
                    } => {
                        proofs::cmd_check_tx_proof(
                            &ctx,
                            &txid,
                            &address,
                            &signature,
                            message.as_deref(),
                        );
                    }
                    ResolvedCommand::GetReserveProof {
                        account_index,
                        amount,
                        message,
                    } => {
                        proofs::cmd_get_reserve_proof(
                            &ctx,
                            account_index,
                            amount,
                            message.as_deref(),
                        );
                    }
                    ResolvedCommand::CheckReserveProof {
                        address,
                        signature,
                        message,
                    } => {
                        proofs::cmd_check_reserve_proof(
                            &ctx,
                            &address,
                            &signature,
                            message.as_deref(),
                        );
                    }

                    // Signing
                    ResolvedCommand::Sign { message } => sign::cmd_sign(&ctx, &message),
                    ResolvedCommand::Verify {
                        address,
                        message,
                        signature,
                    } => {
                        sign::cmd_verify(&ctx, &address, &message, &signature);
                    }

                    // Offline signing
                    ResolvedCommand::DescribeTransfer { unsigned_hex } => {
                        offline::cmd_describe_transfer(&ctx, &unsigned_hex);
                    }
                    ResolvedCommand::SignTransfer { unsigned_hex, file } => {
                        offline::cmd_sign_transfer(&ctx, &unsigned_hex, file.as_deref());
                    }
                    ResolvedCommand::SubmitTransfer { signed_hex } => {
                        offline::cmd_submit_transfer(&ctx, &signed_hex);
                    }

                    // Meta
                    ResolvedCommand::Version => sign::cmd_version(),
                    ResolvedCommand::EngineInfo => sign::cmd_engine_info(&ctx),

                    ResolvedCommand::Unknown { cmd } => {
                        eprintln!("Unknown command: {cmd}. Type \"help\" for available commands.");
                    }
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                if ctx.is_open() {
                    if let Err(e) = ctx.close() {
                        eprintln!("Warning: failed to close engine: {e}");
                    }
                }
                break;
            }
            Err(e) => {
                eprintln!("Input error: {e}");
                break;
            }
        }
    }

    let _ = rl.save_history(&hist);
    Ok(())
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

/// Dangerous-operation confirmation: user must type a context-specific token.
///
/// The token should encode operation-specific information that forces the user
/// to verify what they're doing (e.g. the total amount, truncated address, or
/// an acknowledgment phrase).
pub(crate) fn confirm_dangerous(prompt: &str, expected_token: &str) -> bool {
    eprint!("{prompt}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == expected_token
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

pub(crate) fn require_open(ctx: &EngineContext) -> bool {
    if !ctx.is_open() {
        eprintln!("No engine is open. Use \"open <filename>\" or \"create <filename>\" first.");
        return false;
    }
    true
}

pub(crate) fn require_closed(ctx: &EngineContext) -> bool {
    if ctx.is_open() {
        eprintln!("An engine is already open. Use \"close\" first.");
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
// Amount formatting and parsing (12-digit piconero precision)
// ---------------------------------------------------------------------------

pub fn format_amount(atomic: u64) -> String {
    let whole = atomic / 1_000_000_000_000;
    let frac = atomic % 1_000_000_000_000;
    if frac == 0 {
        format!("{whole}.000000000000")
    } else {
        format!("{whole}.{frac:012}")
    }
}

pub fn parse_amount(s: &str) -> Option<u64> {
    if let Some(dot_pos) = s.find('.') {
        let whole: u64 = s[..dot_pos].parse().ok()?;
        let frac_str = &s[dot_pos + 1..];
        if frac_str.len() > 12 {
            return None;
        }
        let padded = format!("{frac_str:0<12}");
        let frac: u64 = padded.parse().ok()?;
        whole.checked_mul(1_000_000_000_000)?.checked_add(frac)
    } else {
        let whole: u64 = s.parse().ok()?;
        whole.checked_mul(1_000_000_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(0), "0.000000000000");
        assert_eq!(format_amount(1_000_000_000_000), "1.000000000000");
        assert_eq!(format_amount(1_500_000_000_000), "1.500000000000");
        assert_eq!(format_amount(123_456_789), "0.000123456789");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1"), Some(1_000_000_000_000));
        assert_eq!(parse_amount("1.5"), Some(1_500_000_000_000));
        assert_eq!(parse_amount("0.000000000001"), Some(1));
        assert_eq!(parse_amount("1.0"), Some(1_000_000_000_000));
        assert_eq!(parse_amount("abc"), None);
        assert_eq!(parse_amount("1.0000000000001"), None); // >12 decimal places
    }

    #[test]
    fn test_parse_format_roundtrip() {
        for val in [
            0,
            1,
            999_999_999_999,
            1_000_000_000_000,
            123_456_789_012_345,
        ] {
            let formatted = format_amount(val);
            let parsed = parse_amount(&formatted).expect("roundtrip should succeed");
            assert_eq!(val, parsed, "roundtrip failed for {val}");
        }
    }
}
