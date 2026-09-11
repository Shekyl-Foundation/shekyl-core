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
mod mine;
mod proofs;
mod receiving;
pub mod scripted;
mod signing;
mod staking;
mod transfers;

use crate::daemon::DaemonClient;
use crate::rpc_client::RpcSession;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use zeroize::Zeroizing;

const HELP_TEXT: &str = "\
Wallet lifecycle:
  create <filename>                   Create a new wallet
  open <filename>                     Open an existing wallet
  close                               Close the current wallet
  restore <filename> <seed...>        Restore wallet from mnemonic seed
  password                            Change wallet password
  refresh                             Sync with the daemon
  rescan                              Rebuild transaction history from the
                                      chain (\"hard\" accepted; same rescan)
  status                              Show wallet and daemon sync heights

Address and balance:
  address                             Show the wallet's primary address
                                      (short display form; not pasteable)
    [--full]                          Print the full address
    [--out <path>]                    Write the full address to a new
                                      private file (never overwrites)
  balance                             Show balance breakdown

Transfers:
  transfer <amount> <address>         Send SKL to an address
    [--priority N]                    0-1 economy, 2 standard, 3+ priority
    [--no-confirm]                    Skip confirmation (non-TTY only)
  transfers                           Show recent transactions
  show_transfer <txid>                Show details for a transaction
  get_tx_note <txid>                  Show the local note for a transaction
  set_tx_note <txid> <note>           Attach a local note to a transaction
                                      (the note is everything after the txid,
                                      taken exactly as typed)
  abandon <txid>                      Give up on a dispatched send (funds stay
                                      locked until the network is confirmed to
                                      have dropped it)
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
    [--complete-tree-foundation]      Foundation nodes only: serve EVERY
                                      frozen shard, forever. Earns NOTHING
                                      — outside the reward market by
                                      design. States the terms and
                                      requires a typed phrase.
  staked_balance                      Show the staked-balance breakdown
  staked_outputs                      List unspent staking-side outputs
  staking_info                        Show staking state and scan height
  stake_in <amount>                   Add funds to the staking balance (an
                                      ordinary transfer from this wallet;
                                      prints a privacy note, then confirms)
  drain_balance                       Show how much staking money can be
                                      moved back to this wallet
  drain <amount>                      Move staking funds back to this wallet
                                      (fee and destination are automatic; no
                                      flags exist)
  unstake                             Post the permanent exit for the staked
                                      bond (irreversible; confirms first)
  collect_unstaked                    Collect the released exit funds back
                                      into this wallet (one pass at a time;
                                      the reply says what remains)
  chain_health                        Show daemon/chain health (separate conn)

Mining (the daemon does the hashing; these control it):
  mine start [threads|auto]           Start mining on the local daemon,
                                      paying to this wallet (default
                                      threads: min(cores, 4); keeps
                                      running after the CLI exits)
  mine stop                           Stop mining on the daemon
  mine status                         Show mining state and hash rate

Proofs (multi-word [message] binds into the proof; the verifier must
supply the identical string — repeated spaces are collapsed to one):
  get_tx_proof <txid> <address> [message]
                                      Prove a payment to <address> (sent
                                      or received; open wallet required)
  check_tx_proof <txid> <address> <proof> [message]
                                      Verify a tx proof (no wallet needed)
  get_reserve_proof [amount] [message]
                                      Prove unspent reserve (FULL wallet;
                                      omit amount to prove full balance; a
                                      numeric first word is read as the
                                      amount — the binding is echoed, with
                                      a disclosure warning, at generation)
  check_reserve_proof <address> <proof> [message]
                                      Verify a reserve proof (no wallet
                                      needed)

Message signing (the message is everything after the command, taken
exactly as typed — the verifier must supply the identical string; a
message that spans multiple lines cannot be entered here, use the
sign_message / verify_message RPC directly):
  sign <message>                      Sign a message as this wallet's address
                                      (takes a few seconds by design)
  verify <address> <signature> <message>
                                      Check a message signature (no wallet
                                      needed; paste the signature as one
                                      unbroken token, or @path to a file)

Receiving history:
  history incoming --unattributed     List receives with no payment-request
                                      match (FA-8 UNATTRIBUTED)

Meta:
  wallet                              Wallet summary (height, balance, address)
  version                             Show CLI and wallet-RPC versions
  help [command]                      Show this help, or one command's usage
  exit / quit                         Exit shekyl-cli";

pub fn repl(
    rpc: RpcSession,
    daemon_client: Option<&DaemonClient>,
    network: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::resolve::{self, ResolvedCommand};

    let mut rl = DefaultEditor::new()?;
    let hist = history_path().unwrap_or_default();

    if rl.load_history(&hist).is_err() {
        // No history file yet -- that's fine on first run.
    }

    println!("Welcome to shekyl-cli. Type \"help\" for commands.");

    loop {
        let prompt = crate::session::prompt(network, rpc.open_wallet_name().as_deref());

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let first_token = line.split_whitespace().next().unwrap_or("");
                if !crate::display::omit_from_history(first_token) {
                    drop(rl.add_history_entry(line));
                }

                match resolve::parse(line) {
                    ResolvedCommand::Help => println!("{HELP_TEXT}"),
                    ResolvedCommand::HelpCommand { topic } => match command_help(&topic) {
                        Some(block) => println!("{block}"),
                        None => {
                            eprintln!("No help for {topic:?}. Type \"help\" for the command list.")
                        }
                    },
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
                    ResolvedCommand::Rescan { hard } => {
                        lifecycle::cmd_rescan(&rpc, hard);
                    }

                    // Balance / address
                    ResolvedCommand::Balance => balance::cmd_balance(&rpc),
                    ResolvedCommand::Address { full, out } => {
                        balance::cmd_address(&rpc, full, out.as_deref());
                    }

                    // Transfers
                    ResolvedCommand::Transfer {
                        dest,
                        amount,
                        priority,
                        no_confirm,
                    } => {
                        transfers::cmd_transfer(&rpc, amount, &dest, priority, no_confirm);
                    }
                    ResolvedCommand::Transfers => transfers::cmd_transfers(&rpc),
                    ResolvedCommand::ShowTransfer { txid } => {
                        transfers::cmd_show_transfer(&rpc, &txid);
                    }
                    ResolvedCommand::GetTxNote { txid } => {
                        transfers::cmd_get_tx_note(&rpc, &txid);
                    }
                    ResolvedCommand::SetTxNote { txid, note } => {
                        transfers::cmd_set_tx_note(&rpc, &txid, &note);
                    }
                    ResolvedCommand::Abandon { txid } => {
                        transfers::cmd_abandon(&rpc, &txid);
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
                        transfers::cmd_history_incoming_unattributed(&rpc);
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
                    ResolvedCommand::Stake { foundation } => {
                        staking::cmd_stake(&rpc, foundation);
                    }
                    ResolvedCommand::StakedBalance => staking::cmd_staked_balance(&rpc),
                    ResolvedCommand::StakedOutputs => staking::cmd_staked_outputs(&rpc),
                    ResolvedCommand::StakingInfo => staking::cmd_staking_info(&rpc),

                    // Archival principal staking actions (WI-RPC-5)
                    ResolvedCommand::StakeIn { amount } => staking::cmd_stake_in(&rpc, amount),
                    ResolvedCommand::DrainBalance => staking::cmd_drain_balance(&rpc),
                    ResolvedCommand::Drain { amount } => staking::cmd_drain(&rpc, amount),
                    ResolvedCommand::Unstake => staking::cmd_unstake(&rpc),
                    ResolvedCommand::CollectUnstaked => staking::cmd_collect_unstaked(&rpc),

                    // Fees (WI-RPC-1 surface)
                    ResolvedCommand::Fee {
                        n_inputs,
                        n_outputs,
                    } => fees::cmd_fee(&rpc, n_inputs, n_outputs),

                    ResolvedCommand::ChainHealth => {
                        chain::cmd_chain_health(daemon_client);
                    }

                    // Mining control (CU-3; the daemon does the hashing)
                    ResolvedCommand::MineStart { threads } => {
                        mine::cmd_mine_start(&rpc, daemon_client, network, threads);
                    }
                    ResolvedCommand::MineStop => {
                        mine::cmd_mine_stop(&rpc, daemon_client, network);
                    }
                    ResolvedCommand::MineStatus => {
                        mine::cmd_mine_status(&rpc, daemon_client, network);
                    }

                    // Proofs (WI-RPC-3 surface)
                    ResolvedCommand::GetTxProof {
                        txid,
                        address,
                        message,
                    } => {
                        proofs::cmd_get_tx_proof(&rpc, &txid, &address, message.as_deref());
                    }
                    ResolvedCommand::CheckTxProof {
                        txid,
                        address,
                        proof,
                        message,
                    } => {
                        proofs::cmd_check_tx_proof(
                            &rpc,
                            &txid,
                            &address,
                            &proof,
                            message.as_deref(),
                        );
                    }
                    ResolvedCommand::GetReserveProof { amount, message } => {
                        proofs::cmd_get_reserve_proof(&rpc, amount, message.as_deref());
                    }
                    ResolvedCommand::CheckReserveProof {
                        address,
                        proof,
                        message,
                    } => {
                        proofs::cmd_check_reserve_proof(&rpc, &address, &proof, message.as_deref());
                    }

                    // Message signing (PR-SM-2 surface)
                    ResolvedCommand::Sign { message } => signing::cmd_sign(&rpc, &message),
                    ResolvedCommand::Verify {
                        address,
                        signature,
                        message,
                    } => {
                        signing::cmd_verify(&rpc, &address, &signature, &message);
                    }

                    // Meta
                    ResolvedCommand::Version => cmd_version(&rpc),
                    ResolvedCommand::Wallet => {
                        balance::cmd_wallet(&rpc);
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

    drop(rl.save_history(&hist));
    // Closes any open wallet and stops the self-hosted server (removing its
    // private UDS socket directory).
    rpc.shutdown();
    Ok(())
}

/// The one-command usage block for `help <command>` (CU-2): the lines of
/// [`HELP_TEXT`] whose command column names `topic`, plus their continuation
/// lines. **Derived from `HELP_TEXT` rather than kept as a second table**, so
/// the listing and the one-pagers can never disagree — a new command's help
/// line is automatically its `help <command>` answer.
///
/// The extraction leans on `HELP_TEXT`'s fixed shape: command lines are
/// indented exactly two spaces, continuation lines deeper, and section
/// headers/blank lines start at column zero.
fn command_help(topic: &str) -> Option<String> {
    // Hidden aliases answer with their public block.
    let canonical = match topic {
        "engine_info" => "wallet",
        "quit" => "exit",
        "start_mining" | "stop_mining" | "mining_status" => "mine",
        t => t,
    };
    let mut out: Vec<&str> = Vec::new();
    let mut capturing = false;
    for line in HELP_TEXT.lines() {
        let indent = line.len() - line.trim_start().len();
        if indent == 2 {
            let first = line.split_whitespace().next().unwrap_or("");
            capturing = first == canonical;
        } else if indent == 0 {
            capturing = false;
        }
        if capturing {
            out.push(line);
        }
    }
    (!out.is_empty()).then(|| out.join("\n"))
}

/// `version`: CLI version, plus the connected wallet-RPC server's version
/// when reachable.
fn cmd_version(rpc: &RpcSession) {
    println!("shekyl-cli {}", env!("CARGO_PKG_VERSION"));
    match rpc.call("get_version", serde_json::json!({})) {
        Ok(val) => {
            let server = val.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            let api = val
                .get("api_version")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
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
    drop(std::io::Write::flush(&mut std::io::stderr()));
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == "yes"
}

/// Confirmation for money-moving commands that ship no `--no-confirm`
/// affordance (`stake_in`, `drain`): interactive "yes", and a loud refusal
/// on non-interactive input. Reading [`confirm`] from a pipe would silently
/// consume the next scripted line (or hit EOF) as the answer — automation
/// would see funds "sent" that never moved, with no clear reason.
/// `action` names the command in the refusal so a script's log says which
/// step was blocked.
pub(crate) fn confirm_interactive(prompt: &str, action: &str) -> bool {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        eprintln!(
            "Refusing to {action} without confirmation on non-interactive \
             input; run interactively."
        );
        return false;
    }
    confirm(prompt)
}

// ---------------------------------------------------------------------------
// Shared helpers used by submodule command handlers
// ---------------------------------------------------------------------------

fn history_path() -> Option<String> {
    dirs::data_local_dir().map(|mut p| {
        p.push("shekyl-cli");
        drop(std::fs::create_dir_all(&p));
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

/// Prompt for a password, returning it in a wrapper that wipes on drop.
///
/// **`Zeroizing` rather than `String`, so the wipe is structural** (rule 35).
/// The previous signature handed back a bare `String` and left every call
/// site to remember `password.zeroize()` before each return path — a
/// discipline that held only as long as nobody added an early `return`, and
/// which said nothing about the copies the value was handed to.
pub(crate) fn read_password(prompt: &str) -> Option<Zeroizing<String>> {
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
        .map(shekyl_units::AtomicUnits::to_raw)
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

    /// `help <command>` extracts that command's block from HELP_TEXT —
    /// including multi-line continuations and flag lines — answers hidden
    /// aliases with the public block, and is honest about unknown topics.
    #[test]
    fn command_help_extracts_one_command_block() {
        let transfer = command_help("transfer").expect("transfer is documented");
        assert!(
            transfer.contains("transfer <amount> <address>"),
            "{transfer}"
        );
        assert!(transfer.contains("--priority"), "{transfer}");
        assert!(
            !transfer.contains("transfers "),
            "the sibling command's block must not bleed in: {transfer}"
        );
        // A two-word grammar answers under its first token.
        let request = command_help("request").expect("request is documented");
        assert!(request.contains("request new"), "{request}");
        // Hidden alias → public block.
        let wallet = command_help("engine_info").expect("alias answers");
        assert!(wallet.contains("wallet"), "{wallet}");
        // Mining aliases (CU-3) all answer with the `mine` block.
        for alias in ["start_mining", "stop_mining", "mining_status", "mine"] {
            let mine = command_help(alias).expect("mining alias answers");
            assert!(mine.contains("mine start"), "{alias}: {mine}");
            assert!(mine.contains("mine stop"), "{alias}: {mine}");
        }
        assert!(command_help("no_such_command").is_none());
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
