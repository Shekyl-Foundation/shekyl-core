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
pub(crate) mod mine;
mod proofs;
mod receiving;
pub mod scripted;
mod signing;
mod staking;

pub use staking::FOUNDATION_PHRASE;
mod transfers;

use crate::daemon::DaemonClient;
use crate::rpc_client::RpcSession;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use zeroize::Zeroizing;

struct CliHelper;

impl Completer for CliHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let end = pos.min(line.len());
        let (start, words) = crate::catalog::complete(&line[..end]);
        let pairs = words
            .into_iter()
            .map(|replacement| Pair {
                display: replacement.clone(),
                replacement,
            })
            .collect();
        Ok((start, pairs))
    }
}

impl Hinter for CliHelper {
    type Hint = String;
}

impl Highlighter for CliHelper {}

impl Validator for CliHelper {}

impl Helper for CliHelper {}

pub fn repl(
    rpc: RpcSession,
    daemon_client: Option<&DaemonClient>,
    network: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::grammar::parse;
    use crate::resolve::ResolvedCommand;

    let script = !std::io::IsTerminal::is_terminal(&std::io::stdin());
    let mut rl = if script {
        None
    } else {
        let mut editor = Editor::<CliHelper, DefaultHistory>::new()?;
        let hist = history_path().unwrap_or_default();
        if editor.load_history(&hist).is_err() {
            // No history file yet -- that's fine on first run.
        }
        Some((editor, hist))
    };

    if !script {
        println!("Welcome to shekyl-cli. Type \"help\" for commands.");
    }

    let stdin = std::io::stdin();
    let mut script_lines = stdin.lines();
    let sync_label = std::sync::Arc::new(std::sync::Mutex::new(crate::status::SyncView::NoWallet));
    let term_rows = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stop_status = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if !script && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        let label = std::sync::Arc::clone(&sync_label);
        let rows = std::sync::Arc::clone(&term_rows);
        let stop = std::sync::Arc::clone(&stop_status);
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !stop.load(Ordering::Relaxed) {
                let n = rows.load(Ordering::Relaxed);
                let view = label
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or(crate::status::SyncView::NoWallet);
                let line = crate::status::format_line(
                    env!("CARGO_PKG_VERSION"),
                    &crate::status::local_clock(),
                    &view,
                );
                crate::status::paint(n, &line);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }
    let mut last_sync = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(6))
        .unwrap_or_else(std::time::Instant::now);
    loop {
        let prompt = crate::session::prompt(network, rpc.open_wallet_name().as_deref());
        let raw = if script {
            match script_lines.next() {
                Some(Ok(line)) => line,
                Some(Err(e)) => return Err(e.into()),
                None => break,
            }
        } else {
            let (editor, _) = rl.as_mut().expect("tty editor");
            if last_sync.elapsed() >= std::time::Duration::from_secs(5) {
                let view = if rpc.is_open() {
                    match rpc.call("get_height", serde_json::json!({})) {
                        Ok(val) => {
                            let wallet = val
                                .get("wallet_height")
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(0);
                            let daemon =
                                val.get("daemon_height").and_then(serde_json::Value::as_i64);
                            // A failed height read for the status line is not a
                            // failed command.
                            let _ = rpc.take_failed();
                            crate::status::classify(true, daemon, wallet)
                        }
                        Err(_) => {
                            let _ = rpc.take_failed();
                            crate::status::SyncView::DaemonUnreachable
                        }
                    }
                } else {
                    crate::status::SyncView::NoWallet
                };
                if let Ok(mut slot) = sync_label.lock() {
                    *slot = view;
                }
                last_sync = std::time::Instant::now();
            }
            if let Some((_, rows)) = editor.dimensions() {
                term_rows.store(rows, std::sync::atomic::Ordering::Relaxed);
            }
            match editor.readline(&prompt) {
                Ok(line) => line,
                Err(ReadlineError::Interrupted) => continue,
                Err(ReadlineError::Eof) => break,
                Err(e) => {
                    eprintln!("Input error: {e}");
                    break;
                }
            }
        };
        let line = raw.trim();
        if line.is_empty() || (script && line.starts_with('#')) {
            continue;
        }
        if let Some((editor, hist)) = rl.as_mut() {
            if !crate::catalog::omit_from_history(line) {
                drop(editor.add_history_entry(line));
                drop(editor.save_history(hist));
            }
        }

        match parse(line) {
            ResolvedCommand::Help => print!("{}", crate::catalog::HELP_TREE),
            ResolvedCommand::HelpCommand { topic } => match crate::catalog::help_for(&topic) {
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
            ResolvedCommand::Status => {
                lifecycle::cmd_status(&rpc, daemon_client.and_then(DaemonClient::down_hint));
            }
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
                yes,
            } => {
                transfers::cmd_transfer(&rpc, amount, &dest, priority.as_deref(), yes);
            }
            ResolvedCommand::Transfers {
                incoming,
                outgoing,
                unmatched,
            } => transfers::cmd_transfers(&rpc, incoming, outgoing, unmatched),
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
            ResolvedCommand::Stake => staking::cmd_stake_read(&rpc),
            ResolvedCommand::StakeJoin { shard_ids } => {
                staking::cmd_stake_join(&rpc, &shard_ids);
            }
            ResolvedCommand::StakedBalance => staking::cmd_staked_balance(&rpc),
            ResolvedCommand::StakedOutputs => staking::cmd_staked_outputs(&rpc),
            ResolvedCommand::StakingInfo => staking::cmd_staking_info(&rpc),

            ResolvedCommand::StakeIn { amount, yes } => {
                staking::cmd_stake_in(&rpc, amount, yes);
            }
            ResolvedCommand::DrainBalance => staking::cmd_drain_balance(&rpc),
            ResolvedCommand::Drain { amount, yes } => staking::cmd_drain(&rpc, amount, yes),
            ResolvedCommand::Unstake { yes } => staking::cmd_unstake(&rpc, yes),
            ResolvedCommand::CollectUnstaked { yes } => {
                staking::cmd_collect_unstaked(&rpc, yes);
            }
            ResolvedCommand::ShardListAll => chain::cmd_shard_list_all(daemon_client),
            ResolvedCommand::ShardListMine => chain::cmd_shard_list_mine(&rpc),
            ResolvedCommand::ShardShow { shard_id } => {
                chain::cmd_shard_show(daemon_client, shard_id);
            }
            ResolvedCommand::ShardFetch { shard_id } => {
                chain::cmd_shard_fetch(daemon_client, shard_id);
            }

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
                proofs::cmd_check_tx_proof(&rpc, &txid, &address, &proof, message.as_deref());
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
                rpc.fail();
                eprintln!("Unknown command: {cmd}. Type \"help\" for available commands.");
            }
            ResolvedCommand::Diagnostic { message } => {
                rpc.fail();
                eprintln!("{message}");
            }
        }
        if script && rpc.take_failed() {
            rpc.shutdown();
            std::process::exit(1);
        }
    }

    if let Some((editor, hist)) = rl.as_mut() {
        drop(editor.save_history(hist));
    }
    stop_status.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::status::reset_scroll_region();
    // Closes any open wallet and stops the self-hosted server (removing its
    // private UDS socket directory).
    rpc.shutdown();
    Ok(())
}

/// CLI version, plus the connected wallet-RPC server's version when reachable.
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
        Err(e) => {
            rpc.fail();
            eprintln!("wallet RPC unreachable: {e}");
        }
    }
}

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

/// Confirmation for a money-moving command.
///
/// `--yes` is honored only when stdin is not a terminal. On a terminal the
/// flag is ignored and the prompt still runs. A pipe without `--yes` refuses
/// without reading the next line.
pub(crate) fn confirm_money(prompt: &str, action: &str, yes: bool) -> bool {
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if yes && !tty {
        return true;
    }
    if yes && tty {
        eprintln!("--yes is only honored for non-interactive input; confirming.");
        return confirm(prompt);
    }
    if !tty {
        eprintln!(
            "Refusing to {action} without confirmation on non-interactive \
             input. Re-run with --yes, or run interactively."
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
        eprintln!(
            "No wallet is open. Use \"wallet open <name>\" or \"wallet create <name>\" first."
        );
        rpc.fail();
        return false;
    }
    true
}

pub(crate) fn require_closed(rpc: &RpcSession) -> bool {
    if rpc.is_open() {
        eprintln!("A wallet is already open. Use \"wallet close\" first.");
        rpc.fail();
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

    #[test]
    fn help_for_names_the_identity_sequence() {
        let send = crate::catalog::help_for("send").unwrap();
        assert!(send.contains("send <amount> <address>"), "{send}");
        assert!(crate::catalog::help_for("transfer")
            .unwrap()
            .contains("send"));
        assert!(crate::catalog::help_for("no_such_command").is_none());
        let stake = crate::catalog::complete("stake ");
        assert!(stake.1.iter().any(|w| w == "join"));
        assert!(!stake.1.iter().any(|w| w == "foundation"));
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
