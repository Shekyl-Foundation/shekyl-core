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

pub use staking::{accept_foundation_terms, post_foundation_stake, FOUNDATION_PHRASE};
mod transfers;

use crate::daemon::DaemonClient;
use crate::outcome::{failed, present, CommandResult};
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
    repl_lines(rpc, daemon_client, network, None, false, None)
}

/// Run one already-parsed command line and stop. Used by one-shot argv.
pub fn run_one(
    rpc: RpcSession,
    daemon_client: Option<&DaemonClient>,
    network: &str,
    line: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    repl_lines(
        rpc,
        daemon_client,
        network,
        Some(line.to_owned()),
        true,
        None,
    )
}

/// Run every line of a script file against one wallet session.
pub fn run_file(
    rpc: RpcSession,
    daemon_client: Option<&DaemonClient>,
    network: &str,
    lines: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    repl_lines(rpc, daemon_client, network, None, false, Some(lines))
}

/// `script_file` replaces stdin. `oneshot` runs a single line and stops.
fn repl_lines(
    rpc: RpcSession,
    daemon_client: Option<&DaemonClient>,
    network: &str,
    mut oneshot_line: Option<String>,
    oneshot: bool,
    file_lines: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::grammar::parse;
    use crate::resolve::ResolvedCommand;

    let mut file_lines = file_lines.map(Vec::into_iter);
    let script = oneshot
        || file_lines.is_some()
        || crate::outcome::noninteractive()
        || !std::io::IsTerminal::is_terminal(&std::io::stdin());
    let mut rl = if script {
        None
    } else {
        let mut editor = Editor::<CliHelper, DefaultHistory>::new()?;
        editor.set_helper(Some(CliHelper));
        let hist = history_path().unwrap_or_default();
        if editor.load_history(&hist).is_err() {
            // No history file yet -- that's fine on first run.
        }
        Some((editor, hist))
    };

    if !script && !crate::outcome::json_mode() {
        println!("Welcome to shekyl-cli. Type \"help\" for commands.");
    }

    let stdin = std::io::stdin();
    let mut script_lines = stdin.lines();
    loop {
        let prompt = crate::session::prompt(network, rpc.open_wallet_name().as_deref());
        let raw = if oneshot {
            match oneshot_line.take() {
                Some(line) => line,
                None => break,
            }
        } else if let Some(lines) = file_lines.as_mut() {
            match lines.next() {
                Some(line) => line,
                None => break,
            }
        } else if script {
            match script_lines.next() {
                Some(Ok(line)) => line,
                Some(Err(e)) => return Err(e.into()),
                None => break,
            }
        } else {
            let (editor, _) = rl.as_mut().expect("tty editor");
            if !crate::outcome::json_mode() {
                let view = sync_view(&rpc);
                crate::status::print_above_prompt(&crate::status::format_line(
                    env!("CARGO_PKG_VERSION"),
                    &crate::status::local_clock(),
                    &view,
                ));
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

        let ok = match parse(line) {
            ResolvedCommand::Help => {
                let text = crate::catalog::help_listing();
                present("help", Ok(serde_json::json!({ "text": text })), |val| {
                    print!("{}", val.get("text").and_then(|v| v.as_str()).unwrap_or(""));
                })
            }
            ResolvedCommand::HelpCommand { topic } => match crate::catalog::help_for(&topic) {
                Some(block) => present("help", Ok(serde_json::json!({ "text": block })), |val| {
                    println!("{}", val.get("text").and_then(|v| v.as_str()).unwrap_or(""));
                }),
                None => present(
                    "help",
                    failed(format!(
                        "No help for {topic:?}. Type \"help\" for the command list."
                    )),
                    |_| {},
                ),
            },
            ResolvedCommand::Exit => break,

            ResolvedCommand::Create { filename } => present(
                "wallet create",
                lifecycle::cmd_create(&rpc, &filename),
                lifecycle::show_created,
            ),
            ResolvedCommand::Open { filename } => present(
                "wallet open",
                lifecycle::cmd_open(&rpc, &filename),
                lifecycle::show_opened,
            ),
            ResolvedCommand::Close => present(
                "wallet close",
                lifecycle::cmd_close(&rpc),
                lifecycle::show_closed,
            ),
            ResolvedCommand::Restore {
                filename,
                seed_words,
            } => present(
                "wallet restore",
                lifecycle::cmd_restore(&rpc, &filename, &seed_words),
                lifecycle::show_restored,
            ),
            ResolvedCommand::Refresh => present(
                "wallet refresh",
                lifecycle::cmd_refresh(&rpc),
                lifecycle::show_refresh,
            ),
            ResolvedCommand::Status => present(
                "status",
                lifecycle::cmd_status(&rpc, daemon_client.and_then(DaemonClient::down_hint)),
                lifecycle::show_status,
            ),
            ResolvedCommand::Password => present(
                "wallet password",
                lifecycle::cmd_password(&rpc),
                lifecycle::show_password,
            ),
            ResolvedCommand::Rescan { hard } => present(
                "wallet rescan",
                lifecycle::cmd_rescan(&rpc, hard),
                lifecycle::show_rescan,
            ),

            ResolvedCommand::Balance => {
                present("balance", balance::cmd_balance(&rpc), balance::show_balance)
            }
            ResolvedCommand::Address { full, out } => present(
                "address",
                balance::cmd_address(&rpc, full, out.as_deref()),
                balance::show_address,
            ),

            ResolvedCommand::Transfer {
                dest,
                amount,
                priority,
                yes,
            } => present(
                "send",
                transfers::cmd_transfer(&rpc, amount, &dest, priority, yes),
                transfers::show_submit,
            ),
            ResolvedCommand::Transfers {
                incoming,
                outgoing,
                unmatched,
            } => present(
                "tx list",
                transfers::cmd_transfers(&rpc, incoming, outgoing, unmatched),
                transfers::show_transfers,
            ),
            ResolvedCommand::ShowTransfer { txid } => present(
                "tx show",
                transfers::cmd_show_transfer(&rpc, &txid),
                transfers::show_transfer,
            ),
            ResolvedCommand::GetTxNote { txid } => present(
                "tx note",
                transfers::cmd_get_tx_note(&rpc, &txid),
                transfers::show_note,
            ),
            ResolvedCommand::SetTxNote { txid, note } => present(
                "tx note",
                transfers::cmd_set_tx_note(&rpc, &txid, &note),
                transfers::show_note_stored,
            ),
            ResolvedCommand::Abandon { txid } => present(
                "tx abandon",
                transfers::cmd_abandon(&rpc, &txid),
                transfers::show_abandoned,
            ),

            ResolvedCommand::RequestNew {
                amount,
                label,
                expiry,
            } => present(
                "request new",
                receiving::cmd_request_new(&rpc, amount, &label, expiry),
                receiving::show_request_new,
            ),
            ResolvedCommand::RequestsList { filter } => present(
                "request list",
                receiving::cmd_requests_list(&rpc, filter),
                receiving::show_requests,
            ),
            ResolvedCommand::MakeUri {
                address,
                amount,
                label,
            } => present(
                "uri make",
                receiving::cmd_make_uri(&rpc, address.as_deref(), amount, label.as_deref()),
                receiving::show_uri,
            ),
            ResolvedCommand::ParseUri { uri } => present(
                "uri read",
                receiving::cmd_parse_uri(&rpc, &uri),
                receiving::show_parsed_uri,
            ),

            ResolvedCommand::Stake => {
                present("stake", staking::cmd_stake_read(&rpc), staking::show_stake)
            }
            ResolvedCommand::StakeJoin { shard_ids } => present(
                "stake join",
                staking::cmd_stake_join(&rpc, &shard_ids),
                |_| {},
            ),
            ResolvedCommand::StakedBalance => present(
                "stake balance",
                staking::cmd_staked_balance(&rpc),
                staking::show_staked_balance,
            ),
            ResolvedCommand::StakedOutputs => present(
                "stake outputs",
                staking::cmd_staked_outputs(&rpc),
                staking::show_staked_outputs,
            ),
            ResolvedCommand::StakeIn { amount, yes } => present(
                "stake add",
                staking::cmd_stake_in(&rpc, amount, yes),
                transfers::show_submit,
            ),
            ResolvedCommand::DrainBalance => present(
                "stake available",
                staking::cmd_drain_balance(&rpc),
                staking::show_drain_balance,
            ),
            ResolvedCommand::Drain { amount, yes } => present(
                "stake return",
                staking::cmd_drain(&rpc, amount, yes),
                staking::show_drain,
            ),
            ResolvedCommand::Unstake { yes } => present(
                "release",
                staking::cmd_unstake(&rpc, yes),
                staking::show_release,
            ),
            ResolvedCommand::CollectUnstaked { yes } => present(
                "stake collect",
                staking::cmd_collect_unstaked(&rpc, yes),
                staking::show_collect,
            ),
            ResolvedCommand::ShardListAll => present(
                "shard list all",
                chain::cmd_shard_list_all(daemon_client),
                chain::show_coverage,
            ),
            ResolvedCommand::ShardListMine => {
                present("shard list mine", chain::cmd_shard_list_mine(&rpc), |_| {})
            }
            ResolvedCommand::ShardShow { shard_id } => present(
                "shard show",
                chain::cmd_shard_show(daemon_client, shard_id),
                chain::show_shard,
            ),
            ResolvedCommand::ShardFetch { shard_id } => present(
                "shard fetch",
                chain::cmd_shard_fetch(daemon_client, shard_id),
                chain::show_fetch,
            ),

            ResolvedCommand::Fee {
                n_inputs,
                n_outputs,
            } => present(
                "fee",
                fees::cmd_fee(&rpc, n_inputs, n_outputs),
                fees::show_fee,
            ),
            ResolvedCommand::ChainHealth => present(
                "chain",
                chain::cmd_chain_health(daemon_client),
                chain::show_chain,
            ),

            ResolvedCommand::MineStart { threads } => present(
                "mine start",
                mine::cmd_mine_start(&rpc, daemon_client, network, threads),
                mine::show_mine_start,
            ),
            ResolvedCommand::MineStop => present(
                "mine stop",
                mine::cmd_mine_stop(&rpc, daemon_client, network),
                mine::show_mine_stop,
            ),
            ResolvedCommand::MineStatus => present(
                "mine status",
                mine::cmd_mine_status(&rpc, daemon_client, network),
                mine::show_mine_status,
            ),

            ResolvedCommand::GetTxProof {
                txid,
                address,
                message,
            } => present(
                "prove payment",
                proofs::cmd_get_tx_proof(&rpc, &txid, &address, message.as_deref()),
                proofs::show_tx_proof,
            ),
            ResolvedCommand::CheckTxProof {
                txid,
                address,
                proof,
                message,
            } => present(
                "check payment",
                proofs::cmd_check_tx_proof(&rpc, &txid, &address, &proof, message.as_deref()),
                proofs::show_tx_check,
            ),
            ResolvedCommand::GetReserveProof { amount, message } => present(
                "prove reserve",
                proofs::cmd_get_reserve_proof(&rpc, amount, message.as_deref()),
                proofs::show_reserve_proof,
            ),
            ResolvedCommand::CheckReserveProof {
                address,
                proof,
                message,
            } => present(
                "check reserve",
                proofs::cmd_check_reserve_proof(&rpc, &address, &proof, message.as_deref()),
                proofs::show_reserve_check,
            ),

            ResolvedCommand::Sign { message } => present(
                "sign",
                signing::cmd_sign(&rpc, &message),
                signing::show_signature,
            ),
            ResolvedCommand::Verify {
                address,
                signature,
                message,
            } => present(
                "verify",
                signing::cmd_verify(&rpc, &address, &signature, &message),
                signing::show_verify,
            ),

            ResolvedCommand::Version => present("version", cmd_version(&rpc), show_version),
            ResolvedCommand::Wallet => {
                present("wallet", balance::cmd_wallet(&rpc), balance::show_wallet)
            }

            ResolvedCommand::Unknown { cmd } => present(
                "unknown",
                failed(format!(
                    "Unknown command: {cmd}. Type \"help\" for available commands."
                )),
                |_| {},
            ),
            ResolvedCommand::Diagnostic { message } => present("refused", failed(message), |_| {}),
        };
        if !ok && script {
            rpc.shutdown();
            std::process::exit(1);
        }
        if oneshot {
            break;
        }
    }

    if let Some((editor, hist)) = rl.as_mut() {
        drop(editor.save_history(hist));
    }
    // Closes any open wallet and stops the self-hosted server (removing its
    // private UDS socket directory).
    rpc.shutdown();
    Ok(())
}

/// Wallet sync for the line above the prompt. A failed read is not a failed command.
fn sync_view(rpc: &RpcSession) -> crate::status::SyncView {
    if !rpc.is_open() {
        return crate::status::SyncView::NoWallet;
    }
    match rpc.call("get_height", serde_json::json!({})) {
        Ok(val) => {
            let wallet = val
                .get("wallet_height")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let daemon = val.get("daemon_height").and_then(serde_json::Value::as_i64);
            crate::status::classify(true, daemon, wallet)
        }
        Err(_) => crate::status::SyncView::WalletRpcUnreachable,
    }
}

/// CLI version, plus the connected wallet-RPC server's version when reachable.
fn cmd_version(rpc: &RpcSession) -> CommandResult {
    match rpc.call("get_version", serde_json::json!({})) {
        Ok(mut val) => {
            if let Some(object) = val.as_object_mut() {
                object.insert(
                    "cli_version".to_owned(),
                    serde_json::json!(env!("CARGO_PKG_VERSION")),
                );
            }
            Ok(val)
        }
        Err(e) => failed(format!("wallet RPC unreachable: {e}")),
    }
}

fn show_version(val: &serde_json::Value) {
    let cli = val
        .get("cli_version")
        .and_then(|v| v.as_str())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    println!("shekyl-cli {cli}");
    let server = val.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    let api = val
        .get("api_version")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    println!("shekyl-wallet-rpc {server} (api v{api})");
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
/// Confirmation for a money-moving command.
///
/// A one-shot or a script honors `--yes` and refuses without it, without
/// reading the next line. On an interactive terminal `--yes` is ignored and
/// the prompt still runs.
pub(crate) fn confirm_money(
    prompt: &str,
    action: &str,
    yes: bool,
) -> Result<(), crate::outcome::CommandFailed> {
    if crate::outcome::noninteractive() {
        return if yes {
            Ok(())
        } else {
            Err(crate::outcome::refusal(format!(
                "Refusing to {action} without confirmation on non-interactive \
                 input. Re-run with --yes, or run interactively."
            )))
        };
    }
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if yes && !tty {
        return Ok(());
    }
    if yes && tty {
        eprintln!("--yes is only honored for non-interactive input; confirming.");
        return if confirm(prompt) {
            Ok(())
        } else {
            Err(crate::outcome::refusal("Not confirmed."))
        };
    }
    if !tty {
        return Err(crate::outcome::refusal(format!(
            "Refusing to {action} without confirmation on non-interactive \
             input. Re-run with --yes, or run interactively."
        )));
    }
    if confirm(prompt) {
        Ok(())
    } else {
        Err(crate::outcome::refusal("Not confirmed."))
    }
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

pub(crate) fn require_open(rpc: &RpcSession) -> Result<(), crate::outcome::CommandFailed> {
    if rpc.is_open() {
        Ok(())
    } else {
        Err(crate::outcome::refusal(
            "No wallet is open. Use \"wallet open <name>\" or \"wallet create <name>\" first.",
        ))
    }
}

pub(crate) fn require_closed(rpc: &RpcSession) -> Result<(), crate::outcome::CommandFailed> {
    if rpc.is_open() {
        Err(crate::outcome::refusal(
            "A wallet is already open. Use \"wallet close\" first.",
        ))
    } else {
        Ok(())
    }
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
