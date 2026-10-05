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
use crate::outcome::{
    nothing_sent, present, present_failure, refusal, CommandFailed, MoneyGate, Presentation,
};
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

/// Where the command lines come from. One session has one source.
pub enum CommandSource {
    /// The rustyline prompt.
    Terminal,
    /// Stdin, one command per line. A pipe, not a conversation.
    Stdin,
    /// `--script`. The file has already been read.
    File(Vec<String>),
    /// One-shot argv. The shell already split the words.
    One(Vec<String>),
}

/// Run the command source against one wallet session.
pub fn run(
    rpc: RpcSession,
    daemon_client: Option<&DaemonClient>,
    network: &str,
    presentation: Presentation,
    source: CommandSource,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::grammar::parse;
    use crate::resolve::ResolvedCommand;

    let mut reader = match source {
        CommandSource::Terminal => {
            let mut editor = match Editor::<CliHelper, DefaultHistory>::new() {
                Ok(editor) => editor,
                Err(error) => {
                    // `process::exit` in the caller skips destructors, so the
                    // self-hosted server has to stop before this returns.
                    rpc.shutdown();
                    return Err(error.into());
                }
            };
            editor.set_helper(Some(CliHelper));
            let hist = history_path().unwrap_or_default();
            if editor.load_history(&hist).is_err() {
                // No history file yet -- that's fine on first run.
            }
            LineReader::Terminal {
                editor: Box::new(editor),
                hist,
            }
        }
        CommandSource::Stdin => LineReader::Stdin(std::io::stdin().lines()),
        CommandSource::File(lines) => LineReader::Lines(lines.into_iter()),
        CommandSource::One(words) => LineReader::One(Some(words)),
    };

    if matches!(reader, LineReader::Terminal { .. }) && presentation.human() {
        println!("Welcome to shekyl-cli. Type \"help\" for commands.");
    }

    loop {
        let prompt = crate::session::prompt(network, rpc.open_wallet_name().as_deref());
        let resolved = match next_line(&mut reader, &presentation, &rpc, &prompt) {
            Line::Prompt(raw) => {
                let line = raw.trim();
                // A script file and a pipe use `#` as a comment. The terminal
                // does not: a person who types `#` gets the unknown-command
                // refusal. A one-shot has no line to comment.
                if line.is_empty() || (!presentation.interactive() && line.starts_with('#')) {
                    continue;
                }
                if let LineReader::Terminal { editor, hist } = &mut reader {
                    if !crate::catalog::omit_from_history(line) {
                        drop(editor.add_history_entry(line));
                        drop(editor.save_history(hist));
                    }
                }
                parse(line)
            }
            Line::Argv(words) => crate::grammar::parse_argv(&words),
            Line::Skip => continue,
            Line::Done => break,
            Line::Broken(error) => {
                rpc.shutdown();
                return Err(error);
            }
        };

        let ok = match resolved {
            ResolvedCommand::Help => {
                let text = crate::catalog::help_listing();
                present(
                    &presentation,
                    "help",
                    Ok(serde_json::json!({ "text": text })),
                    |val| {
                        print!("{}", val.get("text").and_then(|v| v.as_str()).unwrap_or(""));
                    },
                )
            }
            ResolvedCommand::HelpCommand { topic } => match crate::catalog::help_for(&topic) {
                Some(block) => present(
                    &presentation,
                    "help",
                    Ok(serde_json::json!({ "text": block })),
                    |val| {
                        println!("{}", val.get("text").and_then(|v| v.as_str()).unwrap_or(""));
                    },
                ),
                None => present_failure(
                    &presentation,
                    "help",
                    refusal(format!(
                        "No help for {topic:?}. Type \"help\" for the command list."
                    )),
                ),
            },
            ResolvedCommand::Exit => break,

            // The seed is shown inside the handler, between the announcement
            // and the return, then wiped. The result carries only the name,
            // so the human formatter has nothing left to print.
            ResolvedCommand::Create { filename } => present(
                &presentation,
                "wallet create",
                lifecycle::cmd_create(&rpc, &presentation, &filename),
                |_| {},
            ),
            ResolvedCommand::Open { filename } => present(
                &presentation,
                "wallet open",
                lifecycle::cmd_open(&rpc, &presentation, &filename),
                lifecycle::show_opened,
            ),
            ResolvedCommand::Close => present(
                &presentation,
                "wallet close",
                lifecycle::cmd_close(&rpc),
                lifecycle::show_closed,
            ),
            ResolvedCommand::Restore {
                filename,
                seed_words,
            } => present(
                &presentation,
                "wallet restore",
                lifecycle::cmd_restore(&rpc, &presentation, &filename, &seed_words),
                lifecycle::show_restored,
            ),
            ResolvedCommand::Refresh => present(
                &presentation,
                "wallet refresh",
                lifecycle::cmd_refresh(&rpc, &presentation),
                lifecycle::show_refresh,
            ),
            ResolvedCommand::Status => present(
                &presentation,
                "status",
                lifecycle::cmd_status(&rpc, daemon_client.and_then(DaemonClient::down_hint)),
                lifecycle::show_status,
            ),
            ResolvedCommand::Password => present(
                &presentation,
                "wallet password",
                lifecycle::cmd_password(&rpc, &presentation),
                lifecycle::show_password,
            ),
            ResolvedCommand::Rescan { hard } => present(
                &presentation,
                "wallet rescan",
                lifecycle::cmd_rescan(&rpc, &presentation, hard),
                lifecycle::show_rescan,
            ),

            ResolvedCommand::Balance => present(
                &presentation,
                "balance",
                balance::cmd_balance(&rpc),
                balance::show_balance,
            ),
            ResolvedCommand::Address { full, out } => present(
                &presentation,
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
                &presentation,
                "send",
                transfers::cmd_transfer(&rpc, &presentation, amount, &dest, priority, yes),
                transfers::show_submit,
            ),
            ResolvedCommand::Transfers {
                incoming,
                outgoing,
                unmatched,
            } => present(
                &presentation,
                "tx list",
                transfers::cmd_transfers(&rpc, incoming, outgoing, unmatched),
                transfers::show_transfers,
            ),
            ResolvedCommand::ShowTransfer { txid } => present(
                &presentation,
                "tx show",
                transfers::cmd_show_transfer(&rpc, &txid),
                transfers::show_transfer,
            ),
            ResolvedCommand::GetTxNote { txid } => present(
                &presentation,
                "tx note",
                transfers::cmd_get_tx_note(&rpc, &txid),
                transfers::show_note,
            ),
            ResolvedCommand::SetTxNote { txid, note } => present(
                &presentation,
                "tx note",
                transfers::cmd_set_tx_note(&rpc, &txid, &note),
                transfers::show_note_stored,
            ),
            ResolvedCommand::Abandon { txid } => present(
                &presentation,
                "tx abandon",
                transfers::cmd_abandon(&rpc, &txid),
                transfers::show_abandoned,
            ),

            ResolvedCommand::RequestNew {
                amount,
                label,
                expiry,
            } => present(
                &presentation,
                "request new",
                receiving::cmd_request_new(&rpc, amount, &label, expiry),
                receiving::show_request_new,
            ),
            ResolvedCommand::RequestsList { filter } => present(
                &presentation,
                "request list",
                receiving::cmd_requests_list(&rpc, filter),
                receiving::show_requests,
            ),
            ResolvedCommand::MakeUri {
                address,
                amount,
                label,
            } => present(
                &presentation,
                "uri make",
                receiving::cmd_make_uri(&rpc, address.as_deref(), amount, label.as_deref()),
                receiving::show_uri,
            ),
            ResolvedCommand::ParseUri { uri } => present(
                &presentation,
                "uri read",
                receiving::cmd_parse_uri(&rpc, &uri),
                receiving::show_parsed_uri,
            ),

            ResolvedCommand::Stake => present(
                &presentation,
                "stake",
                staking::cmd_stake_read(&rpc),
                staking::show_stake,
            ),
            ResolvedCommand::StakeJoin { shard_ids } => present(
                &presentation,
                "stake join",
                staking::cmd_stake_join(&rpc, &shard_ids),
                |_| {},
            ),
            ResolvedCommand::StakedBalance => present(
                &presentation,
                "stake balance",
                staking::cmd_staked_balance(&rpc),
                staking::show_staked_balance,
            ),
            ResolvedCommand::StakedOutputs => present(
                &presentation,
                "stake outputs",
                staking::cmd_staked_outputs(&rpc),
                staking::show_staked_outputs,
            ),
            ResolvedCommand::StakeIn { amount, yes } => present(
                &presentation,
                "stake add",
                staking::cmd_stake_in(&rpc, &presentation, amount, yes),
                transfers::show_submit,
            ),
            ResolvedCommand::DrainBalance => present(
                &presentation,
                "stake available",
                staking::cmd_drain_balance(&rpc),
                staking::show_drain_balance,
            ),
            ResolvedCommand::Drain { amount, yes } => present(
                &presentation,
                "stake return",
                staking::cmd_drain(&rpc, &presentation, amount, yes),
                staking::show_drain,
            ),
            ResolvedCommand::Unstake { yes } => present(
                &presentation,
                "stake release",
                staking::cmd_unstake(&rpc, &presentation, yes),
                staking::show_release,
            ),
            ResolvedCommand::CollectUnstaked { yes } => present(
                &presentation,
                "stake collect",
                staking::cmd_collect_unstaked(&rpc, &presentation, yes),
                staking::show_collect,
            ),
            ResolvedCommand::ShardListAll => present(
                &presentation,
                "shard list all",
                chain::cmd_shard_list_all(daemon_client),
                chain::show_coverage,
            ),
            ResolvedCommand::ShardListMine => present(
                &presentation,
                "shard list mine",
                chain::cmd_shard_list_mine(&rpc),
                |_| {},
            ),
            ResolvedCommand::ShardShow { shard_id } => present(
                &presentation,
                "shard show",
                chain::cmd_shard_show(daemon_client, shard_id),
                chain::show_shard,
            ),
            ResolvedCommand::ShardFetch { shard_id } => present(
                &presentation,
                "shard fetch",
                chain::cmd_shard_fetch(daemon_client, shard_id),
                chain::show_fetch,
            ),

            ResolvedCommand::Fee {
                n_inputs,
                n_outputs,
            } => present(
                &presentation,
                "fee",
                fees::cmd_fee(&rpc, n_inputs, n_outputs),
                fees::show_fee,
            ),
            ResolvedCommand::ChainHealth => present(
                &presentation,
                "chain",
                chain::cmd_chain_health(daemon_client),
                chain::show_chain,
            ),

            ResolvedCommand::MineStart { threads } => present(
                &presentation,
                "mine start",
                mine::cmd_mine_start(&rpc, daemon_client, network, threads),
                mine::show_mine_start,
            ),
            ResolvedCommand::MineStop => present(
                &presentation,
                "mine stop",
                mine::cmd_mine_stop(&rpc, daemon_client, network),
                mine::show_mine_stop,
            ),
            ResolvedCommand::MineStatus => present(
                &presentation,
                "mine status",
                mine::cmd_mine_status(&rpc, daemon_client, network),
                mine::show_mine_status,
            ),

            ResolvedCommand::GetTxProof {
                txid,
                address,
                message,
            } => {
                let result = proofs::cmd_get_tx_proof(&rpc, &txid, &address, message.as_deref());
                let disclosure = result.as_ref().ok().and_then(proofs::tx_proof_disclosure);
                let ok = present(
                    &presentation,
                    "prove payment",
                    result,
                    proofs::show_tx_proof,
                );
                if let Some(text) = disclosure {
                    presentation.disclose(text);
                }
                ok
            }
            ResolvedCommand::CheckTxProof {
                txid,
                address,
                proof,
                message,
            } => present(
                &presentation,
                "check payment",
                proofs::cmd_check_tx_proof(&rpc, &txid, &address, &proof, message.as_deref()),
                proofs::show_tx_check,
            ),
            ResolvedCommand::GetReserveProof { amount, message } => {
                let result = proofs::cmd_get_reserve_proof(&rpc, amount, message.as_deref());
                let ok = present(
                    &presentation,
                    "prove reserve",
                    result,
                    proofs::show_reserve_proof,
                );
                if ok {
                    presentation.disclose(proofs::RESERVE_PROOF_DISCLOSURE);
                }
                ok
            }
            ResolvedCommand::CheckReserveProof {
                address,
                proof,
                message,
            } => present(
                &presentation,
                "check reserve",
                proofs::cmd_check_reserve_proof(&rpc, &address, &proof, message.as_deref()),
                proofs::show_reserve_check,
            ),

            ResolvedCommand::Sign { message } => present(
                &presentation,
                "sign",
                signing::cmd_sign(&rpc, &presentation, &message),
                signing::show_signature,
            ),
            ResolvedCommand::Verify {
                address,
                signature,
                message,
            } => present(
                &presentation,
                "verify",
                signing::cmd_verify(&rpc, &address, &signature, &message),
                signing::show_verify,
            ),

            ResolvedCommand::Version => present(
                &presentation,
                "version",
                Ok(cmd_version(&rpc)),
                show_version,
            ),
            ResolvedCommand::Wallet => present(
                &presentation,
                "wallet",
                balance::cmd_wallet(&rpc),
                balance::show_wallet,
            ),

            ResolvedCommand::Unknown { cmd } => present_failure(
                &presentation,
                "unknown",
                refusal(format!(
                    "Unknown command: {cmd}. Type \"help\" for available commands."
                )),
            ),
            ResolvedCommand::Diagnostic { message } => {
                present_failure(&presentation, "refused", refusal(message))
            }
        };
        if !ok && !presentation.interactive() {
            rpc.shutdown();
            std::process::exit(1);
        }
        if matches!(reader, LineReader::One(_)) {
            break;
        }
    }

    if let LineReader::Terminal { editor, hist } = &mut reader {
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

enum Line {
    /// A prompt, script, or pipe line. Parsed by [`crate::grammar::parse`].
    Prompt(String),
    /// One-shot argv. Parsed by [`crate::grammar::parse_argv`].
    Argv(Vec<String>),
    /// Empty read that is not the end of the source. The prompt continues.
    Skip,
    Done,
    Broken(Box<dyn std::error::Error>),
}

enum LineReader {
    Terminal {
        editor: Box<Editor<CliHelper, DefaultHistory>>,
        hist: String,
    },
    Stdin(std::io::Lines<std::io::StdinLock<'static>>),
    Lines(std::vec::IntoIter<String>),
    One(Option<Vec<String>>),
}

fn next_line(
    reader: &mut LineReader,
    presentation: &Presentation,
    rpc: &RpcSession,
    prompt: &str,
) -> Line {
    match reader {
        LineReader::One(words) => match words.take() {
            Some(words) => Line::Argv(words),
            None => Line::Done,
        },
        LineReader::Lines(lines) => match lines.next() {
            Some(line) => Line::Prompt(line),
            None => Line::Done,
        },
        LineReader::Stdin(lines) => match lines.next() {
            Some(Ok(line)) => Line::Prompt(line),
            Some(Err(error)) => Line::Broken(error.into()),
            None => Line::Done,
        },
        LineReader::Terminal { editor, .. } => {
            if presentation.human() {
                let view = sync_view(rpc);
                crate::status::print_above_prompt(&crate::status::format_line(
                    env!("CARGO_PKG_VERSION"),
                    &crate::status::local_clock(),
                    &view,
                ));
            }
            match editor.readline(prompt) {
                Ok(line) => Line::Prompt(line),
                Err(ReadlineError::Interrupted) => Line::Skip,
                Err(ReadlineError::Eof) => Line::Done,
                Err(error) => {
                    eprintln!("Input error: {error}");
                    Line::Done
                }
            }
        }
    }
}

/// The CLI's own version, and the wallet-RPC version when the server answers.
///
/// The local version does not depend on the server. A server that cannot be
/// asked is `wallet_rpc_error` on a successful report, not a missing line.
#[derive(serde::Serialize)]
struct VersionReport {
    cli_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_rpc_error: Option<String>,
}

fn version_report(
    cli_version: &'static str,
    response: Result<serde_json::Value, String>,
) -> VersionReport {
    match response {
        Ok(val) => VersionReport {
            cli_version,
            version: val
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            api_version: val.get("api_version").and_then(serde_json::Value::as_i64),
            wallet_rpc_error: None,
        },
        Err(error) => VersionReport {
            cli_version,
            version: None,
            api_version: None,
            wallet_rpc_error: Some(error),
        },
    }
}

fn cmd_version(rpc: &RpcSession) -> VersionReport {
    let response = match rpc.call("get_version", serde_json::json!({})) {
        Ok(val) => Ok(val),
        Err(error) => Err(format!("wallet RPC unreachable: {error}")),
    };
    version_report(env!("CARGO_PKG_VERSION"), response)
}

fn show_version(report: &VersionReport) {
    println!("shekyl-cli {}", report.cli_version);
    match &report.wallet_rpc_error {
        Some(error) => eprintln!("{error}"),
        None => {
            let server = report.version.as_deref().unwrap_or("?");
            let api = report.api_version.unwrap_or(0);
            println!("shekyl-wallet-rpc {server} (api v{api})");
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
/// A script or a one-shot honors `--yes` and refuses without it, without
/// reading the next line. On an interactive terminal `--yes` is ignored and
/// the prompt still runs. The refusal says that nothing was sent, so both
/// transcripts carry that fact.
pub(crate) fn confirm_money(
    presentation: &Presentation,
    prompt: &str,
    action: &str,
    yes: bool,
) -> Result<(), CommandFailed> {
    match presentation.money_gate(action, yes) {
        MoneyGate::Proceed => Ok(()),
        MoneyGate::Refuse(error) => Err(error),
        MoneyGate::Ask { ignored_yes } => {
            if ignored_yes {
                eprintln!("--yes is only honored for a script or a one-shot; confirming.");
            }
            if confirm(prompt) {
                Ok(())
            } else {
                Err(nothing_sent("Not confirmed. Nothing was sent."))
            }
        }
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
pub(crate) fn read_password(prompt: &str) -> Result<Zeroizing<String>, CommandFailed> {
    crate::prompt_password(prompt)
        .map_err(|error| refusal(format!("Failed to read password: {error}")))
}

/// Startup `wallet open`, through the same printer as the prompt command.
pub fn publish_wallet_open(
    presentation: &Presentation,
    rpc: &RpcSession,
    filename: &str,
    password: &str,
) -> bool {
    present(
        presentation,
        "wallet open",
        lifecycle::open_with_password(rpc, filename, password),
        lifecycle::show_opened,
    )
}

/// The hidden `--complete-tree-foundation` stake, through the same printer.
/// The command name is the flag: it is not a prompt verb.
pub fn publish_foundation_stake(
    presentation: &Presentation,
    rpc: &RpcSession,
    password: &str,
) -> bool {
    present(
        presentation,
        "complete-tree-foundation",
        staking::post_foundation_stake(rpc, password),
        staking::show_foundation,
    )
}

/// A failure that is not inside the command loop: missing script, refused
/// flag, session that never started. Still one envelope.
pub fn publish_failure(presentation: &Presentation, command: &str, error: CommandFailed) {
    let _shown = present_failure(presentation, command, error);
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
    fn version_reports_the_cli_when_the_server_cannot_be_asked() {
        let down = version_report("9.9.9", Err("wallet RPC unreachable: refused".to_owned()));
        assert_eq!(down.cli_version, "9.9.9");
        assert!(down.version.is_none());
        assert_eq!(
            down.wallet_rpc_error.as_deref(),
            Some("wallet RPC unreachable: refused")
        );

        let up = version_report(
            "9.9.9",
            Ok(serde_json::json!({"version": "1.2.3", "api_version": 4})),
        );
        assert_eq!(up.version.as_deref(), Some("1.2.3"));
        assert_eq!(up.api_version, Some(4));
        assert!(up.wallet_rpc_error.is_none());
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
