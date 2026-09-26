// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parse a prompt line into a [`ResolvedCommand`].
//!
//! The command path comes from [`crate::catalog`]. This module only reads
//! the arguments that path leaves behind. A retired spelling prints the
//! new line and does not run. Monero-deleted commands keep their own
//! refusals.

use crate::catalog::{self, split_flags, usage, CommandId, Split, Walk};
use crate::resolve::{
    diag, parse_flag_str, parse_invoice_expiry, raw_remainder, reject_removed_command,
    reject_removed_flags, unix_now, FeePriority, FlagValue, RequestFilter, ResolvedCommand,
};

/// Parse one line. Empty input is an unknown command with an empty name,
/// which the prompt loop never submits.
pub fn parse(input: &str) -> ResolvedCommand {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    if tokens.is_empty() {
        return ResolvedCommand::Unknown { cmd: String::new() };
    }
    if let Some(msg) = reject_removed_flags(&tokens) {
        return diag(msg);
    }
    if tokens
        .iter()
        .any(|token| *token == "--no-confirm" || token.starts_with("--no-confirm="))
    {
        return diag("--no-confirm → --yes");
    }
    if let Some(msg) = reject_removed_command(tokens[0], &tokens[1..]) {
        return diag(msg);
    }
    if let Some(msg) = catalog::retired_message(&tokens) {
        return diag(msg);
    }
    match catalog::walk(&tokens) {
        Walk::Ready { id, rest } => parse_ready(id, input, rest),
        Walk::NeedVerb { id } => diag(catalog::need_verb(id)),
        Walk::UnknownVerb { id, word } => diag(catalog::unknown_verb(id, word)),
        Walk::Unknown { word } => ResolvedCommand::Unknown { cmd: word },
    }
}

#[allow(clippy::enum_glob_use)]
fn parse_ready(id: CommandId, input: &str, args: &[&str]) -> ResolvedCommand {
    use CommandId::*;
    match id {
        Help => parse_help(args),
        Exit => bare(id, args, ResolvedCommand::Exit),
        Balance => bare(id, args, ResolvedCommand::Balance),
        Status => bare(id, args, ResolvedCommand::Status),
        Chain => bare(id, args, ResolvedCommand::ChainHealth),
        Version => bare(id, args, ResolvedCommand::Version),
        Wallet => bare(id, args, ResolvedCommand::Wallet),
        Stake => bare(id, args, ResolvedCommand::Stake),
        WalletCreate => one_word(id, args, |name| ResolvedCommand::Create {
            filename: name.to_string(),
        }),
        WalletOpen => one_word(id, args, |name| ResolvedCommand::Open {
            filename: name.to_string(),
        }),
        WalletClose => bare(id, args, ResolvedCommand::Close),
        WalletRestore => parse_restore(args),
        WalletPassword => bare(id, args, ResolvedCommand::Password),
        WalletRefresh => bare(id, args, ResolvedCommand::Refresh),
        WalletRescan => parse_rescan(args),
        Address => parse_address(args),
        Fee => parse_fee(args),
        Send => parse_send(args),
        TxList => parse_tx_list(args),
        TxShow => one_word(id, args, |txid| ResolvedCommand::ShowTransfer {
            txid: txid.to_string(),
        }),
        TxNote => parse_tx_note(input, args),
        TxAbandon => one_word(id, args, |txid| ResolvedCommand::Abandon {
            txid: txid.to_string(),
        }),
        RequestNew => parse_request_new(args),
        RequestList => parse_request_list(args),
        UriMake => parse_uri_make(args),
        UriRead => one_word(id, args, |uri| ResolvedCommand::ParseUri {
            uri: uri.to_string(),
        }),
        StakeBalance => bare(id, args, ResolvedCommand::StakedBalance),
        StakeOutputs => bare(id, args, ResolvedCommand::StakedOutputs),
        StakeAvailable => bare(id, args, ResolvedCommand::DrainBalance),
        StakeAdd => parse_amount_yes(id, args, |amount, yes| ResolvedCommand::StakeIn {
            amount,
            yes,
        }),
        StakeReturn => parse_amount_yes(id, args, |amount, yes| ResolvedCommand::Drain {
            amount,
            yes,
        }),
        StakeExit => parse_yes_only(id, args, |yes| ResolvedCommand::Unstake { yes }),
        StakeCollect => parse_yes_only(id, args, |yes| ResolvedCommand::CollectUnstaked { yes }),
        StakeJoin => parse_stake_join(args),
        ShardListAll => bare(id, args, ResolvedCommand::ShardListAll),
        ShardListMine => bare(id, args, ResolvedCommand::ShardListMine),
        ShardShow => one_id(id, args, |shard_id| ResolvedCommand::ShardShow { shard_id }),
        ShardFetch => one_id(id, args, |shard_id| ResolvedCommand::ShardFetch {
            shard_id,
        }),
        MineStart => parse_mine_start(args),
        MineStop => bare(id, args, ResolvedCommand::MineStop),
        MineStatus => bare(id, args, ResolvedCommand::MineStatus),
        ProvePayment => parse_prove_payment(input, args),
        ProveReserve => parse_prove_reserve(input, args),
        CheckPayment => parse_check_payment(input, args),
        CheckReserve => parse_check_reserve(input, args),
        Sign => parse_sign(input),
        Verify => parse_verify(input, args),
        // Subjects. `walk` asks for a verb before this match; the arm keeps
        // the match exhaustive if that ever changes.
        Tx | Request | Uri | Shard | ShardList | Mine | Prove | Check => {
            diag(catalog::need_verb(id))
        }
    }
}

fn bare(id: CommandId, args: &[&str], command: ResolvedCommand) -> ResolvedCommand {
    if args.is_empty() {
        command
    } else {
        diag(usage(id))
    }
}

fn one_word(
    id: CommandId,
    args: &[&str],
    build: impl FnOnce(&str) -> ResolvedCommand,
) -> ResolvedCommand {
    match args {
        [word] => build(word),
        _ => diag(usage(id)),
    }
}

fn one_id(
    id: CommandId,
    args: &[&str],
    build: impl FnOnce(u64) -> ResolvedCommand,
) -> ResolvedCommand {
    match args {
        [raw] => match raw.parse::<u64>() {
            Ok(shard_id) => build(shard_id),
            Err(_) => diag(format!("{}: {raw:?} is not a shard id", usage(id))),
        },
        _ => diag(usage(id)),
    }
}

fn flags<'a>(id: CommandId, args: &'a [&'a str]) -> Result<Split<'a>, ResolvedCommand> {
    split_flags(args, catalog::flags_of(id)).map_err(diag)
}

fn parse_help(args: &[&str]) -> ResolvedCommand {
    if args.is_empty() {
        ResolvedCommand::Help
    } else {
        ResolvedCommand::HelpCommand {
            topic: args.join(" "),
        }
    }
}

fn parse_restore(args: &[&str]) -> ResolvedCommand {
    if args.len() >= 2 {
        ResolvedCommand::Restore {
            filename: args[0].to_string(),
            seed_words: args[1..].iter().map(|word| (*word).to_string()).collect(),
        }
    } else {
        diag(usage(CommandId::WalletRestore))
    }
}

fn parse_rescan(args: &[&str]) -> ResolvedCommand {
    match args {
        [] => ResolvedCommand::Rescan { hard: false },
        ["hard"] => ResolvedCommand::Rescan { hard: true },
        _ => diag(usage(CommandId::WalletRescan)),
    }
}

fn parse_address(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::Address, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if !split.positional.is_empty() {
        return diag(usage(CommandId::Address));
    }
    let full = split.has("--full");
    let out = split.value("--out").map(str::to_owned);
    if full && out.is_some() {
        return diag("address: use --full or --out <path>, not both");
    }
    ResolvedCommand::Address { full, out }
}

fn parse_fee(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::Fee, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if !split.positional.is_empty() {
        return diag(usage(CommandId::Fee));
    }
    let count = |name: &str| -> Result<Option<i64>, String> {
        match split.value(name) {
            None => Ok(None),
            Some(raw) => match raw.parse::<u64>() {
                Ok(value) => match i64::try_from(value) {
                    Ok(value) => Ok(Some(value)),
                    Err(_) => Err(format!("fee: {name} is too large")),
                },
                Err(_) => Err(format!("fee: {name} expects a count, got {raw:?}")),
            },
        }
    };
    match (count("--inputs"), count("--outputs")) {
        (Ok(n_inputs), Ok(n_outputs)) => ResolvedCommand::Fee {
            n_inputs,
            n_outputs,
        },
        (Err(message), _) | (_, Err(message)) => diag(message),
    }
}

fn parse_send(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::Send, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    let priority = match split.value("--priority") {
        None | Some("standard") => FeePriority::Standard,
        Some("economy") => FeePriority::Economy,
        Some("high") => FeePriority::High,
        Some(word) => {
            return diag(format!(
                "send: --priority expects economy, standard, or high, got {word:?}"
            ));
        }
    };
    match split.positional.as_slice() {
        [amount, dest] => match crate::commands::parse_amount(amount) {
            Some(amount) => ResolvedCommand::Transfer {
                dest: (*dest).to_string(),
                amount,
                priority,
                yes: split.has("--yes"),
            },
            None => diag(format!("send: invalid amount {amount:?}")),
        },
        _ => diag("send: need <amount> <address>"),
    }
}

fn parse_tx_list(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::TxList, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if !split.positional.is_empty() {
        return diag(usage(CommandId::TxList));
    }
    let incoming = split.has("--in");
    let outgoing = split.has("--out");
    let unmatched = split.has("--unmatched");
    if incoming && outgoing {
        return diag("tx list: use --in or --out, not both");
    }
    if unmatched && outgoing {
        return diag("tx list: --unmatched is incoming only; drop --out");
    }
    ResolvedCommand::Transfers {
        incoming,
        outgoing,
        unmatched,
    }
}

fn parse_tx_note(input: &str, args: &[&str]) -> ResolvedCommand {
    match args {
        [txid] => ResolvedCommand::GetTxNote {
            txid: (*txid).to_string(),
        },
        [txid, ..] => match raw_remainder(input, 3) {
            Some(note) => ResolvedCommand::SetTxNote {
                txid: (*txid).to_string(),
                note: note.to_string(),
            },
            None => diag(usage(CommandId::TxNote)),
        },
        _ => diag(usage(CommandId::TxNote)),
    }
}

fn parse_request_new(args: &[&str]) -> ResolvedCommand {
    let expiry = match parse_flag_str(args, "--expiry") {
        FlagValue::Absent => None,
        FlagValue::Set(raw) => match parse_invoice_expiry(&raw, unix_now()) {
            Some(ts) => Some(ts),
            None => {
                return diag(format!(
                    "request new: --expiry expects unix seconds or a duration (1h, 30m, 7d), got {raw:?}"
                ));
            }
        },
        FlagValue::Invalid(raw) => {
            return diag(format!(
                "request new: --expiry expects unix seconds or a duration (1h, 30m, 7d), got {raw:?}"
            ));
        }
    };
    let split = match flags(CommandId::RequestNew, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if split.positional.len() >= 2 {
        if let Some(amount) = crate::commands::parse_amount(split.positional[0]) {
            ResolvedCommand::RequestNew {
                amount,
                label: split.positional[1..].join(" "),
                expiry,
            }
        } else {
            diag(format!(
                "request new: invalid amount {:?}",
                split.positional[0]
            ))
        }
    } else {
        diag(usage(CommandId::RequestNew))
    }
}

fn parse_request_list(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::RequestList, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if !split.positional.is_empty() {
        return diag(usage(CommandId::RequestList));
    }
    let matched = split.has("--matched");
    let all = split.has("--all");
    if matched && all {
        return diag("request list: use --matched or --all, not both");
    }
    let filter = if all {
        RequestFilter::All
    } else if matched {
        RequestFilter::Matched
    } else {
        RequestFilter::Pending
    };
    ResolvedCommand::RequestsList { filter }
}

fn parse_uri_make(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::UriMake, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if !split.positional.is_empty() {
        return diag(usage(CommandId::UriMake));
    }
    let address = split.value("--address").map(str::to_owned);
    let label = split.value("--label").map(str::to_owned);
    let amount = match split.value("--amount") {
        None => None,
        Some(raw) => match crate::commands::parse_amount(raw) {
            Some(amount) => Some(amount),
            None => return diag(format!("uri make: invalid amount {raw:?}")),
        },
    };
    ResolvedCommand::MakeUri {
        address,
        amount,
        label,
    }
}

fn parse_amount_yes(
    id: CommandId,
    args: &[&str],
    build: impl FnOnce(u64, bool) -> ResolvedCommand,
) -> ResolvedCommand {
    let split = match flags(id, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    match split.positional.as_slice() {
        [one] => match crate::commands::parse_amount(one) {
            Some(amount) => build(amount, split.has("--yes")),
            None => diag(format!("{}: invalid amount {one:?}", usage(id))),
        },
        _ => diag(usage(id)),
    }
}

fn parse_yes_only(
    id: CommandId,
    args: &[&str],
    build: impl FnOnce(bool) -> ResolvedCommand,
) -> ResolvedCommand {
    let split = match flags(id, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if split.positional.is_empty() {
        build(split.has("--yes"))
    } else {
        diag(usage(id))
    }
}

fn parse_stake_join(args: &[&str]) -> ResolvedCommand {
    let split = match flags(CommandId::StakeJoin, args) {
        Ok(split) => split,
        Err(command) => return command,
    };
    if split.positional.is_empty() {
        return diag(usage(CommandId::StakeJoin));
    }
    let mut ids: Vec<u64> = Vec::with_capacity(split.positional.len());
    for raw in &split.positional {
        match raw.parse::<u64>() {
            Ok(id) => {
                if ids.contains(&id) {
                    return diag(format!("stake join: shard {id} was named twice"));
                }
                ids.push(id);
            }
            Err(_) => return diag(format!("stake join: {raw:?} is not a shard id")),
        }
    }
    ResolvedCommand::StakeJoin { shard_ids: ids }
}

fn parse_mine_start(args: &[&str]) -> ResolvedCommand {
    let threads = match args {
        [] | ["auto"] => None,
        [token] => match token.parse::<u64>() {
            Ok(count) if count >= 1 => Some(count),
            _ => {
                return diag(format!(
                    "mine start: threads must be a positive number or \"auto\", got {token:?}"
                ));
            }
        },
        _ => return diag(usage(CommandId::MineStart)),
    };
    ResolvedCommand::MineStart { threads }
}

fn parse_prove_payment(input: &str, args: &[&str]) -> ResolvedCommand {
    if let Some(message) = refuse_flag("prove", args) {
        return diag(message);
    }
    if args.len() >= 2 {
        ResolvedCommand::GetTxProof {
            txid: args[0].to_string(),
            address: args[1].to_string(),
            message: raw_remainder(input, 4).map(str::to_owned),
        }
    } else {
        diag(usage(CommandId::ProvePayment))
    }
}

fn parse_prove_reserve(input: &str, args: &[&str]) -> ResolvedCommand {
    if let Some(message) = refuse_flag("prove", args) {
        return diag(message);
    }
    match args.first() {
        Some(first) => match crate::commands::parse_amount(first) {
            Some(amount) => ResolvedCommand::GetReserveProof {
                amount: Some(amount),
                message: raw_remainder(input, 3).map(str::to_owned),
            },
            None => ResolvedCommand::GetReserveProof {
                amount: None,
                message: raw_remainder(input, 2).map(str::to_owned),
            },
        },
        None => ResolvedCommand::GetReserveProof {
            amount: None,
            message: None,
        },
    }
}

fn parse_check_payment(input: &str, args: &[&str]) -> ResolvedCommand {
    if let Some(message) = refuse_flag("check", args) {
        return diag(message);
    }
    if args.len() >= 3 {
        ResolvedCommand::CheckTxProof {
            txid: args[0].to_string(),
            address: args[1].to_string(),
            proof: args[2].to_string(),
            message: raw_remainder(input, 5).map(str::to_owned),
        }
    } else {
        diag(usage(CommandId::CheckPayment))
    }
}

fn parse_check_reserve(input: &str, args: &[&str]) -> ResolvedCommand {
    if let Some(message) = refuse_flag("check", args) {
        return diag(message);
    }
    if args.len() >= 2 {
        ResolvedCommand::CheckReserveProof {
            address: args[0].to_string(),
            proof: args[1].to_string(),
            message: raw_remainder(input, 4).map(str::to_owned),
        }
    } else {
        diag(usage(CommandId::CheckReserve))
    }
}

fn refuse_flag(verb: &str, args: &[&str]) -> Option<String> {
    args.iter().find(|arg| arg.starts_with('-')).map(|_| {
        format!(
            "{verb}: this command takes no flags — a flag-shaped word would bind into the message"
        )
    })
}

fn parse_sign(input: &str) -> ResolvedCommand {
    match raw_remainder(input, 1) {
        Some(message) => ResolvedCommand::Sign {
            message: message.to_string(),
        },
        None => diag(usage(CommandId::Sign)),
    }
}

fn parse_verify(input: &str, args: &[&str]) -> ResolvedCommand {
    if args.len() < 3 {
        return diag(usage(CommandId::Verify));
    }
    match raw_remainder(input, 3) {
        Some(message) => ResolvedCommand::Verify {
            address: args[0].to_string(),
            signature: args[1].to_string(),
            message: message.to_string(),
        },
        None => diag(usage(CommandId::Verify)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_retires_to_send() {
        match parse("transfer 1.0 addr") {
            ResolvedCommand::Diagnostic { message } => {
                assert!(message.contains("send <amount> <address>"), "{message}");
            }
            other => panic!("expected diagnostic, got {other:?}"),
        }
    }

    #[test]
    fn send_takes_exactly_two_positionals_and_named_priority() {
        match parse("send 1.5 addr --priority economy") {
            ResolvedCommand::Transfer {
                amount,
                priority,
                yes,
                ..
            } => {
                assert_eq!(amount, 1_500_000_000);
                assert_eq!(priority, FeePriority::Economy);
                assert!(!yes);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse("send 1 addr --priority 2"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("send 1 addr typo"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("uri make garbage"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }

    #[test]
    fn stake_bare_is_a_read_and_join_names_ids() {
        assert!(matches!(parse("stake"), ResolvedCommand::Stake));
        match parse("stake join 3 3") {
            ResolvedCommand::Diagnostic { message } => {
                assert!(message.contains("twice"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        match parse("stake join 4 9") {
            ResolvedCommand::StakeJoin { shard_ids } => assert_eq!(shard_ids, vec![4, 9]),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse("stake join 4 --yes"),
            ResolvedCommand::Diagnostic { .. }
        ));
        match parse("stake foundation") {
            ResolvedCommand::Diagnostic { message } => {
                assert!(message.contains("startup flag"), "{message}");
                assert!(message.contains("no reward"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn shard_list_requires_which() {
        match parse("shard list") {
            ResolvedCommand::Diagnostic { message } => {
                assert!(message.contains("shard list all"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse("shard list all"),
            ResolvedCommand::ShardListAll
        ));
        assert!(matches!(
            parse("shard list mine"),
            ResolvedCommand::ShardListMine
        ));
    }

    #[test]
    fn tx_list_unmatched_rejects_out() {
        assert!(matches!(
            parse("tx list --unmatched --out"),
            ResolvedCommand::Diagnostic { .. }
        ));
        match parse("tx list --in --unmatched") {
            ResolvedCommand::Transfers {
                incoming,
                unmatched,
                outgoing,
            } => {
                assert!(incoming && unmatched && !outgoing);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_confirm_does_not_run() {
        match parse("send 1 addr --no-confirm") {
            ResolvedCommand::Diagnostic { message } => {
                assert!(message.contains("--yes"), "{message}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cold_sign_and_sweep_stay_removed() {
        for line in ["sweep_all", "sign_transfer", "seed", "account"] {
            assert!(
                matches!(parse(line), ResolvedCommand::Diagnostic { .. }),
                "{line}"
            );
        }
    }

    #[test]
    fn sign_keeps_internal_spaces() {
        match parse("sign hello   world") {
            ResolvedCommand::Sign { message } => assert_eq!(message, "hello   world"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn help_topic_is_the_rest_of_the_line() {
        match parse("help stake join") {
            ResolvedCommand::HelpCommand { topic } => assert_eq!(topic, "stake join"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rpc_method_names_are_not_commands() {
        assert!(matches!(
            parse("get_balance"),
            ResolvedCommand::Unknown { .. }
        ));
    }

    #[test]
    fn rescan_hard_still_reaches_the_single_rescan() {
        assert!(matches!(
            parse("wallet rescan"),
            ResolvedCommand::Rescan { hard: false }
        ));
        assert!(matches!(
            parse("wallet rescan hard"),
            ResolvedCommand::Rescan { hard: true }
        ));
        assert!(matches!(
            parse("wallet rescan soft"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }

    #[test]
    fn mine_start_accepts_a_count_or_auto() {
        assert!(matches!(
            parse("mine start"),
            ResolvedCommand::MineStart { threads: None }
        ));
        assert!(matches!(
            parse("mine start auto"),
            ResolvedCommand::MineStart { threads: None }
        ));
        assert!(matches!(
            parse("mine start 2"),
            ResolvedCommand::MineStart { threads: Some(2) }
        ));
        assert!(matches!(
            parse("mine start 0"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("mine stop now"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }
}
