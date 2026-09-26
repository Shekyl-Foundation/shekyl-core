// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parse a prompt line into a [`ResolvedCommand`].
//!
//! Canonical tokens only. A retired spelling prints the new line and does
//! not run. Monero-deleted commands keep their own refusals.

use crate::catalog;
use crate::commands::mine::{self, ParsedMine};
use crate::resolve::{
    diag, parse_flag, parse_flag_str, parse_invoice_expiry, raw_remainder, reject_removed_command,
    reject_removed_flags, strip_flag_with_value, unix_now, FlagValue, ResolvedCommand,
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
    if tokens.contains(&"--no-confirm") {
        return diag("--no-confirm → --yes");
    }
    if let Some(msg) = reject_removed_command(tokens[0], &tokens[1..]) {
        return diag(msg);
    }
    if let Some(msg) = catalog::retired(&tokens) {
        return diag(msg);
    }
    dispatch(input, &tokens)
}

#[allow(clippy::unnested_or_patterns)]
fn dispatch(input: &str, tokens: &[&str]) -> ResolvedCommand {
    match tokens {
        ["help"] => ResolvedCommand::Help,
        ["help", rest @ ..] => ResolvedCommand::HelpCommand {
            topic: rest.join(" "),
        },
        ["exit" | "quit"] => ResolvedCommand::Exit,
        ["balance"] => ResolvedCommand::Balance,
        ["status"] => ResolvedCommand::Status,
        ["chain"] => ResolvedCommand::ChainHealth,
        ["version"] => ResolvedCommand::Version,
        ["wallet"] => ResolvedCommand::Wallet,
        ["stake"] => ResolvedCommand::Stake,
        ["address", rest @ ..] => parse_address(rest),
        ["fee", rest @ ..] => parse_fee(rest),
        ["send", rest @ ..] => parse_send(rest),
        ["wallet", rest @ ..] => parse_wallet(rest),
        ["tx", rest @ ..] => parse_tx(input, rest),
        ["request", rest @ ..] => parse_request(rest),
        ["uri", rest @ ..] => parse_uri(rest),
        ["stake", rest @ ..] => parse_stake(rest),
        ["shard", rest @ ..] => parse_shard(rest),
        ["mine", rest @ ..] => match mine::parse_mine(rest) {
            Ok(parsed) => resolved_mine(parsed),
            Err(message) => diag(message),
        },
        ["prove", rest @ ..] => parse_prove(input, rest),
        ["check", rest @ ..] => parse_check(input, rest),
        ["sign", rest @ ..] => parse_sign(input, rest),
        ["verify", rest @ ..] => parse_verify(input, rest),
        [] => ResolvedCommand::Unknown { cmd: String::new() },
        [other, ..] => ResolvedCommand::Unknown {
            cmd: (*other).to_string(),
        },
    }
}

fn resolved_mine(parsed: ParsedMine) -> ResolvedCommand {
    match parsed {
        ParsedMine::Start { threads } => ResolvedCommand::MineStart { threads },
        ParsedMine::Stop => ResolvedCommand::MineStop,
        ParsedMine::Status => ResolvedCommand::MineStatus,
    }
}

fn parse_wallet(args: &[&str]) -> ResolvedCommand {
    match args {
        ["create", name] => ResolvedCommand::Create {
            filename: (*name).to_string(),
        },
        ["open", name] => ResolvedCommand::Open {
            filename: (*name).to_string(),
        },
        ["close"] => ResolvedCommand::Close,
        ["restore", name, ..] if args.len() >= 3 => ResolvedCommand::Restore {
            filename: (*name).to_string(),
            seed_words: args[2..].iter().map(|s| (*s).to_string()).collect(),
        },
        ["password"] => ResolvedCommand::Password,
        ["refresh"] => ResolvedCommand::Refresh,
        ["rescan"] => ResolvedCommand::Rescan { hard: false },
        _ => diag(
            "wallet: usage is create <name>, open <name>, close, restore <name> <seed...>, \
             password, refresh, rescan, or wallet",
        ),
    }
}

fn parse_address(args: &[&str]) -> ResolvedCommand {
    let full = args.contains(&"--full");
    let out = match parse_flag_str(args, "--out") {
        FlagValue::Absent => None,
        FlagValue::Set(p) => Some(p),
        FlagValue::Invalid(_) => return diag("address: --out expects a path"),
    };
    if full && out.is_some() {
        return diag("address: use --full or --out <path>, not both");
    }
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--full" => {}
            "--out" => i += 1,
            a if a.starts_with("--out=") => {}
            other => {
                return diag(format!(
                    "address: unexpected argument {other:?} (usage: address [--full | --out <path>])"
                ));
            }
        }
        i += 1;
    }
    ResolvedCommand::Address { full, out }
}

fn parse_fee(args: &[&str]) -> ResolvedCommand {
    let count = |flag| match parse_flag::<u64>(args, flag) {
        FlagValue::Absent => Ok(None),
        FlagValue::Set(v) => Ok(Some(i64::try_from(v).unwrap_or(i64::MAX))),
        FlagValue::Invalid(v) => Err(format!("fee: {flag} expects a count, got {v:?}")),
    };
    match (count("--inputs"), count("--outputs")) {
        (Ok(n_inputs), Ok(n_outputs)) => ResolvedCommand::Fee {
            n_inputs,
            n_outputs,
        },
        (Err(msg), _) | (_, Err(msg)) => diag(msg),
    }
}

fn parse_send(args: &[&str]) -> ResolvedCommand {
    let yes = args.contains(&"--yes");
    let priority = match parse_flag_str(args, "--priority") {
        FlagValue::Absent => None,
        FlagValue::Set(word) => match priority_tier(&word) {
            Some(tier) => Some(tier.to_owned()),
            None => {
                return diag(format!(
                    "send: --priority expects economy, standard, or high, got {word:?}"
                ));
            }
        },
        FlagValue::Invalid(_) => {
            return diag("send: --priority expects economy, standard, or high");
        }
    };
    let positional = strip_known(args, &["--yes", "--priority"]);
    if positional.len() >= 2 {
        if let Some(amount) = crate::commands::parse_amount(positional[0]) {
            ResolvedCommand::Transfer {
                dest: positional[1].to_string(),
                amount,
                priority,
                yes,
            }
        } else {
            diag(format!("send: invalid amount {:?}", positional[0]))
        }
    } else {
        diag("send: need <amount> <address>")
    }
}

fn priority_tier(word: &str) -> Option<&'static str> {
    match word {
        "economy" => Some("ECONOMY"),
        "standard" => Some("STANDARD"),
        "high" => Some("PRIORITY"),
        _ => None,
    }
}

fn parse_tx(input: &str, args: &[&str]) -> ResolvedCommand {
    match args {
        ["list", rest @ ..] => parse_tx_list(rest),
        ["show", id] => ResolvedCommand::ShowTransfer {
            txid: (*id).to_string(),
        },
        ["note", txid] => ResolvedCommand::GetTxNote {
            txid: (*txid).to_string(),
        },
        ["note", txid, ..] => match raw_remainder(input, 3) {
            Some(note) => ResolvedCommand::SetTxNote {
                txid: (*txid).to_string(),
                note: note.to_string(),
            },
            None => diag("tx note: need <txid> to show, or <txid> <text...> to set"),
        },
        ["abandon", txid] => ResolvedCommand::Abandon {
            txid: (*txid).to_string(),
        },
        _ => diag("tx: usage is list, show <id>, note <txid> [<text...>], or abandon <txid>"),
    }
}

fn parse_tx_list(args: &[&str]) -> ResolvedCommand {
    let incoming = args.contains(&"--in");
    let outgoing = args.contains(&"--out");
    let unmatched = args.contains(&"--unmatched");
    if incoming && outgoing {
        return diag("tx list: use --in or --out, not both");
    }
    if unmatched && outgoing {
        return diag("tx list: --unmatched is incoming only; drop --out");
    }
    let stray = strip_known(args, &["--in", "--out", "--unmatched"]);
    if !stray.is_empty() {
        return diag(format!(
            "tx list: unexpected argument {:?} (usage: tx list [--in | --out] [--unmatched])",
            stray[0]
        ));
    }
    ResolvedCommand::Transfers {
        incoming,
        outgoing,
        unmatched,
    }
}

fn parse_request(args: &[&str]) -> ResolvedCommand {
    match args.first().copied() {
        Some("new") => parse_request_new(&args[1..]),
        Some("list") => parse_request_list(&args[1..]),
        _ => diag("request: usage is new <amount> <label> or list [--matched | --all]"),
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
        FlagValue::Invalid(v) => {
            return diag(format!(
                "request new: --expiry expects unix seconds or a duration (1h, 30m, 7d), got {v:?}"
            ));
        }
    };
    let filtered = strip_flag_with_value(args, "--expiry");
    if filtered.len() >= 2 {
        if let Some(amount) = crate::commands::parse_amount(filtered[0]) {
            ResolvedCommand::RequestNew {
                amount,
                label: filtered[1..].join(" "),
                expiry,
            }
        } else {
            diag(format!("request new: invalid amount {:?}", filtered[0]))
        }
    } else {
        diag("request new: need <amount> <label> [--expiry <unix|duration>]")
    }
}

fn parse_request_list(args: &[&str]) -> ResolvedCommand {
    let matched = args.contains(&"--matched");
    let all = args.contains(&"--all");
    if matched && all {
        return diag("request list: use --matched or --all, not both");
    }
    if !strip_known(args, &["--matched", "--all"]).is_empty() {
        return diag("request list: usage is request list [--matched | --all]");
    }
    let filter = if all {
        Some("all".to_owned())
    } else if matched {
        Some("matched".to_owned())
    } else {
        Some("pending".to_owned())
    };
    ResolvedCommand::RequestsList { filter }
}

fn parse_uri(args: &[&str]) -> ResolvedCommand {
    match args.first().copied() {
        Some("make") => parse_uri_make(&args[1..]),
        Some("read") => match args.get(1) {
            Some(uri) if args.len() == 2 => ResolvedCommand::ParseUri {
                uri: (*uri).to_string(),
            },
            _ => diag("uri read: need <uri>"),
        },
        _ => diag("uri: usage is make or read <uri>"),
    }
}

fn parse_uri_make(args: &[&str]) -> ResolvedCommand {
    let str_flag = |flag: &str| match parse_flag_str(args, flag) {
        FlagValue::Absent => Ok(None),
        FlagValue::Set(v) => Ok(Some(v)),
        FlagValue::Invalid(_) => Err(format!("uri make: {flag} expects a value")),
    };
    let address = match str_flag("--address") {
        Ok(v) => v,
        Err(m) => return diag(m),
    };
    let label = match str_flag("--label") {
        Ok(v) => v,
        Err(m) => return diag(m),
    };
    let amount = match str_flag("--amount") {
        Ok(None) => None,
        Ok(Some(raw)) => match crate::commands::parse_amount(&raw) {
            Some(v) => Some(v),
            None => return diag(format!("uri make: invalid amount {raw:?}")),
        },
        Err(m) => return diag(m),
    };
    ResolvedCommand::MakeUri {
        address,
        amount,
        label,
    }
}

fn parse_stake(args: &[&str]) -> ResolvedCommand {
    match args.first().copied() {
        Some("balance") if args.len() == 1 => ResolvedCommand::StakedBalance,
        Some("outputs") if args.len() == 1 => ResolvedCommand::StakedOutputs,
        Some("available") if args.len() == 1 => ResolvedCommand::DrainBalance,
        Some("add") => parse_amount_yes("stake add", &args[1..], |amount, yes| {
            ResolvedCommand::StakeIn { amount, yes }
        }),
        Some("return") => parse_amount_yes("stake return", &args[1..], |amount, yes| {
            ResolvedCommand::Drain { amount, yes }
        }),
        Some("exit") => parse_yes_only("stake exit", &args[1..], |yes| ResolvedCommand::Unstake {
            yes,
        }),
        Some("collect") => parse_yes_only("stake collect", &args[1..], |yes| {
            ResolvedCommand::CollectUnstaked { yes }
        }),
        Some("join") => parse_stake_join(&args[1..]),
        Some(other) => diag(format!(
            "stake: no verb {other:?}. Usage: stake, balance, outputs, available, \
             add <amount>, return <amount>, exit, collect, join <shard-id>..."
        )),
        None => ResolvedCommand::Stake,
    }
}

fn parse_stake_join(args: &[&str]) -> ResolvedCommand {
    let positional = strip_known(args, &["--yes"]);
    if positional.is_empty() {
        return diag("stake join: need one or more <shard-id>");
    }
    if positional.len() != args.iter().filter(|a| !a.starts_with("--")).count() {
        return diag("stake join: the only flag is --yes, and it does not post a bond yet");
    }
    let mut ids = Vec::with_capacity(positional.len());
    for raw in positional {
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

fn parse_amount_yes(
    verb: &str,
    args: &[&str],
    build: impl FnOnce(u64, bool) -> ResolvedCommand,
) -> ResolvedCommand {
    let yes = args.contains(&"--yes");
    let positional = strip_known(args, &["--yes"]);
    match positional.as_slice() {
        [one] => match crate::commands::parse_amount(one) {
            Some(amount) => build(amount, yes),
            None => diag(format!("{verb}: invalid amount {one:?}")),
        },
        _ => diag(format!("{verb}: need exactly <amount>")),
    }
}

fn parse_yes_only(
    verb: &str,
    args: &[&str],
    build: impl FnOnce(bool) -> ResolvedCommand,
) -> ResolvedCommand {
    let yes = args.contains(&"--yes");
    if strip_known(args, &["--yes"]).is_empty() && args.iter().all(|a| *a == "--yes") {
        build(yes)
    } else {
        diag(format!("{verb}: takes no arguments other than --yes"))
    }
}

fn parse_shard(args: &[&str]) -> ResolvedCommand {
    match args {
        ["list", "all"] => ResolvedCommand::ShardListAll,
        ["list", "mine"] => ResolvedCommand::ShardListMine,
        ["list"] => diag("shard list → shard list all | shard list mine"),
        ["show", id] => match id.parse::<u64>() {
            Ok(shard_id) => ResolvedCommand::ShardShow { shard_id },
            Err(_) => diag(format!("shard show: {id:?} is not a shard id")),
        },
        ["fetch", id] => match id.parse::<u64>() {
            Ok(shard_id) => ResolvedCommand::ShardFetch { shard_id },
            Err(_) => diag(format!("shard fetch: {id:?} is not a shard id")),
        },
        _ => diag("shard: usage is list all, list mine, show <id>, or fetch <id>"),
    }
}

fn parse_prove(input: &str, args: &[&str]) -> ResolvedCommand {
    if args.iter().any(|a| a.starts_with('-')) {
        return diag(
            "prove: this command takes no flags — a flag-shaped word would bind into the message",
        );
    }
    match args.first().copied() {
        Some("payment") if args.len() >= 3 => ResolvedCommand::GetTxProof {
            txid: args[1].to_string(),
            address: args[2].to_string(),
            message: raw_remainder(input, 4).map(str::to_owned),
        },
        Some("reserve") => parse_prove_reserve(input, &args[1..]),
        _ => diag("prove: usage is payment <txid> <address> [message...] or reserve [amount] [message...]"),
    }
}

fn parse_prove_reserve(input: &str, args: &[&str]) -> ResolvedCommand {
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

fn parse_check(input: &str, args: &[&str]) -> ResolvedCommand {
    if args.iter().any(|a| a.starts_with('-')) {
        return diag(
            "check: this command takes no flags — a flag-shaped word would bind into the message",
        );
    }
    match args.first().copied() {
        Some("payment") if args.len() >= 4 => ResolvedCommand::CheckTxProof {
            txid: args[1].to_string(),
            address: args[2].to_string(),
            proof: args[3].to_string(),
            message: raw_remainder(input, 5).map(str::to_owned),
        },
        Some("reserve") if args.len() >= 3 => ResolvedCommand::CheckReserveProof {
            address: args[1].to_string(),
            proof: args[2].to_string(),
            message: raw_remainder(input, 4).map(str::to_owned),
        },
        Some("payment") => diag("check payment: need <txid> <address> <proof> [message...]"),
        Some("reserve") => diag("check reserve: need <address> <proof> [message...]"),
        _ => diag("check: usage is payment <txid> <address> <proof> or reserve <address> <proof>"),
    }
}

fn parse_sign(input: &str, _args: &[&str]) -> ResolvedCommand {
    match raw_remainder(input, 1) {
        Some(message) => ResolvedCommand::Sign {
            message: message.to_string(),
        },
        None => diag("sign: need <message...>"),
    }
}

fn parse_verify(input: &str, args: &[&str]) -> ResolvedCommand {
    if args.len() < 3 {
        return diag("verify: need <address> <signature> <message...>");
    }
    match raw_remainder(input, 3) {
        Some(message) => ResolvedCommand::Verify {
            address: args[0].to_string(),
            signature: args[1].to_string(),
            message: message.to_string(),
        },
        None => diag("verify: need <address> <signature> <message...>"),
    }
}

fn strip_known<'a>(args: &[&'a str], flags: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if flags.contains(arg) {
            if *arg == "--priority" || *arg == "--out" || *arg == "--expiry" {
                skip = true;
            }
            continue;
        }
        if flags
            .iter()
            .any(|flag| arg.starts_with(&format!("{flag}=")))
        {
            continue;
        }
        out.push(*arg);
    }
    out
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
    fn send_priority_words() {
        match parse("send 1.5 addr --priority economy") {
            ResolvedCommand::Transfer {
                amount,
                priority,
                yes,
                ..
            } => {
                assert_eq!(amount, 1_500_000_000);
                assert_eq!(priority.as_deref(), Some("ECONOMY"));
                assert!(!yes);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse("send 1 addr --priority 2"),
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
}
